use rust_vault::*;
use std::sync::Mutex;
// Process-wide budgets are shared; tests serialize their separate lifetimes.
static LOCK: Mutex<()> = Mutex::new(());
const BUDGET: u64 = 256 * 1024 * 1024;
// Public, non-production test-only material. See tests/README.md.
const PRF: [u8; 32] = [0x51; 32];
fn plan(p: &[u8]) -> PurposePlan {
    PurposePlan {
        purpose: p.to_vec(),
        routes: vec![RoutePlan {
            action: 3,
            kind: 2,
            source_route_id: vec![],
            credential_id: b"public-test-credential".to_vec(),
            protection: 0,
        }],
    }
}
fn input(p: &[u8], plain: &[u8]) -> PurposeInput {
    PurposeInput {
        plan: plan(p),
        plaintext: Secret(plain.to_vec()),
    }
}
fn drive(v: &Vault, mut step: Step, recovery: &[u8]) -> Step {
    loop {
        let (op, rid, response) = match &step.value().clone() {
            StepValue::Completed { .. } => return step,
            StepValue::Pending {
                operation_id,
                requests,
            } => {
                assert_eq!(requests.len(), 1);
                let r = &requests[0];
                let response = match &r.payload {
                    AdapterPayload::Prf { .. } => AdapterResponse::Prf(Secret(PRF.to_vec())),
                    AdapterPayload::Recovery { .. } => {
                        AdapterResponse::Recovery(Secret(recovery.to_vec()))
                    }
                    AdapterPayload::Password { .. } => {
                        AdapterResponse::Password(Secret(b"public-test-password".to_vec()))
                    }
                    _ => panic!("unexpected adapter kind"),
                };
                (*operation_id, r.request_id, response)
            }
        };
        drop(step);
        step = v.resume(op, rid, &response).unwrap();
    }
}
fn created(v: &Vault) -> (Source, Secret) {
    let step = drive(
        v,
        v.begin(&Request::Create {
            target: b"test-target".to_vec(),
            purposes: vec![
                input(b"a", b"public payload a"),
                input(b"b", b"public payload b"),
            ],
        })
        .unwrap(),
        &[],
    );
    let StepValue::Completed {
        result: Completed::Candidate(c),
        ..
    } = step.value().clone()
    else {
        panic!("expected candidate")
    };
    v.confirm_saved(c.id, &c.new_hash).unwrap();
    (
        Source {
            snapshot: c.snapshot,
            expected: ExpectedSnapshot {
                target: b"test-target".to_vec(),
                purposes: vec![
                    Expectation {
                        purpose: b"a".to_vec(),
                        generation: 1,
                    },
                    Expectation {
                        purpose: b"b".to_vec(),
                        generation: 1,
                    },
                ],
            },
        },
        c.recovery_key.unwrap(),
    )
}
fn frames(s: &Source, p: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut result = None;
    format::visit_snapshot(&s.snapshot, |id, d, w| {
        if id == p {
            result = Some((d.to_vec(), w.iter().map(|b| b.to_vec()).collect()));
        }
        Ok(())
    })
    .unwrap();
    result.unwrap()
}
fn unlock(v: &Vault, s: &Source, p: &[u8], lifetime: Lifetime) -> u64 {
    let (data, wraps) = frames(s, p);
    let wrap = wraps
        .iter()
        .find(|w| format::wrap(w).unwrap().kind == 2)
        .unwrap()
        .clone();
    let step = drive(
        v,
        v.begin(&Request::Unlock {
            context: Context {
                target: s.expected.target.clone(),
                purpose: p.to_vec(),
                generation: 1,
            },
            data,
            wrap,
            lifetime,
        })
        .unwrap(),
        &[],
    );
    let StepValue::Completed {
        result: Completed::Unlock { handle },
        ..
    } = step.value().clone()
    else {
        panic!("expected context")
    };
    handle
}
fn candidate(step: Step) -> Candidate {
    let StepValue::Completed {
        result: Completed::Candidate(c),
        ..
    } = step.value().clone()
    else {
        panic!("expected candidate")
    };
    c
}
#[test]
fn full_lifecycle_updates_recovery_and_invalidation() {
    let _guard = LOCK.lock().unwrap();
    let v = Vault::new(BUDGET).unwrap();
    let (s, recovery) = created(&v);
    let handle = unlock(&v, &s, b"a", Lifetime::Explicit);
    let (data, old_wraps) = frames(&s, b"a");
    let context = Context {
        target: s.expected.target.clone(),
        purpose: b"a".to_vec(),
        generation: 1,
    };
    let step = v
        .begin(&Request::Decrypt {
            handle,
            context: context.clone(),
            data: data.clone(),
        })
        .unwrap();
    let StepValue::Completed {
        result: Completed::Decrypt { plaintext },
        ..
    } = &step.value().clone()
    else {
        panic!("expected plaintext")
    };
    assert!(plaintext.0 == b"public payload a");
    drop(step);
    let replacement = candidate(
        v.begin(&Request::ReplaceData {
            source: s.clone(),
            handle,
            purpose: b"a".to_vec(),
            plaintext: Secret(b"new public payload".to_vec()),
        })
        .unwrap(),
    );
    let replaced = Source {
        snapshot: replacement.snapshot.clone(),
        expected: s.expected.clone(),
    };
    assert!(frames(&replaced, b"a").1 == old_wraps);
    assert!(frames(&replaced, b"b") == frames(&s, b"b"));
    assert_eq!(
        v.confirm_saved(replacement.id, &[0; 32]),
        Err(Error::ContextMismatch)
    );
    v.confirm_saved(replacement.id, &replacement.new_hash)
        .unwrap();
    // Same-DEK replacement does not invalidate an explicitly retained context.
    assert!(
        v.begin(&Request::Decrypt {
            handle,
            context: context.clone(),
            data: frames(&replaced, b"a").0
        })
        .is_ok()
    );
    let add = Request::AddPurpose {
        source: replaced.clone(),
        purpose: input(b"c", b"new purpose"),
    };
    let added = candidate(drive(&v, v.begin(&add).unwrap(), &recovery.0));
    let mut added_source = Source {
        snapshot: added.snapshot,
        expected: replaced.expected.clone(),
    };
    added_source.expected.purposes.push(Expectation {
        purpose: b"c".to_vec(),
        generation: 1,
    });
    assert!(frames(&added_source, b"a") == frames(&replaced, b"a"));
    v.confirm_saved(added.id, &added.new_hash).unwrap();
    let (_, ws) = frames(&added_source, b"a");
    let normal = ws
        .iter()
        .find(|w| format::wrap(w).unwrap().kind == 2)
        .unwrap();
    let f = format::wrap(normal).unwrap();
    let keep = RoutePlan {
        action: 1,
        kind: 2,
        source_route_id: f.route.to_vec(),
        credential_id: b"public-test-credential".to_vec(),
        protection: 0,
    };
    let fresh = vec![UnlockRoute {
        purpose: b"a".to_vec(),
        route: f.route.to_vec(),
    }];
    let rew = candidate(drive(
        &v,
        v.begin(&Request::Rewrap {
            source: added_source.clone(),
            plans: vec![PurposePlan {
                purpose: b"a".to_vec(),
                routes: vec![keep.clone()],
            }],
            fresh_unlock_routes: fresh.clone(),
        })
        .unwrap(),
        &[],
    ));
    assert!(rew.snapshot == added_source.snapshot);
    v.confirm_saved(rew.id, &rew.new_hash).unwrap();
    assert!(
        v.begin(&Request::Decrypt {
            handle,
            context: context.clone(),
            data: data.clone()
        })
        .is_ok()
    );
    let mut reprotected = keep.clone();
    reprotected.action = 2;
    let changed = candidate(drive(
        &v,
        v.begin(&Request::Rewrap {
            source: added_source.clone(),
            plans: vec![PurposePlan {
                purpose: b"a".to_vec(),
                routes: vec![reprotected.clone()],
            }],
            fresh_unlock_routes: fresh.clone(),
        })
        .unwrap(),
        &[],
    ));
    v.confirm_saved(changed.id, &changed.new_hash).unwrap();
    added_source.snapshot = changed.snapshot;
    assert_eq!(
        v.begin(&Request::Decrypt {
            handle,
            context,
            data
        })
        .unwrap_err(),
        Error::InvalidHandle
    );
    let rotated = candidate(drive(
        &v,
        v.begin(&Request::RotateDek {
            source: added_source.clone(),
            plans: vec![PurposePlan {
                purpose: b"a".to_vec(),
                routes: vec![reprotected],
            }],
            fresh_unlock_routes: fresh,
        })
        .unwrap(),
        &recovery.0,
    ));
    let mut rotated_source = Source {
        snapshot: rotated.snapshot,
        expected: added_source.expected.clone(),
    };
    rotated_source.expected.purposes[0].generation = 2;
    assert!(frames(&rotated_source, b"b") == frames(&added_source, b"b"));
    assert_eq!(
        format::data(&frames(&rotated_source, b"a").0)
            .unwrap()
            .generation,
        2
    );
    v.confirm_saved(rotated.id, &rotated.new_hash).unwrap();
    let selected = frames(&rotated_source, b"a");
    let rw = selected
        .1
        .iter()
        .find(|w| format::wrap(w).unwrap().kind == 3)
        .unwrap()
        .clone();
    let selection = vec![SelectionInput {
        context: Context {
            target: s.expected.target.clone(),
            purpose: b"a".to_vec(),
            generation: 2,
        },
        data: selected.0,
        recovery_wrap: rw,
    }];
    let recovered = drive(
        &v,
        v.begin(&Request::RecoverSelected {
            selection,
            lifetime: Lifetime::Operation,
        })
        .unwrap(),
        &recovery.0,
    );
    let StepValue::Completed {
        result: Completed::RecoveredSelected { recovered, .. },
        ..
    } = recovered.value().clone()
    else {
        panic!("expected selection")
    };
    assert_eq!(recovered.len(), 1);
    v.release_context(recovered[0].1).unwrap();
    let full = candidate(drive(
        &v,
        v.begin(&Request::Recover {
            source: rotated_source.clone(),
            plans: vec![plan(b"a"), plan(b"b"), plan(b"c")],
        })
        .unwrap(),
        &recovery.0,
    ));
    v.discard_candidate(full.id).unwrap();
    let routes = rotated_source
        .expected
        .purposes
        .iter()
        .map(|p| {
            let (_, ws) = frames(&rotated_source, &p.purpose);
            UnlockRoute {
                purpose: p.purpose.clone(),
                route: format::wrap(
                    ws.iter()
                        .find(|w| format::wrap(w).unwrap().kind == 2)
                        .unwrap(),
                )
                .unwrap()
                .route
                .to_vec(),
            }
        })
        .collect();
    let reissued = candidate(drive(
        &v,
        v.begin(&Request::ReissueRecovery {
            source: rotated_source.clone(),
            fresh_unlock_routes: routes,
        })
        .unwrap(),
        &[],
    ));
    assert!(reissued.recovery_key.is_some());
    v.discard_candidate(reissued.id).unwrap();
    let removed = candidate(
        v.begin(&Request::RemovePurpose {
            source: rotated_source.clone(),
            purposes: vec![b"c".to_vec()],
        })
        .unwrap(),
    );
    v.discard_candidate(removed.id).unwrap();
    v.destroy().unwrap();
}
#[test]
fn rejects_wrong_recovery_before_candidate_for_add_and_rotate() {
    let _guard = LOCK.lock().unwrap();
    let v = Vault::new(BUDGET).unwrap();
    let (s, recovery) = created(&v);
    let mut wrong = recovery.clone();
    wrong.0[0] ^= 1;
    for request in [
        Request::AddPurpose {
            source: s.clone(),
            purpose: input(b"c", b"new"),
        },
        {
            let (_, ws) = frames(&s, b"a");
            let w = ws
                .iter()
                .find(|w| format::wrap(w).unwrap().kind == 2)
                .unwrap();
            let id = format::wrap(w).unwrap().route.to_vec();
            let mut p = plan(b"a");
            p.routes[0].action = 2;
            p.routes[0].source_route_id = id.clone();
            Request::RotateDek {
                source: s.clone(),
                plans: vec![p],
                fresh_unlock_routes: vec![UnlockRoute {
                    purpose: b"a".to_vec(),
                    route: id,
                }],
            }
        },
    ] {
        let step = v.begin(&request).unwrap();
        let StepValue::Pending {
            operation_id,
            requests,
        } = step.value().clone()
        else {
            panic!("expected recovery input")
        };
        assert_eq!(requests[0].payload.kind(), 2);
        assert_eq!(
            v.resume(
                operation_id,
                requests[0].request_id,
                &AdapterResponse::Recovery(wrong.clone())
            )
            .unwrap_err(),
            Error::VerificationFailed
        );
    }
    // Corruption in the chosen old data must fail even when the old wrap unwraps.
    let mut broken = s.clone();
    let (d, _) = frames(&s, b"a");
    let at = broken
        .snapshot
        .windows(d.len())
        .position(|w| w == d)
        .unwrap();
    broken.snapshot[at + d.len() - 1] ^= 1;
    let step = v
        .begin(&Request::AddPurpose {
            source: broken,
            purpose: input(b"c", b"new"),
        })
        .unwrap();
    let StepValue::Pending {
        operation_id,
        requests,
    } = step.value().clone()
    else {
        panic!("expected recovery")
    };
    assert_eq!(
        v.resume(
            operation_id,
            requests[0].request_id,
            &AdapterResponse::Recovery(recovery)
        )
        .unwrap_err(),
        Error::VerificationFailed
    );
    v.destroy().unwrap();
}
#[test]
fn cancellation_references_consumption_and_tamper() {
    let _guard = LOCK.lock().unwrap();
    let v = Vault::new(BUDGET).unwrap();
    let (s, _) = created(&v);
    let request = Request::Create {
        target: b"other-target".to_vec(),
        purposes: vec![input(b"a", b"p")],
    };
    let step = v.begin(&request).unwrap();
    let StepValue::Pending {
        operation_id,
        requests,
    } = &step.value().clone()
    else {
        panic!("pending")
    };
    let (op, rid) = (*operation_id, requests[0].request_id);
    let response = AdapterResponse::Prf(Secret(PRF.to_vec()));
    assert_eq!(
        v.resume(op, rid + 1, &response).unwrap_err(),
        Error::InvalidHandle
    );
    v.cancel(op).unwrap();
    assert_eq!(
        v.resume(op, rid, &response).unwrap_err(),
        Error::InvalidHandle
    );
    drop(step);
    let step = v.begin(&request).unwrap();
    let StepValue::Pending {
        operation_id,
        requests,
    } = step.value().clone()
    else {
        panic!("pending")
    };
    assert_eq!(
        v.resume(
            operation_id,
            requests[0].request_id,
            &AdapterResponse::Prf(Secret(vec![0; 31]))
        )
        .unwrap_err(),
        Error::InvalidInput
    );
    assert_eq!(
        v.resume(operation_id, requests[0].request_id, &response)
            .unwrap_err(),
        Error::InvalidHandle
    );
    let h = unlock(&v, &s, b"a", Lifetime::Operation);
    let (mut data, _) = frames(&s, b"a");
    if let Some(b) = data.last_mut() {
        *b ^= 1;
    }
    let request = Request::Decrypt {
        handle: h,
        context: Context {
            target: s.expected.target.clone(),
            purpose: b"a".to_vec(),
            generation: 1,
        },
        data,
    };
    assert_eq!(v.begin(&request).unwrap_err(), Error::VerificationFailed);
    assert_eq!(v.begin(&request).unwrap_err(), Error::InvalidHandle);
    v.destroy().unwrap();
    assert_eq!(v.begin(&request).unwrap_err(), Error::InvalidHandle);
}
#[test]
fn shared_budget_and_result_lifetime() {
    let _guard = LOCK.lock().unwrap();
    assert_eq!(Vault::new(0).err(), Some(Error::InvalidInput));
    assert_eq!(Vault::new(1).err(), Some(Error::ResourceLimit));
    let v = Vault::new(BUDGET).unwrap();
    let step = v
        .begin(&Request::Create {
            target: b"t".to_vec(),
            purposes: vec![input(b"a", b"p")],
        })
        .unwrap();
    assert_eq!(Vault::new(BUDGET + 1).err(), Some(Error::InvalidInput));
    v.destroy().unwrap();
    drop(v);
    assert_eq!(Vault::new(BUDGET + 1).err(), Some(Error::InvalidInput));
    drop(step);
    let next = Vault::new(BUDGET + 1).unwrap();
    next.destroy().unwrap();
}
#[test]
fn password_route_and_snapshot_rejection() {
    let _guard = LOCK.lock().unwrap();
    let v = Vault::new(BUDGET).unwrap();
    let mut p = input(b"a", b"");
    p.plan.routes[0].kind = 1;
    p.plan.routes[0].credential_id.clear();
    let c = candidate(drive(
        &v,
        v.begin(&Request::Create {
            target: b"t".to_vec(),
            purposes: vec![p],
        })
        .unwrap(),
        &[],
    ));
    let mut bad = c.snapshot.clone();
    bad.push(0);
    assert_eq!(
        format::visit_snapshot(&bad, |_, _, _| Ok(())).err(),
        Some(Error::InvalidInput)
    );
    let mut bad = c.snapshot.clone();
    bad[5] = 2;
    assert_eq!(
        format::visit_snapshot(&bad, |_, _, _| Ok(())).err(),
        Some(Error::Unsupported)
    );
    v.discard_candidate(c.id).unwrap();
    v.destroy().unwrap();
}

#[test]
fn counts_are_shared_across_owners_and_released() {
    let _guard = LOCK.lock().unwrap();
    let budget = 1024 * 1024 * 1024;
    let v = Vault::new(budget).unwrap();
    let other = Vault::new(budget).unwrap();
    let mut pending = Vec::new();
    for _ in 0..32 {
        pending.push(
            v.begin(&Request::Create {
                target: b"t".to_vec(),
                purposes: vec![input(b"a", b"p")],
            })
            .unwrap(),
        );
    }
    let request = Request::Create {
        target: b"t".to_vec(),
        purposes: vec![input(b"a", b"p")],
    };
    assert_eq!(other.begin(&request).unwrap_err(), Error::ResourceLimit);
    let StepValue::Pending { operation_id, .. } = pending[0].value() else {
        panic!("pending")
    };
    v.cancel(*operation_id).unwrap();
    let step = other.begin(&request).unwrap();
    let StepValue::Pending { operation_id, .. } = step.value() else {
        panic!("pending")
    };
    other.cancel(*operation_id).unwrap();
    drop(step);
    v.destroy().unwrap();
    drop(pending);
    drop(v);
    let (s, _) = created(&other);
    let mut contexts = Vec::new();
    for _ in 0..128 {
        contexts.push(unlock(&other, &s, b"a", Lifetime::Explicit));
    }
    let (data, ws) = frames(&s, b"a");
    let wrap = ws
        .into_iter()
        .find(|w| format::wrap(w).unwrap().kind == 2)
        .unwrap();
    assert_eq!(
        other
            .begin(&Request::Unlock {
                context: Context {
                    target: s.expected.target.clone(),
                    purpose: b"a".to_vec(),
                    generation: 1
                },
                data,
                wrap,
                lifetime: Lifetime::Explicit
            })
            .unwrap_err(),
        Error::ResourceLimit
    );
    for handle in contexts {
        other.release_context(handle).unwrap();
    }
    let mut ids = Vec::new();
    for _ in 0..32 {
        ids.push(candidate(drive(&other, other.begin(&request).unwrap(), &[])).id);
    }
    let step = other.begin(&request).unwrap();
    let StepValue::Pending {
        operation_id,
        requests,
    } = step.value().clone()
    else {
        panic!("pending")
    };
    let response = AdapterResponse::Prf(Secret(PRF.to_vec()));
    let step = other
        .resume(operation_id, requests[0].request_id, &response)
        .unwrap();
    let StepValue::Pending {
        operation_id,
        requests,
    } = step.value().clone()
    else {
        panic!("pending")
    };
    assert_eq!(
        other
            .resume(operation_id, requests[0].request_id, &response)
            .unwrap_err(),
        Error::ResourceLimit
    );
    for id in ids {
        other.discard_candidate(id).unwrap();
    }
    other.destroy().unwrap();
}

#[test]
fn malformed_input_preserves_unused_key_and_owner_isolation() {
    let _guard = LOCK.lock().unwrap();
    let v = Vault::new(BUDGET).unwrap();
    let other = Vault::new(BUDGET).unwrap();
    let (s, _) = created(&v);
    let h = unlock(&v, &s, b"a", Lifetime::Operation);
    let (data, _) = frames(&s, b"a");
    let c = Context {
        target: s.expected.target.clone(),
        purpose: b"a".to_vec(),
        generation: 1,
    };
    assert_eq!(other.release_context(h), Err(Error::InvalidHandle));
    assert_eq!(
        v.begin(&Request::Decrypt {
            handle: h,
            context: c.clone(),
            data: vec![]
        })
        .unwrap_err(),
        Error::InvalidInput
    );
    assert!(
        v.begin(&Request::Decrypt {
            handle: h,
            context: c,
            data
        })
        .is_ok()
    );
    other.destroy().unwrap();
    v.destroy().unwrap();
}

#[test]
fn parser_prefixes_mutations_and_plaintext_boundaries() {
    let _guard = LOCK.lock().unwrap();
    let v = Vault::new(BUDGET).unwrap();
    let (s, _) = created(&v);
    let (data, ws) = frames(&s, b"a");
    for (raw, is_data) in [(&data, true), (&ws[0], false)] {
        for end in 0..raw.len() {
            let result = if is_data {
                format::data(&raw[..end])
            } else {
                format::wrap(&raw[..end])
            };
            assert!(result.is_err());
        }
    }
    // Bounded deterministic mutation smoke test of the production parser. This
    // does not claim sustained coverage-guided fuzzing or cryptographic validity.
    let mut seed = 1u64;
    for _ in 0..1024 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut raw = s.snapshot.clone();
        let at = (seed as usize) % raw.len();
        raw[at] ^= ((seed >> 32) as u8) | 1;
        let _ = format::visit_snapshot(&raw, |_, _, _| Ok(()));
    }
    let mut maximum = input(b"a", b"");
    maximum.plaintext = Secret(vec![0x31; format::MAX_PLAINTEXT]);
    let c = candidate(drive(
        &v,
        v.begin(&Request::Create {
            target: b"t".to_vec(),
            purposes: vec![maximum],
        })
        .unwrap(),
        &[],
    ));
    v.discard_candidate(c.id).unwrap();
    let mut too_large = input(b"a", b"");
    too_large.plaintext = Secret(vec![0; format::MAX_PLAINTEXT + 1]);
    assert_eq!(
        v.begin(&Request::Create {
            target: b"t".to_vec(),
            purposes: vec![too_large]
        })
        .unwrap_err(),
        Error::InvalidInput
    );
    v.destroy().unwrap();
}

#[test]
fn operation_key_has_only_one_concurrent_consumer_and_debug_is_redacted() {
    let _guard = LOCK.lock().unwrap();
    let v = Vault::new(BUDGET).unwrap();
    let (s, _) = created(&v);
    let handle = unlock(&v, &s, b"a", Lifetime::Operation);
    let (data, _) = frames(&s, b"a");
    let request = Request::Decrypt {
        handle,
        context: Context {
            target: s.expected.target.clone(),
            purpose: b"a".to_vec(),
            generation: 1,
        },
        data,
    };
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let v = v.clone();
        let r = request.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            v.begin(&r)
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| matches!(e, Error::Busy | Error::InvalidHandle))
    );
    assert!(format!("{s:?}").len() < 100);
    assert!(!format!("{:?}", plan(b"a")).contains("credential"));
    let response = AdapterResponse::Password(Secret(b"public-test-password".to_vec()));
    assert!(!format!("{response:?}").contains("public-test-password"));
    v.destroy().unwrap();
}
