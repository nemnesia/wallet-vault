use crate::{
    crypto,
    format::{self, Reader},
    model::Key,
    *,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

type RunResult<T> = std::result::Result<T, Halt>;
pub(crate) enum Halt {
    Error(Error),
    Pending(Box<AdapterPayload>),
}
impl From<Error> for Halt {
    fn from(e: Error) -> Self {
        Self::Error(e)
    }
}
pub(crate) struct Bundle {
    pub data: Vec<u8>,
    pub wraps: Vec<Vec<u8>>,
}
pub(crate) struct Snapshot {
    pub target: Vec<u8>,
    pub bundles: Vec<Bundle>,
}
impl Snapshot {
    fn read(source: &Source) -> Result<Self> {
        check_source(source)?;
        let mut bundles = Vec::with_capacity(source.expected.purposes.len());
        let target = format::visit_snapshot(&source.snapshot, |_, data, wraps| {
            bundles.push(Bundle {
                data: data.to_vec(),
                wraps: wraps.iter().map(|w| w.to_vec()).collect(),
            });
            Ok(())
        })?
        .to_vec();
        Ok(Self { target, bundles })
    }
    fn index(&self, purpose: &[u8]) -> Result<usize> {
        self.bundles
            .iter()
            .position(|b| format::data(&b.data).is_ok_and(|d| d.purpose == purpose))
            .ok_or(Error::ContextMismatch)
    }
    fn context(&self, i: usize) -> Result<Context> {
        let d = format::data(&self.bundles[i].data)?;
        Ok(Context {
            target: d.target.to_vec(),
            purpose: d.purpose.to_vec(),
            generation: d.generation,
        })
    }
    fn encode(&mut self) -> Result<Vec<u8>> {
        self.bundles.sort_by(|a, b| {
            format::data(&a.data)
                .map(|d| d.purpose)
                .unwrap_or_default()
                .cmp(format::data(&b.data).map(|d| d.purpose).unwrap_or_default())
        });
        let body = 2
            + self.target.len()
            + 2
            + self
                .bundles
                .iter()
                .map(|b| 4 + b.data.len() + 2 + b.wraps.iter().map(|w| 4 + w.len()).sum::<usize>())
                .sum::<usize>();
        if body + 11 > format::MAX_SNAPSHOT {
            return Err(Error::InvalidInput);
        }
        let mut out = format::start(1, body);
        format::put16(&mut out, &self.target);
        out.extend_from_slice(&(self.bundles.len() as u16).to_be_bytes());
        for bundle in &mut self.bundles {
            bundle.wraps.sort_by(|a, b| {
                format::wrap(a)
                    .map(|w| w.route)
                    .unwrap_or_default()
                    .cmp(format::wrap(b).map(|w| w.route).unwrap_or_default())
            });
            format::put32(&mut out, &bundle.data);
            out.extend_from_slice(&(bundle.wraps.len() as u16).to_be_bytes());
            for w in &bundle.wraps {
                format::put32(&mut out, w);
            }
        }
        format::visit_snapshot(&out, |_, _, _| Ok(()))?;
        Ok(out)
    }
}
pub(crate) enum Draft {
    Contexts {
        contexts: Vec<(Context, Key, Lifetime)>,
        selected: bool,
    },
    Plain(Secret),
    Candidate {
        snapshot: Vec<u8>,
        recovery_key: Option<Secret>,
        invalidated: Vec<Vec<u8>>,
    },
}
pub(crate) struct Runner<'a> {
    responses: &'a [AdapterResponse],
    tape: &'a mut Secret,
    random_pos: usize,
    response_pos: usize,
    cancelled: &'a Arc<AtomicBool>,
    os: u8,
    cache: &'a mut Vec<(usize, Key)>,
}
impl<'a> Runner<'a> {
    fn check(&self) -> RunResult<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(Error::Cancelled.into())
        } else {
            Ok(())
        }
    }
    fn random<const N: usize>(&mut self) -> RunResult<[u8; N]> {
        self.check()?;
        let end = self.random_pos.checked_add(N).ok_or(Error::ResourceLimit)?;
        if self.tape.0.len() < end {
            self.tape.0.extend_from_slice(&crypto::random::<N>()?);
        }
        let out = self.tape.0[self.random_pos..end]
            .try_into()
            .map_err(|_| Error::InternalFailure)?;
        self.random_pos = end;
        Ok(out)
    }
    fn ask(&mut self, payload: AdapterPayload) -> RunResult<AdapterResponse> {
        self.check()?;
        let required_os = match payload.kind() {
            4..=6 => 4,
            7..=9 => 5,
            _ => 0,
        };
        if required_os != 0 && self.os != required_os {
            return Err(Error::Unsupported.into());
        }
        let Some(response) = self.responses.get(self.response_pos) else {
            return Err(Halt::Pending(Box::new(payload)));
        };
        self.response_pos += 1;
        if response.kind() != payload.kind() {
            return Err(Error::InvalidInput.into());
        }
        if let AdapterResponse::Failure { error, .. } = response {
            return Err((*error).into());
        }
        validate_response(response)?;
        Ok(response.clone())
    }
    fn password(&mut self, password: &[u8], salt: &[u8]) -> RunResult<Key> {
        let index = self.response_pos;
        if let Some((_, key)) = self.cache.iter().find(|(i, _)| *i == index) {
            return Ok(key.clone());
        }
        let key = crypto::password(password, salt)?;
        self.cache.push((index, key.clone()));
        Ok(key)
    }
    fn recovery(&mut self, expected: &ExpectedSnapshot) -> RunResult<Key> {
        match self.ask(AdapterPayload::Recovery {
            expected: expected.clone(),
        })? {
            AdapterResponse::Recovery(v) => Ok(key(&v.0)?),
            _ => Err(Error::InvalidInput.into()),
        }
    }
    fn open_wrap(&mut self, c: &Context, raw: &[u8], recovery: Option<&[u8]>) -> RunResult<Key> {
        let w = format::wrap(raw)?;
        w.check(c)?;
        let route = w.route.to_vec();
        let context = c.clone();
        let ikm = match w.kind {
            1 => match self.ask(AdapterPayload::Password {
                context,
                route,
                for_protection: false,
            })? {
                AdapterResponse::Password(p) => self.password(&p.0, w.metadata)?,
                _ => return Err(Error::InvalidInput.into()),
            },
            2 => {
                let mut r = Reader::new(w.metadata);
                let credential_id = r.b16()?.to_vec();
                let input = r.take(32)?.to_vec();
                match self.ask(AdapterPayload::Prf {
                    context,
                    route,
                    credential_id,
                    input,
                })? {
                    AdapterResponse::Prf(v) => key(&v.0)?,
                    _ => return Err(Error::InvalidInput.into()),
                }
            }
            3 => key(recovery.ok_or(Error::InvalidInput)?)?,
            4 => {
                let mut r = Reader::new(w.metadata);
                let key_ref = r.b16()?.to_vec();
                return match self.ask(AdapterPayload::AndroidDecrypt {
                    context,
                    route,
                    key_ref,
                    salt: w.salt.to_vec(),
                    nonce: w.nonce.to_vec(),
                    aad: w.aad.to_vec(),
                    ciphertext: w.ciphertext.to_vec(),
                })? {
                    AdapterResponse::AndroidDecrypted(v) => Ok(key(&v.0)?),
                    _ => Err(Error::InvalidInput.into()),
                };
            }
            5 => {
                let mut r = Reader::new(w.metadata);
                let key_ref = r.b16()?.to_vec();
                let ephemeral_public_key = r.take(65)?.to_vec();
                return match self.ask(AdapterPayload::IosDecrypt {
                    context,
                    route,
                    key_ref,
                    ephemeral_public_key,
                    salt: w.salt.to_vec(),
                    nonce: w.nonce.to_vec(),
                    info: info(c, Some((w.route, 5)))?,
                    aad: w.aad.to_vec(),
                    ciphertext: w.ciphertext.to_vec(),
                })? {
                    AdapterResponse::IosDecrypted(v) => Ok(key(&v.0)?),
                    _ => Err(Error::InvalidInput.into()),
                };
            }
            _ => return Err(Error::Unsupported.into()),
        };
        let k = crypto::hkdf(&*ikm, w.salt, &info(c, Some((w.route, w.kind)))?)?;
        Ok(key(&crypto::open(&*k, w.nonce, w.aad, w.ciphertext)?)?)
    }
    fn open_data(&self, c: &Context, raw: &[u8], dek: &[u8]) -> RunResult<Secret> {
        self.check()?;
        let d = format::data(raw)?;
        d.check(c)?;
        let k = crypto::hkdf(dek, d.salt, &info(c, None)?)?;
        let mut plain = crypto::open(&*k, d.nonce, d.aad, d.ciphertext)?;
        Ok(Secret(std::mem::take(&mut *plain)))
    }
    fn data(&mut self, c: &Context, dek: &[u8], plaintext: &[u8]) -> RunResult<Vec<u8>> {
        let salt = self.random::<32>()?;
        let nonce = self.random::<12>()?;
        let mut out = prefix(c, None, &[], &salt, &nonce, plaintext.len() + 16)?;
        let k = crypto::hkdf(dek, &salt, &info(c, None)?)?;
        out.extend_from_slice(&crypto::seal(&*k, &nonce, &out, plaintext)?);
        Ok(out)
    }
    fn protect(
        &mut self,
        c: &Context,
        dek: &[u8],
        plan: Option<&RoutePlan>,
        recovery: Option<&[u8]>,
        route: Vec<u8>,
    ) -> RunResult<Vec<u8>> {
        let kind = plan.map_or(3, |p| p.kind as u8);
        let salt = self.random::<32>()?;
        let mut nonce = self.random::<12>()?;
        let mut metadata = Vec::new();
        let context = c.clone();
        let ikm = match kind {
            1 => {
                let psalt = self.random::<16>()?;
                metadata.extend_from_slice(&psalt);
                match self.ask(AdapterPayload::Password {
                    context: context.clone(),
                    route: route.clone(),
                    for_protection: true,
                })? {
                    AdapterResponse::Password(p) => Some(self.password(&p.0, &psalt)?),
                    _ => return Err(Error::InvalidInput.into()),
                }
            }
            2 => {
                let credential_id = plan.ok_or(Error::InternalFailure)?.credential_id.clone();
                let input = self.random::<32>()?.to_vec();
                format::put16(&mut metadata, &credential_id);
                metadata.extend_from_slice(&input);
                match self.ask(AdapterPayload::Prf {
                    context: context.clone(),
                    route: route.clone(),
                    credential_id,
                    input,
                })? {
                    AdapterResponse::Prf(v) => Some(key(&v.0)?),
                    _ => return Err(Error::InvalidInput.into()),
                }
            }
            3 => Some(key(recovery.ok_or(Error::InvalidInput)?)?),
            4 => {
                let protection = plan.ok_or(Error::InternalFailure)?.protection;
                match self.ask(AdapterPayload::AndroidPrepare {
                    context: context.clone(),
                    route: route.clone(),
                    protection,
                })? {
                    AdapterResponse::AndroidPrepared {
                        key_ref,
                        protection: actual,
                        nonce: generated,
                    } => {
                        if protection == 2 && actual != 2 {
                            return Err(Error::Unsupported.into());
                        }
                        format::put16(&mut metadata, &key_ref);
                        metadata.push(actual as u8);
                        nonce.copy_from_slice(&generated);
                        None
                    }
                    _ => return Err(Error::InvalidInput.into()),
                }
            }
            5 => match self.ask(AdapterPayload::IosPrepare {
                context: context.clone(),
                route: route.clone(),
            })? {
                AdapterResponse::IosPrepared {
                    key_ref,
                    ephemeral_public_key,
                } => {
                    format::put16(&mut metadata, &key_ref);
                    metadata.extend_from_slice(&ephemeral_public_key);
                    None
                }
                _ => return Err(Error::InvalidInput.into()),
            },
            _ => return Err(Error::Unsupported.into()),
        };
        let mut out = prefix(c, Some((&route, kind)), &metadata, &salt, &nonce, 48)?;
        let ciphertext = if let Some(ikm) = ikm {
            let k = crypto::hkdf(&*ikm, &salt, &info(c, Some((&route, kind)))?)?;
            crypto::seal(&*k, &nonce, &out, dek)?
        } else {
            let mut r = Reader::new(&metadata);
            let key_ref = r.b16()?.to_vec();
            let payload = if kind == 4 {
                AdapterPayload::AndroidEncrypt {
                    context,
                    route: route.clone(),
                    key_ref,
                    salt: salt.to_vec(),
                    nonce: nonce.to_vec(),
                    aad: out.clone(),
                    dek: Secret(dek.to_vec()),
                }
            } else {
                AdapterPayload::IosEncrypt {
                    context,
                    route: route.clone(),
                    key_ref,
                    salt: salt.to_vec(),
                    nonce: nonce.to_vec(),
                    info: info(c, Some((&route, kind)))?,
                    aad: out.clone(),
                    dek: Secret(dek.to_vec()),
                }
            };
            match self.ask(payload)? {
                AdapterResponse::AndroidEncrypted(v) | AdapterResponse::IosEncrypted(v) => v,
                _ => return Err(Error::InvalidInput.into()),
            }
        };
        out.extend_from_slice(&ciphertext);
        format::wrap(&out)?;
        Ok(out)
    }
    fn checked_wrap(
        &mut self,
        c: &Context,
        data: &[u8],
        raw: &[u8],
        recovery: Option<&[u8]>,
    ) -> RunResult<Key> {
        let dek = self.open_wrap(c, raw, recovery)?;
        self.open_data(c, data, &*dek)?;
        Ok(dek)
    }
    fn normal_wraps(
        &mut self,
        c: &Context,
        dek: &[u8],
        data: &[u8],
        plans: &[RoutePlan],
        old: &[Vec<u8>],
        recovery: Option<&[u8]>,
    ) -> RunResult<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(plans.len() + 1);
        for p in plans {
            let route = if p.action == 3 {
                self.random::<16>()?.to_vec()
            } else {
                p.source_route_id.clone()
            };
            if p.action == 1 {
                let w = old
                    .iter()
                    .find(|w| format::wrap(w).is_ok_and(|f| f.route == route))
                    .ok_or(Error::InvalidInput)?;
                out.push(w.clone());
                continue;
            }
            let w = self.protect(c, dek, Some(p), None, route)?;
            self.checked_wrap(c, data, &w, recovery)?;
            out.push(w);
        }
        Ok(out)
    }
    fn recovery_wrap(
        &mut self,
        c: &Context,
        dek: &[u8],
        data: &[u8],
        recovery: &[u8],
        route: Option<Vec<u8>>,
    ) -> RunResult<Vec<u8>> {
        let route = match route {
            Some(v) => v,
            None => self.random::<16>()?.to_vec(),
        };
        let w = self.protect(c, dek, None, Some(recovery), route)?;
        self.checked_wrap(c, data, &w, Some(recovery))?;
        Ok(w)
    }
}
fn key(v: &[u8]) -> Result<Key> {
    Ok(Zeroizing::new(
        v.try_into().map_err(|_| Error::InvalidInput)?,
    ))
}
pub(crate) fn info(c: &Context, route: Option<(&[u8], u8)>) -> Result<Vec<u8>> {
    let label: &[u8] = match route.map(|r| r.1) {
        None => b"data",
        Some(1) => b"password",
        Some(2) => b"prf",
        Some(3) => b"recovery",
        Some(5) => b"ios",
        _ => return Err(Error::InvalidInput),
    };
    let mut out = Vec::with_capacity(64 + c.target.len() + c.purpose.len());
    out.extend_from_slice(b"RVLT/v1/");
    out.extend_from_slice(label);
    out.push(0);
    format::put16(&mut out, &c.target);
    format::put16(&mut out, &c.purpose);
    out.extend_from_slice(&c.generation.to_be_bytes());
    if let Some((id, kind)) = route {
        out.extend_from_slice(id);
        out.push(kind);
    }
    Ok(out)
}
fn prefix(
    c: &Context,
    route: Option<(&[u8], u8)>,
    metadata: &[u8],
    salt: &[u8],
    nonce: &[u8],
    ciphertext_len: usize,
) -> Result<Vec<u8>> {
    c.validate()?;
    let body = 2
        + c.target.len()
        + 2
        + c.purpose.len()
        + 8
        + 32
        + 12
        + 4
        + ciphertext_len
        + route.map_or(0, |_| 16 + 1 + 2 + metadata.len());
    let mut out = format::start(if route.is_some() { 3 } else { 2 }, body);
    format::put16(&mut out, &c.target);
    format::put16(&mut out, &c.purpose);
    out.extend_from_slice(&c.generation.to_be_bytes());
    if let Some((id, kind)) = route {
        out.extend_from_slice(id);
        out.push(kind);
        format::put16(&mut out, metadata);
    }
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(ciphertext_len as u32).to_be_bytes());
    Ok(out)
}
pub(crate) fn validate_response(r: &AdapterResponse) -> Result<()> {
    match r {
        AdapterResponse::Password(v) => {
            format::sized(&v.0, 1, 1024)?;
            std::str::from_utf8(&v.0).map_err(|_| Error::InvalidInput)?;
        }
        AdapterResponse::Recovery(v)
        | AdapterResponse::Prf(v)
        | AdapterResponse::AndroidDecrypted(v)
        | AdapterResponse::IosDecrypted(v) => format::sized(&v.0, 32, 32)?,
        AdapterResponse::AndroidPrepared {
            key_ref,
            protection,
            nonce,
        } => {
            format::sized(key_ref, 1, 1024)?;
            format::sized(nonce, 12, 12)?;
            if !matches!(protection, 1 | 2) {
                return Err(Error::InvalidInput);
            }
        }
        AdapterResponse::AndroidEncrypted(v) | AdapterResponse::IosEncrypted(v) => {
            format::sized(v, 48, 48)?
        }
        AdapterResponse::IosPrepared {
            key_ref,
            ephemeral_public_key,
        } => {
            format::sized(key_ref, 1, 1024)?;
            format::sized(ephemeral_public_key, 65, 65)?;
            if ephemeral_public_key[0] != 4
                || p256::PublicKey::from_sec1_bytes(ephemeral_public_key).is_err()
            {
                return Err(Error::InvalidInput);
            }
        }
        AdapterResponse::Failure { kind, .. } => {
            if !(1..=9).contains(kind) {
                return Err(Error::InvalidInput);
            }
        }
    }
    Ok(())
}
fn count(n: usize, max: usize) -> Result<()> {
    if n == 0 || n > max {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
fn ordered<'a>(ids: impl Iterator<Item = &'a [u8]>) -> Result<()> {
    let mut last = &[][..];
    for item in ids {
        format::id(item)?;
        if item <= last {
            return Err(Error::InvalidInput);
        }
        last = item;
    }
    Ok(())
}
fn expected(e: &ExpectedSnapshot) -> Result<()> {
    format::id(&e.target)?;
    count(e.purposes.len(), 32)?;
    ordered(e.purposes.iter().map(|p| p.purpose.as_slice()))?;
    if e.purposes.iter().any(|p| p.generation == 0) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn source_structure(s: &Source) -> Result<()> {
    match format::visit_snapshot(&s.snapshot, |_, _, _| Ok(())) {
        Ok(_) | Err(Error::ContextMismatch) => {}
        Err(e) => return Err(e),
    };
    expected(&s.expected)
}
fn check_source(s: &Source) -> Result<()> {
    let mut n = 0;
    let mut mismatch = false;
    let target = format::visit_snapshot(&s.snapshot, |purpose, data, _| {
        let d = format::data(data)?;
        if s.expected
            .purposes
            .get(n)
            .is_none_or(|e| e.purpose != purpose || e.generation != d.generation)
        {
            mismatch = true;
        }
        n += 1;
        Ok(())
    })?;
    if mismatch || n != s.expected.purposes.len() || target != s.expected.target {
        return Err(Error::ContextMismatch);
    }
    Ok(())
}
fn plans(ps: &[PurposePlan], actions: &[u32]) -> Result<()> {
    count(ps.len(), 32)?;
    ordered(ps.iter().map(|p| p.purpose.as_slice()))?;
    for p in ps {
        count(p.routes.len(), 15)?;
        for (i, r) in p.routes.iter().enumerate() {
            if !actions.contains(&r.action) || !matches!(r.kind, 1 | 2 | 4 | 5) {
                return Err(Error::InvalidInput);
            }
            if r.action == 3 {
                if !r.source_route_id.is_empty() {
                    return Err(Error::InvalidInput);
                }
            } else {
                format::sized(&r.source_route_id, 16, 16)?;
                if p.routes[..i]
                    .iter()
                    .any(|a| a.source_route_id == r.source_route_id)
                {
                    return Err(Error::InvalidInput);
                }
            }
            if r.kind == 2 {
                format::sized(&r.credential_id, 1, 1024)?;
            } else if !r.credential_id.is_empty() {
                return Err(Error::InvalidInput);
            }
            if r.kind == 4 {
                if !matches!(r.protection, 1 | 2) {
                    return Err(Error::InvalidInput);
                }
            } else if r.protection != 0 {
                return Err(Error::InvalidInput);
            }
        }
    }
    Ok(())
}
fn unlock_routes(rs: &[UnlockRoute]) -> Result<()> {
    count(rs.len(), 32)?;
    ordered(rs.iter().map(|r| r.purpose.as_slice()))?;
    for r in rs {
        format::sized(&r.route, 16, 16)?;
    }
    Ok(())
}
pub(crate) fn validate(request: &Request) -> Result<()> {
    match request {
        Request::Create { target, purposes } => {
            format::id(target)?;
            count(purposes.len(), 32)?;
            ordered(purposes.iter().map(|p| p.plan.purpose.as_slice()))?;
            for p in purposes {
                plans(std::slice::from_ref(&p.plan), &[3])?;
                format::sized(&p.plaintext.0, 0, format::MAX_PLAINTEXT)?;
            }
        }
        Request::AddPurpose { source, purpose } => {
            source_structure(source)?;
            plans(std::slice::from_ref(&purpose.plan), &[3])?;
            format::sized(&purpose.plaintext.0, 0, format::MAX_PLAINTEXT)?;
        }
        Request::RemovePurpose { source, purposes } => {
            source_structure(source)?;
            count(purposes.len(), 32)?;
            ordered(purposes.iter().map(|p| p.as_slice()))?;
        }
        Request::Unlock {
            context,
            data,
            wrap,
            ..
        } => {
            context.validate()?;
            format::data(data)?;
            format::wrap(wrap)?;
        }
        Request::Decrypt { context, data, .. } => {
            context.validate()?;
            format::data(data)?;
        }
        Request::ReplaceData {
            source,
            purpose,
            plaintext,
            ..
        } => {
            source_structure(source)?;
            format::id(purpose)?;
            format::sized(&plaintext.0, 0, format::MAX_PLAINTEXT)?;
        }
        Request::Rewrap {
            source,
            plans: ps,
            fresh_unlock_routes: rs,
        }
        | Request::RotateDek {
            source,
            plans: ps,
            fresh_unlock_routes: rs,
        } => {
            source_structure(source)?;
            plans(
                ps,
                if matches!(request, Request::Rewrap { .. }) {
                    &[1, 2, 3]
                } else {
                    &[2, 3]
                },
            )?;
            unlock_routes(rs)?;
            if ps.len() != rs.len() || ps.iter().zip(rs).any(|(p, r)| p.purpose != r.purpose) {
                return Err(Error::InvalidInput);
            }
        }
        Request::Recover { source, plans: ps } => {
            source_structure(source)?;
            plans(ps, &[2, 3])?;
        }
        Request::ReissueRecovery {
            source,
            fresh_unlock_routes: rs,
        } => {
            source_structure(source)?;
            unlock_routes(rs)?;
        }
        Request::RecoverSelected { selection, .. } => {
            count(selection.len(), 32)?;
            ordered(selection.iter().map(|i| i.context.purpose.as_slice()))?;
            for i in selection {
                i.context.validate()?;
                format::data(&i.data)?;
                let w = format::wrap(&i.recovery_wrap)?;
                if w.kind != 3 {
                    return Err(Error::InvalidInput);
                }
            }
        }
    }
    Ok(())
}
fn check_plans(s: &Snapshot, ps: &[PurposePlan]) -> Result<()> {
    for p in ps {
        let i = s.index(&p.purpose)?;
        for r in &p.routes {
            if r.action == 3 {
                continue;
            }
            let raw = s.bundles[i]
                .wraps
                .iter()
                .find(|w| format::wrap(w).is_ok_and(|w| w.route == r.source_route_id))
                .ok_or(Error::InvalidInput)?;
            let w = format::wrap(raw)?;
            if w.kind as u32 != r.kind || w.kind == 3 {
                return Err(Error::InvalidInput);
            }
            if r.action == 1 {
                if w.kind == 2 {
                    let mut reader = Reader::new(w.metadata);
                    if reader.b16()? != r.credential_id {
                        return Err(Error::InvalidInput);
                    }
                }
                if w.kind == 4 {
                    let mut reader = Reader::new(w.metadata);
                    reader.b16()?;
                    if reader.u8()? as u32 != r.protection {
                        return Err(Error::InvalidInput);
                    }
                }
            }
        }
    }
    Ok(())
}
fn route<'a>(s: &'a Snapshot, r: &UnlockRoute) -> Result<&'a [u8]> {
    let i = s.index(&r.purpose)?;
    s.bundles[i]
        .wraps
        .iter()
        .find(|w| format::wrap(w).is_ok_and(|w| w.route == r.route))
        .map(|v| v.as_slice())
        .ok_or(Error::InvalidInput)
}
fn recovery_route(b: &Bundle) -> Result<&[u8]> {
    b.wraps
        .iter()
        .find(|w| format::wrap(w).is_ok_and(|w| w.kind == 3))
        .map(|v| v.as_slice())
        .ok_or(Error::InvalidInput)
}
fn recover_expected(selection: &[SelectionInput]) -> ExpectedSnapshot {
    ExpectedSnapshot {
        target: selection[0].context.target.clone(),
        purposes: selection
            .iter()
            .map(|i| Expectation {
                purpose: i.context.purpose.clone(),
                generation: i.context.generation,
            })
            .collect(),
    }
}
fn complete_candidate(
    snapshot: &mut Snapshot,
    recovery_key: Option<Secret>,
    invalidated: Vec<Vec<u8>>,
) -> RunResult<Draft> {
    Ok(Draft::Candidate {
        snapshot: snapshot.encode()?,
        recovery_key,
        invalidated,
    })
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    request: &Request,
    responses: &[AdapterResponse],
    tape: &mut Secret,
    cancelled: &Arc<AtomicBool>,
    context_key: Option<&Key>,
    os: u8,
    cache: &mut Vec<(usize, Key)>,
) -> RunResult<Draft> {
    let mut r = Runner {
        responses,
        tape,
        random_pos: 0,
        response_pos: 0,
        cancelled,
        os,
        cache,
    };
    r.check()?;
    match request {
        Request::Create { target, purposes } => {
            let recovery = Zeroizing::new(r.random::<32>()?);
            let mut snapshot = Snapshot {
                target: target.clone(),
                bundles: Vec::with_capacity(purposes.len()),
            };
            for p in purposes {
                let c = Context {
                    target: target.clone(),
                    purpose: p.plan.purpose.clone(),
                    generation: 1,
                };
                let dek = Zeroizing::new(r.random::<32>()?);
                let data = r.data(&c, &*dek, &p.plaintext.0)?;
                let mut wraps = r.normal_wraps(&c, &*dek, &data, &p.plan.routes, &[], None)?;
                wraps.push(r.recovery_wrap(&c, &*dek, &data, &*recovery, None)?);
                snapshot.bundles.push(Bundle { data, wraps });
            }
            complete_candidate(&mut snapshot, Some(Secret(recovery.to_vec())), vec![])
        }
        Request::Unlock {
            context,
            data,
            wrap,
            lifetime,
        } => {
            format::data(data)?.check(context)?;
            let w = format::wrap(wrap)?;
            w.check(context)?;
            let recovery = if w.kind == 3 {
                Some(r.recovery(&ExpectedSnapshot {
                    target: context.target.clone(),
                    purposes: vec![Expectation {
                        purpose: context.purpose.clone(),
                        generation: context.generation,
                    }],
                })?)
            } else {
                None
            };
            let dek = r.checked_wrap(
                context,
                data,
                wrap,
                recovery.as_deref().map(|k| k.as_slice()),
            )?;
            Ok(Draft::Contexts {
                contexts: vec![(context.clone(), dek, *lifetime)],
                selected: false,
            })
        }
        Request::Decrypt { context, data, .. } => Ok(Draft::Plain(r.open_data(
            context,
            data,
            &**context_key.ok_or(Error::InvalidHandle)?,
        )?)),
        Request::RecoverSelected {
            selection,
            lifetime,
        } => {
            let e = recover_expected(selection);
            for i in selection {
                if i.context.target != e.target {
                    return Err(Error::ContextMismatch.into());
                }
                format::data(&i.data)?.check(&i.context)?;
                format::wrap(&i.recovery_wrap)?.check(&i.context)?;
            }
            let recovery = r.recovery(&e)?;
            let mut contexts = Vec::with_capacity(selection.len());
            for i in selection {
                let dek =
                    r.checked_wrap(&i.context, &i.data, &i.recovery_wrap, Some(&*recovery))?;
                contexts.push((i.context.clone(), dek, *lifetime));
            }
            Ok(Draft::Contexts {
                contexts,
                selected: true,
            })
        }
        Request::AddPurpose { source, purpose } => {
            let mut s = Snapshot::read(source)?;
            if s.bundles.len() >= 32 || s.index(&purpose.plan.purpose).is_ok() {
                return Err(Error::InvalidInput.into());
            }
            let recovery = r.recovery(&source.expected)?;
            r.checked_wrap(
                &s.context(0)?,
                &s.bundles[0].data,
                recovery_route(&s.bundles[0])?,
                Some(&*recovery),
            )?;
            let c = Context {
                target: s.target.clone(),
                purpose: purpose.plan.purpose.clone(),
                generation: 1,
            };
            let dek = Zeroizing::new(r.random::<32>()?);
            let data = r.data(&c, &*dek, &purpose.plaintext.0)?;
            let mut wraps = r.normal_wraps(&c, &*dek, &data, &purpose.plan.routes, &[], None)?;
            wraps.push(r.recovery_wrap(&c, &*dek, &data, &*recovery, None)?);
            s.bundles.push(Bundle { data, wraps });
            complete_candidate(&mut s, None, vec![])
        }
        Request::RemovePurpose { source, purposes } => {
            let mut s = Snapshot::read(source)?;
            if purposes.len() >= s.bundles.len() {
                return Err(Error::InvalidInput.into());
            }
            for p in purposes {
                s.index(p)?;
            }
            s.bundles.retain(|b| {
                format::data(&b.data).is_ok_and(|d| !purposes.iter().any(|p| p == d.purpose))
            });
            complete_candidate(&mut s, None, purposes.clone())
        }
        Request::ReplaceData {
            source,
            purpose,
            plaintext,
            ..
        } => {
            let mut s = Snapshot::read(source)?;
            let i = s.index(purpose)?;
            let c = s.context(i)?;
            let dek = context_key.ok_or(Error::InvalidHandle)?;
            r.open_data(&c, &s.bundles[i].data, &**dek)?;
            s.bundles[i].data = r.data(&c, &**dek, &plaintext.0)?;
            complete_candidate(&mut s, None, vec![])
        }
        Request::Rewrap {
            source,
            plans: ps,
            fresh_unlock_routes: rs,
        }
        | Request::RotateDek {
            source,
            plans: ps,
            fresh_unlock_routes: rs,
        } => {
            let rotate = matches!(request, Request::RotateDek { .. });
            let mut s = Snapshot::read(source)?;
            check_plans(&s, ps)?;
            for u in rs {
                route(&s, u)?;
            }
            if rotate {
                for p in ps {
                    if s.context(s.index(&p.purpose)?)?.generation == u64::MAX {
                        return Err(Error::InvalidInput.into());
                    }
                }
            }
            let needs_recovery = rotate
                || rs.iter().any(|u| {
                    route(&s, u).is_ok_and(|w| format::wrap(w).is_ok_and(|w| w.kind == 3))
                });
            let recovery = if needs_recovery {
                Some(r.recovery(&source.expected)?)
            } else {
                None
            };
            if rotate {
                let i = s.index(&ps[0].purpose)?;
                r.checked_wrap(
                    &s.context(i)?,
                    &s.bundles[i].data,
                    recovery_route(&s.bundles[i])?,
                    recovery.as_deref().map(|v| v.as_slice()),
                )?;
            }
            let mut invalidated = Vec::new();
            for (p, u) in ps.iter().zip(rs) {
                let i = s.index(&p.purpose)?;
                let mut c = s.context(i)?;
                let old = r.checked_wrap(
                    &c,
                    &s.bundles[i].data,
                    route(&s, u)?,
                    recovery.as_deref().map(|v| v.as_slice()),
                )?;
                let dek = if rotate {
                    Zeroizing::new(r.random::<32>()?)
                } else {
                    old.clone()
                };
                if rotate {
                    let plaintext = r.open_data(&c, &s.bundles[i].data, &*old)?;
                    c.generation += 1;
                    s.bundles[i].data = r.data(&c, &*dek, &plaintext.0)?;
                }
                let mut wraps = r.normal_wraps(
                    &c,
                    &*dek,
                    &s.bundles[i].data,
                    &p.routes,
                    &s.bundles[i].wraps,
                    recovery.as_deref().map(|v| v.as_slice()),
                )?;
                for w in &s.bundles[i].wraps {
                    let f = format::wrap(w)?;
                    if f.kind == 3 {
                        wraps.push(if rotate {
                            r.recovery_wrap(
                                &c,
                                &*dek,
                                &s.bundles[i].data,
                                &**recovery.as_ref().ok_or(Error::InvalidInput)?,
                                Some(f.route.to_vec()),
                            )?
                        } else {
                            w.clone()
                        });
                    }
                }
                wraps.sort_by(|a, b| {
                    format::wrap(a)
                        .map(|w| w.route)
                        .unwrap_or_default()
                        .cmp(format::wrap(b).map(|w| w.route).unwrap_or_default())
                });
                if rotate || wraps != s.bundles[i].wraps {
                    invalidated.push(p.purpose.clone());
                }
                s.bundles[i].wraps = wraps;
            }
            complete_candidate(&mut s, None, invalidated)
        }
        Request::Recover { source, plans: ps } => {
            let mut s = Snapshot::read(source)?;
            check_plans(&s, ps)?;
            if ps.len() != s.bundles.len()
                || ps
                    .iter()
                    .zip(&source.expected.purposes)
                    .any(|(p, e)| p.purpose != e.purpose)
            {
                return Err(Error::ContextMismatch.into());
            }
            let recovery = r.recovery(&source.expected)?;
            for (i, p) in ps.iter().enumerate() {
                let c = s.context(i)?;
                let dek = r.checked_wrap(
                    &c,
                    &s.bundles[i].data,
                    recovery_route(&s.bundles[i])?,
                    Some(&*recovery),
                )?;
                let mut wraps = r.normal_wraps(
                    &c,
                    &*dek,
                    &s.bundles[i].data,
                    &p.routes,
                    &s.bundles[i].wraps,
                    None,
                )?;
                wraps.extend(
                    s.bundles[i]
                        .wraps
                        .iter()
                        .filter(|w| format::wrap(w).is_ok_and(|w| w.kind == 3))
                        .cloned(),
                );
                s.bundles[i].wraps = wraps;
            }
            complete_candidate(&mut s, None, ps.iter().map(|p| p.purpose.clone()).collect())
        }
        Request::ReissueRecovery {
            source,
            fresh_unlock_routes: rs,
        } => {
            let mut s = Snapshot::read(source)?;
            if rs.len() != s.bundles.len()
                || rs
                    .iter()
                    .zip(&source.expected.purposes)
                    .any(|(r, e)| r.purpose != e.purpose)
            {
                return Err(Error::ContextMismatch.into());
            }
            for u in rs {
                route(&s, u)?;
            }
            let needs_old = rs
                .iter()
                .any(|u| route(&s, u).is_ok_and(|w| format::wrap(w).is_ok_and(|w| w.kind == 3)));
            let old = if needs_old {
                Some(r.recovery(&source.expected)?)
            } else {
                None
            };
            let recovery = Zeroizing::new(r.random::<32>()?);
            for (i, u) in rs.iter().enumerate() {
                let c = s.context(i)?;
                let dek = r.checked_wrap(
                    &c,
                    &s.bundles[i].data,
                    route(&s, u)?,
                    old.as_deref().map(|v| v.as_slice()),
                )?;
                let mut wraps = Vec::with_capacity(s.bundles[i].wraps.len());
                for w in &s.bundles[i].wraps {
                    let f = format::wrap(w)?;
                    wraps.push(if f.kind == 3 {
                        r.recovery_wrap(
                            &c,
                            &*dek,
                            &s.bundles[i].data,
                            &*recovery,
                            Some(f.route.to_vec()),
                        )?
                    } else {
                        w.clone()
                    });
                }
                s.bundles[i].wraps = wraps;
            }
            complete_candidate(
                &mut s,
                Some(Secret(recovery.to_vec())),
                rs.iter().map(|u| u.purpose.clone()).collect(),
            )
        }
    }
}
/// Conservative upper bound for heap owned during a replay, including retained responses
/// and transient copies. Container overhead is bounded by 32 purposes / 16 routes.
pub(crate) fn workspace(request: &Request) -> Result<usize> {
    fn route(p: &RoutePlan) -> usize {
        p.source_route_id.capacity() + p.credential_id.capacity() + 64
    }
    fn plan(p: &PurposePlan) -> usize {
        p.purpose.capacity()
            + p.routes.iter().map(route).sum::<usize>()
            + p.routes.capacity() * std::mem::size_of::<RoutePlan>()
    }
    fn source(s: &Source) -> usize {
        s.snapshot.capacity()
            + s.expected.target.capacity()
            + s.expected
                .purposes
                .iter()
                .map(|p| p.purpose.capacity() + 64)
                .sum::<usize>()
    }
    let n = match request {
        Request::Create { target, purposes } => {
            target.capacity()
                + purposes
                    .iter()
                    .map(|p| plan(&p.plan) + p.plaintext.0.capacity())
                    .sum::<usize>()
        }
        Request::AddPurpose {
            source: s,
            purpose: p,
        } => source(s) + plan(&p.plan) + p.plaintext.0.capacity(),
        Request::RemovePurpose {
            source: s,
            purposes,
        } => source(s) + purposes.iter().map(|p| p.capacity() + 32).sum::<usize>(),
        Request::Unlock {
            context,
            data,
            wrap,
            ..
        } => {
            context.target.capacity()
                + context.purpose.capacity()
                + data.capacity()
                + wrap.capacity()
        }
        Request::Decrypt { context, data, .. } => {
            context.target.capacity() + context.purpose.capacity() + data.capacity()
        }
        Request::ReplaceData {
            source: s,
            purpose,
            plaintext,
            ..
        } => source(s) + purpose.capacity() + plaintext.0.capacity(),
        Request::Rewrap {
            source: s,
            plans: ps,
            fresh_unlock_routes: rs,
        }
        | Request::RotateDek {
            source: s,
            plans: ps,
            fresh_unlock_routes: rs,
        } => {
            source(s)
                + ps.iter().map(plan).sum::<usize>()
                + rs.iter()
                    .map(|u| u.purpose.capacity() + u.route.capacity() + 64)
                    .sum::<usize>()
        }
        Request::Recover {
            source: s,
            plans: ps,
        } => source(s) + ps.iter().map(plan).sum::<usize>(),
        Request::ReissueRecovery {
            source: s,
            fresh_unlock_routes: rs,
        } => {
            source(s)
                + rs.iter()
                    .map(|u| u.purpose.capacity() + u.route.capacity() + 64)
                    .sum::<usize>()
        }
        Request::RecoverSelected { selection, .. } => selection
            .iter()
            .map(|i| {
                i.context.target.capacity()
                    + i.context.purpose.capacity()
                    + i.data.capacity()
                    + i.recovery_wrap.capacity()
                    + 128
            })
            .sum(),
    };
    n.checked_mul(64)
        .and_then(|v| v.checked_add(8 * 1024 * 1024))
        .ok_or(Error::ResourceLimit)
}
pub(crate) fn needs_kdf(request: &Request) -> bool {
    fn plans(ps: &[PurposePlan]) -> bool {
        ps.iter()
            .any(|p| p.routes.iter().any(|r| r.kind == 1 && r.action != 1))
    }
    fn routes(s: &Source, rs: &[UnlockRoute]) -> bool {
        let mut yes = false;
        let _ = format::visit_snapshot(&s.snapshot, |purpose, _, ws| {
            if let Some(u) = rs.iter().find(|u| u.purpose == purpose) {
                yes |= ws
                    .iter()
                    .any(|w| format::wrap(w).is_ok_and(|w| w.route == u.route && w.kind == 1));
            }
            Ok(())
        });
        yes
    }
    match request {
        Request::Create { purposes, .. } => purposes
            .iter()
            .any(|p| plans(std::slice::from_ref(&p.plan))),
        Request::AddPurpose { purpose, .. } => plans(std::slice::from_ref(&purpose.plan)),
        Request::Unlock { wrap, .. } => format::wrap(wrap).is_ok_and(|w| w.kind == 1),
        Request::Rewrap {
            source,
            plans: ps,
            fresh_unlock_routes: rs,
        }
        | Request::RotateDek {
            source,
            plans: ps,
            fresh_unlock_routes: rs,
        } => routes(source, rs) || plans(ps),
        Request::Recover { plans: ps, .. } => plans(ps),
        Request::ReissueRecovery {
            source,
            fresh_unlock_routes,
        } => routes(source, fresh_unlock_routes),
        _ => false,
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn native_stage_contract_uses_one_fresh_key_per_new_wrap() {
        // Test double, not evidence of hardware protection, ECDH or authentication.
        for kind in [4, 5] {
            let request = Request::Create {
                target: b"public-os-target".to_vec(),
                purposes: vec![PurposeInput {
                    plan: PurposePlan {
                        purpose: b"a".to_vec(),
                        routes: vec![RoutePlan {
                            action: 3,
                            kind,
                            source_route_id: vec![],
                            credential_id: vec![],
                            protection: if kind == 4 { 2 } else { 0 },
                        }],
                    },
                    plaintext: Secret(b"public test payload".to_vec()),
                }],
            };
            validate(&request).unwrap();
            let cancelled = Arc::new(AtomicBool::new(false));
            let mut responses = Vec::new();
            let mut tape = Secret::default();
            let mut cache = Vec::new();
            let mut encryptions = BTreeMap::<Vec<u8>, usize>::new();
            let mut prepared = 0;
            loop {
                match run(
                    &request, &responses, &mut tape, &cancelled, None, kind as u8, &mut cache,
                ) {
                    Ok(Draft::Candidate { snapshot, .. }) => {
                        format::visit_snapshot(&snapshot, |_, _, _| Ok(())).unwrap();
                        break;
                    }
                    Err(Halt::Pending(payload)) => {
                        let response = match *payload {
                            AdapterPayload::AndroidPrepare { protection, .. } => {
                                assert_eq!(protection, 2);
                                prepared += 1;
                                AdapterResponse::AndroidPrepared {
                                    key_ref: format!("public-key-{prepared}").into_bytes(),
                                    protection: 2,
                                    nonce: vec![0x41; 12],
                                }
                            }
                            AdapterPayload::IosPrepare { .. } => {
                                prepared += 1;
                                AdapterResponse::IosPrepared{key_ref:format!("public-key-{prepared}").into_bytes(),ephemeral_public_key:hex::decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap()}
                            }
                            AdapterPayload::AndroidEncrypt {
                                key_ref,
                                nonce,
                                aad,
                                dek,
                                ..
                            } => {
                                *encryptions.entry(key_ref).or_default() += 1;
                                AdapterResponse::AndroidEncrypted(
                                    crypto::seal(&[0x42; 32], &nonce, &aad, &dek.0).unwrap(),
                                )
                            }
                            AdapterPayload::AndroidDecrypt {
                                nonce,
                                aad,
                                ciphertext,
                                ..
                            } => AdapterResponse::AndroidDecrypted(Secret(
                                crypto::open(&[0x42; 32], &nonce, &aad, &ciphertext)
                                    .unwrap()
                                    .to_vec(),
                            )),
                            AdapterPayload::IosEncrypt {
                                key_ref,
                                salt,
                                nonce,
                                info,
                                aad,
                                dek,
                                ..
                            } => {
                                *encryptions.entry(key_ref).or_default() += 1;
                                let k = crypto::hkdf(&[0x43; 32], &salt, &info).unwrap();
                                AdapterResponse::IosEncrypted(
                                    crypto::seal(&*k, &nonce, &aad, &dek.0).unwrap(),
                                )
                            }
                            AdapterPayload::IosDecrypt {
                                salt,
                                nonce,
                                info,
                                aad,
                                ciphertext,
                                ..
                            } => {
                                let k = crypto::hkdf(&[0x43; 32], &salt, &info).unwrap();
                                AdapterResponse::IosDecrypted(Secret(
                                    crypto::open(&*k, &nonce, &aad, &ciphertext)
                                        .unwrap()
                                        .to_vec(),
                                ))
                            }
                            _ => panic!("unexpected adapter stage"),
                        };
                        responses.push(response);
                    }
                    _ => panic!("unexpected operation outcome"),
                }
            }
            assert_eq!(prepared, 1);
            assert!(encryptions.values().all(|n| *n == 1));
        }
    }
}
