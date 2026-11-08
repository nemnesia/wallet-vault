# Test data

All identifiers, payloads, passwords and deterministic PRF inputs in these tests
are public, non-production test-only values defined in the test source. They are
not user credentials or device-generated secrets. Never reuse them in production.
Generated Recovery Keys stay in test memory and are neither printed nor stored.

Primitive vectors use RFC 5869 test case 1 and the NIST AES-256-GCM empty-message
vector. Composite frame fixtures are generated independently with Python
cryptography; see `tools/generate_vectors.py` for provenance and comparison scope.
