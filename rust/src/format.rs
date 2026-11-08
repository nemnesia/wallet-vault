//! Strict, allocation-free readers for the version 1 persistence format.
use crate::{Context, Error, Result};

pub const MAX_PLAINTEXT: usize = 1_048_576;
pub const MAX_SNAPSHOT: usize = 67_108_864;
pub const MAX_PURPOSES: usize = 32;
pub const MAX_ROUTES: usize = 16;
pub const HEADER: usize = 11;

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::InvalidInput)?;
        let b = self.bytes.get(self.pos..end).ok_or(Error::InvalidInput)?;
        self.pos = end;
        Ok(b)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<usize> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| Error::InvalidInput)?) as usize)
    }
    pub(crate) fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| Error::InvalidInput)?) as usize)
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::InvalidInput)?,
        ))
    }
    pub(crate) fn b16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
    pub(crate) fn f32(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()?;
        self.take(n)
    }
    pub(crate) fn end(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
}
pub(crate) fn id(bytes: &[u8]) -> Result<()> {
    sized(bytes, 1, 255)
}
pub(crate) fn sized(bytes: &[u8], min: usize, max: usize) -> Result<()> {
    if (min..=max).contains(&bytes.len()) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}
fn header(bytes: &[u8], kind: u8) -> Result<Reader<'_>> {
    let mut r = Reader::new(bytes);
    if r.take(4)? != b"RVLT" {
        return Err(Error::InvalidInput);
    }
    if r.u16()? != 1 {
        return Err(Error::Unsupported);
    }
    let t = r.u8()?;
    if !(1..=3).contains(&t) {
        return Err(Error::Unsupported);
    }
    if t != kind {
        return Err(Error::InvalidInput);
    }
    let n = r.u32()?;
    if n != bytes.len().checked_sub(HEADER).ok_or(Error::InvalidInput)? {
        return Err(Error::InvalidInput);
    }
    Ok(r)
}
#[derive(Clone, Copy)]
pub struct Frame<'a> {
    pub target: &'a [u8],
    pub purpose: &'a [u8],
    pub generation: u64,
    pub route: &'a [u8],
    pub kind: u8,
    pub metadata: &'a [u8],
    pub salt: &'a [u8],
    pub nonce: &'a [u8],
    pub aad: &'a [u8],
    pub ciphertext: &'a [u8],
}
impl Frame<'_> {
    pub fn check(&self, c: &Context) -> Result<()> {
        if self.target == c.target && self.purpose == c.purpose && self.generation == c.generation {
            Ok(())
        } else {
            Err(Error::ContextMismatch)
        }
    }
}
pub fn data(bytes: &[u8]) -> Result<Frame<'_>> {
    frame(bytes, false)
}
pub fn wrap(bytes: &[u8]) -> Result<Frame<'_>> {
    frame(bytes, true)
}
fn frame(bytes: &[u8], is_wrap: bool) -> Result<Frame<'_>> {
    // The maximum header/metadata sizes are bounded before inspecting the frame.
    if bytes.len() > MAX_PLAINTEXT + 4096 {
        return Err(Error::InvalidInput);
    }
    let mut r = header(bytes, if is_wrap { 3 } else { 2 })?;
    let target = r.b16()?;
    id(target)?;
    let purpose = r.b16()?;
    id(purpose)?;
    let generation = r.u64()?;
    if generation == 0 {
        return Err(Error::InvalidInput);
    }
    let (route, kind, metadata) = if is_wrap {
        let route = r.take(16)?;
        let kind = r.u8()?;
        if !(1..=5).contains(&kind) {
            return Err(Error::Unsupported);
        }
        let m = r.b16()?;
        validate_metadata(kind, m)?;
        (route, kind, m)
    } else {
        (&[][..], 0, &[][..])
    };
    let salt = r.take(32)?;
    let nonce = r.take(12)?;
    let n = r.u32()?;
    if (is_wrap && n != 48) || (!is_wrap && !(16..=MAX_PLAINTEXT + 16).contains(&n)) {
        return Err(Error::InvalidInput);
    }
    let aad = &bytes[..r.pos];
    let ciphertext = r.take(n)?;
    r.end()?;
    Ok(Frame {
        target,
        purpose,
        generation,
        route,
        kind,
        metadata,
        salt,
        nonce,
        aad,
        ciphertext,
    })
}
pub(crate) fn validate_metadata(kind: u8, metadata: &[u8]) -> Result<()> {
    let mut r = Reader::new(metadata);
    match kind {
        1 => {
            r.take(16)?;
        }
        2 => {
            sized(r.b16()?, 1, 1024)?;
            r.take(32)?;
        }
        3 => {}
        4 => {
            sized(r.b16()?, 1, 1024)?;
            if !matches!(r.u8()?, 1 | 2) {
                return Err(Error::InvalidInput);
            }
        }
        5 => {
            sized(r.b16()?, 1, 1024)?;
            let point = r.take(65)?;
            if point[0] != 4 || p256::PublicKey::from_sec1_bytes(point).is_err() {
                return Err(Error::InvalidInput);
            }
        }
        _ => return Err(Error::Unsupported),
    }
    r.end()
}
/// Walks a fully validated snapshot without allocating or interpreting plaintext.
pub fn visit_snapshot<'a>(
    bytes: &'a [u8],
    mut visit: impl FnMut(&'a [u8], &'a [u8], &[&'a [u8]]) -> Result<()>,
) -> Result<&'a [u8]> {
    if bytes.len() > MAX_SNAPSHOT {
        return Err(Error::InvalidInput);
    }
    let mut r = header(bytes, 1)?;
    let target = r.b16()?;
    id(target)?;
    let count = r.u16()?;
    if !(1..=MAX_PURPOSES).contains(&count) {
        return Err(Error::InvalidInput);
    }
    let mut previous = &[][..];
    let mut mismatch = false;
    for _ in 0..count {
        let raw = r.f32()?;
        let d = data(raw)?;
        if d.purpose <= previous {
            return Err(Error::InvalidInput);
        }
        previous = d.purpose;
        let n = r.u16()?;
        if !(2..=MAX_ROUTES).contains(&n) {
            return Err(Error::InvalidInput);
        }
        let mut wraps = [&[][..]; MAX_ROUTES];
        let mut last_route = &[][..];
        let mut recovery = false;
        let mut normal = false;
        for slot in &mut wraps[..n] {
            *slot = r.f32()?;
            let w = wrap(slot)?;
            if w.route <= last_route {
                return Err(Error::InvalidInput);
            }
            last_route = w.route;
            if w.target != d.target || w.purpose != d.purpose || w.generation != d.generation {
                mismatch = true;
            }
            recovery |= w.kind == 3;
            normal |= w.kind != 3;
        }
        if !recovery || !normal {
            return Err(Error::InvalidInput);
        }
        if d.target != target {
            mismatch = true;
        }
        visit(d.purpose, raw, &wraps[..n])?;
    }
    r.end()?;
    if mismatch {
        return Err(Error::ContextMismatch);
    }
    Ok(target)
}
pub(crate) fn put16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}
pub(crate) fn put32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
pub(crate) fn start(kind: u8, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body_len);
    out.extend_from_slice(b"RVLT");
    out.extend_from_slice(&1u16.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out
}
