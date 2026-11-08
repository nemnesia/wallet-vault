use crate::{Error, Result};
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub(crate) struct Budget {
    limit: usize,
    used: Mutex<usize>,
    counts: Mutex<[usize; 3]>,
    pub crypto: Mutex<()>,
}
static SHARED: OnceLock<Mutex<Weak<Budget>>> = OnceLock::new();
pub(crate) struct Reservation {
    budget: Arc<Budget>,
    size: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut used) = self.budget.used.lock() {
            *used -= self.size;
        }
    }
}
pub(crate) struct Slot {
    budget: Arc<Budget>,
    kind: usize,
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.budget.counts.lock() {
            counts[self.kind] -= 1;
        }
    }
}
impl Budget {
    pub fn shared(limit: u64) -> Result<Arc<Self>> {
        let limit = usize::try_from(limit).map_err(|_| Error::InvalidInput)?;
        if limit == 0 || limit > isize::MAX as usize {
            return Err(Error::InvalidInput);
        }
        if limit < 8192 {
            return Err(Error::ResourceLimit);
        }
        let mut global = SHARED
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .map_err(|_| Error::InternalFailure)?;
        if let Some(budget) = global.upgrade() {
            if budget.limit != limit {
                return Err(Error::InvalidInput);
            }
            return Ok(budget);
        }
        let budget = Arc::new(Self {
            limit,
            used: Mutex::new(0),
            counts: Mutex::new([0; 3]),
            crypto: Mutex::new(()),
        });
        *global = Arc::downgrade(&budget);
        Ok(budget)
    }
    pub fn reserve(self: &Arc<Self>, size: usize) -> Result<Reservation> {
        let mut used = self.used.lock().map_err(|_| Error::InternalFailure)?;
        let next = used.checked_add(size).ok_or(Error::ResourceLimit)?;
        if next > self.limit {
            return Err(Error::ResourceLimit);
        }
        *used = next;
        Ok(Reservation {
            budget: self.clone(),
            size,
        })
    }
    pub fn slot(self: &Arc<Self>, kind: usize) -> Result<Slot> {
        let mut counts = self.counts.lock().map_err(|_| Error::InternalFailure)?;
        if counts[kind] >= [128, 32, 32][kind] {
            return Err(Error::ResourceLimit);
        }
        counts[kind] += 1;
        Ok(Slot {
            budget: self.clone(),
            kind,
        })
    }
}
