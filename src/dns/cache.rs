use crate::config::{ALLOWLIST_MAX, Config};
use crate::eligibility::NumericAddr;
use std::fmt;
use std::net::Ipv4Addr;

/// Fixed address capacity per configured name and family.
pub const MAX_ADDRESSES: usize = 16;

/// Stale DNS authorization grace after TTL expiry, in seconds.
pub const STALE_GRACE: u64 = 259_200;

/// How long a stale entry may still be served past its freshness deadline,
/// in seconds (RT-006). Beyond this window a stale entry is no longer served
/// even though it remains in the cache until retirement.
pub const STALE_SERVING_WINDOW: u64 = 3600;

/// Maximum honored DNS TTL, in seconds (docs/alumina-proxy.md L12).
pub const TTL_CAP: u64 = 86_400;

const UNUSED_SLOT: NumericAddr = NumericAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The two DNS record families a cache entry is keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    A,
    Aaaa,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::A, Family::Aaaa];

    const fn index(self) -> usize {
        match self {
            Family::A => 0,
            Family::Aaaa => 1,
        }
    }
}

/// A name index admitted by the configured allowlist, never from unchecked input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NameIndex(u8);

impl NameIndex {
    fn get(self) -> usize {
        usize::from(self.0)
    }
}

/// A generation tag carried by validated in-flight results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Generation(u64);

impl Generation {
    pub const INITIAL: Generation = Generation(0);

    /// Returns the next generation, or `None` at the maximum value so exhaustion
    /// is explicit and no entry is mutated on failure.
    pub fn checked_next(self) -> Option<Generation> {
        self.0.checked_add(1).map(Generation)
    }
}

/// Freshness view computed from deadlines, never stored on the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    Empty,
    Fresh,
    Stale,
    Retired,
}

impl EntryState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            EntryState::Empty => "empty",
            EntryState::Fresh => "fresh",
            EntryState::Stale => "stale",
            EntryState::Retired => "retired",
        }
    }
}

/// A single cache entry: bindings, one freshness deadline, one retirement
/// deadline, and a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    generation: Generation,
    freshness_deadline: Option<u64>,
    retirement_deadline: Option<u64>,
    bindings: [NumericAddr; MAX_ADDRESSES],
    binding_len: u8,
    /// Whether this entry may be served past its freshness deadline. Derived
    /// from the earliest supporting TTL: a zero-TTL entry is never served
    /// stale (F-10).
    stale_allowed: bool,
}

impl Entry {
    const EMPTY: Entry = Entry {
        generation: Generation::INITIAL,
        freshness_deadline: None,
        retirement_deadline: None,
        bindings: [UNUSED_SLOT; MAX_ADDRESSES],
        binding_len: 0,
        stale_allowed: false,
    };

    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.binding_len == 0
    }

    /// The currently authorized eligible bindings.
    #[must_use]
    pub fn bindings(&self) -> &[NumericAddr] {
        &self.bindings[..usize::from(self.binding_len)]
    }

    /// The freshness and retirement deadlines, present exactly when non-empty.
    #[must_use]
    pub const fn deadlines(&self) -> (Option<u64>, Option<u64>) {
        (self.freshness_deadline, self.retirement_deadline)
    }

    /// Computes freshness at `now`; a valid instance yields the same result no
    /// matter how delayed timer processing was.
    #[must_use]
    pub const fn state(&self, now: u64) -> EntryState {
        match self.retirement_deadline {
            None => EntryState::Empty,
            Some(retirement) if now >= retirement => EntryState::Retired,
            Some(_) => match self.freshness_deadline {
                Some(freshness) if now < freshness => EntryState::Fresh,
                Some(_) | None => EntryState::Stale,
            },
        }
    }

    /// Whether the entry may still be served at `now`: fresh bindings always,
    /// stale bindings only when this entry admits stale serving and only
    /// within `STALE_SERVING_WINDOW` past their freshness deadline. A zero-TTL
    /// entry never admits stale serving (F-10). A stale entry past the serving
    /// window is retained for revalidation but never served (RT-006).
    #[must_use]
    pub const fn servable(&self, now: u64) -> bool {
        match self.state(now) {
            EntryState::Fresh => true,
            EntryState::Stale => match self.freshness_deadline {
                Some(freshness) => {
                    self.stale_allowed && now < freshness.saturating_add(STALE_SERVING_WINDOW)
                }
                None => false,
            },
            EntryState::Retired | EntryState::Empty => false,
        }
    }

    /// Whether this entry may be served past its freshness deadline. False for
    /// entries published from a zero-TTL answer (F-10).
    #[must_use]
    pub const fn stale_allowed(&self) -> bool {
        self.stale_allowed
    }
}

const fn empty_with_generation(generation: Generation) -> Entry {
    Entry {
        generation,
        ..Entry::EMPTY
    }
}

/// A complete validated positive outcome staged for atomic publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedPositive {
    name: NameIndex,
    family: Family,
    generation: Generation,
    bindings: [NumericAddr; MAX_ADDRESSES],
    binding_len: u8,
    receipt: u64,
    ttl: u64,
}

impl StagedPositive {
    /// Stages validated numeric candidate addresses for one name and family.
    ///
    /// The route is crate-private, reserved for the validated DNS outcome
    /// adapter of a later increment. Cross-family and capacity membership are
    /// runtime-validated here; configured-range membership is enforced at
    /// publication time by the admitting cache.
    ///
    /// # Errors
    ///
    /// Returns `BindingCapacityExceeded` when `bindings` exceeds
    /// `MAX_ADDRESSES` (never truncating), or `FamilyMismatch` when a binding
    /// does not match `family`.
    #[expect(
        clippy::expect_used,
        reason = "binding count is checked against MAX_ADDRESSES=16, which fits u8"
    )]
    pub(crate) fn stage(
        name: NameIndex,
        family: Family,
        generation: Generation,
        bindings: &[NumericAddr],
        receipt: u64,
        ttl: u64,
    ) -> Result<StagedPositive, CacheError> {
        if bindings.len() > MAX_ADDRESSES {
            return Err(CacheError::BindingCapacityExceeded);
        }
        if bindings.iter().any(|&addr| {
            matches!(
                (family, addr),
                (Family::A, NumericAddr::V6(_)) | (Family::Aaaa, NumericAddr::V4(_))
            )
        }) {
            return Err(CacheError::FamilyMismatch);
        }
        let mut slots = [UNUSED_SLOT; MAX_ADDRESSES];
        slots[..bindings.len()].copy_from_slice(bindings);
        Ok(StagedPositive {
            name,
            family,
            generation,
            bindings: slots,
            binding_len: u8::try_from(bindings.len())
                .expect("binding count bounded by MAX_ADDRESSES"),
            receipt,
            ttl,
        })
    }
}

/// Reasons a cache operation can refuse, always leaving prior entries intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
    NameOutOfRange,
    BindingCapacityExceeded,
    FamilyMismatch,
    GenerationExhausted,
    StaleGeneration,
    DeadlineOverflow,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            CacheError::NameOutOfRange => "admitted name range",
            CacheError::BindingCapacityExceeded => "entry address capacity",
            CacheError::FamilyMismatch => "entry record family",
            CacheError::GenerationExhausted => "entry generation",
            CacheError::StaleGeneration => "stale generation",
            CacheError::DeadlineOverflow => "cache deadline overflow",
        };
        write!(f, "cache {detail}")
    }
}

/// The fixed-capacity cache: one entry per admitted name and family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cache {
    name_count: u8,
    entries: [[Entry; 2]; ALLOWLIST_MAX],
}

impl Cache {
    /// Constructs a cache admitting `name_count` allowlist names.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name_count` is zero or exceeds
    /// `ALLOWLIST_MAX`.
    #[expect(
        clippy::large_stack_arrays,
        reason = "designed cache-storage fixed-profile buffer; no runtime heap"
    )]
    pub fn new(name_count: usize) -> Result<Cache, CacheError> {
        if name_count == 0 || name_count > ALLOWLIST_MAX {
            return Err(CacheError::NameOutOfRange);
        }
        let name_count = u8::try_from(name_count).map_err(|_| CacheError::NameOutOfRange)?;
        Ok(Cache {
            name_count,
            entries: [[Entry::EMPTY; 2]; ALLOWLIST_MAX],
        })
    }

    /// Constructs a cache whose name count exactly matches the validated
    /// allowlist of `config`, so allowlist ordinals index the same names in
    /// the cache (destination-binding, docs/alumina-proxy.md:145). The single
    /// running-path constructor: a worker never pairs a config with an
    /// independently sized cache (9pac M4).
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when the allowlist is empty or exceeds
    /// `ALLOWLIST_MAX` (configuration validation already rejects both).
    pub fn for_config(config: &Config) -> Result<Cache, CacheError> {
        Cache::new(config.allowlist().len())
    }

    /// The number of admitted names.
    #[must_use]
    pub fn name_count(&self) -> usize {
        usize::from(self.name_count)
    }

    /// Returns the admitted index for `index`, or `None` when out of range.
    pub fn name_index(&self, index: usize) -> Option<NameIndex> {
        if index < self.name_count() {
            u8::try_from(index).ok().map(NameIndex)
        } else {
            None
        }
    }

    fn admit(&self, name: NameIndex) -> Result<(), CacheError> {
        if name.get() < self.name_count() {
            Ok(())
        } else {
            Err(CacheError::NameOutOfRange)
        }
    }

    /// A read-level snapshot of one entry by value; the cache never lends
    /// references into its own storage.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache.
    pub fn entry(&self, name: NameIndex, family: Family) -> Result<Entry, CacheError> {
        self.admit(name)?;
        Ok(*self.entry_ref(name, family))
    }

    fn entry_ref(&self, name: NameIndex, family: Family) -> &Entry {
        &self.entries[name.get()][family.index()]
    }

    fn entry_mut(&mut self, name: NameIndex, family: Family) -> &mut Entry {
        &mut self.entries[name.get()][family.index()]
    }

    /// Publishes a staged positive for the queried family following candidate
    /// eligibility and TTL validation, atomically replacing the entry.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange`, `StaleGeneration`, `GenerationExhausted`, or
    /// `DeadlineOverflow` when respectively the name is not admitted by this
    /// cache, the staged request tag no longer matches the current entry
    /// generation, advancing past the maximum generation, or the
    /// receipt-derived deadlines overflow. The entry is unchanged on every
    /// error path.
    ///
    /// # Panics
    ///
    /// This function does not panic. Names not admitted by this cache are
    /// rejected by `admit` with `Err(NameOutOfRange)` (listed in `# Errors`)
    /// before any fixed-size entry indexing occurs.
    #[expect(
        clippy::expect_used,
        reason = "eligible count cannot exceed MAX_ADDRESSES=16 after the staged-filter, fitting u8"
    )]
    pub fn publish_positive(&mut self, staged: &StagedPositive) -> Result<(), CacheError> {
        self.admit(staged.name)?;
        let entry = self.entry_mut(staged.name, staged.family);
        if staged.generation != entry.generation {
            return Err(CacheError::StaleGeneration);
        }
        let next_generation = entry
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        let ttl = staged.ttl.clamp(1, TTL_CAP);
        let freshness = staged
            .receipt
            .checked_add(ttl)
            .ok_or(CacheError::DeadlineOverflow)?;
        let retirement = freshness
            .checked_add(STALE_GRACE)
            .ok_or(CacheError::DeadlineOverflow)?;
        let mut eligible = [UNUSED_SLOT; MAX_ADDRESSES];
        let mut eligible_len = 0usize;
        for &addr in &staged.bindings[..usize::from(staged.binding_len)] {
            if addr.is_eligible() && !eligible[..eligible_len].contains(&addr) {
                eligible[eligible_len] = addr;
                eligible_len += 1;
            }
        }
        let new_entry = if eligible_len == 0 {
            Entry {
                generation: next_generation,
                ..Entry::EMPTY
            }
        } else {
            Entry {
                generation: next_generation,
                freshness_deadline: Some(freshness),
                retirement_deadline: Some(retirement),
                bindings: eligible,
                binding_len: u8::try_from(eligible_len)
                    .expect("eligible count bounded by MAX_ADDRESSES"),
                stale_allowed: staged.ttl != 0,
            }
        };
        *entry = new_entry;
        Ok(())
    }

    /// Evicts both families of a name following a validated NXDOMAIN.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache, or
    /// `GenerationExhausted` and leaves both entries unchanged when either
    /// generation cannot advance.
    pub fn evict_nxdomain(&mut self, name: NameIndex) -> Result<(), CacheError> {
        self.admit(name)?;
        let a_next = self
            .entry_ref(name, Family::A)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        let aaaa_next = self
            .entry_ref(name, Family::Aaaa)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        *self.entry_mut(name, Family::A) = empty_with_generation(a_next);
        *self.entry_mut(name, Family::Aaaa) = empty_with_generation(aaaa_next);
        Ok(())
    }

    /// Evicts only the queried family following a validated NODATA.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache, or
    /// `GenerationExhausted` and leaves the entry unchanged when its
    /// generation cannot advance.
    pub fn evict_nodata(&mut self, name: NameIndex, family: Family) -> Result<(), CacheError> {
        self.admit(name)?;
        let next = self
            .entry_ref(name, family)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        *self.entry_mut(name, family) = empty_with_generation(next);
        Ok(())
    }

    /// Records an exchange failure for an admitted name and family without any
    /// cache mutation, so bindings survive only within existing deadlines.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache;
    /// otherwise the call records nothing and never changes a deadline.
    pub fn note_exchange_failure(
        &self,
        name: NameIndex,
        _family: Family,
    ) -> Result<(), CacheError> {
        self.admit(name)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
