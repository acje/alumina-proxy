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

/// The query-start generation snapshot for one exchange: the queried family's
/// cache entry generation plus the other family's, captured together from the
/// same cache before any network work and retained immutably for the
/// whole-family negative guard (docs/alumina-proxy.md:119, :121-124).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Generations {
    /// The queried family's entry generation, authoritative for positives.
    pub(crate) queried: Generation,
    /// The non-queried family's entry generation from the same snapshot.
    pub(crate) other: Generation,
}

/// Test-only single-generation convenience for direct-call test fixtures;
/// `other` stays INITIAL because a test-authored exchange authors nothing
/// (publication-free). The production entry takes a concrete pair, so this
/// never makes a missing other-family tag silently INITIAL there.
#[cfg(test)]
impl Generations {
    /// Single-generation snapshot for direct-call test fixtures.
    pub(crate) const fn only(queried: Generation) -> Self {
        Self {
            queried,
            other: Generation::INITIAL,
        }
    }
}

/// Test-only: lets direct-call test fixtures pass a bare [`Generation`].
#[cfg(test)]
impl From<Generation> for Generations {
    fn from(queried: Generation) -> Self {
        Self::only(queried)
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
    /// Optional immutable reply evidence, stored atomically with the
    /// bindings; legacy publishes leave this `None`.
    evidence: Option<evidence::Evidence>,
    /// Closed negative scope minted with this entry.
    negative: Option<NegativeProof>,
}

impl Entry {
    const EMPTY: Entry = Entry {
        generation: Generation::INITIAL,
        freshness_deadline: None,
        retirement_deadline: None,
        bindings: [UNUSED_SLOT; MAX_ADDRESSES],
        binding_len: 0,
        stale_allowed: false,
        evidence: None,
        negative: None,
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

    /// The immutable reply evidence stored with this entry, `None` for legacy
    /// or currently unevidenced positives.
    #[must_use]
    pub const fn evidence(&self) -> Option<evidence::Evidence> {
        self.evidence
    }

    /// The effective proof class for serving at `now`: a stored evidence
    /// projects its own class whenever it is valid at `now`, independent of
    /// address usability (candidate eligibility or servability); a positive
    /// without a currently valid evidence class projects at most ordinary
    /// trusted while its binding stays servable and nothing otherwise, so an
    /// expired proof on a still-servable positive keeps the ordinary baseline
    /// instead of vanishing.
    #[must_use]
    pub const fn effective_projection(&self, now: u64) -> Option<evidence::ProofClass> {
        let valid = match self.evidence {
            Some(ev) => ev.valid_class(now),
            None => None,
        };
        match valid {
            Some(class) => Some(class),
            None if self.servable(now) => Some(evidence::ProofClass::Trusted),
            None => None,
        }
    }
}

const fn empty_with_generation(generation: Generation) -> Entry {
    Entry {
        generation,
        ..Entry::EMPTY
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NegativeProof {
    Nx {
        sibling_tag: Generation,
        evidence: evidence::Evidence,
    },
    NoData {
        evidence: evidence::Evidence,
    },
}

const fn negative_entry(generation: Generation, negative: NegativeProof) -> Entry {
    Entry {
        generation,
        negative: Some(negative),
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
    evidence: Option<evidence::Evidence>,
}

/// The absolute deadlines a plotted entry carries, derived once from the
/// staged receipt and TTL so publication never recomputes them.
#[derive(Clone, Copy)]
struct Deadlines {
    freshness: u64,
    retirement: u64,
}

/// The deduplicated eligible addresses a staged positive publishes, with their
/// count kept alongside the fixed-capacity slots they occupy.
#[derive(Clone, Copy)]
struct EligibleBindings {
    addrs: [NumericAddr; MAX_ADDRESSES],
    len: usize,
}

impl StagedPositive {
    /// Stages validated numeric candidate addresses for one name and family.
    ///
    /// The route is crate-private, reserved for the validated DNS outcome
    /// adapter of a later increment. Cross-family and capacity membership are
    /// runtime-validated here; configured-range membership is enforced at
    /// publication time by the admitting cache. Defaults to carrying no
    /// evidence; [`StagedPositive::stage_with_evidence`] binds it.
    ///
    /// # Errors
    ///
    /// Returns `BindingCapacityExceeded` when `bindings` exceeds
    /// `MAX_ADDRESSES` (never truncating), or `FamilyMismatch` when a binding
    /// does not match `family`.
    #[cfg(test)]
    pub(crate) fn stage(
        name: NameIndex,
        family: Family,
        generation: Generation,
        bindings: &[NumericAddr],
        receipt: u64,
        ttl: u64,
    ) -> Result<StagedPositive, CacheError> {
        Self::stage_with_evidence(name, family, generation, bindings, receipt, ttl, None)
    }

    /// Stages a validated positive carrying immutable reply `evidence`, bound
    /// atomically with the bindings at publication. There is no detached
    /// setter: evidence is fixed at construction.
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
    pub(crate) fn stage_with_evidence(
        name: NameIndex,
        family: Family,
        generation: Generation,
        bindings: &[NumericAddr],
        receipt: u64,
        ttl: u64,
        evidence: Option<evidence::Evidence>,
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
            evidence,
        })
    }
}

fn staged_deadlines(staged: &StagedPositive) -> Result<Deadlines, CacheError> {
    let ttl = staged.ttl.clamp(1, TTL_CAP);
    let freshness = staged
        .receipt
        .checked_add(ttl)
        .ok_or(CacheError::DeadlineOverflow)?;
    let retirement = freshness
        .checked_add(STALE_GRACE)
        .ok_or(CacheError::DeadlineOverflow)?;
    Ok(Deadlines {
        freshness,
        retirement,
    })
}

fn validate_staged_evidence(staged: &StagedPositive, freshness: u64) -> Result<(), CacheError> {
    let Some(evidence) = staged.evidence else {
        return Ok(());
    };
    if evidence.evidential_start() > staged.receipt {
        return Err(CacheError::EvidenceInconsistent);
    }
    let supporting = evidence
        .raw_supporting_ttl()
        .ok_or(CacheError::EvidenceInconsistent)?;
    if u64::from(supporting) != staged.ttl {
        return Err(CacheError::EvidenceInconsistent);
    }
    if let Some(deadline) = evidence.evidential_deadline()
        && deadline > freshness
    {
        return Err(CacheError::EvidenceInconsistent);
    }
    Ok(())
}

fn eligible_bindings(staged: &StagedPositive) -> EligibleBindings {
    let mut addrs = [UNUSED_SLOT; MAX_ADDRESSES];
    let mut len = 0usize;
    for &addr in &staged.bindings[..usize::from(staged.binding_len)] {
        if addr.is_eligible() && !addrs[..len].contains(&addr) {
            addrs[len] = addr;
            len += 1;
        }
    }
    EligibleBindings { addrs, len }
}

#[expect(
    clippy::expect_used,
    reason = "eligible count cannot exceed MAX_ADDRESSES=16 after the staged-filter, fitting u8"
)]
fn published_entry(
    staged: &StagedPositive,
    next_generation: Generation,
    deadlines: Deadlines,
    bindings: EligibleBindings,
) -> Entry {
    if bindings.len == 0 {
        return Entry {
            generation: next_generation,
            evidence: staged.evidence,
            ..Entry::EMPTY
        };
    }
    Entry {
        generation: next_generation,
        freshness_deadline: Some(deadlines.freshness),
        retirement_deadline: Some(deadlines.retirement),
        bindings: bindings.addrs,
        binding_len: u8::try_from(bindings.len).expect("eligible count bounded by MAX_ADDRESSES"),
        stale_allowed: staged.ttl != 0,
        evidence: staged.evidence,
        negative: None,
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
    /// Staged evidence is internally inconsistent: its evidential floor
    /// follows the receipt, or its lease outlives the supporting binding TTL.
    EvidenceInconsistent,
    /// The candidate's own evidence does not satisfy the name's owned
    /// assurance requirement at publication time.
    InsufficientAssurance,
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
            CacheError::EvidenceInconsistent => "inconsistent staged evidence",
            CacheError::InsufficientAssurance => "insufficient assurance for the owned requirement",
        };
        write!(f, "cache {detail}")
    }
}

/// The fixed-capacity cache: one entry per admitted name and family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cache {
    name_count: u8,
    requirements: [evidence::AssuranceRequirement; ALLOWLIST_MAX],
    entries: [[Entry; 2]; ALLOWLIST_MAX],
}

impl Cache {
    /// Constructs a cache admitting `name_count` allowlist names.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name_count` is zero or exceeds
    /// `ALLOWLIST_MAX`.
    pub fn new(name_count: usize) -> Result<Cache, CacheError> {
        Self::with_requirement(name_count, evidence::AssuranceRequirement::ResolverTrusted)
    }

    pub(crate) fn with_requirement(
        name_count: usize,
        required: evidence::AssuranceRequirement,
    ) -> Result<Cache, CacheError> {
        Self::with_entry_requirements(name_count, [required; ALLOWLIST_MAX])
    }

    #[expect(
        clippy::large_stack_arrays,
        reason = "designed cache-storage fixed-profile buffer; no runtime heap"
    )]
    fn with_entry_requirements(
        name_count: usize,
        requirements: [evidence::AssuranceRequirement; ALLOWLIST_MAX],
    ) -> Result<Cache, CacheError> {
        if name_count == 0 || name_count > ALLOWLIST_MAX {
            return Err(CacheError::NameOutOfRange);
        }
        let name_count = u8::try_from(name_count).map_err(|_| CacheError::NameOutOfRange)?;
        Ok(Cache {
            name_count,
            requirements,
            entries: [[Entry::EMPTY; 2]; ALLOWLIST_MAX],
        })
    }

    /// Constructs a cache whose name count exactly matches the validated
    /// allowlist of `config`, so allowlist ordinals index the same names in
    /// the cache (destination-binding, docs/alumina-proxy.md:145). Each
    /// admitted entry retains the config's per-allowlist assurance
    /// requirement at the same ordinal, so requirement ownership stays in
    /// config. The single running-path constructor: a worker never pairs a
    /// config with an independently sized cache (9pac M4).
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when the allowlist is empty or exceeds
    /// `ALLOWLIST_MAX` (configuration validation already rejects both).
    pub fn for_config(config: &Config) -> Result<Cache, CacheError> {
        let allowlist_len = config.allowlist().len();
        let mut requirements = [evidence::AssuranceRequirement::ResolverTrusted; ALLOWLIST_MAX];
        for (slot, index) in requirements.iter_mut().zip(0..allowlist_len) {
            *slot = config.entry_requirement(index);
        }
        Self::with_entry_requirements(allowlist_len, requirements)
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

    /// The query-start snapshot for `family` at `name`: the queried family's
    /// entry generation plus the other family's, captured together from this
    /// cache before any network work and owned here so startup, serving, and
    /// test witnesses share one capture path (docs/alumina-proxy.md:119).
    ///
    /// # Errors
    ///
    /// Returns `CacheError::NameOutOfRange` when `name` is outside the
    /// admitted range.
    pub(crate) fn generations_before_query(
        &self,
        name: NameIndex,
        family: Family,
    ) -> Result<Generations, CacheError> {
        let other = match family {
            Family::A => Family::Aaaa,
            Family::Aaaa => Family::A,
        };
        Ok(Generations {
            queried: self.entry(name, family)?.generation(),
            other: self.entry(name, other)?.generation(),
        })
    }

    pub(crate) fn check_publication_requirement(
        &self,
        name: NameIndex,
        candidate: Option<evidence::Evidence>,
        now: u64,
    ) -> Result<(), CacheError> {
        let required = self.requirements[name.get()];
        let class = candidate.and_then(|candidate| candidate.valid_class(now));
        match required {
            evidence::AssuranceRequirement::ResolverTrusted => Ok(()),
            _ if required.admits(class) => Ok(()),
            _ => Err(CacheError::InsufficientAssurance),
        }
    }

    fn entry_mut(&mut self, name: NameIndex, family: Family) -> &mut Entry {
        &mut self.entries[name.get()][family.index()]
    }

    /// Publishes a staged positive for the queried family following candidate
    /// eligibility and TTL validation, atomically replacing the entry.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange`, `StaleGeneration`, `GenerationExhausted`,
    /// `DeadlineOverflow`, or `EvidenceInconsistent` when respectively the
    /// name is not admitted by this cache, the staged request tag no longer
    /// matches the current entry generation, advancing past the maximum
    /// generation, the receipt-derived deadlines overflow, or the staged
    /// evidence is internally inconsistent. The entry is unchanged on every
    /// error path.
    ///
    /// # Panics
    ///
    /// This function does not panic. Names not admitted by this cache are
    /// rejected by `admit` with `Err(NameOutOfRange)` (listed in `# Errors`)
    /// before any fixed-size entry indexing occurs.
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
        let deadlines = staged_deadlines(staged)?;
        validate_staged_evidence(staged, deadlines.freshness)?;
        *entry = published_entry(
            staged,
            next_generation,
            deadlines,
            eligible_bindings(staged),
        );
        Ok(())
    }

    fn peer_admissible(
        &self,
        name: NameIndex,
        family: Family,
        addr: NumericAddr,
        now: u64,
        required: evidence::AssuranceRequirement,
    ) -> Result<bool, CacheError> {
        let entry = self.entry(name, family)?;
        let admitted = entry.servable(now)
            && entry.bindings().contains(&addr)
            && addr.is_eligible()
            && required.admits(entry.effective_projection(now));
        Ok(admitted)
    }

    pub(crate) fn is_peer_admissible(
        &self,
        name: NameIndex,
        family: Family,
        addr: NumericAddr,
        now: u64,
    ) -> Result<bool, CacheError> {
        self.admit(name)?;
        let required = self.requirements[name.get()];
        self.peer_admissible(name, family, addr, now, required)
    }

    pub(crate) fn is_name_admissible(&self, name: NameIndex, now: u64) -> Result<bool, CacheError> {
        for family in Family::ALL {
            for &addr in self.entry(name, family)?.bindings() {
                if self.is_peer_admissible(name, family, addr, now)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
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

    pub(crate) fn evict_nodata_evidenced(
        &mut self,
        name: NameIndex,
        family: Family,
        evidence: evidence::Evidence,
    ) -> Result<(), CacheError> {
        self.admit(name)?;
        let next = self
            .entry_ref(name, family)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        *self.entry_mut(name, family) = negative_entry(next, NegativeProof::NoData { evidence });
        Ok(())
    }

    pub(crate) fn evict_nxdomain_evidenced(
        &mut self,
        name: NameIndex,
        evidence: evidence::Evidence,
    ) -> Result<(), CacheError> {
        self.admit(name)?;
        let a = self
            .entry_ref(name, Family::A)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        let aaaa = self
            .entry_ref(name, Family::Aaaa)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        *self.entry_mut(name, Family::A) = negative_entry(
            a,
            NegativeProof::Nx {
                sibling_tag: aaaa,
                evidence,
            },
        );
        *self.entry_mut(name, Family::Aaaa) = negative_entry(
            aaaa,
            NegativeProof::Nx {
                sibling_tag: a,
                evidence,
            },
        );
        Ok(())
    }

    pub(crate) fn negative_lease_flags(&self, name: NameIndex, now: u64) -> Option<[bool; 2]> {
        match (
            self.negative_projection(name, Family::A, now),
            self.negative_projection(name, Family::Aaaa, now),
        ) {
            (Ok(a), Ok(aaaa)) => Some([a.is_some(), aaaa.is_some()]),
            _ => None,
        }
    }

    pub(crate) fn negative_projection(
        &self,
        name: NameIndex,
        family: Family,
        now: u64,
    ) -> Result<Option<NegativeProof>, CacheError> {
        let Some(proof) = self.entry(name, family)?.negative else {
            return Ok(None);
        };
        match proof {
            NegativeProof::NoData { evidence } => {
                if evidence.valid_class(now).is_none() {
                    return Ok(None);
                }
                Ok(Some(NegativeProof::NoData { evidence }))
            }
            NegativeProof::Nx {
                sibling_tag,
                evidence,
            } => {
                let sibling = match family {
                    Family::A => self.entry(name, Family::Aaaa)?,
                    Family::Aaaa => self.entry(name, Family::A)?,
                };
                if sibling.generation() != sibling_tag {
                    return Ok(None);
                }
                if evidence.valid_class(now).is_none() {
                    return Ok(None);
                }
                Ok(Some(NegativeProof::Nx {
                    sibling_tag,
                    evidence,
                }))
            }
        }
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

pub(crate) mod grade_key;

pub mod evidence {
    use super::TTL_CAP;
    use crate::dns::resolver::MAX_RESOLVERS;

    /// Historical proof class derived from the raw reply facts, independent of
    /// the clock and of address usability. A plain (unauthenticated-origin)
    /// reply is never authenticated. Every authenticated-origin reply is at
    /// least authenticated; only a qualified deployment with the AD bit set
    /// is delegated.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProofClass {
        /// No authenticated assurance: `resolver_trusted` fallback.
        Trusted,
        /// Authenticated-origin `resolver_authenticated` assurance.
        Authenticated,
        /// Qualified, authenticated, AD-set `delegated_dnssec` evidence.
        Delegated,
    }

    impl ProofClass {
        const fn classify(origin_authenticated: bool, qualified: bool, ad: bool) -> ProofClass {
            match (origin_authenticated, qualified, ad) {
                (false, _, _) => ProofClass::Trusted,
                (true, true, true) => ProofClass::Delegated,
                (true, _, _) => ProofClass::Authenticated,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum AssuranceRequirement {
        ResolverTrusted,
        ResolverAuthenticated,
        DelegatedDnssec,
    }

    impl AssuranceRequirement {
        pub(crate) const fn admits(self, class: Option<ProofClass>) -> bool {
            match self {
                Self::ResolverTrusted => class.is_some(),
                Self::ResolverAuthenticated => {
                    matches!(
                        class,
                        Some(ProofClass::Authenticated | ProofClass::Delegated)
                    )
                }
                Self::DelegatedDnssec => matches!(class, Some(ProofClass::Delegated)),
            }
        }
    }

    /// The upstream resolver identity that produced the reply: one of the
    /// existing resolver-selection indices (`0..MAX_RESOLVERS`) or an explicit
    /// unknown. Out-of-range indices are rejected, never silently truncated.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ResolverSource(Option<u8>);

    impl ResolverSource {
        /// An explicit unknown origin when no resolver identity is attributable.
        pub const UNKNOWN: ResolverSource = ResolverSource(None);

        /// Bounds a resolver index to the existing selection; `None` outside it.
        pub const fn index(index: u8) -> Option<ResolverSource> {
            if (index as usize) < MAX_RESOLVERS {
                Some(ResolverSource(Some(index)))
            } else {
                None
            }
        }

        /// The resolver index, or `None` when the origin is unknown.
        pub const fn get(self) -> Option<u8> {
            self.0
        }
    }

    /// A checked construction refusal; the resulting value would be invalid.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EvidenceError {
        /// `query_start + capped_raw_supporting_ttl` overflowed `u64`.
        DeadlineOverflow,
        /// An authenticated-origin reply had no attributable resolver source.
        AuthenticatedWithoutSource,
    }

    /// Lossless immutable reply evidence. Retains raw AD, the authenticated-origin
    /// fact (the trusted owner's already-established strict-pin TLS identity/key
    /// possession, never inferred from a configured pin or AD), the qualification
    /// deployment condition, the source identity, and the raw supporting TTL
    /// (`None` for unknown differs from `Some(0)` for explicit zero). The
    /// historical `class()` is separate from clock-relative `active_class(now)`
    /// bounded below by the query-start floor.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Evidence {
        raw_ad: bool,
        origin_authenticated: bool,
        qualified: bool,
        source: ResolverSource,
        raw_supporting_ttl: Option<u32>,
        evidential_start: u64,
        evidential_deadline: Option<u64>,
    }

    impl Evidence {
        /// Builds evidence from the raw reply facts. `origin_authenticated`
        /// must already be the completed strict-pin TLS identity fact, and
        /// `qualified` the external trusted deployment condition; neither is
        /// derived here. The evidential floor anchors at `query_start`
        /// (genuine owner input) and the deadline at that floor plus the raw
        /// supporting TTL capped to `TTL_CAP`; a `None` or `Some(0)` TTL
        /// yields no reusable lease.
        ///
        /// # Errors
        ///
        /// Returns `DeadlineOverflow` when `query_start + capped_ttl`
        /// overflows `u64`; no evidence is produced. Returns
        /// `AuthenticatedWithoutSource` when `origin_authenticated` is set
        /// without an attributable resolver source; no evidence is produced.
        pub const fn new(
            raw_ad: bool,
            origin_authenticated: bool,
            qualified: bool,
            source: ResolverSource,
            raw_supporting_ttl: Option<u32>,
            query_start: u64,
        ) -> Result<Evidence, EvidenceError> {
            if origin_authenticated && matches!(source, ResolverSource::UNKNOWN) {
                return Err(EvidenceError::AuthenticatedWithoutSource);
            }
            let evidential_deadline = match raw_supporting_ttl {
                None => None,
                Some(ttl) => {
                    let raw = ttl as u64;
                    let capped = if raw < TTL_CAP { raw } else { TTL_CAP };
                    match query_start.checked_add(capped) {
                        Some(deadline) => Some(deadline),
                        None => return Err(EvidenceError::DeadlineOverflow),
                    }
                }
            };
            Ok(Evidence {
                raw_ad,
                origin_authenticated,
                qualified,
                source,
                raw_supporting_ttl,
                evidential_start: query_start,
                evidential_deadline,
            })
        }

        /// The raw AD bit, retained independently of the derived class.
        pub const fn raw_ad(self) -> bool {
            self.raw_ad
        }

        /// The already-established authenticated-origin fact.
        pub const fn origin_authenticated(self) -> bool {
            self.origin_authenticated
        }

        /// The external qualified-deployment condition.
        pub const fn qualified(self) -> bool {
            self.qualified
        }

        /// The bounded resolver origin/source identity.
        pub const fn source(self) -> ResolverSource {
            self.source
        }

        /// The raw supporting TTL: `None` (unknown) distinct from `Some(0)`.
        pub const fn raw_supporting_ttl(self) -> Option<u32> {
            self.raw_supporting_ttl
        }

        /// The checked evidential deadline, `None` when no reusable lease exists.
        pub const fn evidential_deadline(self) -> Option<u64> {
            self.evidential_deadline
        }

        /// The query-start floor anchoring the evidential window.
        pub const fn evidential_start(self) -> u64 {
            self.evidential_start
        }

        /// The historical proof class, always available from the raw facts.
        pub const fn class(self) -> ProofClass {
            ProofClass::classify(self.origin_authenticated, self.qualified, self.raw_ad)
        }

        /// The proof class valid at `now` purely from the evidential window,
        /// for any class including ordinary trusted; `None` before the
        /// query-start floor, after the checked deadline, or when no reusable
        /// lease exists.
        pub const fn valid_class(self, now: u64) -> Option<ProofClass> {
            match self.evidential_deadline {
                Some(deadline) if now >= self.evidential_start && now < deadline => {
                    Some(self.class())
                }
                Some(_) | None => None,
            }
        }

        /// Established authenticated assurance at `now`: only an
        /// authenticated/delegated class inside its evidential window.
        /// Trusted-class, not-yet-begun, expired, unknown, and zero-TTL
        /// evidence never authenticates.
        pub const fn active_class(self, now: u64) -> Option<ProofClass> {
            match self.valid_class(now) {
                Some(ProofClass::Trusted) => None,
                other => other,
            }
        }
    }
}
