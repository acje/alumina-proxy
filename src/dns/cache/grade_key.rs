//! Per-entry grade-change key.
//!
//! Carries the entry's immutable required minimum and the cache-derived
//! achieved assurance per family at a point in time.

use super::evidence::{AssuranceRequirement, Evidence, ProofClass, ResolverSource};
use super::{Cache, CacheError, Family, NameIndex, NegativeProof};

/// The exact closed grade key of one cache entry at a point in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EntryGradeKey {
    required: AssuranceRequirement,
    a: Option<ProofClass>,
    aaaa: Option<ProofClass>,
}

impl Cache {
    /// The entry's exact assurance-grade key at `now`.
    ///
    /// Each family is `None` when the cache commits no currently achieved
    /// assurance (empty, unresolved, unevidenced-negative, or not servable);
    /// otherwise it is the committed served class of the established positive
    /// or the valid negative proof's class. Answer kind (positive, NODATA,
    /// NXDOMAIN) is never part of the key, and a Trusted-class evidence window
    /// closing without changing the served class is also not.
    ///
    /// # Errors
    ///
    /// Returns `CacheError::NameOutOfRange` when `name` is not admitted.
    pub(crate) fn grade_key(&self, name: NameIndex, now: u64) -> Result<EntryGradeKey, CacheError> {
        self.admit(name)?;
        Ok(EntryGradeKey {
            required: self.requirements[name.get()],
            a: self.achieved_assurance(name, Family::A, now)?,
            aaaa: self.achieved_assurance(name, Family::Aaaa, now)?,
        })
    }

    /// Current achieved assurance for one family, or `None` when the cache
    /// commits none; lookup errors propagate rather than folding into `None`.
    fn achieved_assurance(
        &self,
        name: NameIndex,
        family: Family,
        now: u64,
    ) -> Result<Option<ProofClass>, CacheError> {
        if let Some(proof) = self.negative_projection(name, family, now)? {
            let evidence = match proof {
                NegativeProof::NoData { evidence } | NegativeProof::Nx { evidence, .. } => evidence,
            };
            return Ok(Some(evidence.class()));
        }
        match self.entry(name, family)? {
            entry if entry.servable(now) => Ok(entry.effective_projection(now)),
            _ => Ok(None),
        }
    }

    /// Stored proof facts for `family` at `now`. A stored proof outside its
    /// window stays `Some` with truthful flags, never inventing a renewal.
    ///
    /// # Errors
    ///
    /// Returns `CacheError::NameOutOfRange` when `name` is not admitted.
    pub(crate) fn family_retained(
        &self,
        name: NameIndex,
        family: Family,
        now: u64,
    ) -> Result<Option<Retained>, CacheError> {
        let entry = self.entry(name, family)?;
        if let Some(negative) = entry.negative {
            let (kind, evidence) = match negative {
                NegativeProof::NoData { evidence } => (RetainedKind::NoData, evidence),
                NegativeProof::Nx { evidence, .. } => (RetainedKind::Nx, evidence),
            };
            let applicable = self.negative_projection(name, family, now)?.is_some();
            return Ok(Some(Retained::new(kind, evidence, now, applicable)));
        }
        if let Some(evidence) = entry.evidence() {
            let valid = evidence.valid_class(now).is_some();
            return Ok(Some(Retained::new(
                RetainedKind::Positive,
                evidence,
                now,
                entry.servable(now) && valid,
            )));
        }
        Ok(None)
    }

    /// Per-family snapshot: owned minimum, cache-derived current grade,
    /// current applicable outcome, retained proof facts, and usable bindings
    /// at `now`.
    ///
    /// # Errors
    ///
    /// Returns `CacheError::NameOutOfRange` when `name` is not admitted.
    pub(crate) fn family_snapshot(
        &self,
        name: NameIndex,
        family: Family,
        now: u64,
    ) -> Result<FamilySnapshot, CacheError> {
        let entry = self.entry(name, family)?;
        let required = self.requirements[name.get()];
        let retained = self.family_retained(name, family, now)?;
        let current = self.achieved_assurance(name, family, now)?;
        let (outcome, usable) = match self.negative_projection(name, family, now)? {
            Some(NegativeProof::NoData { .. }) => (Outcome::NoData, 0),
            Some(NegativeProof::Nx { .. }) => (Outcome::Nx, 0),
            None if entry.servable(now) => (
                Outcome::Positive,
                if required.admits(current) {
                    entry.binding_len
                } else {
                    0
                },
            ),
            None => (Outcome::Unknown, 0),
        };
        Ok(FamilySnapshot {
            required,
            current,
            outcome,
            retained,
            usable,
        })
    }
}

/// Committed stored answer kind of a retained proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetainedKind {
    Positive,
    NoData,
    Nx,
}

/// Closed retained proof facts; presence never implies current assurance,
/// only that a proof is stored for the family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Retained {
    kind: RetainedKind,
    class: ProofClass,
    source: ResolverSource,
    time_valid: bool,
    applicable: bool,
}

impl Retained {
    fn new(kind: RetainedKind, evidence: Evidence, now: u64, applicable: bool) -> Retained {
        Retained {
            kind,
            class: evidence.class(),
            source: evidence.source(),
            time_valid: evidence.valid_class(now).is_some(),
            applicable,
        }
    }

    #[must_use]
    pub(crate) const fn kind(self) -> RetainedKind {
        self.kind
    }
    #[must_use]
    pub(crate) const fn class(self) -> ProofClass {
        self.class
    }
    #[must_use]
    pub(crate) const fn source(self) -> ResolverSource {
        self.source
    }
    #[must_use]
    pub(crate) const fn time_valid(self) -> bool {
        self.time_valid
    }
    #[must_use]
    pub(crate) const fn applicable(self) -> bool {
        self.applicable
    }
}

/// Currently applicable answer kind of one family, distinct from the
/// historical kind a retained proof records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Positive,
    NoData,
    Nx,
    Unknown,
}

/// Closed cache-owned per-family snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FamilySnapshot {
    required: AssuranceRequirement,
    current: Option<ProofClass>,
    outcome: Outcome,
    retained: Option<Retained>,
    usable: u8,
}

impl FamilySnapshot {
    #[must_use]
    pub(crate) const fn required(self) -> AssuranceRequirement {
        self.required
    }
    #[must_use]
    pub(crate) const fn current(self) -> Option<ProofClass> {
        self.current
    }
    #[must_use]
    pub(crate) const fn outcome(self) -> Outcome {
        self.outcome
    }
    #[must_use]
    pub(crate) const fn retained(self) -> Option<Retained> {
        self.retained
    }
    #[must_use]
    pub(crate) const fn usable(self) -> u8 {
        self.usable
    }
}

#[cfg(test)]
mod tests;
