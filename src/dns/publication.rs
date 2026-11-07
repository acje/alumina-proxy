use crate::dns::cache::evidence;
use crate::dns::cache::{Cache, CacheError, Family, Generation, NameIndex, StagedPositive};
use crate::dns::schedule::{
    IncidentTransition, OutcomeIncidents, PerTypeTransition, Schedules, family_slot,
};
use crate::dns::wire::{DnsError, Outcome};

/// The positional apply context grouped to keep the shared route below the
/// argument-count gate: the allowlist `index`, the in-flight `generation`,
/// and the monotonic `receipt`/`now` values.
#[derive(Clone, Copy)]
pub(super) struct ApplyContext {
    pub(super) index: usize,
    pub(super) generation: Generation,
    pub(super) receipt: u64,
    pub(super) now: u64,
    /// The queried family and the other family's query-start tag, owned by
    /// the private production apply route for the whole-family negative
    /// guard. The legacy public [`apply_outcome`] passes `None` here and is
    /// explicitly untracked: a negative publication through it is not
    /// claimed two-family guarded.
    pub(super) query_family: Option<Family>,
    pub(super) other_generation: Option<Generation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObservationPhase {
    BeforeCommit,
    AfterCommit,
}

/// Applies a validated `outcome` to the cache and schedule for one allowlist
/// `index`, using the in-flight `generation` and the monotonic `receipt` and
/// `now` values. Only validated outcomes mutate state. Returns the incident
/// deltas the outcome produced for the name: the sustained-negative delta plus
/// the per-type exchange-failure deltas in A/Aaaa slot order. The public route
/// stays evidence-free, so no detached flag or arbitrary evidence can enter
/// the cache through it.
///
/// # Errors
///
/// Returns `DnsError::Cache` on a pre-publication cache or schedule refusal.
/// A successful schedule preparation admits the index; subsequent incident
/// clearing cannot fail on the current route.
pub fn apply_outcome(
    cache: &mut Cache,
    schedules: &mut Schedules,
    index: usize,
    generation: Generation,
    receipt: u64,
    now: u64,
    outcome: &Outcome,
) -> Result<OutcomeIncidents, DnsError> {
    apply_route(
        cache,
        schedules,
        ApplyContext {
            index,
            generation,
            receipt,
            now,
            query_family: None,
            other_generation: None,
        },
        outcome,
        None,
    )
}

pub(super) fn apply_route(
    cache: &mut Cache,
    schedules: &mut Schedules,
    context: ApplyContext,
    outcome: &Outcome,
    evidence: Option<evidence::Evidence>,
) -> Result<OutcomeIncidents, DnsError> {
    apply_route_observed(
        cache,
        schedules,
        context,
        outcome,
        evidence,
        &mut |_, _, _, _| {},
    )
}

pub(super) fn apply_route_observed<F>(
    cache: &mut Cache,
    schedules: &mut Schedules,
    context: ApplyContext,
    outcome: &Outcome,
    evidence: Option<evidence::Evidence>,
    observer: &mut F,
) -> Result<OutcomeIncidents, DnsError>
where
    F: FnMut(ObservationPhase, &Cache, NameIndex, u64),
{
    let ApplyContext {
        index,
        generation,
        receipt,
        now,
        query_family,
        other_generation,
    } = context;
    let name = cache
        .name_index(index)
        .ok_or(DnsError::Cache(CacheError::NameOutOfRange))?;
    reject_obsolete_generation(cache, name, context, outcome)?;
    cache
        .check_publication_requirement(name, evidence, now)
        .map_err(DnsError::Cache)?;
    observer(ObservationPhase::BeforeCommit, cache, name, now);
    match outcome {
        Outcome::Positive {
            bindings,
            ttl,
            family: positive_family,
        } => {
            let staged = StagedPositive::stage_with_evidence(
                name,
                *positive_family,
                generation,
                bindings.as_slice(),
                receipt,
                *ttl,
                evidence,
            )
            .map_err(DnsError::Cache)?;
            let cacheable = bindings.as_slice().iter().any(|b| b.is_eligible());
            let prepared = schedules
                .prepare_positive(index, *positive_family, receipt, *ttl, cacheable, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
            cache.publish_positive(&staged).map_err(DnsError::Cache)?;
            observer(ObservationPhase::AfterCommit, cache, name, now);
            schedules.commit_positive(index, *positive_family, prepared);
            let sustained = schedules.reset_negative_streak(index);
            let mut per_type = [PerTypeTransition::None; 2];
            per_type[family_slot(*positive_family)] = schedules
                .clear_exchange_incident(index, *positive_family, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
            Ok(OutcomeIncidents {
                sustained,
                per_type,
            })
        }
        Outcome::NxDomain { soa } => {
            let prepared = schedules
                .prepare_nxdomain(index, *soa, receipt, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
            let minted = match negative_evidence(evidence, query_family, other_generation) {
                Some(evidence) => cache.evict_nxdomain_evidenced(name, evidence),
                None => cache.evict_nxdomain(name),
            };
            minted.map_err(DnsError::Cache)?;
            observer(ObservationPhase::AfterCommit, cache, name, now);
            schedules.commit_nxdomain(index, prepared);
            let sustained = schedules.note_negative_streak(index, now);
            let per_type = [
                schedules
                    .clear_exchange_incident(index, Family::A, now)
                    .map_err(|err| DnsError::Cache(map_schedule(err)))?,
                schedules
                    .clear_exchange_incident(index, Family::Aaaa, now)
                    .map_err(|err| DnsError::Cache(map_schedule(err)))?,
            ];
            Ok(OutcomeIncidents {
                sustained,
                per_type,
            })
        }
        Outcome::NoData {
            family: no_data_family,
            soa,
        } => {
            let prepared = schedules
                .prepare_nodata(index, *no_data_family, *soa, receipt, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
            let minted = match negative_evidence(evidence, query_family, other_generation) {
                Some(evidence) => cache.evict_nodata_evidenced(name, *no_data_family, evidence),
                None => cache.evict_nodata(name, *no_data_family),
            };
            minted.map_err(DnsError::Cache)?;
            observer(ObservationPhase::AfterCommit, cache, name, now);
            schedules.commit_nodata(index, *no_data_family, prepared);
            let mut per_type = [PerTypeTransition::None; 2];
            per_type[family_slot(*no_data_family)] = schedules
                .clear_exchange_incident(index, *no_data_family, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
            Ok(OutcomeIncidents {
                sustained: IncidentTransition::None,
                per_type,
            })
        }
    }
}

const fn negative_evidence(
    evidence: Option<evidence::Evidence>,
    query_family: Option<Family>,
    other_generation: Option<Generation>,
) -> Option<evidence::Evidence> {
    if query_family.is_some() && other_generation.is_some() {
        evidence
    } else {
        None
    }
}

const fn map_schedule(err: crate::dns::schedule::ScheduleError) -> CacheError {
    match err {
        crate::dns::schedule::ScheduleError::NameOutOfRange => CacheError::NameOutOfRange,
        crate::dns::schedule::ScheduleError::DeadlineOverflow => CacheError::DeadlineOverflow,
    }
}

fn reject_obsolete_generation(
    cache: &Cache,
    name: crate::dns::cache::NameIndex,
    context: ApplyContext,
    outcome: &Outcome,
) -> Result<(), DnsError> {
    let ApplyContext {
        generation: queried_generation,
        query_family,
        other_generation,
        ..
    } = context;
    match outcome {
        Outcome::Positive { family, .. } => {
            let queried_now = cache
                .entry(name, *family)
                .map_err(DnsError::Cache)?
                .generation();
            if queried_now != queried_generation {
                return Err(DnsError::Cache(CacheError::StaleGeneration));
            }
        }
        Outcome::NxDomain { .. } => {
            let (Some(query_family), Some(other_generation)) = (query_family, other_generation)
            else {
                return Ok(());
            };
            let other_family = match query_family {
                Family::A => Family::Aaaa,
                Family::Aaaa => Family::A,
            };
            let queried_now = cache
                .entry(name, query_family)
                .map_err(DnsError::Cache)?
                .generation();
            let other_now = cache
                .entry(name, other_family)
                .map_err(DnsError::Cache)?
                .generation();
            if queried_now != queried_generation || other_now != other_generation {
                return Err(DnsError::Cache(CacheError::StaleGeneration));
            }
        }
        Outcome::NoData { family, .. } => {
            let (Some(query_family), Some(_)) = (query_family, other_generation) else {
                return Ok(());
            };
            if *family != query_family {
                return Err(DnsError::Cache(CacheError::StaleGeneration));
            }
            let queried_now = cache
                .entry(name, query_family)
                .map_err(DnsError::Cache)?
                .generation();
            if queried_now != queried_generation {
                return Err(DnsError::Cache(CacheError::StaleGeneration));
            }
        }
    }
    Ok(())
}
