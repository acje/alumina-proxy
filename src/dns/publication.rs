use crate::cache::{Cache, CacheError, Family, Generation, StagedPositive};
use crate::dns::{DnsError, Outcome};
use crate::schedule::{
    IncidentTransition, OutcomeIncidents, PerTypeTransition, Schedules, family_slot,
};

/// Applies a validated `outcome` to the cache and schedule for one allowlist
/// `index`, using the in-flight `generation` and the monotonic `receipt` and
/// `now` values. Only validated outcomes mutate state. Returns the incident
/// deltas the outcome produced for the name: the sustained-negative delta plus
/// the per-type exchange-failure deltas in A/Aaaa slot order.
///
/// # Errors
///
/// Returns `DnsError::Cache` when the cache or schedule refuses the mutation
/// without changing any entry.
pub fn apply_outcome(
    cache: &mut Cache,
    schedules: &mut Schedules,
    index: usize,
    generation: Generation,
    receipt: u64,
    now: u64,
    outcome: &Outcome,
) -> Result<OutcomeIncidents, DnsError> {
    let name = cache
        .name_index(index)
        .ok_or(DnsError::Cache(CacheError::NameOutOfRange))?;
    match outcome {
        Outcome::Positive {
            bindings,
            ttl,
            family: positive_family,
        } => {
            let staged = StagedPositive::stage(
                name,
                *positive_family,
                generation,
                bindings.as_slice(),
                receipt,
                *ttl,
            )
            .map_err(DnsError::Cache)?;
            let cacheable = bindings.as_slice().iter().any(|b| b.is_eligible());
            let prepared = schedules
                .prepare_positive(index, *positive_family, receipt, *ttl, cacheable, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
            cache.publish_positive(&staged).map_err(DnsError::Cache)?;
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
            cache.evict_nxdomain(name).map_err(DnsError::Cache)?;
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
            cache
                .evict_nodata(name, *no_data_family)
                .map_err(DnsError::Cache)?;
            schedules.commit_nodata(index, *no_data_family, prepared);
            Ok(OutcomeIncidents {
                sustained: IncidentTransition::None,
                per_type: [PerTypeTransition::None; 2],
            })
        }
    }
}

const fn map_schedule(err: crate::schedule::ScheduleError) -> CacheError {
    match err {
        crate::schedule::ScheduleError::NameOutOfRange => CacheError::NameOutOfRange,
        crate::schedule::ScheduleError::DeadlineOverflow => CacheError::DeadlineOverflow,
    }
}
