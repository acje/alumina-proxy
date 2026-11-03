pub use crate::dns::schedule::{
    BACKOFF_STAGES, DueToken, INCIDENT_M, INCIDENT_N, INCIDENT_WINDOW, IncidentTransition,
    NEGATIVE_REFRESH_MIN, OutcomeIncidents, PerTypeTransition, REFRESH_MAX, REFRESH_MIN,
    ScheduleError, Schedules, Soa, negative_refresh_interval, normal_refresh_interval,
};
