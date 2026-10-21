//! Alumina binary: fixed documented config inputs, no CLI or
//! environment policy overrides. Runs the boot harness (privilege check,
//! config read incl. the validated resolver set, 128 MiB traffic store +
//! serving workspaces), then
//! continues the same owner into the shared-readiness runtime: the serving
//! workspaces are preallocated before the boot-owned startup DNS window, the
//! canonical readiness rule runs (the listener opens for a serving decision;
//! an unresolved count beyond the allowance exits `EX_TEMPFAIL` 75), and a
//! serving decision attaches the startup listener and enters the serving loop
//! for the process lifetime. A boot or startup failure exits `EX_CONFIG` (78)
//! with a diagnostic naming the field/source.

use alumina::boot::{BootReport, EX_CONFIG, run_boot};
use alumina::runtime::Preallocated;
use alumina::serve::{ServeStorage, StartupDecision};

/// Fixed documented input path, relative to the working directory. No CLI
/// arguments or environment variables are read as policy (see README).
const CONFIG_PATH: &str = "config.toml";
const EX_TEMPFAIL: i32 = 75;
const EX_SOFTWARE: i32 = 70;

/// Cache and startup time are process-relative whole seconds; receipt and
/// readiness snapshots share this origin.
const PROCESS_EPOCH_SECS: u64 = 0;

fn main() {
    emit_kernel_facts();
    match run_boot(CONFIG_PATH) {
        Ok(report) => {
            println!(
                "inventory named fixed buffers (lower bound): {} (traffic {} + serving workspace {} + dns named buffers {})",
                report.inventory.named_fixed_buffer_bytes(),
                report.inventory.traffic_storage_bytes(),
                report.inventory.serving_workspace_bytes(),
                report.inventory.dns_named_buffer_bytes(),
            );
            println!(
                "inventory transient scratch (config doc buffer, not retained): {}",
                report.inventory.transient_scratch_bytes()
            );
            println!(
                "inventory reserved-future: boot-owned best-effort log queue (256 records x 8 KiB), reserved and initialized once by the log store at boot and retained for the process lifetime: {}",
                report.inventory.reserved_future_bytes()
            );
            println!(
                "resolver first nameserver: {} port {}",
                report.config.resolver_set().primary().addr(),
                report.config.resolver_set().primary().port()
            );
            print_resolver_warnings(&report);
            println!(
                "allowlist entries: {} allowance: {} listen: {}:{}",
                report.config.allowlist().len(),
                report.config.startup_unresolved_allowance(),
                report.config.listen().ip(),
                report.config.listen().port()
            );
            let storage = match ServeStorage::boot(&report.config) {
                Ok(storage) => storage,
                Err(err) => {
                    write_stderr(format_args!("alumina: serving storage: {err}\n"));
                    std::process::exit(EX_CONFIG);
                }
            };
            let mut owner = match Preallocated::preallocate(storage, report.storage) {
                Ok(owner) => owner,
                Err(err) => {
                    write_stderr(format_args!("alumina: serving workspace: {err}\n"));
                    std::process::exit(EX_CONFIG);
                }
            };
            if owner.prepare_stdout_log_sink().is_err() {
                write_stderr(format_args!(
                    "alumina: cannot prepare the stdout log sink\n"
                ));
                std::process::exit(EX_CONFIG);
            }
            let nameserver = std::net::SocketAddr::new(
                report.config.resolver_set().primary().addr(),
                report.config.resolver_set().primary().port(),
            );
            match owner.run_startup(nameserver, PROCESS_EPOCH_SECS) {
                Ok(outcome) => match outcome.decision {
                    StartupDecision::Serve(_mode) => {
                        let Some(listener) = outcome.listener else {
                            owner.emit_fatal_and_drain(format_args!(
                                "alumina: serving decision without a bound listener",
                            ));
                            std::process::exit(EX_SOFTWARE);
                        };
                        let Ok(runtime) = owner.attach(listener) else {
                            std::process::exit(EX_SOFTWARE);
                        };
                        match runtime.serve() {
                            Err(_) => std::process::exit(EX_SOFTWARE),
                            Ok(never) => match never {},
                        }
                    }
                    StartupDecision::Exit75 { .. } => std::process::exit(EX_TEMPFAIL),
                    StartupDecision::Terminated => {
                        owner.emit_shutdown_and_drain();
                        std::process::exit(0);
                    }
                },
                Err(err) => {
                    owner.emit_fatal_and_drain(format_args!("alumina: startup: {err}"));
                    std::process::exit(EX_CONFIG);
                }
            }
        }
        Err(err) => {
            write_stderr(format_args!("alumina: {err}\n"));
            std::process::exit(EX_CONFIG);
        }
    }
}

/// Prints one stdout startup warning line per resolver entry whose trust form
/// is degraded but operator-visible at boot: bare-IP entries (no `IP#fqdn`
/// FQDN, plain DNS only) and `IP#fqdn` entries without a strict `#pin-sha256=`
/// pin (`DoT` against an empty root store, deterministic fail-closed until a
/// trust-anchor intake lands). Boot-time only; never on a serving path.
fn print_resolver_warnings(report: &BootReport) {
    for nameserver in report.ip_only_resolvers() {
        println!(
            "alumina: warning: resolver {} has no FQDN (IP#fqdn) metadata; plain DNS over port 53 only — the future DoT (853) SNI/SAN identity surface is unavailable",
            nameserver.addr()
        );
    }
    for nameserver in report.unpinned_dot_resolvers() {
        if let Some(fqdn) = nameserver.fqdn() {
            println!(
                "alumina: warning: resolver {} ({}) has no #pin-sha256= pin; DoT (853) validates against an empty root store and fails closed until a trust-anchor intake lands",
                nameserver.addr(),
                fqdn.as_str()
            );
        }
    }
}

fn write_stderr(args: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = std::io::stderr().write_fmt(args);
}

#[cfg(feature = "fixture-facts")]
fn emit_kernel_facts() {
    match alumina::preflight::read_kernel_facts() {
        Ok(facts) => eprintln!(
            "kernel-facts: ruid={} euid={} suid={} fsuid={} cap_eff={:x} cap_prm={:x} cap_amb={:x} no_new_privs={}",
            facts.ruid,
            facts.euid,
            facts.suid,
            facts.fsuid,
            facts.cap_eff,
            facts.cap_prm,
            facts.cap_amb,
            u8::from(facts.no_new_privs)
        ),
        Err(err) => eprintln!("kernel-facts: unreadable: {}", err),
    }
}

#[cfg(not(feature = "fixture-facts"))]
const fn emit_kernel_facts() {}
