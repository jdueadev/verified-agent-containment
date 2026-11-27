//! Linux containment prototype and adversarial test harness.

mod agent;
mod agent_loop;
mod common;
mod controller;
mod differential;
mod harness;
mod helpers;
mod http;
mod hud;
mod live;
mod live_suite;
mod mock;
mod redteam;
mod run_live;
mod sandbox;
mod sandbox_view;
mod system_one;

use std::process::ExitCode;

const USAGE: &str = "\
Usage: containment-lab <COMMAND> [OPTIONS]

Commands (each takes --help):
  attack-suite    run the Linux attack suite and its sabotaged controllers
  live            run a live agent with a local model under a policy
  ctl             status, stop or signed reset for a running live controller
  hud             serve the read-only HUD for a running live controller
  live-suite      run the live-mode suite with a scripted model
  redteam         run the red-team pack against a model and write a scorecard
  mock-model      scripted OpenAI-compatible model server (for tests)
  fixture-server  fixture HTTP server (for tests)
  kernel-cases    turn a live run's private/kernel.jsonl into differential cases

attack-suite, live, live-suite and redteam run attack code as root. They refuse
to start unless FACTORY_LAB_DISPOSABLE=1 says this machine is disposable.
";

/// The marker that says this machine is disposable. The same name gates
/// `scripts/factory.sh lab` and every root script under `scripts/`.
const DISPOSABLE_MARKER: &str = "FACTORY_LAB_DISPOSABLE";

/// Commands that run attack code as root. Each refuses to start without the marker.
const ROOT_COMMANDS: &[&str] = &["attack-suite", "live", "live-suite", "redteam"];

/// Commands that start no attack code of their own: help and version, the test
/// servers, the differential and kernel cases, `ctl` and `hud` (which talk to a controller a
/// root command already started), and the internal children a root command spawns,
/// some of them with a cleared environment that could not carry the marker.
/// `tools/lab_throwaway_check.py` fails if a command is in neither list; only it and
/// the tests below read this one.
#[cfg(test)]
const NO_MARKER_COMMANDS: &[&str] = &[
    "controller", "sandbox-launch", "agent", "monitor", "sink", "probe-operator", "probe-root", "system-one",
    "ctl", "hud", "mock-model", "fixture-server", "differential-cases", "kernel-cases",
];

/// Why `command` may not start here, or `None` when it may.
fn disposable_refusal(command: &str, marker: Option<&str>) -> Option<String> {
    if !ROOT_COMMANDS.contains(&command) || marker == Some("1") {
        return None;
    }
    Some(format!(
        "containment-lab: {command} runs attack code as root, so it runs only on a disposable Linux or WSL2 machine.\n\
         containment-lab: on such a machine, set {DISPOSABLE_MARKER}=1 to confirm \
         (sudo {DISPOSABLE_MARKER}=1 containment-lab {command} ...), or run scripts/factory.sh lab.\n"
    ))
}

fn main() -> ExitCode {
    // Arguments are decoded explicitly: a non-UTF-8 argument is a usage error, not a panic.
    let args: Result<Vec<String>, _> = std::env::args_os().skip(1).map(std::ffi::OsString::into_string).collect();
    let Ok(args) = args else {
        eprintln!("containment-lab: arguments must be valid UTF-8");
        return ExitCode::from(2);
    };
    if let Some(refusal) = args.first().and_then(|c| disposable_refusal(c, std::env::var(DISPOSABLE_MARKER).ok().as_deref())) {
        eprint!("{refusal}");
        return ExitCode::FAILURE;
    }
    let result = match args.first().map(String::as_str) {
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Some("-V" | "--version") => {
            println!("containment-lab {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("attack-suite") => harness::run(&args[1..]),
        Some("controller") => controller::run(&args[1..]),
        Some("sandbox-launch") => sandbox::launch(&args[1..]),
        Some("agent") => agent::run(&args[1..]),
        Some("monitor") => helpers::monitor(&args[1..]),
        Some("sink") => helpers::sink(&args[1..]),
        Some("probe-operator") => helpers::probe_operator(&args[1..]),
        Some("probe-root") => helpers::probe_root(&args[1..]),
        Some("system-one") => system_one::run(&args[1..]),
        Some("live") => run_live::live(&args[1..]),
        Some("live-suite") => live_suite::run(&args[1..]),
        Some("ctl") => run_live::ctl(&args[1..]),
        Some("hud") => hud::run(&args[1..]),
        Some("redteam") => redteam::run(&args[1..]),
        Some("mock-model") => mock::mock_model(&args[1..]),
        Some("fixture-server") => mock::fixture_server(&args[1..]),
        Some("differential-cases") => differential::run(&args[1..]),
        Some("kernel-cases") => differential::kernel_cases(&args[1..]),
        Some(other) => Err(Box::new(common::UsageError(format!("error: unknown command '{other}'\n\n{USAGE}"))) as Box<dyn std::error::Error>),
        None => Err(Box::new(common::UsageError(USAGE.to_owned())) as Box<dyn std::error::Error>),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.is::<common::UsageError>() => {
            eprint!("{error}");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("containment-lab: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_commands_refuse_without_the_marker_and_name_the_fix() {
        for command in ROOT_COMMANDS {
            for marker in [None, Some(""), Some("0"), Some("yes"), Some("1 ")] {
                let refusal = disposable_refusal(command, marker).unwrap_or_else(|| panic!("{command} started with {marker:?}"));
                assert!(refusal.contains("FACTORY_LAB_DISPOSABLE=1"), "{refusal}");
            }
            assert_eq!(disposable_refusal(command, Some("1")), None, "{command}");
        }
    }

    #[test]
    fn other_commands_need_no_marker() {
        for command in NO_MARKER_COMMANDS {
            assert_eq!(disposable_refusal(command, None), None, "{command}");
        }
    }
}
