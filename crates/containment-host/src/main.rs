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
mod sandbox_grants;
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
";

fn main() -> ExitCode {
    // Arguments are decoded explicitly: a non-UTF-8 argument is a usage error, not a panic.
    let args: Result<Vec<String>, _> = std::env::args_os().skip(1).map(std::ffi::OsString::into_string).collect();
    let Ok(args) = args else {
        eprintln!("containment-lab: arguments must be valid UTF-8");
        return ExitCode::from(2);
    };
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
        Some("system-one") => system_one::run(&args[1..]),
        Some("live") => run_live::live(&args[1..]),
        Some("live-suite") => live_suite::run(&args[1..]),
        Some("ctl") => run_live::ctl(&args[1..]),
        Some("hud") => hud::run(&args[1..]),
        Some("redteam") => redteam::run(&args[1..]),
        Some("mock-model") => mock::mock_model(&args[1..]),
        Some("fixture-server") => mock::fixture_server(&args[1..]),
        Some("differential-cases") => differential::run(&args[1..]),
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
