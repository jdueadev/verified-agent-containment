//! Linux containment prototype and adversarial test harness.

mod agent;
mod common;
mod controller;
mod differential;
mod harness;
mod helpers;
mod sandbox;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("attack-suite") => harness::run(&args[1..]),
        Some("controller") => controller::run(&args[1..]),
        Some("sandbox-launch") => sandbox::launch(&args[1..]),
        Some("agent") => agent::run(&args[1..]),
        Some("monitor") => helpers::monitor(&args[1..]),
        Some("sink") => helpers::sink(&args[1..]),
        Some("probe-operator") => helpers::probe_operator(&args[1..]),
        Some("differential-cases") => differential::run(&args[1..]),
        _ => Err("usage: containment-lab attack-suite [--repeat N] [--out FILE]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("containment-lab: {error}");
            ExitCode::FAILURE
        }
    }
}
