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
mod run_live;
mod sandbox;
mod system_one;

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
        Some("system-one") => system_one::run(&args[1..]),
        Some("live") => run_live::live(&args[1..]),
        Some("live-suite") => live_suite::run(&args[1..]),
        Some("ctl") => run_live::ctl(&args[1..]),
        Some("hud") => hud::run(&args[1..]),
        Some("mock-model") => mock::mock_model(&args[1..]),
        Some("fixture-server") => mock::fixture_server(&args[1..]),
        Some("differential-cases") => differential::run(&args[1..]),
        _ => Err("usage: containment-lab attack-suite [--repeat N] [--out FILE] | live --policy FILE --task TEXT | ctl --run DIR status|stop|reset MODE".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("containment-lab: {error}");
            ExitCode::FAILURE
        }
    }
}
