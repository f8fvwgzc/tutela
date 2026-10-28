//! THROWAWAY week-1 spike for Tutela. See docs/SPIKE-WEEK1.md.
//!
//!   tutela-spike-week1 check-latency       question 1
//!   tutela-spike-week1 closure             question 2 (Postgres on port 5442)
//!   tutela-spike-week1 differential [--no-sql] [--threads N] [--seeds A-B]

mod bench;
mod closure;
mod diff;
mod eval;
mod filter;
mod models;
mod model;
mod pg;
mod rng;
mod tree;

const BIG_SEED: u64 = 2026_10_28;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    match args.get(1).map(String::as_str) {
        Some("check-latency") => bench::run(BIG_SEED),
        Some("closure") => closure::run(&mut pg::connect()?, BIG_SEED)?,
        Some("differential") => {
            let threads: usize = flag("--threads").and_then(|t| t.parse().ok()).unwrap_or(4);
            let (a, b) = flag("--seeds")
                .and_then(|s| s.split_once('-').map(|(a, b)| (a.parse().ok(), b.parse().ok())))
                .and_then(|(a, b)| Some((a?, b?)))
                .unwrap_or((1u64, 20u64));
            let seeds: Vec<u64> = (a..=b).collect();
            let ok = if args.iter().any(|a| a == "--no-sql") {
                diff::run(None, &seeds, threads)?
            } else {
                let mut c = pg::connect()?;
                diff::run(Some(&mut c), &seeds, threads)?
            };
            if !ok {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: tutela-spike-week1 check-latency | closure | differential [--no-sql] [--threads N] [--seeds A-B]");
            std::process::exit(2);
        }
    }
    Ok(())
}
