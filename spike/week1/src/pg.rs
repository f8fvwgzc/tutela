//! Postgres helpers. THROWAWAY.

use crate::filter::Param;
use postgres::types::ToSql;
use postgres::{Client, NoTls};

pub fn connect() -> Result<Client, postgres::Error> {
    let url = std::env::var("SPIKE_PG").unwrap_or_else(|_| "host=127.0.0.1 port=5442 user=spike dbname=spike".into());
    Client::connect(&url, NoTls)
}

pub fn boxed(params: &[Param]) -> Vec<Box<dyn ToSql + Sync>> {
    params
        .iter()
        .map(|p| -> Box<dyn ToSql + Sync> {
            match p {
                Param::I64s(v) => Box::new(v.clone()),
                Param::Str(s) => Box::new(s.clone()),
                Param::Strs(v) => Box::new(v.clone()),
                Param::I64(i) => Box::new(*i),
                Param::Bool(b) => Box::new(*b),
            }
        })
        .collect()
}

pub fn refs(b: &[Box<dyn ToSql + Sync>]) -> Vec<&(dyn ToSql + Sync)> {
    b.iter().map(|x| x.as_ref()).collect()
}

pub fn array(v: impl IntoIterator<Item = impl std::fmt::Display>) -> String {
    let parts: Vec<String> = v.into_iter().map(|x| x.to_string()).collect();
    format!("{{{}}}", parts.join(","))
}

pub fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "\\N".into(),
    }
}

pub struct Stats {
    pub n: usize,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
}

/// Percentiles of nanosecond samples, in microseconds.
pub fn stats(mut ns: Vec<u64>) -> Stats {
    ns.sort_unstable();
    let n = ns.len();
    if n == 0 {
        return Stats { n, p50: 0.0, p90: 0.0, p99: 0.0, p999: 0.0, max: 0.0 };
    }
    let at = |q: f64| {
        let i = ((q * n as f64).ceil() as usize).clamp(1, n) - 1;
        ns[i] as f64 / 1000.0
    };
    Stats { n, p50: at(0.50), p90: at(0.90), p99: at(0.99), p999: at(0.999), max: ns[n - 1] as f64 / 1000.0 }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "n={} p50={:.1}us p90={:.1}us p99={:.1}us p99.9={:.1}us max={:.1}us",
            self.n, self.p50, self.p90, self.p99, self.p999, self.max
        )
    }
}
