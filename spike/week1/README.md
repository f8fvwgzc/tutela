# Week-1 spike (THROWAWAY)

This folder is **throwaway spike code**. It is not a member of the Cargo workspace, it is not under the CI gates, and nothing in Tutela may depend on it. It is kept only so the numbers in [ADR-0011](../../docs/DECISIONS.md) can be reproduced. Its outputs live in [`docs/spike-week1-results/`](../../docs/spike-week1-results/). The plan, the sizes and the go/no-go rules were fixed before this code ran: [docs/SPIKE-WEEK1.md](../../docs/SPIKE-WEEK1.md). Delete this folder once `tutela-pdp` has its own benchmarks and differential tests.

## What is here

| File | What |
|---|---|
| `src/model.rs` | Tutela-side data compiled into in-memory indexes |
| `src/tree.rs` | The product's tree with an ancestors list per node |
| `src/eval.rs` | `check` and `list_filter` (two filter forms: `flat` and the default `levels`) |
| `src/filter.rs` | The filter AST, its evaluation on a row, and its SQL (bound parameters only) |
| `src/models.rs` | The fixed big model (notes §4.1) and the random models (notes §6.1) |
| `src/bench.rs` | Question 1: `check` latency |
| `src/closure.rs` | Question 2: closure latency in Postgres |
| `src/diff.rs` | Question 3: `list_filter` ≡ `check` on 100k rows |
| `run.sh` | Waits for a quiet machine, samples `cargo`/`rustc` and load, writes `docs/spike-week1-results/` |

## How to run

You need Rust 1.99 and PostgreSQL 16 on `127.0.0.1:5442` (user `spike`, database `spike`, trust auth; `btree_gin` must be available).

```sh
cargo build --release
./run.sh differential differential            # question 3, seeds 1-20, levels form
SPIKE_FORM=flat ./run.sh differential-flat differential
./run.sh check-latency check-latency           # question 1
./run.sh closure closure                       # question 2
```

`SPIKE_MUTATE=1..7` plants one known bug on the list side (6: in the SQL) to show that the differential test catches it. Never set it for a real run.
