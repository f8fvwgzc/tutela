#!/usr/bin/env python3
"""Planted bugs for the service, run against the tests that must catch them.

Each mutant changes one place in `tutelad` or `tutela-store`, and runs the
named test targets on a real Postgres. A mutant that survives is a hole in the
tests. The script restores each file after its run, and writes the results to
`results.txt` next to it. It is not part of `make`; the tests it runs are.

Usage, from the repository root, with the same environment as `make`
(`TUTELA_TEST_DATABASE_URL` set, `TUTELA_REQUIRE_DATABASE=1`):

    python3 crates/tutelad/mutants/mutants.py              # run all
    python3 crates/tutelad/mutants/mutants.py --check      # only check they apply
    python3 crates/tutelad/mutants/mutants.py --only S01   # run these

Exit code 1 if a mutant does not apply, does not compile, or survives.
"""

import datetime
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = pathlib.Path(__file__).resolve().parent / "results.txt"
MODELS = "crates/tutelad/src/models/mod.rs"

# (id, file, what it breaks, old text, new text, cargo test arguments).
# `old` must occur once.
#
# Not every guard can be a mutant. `models::principal` refuses agents, and
# the evaluator never gives them an admin key either, so removing the first
# alone changes no answer. It stays as defense in depth.
MUTANTS = [
    ("S01", MODELS, "a widening publish needs no token",
     "    if d.is_widening() {\n",
     "    if false && d.is_widening() {\n",
     ["-p", "tutelad", "--test", "models"]),
    ("S02", MODELS, "a token for the whole app approves one tenant's change",
     "approval::verify(token, &key.public_key, app, from, to, Some(&tid), now)",
     "approval::verify(token, &key.public_key, app, from, to, None, now)",
     ["-p", "tutelad", "--test", "models"]),
    ("S03", MODELS, "anyone in the tenant may publish",
     "            if !decision.is_allowed() {\n                return Err(Problem::forbidden());\n",
     "            if false && !decision.is_allowed() {\n                return Err(Problem::forbidden());\n",
     ["-p", "tutelad", "--test", "models"]),
    ("S04", MODELS, "the keys at one org are enough for a tenant of two",
     "    for org in orgs {\n",
     "    for org in orgs.into_iter().take(1) {\n",
     ["-p", "tutelad", "--test", "models"]),
    ("S06", "crates/tutela-store/src/manifest.rs", "an app publish overwrites a tenant's own model",
     'if head.as_ref().is_none_or(|(_, origin)| origin != "tenant") {',
     "if true {",
     ["-p", "tutela-store", "--lib"]),
]


def run(args):
    r = subprocess.run(["cargo", "test", "--offline", *args], cwd=ROOT,
                       capture_output=True, text=True)
    text = r.stdout + r.stderr
    if "could not compile" in text:
        return None, []
    failed = [l.split()[1] for l in text.splitlines()
              if l.startswith("test ") and l.rstrip().endswith("FAILED")]
    return r.returncode == 0, failed


def main():
    argv = sys.argv[1:]
    check_only = "--check" in argv
    only = argv[argv.index("--only") + 1:] if "--only" in argv else None
    bad = False
    lines = []
    for mid, file, what, old, new, args in MUTANTS:
        if only is not None and mid not in only:
            continue
        path = ROOT / file
        src = path.read_text()
        if src.count(old) != 1:
            lines.append(f"{mid}: DOES NOT APPLY ({src.count(old)} matches) - {what}")
            print(lines[-1], flush=True)
            bad = True
            continue
        if check_only:
            continue
        try:
            path.write_text(src.replace(old, new))
            passed, failed = run(args)
        finally:
            path.write_text(src)
        if passed is None:
            lines.append(f"{mid}: DOES NOT COMPILE - {what}")
            bad = True
        elif passed or not failed:
            lines.append(f"{mid}: SURVIVED - {what}")
            bad = True
        else:
            shown = ", ".join(failed[:4]) + (f" and {len(failed) - 4} more" if len(failed) > 4 else "")
            lines.append(f"{mid}: caught by {len(failed)} test(s) - {what}\n      {shown}")
        print(lines[-1], flush=True)
    if check_only:
        return 1 if bad else 0
    if only is not None:
        old = OUT.read_text().split("\n") if OUT.exists() else []
        fresh = {line.split(":", 1)[0]: line for line in lines}
        merged, skip = [], False
        for line in old:
            mid = line.split(":", 1)[0]
            if mid in fresh:
                merged.append(fresh.pop(mid))
                skip = True
                continue
            if skip and line.startswith("      "):
                continue
            skip = False
            merged.append(line)
        merged.extend(fresh.values())
        OUT.write_text("\n".join(merged).rstrip("\n") + "\n")
        return 1 if bad else 0
    header = [
        "Planted bugs in the service, each run against the tests named in mutants.py.",
        f"Date: {datetime.date.today()}. Every mutant must be caught.",
        "",
    ]
    OUT.write_text("\n".join(header + lines) + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
