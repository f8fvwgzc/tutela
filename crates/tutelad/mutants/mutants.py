#!/usr/bin/env python3
"""Planted bugs for the service, run against the tests that must catch them.

Each mutant changes one place in `tutelad`, `tutela-store` or
`tutela-contracts`, and runs the
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
EXPLAIN = "crates/tutelad/src/authz/explain.rs"
TWO = ["-p", "tutelad", "--test", "two_person"]
KEYS_STORE = "crates/tutela-store/src/signing_keys.rs"
CONFIG = "crates/tutelad/src/config.rs"
SDK_CLAIMS = "crates/tutela-contracts/src/claims.rs"
EXCHANGE_SRC = "crates/tutelad/src/exchange.rs"
REVOCATION = "crates/tutelad/src/revocation.rs"
PRINCIPALS = "crates/tutela-store/src/principals.rs"
EXCHANGE = ["-p", "tutelad", "--test", "exchange"]

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
    ("S07", EXPLAIN, "explain and simulate need no admin key",
     "    if decision.is_allowed() {\n        Ok(())",
     "    if true || decision.is_allowed() {\n        Ok(())",
     ["-p", "tutelad", "--test", "explain"]),
    ("S08", EXPLAIN, "a made-up path is believed",
     "    verify_path(&snapshot.paths, tenant, resource)?;\n",
     "",
     ["-p", "tutelad", "--test", "explain"]),
    ("S09", EXPLAIN, "a simulation ignores its what-if assignments",
     "        what_if(&mut data, &c)?;\n",
     "        let _ = &c;\n",
     ["-p", "tutelad", "--test", "explain"]),
    ("S10", MODELS, "the proposer approves its own proposal",
     "    if by == p.proposed_by {\n",
     "    if false && by == p.proposed_by {\n",
     TWO),
    ("S11", MODELS, "a proposal whose report changed is approved",
     "(impact.digest != p.impact_digest)",
     "(false && impact.digest != p.impact_digest)",
     TWO),
    ("S12", MODELS, "a proposal with a report cut short ignores changes",
     "} else if !p.impact_complete && now.bundle.rev != p.rev {",
     "} else if false && !p.impact_complete && now.bundle.rev != p.rev {",
     TWO),
    ("S13", "crates/tutela-store/src/models.rs", "a direct publish ignores two-person",
     "    require_one_person(tx, &tid).await?;\n",
     "",
     TWO),
    ("S14", "crates/tutela-store/src/proposals.rs", "one person turns two-person off",
     "(false, true, Some(first)) if first != by => TwoPerson {",
     "(false, true, _) => TwoPerson {",
     TWO),
    ("S15", MODELS, "a proposal ignores a new active model",
     "let why = if now.active.version != p.base_version || now.active.digest != p.base_digest {",
     "let why = if false {",
     TWO),
    # Part 3a: the service's own keys, token exchange, admin and delegated
    # tokens (ADR-0030 to ADR-0033).
    ("T01", KEYS_STORE, "a private key is stored in plain text",
     "    let sealed = vault\n        .seal(PURPOSE, kid.as_bytes(), pkcs8.as_ref())\n",
     "    let sealed = Ok::<_, StoreError>(pkcs8.as_ref().to_vec())\n        .map(|v| v)\n",
     ["-p", "tutela-store", "--lib", "tm15"]),
    ("T02", CONFIG, "a missing master key still starts",
     '        LocalKms::from_values(master, master_previous).map_err(|e| anyhow!("{e}"))?;\n'
     '        let master = present(master).context("TUTELA_MASTER_KEY is not set")?;\n',
     '        let master = present(master)\n'
     '            .unwrap_or("00000000000000000000000000000000000000000000000000000000000000ff");\n',
     ["-p", "tutelad", "--lib", "tm22"]),
    ("T03", KEYS_STORE, "a denied key is not denied",
     '"UPDATE tutela.signing_key SET denied_at = coalesce(denied_at, $2) WHERE kid = $1"',
     '"UPDATE tutela.signing_key SET denied_at = denied_at WHERE kid = $1 AND $2::timestamptz IS NOT NULL"',
     ["-p", "tutelad", "--test", "keys"]),
    ("T04", KEYS_STORE, "the next key signs at once, before any cache has it",
     "    let signs_from = now + times.lead;\n",
     "    let signs_from = now;\n",
     ["-p", "tutelad", "--test", "keys"]),
    ("T05", SDK_CLAIMS, "an issuer may speak for any tenant",
     "        if !trusted.allows(self.iss, self.tid) {\n",
     "        if false && !trusted.allows(self.iss, self.tid) {\n",
     EXCHANGE),
    ("T06", EXCHANGE_SRC, "a token of another issuer is exchanged in its tenant",
     "        Identity::Access(c) if c.iss == *state.keys.iss() => Tenant::of(&id),\n",
     "        Identity::Access(_) => Tenant::of(&id),\n",
     EXCHANGE),
    ("T07", EXCHANGE_SRC, "an expired subject token is exchanged",
     "    if exp <= now {\n        return Err(Refusal::grant(\"expired\"));\n",
     "    if false && exp <= now {\n        return Err(Refusal::grant(\"expired\"));\n",
     EXCHANGE),
    ("T08", EXCHANGE_SRC, "a replayed subject token is exchanged",
     "    if !tutela_store::note_exchange(tx, key, &t.tenant.iss, &jti, expires).await? {\n",
     "    if tutela_store::note_exchange(tx, key, &t.tenant.iss, &jti, expires).await? && false {\n",
     EXCHANGE),
    ("T09", EXCHANGE_SRC, "a disabled person gets a token",
     "    if person.disabled {\n",
     "    if false && person.disabled {\n",
     EXCHANGE),
    ("T10", REVOCATION, "a raised epoch or a disabled principal is still accepted",
     "        if book.current(sub, epoch) && !actors.iter().any(|a| book.disabled(a)) {\n",
     "        if true || book.current(sub, epoch) && !actors.iter().any(|a| book.disabled(a)) {\n",
     EXCHANGE),
    ("T11", EXCHANGE_SRC, "a revoked token of this service is exchanged again",
     "    if known.is_some_and(|s| s.disabled || c.epoch < s.epoch) {\n",
     "    if false && known.is_some_and(|s| s.disabled || c.epoch < s.epoch) {\n",
     EXCHANGE),
    ("T12", PRINCIPALS, "one upstream subject is one person across issuers",
     "         WHERE a.tenant_id = $1 AND a.iss = $2 AND a.sub = $3\"\n",
     "         WHERE a.tenant_id = $1 AND $2::text IS NOT NULL AND a.sub = $3\"\n",
     EXCHANGE),
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
