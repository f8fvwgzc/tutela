#!/usr/bin/env python3
"""Planted bugs ("mutants") for tutela-pdp, run against its own tests.

Each mutant changes one place in the evaluator. The tests must catch every
one: a mutant that survives is a hole in the tests. The script restores each
file after its run, and writes the results to `results.txt` next to it.

Usage, from the repository root, on a quiet machine (one heavy build at a
time):

    python3 crates/tutela-pdp/mutants/mutants.py           # run all
    python3 crates/tutela-pdp/mutants/mutants.py --check   # only check that
                                                           # every mutant applies
    python3 crates/tutela-pdp/mutants/mutants.py --only M19 M20  # run these again
                                                           # and update their lines

Exit code 1 if a mutant does not apply, does not compile, or survives.

Not every guard can be a mutant here. For example, the rule that admin keys
and owner-only actions never pass through delegation is also enforced by the
compiler: a role that holds them may never be given to an agent, and every
actor is an agent. Removing either guard alone changes no answer (an
"equivalent mutant"); both stay as defense in depth.
"""

import datetime
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "crates" / "tutela-pdp" / "src"
# Proptest records the seeds of failing cases here. Under a mutant those are
# failures of the planted bug, so the script removes what it adds.
REGRESSIONS = ROOT / "crates" / "tutela-pdp" / "proptest-regressions"
OUT = pathlib.Path(__file__).resolve().parent / "results.txt"

# (id, file, what it breaks, old text, new text). `old` must occur once.
MUTANTS = [
    ("M01", "eval.rs", "a service account (not only a user) can be the org Owner",
     "    if p.kind() != PrincipalKind::User {\n        return None;\n    }\n    let &bi",
     "    if false {\n        return None;\n    }\n    let &bi"),
    ("M02", "eval.rs", "check: a private scope does not stop inheritance",
     "            if scope.private {",
     "            if false && scope.private {"),
    ("M03", "eval.rs", "a direct assignment no longer beats group ones",
     "    if let Some(&bi) = node.direct.get(p) {\n        return vec![bi];\n    }",
     "    if let Some(&bi) = node.direct.get(p) {\n"
     "        let groups = index.groups_of(p);\n"
     "        let mut out = vec![bi];\n"
     "        out.extend(node.groups.iter().filter(|(g, _)| groups.contains(*g)).map(|(_, &b)| b));\n"
     "        return out;\n    }"),
    ("M04", "eval.rs", "only the first group role at a scope counts",
     "    out.sort_unstable();\n    out\n}",
     "    out.sort_unstable();\n    out.truncate(1);\n    out\n}"),
    ("M05", "eval.rs", "check: conditions never narrow",
     "                if !holds {\n                    eval.item = eval.item.min(c.otherwise);",
     "                if false && !holds {\n                    eval.item = eval.item.min(c.otherwise);"),
    ("M06", "eval.rs", "check: an unknown group does not make the condition false",
     "    if names_unknown_group(ctx.index, when) {",
     "    if false && names_unknown_group(ctx.index, when) {"),
    ("M07", "eval.rs", "field rules at single scopes are ignored",
     "    for node in rule_nodes {",
     "    for node in rule_nodes.iter().take(0) {"),
    ("M08", "pdp.rs", "a delegated request may name a user (not only agents) as an actor",
     "        if actors.iter().any(|a| a.kind() != PrincipalKind::Agent) {",
     "        if false && actors.iter().any(|a| a.kind() != PrincipalKind::Agent) {"),
    ("M09", "eval.rs", "an agent assigned at the org root keeps its access",
     "    if p.kind() == PrincipalKind::Agent && node == last {",
     "    if false && p.kind() == PrincipalKind::Agent && node == last {"),
    ("M10", "pdp.rs", "check: the actors' answers are ignored",
     "            .map(|s| side_allows(ctx, s, &req.action, kind, who.delegated()))",
     "            .take(1)\n            .map(|s| side_allows(ctx, s, &req.action, kind, who.delegated()))"),
    ("M11", "pdp.rs", "a resource of another tenant is not refused",
     "    org.is_some_and(|o| index.orgs.contains(&o))",
     "    org.is_some()"),
    ("M12", "pdp.rs", "the write mask keeps grants_access fields without manage_access",
     "|k| manage_ok || !guarded(k)",
     "|k| manage_ok || guarded(k) || !guarded(k)"),
    ("M13", "pdp.rs", "an org claimed by another tenant is accepted",
     ".is_some_and(|owner| *owner != tenant))",
     ".is_some_and(|owner| *owner != tenant && false))"),
    ("M22", "pdp.rs", "a refused reload already gave up the tenant's org claims",
     "        let index = Index::build(&model, data)?;\n        self.org_claims.retain(|_, owner| *owner != tenant);",
     "        self.org_claims.retain(|_, owner| *owner != tenant);\n        let index = Index::build(&model, data)?;"),
    ("M14", "pdp.rs", "field values of the wrong type act like null",
     "        if !ok {\n            return Err(PdpError::invalid(format!(",
     "        if false && !ok {\n            return Err(PdpError::invalid(format!("),
    ("M15", "filter.rs", "list: private scopes do not stop inheritance",
     "            deciding.insert(x);",
     "            let _ = x;"),
    ("M16", "filter.rs", "list: the next level is not excluded",
     "            parts.push(FilterExpr::not(at_or_under(listed, next)));",
     "            let _ = next;"),
    ("M17", "filter.rs", "list: `under` dropped for a type that is not a container",
     "        under(scopes.iter().map(|&s| s.clone()).collect()),",
     "        under(\n            scopes\n                .iter()\n"
     "                .filter(|s| s.type_name.as_str() != \"box\" && s.type_name.as_str() != \"invoice\")\n"
     "                .map(|&s| s.clone())\n                .collect(),\n        ),"),
    ("M18", "filter.rs", "list: a path may repeat an entry or hold the scope itself",
     "        if !path.iter().all(|e| seen.insert(e)) {",
     "        if false && !path.iter().all(|e| seen.insert(e)) {"),
    ("M19", "filter.rs", "list: paths that disagree are accepted",
     "    placer.check_consistent()?;",
     "    if false {\n        placer.check_consistent()?;\n    }"),
    ("M20", "filter.rs", "list: `not(eq)` becomes `ne`, which is false on null",
     "            Self::Not { arg } => *arg,\n",
     "            Self::Not { arg } => *arg,\n"
     "            Self::Eq { attr, value } => Self::Ne { attr, value },\n"),
    ("M21", "filter.rs", "list: the agent's own filter is dropped",
     "            Some(acc) => acc.and(side),",
     "            Some(acc) => {\n                let _ = side;\n                acc\n            }"),
    ("M23", "data.rs", "a group's own closure costs nothing against the work budget",
     "                if let Some(set) = above.get(p) {\n                    spend(set.len())?;",
     "                if let Some(set) = above.get(p) {"),
    ("M24", "data.rs", "a group in two groups gets only its first holder's groups",
     "            for &p in inside.get(g).into_iter().flatten() {",
     "            for &p in inside.get(g).into_iter().flatten().take(1) {"),
    ("M25", "pdp.rs", "a field that decides access may be left out (read as null)",
     "    if complete\n        && let Some(name) = def",
     "    if false\n        && complete\n        && let Some(name) = def"),
    ("M26", "pdp.rs", "a field integer above 2^53 - 1 is accepted",
     "(FieldType::Integer, AttrValue::Integer(i)) => i.unsigned_abs() <= MAX_JSON_INT,",
     "(FieldType::Integer, AttrValue::Integer(i)) => i.unsigned_abs() <= u64::MAX,"),
    ("M27", "search.rs", "a resource search lists what a field value could still deny",
     ".is_none_or(|c| c.run(&scope.id, &path) == Tri::True);",
     ".is_none_or(|c| c.run(&scope.id, &path) != Tri::False);"),
    ("M28", "search.rs", "a resource search: `not` of an unknown is true",
     "            Self::Unknown => Self::Unknown,\n        }\n    }\n\n    /// The false",
     "            Self::Unknown => Self::True,\n        }\n    }\n\n    /// The false"),
    ("M29", "search.rs", "a resource search lists a row with 33 ancestors",
     "let passes = path.len() <= MAX_PATH\n",
     "let passes = path.len() <= MAX_PATH + 1\n"),
    ("M30", "search.rs", "a resource search: a scope counts as its own ancestor",
     "Self::Under(scopes) => Tri::of(path.iter().any(|a| scopes.contains(a))),",
     "Self::Under(scopes) => Tri::of(path.iter().any(|a| scopes.contains(a)) || scopes.iter().any(|s| s.id == *id)),"),
    ("M31", "search.rs", "a resource search stops at the last result, not the last scope looked at",
     "        for (scanned, scope) in candidates.range((start, Bound::Unbounded)).enumerate() {\n            if results.len() == limit || scanned == MAX_SEARCH_SCAN {\n                next = last.cloned();",
     "        for (scanned, scope) in candidates.range((start, Bound::Unbounded)).enumerate() {\n            if results.len() == limit || scanned == MAX_SEARCH_SCAN {\n                next = results.last().cloned();"),
    ("M32", "search.rs", "a subject search forgets assignments on the resource itself",
     "for scope in core::iter::once(&this).chain(&req.resource.path) {",
     "for scope in core::iter::once(&this).chain(&req.resource.path).skip(1) {"),
    ("M33", "search.rs", "a subject search forgets group members",
     "        if !groups.is_empty() {",
     "        if false && !groups.is_empty() {"),
    ("M34", "search.rs", "a subject search lists every candidate without asking check",
     "            if decision.is_allowed() {",
     "            if true || decision.is_allowed() {"),
    ("M35", "search.rs", "a subject search mixes principal kinds",
     "candidates.extend(s.direct.keys().filter(|p| p.kind() == req.kind));",
     "candidates.extend(s.direct.keys());"),
    ("M36", "moves.rs", "a move ignores moves_out",
     "match rule_stops(b, who, &res.path, left, far, |r| r.moves_out)? {",
     "match rule_stops(b, who, &res.path, left, far, |_| None)? {"),
    ("M37", "moves.rs", "a move ignores moves_in",
     "None => rule_stops(b, who, new_path, entered, far, |r| r.moves_in)?,",
     "None => rule_stops(b, who, new_path, entered, far, |_| None)?,"),
    ("M38", "moves.rs", "a move across teams needs no owners",
     "Some(MoveRule::Members) if far && i == 0 => Some(MoveRule::Owners),",
     "Some(MoveRule::Members) if false && far && i == 0 => Some(MoveRule::Owners),"),
    ("M39", "moves.rs", "the nearest scope has no default rule",
     ".or((i == 0).then_some(MoveRule::Members));",
     ".or(None);"),
    ("M40", "moves.rs", "on_looser = block does not block",
     ".find(|(_, s)| boundary(b, s).on_looser == Some(OnLooser::Block))",
     ".find(|(_, s)| false && boundary(b, s).on_looser == Some(OnLooser::Block))"),
    ("M41", "moves.rs", "a move that widens is not looser",
     "let looser = !complete || !lines.is_empty();",
     "let looser = !complete;"),
    ("M42", "moves.rs", "a comparison that stopped early says nobody gains",
     "let looser = !complete || !lines.is_empty();",
     "let looser = !lines.is_empty();"),
    ("M43", "moves.rs", "anyone named in approved_by approves",
     "ok = ok || may_approve(b, a, s, above(&res.path, i), &key)?;",
     "ok = ok || may_approve(b, a, s, above(&res.path, i), &key).is_ok();"),
    ("M44", "moves.rs", "a delegated mover approves its own move",
     "let mover = (!delegated).then_some(who.subject);",
     "let mover = Some(who.subject);"),
    ("M45", "moves.rs", "a rule left behind counts for nobody below the moved scope",
     "    lines.extend(raised_caps(b, this, &below, &old_rules, &new_rules, &mut budget)?);\n",
     ""),
    ("M46", "moves.rs", "the comparison looks at the moved item only",
     "let below: Vec<(ResourceType, Vec<Access>)> = types_below(&b.model, ty)",
     "let below: Vec<(ResourceType, Vec<Access>)> = BTreeSet::<ResourceType>::new()"),
    ("M47", "impact.rs", "the comparison ignores field rules",
     "                .min(closest_cap(self.ctx, self.rules, h.key, f).0),\n",
     "                .min(Level::Full),\n"),
    ("M48", "impact.rs", "an unknown condition counts at its best on both sides",
     "        (hi1 > lo0, hi0 > lo1)\n",
     "        (hi1 > hi0, hi0 > hi1)\n"),
    ("M49", "moves.rs", "a link ignores links_from",
     "let stopped = match boundary(b, n).links_from {",
     "let stopped = match None::<LinksFrom> {"),
    ("M50", "moves.rs", "a link may point at what the person cannot open",
     "    if !readable {\n",
     "    if false && !readable {\n"),
    ("M51", "moves.rs", "a link needs no write on its source",
     "    let ids = rule_ids(ctx, &sides, &BTreeSet::new());\n    if !allowed.iter().all(|&a| a) {\n        let r = decision_reason(ctx, &walk, &sides, &allowed, &write, kind, who.delegated());",
     "    let ids = rule_ids(ctx, &sides, &BTreeSet::new());\n    if false && !allowed.iter().all(|&a| a) {\n        let r = decision_reason(ctx, &walk, &sides, &allowed, &write, kind, who.delegated());"),
    ("M52", "moves.rs", "a move needs no write on the item",
     "    let ids = rule_ids(ctx, &sides, &BTreeSet::new());\n    if !allowed.iter().all(|&a| a) {\n        let r = decision_reason(ctx, &walk, &sides, &allowed, &write, write_kind, delegated);",
     "    let ids = rule_ids(ctx, &sides, &BTreeSet::new());\n    if false && !allowed.iter().all(|&a| a) {\n        let r = decision_reason(ctx, &walk, &sides, &allowed, &write, write_kind, delegated);"),
    ("M53", "moves.rs", "a move needs no write on the new parent",
     "if !scope_allows(b, who, parent, above(new_path, 0), &write_parent)? {",
     "if false && !scope_allows(b, who, parent, above(new_path, 0), &write_parent)? {"),
    ("M54", "moves.rs", "a move crosses only the first scope of each side",
     "        new.get(..new.len() - shared).unwrap_or_default(),\n",
     "        new.get(..(new.len() - shared).min(1)).unwrap_or_default(),\n"),
    ("M55", "moves.rs", "a move may leave its org",
     "    if res.path.last() != new_path.last() {\n",
     "    if false && res.path.last() != new_path.last() {\n"),
    ("M56", "data.rs", "boundary rules are not loaded",
     "scopes.entry(scope).or_default().boundary = rule;",
     "let _ = (scope, rule);"),
]


def run_tests():
    """Runs the crate's tests; returns (passed, names of failed tests)."""
    proc = subprocess.run(
        ["cargo", "test", "-p", "tutela-pdp", "--lib"],
        cwd=ROOT, capture_output=True, text=True, timeout=1800,
    )
    text = proc.stdout + proc.stderr
    if "could not compile" in text:
        return None, []
    failed = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", text, re.M)))
    return proc.returncode == 0, failed


def main():
    check_only = "--check" in sys.argv
    only = set(sys.argv[sys.argv.index("--only") + 1:]) if "--only" in sys.argv else None
    lines = []
    bad = False
    for mid, name, what, old, new in MUTANTS:
        if only is not None and mid not in only:
            continue
        path = SRC / name
        text = path.read_text()
        if text.count(old) != 1:
            lines.append(f"{mid} {name}: DOES NOT APPLY ({text.count(old)} matches) - {what}")
            bad = True
            continue
        if check_only:
            lines.append(f"{mid} {name}: applies - {what}")
            continue
        before = {f: f.read_text() for f in REGRESSIONS.glob("*")} if REGRESSIONS.exists() else {}
        try:
            path.write_text(text.replace(old, new))
            passed, failed = run_tests()
        finally:
            path.write_text(text)
            for f in REGRESSIONS.glob("*") if REGRESSIONS.exists() else []:
                if f in before:
                    f.write_text(before[f])
                else:
                    f.unlink()
            if REGRESSIONS.exists() and not any(REGRESSIONS.iterdir()):
                REGRESSIONS.rmdir()
        if passed is None:
            lines.append(f"{mid} {name}: DOES NOT COMPILE - {what}")
            bad = True
        elif passed or not failed:
            lines.append(f"{mid} {name}: SURVIVED - {what}")
            bad = True
        else:
            shown = ", ".join(failed[:6]) + (f" and {len(failed) - 6} more" if len(failed) > 6 else "")
            lines.append(f"{mid} {name}: caught by {len(failed)} test(s) - {what}\n      {shown}")
        print(lines[-1], flush=True)
    if check_only:
        print("\n".join(lines))
        return 1 if bad else 0
    if only is not None:
        # Replace the lines of the mutants that ran; keep the others.
        old = OUT.read_text().split("\n") if OUT.exists() else []
        fresh = {line.split(" ", 1)[0]: line for line in lines}
        merged, skip = [], False
        for line in old:
            mid = line.split(" ", 1)[0]
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
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "crates/tutela-pdp/src"],
                           cwd=ROOT, capture_output=True, text=True).stdout.strip()
    tree = "with uncommitted changes in crates/tutela-pdp/src" if dirty else "clean tree"
    rustc = subprocess.run(["rustc", "--version"], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    header = [
        "Planted bugs in tutela-pdp, each run against `cargo test -p tutela-pdp --lib`.",
        f"Date: {datetime.date.today()}. Commit: {head} ({tree}). {rustc}.",
        "Every mutant must be caught. The sources are restored after each run.",
        "Each line names the tests that failed (the first six).",
        "",
    ]
    OUT.write_text("\n".join(header + lines) + "\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
