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
DELEGATION = ["-p", "tutelad", "--test", "delegation"]
STORE_AUDIT = "crates/tutela-store/src/audit.rs"
ISOLATION = "crates/tutela-store/src/isolation.rs"
AUDIT_SQL = "crates/tutela-store/migrations/0008_audit_log.sql"
STORE_TM20 = ["-p", "tutela-store", "--lib", "tm20"]
AUDIT = ["-p", "tutelad", "--test", "audit"]
WRITE_SRC = "crates/tutelad/src/authz/write.rs"
EVENTS_SRC = "crates/tutela-store/src/events.rs"
STORE_LIB = "crates/tutela-store/src/lib.rs"
STORE_EVENTS = ["-p", "tutela-store", "--lib"]
EVENTS = ["-p", "tutelad", "--test", "events"]
HOOKS_SRC = "crates/tutelad/src/webhooks.rs"
HOOKS_STORE = "crates/tutela-store/src/webhooks.rs"
HOOKS = ["-p", "tutelad", "--test", "webhooks"]
HOOKS_ALL = ["-p", "tutelad", "--test", "webhooks", "--lib"]
STREAM_SRC = "crates/tutelad/src/stream.rs"
SSE = ["-p", "tutelad", "--test", "sse"]
BUNDLE_SRC = "crates/tutelad/src/bundle.rs"
BUNDLE_SDK = "crates/tutela-sdk/src/bundle.rs"
BUNDLE = ["-p", "tutelad", "--test", "bundle"]
LEDGER_SRC = "crates/tutelad/src/ledger.rs"
LEDGER = ["-p", "tutelad", "--test", "ledger"]
ADMIN_MOD = "crates/tutelad/src/admin/mod.rs"
ADMIN_PRINCIPALS = "crates/tutelad/src/admin/principals.rs"
ADMIN_BOUNDARIES = "crates/tutelad/src/admin/boundaries.rs"
ADMIN_TYPES = "crates/tutelad/src/admin/types.rs"
ADMIN = ["-p", "tutelad", "--test", "admin"]
ADMIN_LIB = ["-p", "tutelad", "--lib", "admin::"]
STORE_LIFECYCLE = "crates/tutela-store/src/lifecycle.rs"
STORE_BINDINGS = "crates/tutela-store/src/bindings.rs"
STORE_WRITE = "crates/tutela-store/src/write.rs"
ADMIN_LIFECYCLE = "crates/tutelad/src/admin/lifecycle.rs"
LIFECYCLE_SQL = "crates/tutela-store/migrations/0012_lifecycle.sql"
LIFECYCLE = ["-p", "tutelad", "--test", "lifecycle"]

# (id, file, what it breaks, old text, new text, cargo test arguments).
# `old` must occur once.
#
# Not every guard can be a mutant. `models::principal` refuses agents, and
# the evaluator never gives them an admin key either, so removing the first
# alone changes no answer. It stays as defense in depth. The same holds for
# the check of attache's path on a workload actor in `exchange::actor`: the
# store refuses to register any other path, and a CHECK in migration 7 holds
# it, so no agent can be found for one (an equivalent mutant, run and kept
# out of this list).
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
     'let follows = head.as_ref().is_none_or(|(_, origin)| origin != "tenant");',
     "let follows = true;",
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
     "        Identity::Access(c) if c.iss == *own_iss => Tenant::of(&id),\n",
     "        Identity::Access(_) => Tenant::of(&id),\n",
     EXCHANGE),
    ("T07", EXCHANGE_SRC, "an expired subject token is exchanged",
     ".min(now + state.audiences.token_ttl.as_secs().min(ttl));\n    if exp <= now {\n",
     ".min(now + state.audiences.token_ttl.as_secs().min(ttl));\n    if false && exp <= now {\n",
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
     "    if known.is_some_and(|s| s.disabled || epoch < s.epoch) {\n",
     "    if false && known.is_some_and(|s| s.disabled || epoch < s.epoch) {\n",
     EXCHANGE),
    ("T12", PRINCIPALS, "one upstream subject is one person across issuers",
     "         WHERE a.tenant_id = $1 AND a.iss = $2 AND a.sub = $3\"\n",
     "         WHERE a.tenant_id = $1 AND $2::text IS NOT NULL AND a.sub = $3\"\n",
     EXCHANGE),
    ("T13", MODELS, "a person's tutela-authz token opens the admin routes",
     "        PrincipalKind::User => admin && step_up(c.acr.as_deref()),\n",
     "        PrincipalKind::User => true,\n",
     ["-p", "tutelad", "--test", "models"]),
    ("T14", EXCHANGE_SRC, "an admin token is issued without step-up",
     "        if !state.audiences.is_step_up(subject.acr.as_deref()) {\n",
     "        if false && !state.audiences.is_step_up(subject.acr.as_deref()) {\n",
     EXCHANGE),
    ("T15", MODELS, "a service's admin token opens the admin routes",
     "        PrincipalKind::ServiceAccount | PrincipalKind::Key => !admin,\n",
     "        PrincipalKind::ServiceAccount | PrincipalKind::Key => true,\n",
     ["-p", "tutelad", "--test", "models"]),
    ("T16", EXCHANGE_SRC, "an admin token lives as long as an access token",
     "        MAX_ADMIN_TOKEN_LIFETIME_SECS\n",
     "        MAX_ACCESS_TOKEN_LIFETIME_SECS\n",
     EXCHANGE),
    ("T17", EXCHANGE_SRC, "a delegated token is issued for an audience that is not delegation-aware",
     "            .is_some_and(|r| r.delegation_aware)\n",
     "            .is_some_and(|_| true)\n",
     DELEGATION),
    ("T18", EXCHANGE_SRC, "an actor gets the person's own token: wider than the person AND the agent",
     "    let delegating = actor_token.is_some() || matches!(id, Identity::Delegated(_));\n",
     "    let delegating = false && (actor_token.is_some() || matches!(id, Identity::Delegated(_)));\n",
     DELEGATION),
    ("T19", EXCHANGE_SRC, "a disabled or unknown agent acts",
     "        Some(s) if s.principal.kind() == PrincipalKind::Agent && !s.disabled => Ok(s),\n",
     "        Some(s) => Ok(s),\n        None if false => Ok(PrincipalState { principal: a.clone(), epoch: 0, disabled: false, workload: None }),\n",
     DELEGATION),
    ("T20", EXCHANGE_SRC, "an agent token of another tenant acts",
     "            if c.tid != tid {\n                return Err(Refusal::grant(\"actor_tenant\"));\n            }\n            let known = agent(tx, &c.sub).await?;\n",
     "            let known = agent(tx, &c.sub).await?;\n",
     DELEGATION),
    ("T21", EXCHANGE_SRC, "a chain past four actors is issued",
     "    act.check_chain().map_err(|_| Refusal::grant(\"chain\"))?;\n",
     "",
     DELEGATION),
    ("T22", REVOCATION, "a disabled actor's delegated token is still accepted",
     "        if book.current(sub, epoch) && !actors.iter().any(|a| book.disabled(a)) {\n",
     "        if book.current(sub, epoch) {\n",
     DELEGATION),
    # The local audit log (ADR-0034).
    ("A01", MODELS, "the publish record is written outside the change's transaction, before it",
     "    let author = actor.to_string();\n    let mut conn = state.db.conn().await?;\n    let tx = conn.begin(&tenant).await?;\n    let stored = tutela_store::publish_tenant_model(\n",
     "    let author = actor.to_string();\n    audit::write_alone(state, &tenant, vec![Published { version: expected + 1, rev: now.bundle.rev, author: &author, approvers: Vec::new(), class: \"neutral\", restores, impact_digest: &impact.digest, from: &now.active.digest, to: &to }.record(&tenant, &actor)]).await?;\n    let mut conn = state.db.conn().await?;\n    let tx = conn.begin(&tenant).await?;\n    let stored = tutela_store::publish_tenant_model(\n",
     AUDIT),
    ("A02", MODELS, "a close that did not happen is recorded as done",
     "        StoreErrorKind::NotFound => conflict(\"not_open\", \"this proposal is not open\"),\n        _ => e.into(),\n    })?;\n    let rev = tutela_store::rev(&tx, tenant.key()).await?;\n",
     "        StoreErrorKind::NotFound => conflict(\"not_open\", \"this proposal is not open\"),\n        _ => e.into(),\n    }).ok();\n    let rev = tutela_store::rev(&tx, tenant.key()).await?;\n",
     AUDIT),
    ("A03", STORE_AUDIT, "the verifier does not check the link to the record before",
     "            } else if e.prev_hash != prev {\n",
     "            } else if false && e.prev_hash != prev {\n",
     STORE_TM20),
    ("A04", STORE_AUDIT, "the verifier does not see a missing record",
     "            let problem = if e.seq != expected {\n",
     "            let problem = if false && e.seq != expected {\n",
     STORE_TM20),
    ("A05", STORE_AUDIT, "the verifier does not see the last records gone",
     "    if last != head_seq || (head_seq > 0 && prev != head_hash) {\n",
     "    if false && (last != head_seq || (head_seq > 0 && prev != head_hash)) {\n",
     STORE_TM20),
    ("A06", STORE_AUDIT, "a record of another tenant goes into this tenant's chain",
     "    if drafts.iter().any(|d| d.tenant.tid != *tid) {\n",
     "    if false && drafts.iter().any(|d| d.tenant.tid != *tid) {\n",
     STORE_TM20),
    ("A07", AUDIT_SQL, "the database lets a record be changed or removed",
     "    RAISE EXCEPTION 'the audit log is append-only'\n        USING ERRCODE = 'integrity_constraint_violation';\n",
     "    RETURN NULL;\n",
     STORE_TM20),
    ("A08", ISOLATION, "the service role may change the audit log",
     "    (\"audit_record\", \"SELECT, INSERT\"),\n",
     "    (\"audit_record\", \"SELECT, INSERT, UPDATE, DELETE\"),\n",
     AUDIT),
    ("A09", EXCHANGE_SRC, "a refused exchange of a known tenant leaves no record",
     "    if let (Err(refusal), Some(tenant)) = (&result, &trail.tenant) {\n",
     "    if let (Err(refusal), Some(tenant)) = (&result, &None::<Tenant>) {\n",
     EXCHANGE),
    ("A10", EXPLAIN, "an explain answers with no record of who asked",
     "        record_asked(state, &tenant, id, OP, &ask, rev, e.decision.is_allowed()).await?;\n",
     "",
     AUDIT),
    ("A11", WRITE_SRC, "a write-check deny leaves no record",
     "    if d.effect == Effect::Allow && d.moved.is_none() && denied_links.is_empty() {\n",
     "    if true || (d.effect == Effect::Allow && d.moved.is_none() && denied_links.is_empty()) {\n",
     AUDIT),
    ("A12", REVOCATION, "a token may speak as tutelad itself",
     "        if sub.to_string() == crate::audit::SYSTEM {\n",
     "        if false && sub.to_string() == crate::audit::SYSTEM {\n",
     AUDIT),
    # The transactional outbox (ADR-0035).
    ("E01", MODELS, "a publish emits its event outside its transaction, before it",
     "    let author = actor.to_string();\n",
     "    let author = actor.to_string();\n    {\n        let mut c = state.db.conn().await?;\n        let t = c.begin(&tenant).await?;\n        tutela_store::emit(&t, tenant.key(), tutela_store::OutboxEvent::ModelPublished { rev: now.bundle.rev + 1 }).await?;\n        t.commit().await?;\n    }\n",
     EVENTS),
    # A person found again returns before the event, so "announce every
    # sign-in as a new person" is an equivalent mutant; this is the real one.
    ("E02", PRINCIPALS, "a new person is not announced",
     "    if created {\n",
     "    if false && created {\n",
     EXCHANGE),
    ("E03", EVENTS_SRC, "event numbers are not given in commit order",
     '            "UPDATE tutela.tenant_rev SET event_seq = event_seq + 1 WHERE tenant_id = $1 \\\n             RETURNING event_seq",\n',
     '            "SELECT coalesce(max(seq), 0) + 1 FROM tutela.event WHERE tenant_id = $1",\n',
     STORE_EVENTS),
    ("E04", EVENTS_SRC, "a reader walks events out of order",
     "                 ORDER BY seq LIMIT $3\"\n",
     "                 ORDER BY id DESC LIMIT $3\"\n",
     STORE_EVENTS),
    ("E05", PRINCIPALS, "a session revocation announces no new epoch",
     "                principal: principal.clone(),\n                epoch,\n                sid: None,\n",
     "                principal: principal.clone(),\n                epoch: 0,\n                sid: None,\n",
     STORE_EVENTS),
    ("E06", PRINCIPALS, "disabling a principal announces nothing",
     "        out.push(crate::events::OutboxEvent::PrincipalDisabled {\n            principal: principal.clone(),\n            epoch,\n        });\n",
     "",
     STORE_EVENTS),
    ("E07", STORE_LIB, "a data change announces no new revision",
     "    events::insert(\n        tx,\n        &tenant.tid,\n        &events::OutboxEvent::PermissionsChanged { rev },\n    )\n    .await?;\n",
     "",
     STORE_EVENTS),
    # Webhooks (ADR-0036).
    ("W01", HOOKS_SRC, "a webhook may be sent to a private address",
     "        let client = Client::new(\n            policy\n",
     "        let client = Client::new(\n            policy.dev_loopback()\n",
     HOOKS),
    ("W02", HOOKS_SRC, "a webhook is sent unsigned",
     "            (\"webhook-signature\", signature.as_str()),\n",
     "",
     HOOKS),
    ("W03", HOOKS_SRC, "a webhook is signed without its timestamp",
     "    msg.extend_from_slice(timestamp.to_string().as_bytes());\n    msg.push(b'.');\n",
     "",
     HOOKS_ALL),
    ("W04", HOOKS_SRC, "a webhook URL is stored without its check",
     "    client.check(url).await.map_err(|e| {\n",
     "    Ok::<_, tutela_safenet::SafenetError>(()).map_err(|e| {\n",
     HOOKS),
    ("W05", HOOKS_STORE, "an event goes before an earlier one of its subject",
     "                 AND e.subject = d.subject AND e.state = 'pending' AND e.seq < d.seq) \\\n",
     "                 AND false) \\\n",
     HOOKS),
    ("W06", HOOKS_STORE, "a second replica takes a delivery the first one holds",
     "               AND (d.claimed_until IS NULL OR d.claimed_until < clock_timestamp()) \\\n",
     "",
     HOOKS),
    ("W07", HOOKS_SRC, "a failing delivery is retried for ever",
     "            if age >= self.settings.give_up {\n",
     "            if false && age >= self.settings.give_up {\n",
     HOOKS),
    ("W08", HOOKS_STORE, "the old secret stops signing at once on a rotation",
     "        if let (Some(p), Some(v), Some(true)) = (previous, previous_version, overlapping) {\n",
     "        if let (Some(p), Some(v), Some(false)) = (previous, previous_version, overlapping) {\n",
     HOOKS),
    # SSE GET /v1/events (ADR-0037).
    ("X01", STREAM_SRC, "a stream joins another tenant's feed",
     "        if let Some(tx) = feeds.get(tenant.key()) {\n",
     "        if let Some(tx) = feeds.values().next() {\n",
     SSE),
    ("X02", STREAM_SRC, "a person may listen to the tenant's events",
     "                PrincipalKind::ServiceAccount | PrincipalKind::Key\n",
     "                PrincipalKind::ServiceAccount | PrincipalKind::Key | PrincipalKind::User\n",
     SSE),
    ("X03", STREAM_SRC, "a resumed stream skips what it missed",
     "                    self.queue.extend(first);\n                    self.phase = Phase::Replay;\n",
     "                    self.queue.extend(first);\n                    self.phase = Phase::Live;\n",
     SSE),
    ("X04", STREAM_SRC, "an unknown Last-Event-ID resumes with no reset",
     "    if lost {\n        first.push(reset());\n    }\n",
     "",
     SSE),
    ("X05", STREAM_SRC, "a slow client is never reset",
     "                        Some(Err(broadcast::error::RecvError::Lagged(_))) => {\n                            self.queue.push_back(reset());\n                            self.phase = Phase::End;\n                        }\n",
     "                        Some(Err(broadcast::error::RecvError::Lagged(_))) => {}\n",
     SSE),
    ("X06", STREAM_SRC, "a replica opens streams without bound",
     "    if hub.open.fetch_add(1, Ordering::SeqCst) >= hub.settings.max_streams {\n",
     "    if false && hub.open.fetch_add(1, Ordering::SeqCst) >= hub.settings.max_streams {\n",
     SSE),
    ("X07", STREAM_SRC, "a denied kid is never pushed after the first message",
     "            if denied.as_ref() != Some(&kids) {\n",
     "            if denied.is_none() {\n",
     SSE),
    ("X08", STREAM_SRC, "a stream outlives its age limit",
     "        until: now + left.min(settings.max_age),\n",
     "        until: now + left,\n",
     SSE),
    # Signed bundles (ADR-0038).
    ("B01", BUNDLE_SRC, "a bundle outlives the first assignment in it that expires",
     "        end = end.min(started + left);\n",
     "        let _ = left;\n",
     BUNDLE),
    ("B02", BUNDLE_SRC, "a bundle is signed as an access token",
     "    let jws = state.keys.sign_jwt(BUNDLE_TYP, &claims).map_err(|e| {\n",
     "    let jws = state.keys.sign_jwt(\"at+jwt\", &claims).map_err(|e| {\n",
     BUNDLE),
    ("B03", BUNDLE_SDK, "a bundle of a denied kid verifies",
     "        if self.denied.read().map_or(true, |d| d.contains(&kid)) {\n",
     "        if false && self.denied.read().map_or(true, |d| d.contains(&kid)) {\n",
     BUNDLE),
    ("B04", BUNDLE_SDK, "an offline PDP answers past the bundle's exp",
     "        if self.clock.now() >= self.exp {\n",
     "        if false && self.clock.now() >= self.exp {\n",
     BUNDLE),
    ("B05", BUNDLE_SDK, "an older bundle replaces a newer one",
     "        if self.rev.is_some_and(|r| b.rev < r) {\n",
     "        if false && self.rev.is_some_and(|r| b.rev < r) {\n",
     BUNDLE),
    ("B06", BUNDLE_SRC, "any service of the tenant pulls the whole tenant",
     "    let who = crate::models::admin(state, id, &tenant, &crate::models::READ_KEYS).await?;\n",
     "    let who = crate::models::admin(state, id, &tenant, &[]).await?;\n",
     BUNDLE),
    ("B07", BUNDLE_SDK, "an expired bundle verifies",
     "        if now >= claims.exp {\n",
     "        if false && now >= claims.exp {\n",
     BUNDLE),
    ("B08", BUNDLE_SDK, "a bundle of a tenant the issuer may not speak for verifies",
     "        if !self.config.trust.allows(&claims.iss, &claims.tid) {\n",
     "        if false && !self.config.trust.allows(&claims.iss, &claims.tid) {\n",
     BUNDLE),
    # Forwarding to attache's evidence ledger (ADR-0039).
    ("L01", LEDGER_SRC, "a batch the ledger did not take is marked shipped",
     "                    tracing::warn!(reason = why, \"the ledger did not take a batch; it waits\");\n                    None\n",
     "                    tracing::warn!(reason = why, \"the ledger did not take a batch; it waits\");\n                    Some(last)\n",
     LEDGER),
    ("L02", LEDGER_SRC, "a record is signed over other bytes than its body",
     "            let sig = self.pair.sign(e.body.as_bytes());\n",
     "            let sig = self.pair.sign(e.id.as_bytes());\n",
     LEDGER),
    ("L03", STORE_AUDIT, "a second replica sends a chain another one holds",
     "             WHERE tenant_id = $1 AND (claimed_until IS NULL \\\n               OR claimed_until < clock_timestamp() OR claimed_by = $2) \\\n",
     "             WHERE tenant_id = $1 \\\n",
     LEDGER),
    # The admin API, tutela.admin.v1 (ADR-0040).
    ("D01", MODELS, "an admin call takes a person's plain tutela-authz token",
     "        PrincipalKind::User => admin && step_up(c.acr.as_deref()),\n",
     "        PrincipalKind::User => !admin || step_up(c.acr.as_deref()),\n",
     ADMIN),
    ("D02", ADMIN_PRINCIPALS, "an agent of another tenant is changed through this one",
     "        None => Err(not_found()),\n",
     "        None => Ok(PrincipalState {\n            principal: p.clone(),\n            epoch: 0,\n            disabled: false,\n            workload: None,\n        }),\n",
     ADMIN),
    ("D03", ADMIN_PRINCIPALS, "a disabled agent's token still works",
     "    let epoch = tutela_store::set_disabled(&tx, tenant.key(), &p, disabled)\n",
     "    let epoch = tutela_store::set_disabled(&tx, tenant.key(), &p, false)\n",
     ADMIN),
    ("D04", ADMIN_PRINCIPALS, "disabling or enabling a principal leaves no audit record",
     "    audit::write(\n        state,\n        &tx,\n        vec![\n            Record::new(\n                tenant.key(),\n                Actor::new(by),\n                action,\n                (\"tutela_principal\", &name),\n            )\n            .allowed(rev)\n            .detail(\"principal\", name.clone())\n            .detail(\"epoch\", epoch)\n            .detail(\"rev\", rev),\n        ],\n    )\n    .await?;\n    tx.commit().await?;\n    tracing::info!(disabled",
     "    tx.commit().await?;\n    let _ = (by, action);\n    tracing::info!(disabled",
     ADMIN),
    ("D05", ADMIN_BOUNDARIES, "a scope's rules are set without manage_boundaries on it",
     "    if !decision.is_allowed() {\n",
     "    if false && !decision.is_allowed() {\n",
     ADMIN),
    ("D06", ADMIN_MOD, "a refused admin call leaves no record",
     "    let Some(actor) = audit::actor_of(id) else {\n",
     "    let Some(actor) = audit::actor_of(id).filter(|_| false) else {\n",
     ADMIN),
    ("D07", ADMIN_TYPES, "a pushed type changes what the model has",
     "            (_, Some(old)) if *old == value => {}\n            _ => return Err(not_additive(ty, &key)),\n",
     "            (_, Some(old)) => *old = value,\n",
     ADMIN_LIB),
    ("D08", ADMIN_PRINCIPALS, "registering an agent needs no admin key",
     "        &AGENT_KEYS,\n        action,\n        (\"tutela_principal\", \"agent\"),\n",
     "        &[],\n        action,\n        (\"tutela_principal\", \"agent\"),\n",
     ADMIN),
    # The lifecycle of tenants, orgs and people (ADR-0041).
    ("G01", STORE_LIB, "a soft-deleted tenant still answers",
     "        None if deleted => Err(StoreError::unknown_tenant()),\n",
     "        None if false && deleted => Err(StoreError::unknown_tenant()),\n",
     LIFECYCLE),
    ("G02", STORE_LIFECYCLE, "a purge deletes the audit chain",
     "const PURGED: [&str; 16] = [\n    \"webhook_delivery\",\n",
     "const PURGED: [&str; 17] = [\n    \"audit_record\",\n    \"webhook_delivery\",\n",
     LIFECYCLE),
    ("G03", STORE_BINDINGS, "the jobs still visit a soft-deleted tenant",
     "FROM tutela.tenant WHERE deleted_at IS NULL ORDER BY tenant_id",
     "FROM tutela.tenant ORDER BY tenant_id",
     LIFECYCLE),
    ("G04", ADMIN_LIFECYCLE, "a tenant's deletion leaves no audit record",
     "    audit::write(\n        state,\n        &tx,\n        vec![\n            Record::new(\n                tenant.key(),\n                Actor::new(by.clone()),\n                action,\n                (\"tutela_tenant\", &tid),\n            )\n            .allowed(rev)\n            .detail(\"purge_after\", when.clone()),\n        ],\n    )\n    .await?;\n",
     "    let _ = rev;\n",
     LIFECYCLE),
    ("G05", STORE_WRITE, "new data is written under a soft-deleted org",
     "                 AND deleted_at IS NULL\",\n                &[&tid, &org.to_string()],\n",
     "                 \",\n                &[&tid, &org.to_string()],\n",
     LIFECYCLE),
    ("G06", ADMIN_LIFECYCLE, "a new org gets no owner, so its tenant has no admin",
     "RoleKey::parse(crate::lifecycle::OWNER_ROLE)",
     "RoleKey::parse(\"reader\")",
     LIFECYCLE),
    ("G07", STORE_LIFECYCLE, "a deleted person keeps its upstream account",
     "\"DELETE FROM tutela.upstream_account WHERE tenant_id = $1 AND principal = $2\"",
     "\"DELETE FROM tutela.upstream_account WHERE false AND tenant_id = $1 AND principal = $2\"",
     LIFECYCLE),
    ("G08", ADMIN_LIFECYCLE, "an org is renamed without manage_access on it",
     "        if !d.is_allowed() {\n",
     "        if false && !d.is_allowed() {\n",
     LIFECYCLE),
    ("G09", LIFECYCLE_SQL, "the service role updates any tenant of the directory",
     "    USING (tenant_id = current_setting('tutela.tenant_id', true))\n    WITH CHECK (tenant_id = current_setting('tutela.tenant_id', true));\n",
     "    USING (true)\n    WITH CHECK (true);\n",
     LIFECYCLE),
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
