import { describe, expect, it } from "vitest";

import {
  draftOf,
  draftWidens,
  grantsLine,
  impactSentences,
  ModelEditError,
  permissionMatrix,
  type Role,
  type RolesAnswer,
  setRoleGrants,
} from "../src/index.js";

const answer: RolesAnswer = {
  version: 4,
  roles: [
    {
      key: "approver",
      levels: { invoice: "write", project: "write" },
      field_levels: { "invoice.amount": "read", "invoice.@ai": "full" },
      grants: ["invoice:approve", "project:manage_access"],
      assignable_to: ["user", "sa"],
    },
    {
      key: "reader",
      levels: { invoice: "read", project: "read" },
      field_levels: { "invoice.amount": "write" },
      grants: [],
      assignable_to: ["user", "group"],
    },
    {
      key: "owner",
      seeded: "owner",
      levels: { org: "full", invoice: "full", project: "full" },
      field_levels: {},
      grants: ["org:read_audit"],
      assignable_to: ["user", "sa"],
    },
  ],
  types: [
    {
      name: "project",
      parents: ["org"],
      container: true,
      starts_private: false,
      fields: [],
      features: [],
      actions: [],
    },
    {
      name: "invoice",
      label: "Invoice",
      parents: ["project"],
      container: false,
      starts_private: false,
      fields: [
        { name: "amount", sensitivity: "confidential" },
        { name: "status", sensitivity: "internal", label: "Status" },
      ],
      features: ["@ai"],
      actions: ["approve"],
    },
  ],
};

const role = (key: string): Role => {
  const r = answer.roles.find((x) => x.key === key);
  if (r === undefined) throw new Error(key);
  return r;
};

describe("the permission matrix", () => {
  const m = permissionMatrix(answer);
  const row = (key: string) => {
    const r = m.rows.find((x) => x.key === key);
    if (r === undefined) throw new Error(key);
    return r;
  };

  it("has field, feature, action and admin rows under their type", () => {
    const keys = m.rows.map((r) => r.key);
    const at = (k: string) => keys.indexOf(k);
    expect(at("invoice")).toBeLessThan(at("invoice.amount"));
    expect(at("invoice.amount")).toBeLessThan(at("invoice.@ai"));
    expect(at("invoice.@ai")).toBeLessThan(at("invoice:approve"));
    expect(at("invoice:approve")).toBeLessThan(at("invoice:manage_access"));
    expect(row("invoice.status").label).toBe("Status");
    expect(row("invoice.amount").sensitivity).toBe("confidential");
    // org gets rows because a role names it.
    expect(at("org")).toBe(0);
  });

  it("reads a type cell from levels, none when missing", () => {
    expect(m.cell(role("approver"), row("invoice"))).toEqual({ level: "write", inherited: false });
    expect(m.cell(role("approver"), row("org"))).toEqual({ level: "none", inherited: false });
  });

  it("never shows a field above the item level, and a missing field as the item level", () => {
    expect(m.cell(role("reader"), row("invoice.amount"))).toEqual({
      level: "read",
      inherited: false,
    });
    expect(m.cell(role("approver"), row("invoice.amount"))).toEqual({
      level: "read",
      inherited: false,
    });
    expect(m.cell(role("approver"), row("invoice.status"))).toEqual({
      level: "write",
      inherited: true,
    });
  });

  it("lets a feature be above the item level (MANIFEST.md 5)", () => {
    expect(m.cell(role("approver"), row("invoice.@ai"))).toEqual({
      level: "full",
      inherited: false,
    });
  });

  it("reads actions and admin keys from grants", () => {
    expect(m.cell(role("approver"), row("invoice:approve"))).toEqual({ granted: true });
    expect(m.cell(role("reader"), row("invoice:approve"))).toEqual({ granted: false });
    expect(m.cell(role("approver"), row("project:manage_access"))).toEqual({ granted: true });
    expect(m.cell(role("owner"), row("org:read_audit"))).toEqual({ granted: true });
  });
});

describe("a role draft", () => {
  it("writes grants in a stable order, with quoted keys where TOML needs them", () => {
    expect(grantsLine(draftOf(role("approver")))).toBe(
      'grants = { invoice = "write", project = "write", "invoice.@ai" = "full", "invoice.amount" = "read", "invoice:approve" = true, "project:manage_access" = true }',
    );
  });

  it("says when it widens: a higher level, a higher field, a new grant", () => {
    const d = draftOf(role("reader"));
    expect(draftWidens(role("reader"), d)).toBe(false);
    expect(draftWidens(role("reader"), { ...d, levels: { ...d.levels, invoice: "write" } })).toBe(
      true,
    );
    expect(draftWidens(role("reader"), { ...d, grants: ["invoice:approve"] })).toBe(true);
    expect(draftWidens(role("reader"), { ...d, levels: { ...d.levels, invoice: "none" } })).toBe(
      false,
    );
    expect(draftWidens(undefined, d)).toBe(true);
  });
});

const MANIFEST = `version = 1   # the format
[app]
name = "crm"

# Readers read.
[roles.reader]
label = "Reader"
grants = { project = "read", invoice = "read" }   # keep this comment
assignable_to = ["user", "group"]

[roles.approver]
grants = {
  project = "write",
  invoice = "write",
  "invoice:approve" = true,
}

[[conditions]]
role = "approver"
type = "invoice"
when = { eq = { field = "status", value = "open" } }
else = "read"
`;

describe("setRoleGrants", () => {
  it("replaces one role's inline grants and leaves every other byte", () => {
    const d = {
      ...draftOf(role("reader")),
      levels: { project: "read" as const, invoice: "write" as const },
      field_levels: {},
    };
    const out = setRoleGrants(MANIFEST, d);
    expect(out).toBe(
      MANIFEST.replace(
        'grants = { project = "read", invoice = "read" }',
        'grants = { invoice = "write", project = "read" }',
      ),
    );
  });

  it("replaces a multi-line inline table (TOML 1.1)", () => {
    const d = {
      key: "approver",
      levels: { project: "write" as const, invoice: "write" as const },
      field_levels: {},
      grants: [],
    };
    const out = setRoleGrants(MANIFEST, d);
    expect(out).toContain(
      '[roles.approver]\ngrants = { invoice = "write", project = "write" }\n\n[[conditions]]',
    );
    expect(out).toContain('grants = { project = "read", invoice = "read" }   # keep this comment');
  });

  it("rewrites a [roles.<key>.grants] table", () => {
    const src = `[roles.auditor]\nlabel = "Auditor"\n\n[roles.auditor.grants]\nproject = "read"\n\n[ui."x"]\nactions = ["project:read"]\n`;
    const out = setRoleGrants(src, {
      key: "auditor",
      levels: { project: "write" },
      field_levels: {},
      grants: ["project:read_audit"],
    });
    expect(out).toBe(
      `[roles.auditor]\nlabel = "Auditor"\n\n[roles.auditor.grants]\nproject = "write"\n"project:read_audit" = true\n\n[ui."x"]\nactions = ["project:read"]\n`,
    );
  });

  it("adds a role the manifest does not declare (a seeded role, a new role) at the end", () => {
    const out = setRoleGrants(MANIFEST, {
      key: "viewer",
      levels: { project: "read" },
      field_levels: {},
      grants: [],
    });
    expect(out).toBe(`${MANIFEST}\n[roles.viewer]\ngrants = { project = "read" }\n`);
  });

  it("adds grants to a declared role that has none", () => {
    const src = `[roles.empty]\nlabel = "Empty"\n`;
    expect(
      setRoleGrants(src, {
        key: "empty",
        levels: { project: "read" },
        field_levels: {},
        grants: [],
      }),
    ).toBe(`[roles.empty]\ngrants = { project = "read" }\nlabel = "Empty"\n`);
  });

  it("does not take a header inside a multi-line string for a table", () => {
    const src = `[types.note]\nparent = "org"\nlabel = """\n[roles.reader]\ngrants = { project = "full" }\n"""\n\n[roles.reader]\ngrants = { project = "read" }\n`;
    const out = setRoleGrants(src, {
      key: "reader",
      levels: { project: "write" },
      field_levels: {},
      grants: [],
    });
    expect(out).toContain('label = """\n[roles.reader]\ngrants = { project = "full" }\n"""');
    expect(out.endsWith('[roles.reader]\ngrants = { project = "write" }\n')).toBe(true);
  });

  it("finds a quoted header key", () => {
    const src = `[ roles . "reader" ]\ngrants = { project = "read" }\n`;
    expect(setRoleGrants(src, { key: "reader", levels: {}, field_levels: {}, grants: [] })).toBe(
      `[ roles . "reader" ]\ngrants = {}\n`,
    );
  });

  it("refuses the owner role, a [roles] table and dotted grants", () => {
    const d = { key: "owner", levels: {}, field_levels: {}, grants: [] };
    expect(() => setRoleGrants(MANIFEST, d)).toThrow(ModelEditError);
    expect(() =>
      setRoleGrants(`[roles]\nreader = { grants = {} }\n`, { ...d, key: "reader" }),
    ).toThrow(ModelEditError);
    expect(() =>
      setRoleGrants(`[roles.reader]\ngrants.project = "read"\n`, { ...d, key: "reader" }),
    ).toThrow(ModelEditError);
    expect(() => setRoleGrants(MANIFEST, { ...d, key: "Bad Key" })).toThrow(ModelEditError);
  });
});

describe("impact sentences", () => {
  const impact = {
    complete: true,
    no_impact: false,
    summary: ["12 users gain read on contract"],
    lines: [],
    omitted_lines: 0,
    digest: "d",
  };

  it("are the server's summary", () => {
    expect(impactSentences(impact)).toEqual(["12 users gain read on contract"]);
  });

  it("say nobody gains or loses for no impact", () => {
    expect(impactSentences({ ...impact, no_impact: true, summary: [] })).toEqual([
      "Nobody gains or loses access.",
    ]);
  });

  it("never read a cut-short report as complete", () => {
    expect(impactSentences({ ...impact, complete: false, omitted_lines: 3 })).toEqual([
      "12 users gain read on contract",
      "And 3 more changes.",
      "The report stopped at its bound: there may be more than this.",
    ]);
  });
});
