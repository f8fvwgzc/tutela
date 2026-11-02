/**
 * The permission matrix and role changes, without a framework.
 *
 * - {@link permissionMatrix}: roles × types from `GET /v1/admin/roles`, as
 *   the ROADMAP notes for part 4b define it.
 * - {@link setRoleGrants}: a role change is a model change. It rewrites one
 *   role's `grants` in the active `tutela.resources.toml` and leaves every
 *   other byte alone. `tutelad` compiles the result, reports its impact and
 *   refuses a widening change without an approval token: this code is a
 *   text edit, never a security decision.
 */

import { TutelaError } from "./errors.js";
import {
  ADMIN_KEYS,
  type Impact,
  LEVELS,
  type Level,
  type ModelChange,
  type ResourceTypeInfo,
  type Role,
  type RolesAnswer,
} from "./types.js";

/** The kind of a matrix row. */
export type MatrixRowKind = "type" | "field" | "feature" | "action" | "admin";

/** One row of the matrix: a type, or a field, feature, action or admin key under it. */
export interface MatrixRow {
  kind: MatrixRowKind;
  /** The type the row is under. */
  type: string;
  /** The permission key: `contract`, `contract.title`, `contract.@ai`, `contract:approve`. */
  key: string;
  /** For people: the label, or the name. */
  label: string;
  /** A field's sensitivity. */
  sensitivity?: string;
}

/** A cell: a level for types, fields and features; held or not for actions and admin keys. */
export type MatrixCell = { level: Level; inherited: boolean } | { granted: boolean };

/** The matrix of roles × permission keys. */
export interface PermissionMatrix {
  version: number;
  roles: Role[];
  rows: MatrixRow[];
  cell(role: Role, row: MatrixRow): MatrixCell;
}

/** The lower of two levels. */
export function minLevel(a: Level, b: Level): Level {
  return LEVELS.indexOf(a) <= LEVELS.indexOf(b) ? a : b;
}

/** `true` when `a` is above `b`. */
export function above(a: Level, b: Level): boolean {
  return LEVELS.indexOf(a) > LEVELS.indexOf(b);
}

function typeRows(t: ResourceTypeInfo): MatrixRow[] {
  const rows: MatrixRow[] = [{ kind: "type", type: t.name, key: t.name, label: t.label ?? t.name }];
  for (const f of t.fields) {
    rows.push({
      kind: "field",
      type: t.name,
      key: `${t.name}.${f.name}`,
      label: f.label ?? f.name,
      sensitivity: f.sensitivity,
    });
  }
  for (const feature of t.features) {
    const name = feature.startsWith("@") ? feature : `@${feature}`;
    rows.push({ kind: "feature", type: t.name, key: `${t.name}.${name}`, label: name });
  }
  for (const a of t.actions) {
    rows.push({ kind: "action", type: t.name, key: `${t.name}:${a}`, label: a });
  }
  for (const k of ADMIN_KEYS) {
    rows.push({ kind: "admin", type: t.name, key: `${t.name}:${k}`, label: k });
  }
  return rows;
}

/**
 * The permission matrix of a roles answer: for each type, its row, then its
 * fields, features, custom actions and admin keys. A type cell is
 * `levels[type]` (missing: `none`); a field cell is `field_levels` (missing:
 * the item level, and never above it); a feature cell may be above the item
 * level (MANIFEST.md 5); an action or admin key is held when it is in
 * `grants`. `org` gets rows when a role names it.
 */
export function permissionMatrix(answer: RolesAnswer): PermissionMatrix {
  const types = [...answer.types];
  const namesOrg = answer.roles.some(
    (r) => r.levels.org !== undefined || r.grants.some((g) => g.startsWith("org:")),
  );
  if (namesOrg && !types.some((t) => t.name === "org")) {
    types.unshift({
      name: "org",
      label: "Org",
      parents: [],
      container: true,
      starts_private: false,
      fields: [],
      features: [],
      actions: [],
    });
  }
  const rows = types.flatMap(typeRows);
  return {
    version: answer.version,
    roles: answer.roles,
    rows,
    cell(role, row) {
      const item: Level = role.levels[row.type] ?? "none";
      switch (row.kind) {
        case "type":
          return { level: item, inherited: false };
        case "field": {
          const own = role.field_levels[row.key];
          return own === undefined
            ? { level: item, inherited: true }
            : { level: minLevel(own, item), inherited: false };
        }
        case "feature": {
          const own = role.field_levels[row.key];
          return own === undefined
            ? { level: item, inherited: true }
            : { level: own, inherited: false };
        }
        case "action":
        case "admin":
          return { granted: role.grants.includes(row.key) };
      }
    },
  };
}

/** A role as the editor changes it. */
export interface RoleDraft {
  key: string;
  levels: Record<string, Level>;
  field_levels: Record<string, Level>;
  grants: string[];
}

/** A copy of `role` to edit. */
export function draftOf(role: Role): RoleDraft {
  return {
    key: role.key,
    levels: { ...role.levels },
    field_levels: { ...role.field_levels },
    grants: [...role.grants],
  };
}

/**
 * The `grants` entries of a draft, in a stable order: item levels, then
 * field and feature levels, then actions and admin keys. A `none` item
 * level is left out (a type a role does not list is `none`).
 */
export function grantEntries(d: RoleDraft): [string, Level | true][] {
  const byKey = (a: [string, unknown], b: [string, unknown]) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
  const levels = Object.entries(d.levels)
    .filter(([, l]) => l !== "none")
    .sort(byKey);
  const fields = Object.entries(d.field_levels).sort(byKey);
  const grants = [...new Set(d.grants)].sort().map((g): [string, true] => [g, true]);
  return [...levels, ...fields, ...grants];
}

/** `true` when the draft holds something `role` did not: a hint for the UI only. */
export function draftWidens(role: Role | undefined, d: RoleDraft): boolean {
  if (role === undefined) return grantEntries(d).length > 0;
  for (const [t, l] of Object.entries(d.levels)) {
    if (above(l, role.levels[t] ?? "none")) return true;
  }
  for (const [f, l] of Object.entries(d.field_levels)) {
    const type = f.split(".")[0] ?? "";
    const before = role.field_levels[f] ?? role.levels[type] ?? "none";
    if (above(l, before)) return true;
  }
  return d.grants.some((g) => !role.grants.includes(g));
}

/** The plain sentences of an impact report, for a page. */
export function impactSentences(impact: Impact): string[] {
  if (impact.no_impact) return ["Nobody gains or loses access."];
  const out = [...impact.summary];
  if (impact.omitted_lines > 0) out.push(`And ${impact.omitted_lines} more changes.`);
  if (!impact.complete) {
    out.push("The report stopped at its bound: there may be more than this.");
  }
  return out;
}

/** `true` when a model change needs an approval token to publish. */
export function needsApproval(change: ModelChange): boolean {
  return change.class === "widening";
}

// ---------- Rewriting one role in a manifest ----------

/** The manifest has a role written in a form this editor does not rewrite. */
export class ModelEditError extends TutelaError {
  override name = "ModelEditError";
}

/** A line of the source: where it starts and ends, and its table header if it is one. */
interface Line {
  start: number;
  /** Index of the newline, or the end of the text. */
  end: number;
  /** The header's key path, for a `[a.b]` or `[[a.b]]` line outside a string. */
  header?: { path: string[]; array: boolean };
  /** `true` when the line starts inside a multi-line string. */
  inString: boolean;
}

/** Splits a TOML text into lines, knowing which start inside a multi-line string. */
function lines(src: string): Line[] {
  const out: Line[] = [];
  let i = 0;
  let ml: '"""' | "'''" | undefined;
  while (i <= src.length) {
    const start = i;
    const startsInString = ml !== undefined;
    // Walk the line to find where it ends and whether a multi-line string
    // opens or closes on it.
    let j = i;
    let inBasic = false;
    let inLiteral = false;
    while (j < src.length && src[j] !== "\n") {
      const c = src[j];
      if (ml !== undefined) {
        if (src.startsWith(ml, j)) {
          if (ml === '"""' && countBackslashes(src, j) % 2 === 1) {
            j++;
            continue;
          }
          j += 3;
          // A closing delimiter may be followed by up to two more quotes.
          while (j < src.length && src[j] === ml[0]) j++;
          ml = undefined;
          continue;
        }
        j++;
        continue;
      }
      if (inBasic) {
        if (c === "\\") j++;
        else if (c === '"') inBasic = false;
        j++;
        continue;
      }
      if (inLiteral) {
        if (c === "'") inLiteral = false;
        j++;
        continue;
      }
      if (c === "#") {
        while (j < src.length && src[j] !== "\n") j++;
        break;
      }
      if (src.startsWith('"""', j)) {
        ml = '"""';
        j += 3;
        continue;
      }
      if (src.startsWith("'''", j)) {
        ml = "'''";
        j += 3;
        continue;
      }
      if (c === '"') inBasic = true;
      else if (c === "'") inLiteral = true;
      j++;
    }
    const line: Line = { start, end: j, inString: startsInString };
    if (!startsInString) {
      const header = parseHeader(src.slice(start, j));
      if (header !== undefined) line.header = header;
    }
    out.push(line);
    if (j >= src.length) break;
    i = j + 1;
  }
  return out;
}

function countBackslashes(s: string, at: number): number {
  let n = 0;
  for (let k = at - 1; k >= 0 && s[k] === "\\"; k--) n++;
  return n;
}

/** The key path of a table header line, or `undefined`. */
function parseHeader(text: string): { path: string[]; array: boolean } | undefined {
  const t = text.trim();
  if (!t.startsWith("[")) return undefined;
  const array = t.startsWith("[[");
  const open = array ? 2 : 1;
  const close = array ? "]]" : "]";
  // The header ends at its closing bracket outside quotes; a comment may follow.
  let k = open;
  let q: string | undefined;
  for (; k < t.length; k++) {
    const c = t[k];
    if (q !== undefined) {
      if (c === "\\" && q === '"') k++;
      else if (c === q) q = undefined;
      continue;
    }
    if (c === '"' || c === "'") q = c;
    else if (t.startsWith(close, k)) break;
  }
  if (k >= t.length) return undefined;
  const path = splitKey(t.slice(open, k));
  return path === undefined ? undefined : { path, array };
}

/** Splits a dotted key into its parts, unquoting each; `undefined` if malformed. */
function splitKey(key: string): string[] | undefined {
  const parts: string[] = [];
  let i = 0;
  const s = key.trim();
  while (i <= s.length) {
    while (s[i] === " " || s[i] === "\t") i++;
    let part = "";
    if (s[i] === '"') {
      i++;
      while (i < s.length && s[i] !== '"') {
        if (s[i] === "\\") {
          const n = s[i + 1];
          part += n === "n" ? "\n" : n === "t" ? "\t" : (n ?? "");
          i += 2;
          continue;
        }
        part += s[i];
        i++;
      }
      if (s[i] !== '"') return undefined;
      i++;
    } else if (s[i] === "'") {
      i++;
      while (i < s.length && s[i] !== "'") part += s[i++];
      if (s[i] !== "'") return undefined;
      i++;
    } else {
      while (i < s.length && /[A-Za-z0-9_-]/.test(s[i] ?? "")) part += s[i++];
      if (part === "") return undefined;
    }
    parts.push(part);
    while (s[i] === " " || s[i] === "\t") i++;
    if (i >= s.length) break;
    if (s[i] !== ".") return undefined;
    i++;
  }
  return parts;
}

/** A key as TOML writes it: bare when it can be, else a basic string. */
export function tomlKey(k: string): string {
  return /^[A-Za-z0-9_-]+$/.test(k) ? k : JSON.stringify(k);
}

/** `grants = { … }` on one line. */
export function grantsLine(d: RoleDraft): string {
  const parts = grantEntries(d).map(
    ([k, v]) => `${tomlKey(k)} = ${v === true ? "true" : JSON.stringify(v)}`,
  );
  return parts.length === 0 ? "grants = {}" : `grants = { ${parts.join(", ")} }`;
}

/** The end (exclusive) of the inline table that starts at `open` (a `{`). */
function inlineTableEnd(src: string, open: number): number {
  let depth = 0;
  for (let k = open; k < src.length; k++) {
    const c = src[k];
    if (c === '"' || c === "'") {
      const triple = src.startsWith(c.repeat(3), k);
      const delim = triple ? c.repeat(3) : c;
      k += delim.length;
      while (k < src.length && !src.startsWith(delim, k)) {
        if (c === '"' && src[k] === "\\") k++;
        k++;
      }
      k += delim.length - 1;
      continue;
    }
    if (c === "#") {
      while (k < src.length && src[k] !== "\n") k++;
      continue;
    }
    if (c === "{" || c === "[") depth++;
    else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0) return k + 1;
    }
  }
  throw new ModelEditError("the role's grants table does not end");
}

/**
 * The manifest `source` with role `d.key`'s `grants` replaced by the
 * draft's, and nothing else changed. A role the manifest does not declare
 * (a seeded role, or a new one) is added at the end. `owner` cannot be
 * changed (MANIFEST.md 5.1).
 */
export function setRoleGrants(source: string, d: RoleDraft): string {
  if (d.key === "owner") throw new ModelEditError("the owner role cannot be changed");
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(d.key)) throw new ModelEditError("a role key is a name");
  const ls = lines(source);
  const at = (path: string[], n: number) => (l: Line) =>
    l.header !== undefined &&
    !l.header.array &&
    l.header.path.length === n &&
    path.every((p, i) => l.header?.path[i] === p);
  // Forms this editor does not rewrite: a `[roles]` table, or dotted keys.
  if (ls.some(at(["roles"], 1))) {
    throw new ModelEditError("the manifest writes its roles in a [roles] table; edit it by hand");
  }
  const roleLine = ls.findIndex(at(["roles", d.key], 2));
  const subLine = ls.findIndex(at(["roles", d.key, "grants"], 3));
  const nextHeader = (from: number) => {
    const k = ls.findIndex((l, i) => i > from && l.header !== undefined);
    return k < 0 ? ls.length : k;
  };
  const line = grantsLine(d);

  if (subLine >= 0) {
    // `[roles.<key>.grants]`: replace its body with `key = value` lines.
    const end = nextHeader(subLine);
    const from = (ls[subLine] as Line).end + 1;
    const to = end < ls.length ? (ls[end] as Line).start : source.length;
    const body = grantEntries(d)
      .map(([k, v]) => `${tomlKey(k)} = ${v === true ? "true" : JSON.stringify(v)}\n`)
      .join("");
    return source.slice(0, from) + body + (to < source.length ? "\n" : "") + source.slice(to);
  }

  if (roleLine < 0) {
    const sep =
      source.length === 0 || source.endsWith("\n\n") ? "" : source.endsWith("\n") ? "\n" : "\n\n";
    return `${source}${sep}[roles.${d.key}]\n${line}\n`;
  }

  const end = nextHeader(roleLine);
  for (let i = roleLine + 1; i < end; i++) {
    const l = ls[i] as Line;
    if (l.inString) continue;
    const text = source.slice(l.start, l.end);
    const m = /^(\s*)grants\s*(=|\.)/.exec(text);
    if (m === null) continue;
    if (m[2] === ".") {
      throw new ModelEditError("the role's grants are dotted keys; edit the manifest by hand");
    }
    const open = source.indexOf("{", l.start);
    if (open < 0 || open > l.end) {
      throw new ModelEditError(
        "the role's grants are not an inline table; edit the manifest by hand",
      );
    }
    const close = inlineTableEnd(source, open);
    return source.slice(0, l.start) + (m[1] ?? "") + line + source.slice(close);
  }
  // A declared role with no grants: add the line under its header.
  const header = ls[roleLine] as Line;
  return `${source.slice(0, header.end)}\n${line}${source.slice(header.end)}`;
}
