import {
  LEVELS,
  type Level,
  type MatrixCell,
  type MatrixRow,
  minLevel,
  type RoleDraft,
} from "@f8fvwgzc/tutela-js";

/** A level shown as a word and a four-step meter. */
export function LevelView({ level, inherited }: { level: Level; inherited: boolean }) {
  const n = LEVELS.indexOf(level);
  return (
    <span className="tutela-level" data-level={level} data-inherited={inherited || undefined}>
      <span className="tutela-meter" aria-hidden="true">
        {[1, 2, 3].map((i) => (
          <span key={i} data-on={i <= n || undefined} />
        ))}
      </span>
      <span>{level}</span>
      {inherited ? <span className="tutela-sr"> (from the item level)</span> : null}
    </span>
  );
}

/** A matrix cell, read-only. */
export function CellView({ cell }: { cell: MatrixCell }) {
  if ("granted" in cell) {
    return cell.granted ? (
      <span className="tutela-granted">
        <svg aria-hidden="true" viewBox="0 0 16 16" width="14" height="14">
          <path d="M3 8.5l3 3 7-7" stroke="currentColor" strokeWidth="1.6" fill="none" />
        </svg>
        <span className="tutela-sr">Granted</span>
      </span>
    ) : (
      <span className="tutela-muted">
        <span aria-hidden="true">—</span>
        <span className="tutela-sr">Not granted</span>
      </span>
    );
  }
  return <LevelView level={cell.level} inherited={cell.inherited} />;
}

/** The draft's value for a row, as the matrix shows it. */
export function draftCell(d: RoleDraft, row: MatrixRow): MatrixCell {
  const item: Level = d.levels[row.type] ?? "none";
  switch (row.kind) {
    case "type":
      return { level: item, inherited: false };
    case "field": {
      const own = d.field_levels[row.key];
      return own === undefined
        ? { level: item, inherited: true }
        : { level: minLevel(own, item), inherited: false };
    }
    case "feature": {
      const own = d.field_levels[row.key];
      return own === undefined
        ? { level: item, inherited: true }
        : { level: own, inherited: false };
    }
    default:
      return { granted: d.grants.includes(row.key) };
  }
}

/**
 * The draft with `row` set to `value`. A field never goes above its item
 * level: lowering an item level lowers its fields' levels with it.
 */
export function setDraft(d: RoleDraft, row: MatrixRow, value: Level | boolean): RoleDraft {
  if (typeof value === "boolean") {
    const grants = d.grants.filter((g) => g !== row.key);
    return { ...d, grants: value ? [...grants, row.key] : grants };
  }
  if (row.kind === "type") {
    const field_levels = { ...d.field_levels };
    for (const [k, l] of Object.entries(field_levels)) {
      if (k.startsWith(`${row.type}.`) && !k.startsWith(`${row.type}.@`)) {
        field_levels[k] = minLevel(l, value);
      }
    }
    return { ...d, levels: { ...d.levels, [row.type]: value }, field_levels };
  }
  return { ...d, field_levels: { ...d.field_levels, [row.key]: value } };
}

/** An editable cell: a level select, or a granted checkbox. */
export function CellInput({
  draft,
  row,
  roleLabel,
  onChange,
}: {
  draft: RoleDraft;
  row: MatrixRow;
  roleLabel: string;
  onChange: (d: RoleDraft) => void;
}) {
  const cell = draftCell(draft, row);
  const name = `${row.key} for ${roleLabel}`;
  if ("granted" in cell) {
    return (
      <input
        type="checkbox"
        className="tutela-check"
        checked={cell.granted}
        aria-label={name}
        onChange={(e) => onChange(setDraft(draft, row, e.target.checked))}
      />
    );
  }
  const item: Level = draft.levels[row.type] ?? "none";
  // A field is never above its item level; a feature may be (MANIFEST.md 5).
  const options =
    row.kind === "field" ? LEVELS.filter((l) => LEVELS.indexOf(l) <= LEVELS.indexOf(item)) : LEVELS;
  return (
    <select
      className="tutela-input tutela-select-level"
      value={cell.level}
      aria-label={`Level of ${name}`}
      onChange={(e) => onChange(setDraft(draft, row, e.target.value as Level))}
    >
      {options.map((l) => (
        <option key={l} value={l}>
          {l}
        </option>
      ))}
    </select>
  );
}
