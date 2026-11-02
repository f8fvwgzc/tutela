/**
 * The UI permission map (CONTRACTS.md 7.5) and a store of maps for a page:
 * `can("project:manage_access", scope)`. The map is a **UI hint only**:
 * every route of `tutelad` checks again (AGENTS.md section 6).
 */

import type { Level, PermissionMapAnswer, ScopeRef, UiEntry } from "./types.js";

/** One answer of `POST /v1/authz/permissions`. */
export class PermissionMap {
  readonly rev: number;
  readonly #answer: PermissionMapAnswer;

  constructor(answer: PermissionMapAnswer) {
    this.rev = answer.rev;
    this.#answer = answer;
  }

  /** `true` only when the map says the action is allowed. */
  can(action: string): boolean {
    return this.#answer.actions[action] === true;
  }

  /** A field's level; `none` when the map does not have it. */
  field(key: string): Level {
    return this.#answer.fields[key] ?? "none";
  }

  /** A UI key's mode; `hide` when the map does not have it. */
  ui(key: string): UiEntry {
    return this.#answer.ui[key] ?? { mode: "hide" };
  }

  /** The answer as it came. */
  toJSON(): PermissionMapAnswer {
    return this.#answer;
  }
}

/** The key of a resource in a {@link PermissionStore}. */
export function resourceKey(r: ScopeRef): string {
  return `${r.type}:${r.id}`;
}

/**
 * The maps a page has loaded, by resource. `can` answers `false` for a
 * resource or an action it has not loaded: what is not known is not shown.
 */
export class PermissionStore {
  readonly #maps = new Map<string, PermissionMap>();
  readonly #listeners = new Set<() => void>();
  #version = 0;

  /** Keeps `map` as the answer for `resource`. */
  set(resource: ScopeRef, map: PermissionMap): void {
    const key = resourceKey(resource);
    if (this.#maps.get(key) === map) return;
    this.#maps.set(key, map);
    this.#changed();
  }

  /** The map of `resource`, if loaded. */
  get(resource: ScopeRef): PermissionMap | undefined {
    return this.#maps.get(resourceKey(resource));
  }

  /** `true` only when a loaded map allows `action` on `resource`. */
  can(action: string, resource: ScopeRef): boolean {
    return this.get(resource)?.can(action) ?? false;
  }

  /** A field's level on `resource`; `none` when not loaded. */
  field(key: string, resource: ScopeRef): Level {
    return this.get(resource)?.field(key) ?? "none";
  }

  /** Forgets every map, for example after a sign-out. */
  clear(): void {
    this.#maps.clear();
    this.#changed();
  }

  /** A number that changes with every change, for `useSyncExternalStore`. */
  get version(): number {
    return this.#version;
  }

  /** Calls `listener` on every change. Returns an unsubscribe. */
  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #changed(): void {
    this.#version++;
    for (const l of this.#listeners) l();
  }
}
