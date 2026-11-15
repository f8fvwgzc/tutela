/**
 * `<Protect>`, `<Can>` and `<Field>` (PERMISSION-MODEL.md 14.3): show,
 * disable or hide parts of a product's own pages from the caller's
 * permission map (CONTRACTS.md 7.5).
 *
 * This is a **UI hint only**. Hiding a button or a value is never security:
 * every server route checks again, and the server removes hidden fields from
 * its responses (AGENTS.md section 6).
 */

import type { CheckResource, Level, PermissionStore, ScopeRef, UiEntry } from "@f8fvwgzc/tutela-js";
import { type ReactNode, useSyncExternalStore } from "react";

import { useTutela } from "./context.js";
import { usePermissionMap } from "./hooks.js";

/** The client's permission store; the caller re-renders on every change. */
function useStore(): PermissionStore {
  const store = useTutela().permissionStore;
  useSyncExternalStore(
    (cb) => store.subscribe(cb),
    () => store.version,
    () => 0,
  );
  return store;
}

/** The key of a field or feature of `resource`'s type: `invoice.amount`, `invoice.@ai`. */
function fieldKey(resource: ScopeRef, name: string): string {
  return `${resource.type}.${name}`;
}

/**
 * The mode of a UI key on `resource` from a loaded map: `show`, `disable`,
 * `hide` or `readonly`. What is not loaded is `hide`.
 */
export function useUi(uiKey: string, resource: ScopeRef): UiEntry {
  return useStore().ui(uiKey, resource);
}

/**
 * The caller's level on one field or feature of `resource` (`amount`,
 * `@ai`) from a loaded map: `none`, `read` or `write`. What is not loaded is
 * `none`.
 */
export function useField(name: string, resource: ScopeRef): Level {
  return useStore().field(fieldKey(resource, name), resource);
}

// ---------- <Protect> ----------

/** The props of {@link Protect}. */
export interface ProtectProps {
  /** The resource, with its path (nearest first, last the org). */
  resource: CheckResource;
  /** The action the section needs, for example `project:read`. */
  action: string;
  /** UI keys that `<Can>` asks about inside, for example `invoices.approve_button`. */
  uiKeys?: string[];
  /** Field or feature names of the resource's type that `<Field>` shows inside: `amount`, `@ai`. */
  fields?: string[];
  children?: ReactNode;
  /** Shown when the action is denied, or the map could not be loaded. Default: nothing. */
  fallback?: ReactNode;
  /** Shown while the map loads. Default: nothing. */
  loading?: ReactNode;
}

/**
 * Guards a page or a section. It loads the caller's permission map on
 * `resource` (with `uiKeys` and `fields` for the `<Can>` and `<Field>`
 * inside) and shows `children` only when `action` is allowed.
 */
export function Protect({
  resource,
  action,
  uiKeys,
  fields,
  children,
  fallback = null,
  loading = null,
}: ProtectProps) {
  const store = useStore();
  const keys = fields?.map((f) => fieldKey(resource, f));
  const loaded = usePermissionMap(resource, [action], {
    ...(uiKeys === undefined ? {} : { uiKeys }),
    ...(keys === undefined ? {} : { fields: keys }),
  });
  if (loaded.error !== undefined) return <>{fallback}</>;
  if (store.can(action, resource)) return <>{children}</>;
  return <>{loaded.loading ? loading : fallback}</>;
}

// ---------- <Can> ----------

/** What a render function of {@link Can} gets. */
export interface CanState {
  /** `true` for `show`. */
  allowed: boolean;
  /** How to show the part (CONTRACTS.md 7.5). Never `hide`: then `fallback` shows. */
  mode: UiEntry["mode"];
  /** With `disable`: a code that is safe to show. */
  reason?: string;
}

interface CanCommon {
  resource: ScopeRef;
  /**
   * The part to show. A function gets the mode and draws the part itself
   * (for example `disabled={mode !== "show"}`). Plain children are wrapped
   * in a disabled `<fieldset class="tutela-can">` for `disable` and
   * `readonly` (the package styles remove its border).
   */
  children: ReactNode | ((state: CanState) => ReactNode);
  /** Shown instead when the mode is `hide`. Default: nothing. */
  fallback?: ReactNode;
  /** The text for a disabled part, usually `UI[key].reason` from `tutela codegen`. */
  reasonText?: string;
}

/** The props of {@link Can}: a UI key, or one action. */
export type CanProps = CanCommon &
  (
    | {
        /** A UI key from the manifest: its mode comes from the map. */
        uiKey: string;
        action?: never;
      }
    | {
        /** One action key, for example `invoice:approve`: shown when allowed, hidden when not. */
        action: string;
        uiKey?: never;
      }
  );

/**
 * Shows a part of a page by the caller's permission map: as normal, greyed
 * out, read only, or not at all. The map must be loaded, by a `<Protect>`
 * above it or by `usePermissionMap`, with this UI key or action in it.
 */
export function Can(props: CanProps) {
  const store = useStore();
  const { resource, children, fallback = null, reasonText } = props;
  let entry: UiEntry;
  if (props.uiKey !== undefined) {
    entry = store.ui(props.uiKey, resource);
  } else {
    entry = { mode: store.can(props.action, resource) ? "show" : "hide" };
  }
  if (entry.mode === "hide") return <>{fallback}</>;
  const state: CanState = {
    allowed: entry.mode === "show",
    mode: entry.mode,
    ...(entry.reason === undefined ? {} : { reason: entry.reason }),
  };
  if (typeof children === "function") return <>{children(state)}</>;
  if (state.allowed) return <>{children}</>;
  return (
    <fieldset disabled className="tutela-can" title={reasonText} data-tutela-mode={state.mode}>
      {children}
    </fieldset>
  );
}

// ---------- <Field> ----------

/** The props of {@link Field}. */
export interface FieldProps {
  resource: ScopeRef;
  /** A field or feature name of the resource's type: `amount`, `@ai`. */
  name: string;
  /**
   * The value. A function gets the level (`read` or `write`) and draws the
   * field itself, for example an input for `write` and text for `read`.
   */
  children: ReactNode | ((level: Exclude<Level, "none">) => ReactNode);
  /**
   * When the caller may not read the field: `restricted` (default) shows a
   * placeholder, so people know whom to ask; `remove` shows nothing.
   */
  whenHidden?: "restricted" | "remove";
  /** The placeholder. Default: `Restricted`. */
  restrictedText?: ReactNode;
}

/**
 * Shows one field by the caller's level on it: the value, or "Restricted",
 * or nothing. The map must be loaded with this field in it, by a
 * `<Protect fields={[…]}>` above it or by `usePermissionMap`.
 */
export function Field({
  resource,
  name,
  children,
  whenHidden = "restricted",
  restrictedText = "Restricted",
}: FieldProps) {
  const level = useField(name, resource);
  if (level === "none") {
    if (whenHidden === "remove") return null;
    return <span className="tutela-restricted">{restrictedText}</span>;
  }
  return <>{typeof children === "function" ? children(level) : children}</>;
}
