import {
  type ActiveModel,
  type Assignment,
  type CheckResource,
  type ModelSettings,
  type PermissionMap,
  type RolesAnswer,
  type ScopeRef,
  UnavailableError,
} from "@f8fvwgzc/tutela-js";
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";

import { useTutela } from "./context.js";

/** What a loading hook gives. */
export interface Loaded<T> {
  data: T | undefined;
  /** The last error; a 503 is retried by itself after `Retry-After`. */
  error: unknown;
  loading: boolean;
  reload: () => void;
}

/** The longest a read waits by itself before it asks again after a 503, in seconds. */
const MAX_AUTO_RETRY = 30;

/**
 * Runs `load` when `key` changes, and again on `reload()`. A 503 is asked
 * again after its `Retry-After` (at most 30 s), so a page recovers by itself.
 */
export function useLoad<T>(key: string, load: (signal: AbortSignal) => Promise<T>): Loaded<T> {
  const [state, setState] = useState<{ data: T | undefined; error: unknown; loading: boolean }>({
    data: undefined,
    error: undefined,
    loading: true,
  });
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  // biome-ignore lint/correctness/useExhaustiveDependencies: `key` and `tick` decide when to load again.
  useEffect(() => {
    const ctl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setState((s) => ({ ...s, loading: true }));
    loadRef.current(ctl.signal).then(
      (data) => {
        if (!ctl.signal.aborted) setState({ data, error: undefined, loading: false });
      },
      (error: unknown) => {
        if (ctl.signal.aborted) return;
        setState((s) => ({ data: s.data, error, loading: false }));
        if (error instanceof UnavailableError) {
          const secs = Math.min(error.retryAfter ?? 1, MAX_AUTO_RETRY);
          timer = setTimeout(() => setTick((t) => t + 1), secs * 1000);
        }
      },
    );
    return () => {
      ctl.abort();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [key, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, reload };
}

/**
 * The permission map of the caller on `resource` for `actions` (CONTRACTS.md
 * 7.5), loaded with the client's `tutela-authz` token, again after each of
 * the client's writes (at least as new as the write).
 */
export function usePermissionMap(
  resource: CheckResource,
  actions: string[],
): Loaded<PermissionMap> {
  const client = useTutela();
  const rev = useSyncExternalStore(
    (cb) => client.onRevision(cb),
    () => client.revision,
    () => 0,
  );
  const key = JSON.stringify([resource, actions, rev]);
  return useLoad(key, (signal) => client.permissions({ resource, actions }, { signal }));
}

/**
 * `true` only when a loaded permission map allows `action` on `resource`.
 * What is not loaded is not allowed: a UI hides it. Every route checks again.
 */
export function useCan(action: string, resource: ScopeRef): boolean {
  const client = useTutela();
  const store = client.permissionStore;
  useSyncExternalStore(
    (cb) => store.subscribe(cb),
    () => store.version,
    () => 0,
  );
  return store.can(action, resource);
}

/** What {@link useAssignments} gives. */
export interface AssignmentsState extends Loaded<Assignment[]> {
  /** `true` while more pages remain. */
  hasMore: boolean;
  loadMore: () => void;
  loadingMore: boolean;
}

/** The assignments at `scope`, a page at a time (`next_after`). */
export function useAssignments(scope: ScopeRef, pageSize = 50): AssignmentsState {
  const client = useTutela();
  const [more, setMore] = useState<{
    items: Assignment[];
    next: string | undefined;
    error: unknown;
  }>({
    items: [],
    next: undefined,
    error: undefined,
  });
  const [loadingMore, setLoadingMore] = useState(false);
  const first = useLoad(`${scope.type}:${scope.id}:${pageSize}`, async (signal) => {
    const p = await client.assignments.page({ scope, limit: pageSize }, { signal });
    setMore({ items: [], next: p.next_after, error: undefined });
    return p.assignments;
  });
  const loadMore = useCallback(() => {
    const after = more.next;
    if (after === undefined) return;
    setLoadingMore(true);
    client.assignments.page({ scope, limit: pageSize, after }).then(
      (p) => {
        setMore((m) => ({
          items: [...m.items, ...p.assignments],
          next: p.next_after,
          error: undefined,
        }));
        setLoadingMore(false);
      },
      (error: unknown) => {
        setMore((m) => ({ ...m, error }));
        setLoadingMore(false);
      },
    );
  }, [client, scope, pageSize, more.next]);
  return {
    data: first.data === undefined ? undefined : [...first.data, ...more.items],
    error: first.error ?? more.error,
    loading: first.loading,
    reload: first.reload,
    hasMore: more.next !== undefined,
    loadMore,
    loadingMore,
  };
}

/** The active model's roles and types: the permission matrix's rows and columns. */
export function useRoles(scope?: ScopeRef): Loaded<RolesAnswer> {
  const client = useTutela();
  const key = scope === undefined ? "tenant" : `${scope.type}:${scope.id}`;
  return useLoad(key, (signal) => client.roles(scope, { signal }));
}

/** The model the tenant runs on (with its text) and its two-person setting. */
export function useModel(): Loaded<{ active: ActiveModel; settings: ModelSettings }> {
  const client = useTutela();
  return useLoad("model", async (signal) => {
    const [active, settings] = await Promise.all([
      client.models.active({ signal }),
      client.models.settings({ signal }),
    ]);
    return { active, settings };
  });
}

/** Seconds left until `until` (ms since the epoch), counting down once a second. */
export function useCountdown(until: number | undefined): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (until === undefined) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [until]);
  return until === undefined ? 0 : Math.max(0, Math.ceil((until - now) / 1000));
}
