import type { SessionState, TutelaClient } from "@f8fvwgzc/tutela-js";
import { createContext, type ReactNode, useContext, useSyncExternalStore } from "react";

const Ctx = createContext<TutelaClient | undefined>(undefined);

/** The props of {@link TutelaProvider}. */
export interface TutelaProviderProps {
  /** The client: a browser session for a person, or a service client. */
  client: TutelaClient;
  children?: ReactNode;
}

/**
 * Gives the components below the client and, through it, the permission
 * maps it has loaded. Tokens stay in the client's memory.
 */
export function TutelaProvider({ client, children }: TutelaProviderProps) {
  return <Ctx.Provider value={client}>{children}</Ctx.Provider>;
}

/** The client of the nearest {@link TutelaProvider}. */
export function useTutela(): TutelaClient {
  const c = useContext(Ctx);
  if (c === undefined) {
    throw new Error("a Tutela component needs a <TutelaProvider client={…}> above it");
  }
  return c;
}

const SIGNED_OUT: SessionState = { status: "signed-out" };

/** The browser session's state (signed out, ready, step-up required). */
export function useSessionState(): SessionState {
  const client = useTutela();
  return useSyncExternalStore(
    (cb) => client.session?.subscribe(cb) ?? (() => undefined),
    () => client.session?.state ?? SIGNED_OUT,
    () => SIGNED_OUT,
  );
}
