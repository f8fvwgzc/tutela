/**
 * `@f8fvwgzc/tutela-js`: the framework-free client of `tutelad`.
 *
 * - {@link TutelaClient}: every route the Tutela Console calls, typed as
 *   CONTRACTS.md gives them; pages as async iterators; problem documents as
 *   typed errors; the revision of a write kept for the next check; the
 *   permission map with ETag and 304; a bounded retry on 503.
 * - {@link BrowserSession}: a person's tokens in a browser, from an upstream
 *   (Keycloak) token by token exchange, in memory only.
 * - {@link permissionMatrix}, {@link setRoleGrants}: the permission matrix
 *   and role changes as model changes.
 *
 * The docs: `docs/JS-SDK.md` in the repo.
 */

export {
  BrowserSession,
  type BrowserSessionOptions,
  payload as jwtPayload,
  type SessionState,
  serviceAuth,
  type TokenAudience,
  type TokenSource,
  type UpstreamReason,
} from "./auth.js";
export {
  type CallOptions,
  type ClientAuth,
  type PageQuery,
  TutelaClient,
  type TutelaClientOptions,
} from "./client.js";
export {
  ConflictError,
  ForbiddenError,
  InvalidRequestError,
  MoveRefusedError,
  NetworkError,
  NotFoundError,
  NotHeldError,
  type ProblemCode,
  ProblemError,
  type ProblemFields,
  problemError,
  SignedOutError,
  StepUpRequiredError,
  TokenExchangeError,
  TutelaError,
  UnauthorizedError,
  UnavailableError,
  UpstreamTokenReusedError,
} from "./errors.js";
export type { TransportOptions } from "./http.js";
export {
  above,
  draftOf,
  draftWidens,
  grantEntries,
  grantsLine,
  impactSentences,
  type MatrixCell,
  type MatrixRow,
  type MatrixRowKind,
  ModelEditError,
  minLevel,
  needsApproval,
  type PermissionMatrix,
  permissionMatrix,
  type RoleDraft,
  setRoleGrants,
  tomlKey,
} from "./model.js";
export { PermissionMap, PermissionStore, resourceKey } from "./permissions.js";
export * from "./types.js";

/** The version of this package. Every artifact of a release has the same one. */
export const VERSION = "0.2.0";
