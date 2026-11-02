/**
 * `@f8fvwgzc/tutela-react`: React 19 admin components for Tutela, built on
 * `@f8fvwgzc/tutela-js`.
 *
 * - {@link TutelaProvider}, {@link useTutela}, {@link useCan}, {@link usePermissionMap},
 *   {@link useAssignments}, {@link useRoles}, {@link useModel}, {@link useSessionState}.
 * - {@link MembersTable}, {@link RoleEditor}, {@link PermissionMatrix}, {@link ErrorNotice}.
 *
 * Import the default styles once: `import "@f8fvwgzc/tutela-react/styles.css"`.
 * They style only the components' own `.tutela` root.
 */

/** The version of this package. Every artifact of a release has the same one. */
export { VERSION } from "@f8fvwgzc/tutela-js";
export { CellView, LevelView } from "./cells.js";
export { TutelaProvider, type TutelaProviderProps, useSessionState, useTutela } from "./context.js";
export { describeError, ErrorNotice, type ErrorNoticeProps } from "./ErrorNotice.js";
export {
  type AssignmentsState,
  type Loaded,
  useAssignments,
  useCan,
  useCountdown,
  useLoad,
  useModel,
  usePermissionMap,
  useRoles,
} from "./hooks.js";
export { type AccessRequest, MembersTable, type MembersTableProps } from "./MembersTable.js";
export { PermissionMatrix, type PermissionMatrixProps } from "./PermissionMatrix.js";
export { RoleEditor, type RoleEditorProps, type RoleEditorResult } from "./RoleEditor.js";
export type { Theme } from "./theme.js";
