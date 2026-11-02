/** A component's colour scheme: `system` follows `prefers-color-scheme`. */
export type Theme = "light" | "dark" | "system";

/** The root attribute for a theme; the stylesheet reads `data-theme`. */
export function themeAttr(theme: Theme | undefined): { "data-theme"?: "light" | "dark" } {
  return theme === "light" || theme === "dark" ? { "data-theme": theme } : {};
}
