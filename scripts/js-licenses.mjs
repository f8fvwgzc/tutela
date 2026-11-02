// Fails when a production dependency of the JavaScript SDKs has a licence
// outside the allow-list (the permissive part of deny.toml). The SDKs are
// linked into products, as the crates are; dev tools never reach a product.
// `make js-licenses` runs it.
import { execFileSync } from "node:child_process";

const ALLOWED = new Set([
  "0BSD",
  "Apache-2.0",
  "Apache-2.0 OR MIT",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MIT",
  "MIT OR Apache-2.0",
  "Zlib",
]);

const out = execFileSync("pnpm", ["-r", "licenses", "list", "--prod", "--json"], {
  encoding: "utf8",
});
if (out.trim().startsWith("No licenses")) {
  console.log("js licences: no production dependency outside the workspace");
  process.exit(0);
}
const byLicence = JSON.parse(out);
const refused = Object.entries(byLicence).filter(([licence]) => !ALLOWED.has(licence));
for (const [licence, packages] of refused) {
  for (const p of packages) {
    console.error(`js licences: ${p.name}@${p.versions.join(",")} is ${licence}, not allowed`);
  }
}
if (refused.length > 0) {
  process.exit(1);
}
console.log(`js licences: ${Object.keys(byLicence).length} licences, all allowed`);
