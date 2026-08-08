import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { validateDashboard } from "./validate";

// Validates the *committed* dashboard.json rather than a freshly built one, so
// a hand-edit to the generated file is caught even if nobody re-runs the
// generator. `npm run generate` runs the same rules before writing.
const path = resolve(import.meta.dirname, "../../docs/grafana/dashboard.json");
const errors = validateDashboard(JSON.parse(readFileSync(path, "utf8")));

if (errors.length > 0) {
  console.error(
    `${path}: ${errors.length} problem${errors.length === 1 ? "" : "s"}`
  );
  for (const error of errors) {
    console.error(`  - ${error}`);
  }
  process.exit(1);
}

console.log(`${path}: OK`);
