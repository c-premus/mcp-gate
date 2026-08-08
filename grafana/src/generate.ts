import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { buildDashboard } from "./dashboard";
import { assertValidDashboard } from "./validate";

const outPath = resolve(
  import.meta.dirname,
  "../../docs/grafana/dashboard.json"
);

const dashboard = buildDashboard().build();

// Validate before writing. A dashboard that fails these rules is valid JSON
// that Grafana loads without complaint and then draws nothing — refuse to emit
// it rather than let CI's generate-and-diff gate wave it through.
assertValidDashboard(dashboard);

const json = JSON.stringify(dashboard, null, 2) + "\n";

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, json);
console.log(`Dashboard written to ${outPath}`);
