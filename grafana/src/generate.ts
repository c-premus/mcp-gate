import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { buildDashboard } from "./dashboard";

const outPath = resolve(
  import.meta.dirname,
  "../../docs/grafana/dashboard.json"
);

const dashboard = buildDashboard().build();
const json = JSON.stringify(dashboard, null, 2) + "\n";

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, json);
console.log(`Dashboard written to ${outPath}`);
