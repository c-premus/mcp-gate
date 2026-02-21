import {
  DashboardBuilder,
  DatasourceVariableBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { overviewRow } from "./panels/overview";
import { authRow } from "./panels/auth";
import { proxyRow } from "./panels/proxy";
import { tracesRow } from "./panels/traces";
import { logsRow } from "./panels/logs";

export function buildDashboard(): DashboardBuilder {
  return new DashboardBuilder("mcp-gate")
    .uid("mcp-gate")
    .description(
      "OAuth 2.1 reverse proxy for MCP servers — RED metrics, authentication, upstream proxy, traces, and logs."
    )
    .tags(["mcp-gate", "mcp", "oauth"])
    .editable()
    .tooltip(0)
    .time({ from: "now-1h", to: "now" })
    .refresh("30s")
    .withVariable(
      new DatasourceVariableBuilder("DS_PROMETHEUS")
        .label("Prometheus")
        .type("prometheus")
    )
    .withVariable(
      new DatasourceVariableBuilder("DS_TEMPO")
        .label("Tempo")
        .type("tempo")
    )
    .withVariable(
      new DatasourceVariableBuilder("DS_LOKI")
        .label("Loki")
        .type("loki")
    )
    .withRow(overviewRow())
    .withRow(authRow())
    .withRow(proxyRow())
    .withRow(tracesRow())
    .withRow(logsRow());
}
