import {
  DashboardBuilder,
  DashboardCursorSync,
  DatasourceVariableBuilder,
  RowBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { overviewPanels } from "./panels/overview";
import { authRow } from "./panels/auth";
import { proxyRow } from "./panels/proxy";
import { tracesRow } from "./panels/traces";
import { logsPanels } from "./panels/logs";

export function buildDashboard(): DashboardBuilder {
  let builder = new DashboardBuilder("mcp-gate")
    .uid("mcp-gate")
    .description(
      "OAuth 2.1 reverse proxy for MCP servers — RED metrics, authentication, upstream proxy, traces, and logs."
    )
    .tags(["mcp-gate", "mcp", "oauth"])
    .editable()
    .tooltip(DashboardCursorSync.Crosshair)
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
    );

  // Service Overview — uncollapsed row with panels added directly to dashboard
  builder = builder.withRow(new RowBuilder("Service Overview"));
  for (const panel of overviewPanels()) {
    builder = builder.withPanel(panel);
  }

  // Collapsed drill-down rows
  builder = builder
    .withRow(authRow())
    .withRow(proxyRow())
    .withRow(tracesRow());

  // Logs — uncollapsed row with panels added directly to dashboard
  builder = builder.withRow(new RowBuilder("Logs"));
  for (const panel of logsPanels()) {
    builder = builder.withPanel(panel);
  }

  return builder;
}
