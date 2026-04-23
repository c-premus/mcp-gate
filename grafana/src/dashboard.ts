import {
  DashboardBuilder,
  DashboardCursorSync,
  DatasourceVariableBuilder,
  RowBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { overviewPanels } from "./panels/overview";
import { authPanels } from "./panels/auth";
import { proxyPanels } from "./panels/proxy";
import { jwksPanels } from "./panels/jwks";
import { runtimeRow } from "./panels/runtime";
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

  // Signal sections — row as separator, panels at dashboard level so they
  // stay expanded. The Grafana Foundation SDK's RowBuilder.withPanel forces
  // collapsed=true because Grafana strips nested panels from expanded rows.
  const expandedSections: [string, () => ReturnType<typeof overviewPanels>][] = [
    ["Service Overview", overviewPanels],
    ["Authentication", authPanels],
    ["Upstream Proxy", proxyPanels],
    ["JWKS Health", jwksPanels],
  ];
  for (const [title, panelsFn] of expandedSections) {
    builder = builder.withRow(new RowBuilder(title));
    for (const panel of panelsFn()) {
      builder = builder.withPanel(panel);
    }
  }

  // Drill-down rows (collapsed by default — operators open these deliberately)
  builder = builder
    .withRow(runtimeRow())
    .withRow(tracesRow());

  // Logs — row as separator, panels at dashboard level so live-log widgets
  // render below the header. Same pattern as the expanded sections above.
  builder = builder.withRow(new RowBuilder("Logs"));
  for (const panel of logsPanels()) {
    builder = builder.withPanel(panel);
  }

  return builder;
}
