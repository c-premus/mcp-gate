import {
  DashboardBuilder,
  DashboardCursorSync,
  DatasourceVariableBuilder,
  QueryVariableBuilder,
  RowBuilder,
  VariableRefresh,
  VariableSort,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, SERVICE_VAR, SERVICE_VAR_METRIC } from "./panels/constants";
import { overviewPanels } from "./panels/overview";
import { authPanels } from "./panels/auth";
import { proxyPanels } from "./panels/proxy";
import { jwksPanels } from "./panels/jwks";
import { mcpRow } from "./panels/mcp";
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
    )
    // Gate selector. One Prometheus job can scrape several mcp-gate instances,
    // each tagged with a distinct `service` target label; this variable is what
    // every panel filters on. mcpgate_info drives it because every gate exposes
    // it unconditionally at startup, so a gate appears in the list as soon as it
    // is scraped — including one that is failing every request.
    //
    // No allValue is set, deliberately. An unset allValue makes Grafana expand
    // "All" to the actual option list — `(mcp-gate|mcp-gate-forgejo)` — rather
    // than to a wildcard. A wildcard would be wrong in two separate ways:
    //
    //   - Loki rejects an empty-compatible stream matcher outright, so
    //     `{service_name=~".*"}` is a 400, not a broad match.
    //   - Loki has no `job` label to scope the family the way Prometheus does,
    //     so `.+` would match every service shipping logs — Tempo, Traefik and
    //     the rest of the stack — and turn Live Logs into a firehose.
    //
    // Expanding to the real list is scoped correctly on all three datasources.
    // It does mean the dashboard depends on the `service` target label actually
    // being set; that contract is documented in docs/setup.md.
    .withVariable(
      new QueryVariableBuilder(SERVICE_VAR)
        .label("Gate")
        .description("mcp-gate instance(s) to display. 'All' pools nothing — panels stay split per gate.")
        .datasource(PROMETHEUS)
        .query({
          qryType: 1, // label_values
          label: SERVICE_VAR,
          metric: SERVICE_VAR_METRIC,
          refId: "PrometheusVariableQueryEditor-VariableQuery",
        })
        .multi(true)
        .includeAll(true)
        .refresh(VariableRefresh.OnDashboardLoad)
        .sort(VariableSort.AlphabeticalAsc)
        .current({ text: ["All"], value: ["$__all"], selected: true })
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
    .withRow(mcpRow())
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
