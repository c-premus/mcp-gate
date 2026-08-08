import { PanelBuilder as TablePanel } from "@grafana/grafana-foundation-sdk/table";
import { TempoQueryBuilder } from "@grafana/grafana-foundation-sdk/tempo";
import { RowBuilder } from "@grafana/grafana-foundation-sdk/dashboard";
import { TEMPO, TRACE_SERVICE_MATCHER } from "./constants";
import { tablePanel } from "./defaults";

function recentTracesTable(): TablePanel {
  return tablePanel()
    .title("Recent Traces")
    .description(
      "Recent traces for the selected gate(s), excluding health checks. " +
        "Requires OTEL_EXPORTER_OTLP_ENDPOINT to be set on the gate AND the " +
        "collector behind it to forward to Tempo — an empty panel with healthy " +
        "gates usually means the collector is not exporting, not that mcp-gate " +
        "stopped tracing. mcpgate_otel_spans_dropped_total cannot confirm this " +
        "either way: it is a placeholder that never increments (internal/otel)."
    )
    .datasource(TEMPO)
    .span(24)
    .height(12)
    .withTarget(
      new TempoQueryBuilder()
        .queryType("traceqlSearch")
        // `=~` because a multi-value variable interpolates as `a|b`; TraceQL
        // treats that as a regex alternation only with the regex operator.
        .query(`{${TRACE_SERVICE_MATCHER} && name !~ ".*healthz.*"}`)
        .limit(20)
        .refId("A")
    );
}

export function tracesRow(): RowBuilder {
  return new RowBuilder("Trace Explorer")
    .collapsed(true)
    .withPanel(recentTracesTable());
}
