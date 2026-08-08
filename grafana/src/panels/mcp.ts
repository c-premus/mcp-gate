import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { PanelBuilder as PiechartPanel } from "@grafana/grafana-foundation-sdk/piechart";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import { RowBuilder } from "@grafana/grafana-foundation-sdk/dashboard";
import { LegendDisplayMode } from "@grafana/grafana-foundation-sdk/common";
import { PROMETHEUS, SELECTOR } from "./constants";
import { legend, piechartPanel, timeseriesPanel } from "./defaults";

// Panels over mcpgate_mcp_requests_total, sourced from the MCP 2026-07-28
// request-metadata headers (Mcp-Method, MCP-Protocol-Version). Values are
// client-asserted and are NOT validated against the request body — mcp-gate
// never parses JSON-RPC. Read these as "what clients claim they are doing",
// which is the right resolution for capacity and migration questions and the
// wrong one for anything security-bearing.
//
// Splitting by `service` matters more here than elsewhere: different gates
// front different upstreams, so their method mixes are genuinely different
// populations and pooling them describes nothing real.

function methodMixTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("MCP Calls by Method")
    .description(
      "Request rate per MCP method, from the Mcp-Method header, split per gate. " +
        "A sustained 'other' line means a method outside the 2026-07-28 core " +
        "set is in use — an extension (e.g. tasks/*) or a client sending a " +
        "method removed in this revision. Add it to mcpMethodLabel if it is legitimate."
    )
    .datasource(PROMETHEUS)
    .unit("reqps")
    // Table legend with per-series mean and max: the method mix is the one
    // panel where the summary statistics answer the question directly ("which
    // methods dominate, and what did each peak at").
    .legend(legend(LegendDisplayMode.Table, ["mean", "max"]))
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (mcp_method, service) (rate(mcpgate_mcp_requests_total{${SELECTOR}}[$__rate_interval]))`
        )
        .legendFormat("{{service}} {{mcp_method}}")
        .refId("A")
    );
}

function protocolVersionTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("MCP Protocol Version Mix")
    .description(
      "Request rate per protocol revision, from the MCP-Protocol-Version header, split per gate. " +
        "'absent' is every client predating 2025-06-18 (when the header was " +
        "introduced) plus any non-MCP traffic on the proxy route; watching it " +
        "fall is how you know clients have migrated. mcp-gate itself is " +
        "version-agnostic and never rejects on this value. Per-gate split also " +
        "shows migration progressing at different rates behind different upstreams."
    )
    .datasource(PROMETHEUS)
    .unit("reqps")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (protocol_version, service) (rate(mcpgate_mcp_requests_total{${SELECTOR}}[$__rate_interval]))`
        )
        .legendFormat("{{service}} {{protocol_version}}")
        .refId("A")
    );
}

function methodMixPiechart(): PiechartPanel {
  return piechartPanel()
    .title("MCP Method Distribution")
    .description("Share of MCP calls by method over the selected time range, split per gate")
    .datasource(PROMETHEUS)
    // Counts, not a rate: the query is a range-wide `increase`.
    .unit("short")
    .noValue("0")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (mcp_method, service) (increase(mcpgate_mcp_requests_total{${SELECTOR}}[$__range]))`
        )
        .legendFormat("{{service}} {{mcp_method}}")
        .refId("A")
        .instant()
    );
}

export function mcpRow(): RowBuilder {
  return new RowBuilder("MCP Protocol")
    .collapsed(true)
    .withPanel(methodMixTimeseries())
    .withPanel(protocolVersionTimeseries())
    .withPanel(methodMixPiechart());
}
