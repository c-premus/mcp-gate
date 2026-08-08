import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import {
  ThresholdsConfigBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { ThresholdsMode } from "@grafana/grafana-foundation-sdk/dashboard";
import {
  BigValueColorMode,
  VizTooltipOptionsBuilder,
  TooltipDisplayMode,
  SortOrder,
} from "@grafana/grafana-foundation-sdk/common";
import type * as cog from "@grafana/grafana-foundation-sdk/cog";
import type * as dashboard from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, SELECTOR } from "./constants";

function proxyP95Stat(): StatPanel {
  return new StatPanel()
    .title("Upstream P95")
    .description("95th percentile upstream response latency, per gate")
    .datasource(PROMETHEUS)
    .unit("ms")
    .noValue("0")
    .decimals(0)
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 500, color: "yellow" },
          { value: 2000, color: "red" },
        ])
    )
    .span(8)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.95, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service)) * 1000`
        )
        .legendFormat("{{service}} p95")
        .refId("A")
    );
}

function proxyErrorRateStat(): StatPanel {
  return new StatPanel()
    .title("Upstream Error Rate")
    .description("5xx upstream responses as percentage of total, per gate")
    .datasource(PROMETHEUS)
    .unit("percentunit")
    .noValue("0")
    .decimals(2)
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 0.01, color: "yellow" },
          { value: 0.05, color: "red" },
        ])
    )
    .span(8)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (service) (rate(mcpgate_proxy_requests_total{${SELECTOR},status_code=~"5.."}[$__rate_interval])) / sum by (service) (rate(mcpgate_proxy_requests_total{${SELECTOR}}[$__rate_interval]))`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function proxyLatencyTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Upstream Latency Percentiles")
    .description("P50, P90, P99 upstream proxy latency, per gate")
    .datasource(PROMETHEUS)
    .unit("s")
    .tooltip(
      new VizTooltipOptionsBuilder()
        .mode(TooltipDisplayMode.Multi)
        .sort(SortOrder.Descending)
    )
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.50, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p50")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.90, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p90")
        .refId("B")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.99, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p99")
        .refId("C")
    );
}

function proxyStatusTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Upstream Status Codes")
    .description("Upstream response status codes over time, per gate")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .tooltip(
      new VizTooltipOptionsBuilder()
        .mode(TooltipDisplayMode.Multi)
        .sort(SortOrder.Descending)
    )
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (status_code, service) (rate(mcpgate_proxy_requests_total{${SELECTOR}}[$__rate_interval]))`
        )
        .legendFormat("{{service}} {{status_code}}")
        .refId("A")
    );
}

/** Returns panels for the Upstream Proxy section (added directly to dashboard so the row stays expanded — the Grafana Foundation SDK forces collapsed=true whenever a row has nested panels). */
export function proxyPanels(): cog.Builder<dashboard.Panel>[] {
  return [
    proxyP95Stat(),
    proxyErrorRateStat(),
    proxyLatencyTimeseries(),
    proxyStatusTimeseries(),
  ];
}
