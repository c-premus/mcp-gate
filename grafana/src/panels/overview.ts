import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import {
  ThresholdsConfigBuilder,
  FieldColorBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import {
  ThresholdsMode,
  FieldColorModeId,
} from "@grafana/grafana-foundation-sdk/dashboard";
import {
  BigValueColorMode,
  VizTooltipOptionsBuilder,
  TooltipDisplayMode,
  SortOrder,
} from "@grafana/grafana-foundation-sdk/common";
import type { cog, dashboard } from "@grafana/grafana-foundation-sdk";
import { PROMETHEUS, JOB_FILTER } from "./constants";

function requestRateStat(): StatPanel {
  return new StatPanel()
    .title("Request Rate")
    .description("Requests per second")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .colorScheme(new FieldColorBuilder().mode(FieldColorModeId.Fixed).fixedColor("green"))
    .span(8)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`sum(rate(mcpgate_http_requests_total{${JOB_FILTER}}[$__rate_interval]))`)
        .legendFormat("req/s")
        .refId("A")
    );
}

function errorRateStat(): StatPanel {
  return new StatPanel()
    .title("Error Rate")
    .description("5xx responses as percentage of total")
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
          `sum(rate(mcpgate_http_requests_total{${JOB_FILTER},status_code=~"5.."}[$__rate_interval])) / sum(rate(mcpgate_http_requests_total{${JOB_FILTER}}[$__rate_interval]))`
        )
        .legendFormat("error %")
        .refId("A")
    );
}

function p95LatencyStat(): StatPanel {
  return new StatPanel()
    .title("P95 Latency")
    .description("95th percentile request latency")
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
          `histogram_quantile(0.95, sum(rate(mcpgate_http_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le)) * 1000`
        )
        .legendFormat("p95")
        .refId("A")
    );
}

function requestRateTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Request Rate by Status")
    .description("HTTP request rate broken down by status code")
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
          `sum by (status_code) (rate(mcpgate_http_requests_total{${JOB_FILTER}}[$__rate_interval]))`
        )
        .legendFormat("{{status_code}}")
        .refId("A")
    );
}

function latencyTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Request Latency Percentiles")
    .description("P50, P90, P99 request latency")
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
          `histogram_quantile(0.50, sum(rate(mcpgate_http_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
        )
        .legendFormat("p50")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.90, sum(rate(mcpgate_http_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
        )
        .legendFormat("p90")
        .refId("B")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.99, sum(rate(mcpgate_http_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
        )
        .legendFormat("p99")
        .refId("C")
    );
}

/** Returns panels for the Service Overview section (added directly to dashboard, not inside a collapsed row). */
export function overviewPanels(): cog.Builder<dashboard.Panel>[] {
  return [
    requestRateStat(),
    errorRateStat(),
    p95LatencyStat(),
    requestRateTimeseries(),
    latencyTimeseries(),
  ];
}
