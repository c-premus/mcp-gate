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
import { BigValueColorMode } from "@grafana/grafana-foundation-sdk/common";
import type * as cog from "@grafana/grafana-foundation-sdk/cog";
import type * as dashboard from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, SELECTOR } from "./constants";
import { statPanel, timeseriesPanel } from "./defaults";

function requestRateStat(): StatPanel {
  return statPanel()
    .title("Request Rate")
    .description("Requests per second, per gate")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .colorScheme(new FieldColorBuilder().mode(FieldColorModeId.Fixed).fixedColor("green"))
    .span(8)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`sum by (service) (rate(mcpgate_http_requests_total{${SELECTOR}}[$__rate_interval]))`)
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function errorRateStat(): StatPanel {
  return statPanel()
    .title("Error Rate")
    .description("5xx responses as percentage of total, per gate")
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
          `sum by (service) (rate(mcpgate_http_requests_total{${SELECTOR},status_code=~"5.."}[$__rate_interval])) / sum by (service) (rate(mcpgate_http_requests_total{${SELECTOR}}[$__rate_interval]))`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function p95LatencyStat(): StatPanel {
  return statPanel()
    .title("P95 Latency")
    .description("95th percentile request latency, per gate")
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
          `histogram_quantile(0.95, sum(rate(mcpgate_http_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service)) * 1000`
        )
        .legendFormat("{{service}} p95")
        .refId("A")
    );
}

function requestRateTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("Request Rate by Status")
    .description("HTTP request rate broken down by status code, per gate")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (status_code, service) (rate(mcpgate_http_requests_total{${SELECTOR}}[$__rate_interval]))`
        )
        .legendFormat("{{service}} {{status_code}}")
        .refId("A")
    );
}

function latencyTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("Request Latency Percentiles")
    .description("P50, P90, P99 request latency, per gate")
    .datasource(PROMETHEUS)
    .unit("s")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.50, sum(rate(mcpgate_http_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p50")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.90, sum(rate(mcpgate_http_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p90")
        .refId("B")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.99, sum(rate(mcpgate_http_request_duration_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p99")
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
