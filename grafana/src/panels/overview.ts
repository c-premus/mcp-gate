import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import { RowBuilder } from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, JOB_FILTER } from "./constants";

function requestRateStat(): StatPanel {
  return new StatPanel()
    .title("Request Rate")
    .description("Requests per second")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .span(4)
    .height(4)
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
    .span(4)
    .height(4)
    .decimals(2)
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
    .unit("s")
    .span(4)
    .height(4)
    .decimals(3)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.95, sum(rate(mcpgate_http_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
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

export function overviewRow(): RowBuilder {
  return new RowBuilder("Service Overview")
    .withPanel(requestRateStat())
    .withPanel(errorRateStat())
    .withPanel(p95LatencyStat())
    .withPanel(requestRateTimeseries())
    .withPanel(latencyTimeseries());
}
