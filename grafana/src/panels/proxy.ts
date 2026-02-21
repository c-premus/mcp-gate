import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import { RowBuilder } from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, JOB_FILTER } from "./constants";

function proxyP95Stat(): StatPanel {
  return new StatPanel()
    .title("Upstream P95")
    .description("95th percentile upstream latency")
    .datasource(PROMETHEUS)
    .unit("s")
    .span(4)
    .height(4)
    .decimals(3)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.95, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
        )
        .legendFormat("p95")
        .refId("A")
    );
}

function proxyErrorRateStat(): StatPanel {
  return new StatPanel()
    .title("Upstream Error Rate")
    .description("5xx upstream responses as percentage")
    .datasource(PROMETHEUS)
    .unit("percentunit")
    .span(4)
    .height(4)
    .decimals(2)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum(rate(mcpgate_proxy_requests_total{${JOB_FILTER},status_code=~"5.."}[$__rate_interval])) / sum(rate(mcpgate_proxy_requests_total{${JOB_FILTER}}[$__rate_interval]))`
        )
        .legendFormat("error %")
        .refId("A")
    );
}

function jwksKeysStat(): StatPanel {
  return new StatPanel()
    .title("JWKS Keys")
    .description("Number of cached JWKS keys")
    .datasource(PROMETHEUS)
    .span(4)
    .height(4)
    .withTarget(
      new PrometheusQuery()
        .expr(`mcpgate_jwks_keys_loaded{${JOB_FILTER}}`)
        .legendFormat("keys")
        .refId("A")
    );
}

function proxyLatencyTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Upstream Latency Percentiles")
    .description("P50, P90, P99 upstream proxy latency")
    .datasource(PROMETHEUS)
    .unit("s")
    .span(6)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.50, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
        )
        .legendFormat("p50")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.90, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
        )
        .legendFormat("p90")
        .refId("B")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.99, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le))`
        )
        .legendFormat("p99")
        .refId("C")
    );
}

function proxyStatusTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Upstream Status Codes")
    .description("Upstream response status codes over time")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .span(6)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (status_code) (rate(mcpgate_proxy_requests_total{${JOB_FILTER}}[$__rate_interval]))`
        )
        .legendFormat("{{status_code}}")
        .refId("A")
    );
}

export function proxyRow(): RowBuilder {
  return new RowBuilder("Upstream Proxy")
    .withPanel(proxyP95Stat())
    .withPanel(proxyErrorRateStat())
    .withPanel(jwksKeysStat())
    .withPanel(proxyLatencyTimeseries())
    .withPanel(proxyStatusTimeseries());
}
