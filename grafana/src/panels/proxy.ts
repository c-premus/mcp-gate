import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import {
  RowBuilder,
  ThresholdsConfigBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { ThresholdsMode } from "@grafana/grafana-foundation-sdk/dashboard";
import {
  BigValueColorMode,
  VizTooltipOptionsBuilder,
  TooltipDisplayMode,
  SortOrder,
} from "@grafana/grafana-foundation-sdk/common";
import { PROMETHEUS, JOB_FILTER } from "./constants";

function proxyP95Stat(): StatPanel {
  return new StatPanel()
    .title("Upstream P95")
    .description("95th percentile upstream response latency")
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
          `histogram_quantile(0.95, sum(rate(mcpgate_proxy_request_duration_seconds_bucket{${JOB_FILTER}}[$__rate_interval])) by (le)) * 1000`
        )
        .legendFormat("p95")
        .refId("A")
    );
}

function proxyErrorRateStat(): StatPanel {
  return new StatPanel()
    .title("Upstream Error Rate")
    .description("5xx upstream responses as percentage of total")
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
          `sum(rate(mcpgate_proxy_requests_total{${JOB_FILTER},status_code=~"5.."}[$__rate_interval])) / sum(rate(mcpgate_proxy_requests_total{${JOB_FILTER}}[$__rate_interval]))`
        )
        .legendFormat("error %")
        .refId("A")
    );
}

function jwksKeysStat(): StatPanel {
  return new StatPanel()
    .title("JWKS Keys")
    .description("Number of cached JWKS signing keys")
    .datasource(PROMETHEUS)
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "red" },
          { value: 1, color: "green" },
        ])
    )
    .span(8)
    .height(5)
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
          `sum by (status_code) (rate(mcpgate_proxy_requests_total{${JOB_FILTER}}[$__rate_interval]))`
        )
        .legendFormat("{{status_code}}")
        .refId("A")
    );
}

export function proxyRow(): RowBuilder {
  return new RowBuilder("Upstream Proxy")
    .collapsed(true)
    .withPanel(proxyP95Stat())
    .withPanel(proxyErrorRateStat())
    .withPanel(jwksKeysStat())
    .withPanel(proxyLatencyTimeseries())
    .withPanel(proxyStatusTimeseries());
}
