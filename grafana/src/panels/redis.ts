import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import { RowBuilder } from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, SELECTOR } from "./constants";
import { timeseriesPanel } from "./defaults";

// The Redis rate-limit backend is optional: these panels are empty unless
// REDIS_ADDR is set (check the "Rate-Limit Backend" tile), which is why the row
// is collapsed. When it IS set they matter more than they look — the limiter
// fails open, so a Redis outage removes per-IP rate limiting while every
// request still succeeds, and the error counter below is the only trace.

function redisErrorsTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("Redis Fail-Open Errors")
    .description(
      "Redis rate-limit calls that failed and let the request through unlimited, by kind (timeout = exceeded REDIS_TIMEOUT, " +
        "unavailable = connection refused, other), per gate. Any sustained rate means rate limiting is not being enforced."
    )
    .datasource(PROMETHEUS)
    .unit("cps")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (kind, service) (rate(mcpgate_ratelimit_redis_errors_total{${SELECTOR}}[$__rate_interval]))`
        )
        .legendFormat("{{service}} {{kind}}")
        .refId("A")
    );
}

function redisLatencyTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("Redis Allow Latency")
    .description(
      "P50 and P99 latency of the Redis rate-limit call, per gate. This is added to every request; p99 above ~10ms on a " +
        "local Redis points to a network or load problem, and calls past REDIS_TIMEOUT fail open."
    )
    .datasource(PROMETHEUS)
    .unit("s")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.50, sum(rate(mcpgate_ratelimit_redis_latency_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p50")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(
          `histogram_quantile(0.99, sum(rate(mcpgate_ratelimit_redis_latency_seconds_bucket{${SELECTOR}}[$__rate_interval])) by (le, service))`
        )
        .legendFormat("{{service}} p99")
        .refId("B")
    );
}

export function redisRow(): RowBuilder {
  return new RowBuilder("Redis Rate Limiter")
    .collapsed(true)
    .withPanel(redisErrorsTimeseries())
    .withPanel(redisLatencyTimeseries());
}
