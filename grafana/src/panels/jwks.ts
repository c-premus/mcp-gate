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

// These panels query gauges and counters directly, with no aggregation — the
// series already carry `service`, so selecting several gates yields one series
// each without any `by` clause. The legends are `{{service}}` for exactly that
// reason: on a stat panel the series name is the only thing distinguishing one
// gate's tile from another's.

function keysLoadedStat(): StatPanel {
  return statPanel()
    .title("JWKS Keys Loaded")
    .description("Number of cached JWKS signing keys, per gate. Zero means that gate cannot validate any JWT.")
    .datasource(PROMETHEUS)
    .unit("short")
    .noValue("0")
    .decimals(0)
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
        .expr(`mcpgate_jwks_keys_loaded{${SELECTOR}}`)
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function refreshErrorsStat(): StatPanel {
  return statPanel()
    .title("Refresh Errors")
    .description("JWKS refresh failures within the dashboard time range, per gate (liveness signal)")
    .datasource(PROMETHEUS)
    .unit("short")
    .noValue("0")
    .decimals(0)
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 1, color: "yellow" },
          { value: 5, color: "red" },
        ])
    )
    .span(8)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`increase(mcpgate_jwks_refresh_errors_total{${SELECTOR}}[$__range])`)
        .legendFormat("{{service}}")
        .refId("A")
        .instant()
    );
}

function timeSinceKeyChangeStat(): StatPanel {
  return statPanel()
    .title("Time Since Key Change")
    .description("Duration since the JWKS key set last changed, per gate (correctness signal — stale may indicate stuck refresh)")
    .datasource(PROMETHEUS)
    .unit("s")
    .noValue("—")
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 2592000, color: "yellow" },
          { value: 7776000, color: "red" },
        ])
    )
    .span(8)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `time() - mcpgate_jwks_last_key_change_timestamp_seconds{${SELECTOR}}`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function refreshErrorRateTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("JWKS Refresh Error Rate")
    .description("Rate of JWKS refresh failures over time, per gate")
    .datasource(PROMETHEUS)
    .unit("cps")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `rate(mcpgate_jwks_refresh_errors_total{${SELECTOR}}[$__rate_interval])`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function keysLoadedTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("JWKS Keys Loaded Over Time")
    .description("Cached JWKS signing-key count over time, per gate")
    .datasource(PROMETHEUS)
    .unit("short")
    .colorScheme(new FieldColorBuilder().mode(FieldColorModeId.Fixed).fixedColor("green"))
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(`mcpgate_jwks_keys_loaded{${SELECTOR}}`)
        .legendFormat("{{service}}")
        .refId("A")
    );
}

/** Returns panels for the JWKS Health section (added directly to dashboard so the row stays expanded — the Grafana Foundation SDK forces collapsed=true whenever a row has nested panels). */
export function jwksPanels(): cog.Builder<dashboard.Panel>[] {
  return [
    keysLoadedStat(),
    refreshErrorsStat(),
    timeSinceKeyChangeStat(),
    refreshErrorRateTimeseries(),
    keysLoadedTimeseries(),
  ];
}
