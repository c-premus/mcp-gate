import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import {
  RowBuilder,
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
import { PROMETHEUS, JOB_FILTER } from "./constants";

function keysLoadedStat(): StatPanel {
  return new StatPanel()
    .title("JWKS Keys Loaded")
    .description("Number of cached JWKS signing keys. Zero means mcp-gate cannot validate any JWT.")
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

function refreshErrorsStat(): StatPanel {
  return new StatPanel()
    .title("Refresh Errors")
    .description("JWKS refresh failures within the dashboard time range (liveness signal)")
    .datasource(PROMETHEUS)
    .noValue("0")
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
        .expr(`increase(mcpgate_jwks_refresh_errors_total{${JOB_FILTER}}[$__range])`)
        .legendFormat("errors")
        .refId("A")
        .instant()
    );
}

function timeSinceKeyChangeStat(): StatPanel {
  return new StatPanel()
    .title("Time Since Key Change")
    .description("Duration since the JWKS key set last changed (correctness signal — stale may indicate stuck refresh)")
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
          `time() - mcpgate_jwks_last_key_change_timestamp_seconds{${JOB_FILTER}}`
        )
        .legendFormat("age")
        .refId("A")
    );
}

function refreshErrorRateTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("JWKS Refresh Error Rate")
    .description("Rate of JWKS refresh failures over time")
    .datasource(PROMETHEUS)
    .unit("cps")
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
          `rate(mcpgate_jwks_refresh_errors_total{${JOB_FILTER}}[$__rate_interval])`
        )
        .legendFormat("errors/s")
        .refId("A")
    );
}

function keysLoadedTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("JWKS Keys Loaded Over Time")
    .description("Cached JWKS signing-key count over time")
    .datasource(PROMETHEUS)
    .colorScheme(new FieldColorBuilder().mode(FieldColorModeId.Fixed).fixedColor("green"))
    .tooltip(
      new VizTooltipOptionsBuilder()
        .mode(TooltipDisplayMode.Multi)
        .sort(SortOrder.Descending)
    )
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(`mcpgate_jwks_keys_loaded{${JOB_FILTER}}`)
        .legendFormat("keys")
        .refId("A")
    );
}

export function jwksRow(): RowBuilder {
  return new RowBuilder("JWKS Health")
    .collapsed(true)
    .withPanel(keysLoadedStat())
    .withPanel(refreshErrorsStat())
    .withPanel(timeSinceKeyChangeStat())
    .withPanel(refreshErrorRateTimeseries())
    .withPanel(keysLoadedTimeseries());
}
