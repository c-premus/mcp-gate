import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { PanelBuilder as PiechartPanel } from "@grafana/grafana-foundation-sdk/piechart";
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

function validAuthStat(): StatPanel {
  return new StatPanel()
    .title("Valid Auth")
    .description("Successful JWT validations per second")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .colorScheme(new FieldColorBuilder().mode(FieldColorModeId.Fixed).fixedColor("green"))
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum(rate(mcpgate_auth_validations_total{${JOB_FILTER},outcome="valid"}[$__rate_interval]))`
        )
        .legendFormat("valid/s")
        .refId("A")
    );
}

function noTokenStat(): StatPanel {
  return new StatPanel()
    .title("No Token")
    .description("Requests without Bearer token per second")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 0.1, color: "yellow" },
          { value: 1, color: "red" },
        ])
    )
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum(rate(mcpgate_auth_validations_total{${JOB_FILTER},outcome="no_token"}[$__rate_interval]))`
        )
        .legendFormat("no_token/s")
        .refId("A")
    );
}

function invalidTokenStat(): StatPanel {
  return new StatPanel()
    .title("Invalid Token")
    .description("Invalid/expired token rejections per second")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 0.1, color: "yellow" },
          { value: 1, color: "red" },
        ])
    )
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum(rate(mcpgate_auth_validations_total{${JOB_FILTER},outcome="invalid_token"}[$__rate_interval]))`
        )
        .legendFormat("invalid/s")
        .refId("A")
    );
}

function insufficientScopeStat(): StatPanel {
  return new StatPanel()
    .title("Insufficient Scope")
    .description("Scope-check failures per second")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 0.1, color: "yellow" },
          { value: 1, color: "red" },
        ])
    )
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum(rate(mcpgate_auth_validations_total{${JOB_FILTER},outcome="insufficient_scope"}[$__rate_interval]))`
        )
        .legendFormat("scope_fail/s")
        .refId("A")
    );
}

function authFailureTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Auth Failure Rate")
    .description("Authentication failures over time by outcome")
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
          `sum by (outcome) (rate(mcpgate_auth_validations_total{${JOB_FILTER},outcome!="valid"}[$__rate_interval]))`
        )
        .legendFormat("{{outcome}}")
        .refId("A")
    );
}

function authOutcomePiechart(): PiechartPanel {
  return new PiechartPanel()
    .title("Auth Outcomes")
    .description("Distribution of authentication outcomes over the selected time range")
    .datasource(PROMETHEUS)
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (outcome) (increase(mcpgate_auth_validations_total{${JOB_FILTER}}[$__range]))`
        )
        .legendFormat("{{outcome}}")
        .refId("A")
        .instant()
    );
}

export function authRow(): RowBuilder {
  return new RowBuilder("Authentication")
    .collapsed(true)
    .withPanel(validAuthStat())
    .withPanel(noTokenStat())
    .withPanel(invalidTokenStat())
    .withPanel(insufficientScopeStat())
    .withPanel(authFailureTimeseries())
    .withPanel(authOutcomePiechart());
}
