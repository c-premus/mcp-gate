import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { PanelBuilder as PiechartPanel } from "@grafana/grafana-foundation-sdk/piechart";
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
import type * as cog from "@grafana/grafana-foundation-sdk/cog";
import type * as dashboard from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, SELECTOR } from "./constants";

function validAuthStat(): StatPanel {
  return new StatPanel()
    .title("Valid Auth")
    .description("Successful JWT validations per second, per gate")
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
          `sum by (service) (rate(mcpgate_auth_validations_total{${SELECTOR},outcome="valid"}[$__rate_interval]))`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function noTokenStat(): StatPanel {
  return new StatPanel()
    .title("No Token")
    .description("Requests without Bearer token per second, per gate")
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
          `sum by (service) (rate(mcpgate_auth_validations_total{${SELECTOR},outcome="no_token"}[$__rate_interval]))`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function invalidTokenStat(): StatPanel {
  return new StatPanel()
    .title("Invalid Token")
    .description("Invalid/expired token rejections per second, per gate")
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
          `sum by (service) (rate(mcpgate_auth_validations_total{${SELECTOR},outcome="invalid_token"}[$__rate_interval]))`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function insufficientScopeStat(): StatPanel {
  return new StatPanel()
    .title("Insufficient Scope")
    .description("Scope-check failures per second, per gate")
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
          `sum by (service) (rate(mcpgate_auth_validations_total{${SELECTOR},outcome="insufficient_scope"}[$__rate_interval]))`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function authFailureTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Auth Failure Rate")
    .description("Authentication failures over time by outcome, per gate")
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
          `sum by (outcome, service) (rate(mcpgate_auth_validations_total{${SELECTOR},outcome!="valid"}[$__rate_interval]))`
        )
        .legendFormat("{{service}} {{outcome}}")
        .refId("A")
    );
}

function authOutcomePiechart(): PiechartPanel {
  return new PiechartPanel()
    .title("Auth Outcomes")
    .description("Distribution of authentication outcomes over the selected time range, per gate")
    .datasource(PROMETHEUS)
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `sum by (outcome, service) (increase(mcpgate_auth_validations_total{${SELECTOR}}[$__range]))`
        )
        .legendFormat("{{service}} {{outcome}}")
        .refId("A")
        .instant()
    );
}

/** Returns panels for the Authentication section (added directly to dashboard so the row stays expanded — the Grafana Foundation SDK forces collapsed=true whenever a row has nested panels). */
export function authPanels(): cog.Builder<dashboard.Panel>[] {
  return [
    validAuthStat(),
    noTokenStat(),
    invalidTokenStat(),
    insufficientScopeStat(),
    authFailureTimeseries(),
    authOutcomePiechart(),
  ];
}
