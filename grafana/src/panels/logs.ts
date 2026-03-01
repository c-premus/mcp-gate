import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { PanelBuilder as LogsPanel } from "@grafana/grafana-foundation-sdk/logs";
import { DataqueryBuilder as LokiQuery } from "@grafana/grafana-foundation-sdk/loki";
import {
  LogsSortOrder,
  LogsDedupStrategy,
  VizTooltipOptionsBuilder,
  TooltipDisplayMode,
  SortOrder,
} from "@grafana/grafana-foundation-sdk/common";
import type { cog, dashboard } from "@grafana/grafana-foundation-sdk";
import { LOKI, SERVICE_NAME, HEALTHZ_FILTER } from "./constants";

function logVolumeTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Log Volume")
    .description("Log volume by level (excludes health checks)")
    .datasource(LOKI)
    .unit("short")
    .tooltip(
      new VizTooltipOptionsBuilder()
        .mode(TooltipDisplayMode.Multi)
        .sort(SortOrder.Descending)
    )
    .span(24)
    .height(5)
    .withTarget(
      new LokiQuery()
        .expr(
          `sum by (level) (count_over_time({service_name="${SERVICE_NAME}"} | json | ${HEALTHZ_FILTER} [$__auto]))`
        )
        .legendFormat("{{level}}")
        .refId("A")
    );
}

function liveLogsPanel(): LogsPanel {
  return new LogsPanel()
    .title("Live Logs")
    .description("Live log stream (excludes health checks)")
    .datasource(LOKI)
    .showTime(true)
    .sortOrder(LogsSortOrder.Descending)
    .dedupStrategy(LogsDedupStrategy.None)
    .wrapLogMessage(true)
    .enableLogDetails(true)
    .span(24)
    .height(16)
    .withTarget(
      new LokiQuery()
        .expr(`{service_name="${SERVICE_NAME}"} | json | ${HEALTHZ_FILTER}`)
        .refId("A")
    );
}

/** Returns panels for the Logs section (added directly to dashboard, not inside a collapsed row). */
export function logsPanels(): cog.Builder<dashboard.Panel>[] {
  return [logVolumeTimeseries(), liveLogsPanel()];
}
