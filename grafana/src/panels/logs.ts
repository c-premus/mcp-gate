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
import type * as cog from "@grafana/grafana-foundation-sdk/cog";
import type * as dashboard from "@grafana/grafana-foundation-sdk/dashboard";
import { LOKI, LOKI_SELECTOR, HEALTHZ_FILTER } from "./constants";

function logVolumeTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Log Volume")
    .description("Log volume by level, per gate (excludes health checks)")
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
        // Grouped by `service_name`, not `service` — on the Loki side the gate
        // identity is carried by the stream label, and grouping by a label the
        // stream does not have would collapse every gate into one series.
        .expr(
          `sum by (level, service_name) (count_over_time(${LOKI_SELECTOR} | json | ${HEALTHZ_FILTER} [$__auto]))`
        )
        .legendFormat("{{service_name}} {{level}}")
        .refId("A")
    );
}

function liveLogsPanel(): LogsPanel {
  return new LogsPanel()
    .title("Live Logs")
    .description("Live log stream, all selected gates (excludes health checks)")
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
        .expr(`${LOKI_SELECTOR} | json | ${HEALTHZ_FILTER}`)
        .refId("A")
    );
}

/** Returns panels for the Logs section (added directly to dashboard, not inside a collapsed row). */
export function logsPanels(): cog.Builder<dashboard.Panel>[] {
  return [logVolumeTimeseries(), liveLogsPanel()];
}
