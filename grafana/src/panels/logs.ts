import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { PanelBuilder as LogsPanel } from "@grafana/grafana-foundation-sdk/logs";
import { DataqueryBuilder as LokiQuery } from "@grafana/grafana-foundation-sdk/loki";
import { RowBuilder } from "@grafana/grafana-foundation-sdk/dashboard";
import { LOKI, SERVICE_NAME } from "./constants";

function logVolumeTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Log Volume")
    .description("Log volume by level")
    .datasource(LOKI)
    .unit("short")
    .span(12)
    .height(6)
    .withTarget(
      new LokiQuery()
        .expr(
          `sum by (level) (count_over_time({service_name="${SERVICE_NAME}"} | json [$__auto]))`
        )
        .legendFormat("{{level}}")
        .refId("A")
    );
}

function liveLogsPanel(): LogsPanel {
  return new LogsPanel()
    .title("Live Logs")
    .description("Live log stream from mcp-gate")
    .datasource(LOKI)
    .span(12)
    .height(12)
    .withTarget(
      new LokiQuery()
        .expr(`{service_name="${SERVICE_NAME}"} | json`)
        .refId("A")
    );
}

export function logsRow(): RowBuilder {
  return new RowBuilder("Logs")
    .withPanel(logVolumeTimeseries())
    .withPanel(liveLogsPanel());
}
