import { PanelBuilder as TablePanel } from "@grafana/grafana-foundation-sdk/table";
import { TempoQueryBuilder } from "@grafana/grafana-foundation-sdk/tempo";
import { RowBuilder } from "@grafana/grafana-foundation-sdk/dashboard";
import { TEMPO, SERVICE_NAME } from "./constants";

function recentTracesTable(): TablePanel {
  return new TablePanel()
    .title("Recent Traces")
    .description("Recent traces (excludes health checks)")
    .datasource(TEMPO)
    .span(24)
    .height(12)
    .withTarget(
      new TempoQueryBuilder()
        .queryType("traceqlSearch")
        .query(`{resource.service.name="${SERVICE_NAME}" && name !~ ".*healthz.*"}`)
        .limit(20)
        .refId("A")
    );
}

export function tracesRow(): RowBuilder {
  return new RowBuilder("Trace Explorer")
    .collapsed(true)
    .withPanel(recentTracesTable());
}
