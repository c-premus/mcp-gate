import type { dashboard } from "@grafana/grafana-foundation-sdk";

export const PROMETHEUS: dashboard.DataSourceRef = {
  type: "prometheus",
  uid: "${DS_PROMETHEUS}",
};

export const TEMPO: dashboard.DataSourceRef = {
  type: "tempo",
  uid: "${DS_TEMPO}",
};

export const LOKI: dashboard.DataSourceRef = {
  type: "loki",
  uid: "${DS_LOKI}",
};

export const JOB_FILTER = 'job="mcp-gate"';
export const SERVICE_NAME = "mcp-gate";
export const HEALTHZ_FILTER = 'path!="/healthz"';
