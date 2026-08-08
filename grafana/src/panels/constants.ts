import type * as dashboard from "@grafana/grafana-foundation-sdk/dashboard";

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

/** Name of the gate-selection dashboard variable, and the metric that populates it. */
export const SERVICE_VAR = "service";
export const SERVICE_VAR_METRIC = 'mcpgate_info{job="mcp-gate"}';

/**
 * Prometheus label selector shared by every mcp-gate panel.
 *
 * `job` pins the scrape job; `service` narrows to the gate(s) selected in the
 * `$service` variable. One mcp-gate deployment per upstream is the expected
 * shape, and a single Prometheus job can scrape several of them by attaching a
 * distinct `service` target label to each — see docs/setup.md.
 *
 * The matcher MUST be `=~`, not `=`: a multi-value variable interpolates as
 * `(a|b)`, which `=` would compare as one literal label value and match
 * nothing. Selecting "All" expands to the real gate list rather than to a
 * wildcard — see the variable definition in dashboard.ts for why.
 */
export const SELECTOR = `job="mcp-gate", service=~"$${SERVICE_VAR}"`;

/**
 * Loki stream selector for mcp-gate logs.
 *
 * `service_name` is Loki's spelling of the identity Prometheus calls `service`
 * — both are the gate's OTEL_SERVICE_NAME — which is what lets one variable
 * drive metrics, logs and traces together. `=~` for the same reason as above.
 *
 * Note there is no `job` equivalent here to bound the selector to mcp-gate:
 * this stream selector is scoped ONLY by the variable's expansion, which is
 * why the variable must never expand to a wildcard.
 */
export const LOKI_SELECTOR = `{service_name=~"$${SERVICE_VAR}"}`;

/** TraceQL resource matcher — the third spelling of that same identity. */
export const TRACE_SERVICE_MATCHER = `resource.service.name=~"$${SERVICE_VAR}"`;

export const HEALTHZ_FILTER = 'path!="/healthz"';
