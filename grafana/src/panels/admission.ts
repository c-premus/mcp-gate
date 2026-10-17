import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import {
  ThresholdsConfigBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { ThresholdsMode } from "@grafana/grafana-foundation-sdk/dashboard";
import {
  BigValueColorMode,
  BigValueTextMode,
} from "@grafana/grafana-foundation-sdk/common";
import type * as cog from "@grafana/grafana-foundation-sdk/cog";
import type * as dashboard from "@grafana/grafana-foundation-sdk/dashboard";
import { PROMETHEUS, SELECTOR } from "./constants";
import { statPanel, timeseriesPanel } from "./defaults";

// Everything mcp-gate does to a request before authentication: per-IP rate
// limiting (429), the per-IP and global concurrency caps (503), Origin
// validation (403), and the transparent strip of a deprecated access_token
// query parameter. Until this section existed none of it was on the dashboard,
// so a gate shedding load or rejecting every browser request looked healthy.
//
// The rejection tiles are range-wide `increase` counts rather than rates, for
// the same reason as JWKS "Refresh Errors": these are rare events, and "how
// many in the selected window" is the question; a rate rounds them to zero.
//
// Six tiles at 4 wide tile the section's first line to exactly 24 — see the
// note in proxy.ts on why widths must tile evenly.

/** Range-wide event count tile: green at zero, yellow on any event. */
function eventCountStat(
  title: string,
  description: string,
  metric: string,
  red: number
): StatPanel {
  return statPanel()
    .title(title)
    .description(description)
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
          { value: red, color: "red" },
        ])
    )
    .span(4)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`increase(${metric}{${SELECTOR}}[$__range])`)
        .legendFormat("{{service}}")
        .refId("A")
        .instant()
    );
}

function rateLimitedStat(): StatPanel {
  return eventCountStat(
    "Rate Limited",
    "Requests rejected with 429 by the per-IP rate limiter (RATE_LIMIT_RPS / RATE_LIMIT_BURST) within the time range, per gate. " +
      "If this climbs while Trusted Proxy CIDRs reads 0 behind a fronting proxy, every client shares one bucket.",
    "mcpgate_rate_limited_total",
    100
  );
}

function concurrencyLimitedStat(): StatPanel {
  return eventCountStat(
    "Concurrency Limited",
    "Requests rejected with 503 because the client IP reached MAX_CONCURRENT_REQUESTS or the gate reached MAX_TOTAL_CONNECTIONS, " +
      "within the time range, per gate. Long-lived SSE streams hold their slot for their whole lifetime.",
    "mcpgate_concurrent_limited_total",
    10
  );
}

function originRejectedStat(): StatPanel {
  return eventCountStat(
    "Origin Rejected",
    "Requests rejected with 403 because Origin was not in ALLOWED_ORIGINS, within the time range, per gate. " +
      "Always 0 while ALLOWED_ORIGINS is unset (validation off). Once enabled this is the only signal of a wrong allow-list: " +
      "it rejects every browser request while /healthz stays green.",
    "mcpgate_origin_rejected_total",
    10
  );
}

function deprecatedTokenQueryStat(): StatPanel {
  return eventCountStat(
    "Deprecated access_token Query",
    "Requests that carried an access_token query parameter, within the time range, per gate. The request still succeeds — the " +
      "parameter is stripped before proxying — so this counter is the only sign of it. RFC 6750 §2.3 deprecates the method and " +
      "MCP 2026-07-28 disallows it; a token in a URL ends up in access logs. Fix the client.",
    "mcpgate_deprecated_access_token_query_total",
    10
  );
}

function trustedProxyCidrsStat(): StatPanel {
  return statPanel()
    .title("Trusted Proxy CIDRs")
    .description(
      "Number of TRUSTED_PROXIES CIDRs parsed at startup, per gate. 0 is correct only when clients connect to the gate directly; " +
        "behind Traefik or Cloudflare it means every request is attributed to the proxy's IP, which silently defeats per-IP rate limiting."
    )
    .datasource(PROMETHEUS)
    .unit("short")
    .noValue("—")
    .decimals(0)
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "yellow" },
          { value: 1, color: "green" },
        ])
    )
    .span(4)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`mcpgate_trusted_proxy_cidrs{${SELECTOR}}`)
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function rateLimitBackendStat(): StatPanel {
  return statPanel()
    .title("Rate-Limit Backend")
    .description(
      "Active rate-limit backend, per gate. 'memory' limits each replica independently; 'redis' (REDIS_ADDR set) coordinates " +
        "across replicas and fails open on Redis errors — see the Redis Rate Limiter row."
    )
    .datasource(PROMETHEUS)
    // The gauge's value is always 1 for the active backend; the information is
    // in the label, so the tile shows the series name instead of the value.
    .unit("none")
    .noValue("—")
    .textMode(BigValueTextMode.Name)
    .colorMode(BigValueColorMode.None)
    .span(4)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`mcpgate_ratelimit_backend_info{${SELECTOR}} == 1`)
        .legendFormat("{{service}}: {{backend}}")
        .refId("A")
    );
}

function rejectionsTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("Admission Rejections")
    .description("Requests rejected before authentication, by reason, per gate")
    .datasource(PROMETHEUS)
    .unit("reqps")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(`rate(mcpgate_rate_limited_total{${SELECTOR}}[$__rate_interval])`)
        .legendFormat("{{service}} rate limited (429)")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(`rate(mcpgate_concurrent_limited_total{${SELECTOR}}[$__rate_interval])`)
        .legendFormat("{{service}} concurrency limited (503)")
        .refId("B")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(`rate(mcpgate_origin_rejected_total{${SELECTOR}}[$__rate_interval])`)
        .legendFormat("{{service}} origin rejected (403)")
        .refId("C")
    );
}

function inFlightTimeseries(): TimeseriesPanel {
  return timeseriesPanel()
    .title("In-Flight Requests & Connections")
    .description(
      "Active HTTP requests and open TCP connections, per gate. Each open SSE stream is one long-lived request, so a plateau " +
        "here is normal. Requests approaching MAX_TOTAL_CONNECTIONS (default 1000) start returning 503."
    )
    .datasource(PROMETHEUS)
    .unit("short")
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(`mcpgate_active_requests{${SELECTOR}}`)
        .legendFormat("{{service}} requests")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(`mcpgate_active_connections{${SELECTOR}}`)
        .legendFormat("{{service}} connections")
        .refId("B")
    );
}

/** Returns panels for the Admission Control section (added directly to dashboard so the row stays expanded — the Grafana Foundation SDK forces collapsed=true whenever a row has nested panels). */
export function admissionPanels(): cog.Builder<dashboard.Panel>[] {
  return [
    rateLimitedStat(),
    concurrencyLimitedStat(),
    originRejectedStat(),
    deprecatedTokenQueryStat(),
    trustedProxyCidrsStat(),
    rateLimitBackendStat(),
    rejectionsTimeseries(),
    inFlightTimeseries(),
  ];
}
