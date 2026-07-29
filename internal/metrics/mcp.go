package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MCP request-metadata headers. Protocol revision 2026-07-28 mirrors selected
// JSON-RPC body fields into HTTP headers so that intermediaries — which is
// exactly what mcp-gate is — can route, meter, and observe requests without
// parsing bodies.
//
// # The read-only rule
//
// These headers are OBSERVABILITY INPUTS ONLY. No mcp-gate code path may branch
// on them: not routing, not rate-limit keying, not auth outcome, not response
// content, not status code. They may only be written to metric labels and log
// fields.
//
// This is load-bearing, not stylistic. The spec obliges intermediaries that
// "enforce policy based on mirrored headers (e.g., routing or rate-limiting by
// tenant)" to verify the MCP-Protocol-Version header and reject requests whose
// version is old or absent. Recording a metric is not enforcing policy — but
// the slip is realistic: a panel becomes an alert becomes an autoscaling rule,
// and an unauthenticated client-supplied header ends up driving infrastructure
// with nobody remembering the obligation triggered three steps back. Holding
// the line at "observability only" keeps mcp-gate permanently outside that
// obligation, which is the right outcome: rejecting old-version requests would
// break every pre-2026-07-28 client for no security gain.
//
// The values are also unvalidated. mcp-gate does not check them against the
// request body — that is the origin server's job, and it rejects a mismatch
// with 400 and JSON-RPC -32020 HeaderMismatch. Treat every value here as a
// client assertion, not a fact.
const (
	HeaderMCPProtocolVersion = "MCP-Protocol-Version"
	HeaderMCPMethod          = "Mcp-Method"
	HeaderMCPName            = "Mcp-Name"
)

// base64SentinelPrefix marks a header value as Base64-encoded UTF-8, per the
// spec's Value Encoding rules. Clients use it when a value cannot be safely
// represented as plain ASCII — and must also use it for any plain-ASCII value
// that would otherwise look like the sentinel.
const base64SentinelPrefix = "=?base64?"

// MCPRequestsTotal counts proxied requests by MCP method and protocol version.
//
// Deliberately a separate metric rather than extra labels on
// mcpgate_http_requests_total: adding them there would multiply the existing
// method × route × status_code series by the MCP method count and change the
// label set of series the Grafana dashboard and the 5xx-ratio alert already
// query.
var MCPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "mcpgate_mcp_requests_total",
	Help: "Proxied requests by MCP method and protocol version, from the " +
		"2026-07-28 request-metadata headers. Values are client-asserted and " +
		"not validated against the request body.",
}, []string{"mcp_method", "protocol_version"})

// mcpMethodLabel maps the Mcp-Method header to a bounded Prometheus label.
//
// The allow-list is the client-to-server method set of protocol revision
// 2026-07-28, taken from the published schema. Note what is NOT here:
// initialize, notifications/initialized, ping, logging/setLevel,
// resources/subscribe, and resources/unsubscribe were all removed in this
// revision. That is not an omission — the Mcp-Method header only exists in the
// 2026-07-28 era, so a client old enough to call those methods does not send
// the header at all and lands in "absent".
//
// Server-to-client methods (sampling/createMessage, roots/list,
// elicitation/create) are likewise absent by design: under Multi Round-Trip
// Requests they are embedded in results, never sent as inbound requests, so
// listing them would encode a wrong mental model.
//
// Extension methods (io.modelcontextprotocol/tasks: tasks/get, tasks/update)
// fall into "other". Add them here if an upstream ever implements the tasks
// extension — a sustained "other" count is the signal to look.
func mcpMethodLabel(m string) string {
	switch m {
	case "":
		return "absent"
	case
		// Requests.
		"server/discover",
		"tools/list",
		"tools/call",
		"resources/list",
		"resources/templates/list",
		"resources/read",
		"prompts/list",
		"prompts/get",
		"completion/complete",
		"subscriptions/listen",
		// Notification. The transport defines no client-to-server
		// notifications over Streamable HTTP in this revision, so this should
		// stay at zero here; it is listed because a client may still POST one.
		"notifications/cancelled":
		return m
	default:
		return "other"
	}
}

// mcpProtocolVersionLabel maps the MCP-Protocol-Version header to a bounded
// Prometheus label. The header is client-controlled and would otherwise be
// unbounded.
//
// "absent" is the interesting value: it is every request from a client
// predating 2026-06-18 (when the header was introduced) plus every non-MCP
// request that reaches the proxy route. Watching it fall over time is how you
// know clients have migrated.
func mcpProtocolVersionLabel(v string) string {
	switch v {
	case "":
		return "absent"
	case
		"2026-07-28",
		"2025-11-25",
		"2025-06-18",
		"2025-03-26",
		"2024-11-05":
		return v
	default:
		return "other"
	}
}

// isBase64Sentinel reports whether v is Base64-sentinel encoded per the spec's
// Value Encoding rules.
//
// Callers must NOT decode such a value before logging it. Decoding turns a
// client-controlled blob into arbitrary bytes in a log sink: injection,
// size amplification, and PII the client deliberately encoded away. The flag
// exists so an operator reading a log line knows the field is opaque rather
// than assuming truncation ate it.
func isBase64Sentinel(v string) bool {
	return strings.HasPrefix(v, base64SentinelPrefix) && strings.HasSuffix(v, "?=")
}
