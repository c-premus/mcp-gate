import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { DataqueryBuilder as PrometheusQuery } from "@grafana/grafana-foundation-sdk/prometheus";
import {
  RowBuilder,
  ThresholdsConfigBuilder,
} from "@grafana/grafana-foundation-sdk/dashboard";
import { ThresholdsMode } from "@grafana/grafana-foundation-sdk/dashboard";
import {
  BigValueColorMode,
  VizTooltipOptionsBuilder,
  TooltipDisplayMode,
  SortOrder,
} from "@grafana/grafana-foundation-sdk/common";
import { PROMETHEUS, SELECTOR } from "./constants";

// Go runtime metrics are per-process, so each gate contributes its own series
// with no aggregation needed. Legends are `{{service}}`-prefixed because these
// numbers are only meaningful attributed to a specific process — a pooled
// goroutine count or RSS across two unrelated gates describes nothing.

function goroutinesStat(): StatPanel {
  return new StatPanel()
    .title("Goroutines")
    .description("Current goroutine count, per gate. Sustained growth suggests a goroutine leak.")
    .datasource(PROMETHEUS)
    .noValue("0")
    .decimals(0)
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 1000, color: "yellow" },
          { value: 5000, color: "red" },
        ])
    )
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`go_goroutines{${SELECTOR}}`)
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function fdUtilStat(): StatPanel {
  return new StatPanel()
    .title("FD Utilization")
    .description("Open file descriptors as fraction of process_max_fds, per gate. Approaches 1.0 = FD exhaustion imminent.")
    .datasource(PROMETHEUS)
    .unit("percentunit")
    .noValue("0")
    .decimals(2)
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 0.5, color: "yellow" },
          { value: 0.8, color: "red" },
        ])
    )
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `process_open_fds{${SELECTOR}} / process_max_fds{${SELECTOR}}`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function residentMemoryStat(): StatPanel {
  return new StatPanel()
    .title("Resident Memory")
    .description("process_resident_memory_bytes, per gate. Sustained growth without plateau suggests a memory leak.")
    .datasource(PROMETHEUS)
    .unit("bytes")
    .noValue("0")
    .colorMode(BigValueColorMode.Value)
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(`process_resident_memory_bytes{${SELECTOR}}`)
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function gcPauseStat(): StatPanel {
  return new StatPanel()
    .title("GC Pause (rate)")
    .description("Sum of GC pause durations per second, per gate. High values indicate GC pressure.")
    .datasource(PROMETHEUS)
    .unit("s")
    .noValue("0")
    .decimals(3)
    .colorMode(BigValueColorMode.Value)
    .thresholds(
      new ThresholdsConfigBuilder()
        .mode(ThresholdsMode.Absolute)
        .steps([
          { value: null as unknown as number, color: "green" },
          { value: 0.05, color: "yellow" },
          { value: 0.1, color: "red" },
        ])
    )
    .span(6)
    .height(5)
    .withTarget(
      new PrometheusQuery()
        .expr(
          `rate(go_gc_duration_seconds_sum{${SELECTOR}}[$__rate_interval])`
        )
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function goroutinesTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Goroutines Over Time")
    .description("Goroutine count over time, per gate — stable baseline + spikes during bursts is healthy; monotonic growth is a leak.")
    .datasource(PROMETHEUS)
    .tooltip(
      new VizTooltipOptionsBuilder()
        .mode(TooltipDisplayMode.Multi)
        .sort(SortOrder.Descending)
    )
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(`go_goroutines{${SELECTOR}}`)
        .legendFormat("{{service}}")
        .refId("A")
    );
}

function memoryTimeseries(): TimeseriesPanel {
  return new TimeseriesPanel()
    .title("Memory")
    .description("Resident set size vs Go heap allocations, per gate. RSS growth without heap growth suggests CGO/stack leaks.")
    .datasource(PROMETHEUS)
    .unit("bytes")
    .tooltip(
      new VizTooltipOptionsBuilder()
        .mode(TooltipDisplayMode.Multi)
        .sort(SortOrder.Descending)
    )
    .span(12)
    .height(8)
    .withTarget(
      new PrometheusQuery()
        .expr(`process_resident_memory_bytes{${SELECTOR}}`)
        .legendFormat("{{service}} rss")
        .refId("A")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(`go_memstats_heap_alloc_bytes{${SELECTOR}}`)
        .legendFormat("{{service}} heap alloc")
        .refId("B")
    )
    .withTarget(
      new PrometheusQuery()
        .expr(`go_memstats_heap_inuse_bytes{${SELECTOR}}`)
        .legendFormat("{{service}} heap in-use")
        .refId("C")
    );
}

export function runtimeRow(): RowBuilder {
  return new RowBuilder("Runtime")
    .collapsed(true)
    .withPanel(goroutinesStat())
    .withPanel(fdUtilStat())
    .withPanel(residentMemoryStat())
    .withPanel(gcPauseStat())
    .withPanel(goroutinesTimeseries())
    .withPanel(memoryTimeseries());
}
