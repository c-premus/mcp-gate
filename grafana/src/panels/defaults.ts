import { PanelBuilder as StatPanel } from "@grafana/grafana-foundation-sdk/stat";
import { PanelBuilder as TimeseriesPanel } from "@grafana/grafana-foundation-sdk/timeseries";
import { PanelBuilder as TablePanel } from "@grafana/grafana-foundation-sdk/table";
import {
  PanelBuilder as PiechartPanel,
  PieChartLegendOptionsBuilder,
  PieChartLabels,
  PieChartLegendValues,
  PieChartType,
} from "@grafana/grafana-foundation-sdk/piechart";
import {
  LegendDisplayMode,
  LegendPlacement,
  ReduceDataOptionsBuilder,
  SortOrder,
  TableCellHeight,
  TooltipDisplayMode,
  VizLegendOptionsBuilder,
  VizTooltipOptionsBuilder,
} from "@grafana/grafana-foundation-sdk/common";

/**
 * Panel factories. Build every panel through these, never through the SDK's
 * `new PanelBuilder()` directly.
 *
 * The Grafana Foundation SDK creates a panel's `options` object lazily — it
 * does not exist until some option setter touches it, and when it is created
 * it is seeded from that panel type's `defaultOptions()`. Several of those
 * seeds leave a required field *explicitly empty* rather than absent, and
 * Grafana does not treat empty and absent alike: an absent field falls back to
 * a sensible default, an empty one is honoured as "the operator asked for
 * nothing". Three instances of that shipped broken to production:
 *
 *   - `reduceOptions.calcs: []` is the seed for every stat and piechart. An
 *     empty reducer list applies no reduction, so the tile renders no value at
 *     all; omitting the field entirely would have defaulted to `lastNotNull`.
 *     All 16 stat tiles on this dashboard were blank.
 *   - A piechart that never calls an option setter never materialises
 *     `options` at all, so it emits `options: null` — no `reduceOptions`, no
 *     legend, nothing. Both piecharts rendered empty.
 *   - `legend.showLegend: false` is the timeseries seed. That is survivable on
 *     a single-series panel, but every query on this dashboard is split
 *     `by (service)` to support several gates, so a hidden legend leaves no
 *     way to tell which line is which gate.
 *
 * The factories below set each of those explicitly. `validate.ts` enforces the
 * resulting invariants over the generated JSON and `npm run generate` fails if
 * any is violated, so the next panel added through a bare SDK builder is a
 * build error rather than a blank tile someone notices months later.
 */

/**
 * Reducer for every single-value panel.
 *
 * `lastNotNull` is right for both shapes on this dashboard: the current-value
 * gauges (Request Rate, JWKS Keys Loaded, Goroutines, …), and the two tiles
 * that run an `instant` range-wide query (`increase(...[$__range])`, which
 * returns exactly one point per series, so "last" is that point).
 */
export const REDUCER = "lastNotNull";

function reduceOptions(): ReduceDataOptionsBuilder {
  return new ReduceDataOptionsBuilder()
    .calcs([REDUCER])
    .fields("")
    .values(false);
}

/**
 * Standard legend. `showLegend(true)` is the whole point — see the file
 * comment. `displayMode`/`calcs` are parameterised for the one panel that
 * wants a table legend with per-series statistics.
 */
export function legend(
  displayMode: LegendDisplayMode = LegendDisplayMode.List,
  calcs: string[] = []
): VizLegendOptionsBuilder {
  return new VizLegendOptionsBuilder()
    .showLegend(true)
    .displayMode(displayMode)
    .placement(LegendPlacement.Bottom)
    .calcs(calcs);
}

/** Standard tooltip: all series at the cursor, largest first. */
export function tooltip(): VizTooltipOptionsBuilder {
  return new VizTooltipOptionsBuilder()
    .mode(TooltipDisplayMode.Multi)
    .sort(SortOrder.Descending);
}

/** Stat panel with an explicit reducer. */
export function statPanel(): StatPanel {
  return new StatPanel().reduceOptions(reduceOptions());
}

/** Timeseries panel with a visible legend and the standard tooltip. */
export function timeseriesPanel(): TimeseriesPanel {
  return new TimeseriesPanel().legend(legend()).tooltip(tooltip());
}

/**
 * Piechart with a fully populated options block.
 *
 * A bare `new PanelBuilder()` here emits `options: null`, which is why both
 * piecharts rendered empty. The legend sits on the right rather than the
 * bottom because a per-gate breakdown produces roughly twice as many entries
 * as a single-gate one.
 */
export function piechartPanel(): PiechartPanel {
  return new PiechartPanel()
    .reduceOptions(reduceOptions())
    .pieType(PieChartType.Pie)
    .displayLabels([PieChartLabels.Percent])
    .legend(
      new PieChartLegendOptionsBuilder()
        .showLegend(true)
        .displayMode(LegendDisplayMode.List)
        .placement(LegendPlacement.Right)
        .values([PieChartLegendValues.Percent])
    )
    .tooltip(tooltip());
}

/**
 * Table with a fully populated options block — same `options: null` hazard as
 * the piechart, since none of the table's own option setters were being called.
 */
export function tablePanel(): TablePanel {
  return new TablePanel().showHeader(true).cellHeight(TableCellHeight.Sm);
}
