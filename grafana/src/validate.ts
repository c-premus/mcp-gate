/**
 * Structural validation of the generated dashboard.
 *
 * Every rule here corresponds to a rendering fault that shipped to production
 * and that nothing else caught: the dashboard JSON was valid, Grafana loaded it
 * without complaint, and the panels simply drew nothing. CI already regenerates
 * the JSON and fails on a diff, which catches drift between source and output —
 * it cannot catch source that is wrong in the first place. These rules can.
 *
 * `generate.ts` runs this before writing, so a violation is a build failure.
 * `npm run validate` runs it against the committed file.
 */

/** Grafana's dashboard grid is 24 columns wide. */
const GRID_WIDTH = 24;

/**
 * Panel types that reduce a series to a single value and therefore need a
 * non-empty `options.reduceOptions.calcs`. With an empty `calcs` array Grafana
 * applies no reduction and renders no value — see panels/defaults.ts.
 */
const REDUCING_TYPES = new Set(["stat", "gauge", "bargauge", "piechart"]);

/**
 * Panel types that must declare a unit. Not a rendering fault on its own, but
 * the same class of omission: a `fieldConfig.defaults` built with only a subset
 * of its fields. Use `short` for bare counts.
 */
const UNIT_REQUIRED_TYPES = new Set([
  "stat",
  "gauge",
  "bargauge",
  "piechart",
  "timeseries",
]);

interface GridPos {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface Panel {
  type?: string;
  title?: string;
  gridPos?: GridPos;
  options?: Record<string, unknown> | null;
  fieldConfig?: { defaults?: Record<string, unknown> } | null;
  panels?: Panel[];
}

interface Dashboard {
  panels?: Panel[];
}

/** Every panel, flattened — nested panels of collapsed rows included. */
function allPanels(dashboard: Dashboard): Panel[] {
  const out: Panel[] = [];
  for (const panel of dashboard.panels ?? []) {
    out.push(panel);
    for (const nested of panel.panels ?? []) {
      out.push(nested);
    }
  }
  return out;
}

function label(panel: Panel): string {
  return `${panel.type ?? "?"} "${panel.title ?? "(untitled)"}"`;
}

function boxesOverlap(a: GridPos, b: GridPos): boolean {
  return (
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h
  );
}

/**
 * Returns one message per violation; an empty array means the dashboard is
 * sound.
 *
 * Takes `unknown` because it runs against two shapes that are structurally the
 * same but nominally different: the SDK's `Dashboard` type as freshly built by
 * `generate.ts`, and the plain result of `JSON.parse` on the committed file.
 * The rules are deliberately structural — they check what Grafana will
 * actually read, not what the SDK's types promise.
 */
export function validateDashboard(dashboard: unknown): string[] {
  const errors: string[] = [];
  const panels = allPanels(dashboard as Dashboard);

  for (const panel of panels) {
    const name = label(panel);
    const type = panel.type ?? "";

    // Rows are separators: no options, no field config, full-width by
    // construction. Skip every content rule for them.
    if (type === "row") {
      continue;
    }

    // An options object that was never materialised. The SDK builds `options`
    // lazily, so a panel whose builder chain touches no option setter emits
    // null and Grafana has nothing to render from.
    if (panel.options === null || panel.options === undefined) {
      errors.push(
        `${name}: options is null — the panel was built without touching any option setter; use a factory from panels/defaults.ts`
      );
    }

    if (REDUCING_TYPES.has(type)) {
      const reduce = panel.options?.["reduceOptions"] as
        | { calcs?: unknown }
        | undefined;
      const calcs = reduce?.calcs;
      if (!Array.isArray(calcs) || calcs.length === 0) {
        errors.push(
          `${name}: options.reduceOptions.calcs is empty or missing — an empty reducer list renders no value (this is NOT the same as omitting the field, which would default to lastNotNull)`
        );
      }
    }

    // Every query on this dashboard is split `by (service)` so that several
    // gates can be displayed at once. A hidden legend makes the resulting
    // series indistinguishable, which defeats the split.
    if (type === "timeseries" || type === "piechart") {
      const legend = panel.options?.["legend"] as
        | { showLegend?: unknown }
        | undefined;
      if (legend?.showLegend !== true) {
        errors.push(
          `${name}: options.legend.showLegend is not true — panels are split by (service), so a hidden legend leaves no way to tell the gates apart`
        );
      }
    }

    if (UNIT_REQUIRED_TYPES.has(type)) {
      const unit = panel.fieldConfig?.defaults?.["unit"];
      if (typeof unit !== "string" || unit === "") {
        errors.push(
          `${name}: fieldConfig.defaults.unit is missing — set one ("short" for a bare count)`
        );
      }
    }
  }

  // Layout. The SDK's auto-layout advances an x cursor and only wraps *after*
  // placing a panel, when the cursor has reached 24 — so a panel that does not
  // fit in the columns remaining is placed anyway and overflows the grid.
  // Grafana then reflows the whole row. Widths have to tile evenly; this rule
  // is what says so out loud.
  const positioned = panels.filter((p) => p.gridPos);
  for (const panel of positioned) {
    const { x, y, w, h } = panel.gridPos as GridPos;
    if (x < 0 || y < 0 || w < 1 || h < 1) {
      errors.push(
        `${label(panel)}: nonsensical gridPos {x:${x}, y:${y}, w:${w}, h:${h}}`
      );
      continue;
    }
    if (x + w > GRID_WIDTH) {
      errors.push(
        `${label(panel)}: gridPos overflows the ${GRID_WIDTH}-column grid (x=${x} + w=${w} = ${x + w}); Grafana will reflow the row. Adjust the spans in that section so they tile evenly.`
      );
    }
  }
  for (const panel of panels.filter((p) => !p.gridPos)) {
    errors.push(`${label(panel)}: no gridPos`);
  }

  for (let i = 0; i < positioned.length; i++) {
    for (let j = i + 1; j < positioned.length; j++) {
      const a = positioned[i]!;
      const b = positioned[j]!;
      if (boxesOverlap(a.gridPos as GridPos, b.gridPos as GridPos)) {
        errors.push(
          `${label(a)} and ${label(b)} occupy overlapping grid boxes`
        );
      }
    }
  }

  return errors;
}

/** Throws with every violation listed, or returns quietly. */
export function assertValidDashboard(dashboard: unknown): void {
  const errors = validateDashboard(dashboard);
  if (errors.length > 0) {
    throw new Error(
      `dashboard validation failed (${errors.length} problem${errors.length === 1 ? "" : "s"}):\n` +
        errors.map((e) => `  - ${e}`).join("\n")
    );
  }
}
