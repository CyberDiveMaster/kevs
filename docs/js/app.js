const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

// Formatters below build HTML strings that Tabulator inserts directly into
// the cell, so any value coming from the (externally-sourced) KEV data must
// be escaped here rather than trusted as-is.
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

function naFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">-</span>';
  }
  return escapeHtml(v);
}

function truncateFormatter(maxLen) {
  return function (cell) {
    const v = cell.getValue();
    if (v === null || v === undefined || v === "") {
      return '<span class="na-cell">-</span>';
    }
    const str = String(v);
    return str.length <= maxLen ? escapeHtml(str) : escapeHtml(str.slice(0, maxLen)) + "…";
  };
}

// Same as truncateFormatter, but appends a small "NVD" hint (same style
// as the CVSS version hint) when the CNA's own record left this field
// "n/a"/empty and NVD's own CPE data was used instead -- see
// vendor_from_nvd/product_from_nvd in build.py.
function vendorProductFormatter(maxLen, fromNvdField) {
  return function (cell) {
    const v = cell.getValue();
    if (v === null || v === undefined || v === "") {
      return '<span class="na-cell">-</span>';
    }
    const str = String(v);
    const shown = str.length <= maxLen ? escapeHtml(str) : escapeHtml(str.slice(0, maxLen)) + "…";
    const fromNvd = cell.getRow().getData()[fromNvdField];
    const hint = fromNvd
      ? ` <span class="cvss-version-hint" title="cve.org's own record didn't provide this -- taken from NVD's CPE data instead">NVD</span>`
      : "";
    return shown + hint;
  };
}

function fullValueTooltip(e, cell) {
  return cell.getValue() || "";
}

// Date Published (cve.org) comes as a full ISO timestamp
// ("2021-12-10T00:00:00.000Z"); Active Since is already date-only, built
// from each catalog's own date-added field. Slicing both to the first 10
// chars keeps the two date columns visually consistent -- a no-op for
// values that are already just a date.
function dateFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">-</span>';
  }
  return escapeHtml(String(v).slice(0, 10));
}

function withVersionHint(cell, formattedValue) {
  const version = cell.getRow().getData().cvss_version;
  return version ? `${formattedValue} <span class="cvss-version-hint">v${escapeHtml(version)}</span>` : formattedValue;
}

function cvssScoreFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">-</span>';
  }
  return withVersionHint(cell, escapeHtml(v));
}

// EPSS score (0-1 probability) is shown as a percentage, with its
// percentile rank folded in as a small hint -- same "primary value +
// muted supplementary detail" pattern as CVSS's version hint, rather
// than a separate column, since percentile only makes sense relative to
// EPSS itself, not as an independent metric. Links to FIRST.org's own
// per-CVE API result -- there's no human-facing detail page on
// first.org for a single CVE, only this raw JSON endpoint.
// Rounds a raw 0-1 EPSS delta to a percentage-point figure at the same
// 1-decimal precision it's displayed at, and normalizes -0 to 0 -- a
// delta that's technically a tiny negative float (subtraction noise
// between two ~equal EPSS values) would otherwise round to "-0.0pp" and
// still trigger the "down" arrow/color despite showing as unchanged.
function roundPp(delta) {
  const pp = Math.round(delta * 1000) / 10;
  return pp === 0 ? 0 : pp; // Math.round can itself produce -0
}

function formatPp(pp) {
  const sign = pp > 0 ? "+" : "";
  return `${sign}${pp.toFixed(1)}pp`;
}

// Trend uses the longest of 30d/7d/1d that actually has a snapshot for
// this CVE (see fetch_epss.py) -- a fixed 30-day window would show "-"
// for most freshly-published/freshly-KEV-listed CVEs, which is exactly
// the population a trend indicator is most useful for. The other
// available windows (if any) are folded into the tooltip rather than
// shown inline, to keep the cell itself scannable.
function epssFormatter(cell) {
  const row = cell.getRow().getData();
  const v = cell.getValue();
  if (v === null || v === undefined) {
    return '<span class="na-cell">-</span>';
  }
  const pct = (v * 100).toFixed(1);

  const percentile = row.epss_percentile;
  const percentileHint = (percentile === null || percentile === undefined)
    ? ""
    : ` <span class="cvss-version-hint">${Math.round(percentile * 100)}th</span>`;

  const windowDays = row.epss_trend_window;
  const trendDelta = row.epss_trend_delta;
  let trendHint = "";
  let trendTitle = "";
  if (windowDays !== null && windowDays !== undefined && trendDelta !== null && trendDelta !== undefined) {
    const pp = roundPp(trendDelta);
    const trendClass = pp > 0 ? "epss-trend-up" : pp < 0 ? "epss-trend-down" : "";
    const arrow = pp > 0 ? "▲" : pp < 0 ? "▼" : "";
    trendHint = ` <span class="cvss-version-hint ${trendClass}">${arrow}${formatPp(pp)}/${windowDays}d</span>`;

    const otherWindows = Object.entries(row.epss_deltas || {})
      .filter(([days]) => Number(days) !== windowDays)
      .sort(([a], [b]) => Number(b) - Number(a))
      .map(([days, d]) => `${days}d: ${formatPp(roundPp(d))}`);
    trendTitle = ` -- change over ${windowDays}d: ${formatPp(pp)}` +
      (otherWindows.length ? ` (${otherWindows.join(", ")})` : "");
  }

  const cveId = row.cve_id;
  const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`;
  const title = escapeHtml(`FIRST.org EPSS data for this CVE (raw JSON)${trendTitle}`);
  return `<a href="${url}" target="_blank" rel="noopener" title="${title}">${pct}%</a>${percentileHint}${trendHint}`;
}

function epssMinFilterFunc(headerValue, rowValue) {
  if (headerValue === "" || headerValue === null || headerValue === undefined) return true;
  const min = Number(headerValue);
  if (Number.isNaN(min)) return true;
  return rowValue !== null && rowValue !== undefined && Number(rowValue) * 100 >= min;
}

function cveLinkFormatter(cell) {
  const v = cell.getValue();
  if (!v) return "";
  return `<a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(v)}" target="_blank" rel="noopener">${escapeHtml(v)}</a>`;
}

// --- Per-catalog presence columns ---
// Each cell shows a checkmark linking to that catalog's page for this CVE
// when listed, or a plain dash when not. The underlying field always holds
// the catalog's own "date added" (or null), not a bare boolean -- kept
// around so Active Since can be computed from it, and so a future column
// could show it directly if useful.

const CATALOG_URL_BUILDERS = {
  cisa_added: (row) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${encodeURIComponent(row.cve_id)}`,
  // Confirmed HTTP 200 for a real EUVD ID at development time (though the
  // page is a React SPA, so the actual rendered content wasn't verified
  // in a browser).
  enisa_added: (row) => row.enisa_id
    ? `https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(row.enisa_id)}`
    : null,
  circl_added: (row) => `https://vulnerability.circl.lu/vuln/${encodeURIComponent(row.cve_id)}`,
  kevintel_added: (row) => `https://kevintel.com/${encodeURIComponent(row.cve_id)}`,
  // Requires a (free) VulnCheck account to actually view -- there is no
  // public, unauthenticated per-CVE page for the VulnCheck community KEV.
  vulncheck_added: (row) => `https://console.vulncheck.com/cve/${encodeURIComponent(row.cve_id)}`,
};

function catalogFormatter(field) {
  const urlBuilder = CATALOG_URL_BUILDERS[field];
  return function (cell) {
    const v = cell.getValue();
    const cellEl = cell.getElement();
    if (!v) {
      cellEl.classList.remove("earliest-cell");
      return '<span class="na-cell">-</span>';
    }
    const row = cell.getRow().getData();
    // Whole-cell background fill (like spreadsheet conditional
    // formatting) when this is (one of) the earliest catalog(s) to list
    // the CVE -- i.e. it's the catalog computeActiveSince's date
    // actually came from. Recomputed live, so excluding a catalog via
    // its header x button can hand this to whichever catalog is now
    // earliest among what's left. Toggled directly on the cell element
    // (not just the returned content) so the fill covers the full cell,
    // not just the checkmark glyph.
    const isEarliest = !excludedCatalogs.has(field) && v === computeActiveSince(row);
    cellEl.classList.toggle("earliest-cell", isEarliest);
    const titleText = isEarliest ? "Earliest listing among included catalogs" : "View on this catalog";
    const url = urlBuilder(row);
    // v is already the catalog's own "date added" (YYYY-MM-DD) -- shown
    // as a small hint next to the checkmark, same style as the CVSS
    // version / EPSS percentile hints elsewhere.
    const dateHint = ` <span class="cvss-version-hint">${escapeHtml(String(v).slice(0, 10))}</span>`;
    const mark = url
      ? `<a href="${url}" target="_blank" rel="noopener" class="catalog-link" title="${escapeHtml(titleText)}">&#x2713;</a>`
      : "&#x2713;";
    return mark + dateHint;
  };
}

const CATALOG_FIELDS = Object.keys(CATALOG_URL_BUILDERS);
const CATALOG_LABELS = {
  cisa_added: "CISA", enisa_added: "ENISA", circl_added: "CIRCL",
  kevintel_added: "KEVIntel", vulncheck_added: "VulnCheck",
};

// Each catalog's own top-level page (not a per-CVE deep link, which is
// what the checkmark cells already link to -- this is just "what is
// this catalog").
const CATALOG_HOME_URLS = {
  cisa_added: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  enisa_added: "https://euvd.enisa.europa.eu/",
  circl_added: "https://vulnerability.circl.lu/known-exploited-vulnerabilities-catalog/",
  kevintel_added: "https://kevintel.com/feed",
  vulncheck_added: "https://console.vulncheck.com/browse/kev",
};

// Explains what "Yes" in this column actually scopes to -- shown on the
// column header (via catalogTitleFormatter), not per-cell, since it's a
// property of the whole column rather than any individual CVE.
const CATALOG_SCOPE_NOTES = {
  enisa_added: "Column shows ENISA's own EU-specific findings only -- excludes CVEs ENISA's EUVD simply mirrors from CISA KEV.",
  circl_added: "Column shows CIRCL's own original curation only -- excludes CVEs CIRCL mirrors from CISA, KEVIntel, ENISA, or Shadowserver.",
  vulncheck_added: "Requires a free VulnCheck account to view.",
};

// --- "Exclude this catalog from the union" -- a small x button in each
// catalog column's header. Excluding a catalog hides its column AND
// drops any row that ONLY qualified for the table through that catalog
// (i.e. isn't Yes in any of the still-active catalogs), since the whole
// table is built as "listed in at least one of these 5". Excluded
// catalogs stay recoverable via a chip in the toolbar rather than being
// gone for good -- there's no other way back once a column is hidden.
const excludedCatalogs = new Set();
const excludedCatalogsEl = document.getElementById("excluded-catalogs");

function renderExcludedChips() {
  excludedCatalogsEl.innerHTML = "";
  if (excludedCatalogs.size === 0) return;
  const label = document.createElement("span");
  label.classList.add("excluded-label");
  label.textContent = "Excluded:";
  excludedCatalogsEl.appendChild(label);
  for (const field of CATALOG_FIELDS) {
    if (!excludedCatalogs.has(field)) continue;
    const chip = document.createElement("button");
    chip.type = "button";
    chip.classList.add("excluded-chip");
    chip.textContent = `${CATALOG_LABELS[field]} ×`;
    chip.title = `Restore ${CATALOG_LABELS[field]}`;
    chip.addEventListener("click", () => restoreCatalog(field));
    excludedCatalogsEl.appendChild(chip);
  }
}

function excludeCatalog(field) {
  excludedCatalogs.add(field);
  const column = table.getColumn(field);
  if (column) column.hide();
  table.refreshFilter();
  table.redraw(true); // re-run formatters -- Active Since depends on excludedCatalogs, not just row data
  renderExcludedChips();
}

function restoreCatalog(field) {
  excludedCatalogs.delete(field);
  const column = table.getColumn(field);
  if (column) column.show();
  table.refreshFilter();
  table.redraw(true);
  renderExcludedChips();
}

// A row qualifies as long as it's Yes in at least one catalog that
// hasn't been excluded. Runs alongside (ANDed with) the normal header
// filters via table.addFilter -- see near table construction below.
function catalogUnionFilter(rowData) {
  return CATALOG_FIELDS.some((field) => !excludedCatalogs.has(field) && rowData[field]);
}

// Plain link-only column header (no exclude button, unlike
// catalogTitleFormatter) -- just the title text itself linking out to a
// reference page.
function linkTitleFormatter(label, url) {
  return function () {
    const link = document.createElement("a");
    link.classList.add("header-link");
    link.href = url;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = label;
    link.title = `About ${label}`;
    link.addEventListener("click", (e) => e.stopPropagation());
    return link;
  };
}

function catalogTitleFormatter(field) {
  const label = CATALOG_LABELS[field];
  const homeUrl = CATALOG_HOME_URLS[field];
  const scopeNote = CATALOG_SCOPE_NOTES[field];
  return function () {
    const wrapper = document.createElement("span");
    wrapper.classList.add("catalog-header-title");

    const text = document.createElement("a");
    text.href = homeUrl;
    text.target = "_blank";
    text.rel = "noopener";
    text.textContent = label;
    text.title = scopeNote ? `Open ${label}'s KEV catalog. ${scopeNote}` : `Open ${label}'s KEV catalog`;
    // Stops the click from also reaching Tabulator's own header-click
    // (sort) listener -- the link still navigates normally, this only
    // blocks the click from bubbling up to that ancestor listener.
    text.addEventListener("click", (e) => e.stopPropagation());

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.classList.add("catalog-hide-btn");
    closeBtn.textContent = "×";
    closeBtn.title = `Exclude ${label} from the table`;
    // Stops the click from also reaching Tabulator's own header-click
    // (sort) listener, which is attached higher up the same DOM chain.
    closeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      excludeCatalog(field);
    });

    wrapper.appendChild(text);
    wrapper.appendChild(closeBtn);
    return wrapper;
  };
}

function presenceFilterFunc(headerValue, rowValue) {
  if (!headerValue || headerValue.length === 0) return true;
  const state = rowValue ? "yes" : "no";
  return headerValue.includes(state);
}

function presenceEmptyCheck(value) {
  return !value || value.length === 0;
}

// --- Multi-select checkbox-dropdown header filter (Yes/No, or any small
// fixed vocabulary) -- a native <select multiple> would technically work
// but requires a non-obvious ctrl/cmd-click gesture to pick more than one
// option, so this builds a small custom popup instead.

const multiSelectPanels = [];

document.addEventListener("click", (e) => {
  for (const { container, panel } of multiSelectPanels) {
    if (!container.contains(e.target)) panel.hidden = true;
  }
});

function multiSelectHeaderFilter(valuesMap) {
  return function (cell, onRendered, success) {
    const container = document.createElement("span");
    container.classList.add("multiselect-filter");

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.classList.add("multiselect-trigger");
    trigger.textContent = "(All)";

    const panel = document.createElement("div");
    panel.classList.add("multiselect-panel");
    panel.hidden = true;
    multiSelectPanels.push({ container, panel });

    const selected = new Set();

    function refreshTrigger() {
      if (selected.size === 0) {
        trigger.textContent = "(All)";
        return;
      }
      const labels = Object.entries(valuesMap)
        .filter(([value]) => selected.has(value))
        .map(([, label]) => label);
      trigger.textContent = labels.join(", ");
      trigger.title = labels.join(", ");
    }

    for (const [value, label] of Object.entries(valuesMap)) {
      const row = document.createElement("label");
      row.classList.add("multiselect-option");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = value;
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          selected.add(value);
        } else {
          selected.delete(value);
        }
        refreshTrigger();
        success(selected.size ? Array.from(selected) : "");
      });
      const labelSpan = document.createElement("span");
      labelSpan.textContent = " " + label;
      row.appendChild(checkbox);
      row.appendChild(labelSpan);
      panel.appendChild(row);
    }

    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      const opening = panel.hidden;

      for (const other of multiSelectPanels) {
        if (other.panel !== panel) other.panel.hidden = true;
      }

      if (opening) {
        // .multiselect-panel is "position: fixed", but Tabulator applies its
        // own CSS transform to the root .tabulator element (a no-op
        // identity matrix, but a transform nonetheless) -- per spec, ANY
        // transform value on an ancestor makes IT the containing block for
        // fixed-position descendants instead of the viewport. So position
        // relative to that element's rect, not the raw viewport-relative
        // getBoundingClientRect() values.
        const tableRect = document.querySelector(".tabulator").getBoundingClientRect();
        const rect = trigger.getBoundingClientRect();
        panel.style.top = `${rect.bottom - tableRect.top}px`;
        panel.style.left = `${rect.left - tableRect.left}px`;
      }
      panel.hidden = !opening;
    });

    container.appendChild(trigger);
    container.appendChild(panel);
    return container;
  };
}

// Pipe-delimited OR substring match, e.g. "forti|palo|sonic" matches any
// row whose value contains at least one of the segments (case-insensitive,
// each segment still a partial/substring match -- same as Tabulator's own
// default "like" behavior, just OR'd across multiple terms).
function pipeOrFilterFunc(headerValue, rowValue) {
  if (!headerValue) return true;
  const needles = String(headerValue).split("|").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (needles.length === 0) return true;
  const haystack = String(rowValue || "").toLowerCase();
  return needles.some((n) => haystack.includes(n));
}

function minScoreFilterFunc(headerValue, rowValue) {
  if (headerValue === "" || headerValue === null || headerValue === undefined) return true;
  const min = Number(headerValue);
  if (Number.isNaN(min)) return true;
  return rowValue !== null && rowValue !== undefined && Number(rowValue) >= min;
}

// --- Date range header filter, shared by Date Published / Active Since ---
// A single readonly text input backed by a Flatpickr range-mode calendar --
// click a start day then an end day, no typing.

function formatDateLocal(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function dateRangeHeaderFilter(cell, onRendered, success) {
  const container = document.createElement("span");
  container.classList.add("range-filter");

  const input = document.createElement("input");
  input.type = "text";
  input.readOnly = true;
  input.placeholder = "Select range...";

  const clearBtn = document.createElement("button");
  clearBtn.type = "button";
  clearBtn.textContent = "×";
  clearBtn.title = "Clear";
  clearBtn.classList.add("range-clear");

  container.appendChild(input);
  container.appendChild(clearBtn);

  onRendered(() => {
    const fp = flatpickr(input, {
      mode: "range",
      dateFormat: "Y-m-d",
      onClose: (selectedDates) => {
        const [from, to] = selectedDates;
        success({
          from: from ? formatDateLocal(from) : "",
          to: to ? formatDateLocal(to) : "",
        });
      },
    });
    clearBtn.addEventListener("click", () => {
      fp.clear();
      success({ from: "", to: "" });
    });
  });

  return container;
}

function dateRangeFilterFunc(headerValue, rowValue) {
  if (!headerValue || (!headerValue.from && !headerValue.to)) return true;
  if (!rowValue) return false;
  const rowDate = String(rowValue).slice(0, 10);
  if (headerValue.from && rowDate < headerValue.from) return false;
  if (headerValue.to && rowDate > headerValue.to) return false;
  return true;
}

function dateRangeEmptyCheck(value) {
  return !value || (!value.from && !value.to);
}

// --- Active Since, recomputed live from whichever catalogs are still
// active --- the stored active_since field is only the INITIAL value (min
// date-added across all 5 catalogs at build time); once a catalog is
// excluded via its header x button, this recomputes the min across the
// remaining ones instead, so the column stays consistent with what's
// still driving each row's presence in the table.
function computeActiveSince(rowData) {
  const dates = CATALOG_FIELDS
    .filter((field) => !excludedCatalogs.has(field) && rowData[field])
    .map((field) => rowData[field]);
  return dates.length ? dates.reduce((min, d) => (d < min ? d : min)) : null;
}

function activeSinceFormatter(cell) {
  const v = computeActiveSince(cell.getRow().getData());
  if (!v) return '<span class="na-cell">-</span>';
  return escapeHtml(String(v).slice(0, 10));
}

// Empty (no remaining catalog dates) rows sort to the bottom regardless
// of direction, matching alignEmptyValues:"bottom" semantics for the
// built-in string sorter -- needed here because the compared value isn't
// the raw field, so the built-in sorter can't be used directly.
function activeSinceSorter(a, b, aRow, bRow, column, dir) {
  const av = computeActiveSince(aRow.getData());
  const bv = computeActiveSince(bRow.getData());
  const aEmpty = !av, bEmpty = !bv;
  if (aEmpty && bEmpty) return 0;
  if (aEmpty) return dir === "asc" ? 1 : -1;
  if (bEmpty) return dir === "asc" ? -1 : 1;
  return av < bv ? -1 : av > bv ? 1 : 0;
}

function activeSinceFilterFunc(headerValue, rowValue, rowData) {
  return dateRangeFilterFunc(headerValue, computeActiveSince(rowData));
}

const CVSS_VERSION_TOOLTIP =
  "Shows the highest CVSS version available for that CVE (v4.0 > v3.1 > v3.0 > v2.0), " +
  "from the CNA record or CISA's ADP enrichment.";

const columns = [
  { title: "CVE ID", field: "cve_id", headerFilter: "input", formatter: cveLinkFormatter, frozen: true },
  {
    title: "Date Published", field: "date_published", width: 140, sorter: "string",
    sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: dateRangeFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: dateFormatter,
  },
  {
    title: "First Listed", field: "active_since", width: 140, sorter: activeSinceSorter,
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: activeSinceFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: activeSinceFormatter,
    tooltip: () => "Earliest date this CVE was added to any catalog still included in the table -- excluding a catalog via its x button recalculates this",
  },
  {
    title: "CVSS Score", field: "cvss_score", sorter: "number",
    sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: "input", headerFilterFunc: minScoreFilterFunc,
    headerFilterPlaceholder: "Min score", formatter: cvssScoreFormatter,
  },
  {
    title: "EPSS", field: "epss", sorter: "number",
    titleFormatter: linkTitleFormatter("EPSS", "https://www.first.org/epss/"),
    sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: "input", headerFilterFunc: epssMinFilterFunc,
    headerFilterPlaceholder: "Min %", formatter: epssFormatter,
    tooltip: () => "FIRST.org EPSS: predicted probability of exploitation in the next 30 days, plus percentile rank among all scored CVEs. Updated daily.",
  },
  {
    title: "CISA", field: "cisa_added", width: 125, hozAlign: "center", sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    titleFormatter: catalogTitleFormatter("cisa_added"),
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("cisa_added"),
  },
  {
    title: "ENISA", field: "enisa_added", width: 125, hozAlign: "center", sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    titleFormatter: catalogTitleFormatter("enisa_added"),
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("enisa_added"),
  },
  {
    title: "CIRCL", field: "circl_added", width: 125, hozAlign: "center", sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    titleFormatter: catalogTitleFormatter("circl_added"),
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("circl_added"),
  },
  {
    title: "KEVIntel", field: "kevintel_added", width: 125, hozAlign: "center", sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    titleFormatter: catalogTitleFormatter("kevintel_added"),
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("kevintel_added"),
  },
  {
    title: "VulnCheck", field: "vulncheck_added", width: 125, hozAlign: "center", sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    titleFormatter: catalogTitleFormatter("vulncheck_added"),
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("vulncheck_added"),
  },
  {
    title: "Vendor", field: "vendor", headerFilter: "input",
    headerFilterFunc: pipeOrFilterFunc, headerFilterPlaceholder: "e.g. forti|palo|sonic",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: vendorProductFormatter(50, "vendor_from_nvd"), tooltip: fullValueTooltip,
  },
  {
    title: "Product", field: "product", headerFilter: "input",
    headerFilterFunc: pipeOrFilterFunc, headerFilterPlaceholder: "e.g. fortios|pan-os|sonicos",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: vendorProductFormatter(50, "product_from_nvd"), tooltip: fullValueTooltip,
  },
];

const table = new Tabulator("#kev-table", {
  layout: "fitDataStretch",
  height: "75vh",
  columns,
  placeholder: "No data",
  columnDefaults: { headerFilterLiveFilter: true },
  initialSort: [{ column: "active_since", dir: "desc" }],
});

table.on("tableBuilt", () => {
  const titleEl = table.getColumn("cvss_score").getElement().querySelector(".tabulator-col-title");
  if (titleEl) titleEl.title = CVSS_VERSION_TOOLTIP;

  // "No data" (the placeholder set above) is meant for a genuinely empty
  // result -- e.g. filters that match nothing -- not for "hasn't loaded
  // yet", which looks identical and reads as the site being broken.
  // table.alert() is a separate overlay that can cover that first-load
  // window without touching the placeholder's own meaning. Cleared once
  // setData succeeds (or replaced with an error message on failure) below.
  table.alert("Loading data…");
});

// Runs ANDed with all header filters. A no-op while excludedCatalogs is
// empty (every row is Yes in at least one catalog, by construction of
// the dataset itself), so this is safe to leave permanently attached.
table.addFilter(catalogUnionFilter);

let totalRowCount = 0;
const filterCountEl = document.getElementById("filter-count");

table.on("dataFiltered", (filters, rows) => {
  filterCountEl.textContent = rows.length === totalRowCount
    ? `${totalRowCount.toLocaleString()} rows`
    : `${rows.length.toLocaleString()} / ${totalRowCount.toLocaleString()} rows match`;
});

// No row cap here -- unlike Vulnrichment Viewer (~162k rows, where a cap
// guards against accidentally exporting a huge file), this dataset is
// the union of 5 KEV catalogs, only ~5,000-6,000 rows total, so even a
// fully unfiltered export is a small, fast CSV.
const exportStatus = document.getElementById("export-status");

document.getElementById("export-csv").addEventListener("click", () => {
  exportStatus.textContent = "";
  exportStatus.classList.remove("error");
  table.download("csv", "kevs-export.csv");
});

// "no-cache" (not "no-store") -- forces a revalidation request every load
// rather than trusting GitHub Pages' CDN cache headers blindly, but still
// lets the server return a cheap 304 when the data hasn't changed.
fetch("data/meta.json", { cache: "no-cache" })
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  })
  .then((meta) => {
    // build.py now writes generated_at without a fractional-seconds
    // component, but this strips one anyway in case an older meta.json
    // (from before that fix) is still live.
    const generatedAt = meta.generated_at.replace(/\.\d+(?=(Z|[+-]\d{2}:?\d{2})?$)/, "");
    document.getElementById("status").textContent =
      `${meta.cve_count.toLocaleString()} CVEs / last updated: ${generatedAt}`;
    totalRowCount = meta.cve_count;
    return fetch("data/kevs.json", { cache: "no-cache" });
  })
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  })
  .then((rows) => {
    table.setData(rows);
    table.clearAlert();
  })
  .catch((err) => {
    document.getElementById("status").textContent = `Failed to load data: ${err.message}`;
    table.alert(`Failed to load data: ${escapeHtml(err.message)}`, "error");
  });
