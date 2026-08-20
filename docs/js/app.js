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
    if (!v) return '<span class="na-cell">-</span>';
    const row = cell.getRow().getData();
    const url = urlBuilder(row);
    if (!url) return "&#x2713;";
    return `<a href="${url}" target="_blank" rel="noopener" class="catalog-link" title="View on this catalog">&#x2713;</a>`;
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
    title: "Active Since", field: "active_since", width: 140, sorter: "string",
    sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: dateRangeFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: dateFormatter,
    tooltip: () => "Earliest date this CVE was added to any of the 5 catalogs",
  },
  {
    title: "CVSS Score", field: "cvss_score", sorter: "number",
    sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: "input", headerFilterFunc: minScoreFilterFunc,
    headerFilterPlaceholder: "Min score", formatter: cvssScoreFormatter,
  },
  {
    title: "CISA", field: "cisa_added", width: 100, hozAlign: "center",
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("cisa_added"),
  },
  {
    title: "ENISA", field: "enisa_added", width: 100, hozAlign: "center",
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("enisa_added"),
    tooltip: () => "ENISA's own EU-specific findings only -- excludes CVEs ENISA's EUVD simply mirrors from CISA KEV",
  },
  {
    title: "CIRCL", field: "circl_added", width: 100, hozAlign: "center",
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("circl_added"),
    tooltip: () => "CIRCL's own original curation only -- excludes CVEs CIRCL mirrors from CISA, KEVIntel, ENISA, or Shadowserver",
  },
  {
    title: "KEVIntel", field: "kevintel_added", width: 100, hozAlign: "center",
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("kevintel_added"),
  },
  {
    title: "VulnCheck", field: "vulncheck_added", width: 100, hozAlign: "center",
    headerFilter: multiSelectHeaderFilter({ yes: "Yes", no: "No" }),
    headerFilterFunc: presenceFilterFunc, headerFilterEmptyCheck: presenceEmptyCheck,
    formatter: catalogFormatter("vulncheck_added"),
    tooltip: () => "Requires a free VulnCheck account to view",
  },
  {
    title: "Vendor", field: "vendor", headerFilter: "input",
    headerFilterFunc: pipeOrFilterFunc, headerFilterPlaceholder: "e.g. forti|palo|sonic",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: truncateFormatter(50), tooltip: fullValueTooltip,
  },
  {
    title: "Product", field: "product", headerFilter: "input",
    headerFilterFunc: pipeOrFilterFunc, headerFilterPlaceholder: "e.g. fortios|pan-os|sonicos",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: truncateFormatter(50), tooltip: fullValueTooltip,
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
});

let totalRowCount = 0;
const filterCountEl = document.getElementById("filter-count");

table.on("dataFiltered", (filters, rows) => {
  filterCountEl.textContent = rows.length === totalRowCount
    ? `${totalRowCount.toLocaleString()} rows`
    : `${rows.length.toLocaleString()} / ${totalRowCount.toLocaleString()} rows match`;
});

// Guard rail, not a hard technical limit -- keeps exports to something a
// spreadsheet-review workflow can realistically use.
const MAX_CSV_EXPORT_ROWS = 5000;

const exportStatus = document.getElementById("export-status");

document.getElementById("export-csv").addEventListener("click", () => {
  const filteredCount = table.getDataCount("active");

  if (filteredCount > MAX_CSV_EXPORT_ROWS) {
    exportStatus.textContent =
      `${filteredCount.toLocaleString()} rows match -- narrow filters to ${MAX_CSV_EXPORT_ROWS.toLocaleString()} or fewer to export.`;
    exportStatus.classList.add("error");
    return;
  }

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
    document.getElementById("status").textContent =
      `${meta.cve_count.toLocaleString()} CVEs / last updated: ${meta.generated_at}`;
    totalRowCount = meta.cve_count;
    return fetch("data/kevs.json", { cache: "no-cache" });
  })
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  })
  .then((rows) => {
    table.setData(rows);
  })
  .catch((err) => {
    document.getElementById("status").textContent = `Failed to load data: ${err.message}`;
  });
