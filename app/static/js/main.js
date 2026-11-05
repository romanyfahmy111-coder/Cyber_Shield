/* PhishLens front-end.
 * All dynamic text is inserted with textContent (never innerHTML), so scanned
 * URLs and provider responses can not inject markup. */
(function () {
  "use strict";

  var STAGES = [
    ["validate", "Validating URL..."],
    ["structure", "Analyzing URL structure..."],
    ["domain", "Checking domain information..."],
    ["dns", "Checking DNS records..."],
    ["threat", "Consulting threat intelligence..."],
    ["risk", "Calculating risk score..."],
    ["report", "Generating security report..."]
  ];

  var LEVEL_TEXT = { low: "Low Risk", medium: "Medium Risk", high: "High Risk", critical: "Critical Risk" };
  var VERDICT_TEXT = {
    confirmed_malicious: "Confirmed malicious",
    suspicious: "Suspicious",
    no_known_threats: "No known threats detected",
    inconclusive: "Inconclusive / scan incomplete"
  };
  var STATUS_TEXT = { complete: "Complete", partial: "Partial (some checks unavailable)", incomplete: "Incomplete" };
  var SEV_TEXT = { info: "Info", low: "Low", medium: "Medium", high: "High", critical: "Critical" };

  // ---------------------------------------------------------------- helpers
  function $(id) { return document.getElementById(id); }

  function el(tag, props, children) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (k) {
        var v = props[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k === "style") node.style.cssText = v; // CSSOM is allowed by the CSP, style="" attributes are not
        else if (k === "dataset") Object.keys(v).forEach(function (d) { node.dataset[d] = v[d]; });
        else if (k.slice(0, 2) === "on" && typeof v === "function") node.addEventListener(k.slice(2), v);
        else node.setAttribute(k, v === true ? "" : v);
      });
    }
    (children || []).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function fmtDate(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return iso || "";
    return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  function levelClass(level) { return "level-" + (LEVEL_TEXT[level] ? level : "low"); }

  function showError(node, message) {
    if (!node) return;
    node.textContent = message;
    node.hidden = !message;
  }

  /** fetch wrapper: resolves with parsed JSON, rejects with Error(message). */
  function api(path, options) {
    options = options || {};
    var init = { method: options.method || "GET", headers: { Accept: "application/json" }, credentials: "same-origin" };
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    return fetch(path, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
        if (!res.ok) {
          var msg = data && data.error && data.error.message
            ? data.error.message
            : "The server returned an error (HTTP " + res.status + ").";
          var err = new Error(msg);
          err.status = res.status;
          throw err;
        }
        return data;
      });
    }, function () {
      throw new Error("Could not reach the PhishLens server. Check that it is running.");
    });
  }

  // ---------------------------------------------------------------- report
  function severityTag(f) {
    if (f.status === "not_available") return el("span", { class: "tag na", text: "Not Available" });
    if (f.status === "pass") return el("span", { class: "tag pass", text: "Passed" });
    if (f.status === "info") return el("span", { class: "tag", text: "Info" });
    return el("span", { class: "tag sev-" + f.severity, text: SEV_TEXT[f.severity] || f.severity });
  }

  function findingCard(f) {
    var cls = "finding";
    if (f.status === "not_available") cls += " na";
    else if (f.status === "pass") cls += " pass";
    else if (f.status === "info") cls += " sev-info";
    else cls += " sev-" + f.severity;

    var dl = el("dl", null, []);
    function row(label, value) {
      if (!value) return;
      dl.appendChild(el("div", null, [el("dt", { text: label }), el("dd", { class: label === "Evidence" ? "evidence" : "", text: value })]));
    }
    row("Explanation", f.explanation);
    row("Evidence", f.evidence);
    row("Source", f.source);
    if (f.status === "flag" || f.status === "not_available") row("Recommendation", f.recommendation);

    return el("article", { class: cls, dataset: { status: f.status } }, [
      el("div", { class: "finding-top" }, [el("h3", { text: f.check }), severityTag(f)]),
      el("p", { class: "result", text: f.result }),
      dl
    ]);
  }

  function intelCard(title, state, big, lines, extra) {
    var kids = [el("h3", { text: title }), el("div", { class: "big", text: big })];
    (lines || []).forEach(function (l) { kids.push(el("p", { class: "muted small", text: l })); });
    if (extra) kids.push(extra);
    return el("div", { class: "intel " + state }, kids);
  }

  function vtCard(vt) {
    if (!vt || vt.status !== "ok") {
      return intelCard("VirusTotal", "na", "Not Available", [vt ? vt.detail : "Not checked."]);
    }
    var c = vt.counts;
    var counts = el("div", { class: "counts" }, [
      el("div", { class: "c-mal" }, [el("b", { text: String(c.malicious) }), el("span", { text: "Malicious" })]),
      el("div", { class: "c-sus" }, [el("b", { text: String(c.suspicious) }), el("span", { text: "Suspicious" })]),
      el("div", { class: "c-har" }, [el("b", { text: String(c.harmless) }), el("span", { text: "Harmless" })]),
      el("div", null, [el("b", { text: String(c.undetected) }), el("span", { text: "Undetected" })])
    ]);
    var state = c.malicious > 0 ? "bad" : (c.suspicious > 0 ? "bad" : "good");
    var big = c.malicious > 0 ? c.malicious + " engine(s) flag it" : (c.suspicious > 0 ? c.suspicious + " suspicious" : "No detections");
    var lines = [vt.detail];
    if (vt.analysed_at) lines.push("Last analysis: " + vt.analysed_at);
    var card = intelCard("VirusTotal", state, big, lines, counts);
    if (vt.flagged && vt.flagged.length) {
      card.appendChild(el("p", { class: "small", text: "Flagged by: " + vt.flagged.slice(0, 6).map(function (f) { return f.engine; }).join(", ") }));
    }
    return card;
  }

  function gsbCard(g) {
    if (!g || g.status !== "ok") {
      return intelCard("Google Safe Browsing", "na", "Not Available", [g ? g.detail : "Not checked."]);
    }
    if (g.threats && g.threats.length) {
      return intelCard("Google Safe Browsing", "bad", "Unsafe: " + g.threat_labels.join(", "), [g.detail]);
    }
    return intelCard("Google Safe Browsing", "good", "No match found", [g.detail]);
  }

  function dnsCard(dns) {
    if (!dns || dns.status === "not_applicable") {
      return intelCard("DNS", "na", "Not applicable", ["The URL uses an IP address."]);
    }
    if (dns.status === "error") return intelCard("DNS", "na", "Not Available", ["The DNS lookup failed or timed out."]);
    if (dns.status === "nxdomain") return intelCard("DNS", "bad", "Domain does not exist", ["NXDOMAIN"]);
    var lines = [];
    if (dns.ips && dns.ips.length) lines.push("Addresses: " + dns.ips.slice(0, 4).join(", "));
    if (dns.NS && dns.NS.length) lines.push("Name servers: " + dns.NS.slice(0, 3).join(", "));
    if (dns.MX && dns.MX.length) lines.push("Mail servers: " + dns.MX.slice(0, 2).join(", "));
    return intelCard("DNS", "good", (dns.ips ? dns.ips.length : 0) + " address(es)", lines);
  }

  function httpsCard(h) {
    if (!h || h.status === "skipped" || h.status === "unreachable" || h.status === "not_applicable") {
      return intelCard("HTTPS", "na", "Not Available", [h && h.detail ? h.detail : "Not inspected."]);
    }
    if (h.status === "ok") {
      return intelCard("HTTPS", "good", "Valid certificate", [
        h.tls_version + " - issuer: " + h.issuer,
        "Expires " + h.not_after + " (" + h.days_remaining + " days)"
      ]);
    }
    return intelCard("HTTPS", "bad", h.status === "invalid_certificate" ? "Invalid certificate" :
      (h.status === "refused" ? "HTTPS not offered" : "TLS problem"), [h.detail || ""]);
  }

  function renderReport(root, report, scanId) {
    clear(root);
    var risk = report.risk;

    // --- main result card
    var gauge = el("div", { class: "gauge " + levelClass(risk.level), style: "--pct:" + Math.max(0, Math.min(100, risk.score)) }, [
      el("div", { class: "gauge-inner" }, [
        el("div", { class: "gauge-score", text: String(risk.score) }),
        el("div", { class: "gauge-sub", text: "risk score" })
      ])
    ]);
    var kv = el("dl", { class: "kv" }, [
      el("dt", { text: "URL" }), el("dd", { class: "mono", text: report.input_url }),
      el("dt", { text: "Domain" }), el("dd", { class: "mono", text: report.domain }),
      el("dt", { text: "Scan status" }), el("dd", { class: "status-" + risk.status, text: STATUS_TEXT[risk.status] || risk.status }),
      el("dt", { text: "Scanned" }), el("dd", { text: fmtDate(report.scanned_at) + (report.duration_ms ? " (" + (report.duration_ms / 1000).toFixed(1) + " s)" : "") })
    ]);
    if (report.normalized_url && report.normalized_url !== report.input_url) {
      kv.appendChild(el("dt", { text: "Normalized" }));
      kv.appendChild(el("dd", { class: "mono", text: report.normalized_url }));
    }
    var meta = el("div", { class: "result-meta" }, [
      el("div", { class: "pills" }, [
        el("span", { class: "pill " + levelClass(risk.level), text: LEVEL_TEXT[risk.level] || risk.classification }),
        el("span", { class: "pill verdict-" + risk.verdict, text: VERDICT_TEXT[risk.verdict] || risk.verdict_label })
      ]),
      el("h2", { text: VERDICT_TEXT[risk.verdict] || risk.verdict_label }),
      el("p", { class: "summary-text muted", text: risk.summary }),
      kv
    ]);
    root.appendChild(el("div", { class: "panel result-card" }, [gauge, meta]));

    // --- callouts
    var notes = [];
    if (risk.verdict === "confirmed_malicious") {
      root.appendChild(el("div", { class: "callout callout-crit" }, [
        el("strong", { text: "Do not open this link. " }),
        "A threat-intelligence source lists it as malicious."
      ]));
    }
    if (report.unavailable && report.unavailable.length) {
      root.appendChild(el("div", { class: "callout callout-warn" }, [
        el("strong", { text: "Some checks could not be completed: " }),
        report.unavailable.join(", ") + ". These are shown as “Not Available” and are not treated as clean."
      ]));
    }
    (report.notes || []).forEach(function (n) { notes.push(el("li", { text: n })); });
    if (notes.length) root.appendChild(el("div", { class: "callout callout-info" }, [el("strong", { text: "Input notes" }), el("ul", null, notes)]));
    if (report.url_shared_with && report.url_shared_with.length) {
      root.appendChild(el("div", { class: "callout callout-info", text: "This URL was sent to: " + report.url_shared_with.join(", ") + "." }));
    }

    // --- threat intelligence
    var ti = report.threat_intel || {};
    root.appendChild(el("div", { class: "panel" }, [
      el("h2", { text: "Threat intelligence & network results" }),
      el("div", { class: "intel-grid" }, [vtCard(ti.virustotal), gsbCard(ti.safe_browsing), dnsCard(report.dns), httpsCard(report.https)])
    ]));

    // --- score breakdown
    if (risk.breakdown && risk.breakdown.length) {
      var rows = risk.breakdown.map(function (b) {
        return el("div", { class: "bar-row" }, [
          el("span", { text: b.label }),
          el("div", { class: "bar" }, [el("i", { style: "width:" + Math.min(100, (b.effective / b.cap) * 100) + "%" })]),
          el("span", { class: "mono small", text: b.effective + " / " + b.cap })
        ]);
      });
      var note = "Correlated indicators are capped per category so the same clue is not counted twice.";
      if (risk.floor_applied) note += " A confirmed detection set the minimum score to " + risk.floor_applied + ".";
      root.appendChild(el("div", { class: "panel" }, [
        el("h2", { text: "How the score was built" }),
        el("div", { class: "breakdown" }, rows),
        el("p", { class: "muted small", text: note })
      ]));
    }

    // --- findings with filters
    var findings = report.findings || [];
    var grid = el("div", { class: "finding-grid" }, []);
    var filterDefs = [
      ["all", "All (" + findings.length + ")", function () { return true; }],
      ["flag", "Flagged", function (f) { return f.status === "flag"; }],
      ["na", "Not Available", function (f) { return f.status === "not_available"; }],
      ["pass", "Passed", function (f) { return f.status === "pass"; }]
    ];
    var bar = el("div", { class: "filters", role: "group", "aria-label": "Filter findings" }, []);
    function draw(pred) {
      clear(grid);
      var order = { flag: 0, not_available: 1, pass: 2, info: 3 };
      var sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      findings.filter(pred).sort(function (a, b) {
        return (order[a.status] - order[b.status]) || (sevOrder[a.severity] - sevOrder[b.severity]);
      }).forEach(function (f) { grid.appendChild(findingCard(f)); });
    }
    filterDefs.forEach(function (def, i) {
      var btn = el("button", { type: "button", class: "filter", "aria-pressed": i === 0 ? "true" : "false", text: def[1] });
      btn.addEventListener("click", function () {
        Array.prototype.forEach.call(bar.children, function (b) { b.setAttribute("aria-pressed", "false"); });
        btn.setAttribute("aria-pressed", "true");
        draw(def[2]);
      });
      bar.appendChild(btn);
    });
    draw(filterDefs[0][2]);
    root.appendChild(el("div", { class: "panel" }, [el("h2", { text: "Detailed findings" }), bar, grid]));

    // --- footer
    var foot = [el("p", { class: "muted small", text: report.disclaimer || "" })];
    if (scanId && document.body.dataset.page === "home") {
      foot.push(el("p", null, [el("a", { class: "btn btn-ghost btn-sm", href: "/report/" + scanId, text: "Open permanent report link" })]));
    }
    root.appendChild(el("div", null, foot));
    root.hidden = false;
  }

  // ---------------------------------------------------------------- home page
  function initStages() {
    var list = $("stage-list");
    clear(list);
    STAGES.forEach(function (s) {
      list.appendChild(el("li", { class: "stage", id: "stage-" + s[0] }, [
        el("span", { class: "icon", "aria-hidden": "true" }),
        el("span", { class: "name", text: s[1] }),
        el("span", { class: "time mono" })
      ]));
    });
  }

  function setStage(ev) {
    var li = $("stage-" + ev.id);
    if (!li) return;
    var state = ev.state;
    li.className = "stage " + state;
    var icon = li.querySelector(".icon");
    icon.textContent = state === "done" ? "✓" : state === "warning" ? "!" : state === "failed" ? "×" : state === "skipped" ? "–" : "";
    var name = li.querySelector(".name");
    clear(name);
    name.appendChild(document.createTextNode(ev.label));
    if (ev.detail) name.appendChild(el("span", { class: "detail", text: ev.detail }));
    var time = li.querySelector(".time");
    time.textContent = ev.elapsed_ms !== undefined ? ev.elapsed_ms + " ms" : "";
  }

  function readEventStream(response, onEvent) {
    var reader = response.body.getReader();
    var decoder = new TextDecoder();
    var buffer = "";
    function pump() {
      return reader.read().then(function (chunk) {
        if (chunk.done) return;
        buffer += decoder.decode(chunk.value, { stream: true });
        var parts = buffer.split("\n\n");
        buffer = parts.pop();
        parts.forEach(function (block) {
          block.split("\n").forEach(function (line) {
            if (line.indexOf("data: ") !== 0) return;
            try { onEvent(JSON.parse(line.slice(6))); } catch (e) { /* ignore malformed chunk */ }
          });
        });
        return pump();
      });
    }
    return pump();
  }

  function runScan(url) {
    var errorBox = $("form-error");
    var panel = $("scan-panel");
    var root = $("report-root");
    var btn = $("scan-btn");
    var label = btn.querySelector(".btn-label");

    showError(errorBox, "");
    root.hidden = true;
    btn.disabled = true;
    label.textContent = "Scanning…";
    btn.insertBefore(el("span", { class: "spinner", id: "btn-spinner" }), label);

    $("scan-target").textContent = url;
    panel.classList.remove("finished");
    initStages();
    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth", block: "center" });

    var badge = $("progress-mode");
    badge.textContent = "Live progress from the server";

    var finished = false;
    function done() {
      btn.disabled = false;
      label.textContent = "Scan URL";
      var sp = $("btn-spinner");
      if (sp) sp.remove();
      panel.classList.add("finished");
    }
    function fail(message) {
      finished = true;
      showError(errorBox, message);
      done();
    }

    function handle(ev) {
      if (ev.type === "stage") setStage(ev);
      else if (ev.type === "error") {
        finished = true;
        panel.hidden = ev.error.code !== "internal_error" ? true : panel.hidden;
        showError(errorBox, ev.error.message);
        done();
      } else if (ev.type === "result") {
        finished = true;
        renderReport(root, ev.report, ev.id);
        done();
        refreshHome();
        root.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }

    fetch("/api/scan/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify({ url: url }),
      credentials: "same-origin"
    }).then(function (res) {
      if (!res.ok) {
        return res.json().catch(function () { return null; }).then(function (data) {
          panel.hidden = true;
          fail(data && data.error ? data.error.message : "The server returned an error (HTTP " + res.status + ").");
        });
      }
      if (!res.body || !res.body.getReader) {
        // Very old browser: fall back to one request without live progress.
        badge.textContent = "Progress is not live in this browser";
        return api("/api/scan", { method: "POST", body: { url: url } }).then(function (data) {
          STAGES.forEach(function (s) { setStage({ id: s[0], label: s[1], state: "done" }); });
          handle({ type: "result", id: data.id, report: data.report });
        });
      }
      return readEventStream(res, handle).then(function () {
        if (!finished) fail("The connection closed before the scan finished. Please try again.");
      });
    }).catch(function (err) {
      if (!finished) { panel.hidden = true; fail(err.message || "Could not reach the PhishLens server."); }
    });
  }

  function badgeFor(level, score) {
    return el("span", { class: "score-chip pill " + levelClass(level), text: String(score) });
  }

  function historyRow(s, full) {
    var open = el("a", { class: "btn btn-ghost btn-sm", href: "/report/" + s.id, text: "View report" });
    var cells = [
      el("td", { class: "nowrap", text: fmtDate(s.scanned_at) }),
      el("td", { class: "url-cell", title: s.url, text: s.url })
    ];
    if (full) cells.push(el("td", { class: "mono small", text: s.domain }));
    cells.push(
      el("td", null, [badgeFor(s.level, s.risk_score)]),
      el("td", { text: s.classification }),
      el("td", null, [el("span", { class: "pill verdict-" + s.verdict, text: VERDICT_TEXT[s.verdict] || s.verdict })])
    );
    if (full) cells.push(el("td", { class: "nowrap", text: STATUS_TEXT[s.status] || s.status }));
    var actions = [open];
    if (full) {
      actions.push(" ");
      actions.push(el("button", { type: "button", class: "btn btn-danger btn-sm", "data-delete": String(s.id), "aria-label": "Delete scan " + s.id, text: "Delete" }));
    }
    cells.push(el("td", { class: "actions" }, actions));
    return el("tr", null, cells);
  }

  function loadStats() {
    return api("/api/stats").then(function (s) {
      $("stat-total").textContent = String(s.total);
      $("stat-confirmed").textContent = String(s.confirmed_malicious);
      $("stat-suspicious").textContent = String(s.suspicious);
      $("stat-avg").textContent = s.average_score === null ? "–" : String(s.average_score);
    }).catch(function () { /* statistics are optional */ });
  }

  function loadRecent() {
    return api("/api/scans?limit=8").then(function (data) {
      var body = $("recent-body");
      clear(body);
      data.scans.forEach(function (s) { body.appendChild(historyRow(s, false)); });
      $("recent-empty").hidden = data.scans.length > 0;
      $("recent-table").hidden = data.scans.length === 0;
    }).catch(function () { $("recent-empty").hidden = false; $("recent-empty").textContent = "Could not load recent scans."; });
  }

  function loadProviders() {
    return api("/api/status").then(function (s) {
      var ul = $("provider-status");
      clear(ul);
      function item(name, on, extra) {
        ul.appendChild(el("li", { class: on ? "on" : "off", text: name + ": " + (on ? "enabled" : "not configured") + (extra || "") }));
      }
      item("VirusTotal", s.providers.virustotal.configured);
      item("Google Safe Browsing", s.providers.safe_browsing.configured);
      item("HTTPS inspection", s.checks.tls_inspection, "");
      item("Domain age", s.checks.domain_age, "");
    }).catch(function () { });
  }

  function refreshHome() { loadStats(); loadRecent(); }

  function initHome() {
    var form = $("scan-form");
    var input = $("url-input");
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var url = input.value.trim();
      if (!url) {
        showError($("form-error"), "Please enter a URL to scan.");
        input.focus();
        return;
      }
      if ($("scan-btn").disabled) return;
      runScan(url);
    });
    Array.prototype.forEach.call(document.querySelectorAll(".chip[data-url]"), function (chip) {
      chip.addEventListener("click", function () {
        input.value = chip.dataset.url;
        input.focus();
      });
    });
    loadProviders();
    refreshHome();
  }

  // ---------------------------------------------------------------- history page
  function initHistory() {
    var body = $("history-body");
    var clearBtn = $("clear-history");
    var errBox = $("history-error");

    function load() {
      return api("/api/scans?limit=500").then(function (data) {
        clear(body);
        data.scans.forEach(function (s) { body.appendChild(historyRow(s, true)); });
        $("history-empty").hidden = data.scans.length > 0;
        $("history-table").hidden = data.scans.length === 0;
        clearBtn.hidden = data.scans.length === 0;
      }).catch(function (e) { showError(errBox, e.message); });
    }

    body.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-delete]");
      if (!btn) return;
      btn.disabled = true;
      api("/api/scans/" + encodeURIComponent(btn.dataset["delete"]), { method: "DELETE" })
        .then(load).catch(function (err) { btn.disabled = false; showError(errBox, err.message); });
    });

    clearBtn.addEventListener("click", function () {
      if (!window.confirm("Delete the entire scan history? This cannot be undone.")) return;
      api("/api/scans", { method: "DELETE" }).then(load).catch(function (err) { showError(errBox, err.message); });
    });
    load();
  }

  // ---------------------------------------------------------------- report page
  function initReportPage() {
    var holder = $("report-page");
    var id = holder.dataset.scanId;
    api("/api/scans/" + encodeURIComponent(id)).then(function (data) {
      $("report-loading").hidden = true;
      renderReport($("report-root"), data.report, data.id);
    }).catch(function (e) {
      $("report-loading").hidden = true;
      showError($("report-error"), e.message);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var page = document.body.dataset.page;
    if (page === "home") initHome();
    else if (page === "history") initHistory();
    else if (page === "report") initReportPage();
  });
})();
