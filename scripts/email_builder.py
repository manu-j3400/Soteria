"""
Soteria Email Builder
======================
Generates detailed HTML email bodies for every automation scenario.
Each function returns a complete, styled HTML string that Make can
drop directly into the Gmail body field via {{data.email_html}}.
"""
from datetime import datetime, timezone


STYLE = """
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a2e; }
  .container { max-width: 640px; margin: 0 auto; padding: 20px; }
  h1 { color: #0f3460; border-bottom: 3px solid #e94560; padding-bottom: 8px; font-size: 22px; }
  h2 { color: #16213e; font-size: 17px; margin-top: 24px; }
  h3 { color: #0f3460; font-size: 15px; margin-top: 18px; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
  .badge-green { background: #d4edda; color: #155724; }
  .badge-yellow { background: #fff3cd; color: #856404; }
  .badge-red { background: #f8d7da; color: #721c24; }
  .badge-blue { background: #cce5ff; color: #004085; }
  .stat-grid { display: flex; gap: 12px; flex-wrap: wrap; margin: 12px 0; }
  .stat-box { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 12px 16px; flex: 1; min-width: 120px; }
  .stat-box .label { font-size: 11px; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-box .value { font-size: 22px; font-weight: bold; color: #16213e; margin-top: 4px; }
  .item-row { padding: 8px 0; border-bottom: 1px solid #f0f0f0; }
  .priority-p0 { color: #dc3545; font-weight: bold; }
  .priority-p1 { color: #e67e22; font-weight: bold; }
  .priority-p2 { color: #3498db; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th { background: #16213e; color: white; padding: 8px 12px; text-align: left; font-size: 12px; }
  td { padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 13px; }
  tr:nth-child(even) { background: #f8f9fa; }
  .footer { margin-top: 30px; padding-top: 15px; border-top: 2px solid #e9ecef; font-size: 11px; color: #6c757d; }
  .code-block { background: #1a1a2e; color: #e94560; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; }
  a { color: #0f3460; }
</style>
"""


def _header(title: str, subtitle: str = "") -> str:
    ts = datetime.now(timezone.utc).strftime("%b %d, %Y at %H:%M UTC")
    return f"""<div class="container">
{STYLE}
<h1>{title}</h1>
<p style="color: #6c757d; font-size: 13px;">{subtitle + ' — ' if subtitle else ''}{ts}</p>
"""


def _footer() -> str:
    return """<div class="footer">
<p>Soteria Autonomous System — this email was generated automatically.<br>
Manage scenarios at <a href="https://www.make.com">Make.com</a> |
Backend at <a href="https://a-c-i-d-1.onrender.com">Render</a></p>
</div></div>"""


def _stat_box(label: str, value, color: str = "#16213e") -> str:
    return f'<div class="stat-box"><div class="label">{label}</div><div class="value" style="color:{color}">{value}</div></div>'


def _badge(text: str, level: str = "blue") -> str:
    return f'<span class="badge badge-{level}">{text}</span>'


# ═══════════════════════════════════════════════════════════════════════════
# PROACTIVE IMPROVEMENT
# ═══════════════════════════════════════════════════════════════════════════

def improvement_enqueued(task_id, priority, description, queue_summary) -> str:
    p = queue_summary
    badge_color = "red" if priority == "P0" else "yellow" if priority == "P1" else "blue"
    return (
        _header("Task Enqueued", f"Priority {priority}")
        + f'<p>{_badge(priority, badge_color)} A new improvement task has been added to the queue.</p>'
        + f'<h2>Task Details</h2>'
        + f'<table><tr><th>Field</th><th>Value</th></tr>'
        + f'<tr><td><strong>Task ID</strong></td><td><code>{task_id}</code></td></tr>'
        + f'<tr><td><strong>Priority</strong></td><td>{priority}</td></tr>'
        + f'<tr><td><strong>Description</strong></td><td>{description}</td></tr>'
        + f'<tr><td><strong>Status</strong></td><td>Queued — Cursor will execute on next check-in</td></tr>'
        + f'</table>'
        + f'<h2>Queue Status</h2>'
        + f'<div class="stat-grid">'
        + _stat_box("Pending", p.get("pending", 0), "#e67e22")
        + _stat_box("In Progress", p.get("in_progress", 0), "#3498db")
        + _stat_box("Completed", p.get("completed", 0), "#27ae60")
        + _stat_box("Failed", p.get("failed", 0), "#dc3545")
        + f'</div>'
        + f'<h2>What Happens Next</h2>'
        + f'<ol><li>Cursor picks up this task automatically</li>'
        + f'<li>Implements the change and runs tests</li>'
        + f'<li>Opens a <strong>draft PR</strong> for your review</li>'
        + f'<li>If CI passes and PR has "automation" label, auto-merges</li></ol>'
        + _footer()
    )


def improvement_no_tasks() -> str:
    return (
        _header("No Tasks Available")
        + f'<p>{_badge("IDLE", "green")} ROADMAP.md is empty or not found. The proactive improvement loop has nothing to work on.</p>'
        + f'<h2>What To Do</h2>'
        + f'<ul><li>Add tasks to <code>ROADMAP.md</code> in the repo</li>'
        + f'<li>Format: <code>- [ ] Your task description</code> under a <code>## P0</code>/<code>P1</code>/<code>P2</code>/<code>P3</code> header</li>'
        + f'<li>The next scheduled run will pick up new tasks automatically</li></ul>'
        + _footer()
    )


def improvement_all_assigned(queue_summary) -> str:
    p = queue_summary
    return (
        _header("All Tasks Assigned")
        + f'<p>{_badge("BUSY", "yellow")} Every task in ROADMAP.md is already queued or in progress. No new work to assign.</p>'
        + f'<h2>Current Queue</h2>'
        + f'<div class="stat-grid">'
        + _stat_box("Pending", p.get("pending", 0), "#e67e22")
        + _stat_box("In Progress", p.get("in_progress", 0), "#3498db")
        + _stat_box("Completed", p.get("completed", 0), "#27ae60")
        + f'</div>'
        + f'<p>Add more tasks to ROADMAP.md or wait for current tasks to complete.</p>'
        + _footer()
    )


# ═══════════════════════════════════════════════════════════════════════════
# REACTIVE HEALING
# ═══════════════════════════════════════════════════════════════════════════

def healing_enqueued(task_id, service, deploy_status, commit, error_excerpt, queue_summary) -> str:
    p = queue_summary
    return (
        _header("Deploy Failure — Healing Task Created", service)
        + f'<p>{_badge("DEPLOY FAILED", "red")} A Render deploy failure was detected. A healing task has been queued for Cursor.</p>'
        + f'<h2>Failure Details</h2>'
        + f'<table><tr><th>Field</th><th>Value</th></tr>'
        + f'<tr><td><strong>Service</strong></td><td>{service}</td></tr>'
        + f'<tr><td><strong>Deploy Status</strong></td><td>{deploy_status}</td></tr>'
        + f'<tr><td><strong>Failing Commit</strong></td><td><code>{commit}</code></td></tr>'
        + f'<tr><td><strong>Task ID</strong></td><td><code>{task_id}</code></td></tr>'
        + f'</table>'
        + f'<h2>Error Logs</h2>'
        + f'<div class="code-block"><pre>{error_excerpt[:1500]}</pre></div>'
        + f'<h2>Queue Status</h2>'
        + f'<div class="stat-grid">'
        + _stat_box("Pending", p.get("pending", 0), "#e67e22")
        + _stat_box("In Progress", p.get("in_progress", 0), "#3498db")
        + f'</div>'
        + f'<h2>Healing Process</h2>'
        + f'<ol><li>Cursor analyzes the error logs</li>'
        + f'<li>Identifies and fixes the root cause</li>'
        + f'<li>Runs tests to verify the fix</li>'
        + f'<li>Opens a draft PR with the fix + error log in description</li></ol>'
        + _footer()
    )


def healing_blocked(service, error_key, breaker_status) -> str:
    return (
        _header("Healing Blocked — Circuit Breaker Open", service)
        + f'<p>{_badge("BLOCKED", "red")} The same error has triggered too many times. Healing is paused to prevent loops.</p>'
        + f'<h2>Details</h2>'
        + f'<table><tr><th>Field</th><th>Value</th></tr>'
        + f'<tr><td><strong>Service</strong></td><td>{service}</td></tr>'
        + f'<tr><td><strong>Error Key</strong></td><td><code>{error_key}</code></td></tr>'
        + f'</table>'
        + f'<h2>Circuit Breaker Status</h2>'
        + f'<table><tr><th>Error Key</th><th>Triggers</th><th>Max</th><th>Blocked</th><th>Resets In</th></tr>'
        + "".join(
            f'<tr><td><code>{k[:12]}</code></td><td>{v["triggers"]}</td><td>{v["max"]}</td>'
            f'<td>{"Yes" if v["blocked"] else "No"}</td><td>{v["resets_in_seconds"]}s</td></tr>'
            for k, v in breaker_status.items()
        )
        + f'</table>'
        + f'<p><strong>Action needed:</strong> Investigate manually. The error is repeating — automatic healing cannot resolve it.</p>'
        + _footer()
    )


# ═══════════════════════════════════════════════════════════════════════════
# DAILY DIGEST
# ═══════════════════════════════════════════════════════════════════════════

def daily_digest(health, queue, scans_24h, roadmap_progress, circuit_breaker,
                 available_roadmap_tasks=None, queue_tasks=None) -> str:
    h = health
    q = queue
    s = scans_24h
    r = roadmap_progress
    grade_color = "#27ae60" if h["score"] >= 90 else "#e67e22" if h["score"] >= 75 else "#dc3545"
    grade_badge = "green" if h["score"] >= 90 else "yellow" if h["score"] >= 75 else "red"

    risk = s.get("risk_breakdown", {})
    risk_rows = "".join(f'<tr><td>{level}</td><td>{count}</td></tr>' for level, count in risk.items()) if risk else '<tr><td colspan="2">No scans in last 24h</td></tr>'

    cb_rows = ""
    for k, v in circuit_breaker.items():
        cb_rows += (f'<tr><td><code>{k[:12]}</code></td><td>{v["triggers"]}/{v["max"]}</td>'
                    f'<td>{"BLOCKED" if v["blocked"] else "OK"}</td></tr>')

    roadmap_pct = round(r["done"] / r["total"] * 100) if r["total"] > 0 else 0

    # ── Next Roadmap Tasks section ──
    roadmap_task_items = available_roadmap_tasks or []
    if roadmap_task_items:
        priority_colors = {"P0": "#dc3545", "P1": "#e67e22", "P2": "#3498db", "P3": "#6c757d"}
        roadmap_bullets = "".join(
            f'<li><span class="priority-{t["priority"].lower()}" '
            f'style="color:{priority_colors.get(t["priority"], "#6c757d")}">'
            f'{t["priority"]}</span>: {t["description"]}</li>'
            for t in roadmap_task_items
        )
        roadmap_tasks_html = f'<ul>{roadmap_bullets}</ul>'
    else:
        roadmap_tasks_html = '<p style="color:#6c757d">All roadmap tasks are completed or in progress.</p>'

    # ── Active Queue section ──
    active_queue = queue_tasks or []
    if active_queue:
        queue_rows = ""
        for t in active_queue:
            status_badge = _badge(t.get("status", "pending").upper(),
                                  "yellow" if t.get("status") == "in_progress" else "blue")
            queue_rows += (
                f'<tr><td><code>{t["id"][:8]}</code></td>'
                f'<td>{t.get("task_type", "unknown")}</td>'
                f'<td>{status_badge}</td>'
                f'<td>{t.get("instruction", "")[:80]}</td></tr>'
            )
        active_queue_html = (
            f'<table><tr><th>ID</th><th>Type</th><th>Status</th><th>Instruction</th></tr>'
            f'{queue_rows}</table>'
        )
    else:
        active_queue_html = (
            '<p style="color:#6c757d">No tasks in queue &mdash; '
            'trigger proactive improvement to pull from roadmap.</p>'
        )

    return (
        _header("Daily Security Digest")
        + f'<div class="stat-grid">'
        + f'<div class="stat-box"><div class="label">Health Grade</div><div class="value" style="color:{grade_color};font-size:36px">{h["grade"]}</div></div>'
        + _stat_box("Score", f'{h["score"]}/100', grade_color)
        + _stat_box("Scans (24h)", s.get("total_scans", 0))
        + _stat_box("Threats", s.get("threats_found", 0), "#dc3545" if s.get("threats_found", 0) > 0 else "#27ae60")
        + f'</div>'

        + f'<h2>Health Issues</h2>'
        + f'<ul>' + "".join(f'<li>{reason}</li>' for reason in h.get("reasons", ["All systems healthy"])) + '</ul>'

        + f'<h2>Task Queue</h2>'
        + f'<div class="stat-grid">'
        + _stat_box("Pending", q.get("pending", 0), "#e67e22")
        + _stat_box("In Progress", q.get("in_progress", 0), "#3498db")
        + _stat_box("Completed", q.get("completed", 0), "#27ae60")
        + _stat_box("Failed", q.get("failed", 0), "#dc3545" if q.get("failed", 0) > 0 else "#6c757d")
        + _stat_box("Skipped", q.get("skipped", 0))
        + f'</div>'

        + f'<h2>Active Queue</h2>'
        + active_queue_html

        + f'<h2>Scan Activity (Last 24 Hours)</h2>'
        + f'<table><tr><th>Metric</th><th>Value</th></tr>'
        + f'<tr><td>Total scans</td><td>{s.get("total_scans", 0)}</td></tr>'
        + f'<tr><td>Threats detected</td><td>{s.get("threats_found", 0)}</td></tr>'
        + f'<tr><td>Top language</td><td>{s.get("top_language", "N/A")}</td></tr>'
        + f'<tr><td>Avg confidence</td><td>{s.get("avg_confidence", 0):.1%}</td></tr>'
        + f'</table>'
        + f'<h3>Risk Breakdown</h3>'
        + f'<table><tr><th>Risk Level</th><th>Count</th></tr>{risk_rows}</table>'

        + f'<h2>Roadmap Progress</h2>'
        + f'<div class="stat-grid">'
        + _stat_box("Done", f'{r["done"]}/{r["total"]}', "#27ae60")
        + _stat_box("In Progress", r["in_progress"], "#3498db")
        + _stat_box("Available", r["available"], "#6c757d")
        + _stat_box("Completion", f'{roadmap_pct}%', "#27ae60" if roadmap_pct > 50 else "#e67e22")
        + f'</div>'

        + f'<h2>Next Roadmap Tasks</h2>'
        + roadmap_tasks_html

        + (f'<h2>Circuit Breaker</h2>'
           + f'<table><tr><th>Error Key</th><th>Triggers</th><th>Status</th></tr>{cb_rows}</table>'
           if cb_rows else '')

        + _footer()
    )


# ═══════════════════════════════════════════════════════════════════════════
# GTM INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════

def gtm_report(communities, competitors, trends, actions,
               community_summary, competitor_summary, trending_summary, actions_summary,
               product_suggestions=None) -> str:

    action_rows = ""
    for a in actions:
        p_class = f'priority-{a["priority"].lower()}'
        action_rows += (
            f'<tr><td class="{p_class}">{a["priority"]}</td>'
            f'<td>{a["action_type"].replace("_", " ").title()}</td>'
            f'<td>{a["description"][:120]}</td>'
            f'<td>{a.get("target_community", "")}</td></tr>'
        )

    trend_rows = ""
    for t in trends[:10]:
        actionable_badge = _badge("ACTION", "red") if t.get("actionable") else _badge("monitor", "blue")
        trend_rows += (
            f'<tr><td>{t.get("points", 0)}</td>'
            f'<td><a href="{t.get("url", "")}">{t["title"][:100]}</a></td>'
            f'<td>{t.get("source", "")}</td>'
            f'<td>{actionable_badge}</td></tr>'
        )

    comp_rows = ""
    for c in competitors:
        tier_badge = _badge(c.get("tier", "?").upper(),
                           "red" if c.get("tier") == "giant" else "yellow" if c.get("tier") == "mid" else "blue")
        comp_rows += (
            f'<tr><td>{tier_badge} {c["name"]}</td>'
            f'<td>{c.get("stars", 0):,}</td>'
            f'<td>{c.get("pricing", "")}</td>'
            f'<td>{c.get("weaknesses", "")[:80]}</td>'
            f'<td>{c.get("last_release", "")}</td></tr>'
        )

    # ── Product Suggestions section ──
    ps = product_suggestions or []
    if ps:
        ps_rows = ""
        for s in ps:
            type_badge = _badge(s["type"].replace("_", " ").upper(),
                                "yellow" if s["type"] == "product_gap" else "blue")
            source_info = s.get("competitor", s.get("source", ""))
            ps_rows += (
                f'<tr><td>{type_badge}</td>'
                f'<td>{source_info}</td>'
                f'<td>{s["suggestion"]}</td>'
                f'<td class="priority-{s["priority"].lower()}">{s["priority"]}</td></tr>'
            )
        product_html = (
            f'<table><tr><th>Type</th><th>Source</th><th>Suggestion</th><th>Priority</th></tr>'
            f'{ps_rows}</table>'
        )
    else:
        product_html = '<p style="color:#6c757d">No new product suggestions from this intel cycle.</p>'

    return (
        _header("GTM Intelligence Report")

        + f'<h2>Recommended Actions ({len(actions)} total)</h2>'
        + (f'<table><tr><th>Priority</th><th>Type</th><th>Action</th><th>Target</th></tr>'
           + action_rows + '</table>' if action_rows else '<p>No new actions generated.</p>')

        + f'<h2>Trending Security Topics ({len(trends)} found)</h2>'
        + (f'<table><tr><th>Points</th><th>Title</th><th>Source</th><th>Status</th></tr>'
           + trend_rows + '</table>' if trend_rows else '<p>No new trends detected.</p>')

        + f'<h2>Competitor Intelligence ({len(competitors)} tracked)</h2>'
        + f'<p>{competitor_summary}</p>'
        + (f'<table><tr><th>Name</th><th>Stars</th><th>Pricing</th><th>Weaknesses</th><th>Last Active</th></tr>'
           + comp_rows + '</table>' if comp_rows else '')

        + f'<h2>Product Suggestions from Intel ({len(ps)})</h2>'
        + product_html

        + f'<h2>Communities ({len(communities)} new)</h2>'
        + f'<p>{community_summary}</p>'

        + _footer()
    )


# ═══════════════════════════════════════════════════════════════════════════
# LEAD SCAN
# ═══════════════════════════════════════════════════════════════════════════

def lead_scan_report(leads, queries_used, stats) -> str:
    lead_rows = ""
    for l in leads:
        risk_badge = _badge(l.get("highest_risk", "LOW"),
                           "red" if l.get("highest_risk") in ("HIGH", "CRITICAL") else
                           "yellow" if l.get("highest_risk") == "MEDIUM" else "green")
        lead_rows += (
            f'<tr><td><a href="https://github.com/{l["repo"]}">{l["repo"]}</a></td>'
            f'<td>{l.get("stars", 0):,}</td>'
            f'<td>{l.get("vulnerabilities_found", 0)}</td>'
            f'<td>{risk_badge}</td>'
            f'<td>{l.get("files_scanned", 0)}</td></tr>'
        )

    return (
        _header("Lead Generation Scan")

        + f'<div class="stat-grid">'
        + _stat_box("Repos Scanned", stats.get("repos_scanned", 0))
        + _stat_box("Vulns Found", stats.get("total_vulnerabilities", 0), "#dc3545" if stats.get("total_vulnerabilities", 0) > 0 else "#27ae60")
        + _stat_box("High-Value Targets", stats.get("high_value_targets", 0), "#e67e22")
        + f'</div>'

        + f'<h2>Leads Found</h2>'
        + (f'<table><tr><th>Repository</th><th>Stars</th><th>Vulns</th><th>Risk</th><th>Files</th></tr>'
           + lead_rows + '</table>' if lead_rows else '<p>No new leads found in this scan.</p>')

        + f'<h2>Search Queries Used</h2>'
        + f'<ul>' + "".join(f'<li><code>{q}</code></li>' for q in queries_used) + '</ul>'

        + f'<p><strong>Next step:</strong> Review high-value targets at <code>GET /automation/leads</code> and prepare outreach.</p>'
        + _footer()
    )


# ═══════════════════════════════════════════════════════════════════════════
# ML HEALTH
# ═══════════════════════════════════════════════════════════════════════════

def ml_health_report(metrics, grade=None, retrain=None) -> str:
    m = metrics
    accuracy_color = "#27ae60" if m["accuracy"] >= 0.85 else "#e67e22" if m["accuracy"] >= 0.70 else "#dc3545"

    html = (
        _header("ML Model Health Report")
        + f'<div class="stat-grid">'
        + _stat_box("Accuracy", f'{m["accuracy"]:.1%}', accuracy_color)
        + _stat_box("Rated Samples", m["rated_samples"])
        + _stat_box("False Positives", m["false_positives"], "#dc3545" if m["false_positives"] > 0 else "#27ae60")
        + _stat_box("False Negatives", m["false_negatives"], "#dc3545" if m["false_negatives"] > 0 else "#27ae60")
        + f'</div>'

        + f'<h2>Details</h2>'
        + f'<table><tr><th>Metric</th><th>Value</th></tr>'
        + f'<tr><td>Total feedback</td><td>{m["total_feedback"]}</td></tr>'
        + f'<tr><td>Accuracy</td><td>{m["accuracy"]:.2%}</td></tr>'
        + f'<tr><td>False positive rate</td><td>{m["false_positive_rate"]:.2%}</td></tr>'
        + f'<tr><td>False negative rate</td><td>{m["false_negative_rate"]:.2%}</td></tr>'
        + f'<tr><td>Retrain threshold</td><td>{m["accuracy_threshold"]:.0%}</td></tr>'
        + f'<tr><td>Min samples for retrain</td><td>{m["min_samples_for_retrain"]}</td></tr>'
        + f'<tr><td>Needs retrain?</td><td>{"YES" if m["needs_retrain"] else "No"}</td></tr>'
        + f'</table>'
    )

    holdout = m.get("last_holdout_eval")
    if holdout and not retrain:
        html += (
            f'<h3>Last Holdout Evaluation</h3>'
            + f'<p style="font-size:12px;color:#6c757d">From most recent retrain (n={holdout.get("total_samples", "?")})</p>'
            + f'<div class="stat-grid">'
            + _stat_box("Accuracy", f'{holdout["accuracy"]:.1%}')
            + _stat_box("Precision", f'{holdout["precision_score"]:.1%}')
            + _stat_box("Recall", f'{holdout["recall_score"]:.1%}')
            + _stat_box("F1", f'{holdout["f1_score"]:.1%}')
            + f'</div>'
        )

    if retrain:
        html += (
            f'<h2>Retrain Result</h2>'
            + f'<p>{_badge(retrain["status"].upper(), "green" if "success" in retrain["status"] else "red")}</p>'
            + f'<p>{retrain.get("notification_summary", "")}</p>'
        )
        ev = retrain.get("evaluation_metrics")
        if ev:
            html += (
                f'<h3>Holdout Evaluation Metrics</h3>'
                + f'<div class="stat-grid">'
                + _stat_box("Accuracy", f'{ev["accuracy"]:.1%}')
                + _stat_box("Precision", f'{ev["precision_score"]:.1%}')
                + _stat_box("Recall", f'{ev["recall_score"]:.1%}')
                + _stat_box("F1 Score", f'{ev["f1_score"]:.1%}')
                + f'</div>'
                + f'<table><tr><th>Metric</th><th>Value</th></tr>'
                + f'<tr><td>True Positives</td><td>{ev["true_positives"]}</td></tr>'
                + f'<tr><td>True Negatives</td><td>{ev["true_negatives"]}</td></tr>'
                + f'<tr><td>False Positives</td><td>{ev["false_positives"]}</td></tr>'
                + f'<tr><td>False Negatives</td><td>{ev["false_negatives"]}</td></tr>'
                + f'<tr><td>Holdout samples</td><td>{ev["total_samples"]}</td></tr>'
                + f'</table>'
            )

    html += _footer()
    return html


# ═══════════════════════════════════════════════════════════════════════════
# GITHUB PUSH SCAN
# ═══════════════════════════════════════════════════════════════════════════

def push_scan_report(repo, branch, pusher, head_sha, commits, scan_results, scan_summary) -> str:
    s = scan_summary
    result_rows = ""
    for r in scan_results:
        if r.get("status") == "scanned":
            risk_badge = _badge(r.get("risk_level", "LOW"),
                               "red" if r.get("risk_level") in ("HIGH", "CRITICAL") else
                               "yellow" if r.get("risk_level") == "MEDIUM" else "green")
            vuln_count = len(r.get("vulnerabilities", []))
            result_rows += (
                f'<tr><td><code>{r["file"]}</code></td>'
                f'<td>{risk_badge}</td>'
                f'<td>{r.get("confidence", 0):.0%}</td>'
                f'<td>{vuln_count}</td>'
                f'<td>{r.get("reason", "")[:60]}</td></tr>'
            )
        else:
            result_rows += (
                f'<tr><td><code>{r.get("file", "?")}</code></td>'
                f'<td>{_badge(r.get("status", "error").upper(), "yellow")}</td>'
                f'<td>—</td><td>—</td>'
                f'<td>{r.get("reason", "")[:60]}</td></tr>'
            )

    commit_list = "".join(f'<li><code>{c}</code></li>' for c in (commits or []))

    return (
        _header("Push Scan Results", f'{repo}/{branch}')

        + f'<div class="stat-grid">'
        + _stat_box("Files Scanned", s.get("total_scanned", 0))
        + _stat_box("Threats", s.get("threats_found", 0), "#dc3545" if s.get("threats_found", 0) > 0 else "#27ae60")
        + _stat_box("High/Critical", s.get("high_risk", 0), "#dc3545" if s.get("high_risk", 0) > 0 else "#27ae60")
        + _stat_box("Errors", s.get("errors", 0))
        + f'</div>'

        + f'<h2>Push Details</h2>'
        + f'<table><tr><th>Field</th><th>Value</th></tr>'
        + f'<tr><td>Repository</td><td><a href="https://github.com/{repo}">{repo}</a></td></tr>'
        + f'<tr><td>Branch</td><td>{branch}</td></tr>'
        + f'<tr><td>Pushed by</td><td>{pusher}</td></tr>'
        + f'<tr><td>Head SHA</td><td><code>{head_sha}</code></td></tr>'
        + f'</table>'

        + f'<h2>Commits</h2><ul>{commit_list}</ul>'

        + f'<h2>Scan Results</h2>'
        + f'<table><tr><th>File</th><th>Risk</th><th>Confidence</th><th>Vulns</th><th>Reason</th></tr>'
        + result_rows + '</table>'

        + _footer()
    )


# ═══════════════════════════════════════════════════════════════════════════
# ERROR (generic)
# ═══════════════════════════════════════════════════════════════════════════

def error_email(endpoint, error_code, message, status_code=500) -> str:
    return (
        _header("Automation Error", endpoint)
        + f'<p>{_badge("ERROR", "red")} An automation endpoint returned an error.</p>'
        + f'<table><tr><th>Field</th><th>Value</th></tr>'
        + f'<tr><td>Endpoint</td><td><code>{endpoint}</code></td></tr>'
        + f'<tr><td>Status Code</td><td>{status_code}</td></tr>'
        + f'<tr><td>Error Code</td><td><code>{error_code}</code></td></tr>'
        + f'<tr><td>Message</td><td>{message}</td></tr>'
        + f'</table>'
        + f'<h2>What To Do</h2>'
        + f'<ol><li>Check Render logs for the full stack trace</li>'
        + f'<li>Hit <code>GET /automation/status</code> to check system health</li>'
        + f'<li>If the issue persists, the reactive healing loop may auto-fix it on next deploy</li></ol>'
        + _footer()
    )
