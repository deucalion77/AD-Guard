import sys
import argparse
import json
import datetime
from pathlib import Path

# Ensure engine/ is importable (rules/, custom_rule_engine.py live next to this file)
ENGINE_DIR = Path(__file__).resolve().parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

# Built-in rules (your existing Python rules)
from rules.kerberoast import rule_kerberoast_exposure
from rules.password_policy import rule_password_never_expires
from rules.machine_account_quota import rule_machine_account_quota
from rules.dcsync import rule_dcsync_risk
from rules.gpo_posture import rule_gpo_posture
from rules.krbtgt import rule_krbtgt_password_age
from rules.dangerous_acls import rule_dangerous_acls

# Custom rules loader + evaluator
from custom_rule_engine import load_custom_rules, evaluate_custom_rules


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def load_json(p: Path):
# Load JSON with BOM tolerance. Returns Python object or None.
    if not p.exists():
        return None
    txt = p.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not txt:
        return None
    return json.loads(txt)


def ensure_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def build_adminsdholder_protected_set(users, groups):
# Best-effort protected set for adminCount-aware suppression.

    protected = set()

    for u in (users or []):
        try:
            sam = (u.get("SamAccountName") or "").strip()
            if not sam:
                continue
            admin_count = u.get("adminCount", None)
            # sometimes adminCount missing; treat only explicit 1 as protected
            if admin_count == 1 or str(admin_count).strip() == "1":
                protected.add(sam.lower())
        except Exception:
            continue

    for g in (groups or []):
        try:
            sam = (g.get("SamAccountName") or g.get("Name") or "").strip()
            if not sam:
                continue
            admin_count = g.get("adminCount", None)
            if admin_count == 1 or str(admin_count).strip() == "1":
                protected.add(sam.lower())
        except Exception:
            continue

    return protected


def score_posture(findings):

# Simple posture score: start at 100 and subtract weighted penalties.

    score = 100
    weights = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0} # Adjust the posture from this 

    for f in findings or []:
        sev = (f.get("severity") or "INFO").upper()
        score -= weights.get(sev, 0)

    if score < 0:
        score = 0
    if score > 100:
        score = 100
    return score


def severity_counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings or []:
        sev = (f.get("severity") or "INFO").upper()
        if sev not in counts:
            sev = "INFO"
        counts[sev] += 1
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, help="Raw JSON folder")
    ap.add_argument("--out", required=True, help="Output scan.json")
    ap.add_argument("--html", required=True, help="Output report.html")
    ap.add_argument("--rules-dir", default="", help="Directory containing custom rules (*.json, *.ndjson)")
    ap.add_argument("--custom-only", action="store_true", help="Run only custom rules (skip built-in rules)")
    args = ap.parse_args()

    raw = Path(args.raw)

    users = load_json(raw / "users.json") or []
    groups = load_json(raw / "groups.json") or []
    domain_policies = load_json(raw / "domain_policies.json") or {}
    domain_acl = load_json(raw / "domain_acl.json") or []

    protected_sams = build_adminsdholder_protected_set(users, groups)

    # Resolve custom rules directory
    engine_dir = ENGINE_DIR  # already computed
    if args.rules_dir and args.rules_dir.strip():
        rules_dir = Path(args.rules_dir)
        if not rules_dir.is_absolute():
            # relative to tool root (parent of engine/)
            rules_dir = (engine_dir.parent / rules_dir).resolve()
        else:
            rules_dir = rules_dir.resolve()
    else:
        # default to engine/custom_rules
        rules_dir = (engine_dir / "custom_rules").resolve()

    custom_rules = load_custom_rules(rules_dir)
#    print(f"[INFO] Custom rules loaded: {len(custom_rules)} from {rules_dir}")

    findings = []

    if not args.custom_only:
        # Built-in rules
        findings += ensure_list(rule_kerberoast_exposure(users))
        findings += ensure_list(rule_password_never_expires(users))
        findings += ensure_list(rule_machine_account_quota(domain_policies))
        findings += ensure_list(rule_dcsync_risk(domain_acl, protected_sams))
        findings += ensure_list(rule_gpo_posture(raw / "gpo_reports"))
        findings += ensure_list(rule_krbtgt_password_age(users))
        findings += ensure_list(rule_dangerous_acls(raw / "acl_targets", protected_sams))
    else:
        print("[INFO] Custom-only mode enabled: skipping built-in rules")

    # Custom rules evaluation
    custom_findings = evaluate_custom_rules(
        custom_rules,
        users=users,
        groups=groups,
        domain_policies=domain_policies,
        domain_acl=domain_acl
    )
    print(f"[INFO] Custom findings produced: {len(custom_findings)}")
    findings += ensure_list(custom_findings)

    # Sort + score
    findings.sort(key=lambda f: -SEVERITY_ORDER.get((f.get("severity") or "INFO").upper(), 0))
    posture_score = score_posture(findings)

    result = {
        "generated_utc": datetime.datetime.now(datetime.UTC).isoformat(),
        "posture_score": posture_score,
        "finding_count": len(findings),
        "findings": findings
    }

    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")

    # ---- HTML report ----
    sev_counts = severity_counts(findings)

    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    values = [sev_counts[k] for k in labels]

    labels_js = json.dumps(labels)
    values_js = json.dumps(values)

    # Basic CSS + dark mode toggle
    html = [f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>ADGuard Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #ffffff;
    --text: #111827;
    --muted: #6b7280;
    --card: #f8fafc;
    --border: #e5e7eb;

    --crit: #b91c1c;
    --high: #ea580c;
    --med:  #ca8a04;
    --low:  #2563eb;
    --info: #475569;
  }}

  body.dark {{
    --bg: #0b1220;
    --text: #e5e7eb;
    --muted: #94a3b8;
    --card: #0f172a;
    --border: #1f2937;
  }}

  body {{
    margin: 0;
    font-family: Segoe UI, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
  }}

  .topbar {{
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }}

  .title {{
    display: flex;
    flex-direction: column;
    gap: 4px;
  }}

  .title h1 {{
    margin: 0;
    font-size: 20px;
    font-weight: 700;
  }}

  .meta {{
    color: var(--muted);
    font-size: 13px;
  }}

  .toggle {{
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--text);
    padding: 8px 10px;
    border-radius: 10px;
    cursor: pointer;
    font-size: 13px;
  }}

  .wrap {{
    padding: 18px 20px 26px 20px;
  }}

  .summary {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 12px;
    margin-bottom: 16px;
  }}

  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 12px 14px;
  }}

  .card .k {{
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 6px;
  }}

  .card .v {{
    font-size: 18px;
    font-weight: 700;
  }}

  .chart-container {{
    width: 600px;
    height: 400px;
    float: right;
    margin-left: 30px;
    margin-bottom: 20px;
  }}

  .finding {{
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 12px 14px;
    margin: 12px 0;
    background: var(--card);
  }}

  .badge {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    margin-right: 8px;
  }}

  .badge.CRITICAL {{ background: rgba(185,28,28,0.18); color: var(--crit); }}
  .badge.HIGH     {{ background: rgba(234,88,12,0.18); color: var(--high); }}
  .badge.MEDIUM   {{ background: rgba(202,138,4,0.18); color: var(--med);  }}
  .badge.LOW      {{ background: rgba(37,99,235,0.18); color: var(--low);  }}
  .badge.INFO     {{ background: rgba(71,85,105,0.18); color: var(--info); }}

  .finding h3 {{
    margin: 8px 0 8px 0;
    font-size: 15px;
  }}

  pre {{
    background: rgba(15, 23, 42, 0.06);
    border: 1px solid var(--border);
    padding: 10px 12px;
    border-radius: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }}
  body.dark pre {{
    background: rgba(255, 255, 255, 0.04);
  }}

  ul {{
    margin: 8px 0 0 18px;
  }}

  .muted {{
    color: var(--muted);
  }}

  .clear {{
    clear: both;
  }}
</style>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>

<body>
  <div class="topbar">
    <div class="title">
      <h1>ADGuard Report</h1>
      <div class="meta">
        Generated (UTC): <b>{result["generated_utc"]}</b> &nbsp; | &nbsp;
        Posture score: <b>{posture_score}/100</b> &nbsp; | &nbsp;
        Total findings: <b>{len(findings)}</b>
      </div>
    </div>
    <button class="toggle" onclick="toggleTheme()">Toggle dark mode</button>
  </div>

  <div class="wrap">

    <div class="summary">
      <div class="card"><div class="k">CRITICAL</div><div class="v">{sev_counts["CRITICAL"]}</div></div>
      <div class="card"><div class="k">HIGH</div><div class="v">{sev_counts["HIGH"]}</div></div>
      <div class="card"><div class="k">MEDIUM</div><div class="v">{sev_counts["MEDIUM"]}</div></div>
    </div>

    <div class="chart-container">
      <canvas id="severityPie" width="600" height="400"></canvas>
      <div class="muted" style="font-size:12px;margin-top:8px;">
        Legend: CRITICAL / HIGH / MEDIUM / LOW / INFO
      </div>
    </div>

    <script>
      const labels = {labels_js};
      const values = {values_js};
      const total = values.reduce((a,b) => a + b, 0);

      const data = {{
        labels: labels,
        datasets: [{{
          data: values
        }}]
      }};

      const pctLabelsPlugin = {{
        id: 'pctLabelsPlugin',
        afterDatasetsDraw(chart, args, pluginOptions) {{
          const {{ctx}} = chart;
          const meta = chart.getDatasetMeta(0);
          ctx.save();
          ctx.font = '12px Segoe UI, Arial, sans-serif';
          ctx.textBaseline = 'middle';

          meta.data.forEach((el, i) => {{
            const val = values[i];
            if (!val) return;
            const pct = total ? Math.round((val / total) * 100) : 0;

            // position labels to the right side of the slice
            const pos = el.tooltipPosition();
            const x = pos.x + 30;
            const y = pos.y;

            ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text').trim() || '#111827';
            ctx.fillText(`${{labels[i]}}: ${{pct}}%`, x, y);
          }});
          ctx.restore();
        }}
      }};

      new Chart(
        document.getElementById('severityPie'),
        {{
          type: 'pie',
          data: data,
          options: {{
            responsive: false,
            plugins: {{
              legend: {{ display: true, position: 'bottom' }}
            }}
          }},
          plugins: [pctLabelsPlugin]
        }}
      );

      function toggleTheme() {{
        document.body.classList.toggle('dark');
        localStorage.setItem('adguardTheme', document.body.classList.contains('dark') ? 'dark' : 'light');
      }}

      (function initTheme() {{
        const t = localStorage.getItem('adguardTheme');
        if (t === 'dark') document.body.classList.add('dark');
      }})();
    </script>

    <div class="clear"></div>
"""]

# No findings message
    if len(findings) == 0:
        html.append("""
    <div class="finding">
      <span class="badge INFO">INFO</span>
      <strong>No findings matched.</strong>
      <p class="muted" style="margin-top:8px;">
        If you expected matches, verify your custom rule operators are supported and your rule conditions match the collected fields.
      </p>
    </div>
""")
    else:
        # Findings list
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            title = f.get("title") or "(no title)"
            impact = f.get("impact") or ""
            remediation = f.get("remediation") or []
            evidence = f.get("evidence", {})

            html.append(f"""
    <div class="finding">
      <div>
        <span class="badge {sev}">{sev}</span>
        <span class="muted">{f.get("id","")}</span>
      </div>
      <h3>{title}</h3>
      <div class="muted" style="margin-top:6px;margin-bottom:6px;"><b>Evidence</b></div>
      <pre>{json.dumps(evidence, indent=2)}</pre>
""")

            if impact:
                html.append(f"""      <div class="muted"><b>Impact:</b></div>
      <div style="margin-top:6px;">{impact}</div>
""")

            if remediation:
                html.append("""      <div class="muted" style="margin-top:10px;"><b>Remediation:</b></div>
      <ul>
""")
                for r in remediation:
                    html.append(f"        <li>{r}</li>\n")
                html.append("      </ul>\n")

            html.append("    </div>\n")  # end finding

    html.append("""
  </div>
</body>
</html>
""")

    Path(args.html).write_text("\n".join(html), encoding="utf-8")

    print(f"Wrote: {args.out}")
    print(f"Wrote: {args.html}")


if __name__ == "__main__":
    main()
