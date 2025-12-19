import argparse, json
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--infile", required=True)
    ap.add_argument("--html", required=True)
    args = ap.parse_args()

    data = json.loads(Path(args.infile).read_text(encoding="utf-8-sig"))
    findings = data.get("findings", [])

    html = ["<html><head><meta charset='utf-8'><title>ADGuard Report</title></head><body>"]
    html.append("<h1>ADGuard Report</h1>")
    html.append(f"<p><b>Generated:</b> {data.get('generated_utc')}</p>")
    html.append(f"<p><b>Posture score:</b> {data.get('posture_score')}/100</p>")
    html.append(f"<p><b>Findings:</b> {len(findings)}</p>")
    for f in findings:
        html.append("<hr/>")
        html.append(f"<h3>[{f.get('severity')}] {f.get('title')}</h3>")
        html.append(f"<pre>{json.dumps(f.get('evidence',{}), indent=2)}</pre>")
        html.append(f"<p><b>Impact:</b> {f.get('impact','')}</p>")
        rem = f.get("remediation", [])
        if rem:
            html.append("<ul>")
            for r in rem:
                html.append(f"<li>{r}</li>")
            html.append("</ul>")
    html.append("</body></html>")
    Path(args.html).write_text("\n".join(html), encoding="utf-8")

if __name__ == "__main__":
    main()
