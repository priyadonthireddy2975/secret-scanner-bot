import json
import os
import sys
import urllib.request

RESULTS_FILE = "trivy-results.json"
MODEL = "gemini-flash-latest"


def load_findings():
    with open(RESULTS_FILE) as file:
        data = json.load(file)
    findings = []
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            findings.append({
                "package": vuln.get("PkgName"),
                "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion"),
                "id": vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity"),
                "title": vuln.get("Title"),
            })
    return findings


def ask_gemini(finding):
    prompt = (
        "Explain this security finding to a student developer in 3 short lines: "
        "what the risk is and the exact fix. Plain language, no headings.\n"
        + json.dumps(finding)
    )
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        + MODEL
        + ":generateContent"
    )
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": os.environ["GEMINI_API_KEY"],
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        reply = json.load(response)
    return reply["candidates"][0]["content"]["parts"][0]["text"].strip()


def explain(finding):
    try:
        return ask_gemini(finding)
        except Exception as error:
        detail = error.read().decode() if hasattr(error, "read") else ""
        print("Gemini failed:", error, detail)
        return finding["title"] or "No explanation available."

def build_comment(findings):
    lines = ["## Dependency scan results", ""]
    for finding in findings:
        fixed = finding["fixed"] or "no fix available yet"
        lines.append(
            f"**{finding['package']} {finding['installed']}** | "
            f"{finding['id']} | {finding['severity']}"
        )
        lines.append(f"Fix: upgrade to {fixed}")
        lines.append("")
        lines.append(explain(finding))
        lines.append("")
    return "\n".join(lines)


def post_comment(text):
    repo = os.environ["GITHUB_REPOSITORY"]
    number = os.environ["PR_NUMBER"]
    url = f"https://api.github.com/repos/{repo}/issues/{number}/comments"
    body = json.dumps({"body": text}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    urllib.request.urlopen(request, timeout=30)


def main():
    findings = load_findings()
    if not findings:
        print("No vulnerabilities found")
        return
    post_comment(build_comment(findings))
    sys.exit(1)


if __name__ == "__main__":
    main()
