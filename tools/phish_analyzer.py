"""phish_analyzer — static phishing analysis of a .eml file (zero dependencies).

Parses an email and flags common phishing indicators:
  * SPF / DKIM / DMARC failures (from Authentication-Results)
  * From vs Reply-To / Return-Path domain mismatch (spoofing)
  * URLs with raw IP hosts or suspicious TLDs
  * Dangerous / double-extension attachments
  * Urgency / lure keywords in the subject
Outputs findings, a risk score, and a verdict.

Usage:
    python phish_analyzer.py message.eml [--format json]
"""
from __future__ import annotations

import argparse
import email
import re
import sys
from email.utils import parseaddr
from typing import Dict, List
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "ru", "zip", "mov", "top", "xyz"}
DANGEROUS_EXT = {"exe", "scr", "js", "vbs", "jar", "bat", "cmd", "ps1", "hta", "lnk", "iso", "img"}
URGENCY_WORDS = ["urgent", "verify", "suspended", "limited", "immediately", "account locked",
                 "confirm your", "unusual activity", "password expire"]
SEVERITY_WEIGHT = {"HIGH": 4, "MEDIUM": 2, "LOW": 1}
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _domain(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    return email_addr.split("@")[-1].lower() if "@" in email_addr else ""


def _bodies(msg) -> str:
    parts = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html") and not part.get_filename():
            try:
                parts.append(part.get_payload(decode=True).decode(errors="ignore"))
            except Exception:  # noqa: BLE001
                pass
    return "\n".join(parts)


def _attachments(msg) -> List[str]:
    return [part.get_filename() for part in msg.walk() if part.get_filename()]


def analyze(raw: str) -> Dict:
    msg = email.message_from_string(raw)
    findings: List[Dict[str, str]] = []

    def add(sev, code, msg_):
        findings.append({"severity": sev, "code": code, "message": msg_})

    from_dom = _domain(msg.get("From"))
    reply_dom = _domain(msg.get("Reply-To"))
    return_dom = _domain(msg.get("Return-Path"))

    # Authentication-Results
    auth = (msg.get("Authentication-Results") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        if m and m.group(1) == "fail":
            add("HIGH", f"{mech.upper()}_FAIL", f"{mech.upper()} authentication failed")
        elif not auth:
            add("LOW", "NO_AUTH_RESULTS", "No Authentication-Results header to verify SPF/DKIM/DMARC")
            break

    # Domain mismatches
    if reply_dom and from_dom and reply_dom != from_dom:
        add("MEDIUM", "REPLYTO_MISMATCH", f"Reply-To domain ({reply_dom}) differs from From ({from_dom})")
    if return_dom and from_dom and return_dom != from_dom:
        add("MEDIUM", "RETURNPATH_MISMATCH", f"Return-Path domain ({return_dom}) differs from From ({from_dom})")

    # URLs
    body = _bodies(msg)
    urls = URL_RE.findall(body)
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if IP_HOST_RE.match(host):
            add("HIGH", "IP_URL", f"Link uses a raw IP address: {url}")
        elif host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("MEDIUM", "SUSPICIOUS_TLD_URL", f"Link uses a suspicious TLD: {host}")

    # Suspicious TLD in sender domains
    for label, dom in (("From", from_dom), ("Reply-To", reply_dom), ("Return-Path", return_dom)):
        if dom and dom.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            add("MEDIUM", "SUSPICIOUS_TLD_SENDER", f"{label} domain uses a suspicious TLD: {dom}")

    # Attachments
    for name in _attachments(msg):
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXT:
            add("HIGH", "DANGEROUS_ATTACHMENT", f"Dangerous attachment: {name}")
        elif name.count(".") >= 2:
            add("MEDIUM", "DOUBLE_EXTENSION", f"Attachment with double extension: {name}")

    # Subject urgency
    subject = (msg.get("Subject") or "").lower()
    if any(w in subject for w in URGENCY_WORDS):
        add("LOW", "URGENCY_LURE", f"Subject uses urgency/lure language: {msg.get('Subject')}")

    score = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    verdict = "Likely Phishing" if score >= 6 else "Suspicious" if score >= 3 else "Likely Benign"
    return {
        "from": msg.get("From"), "subject": msg.get("Subject"),
        "score": score, "verdict": verdict,
        "urls": urls, "attachments": _attachments(msg), "findings": findings,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="phish_analyzer", description="Static .eml phishing analyzer.")
    parser.add_argument("eml", help="path to a .eml file")
    parser.add_argument("-f", "--format", choices=["table", "json"], default="table")
    args = parser.parse_args(argv)
    try:
        with open(args.eml, encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
    except FileNotFoundError:
        print(f"error: file not found: {args.eml}", file=sys.stderr)
        return 2
    result = analyze(raw)

    if args.format == "json":
        import json
        print(json.dumps(result, indent=2))
        return 0
    print(f"From    : {result['from']}")
    print(f"Subject : {result['subject']}")
    print(f"Verdict : {result['verdict']}  (risk score {result['score']})")
    for f in sorted(result["findings"], key=lambda x: -SEVERITY_WEIGHT[x["severity"]]):
        print(f"  [{f['severity']:<6}] {f['code']:<22} {f['message']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
