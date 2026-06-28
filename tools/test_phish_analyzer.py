import os

from phish_analyzer import analyze

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(os.path.dirname(HERE), "samples")


def load(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def test_suspicious_is_flagged():
    r = analyze(load("suspicious-sample.eml"))
    assert r["verdict"] == "Likely Phishing"
    codes = {f["code"] for f in r["findings"]}
    assert {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"} <= codes
    assert "IP_URL" in codes
    assert "DANGEROUS_ATTACHMENT" in codes
    assert "REPLYTO_MISMATCH" in codes


def test_benign_is_clean():
    r = analyze(load("benign-sample.eml"))
    assert r["verdict"] == "Likely Benign"
    assert r["findings"] == []


def test_double_extension_detected():
    eml = (
        'From: a@b.com\nSubject: hi\nMIME-Version: 1.0\n'
        'Authentication-Results: x; spf=pass; dkim=pass; dmarc=pass\n'
        'Content-Type: multipart/mixed; boundary="b"\n\n'
        '--b\nContent-Type: text/plain\n\nhello\n'
        '--b\nContent-Type: application/octet-stream; name="invoice.pdf.htm"\n'
        'Content-Disposition: attachment; filename="invoice.pdf.htm"\n\nx\n--b--\n'
    )
    codes = {f["code"] for f in analyze(eml)["findings"]}
    assert "DOUBLE_EXTENSION" in codes
