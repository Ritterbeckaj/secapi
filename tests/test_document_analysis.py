"""Tests for Document / malware static analysis service."""
from apis.document_analysis.service import analyze_document, detect_type


def test_detect_pdf():
    assert detect_type(b"%PDF-1.4", "x.pdf") == "pdf"


def test_detect_office_zip():
    assert detect_type(b"PK\x03\x04", "x.docx") == "office/zip"


def test_empty_document_non_malicious():
    res = analyze_document("clean.txt", b"just some text")
    assert res.macro_detected is False
    assert res.score < 40


def test_powershell_macro_detected():
    payload = b"Sub AutoOpen()\r\nShell(\"powershell -enc IABCA==\")\r\nEnd Sub"
    res = analyze_document("macro.doc", payload)
    assert res.macro_detected is True
    assert "powershell" in [k.lower() for k in res.macro_keywords]
    assert res.score >= 60


def test_pdf_openaction_flagged():
    payload = b"%PDF-1.4\n/OpenAction <</S /JavaScript /JS (app.launchURL('http://evil.com'))>>"
    res = analyze_document("evil.pdf", payload)
    assert res.file_type == "pdf"
    assert any("OpenAction" in i for i in res.risky_indicators)
    assert any("http://evil.com" in u for u in res.urls)


def test_detect_url_and_email():
    res = analyze_document("report.txt", b"contact us at admin@example.com or http://foo.bar/x")
    assert "admin@example.com" in res.emails
    assert "http://foo.bar/x" in res.urls
