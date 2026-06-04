"""Safe, educational application security assessment checks.

This module is intentionally limited to basic, non-destructive checks that are
appropriate for authorized demo websites and classroom use.
"""

from __future__ import annotations

import html
import re
import socket
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = (
    "Mozilla/5.0 (compatible; WebApplicationSecurityAssessmentTool/1.0; "
    "+https://example.edu/security-lab)"
)
REQUEST_HEADERS = {"User-Agent": USER_AGENT}
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
}
HEADER_CHECKS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "description": "Content Security Policy helps reduce the impact of XSS and injection-based attacks.",
        "recommendation": "Configure a restrictive Content-Security-Policy header for trusted script and asset sources.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "X-Frame-Options reduces clickjacking exposure by controlling framing behavior.",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN where appropriate.",
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "HTTP Strict Transport Security enforces secure connections on HTTPS deployments.",
        "recommendation": "Enable HSTS for HTTPS applications with a safe max-age value.",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "This header helps prevent MIME type sniffing in browsers.",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "A referrer policy limits how much URL information is sent to other sites.",
        "recommendation": "Use a strict policy such as strict-origin-when-cross-origin.",
    },
}
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql",
    r"mariadb",
    r"postgresql",
    r"sqlite",
    r"oracle",
    r"odbc",
    r"unclosed quotation mark",
    r"warning: pg_",
    r"pdoexception",
    r"sqlstate",
]
SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


class ScanError(Exception):
    """Raised when a scan cannot safely continue."""


def normalize_url(raw_url: str) -> str:
    """Validate and normalize a URL entered by the user."""
    if not raw_url:
        raise ScanError("Please enter a URL to scan.")

    candidate = raw_url.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.netloc:
        raise ScanError("Please enter a valid URL such as https://example.com.")

    return candidate


def fetch_target(url: str):
    """Fetch the target page so the rest of the checks can inspect it.

    The response body is reused by multiple modules to keep the workflow close to
    a real assessment process while remaining safe and read-only.
    """
    session = requests.Session()
    try:
        response = session.get(url, timeout=10, headers=REQUEST_HEADERS, verify=True)
    except requests.exceptions.SSLError as exc:
        raise ScanError(
            "SSL validation failed for the target site. Try an authorized demo site with a trusted certificate."
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise ScanError("The target website timed out while responding.") from exc
    except requests.exceptions.ConnectionError as exc:
        raise ScanError("The target website could not be reached.") from exc
    except requests.exceptions.RequestException as exc:
        raise ScanError(f"Unable to complete the web request: {exc}") from exc

    return session, response


def analyze_headers(response):
    """Check for common defensive headers and build educational findings."""
    findings = []
    scheme = urlparse(response.url).scheme

    for header_name, details in HEADER_CHECKS.items():
        if header_name in response.headers:
            continue

        severity = details["severity"]
        if header_name == "Strict-Transport-Security" and scheme == "http":
            severity = "Low"

        findings.append(
            {
                "module": "Security Header Analysis",
                "name": f"Missing {header_name}",
                "severity": severity,
                "description": details["description"],
                "recommendation": details["recommendation"],
            }
        )

    return findings


def scan_ports(hostname: str):
    """Check a small set of common ports using socket programming."""
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise ScanError("Unable to resolve the target hostname for port scanning.") from exc

    results = []
    for port, service in COMMON_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            status_code = sock.connect_ex((resolved_ip, port))
            status = "OPEN" if status_code == 0 else "CLOSED"

        results.append(
            {
                "module": "Open Port Detection",
                "name": f"Port {port} ({service})",
                "port": port,
                "service": service,
                "status": status,
                "severity": "Low" if status == "OPEN" else "Informational",
                "description": f"The {service} service was reported as {status.lower()} on the target host.",
                "recommendation": (
                    "Review whether this service is required and restrict access if it is not needed."
                    if status == "OPEN"
                    else "No immediate action required for this port."
                ),
            }
        )

    return resolved_ip, results


def _collect_form_payloads(form, payload: str):
    """Fill form fields with a safe demo payload to simulate reflection testing."""
    data = {}
    for field in form.find_all(["input", "textarea"]):
        field_name = field.get("name")
        if not field_name:
            continue

        if field.name == "input":
            field_type = (field.get("type") or "text").lower()
            if field_type in {"submit", "button", "image", "file", "checkbox", "radio"}:
                continue

        data[field_name] = payload

    return data


def detect_xss(base_url: str, session: requests.Session, html_text: str):
    """Simulate a reflection check using a harmless JavaScript-like payload.

    The payload is never executed by this tool. It is only sent as data and then
    searched for in the server response to demonstrate how reflection can be
    observed during a controlled assessment.
    """
    findings = []
    soup = BeautifulSoup(html_text, "html.parser")
    forms = soup.find_all("form")
    payload = "<script>alert('xss')</script>"
    escaped_payload = html.escape(payload)

    for form in forms[:5]:
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        target_url = urljoin(base_url, action)
        data = _collect_form_payloads(form, payload)

        if not data:
            continue

        try:
            if method == "post":
                response = session.post(target_url, data=data, timeout=10, headers=REQUEST_HEADERS, verify=True)
            else:
                response = session.get(target_url, params=data, timeout=10, headers=REQUEST_HEADERS, verify=True)
        except requests.RequestException:
            continue

        reflected = payload in response.text or escaped_payload in response.text
        if reflected:
            findings.append(
                {
                    "module": "Basic XSS Detection",
                    "name": "Potential XSS Vulnerability Detected",
                    "severity": "High",
                    "description": "The safe demo payload was reflected in the response, which may indicate weak input handling.",
                    "recommendation": "Apply output encoding, server-side validation, and a strict Content-Security-Policy.",
                }
            )
            break

    return findings


def _looks_like_sql_error(response_text: str) -> bool:
    lowered = response_text.lower()
    return any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in SQL_ERROR_PATTERNS)


def detect_sqli(base_url: str, session: requests.Session, html_text: str):
    """Run a basic SQL injection awareness check with safe demo input."""
    findings = []
    soup = BeautifulSoup(html_text, "html.parser")
    forms = soup.find_all("form")
    payload = "' OR '1'='1"

    for form in forms[:5]:
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        target_url = urljoin(base_url, action)
        data = _collect_form_payloads(form, payload)

        if not data:
            continue

        try:
            if method == "post":
                response = session.post(target_url, data=data, timeout=10, headers=REQUEST_HEADERS, verify=True)
            else:
                response = session.get(target_url, params=data, timeout=10, headers=REQUEST_HEADERS, verify=True)
        except requests.RequestException:
            continue

        if _looks_like_sql_error(response.text) or payload in response.text:
            findings.append(
                {
                    "module": "Basic SQL Injection Detection",
                    "name": "Possible SQL Injection Vulnerability",
                    "severity": "High",
                    "description": "The response showed SQL-related indicators after a safe demo payload was submitted.",
                    "recommendation": "Use parameterized queries, server-side validation, and avoid exposing database errors to users.",
                }
            )
            break

    return findings


def _overall_risk(findings):
    if not findings:
        return "Low"

    highest = 1
    for finding in findings:
        highest = max(highest, SEVERITY_ORDER.get(finding.get("severity", "Low"), 1))

    if highest >= 4:
        return "Critical"
    if highest == 3:
        return "High"
    if highest == 2:
        return "Medium"
    return "Low"


def _build_risk_counts(findings):
    counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for finding in findings:
        severity = finding.get("severity", "Low")
        if severity in counts:
            counts[severity] += 1
    return counts


def generate_report(target_url: str, response, resolved_ip: str, header_findings, port_results, xss_findings, sqli_findings):
    """Combine all findings into a dashboard-friendly report structure."""
    port_findings = [entry for entry in port_results if entry["status"] == "OPEN"]
    all_findings = header_findings + port_findings + xss_findings + sqli_findings
    risk_counts = _build_risk_counts(all_findings)
    recommendations = []

    for finding in all_findings:
        recommendation = finding.get("recommendation")
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    report_rows = []
    for finding in all_findings:
        report_rows.append(
            {
                "module": finding.get("module", "Assessment"),
                "name": finding.get("name", "Finding"),
                "severity": finding.get("severity", "Low"),
                "description": finding.get("description", ""),
                "recommendation": finding.get("recommendation", ""),
            }
        )

    summary_stats = {
        "total_findings": len(all_findings),
        "critical": risk_counts["Critical"],
        "high": risk_counts["High"],
        "medium": risk_counts["Medium"],
        "low": risk_counts["Low"],
        "open_ports": len(port_findings),
    }

    return {
        "target_url": target_url,
        "scan_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "resolved_ip": resolved_ip,
        "status_code": response.status_code,
        "server_banner": response.headers.get("Server", "Not disclosed"),
        "overall_risk": _overall_risk(all_findings),
        "summary_stats": summary_stats,
        "risk_counts": risk_counts,
        "header_findings": header_findings,
        "port_results": port_results,
        "xss_findings": xss_findings,
        "sqli_findings": sqli_findings,
        "recommendations": recommendations,
        "report_rows": report_rows,
        "security_headers_present": {
            header: response.headers.get(header, "Not present") for header in HEADER_CHECKS
        },
    }


def perform_assessment(raw_url: str):
    """Execute the complete safe assessment workflow for the submitted target."""
    normalized_url = normalize_url(raw_url)
    session, response = fetch_target(normalized_url)
    parsed_target = urlparse(response.url)
    hostname = parsed_target.hostname or urlparse(normalized_url).hostname

    if not hostname:
        raise ScanError("The target hostname could not be determined.")

    header_findings = analyze_headers(response)
    resolved_ip, port_results = scan_ports(hostname)
    xss_findings = detect_xss(response.url, session, response.text)
    sqli_findings = detect_sqli(response.url, session, response.text)

    return generate_report(
        target_url=response.url,
        response=response,
        resolved_ip=resolved_ip,
        header_findings=header_findings,
        port_results=port_results,
        xss_findings=xss_findings,
        sqli_findings=sqli_findings,
    )
