import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup


TRUSTED_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "myaccount.google.com",
    "openai.com",
    "cdn.openai.com",
    "medium.com",
    "github.com",
    "microsoft.com",
    "duckduckgo.com",
    "outlook.com",
    "office.com",
    "linkedin.com",
    "apple.com",
    "amazon.com"
}


KEYWORDS = {
    "verify": 10,
    "password": 15,
    "login": 15,
    "urgent": 10,
    "immediately": 10,
    "bank": 10,
    "account": 5,
    "security": 5,
    "update": 5,
    "click here": 20,
    "verify your account": 25,
    "reset password": 25,
    "confirm identity": 25
}


def extract_urls(body):
    pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(pattern, body)
    return list(set(urls))


def analyze_headers(headers):
    result = {
        "spf": "Unknown",
        "dkim": "Unknown",
        "dmarc": "Unknown"
    }

    auth = headers.get("Authentication-Results", "").lower()

    if "spf=pass" in auth:
        result["spf"] = "Pass"
    elif "spf=fail" in auth:
        result["spf"] = "Fail"

    if "dkim=pass" in auth:
        result["dkim"] = "Pass"
    elif "dkim=fail" in auth:
        result["dkim"] = "Fail"

    if "dmarc=pass" in auth:
        result["dmarc"] = "Pass"
    elif "dmarc=fail" in auth:
        result["dmarc"] = "Fail"

    return result


def calculate_risk(body, headers, urls):
    score = 0
    reasons = []

    text = BeautifulSoup(body, "html.parser").get_text(" ").lower()

    for keyword, weight in KEYWORDS.items():
        if keyword in text:
            score += weight
            reasons.append(f"Keyword: {keyword}")

    auth = analyze_headers(headers)

    if auth["spf"] == "Fail":
        score += 20
        reasons.append("SPF Failed")

    if auth["dkim"] == "Fail":
        score += 20
        reasons.append("DKIM Failed")

    if auth["dmarc"] == "Fail":
        score += 20
        reasons.append("DMARC Failed")

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if not domain:
            continue

        if any(domain.endswith(d) for d in TRUSTED_DOMAINS):
            continue

        if "@" in domain:
            score += 20
            reasons.append(f"Username In Domain: {domain}")

        if domain.count(".") > 3:
            score += 10
            reasons.append(f"Suspicious Domain Depth: {domain}")

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            score += 30
            reasons.append(f"IP Address URL: {domain}")

        if "xn--" in domain:
            score += 25
            reasons.append(f"Punycode Domain: {domain}")

        if domain.endswith(".zip"):
            score += 20
            reasons.append(f"ZIP TLD: {domain}")

        if domain.endswith(".mov"):
            score += 20
            reasons.append(f"MOV TLD: {domain}")

    score = min(score, 100)

    if score >= 70:
        classification = "High Risk"
    elif score >= 40:
        classification = "Medium Risk"
    else:
        classification = "Safe"

    return score, reasons, classification


def analyze(headers, body):
    urls = extract_urls(body)

    score, reasons, classification = calculate_risk(
        body,
        headers,
        urls
    )

    return {
        "risk_score": score,
        "classification": classification,
        "headers": analyze_headers(headers),
        "urls": urls,
        "reasons": reasons
    }