"""Phishing and URL Threat Detection Service for SENTINEL X."""

import re
import math
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List

# High-profile targets commonly impersonated in phishing attacks
TARGET_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "netflix.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "sentinel-x.io",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "country", "tk", "ml", "ga", "cf", "gq", "buzz", "surf", "work", "loan", "click"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "update", "banking",
    "password", "credential", "auth", "wallet", "confirm", "recovery", "security", "support"
]

LEET_REPLACEMENTS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '@': 'a', '5': 's', '$': 's', '7': 't', '8': 'b', 'vv': 'w',
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to detect DGA (Domain Generation Algorithm) or randomized strings."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address or integer IP."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        if host.isdigit():
            return True
        return False


def check_punycode_and_homograph(host: str) -> List[str]:
    """Detect Punycode, IDN prefix, and Cyrillic/Greek lookalikes in host."""
    findings = []
    if host.startswith("xn--") or ".xn--" in host or "xn--" in host:
        findings.append("IDN Punycode prefix detected (potential homograph obfuscation)")

    non_ascii = [c for c in host if ord(c) > 127]
    if non_ascii:
        findings.append(f"Non-ASCII Unicode characters found in domain: {''.join(set(non_ascii))}")

    return findings


class PhishingService:
    """Analyzes URLs for structural, linguistic, cryptographic, and domain anomalies."""

    @staticmethod
    def analyze_url(url: str) -> Dict[str, Any]:
        url = url.strip()
        timestamp = datetime.now(timezone.utc).isoformat()

        if not (url.startswith("http://") or url.startswith("https://")):
            test_url = "http://" + url
        else:
            test_url = url

        try:
            parsed = urlparse(test_url)
            host = (parsed.hostname or "").lower()
            path = unquote(parsed.path or "").lower()
            query = unquote(parsed.query or "").lower()
        except Exception:
            return {
                "url": url,
                "findings": ["Malformed or unparseable URL structure"],
                "risk_score": 85,
                "severity": "Critical",
                "explanation": "The URL is syntactically invalid or designed to bypass URL parsers.",
                "analyzed_at": timestamp,
            }

        findings = []
        score = 0

        # 1. Scheme analysis
        if parsed.scheme == "http":
            findings.append("Insecure plain HTTP protocol in use")
            score += 15

        # 2. IP address host
        if is_ip_address(host):
            findings.append(f"Host uses raw IP address instead of domain name: {host}")
            score += 35

        # 3. Embedded credentials (@ symbol)
        if "@" in url:
            findings.append("URL contains '@' user-info delimiter (credential obfuscation vector)")
            score += 30

        # 4. Punycode and Unicode homograph checks
        homograph_findings = check_punycode_and_homograph(host)
        if homograph_findings:
            findings.extend(homograph_findings)
            score += 50

        # 5. Lookalike / Typosquatting checks against popular brands
        domain_parts = host.split(".")
        main_domain = domain_parts[-2] if len(domain_parts) >= 2 else host
        tld = domain_parts[-1] if len(domain_parts) >= 2 else ""

        # Break main domain into hyphenated sub-tokens (e.g. paypa1-security -> paypa1, security)
        domain_tokens = [main_domain] + [tok for tok in re.split(r'[-_]', main_domain) if tok]

        for target in TARGET_DOMAINS:
            # If the host is the genuine target domain itself, it is NOT an impersonating lookalike
            if host == target or host.endswith("." + target):
                continue

            target_main = target.split(".")[0]
            matched_target = False

            for tok in domain_tokens:
                # Direct Levenshtein check
                dist = levenshtein_distance(tok, target_main)
                # Leetspeak normalized token check
                norm_tok = tok
                for k, v in LEET_REPLACEMENTS.items():
                    norm_tok = norm_tok.replace(k, v)
                norm_dist = levenshtein_distance(norm_tok, target_main)

                if dist == 1 and tok != target_main:
                    findings.append(f"Domain token '{tok}' is a 1-character typosquat of target '{target}'")
                    score += 45
                    matched_target = True
                    break
                elif norm_dist == 0 and tok != target_main:
                    findings.append(f"Domain token '{tok}' uses leetspeak substitution for '{target_main}'")
                    score += 50
                    matched_target = True
                    break
                elif dist == 2 and len(target_main) >= 6 and tok != target_main:
                    findings.append(f"Domain '{host}' resembles high-profile brand '{target}'")
                    score += 30
                    matched_target = True
                    break

            if matched_target:
                break

        # 6. Suspicious TLD check
        if tld in SUSPICIOUS_TLDS:
            findings.append(f"Host uses high-risk Top-Level Domain (TLD): .{tld}")
            score += 25

        # 7. Subdomain depth and suspicious stacking
        subdomains = domain_parts[:-2] if len(domain_parts) > 2 else []
        if len(subdomains) >= 3:
            findings.append(f"Excessive subdomain levels detected ({len(subdomains)} subdomains)")
            score += 20

        for target in TARGET_DOMAINS:
            target_main = target.split(".")[0]
            if target_main in subdomains and not host.endswith(target):
                findings.append(f"Legitimate brand name '{target_main}' embedded in subdomain of foreign host '{host}'")
                score += 40

        # 8. Suspicious keywords in path and query
        path_query = f"{path} {query}"
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_query]
        if matched_keywords:
            findings.append(f"Security/credential harvesting keywords found in path/query: {', '.join(matched_keywords[:4])}")
            score += min(len(matched_keywords) * 10, 30)

        # 9. Domain Entropy check
        host_entropy = calculate_entropy(main_domain)
        if host_entropy > 3.8 and len(main_domain) > 10:
            findings.append(f"High domain character entropy ({host_entropy}) indicates algorithmically generated domain (DGA)")
            score += 25

        # 10. URL length anomaly
        if len(url) > 150:
            findings.append(f"Unusually long URL ({len(url)} characters)")
            score += 15

        # Cap score between 0 and 100
        score = min(max(score, 0), 100)

        # Severity categorization
        if score >= 80:
            severity = "Critical"
            explanation = "URL exhibits multiple high-confidence indicators of malicious phishing or credential harvesting."
        elif score >= 60:
            severity = "High"
            explanation = "URL exhibits strong suspicious indicators such as lookalike branding or credential obfuscation."
        elif score >= 30:
            severity = "Medium"
            explanation = "URL exhibits moderate risk factors (insecure scheme, unusual TLD, or keywords)."
        else:
            severity = "Low"
            if not findings:
                findings.append("No overt heuristic anomalies detected; normal caution is advised")
                explanation = "No overt structural or homograph anomalies detected. Continued vigilance recommended."
            else:
                explanation = "Minor structural observations recorded. Overall risk profile is low."

        return {
            "url": url,
            "findings": findings,
            "risk_score": score,
            "severity": severity,
            "explanation": explanation,
            "analyzed_at": timestamp,
        }
