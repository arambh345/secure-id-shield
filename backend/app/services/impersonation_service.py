"""Identity Impersonation and Homoglyph Detection Service for SENTINEL X."""

import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.services.phishing_service import levenshtein_distance

# Character leetspeak / homoglyph normalization table
HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    '|': 'l',
    '!': 'i',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '5': 's',
    '$': 's',
    '7': 't',
    '8': 'b',
    # Cyrillic lookalikes
    '\u0430': 'a',  # Cyrillic small letter a
    '\u0441': 'c',  # Cyrillic small letter es
    '\u0435': 'e',  # Cyrillic small letter ie
    '\u043e': 'o',  # Cyrillic small letter o
    '\u0440': 'p',  # Cyrillic small letter er
    '\u0445': 'x',  # Cyrillic small letter ha
    '\u0443': 'y',  # Cyrillic small letter u
    '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
}

PROTECTED_EXECUTIVE_ROLES = [
    "admin",
    "administrator",
    "root",
    "security",
    "support",
    "ceo",
    "cto",
    "ciso",
    "it-support",
    "compliance",
]


def normalize_homoglyphs(text: str) -> str:
    """Normalize common leetspeak substitutions and homoglyphs into canonical latin characters."""
    normalized = text.lower()
    for source, target in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(source, target)
    normalized = re.sub(r'[\._\-\s]+', '', normalized)
    return normalized


def compute_similarity_ratio(s1: str, s2: str) -> float:
    """Computes normalized similarity ratio based on edit distance relative to length."""
    if s1 == s2:
        return 1.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 0.0
    dist = levenshtein_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))


class ImpersonationService:
    """Detects brand, employee, and executive identity impersonation attempts."""

    @staticmethod
    def check_identity(
        candidate_name: str,
        candidate_email: Optional[str] = None,
        target_identities: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        name_clean = candidate_name.strip()
        norm_candidate = normalize_homoglyphs(name_clean)

        findings: List[str] = []
        highest_similarity = 0.0
        most_similar_target: Optional[Dict[str, str]] = None

        targets = target_identities or [
            {"name": "Administrator", "email": "admin@sentinel.internal", "role": "Admin"},
            {"name": "Security Operations", "email": "secops@sentinel.internal", "role": "Security Analyst"},
            {"name": "Chief Information Officer", "email": "ciso@sentinel.internal", "role": "Executive"},
            {"name": "IT Helpdesk", "email": "helpdesk@sentinel.internal", "role": "Support"},
        ]

        # 1. Check executive/system role impersonation in candidate string
        for role in PROTECTED_EXECUTIVE_ROLES:
            # Check if role keyword is explicitly present as an isolated token or dominant stem
            tokens = re.split(r'[\s._\-0-9]+', name_clean.lower())
            if role in tokens:
                findings.append(f"Candidate identity contains protected executive/system keyword '{role}'")
                highest_similarity = max(highest_similarity, 0.85)

        # 2. Check Unicode / Cyrillic homoglyph usage
        homoglyphs_found = [c for c in candidate_name if c in HOMOGLYPH_MAP and ord(c) > 127]
        if homoglyphs_found:
            findings.append(f"Visual Unicode homoglyphs detected in candidate string: {', '.join(set(homoglyphs_found))}")
            highest_similarity = max(highest_similarity, 0.80)

        # 3. Compare with known corporate targets
        for target in targets:
            target_name = target.get("name", "")
            target_email = target.get("email", "")
            norm_target = normalize_homoglyphs(target_name)

            sim_ratio = compute_similarity_ratio(norm_candidate, norm_target)
            dist = levenshtein_distance(norm_candidate, norm_target)

            # Exact match via leetspeak / homoglyphs
            if dist == 0 and candidate_name.lower() != target_name.lower():
                findings.append(f"Exact phonetic/homoglyphic spoofing of target '{target_name}'")
                highest_similarity = max(highest_similarity, 0.95)
                most_similar_target = target
            # 1-character typo or substitution
            elif dist == 1 and len(norm_target) >= 4:
                findings.append(f"High-confidence 1-character typo/lookalike of target '{target_name}'")
                highest_similarity = max(highest_similarity, 0.88)
                most_similar_target = target
            # 2-character typo for longer names
            elif dist == 2 and len(norm_target) >= 7 and sim_ratio >= 0.75:
                findings.append(f"High structural similarity to protected target '{target_name}'")
                highest_similarity = max(highest_similarity, 0.70)
                most_similar_target = target

            # Email domain check if candidate email is provided
            if candidate_email and target_email and "@" in candidate_email and "@" in target_email:
                cand_domain = candidate_email.split("@")[1].lower()
                target_domain = target_email.split("@")[1].lower()
                if cand_domain != target_domain:
                    domain_dist = levenshtein_distance(cand_domain, target_domain)
                    if domain_dist in (1, 2) and len(target_domain) >= 6:
                        findings.append(f"Email domain '{cand_domain}' typosquats target domain '{target_domain}'")
                        highest_similarity = max(highest_similarity, 0.85)
                        most_similar_target = target

        # Calculate final risk score from verified similarity
        risk_score = int(round(highest_similarity * 100))

        if risk_score >= 80:
            severity = "Critical"
            explanation = "Candidate demonstrates clear signs of targeted identity spoofing or homoglyph impersonation."
        elif risk_score >= 60:
            severity = "High"
            explanation = "High similarity to protected executive identity or organization domain."
        elif risk_score >= 30:
            severity = "Medium"
            explanation = "Moderate structural similarity detected; manual review recommended."
        else:
            severity = "Low"
            explanation = "No substantial identity collision or deceptive characters detected."
            if not findings:
                findings.append("Identity appears distinct from monitored targets.")

        return {
            "candidate_name": candidate_name,
            "candidate_email": candidate_email,
            "similarity_score": round(highest_similarity, 3),
            "risk_score": risk_score,
            "severity": severity,
            "matched_target": most_similar_target,
            "findings": findings,
            "explanation": explanation,
            "checked_at": timestamp,
        }
