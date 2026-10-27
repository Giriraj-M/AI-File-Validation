import re
from pathlib import Path

class SecurityService:
    """
    Performs security scans across file attributes and extracted document text.
    Detects path traversal, prompt injections, credentials, and sensitive PII.
    """

    # Prompt injection and jailbreak attack indicators commonly hidden in documents
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts)\b",
        r"(?i)\byou\s+are\s+now\s+in\s+developer\s+mode\b",
        r"(?i)\bsystem\s+override\b",
        r"(?i)\breveal\s+(the\s+)?(system\s+prompt|instructions|secret\s+key)\b",
        r"(?i)\bdo\s+anything\s+now\b",
        r"(?i)\bDAN\s+mode\b",
        r"(?i)\bdisregard\s+(the\s+)?(guardrails|guidelines|safety)\b",
        r"(?i)\bexfiltrate\s+to\b",
        r"(?i)\bdrop\s+database\b",
        r"(?i)<\s*script[^>]*>.*?</\s*script\s*>",
        r"(?i)javascript\s*:\s*",
    ]

    # Sensitive PII and Secret exposure patterns
    SENSITIVE_PATTERNS = {
        "Private Key": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
        "Generic Secret/Token": r"(?i)(api[_-]?key|secret[_-]?token|bearer\s+[a-zA-Z0-9_\-\.]{20,})",
        "Credit Card Number": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
        "Social Security Number (US)": r"\b\d{3}-\d{2}-\d{4}\b"
    }

    @classmethod
    def scan_path_safety(cls, filename: str) -> tuple[bool, str]:
        """Ensures filename contains no directory traversal sequences."""
        if not filename:
            return False, "Filename cannot be empty."
        if ".." in filename or "/" in filename or "\\" in filename:
            return False, "Dangerous path traversal characters detected."
        if filename.startswith("."):
            return False, "Hidden dot-files are not allowed."
        return True, "Filename is safe."

    @classmethod
    def scan_document_security(cls, text: str) -> dict:
        """
        Scans extracted document text for prompt injections, suspicious instructions,
        and sensitive credentials or PII.
        """
        if not text:
            return {
                "scanned": True,
                "passed": True,
                "has_prompt_injection": False,
                "injection_matches": [],
                "has_sensitive_data": False,
                "sensitive_matches": [],
                "warnings": []
            }

        warnings = []
        injection_matches = []
        sensitive_matches = []

        # 1. Prompt Injection Checks
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            found = re.findall(pattern, text)
            if found:
                match_str = found[0] if isinstance(found[0], str) else found[0][0]
                injection_matches.append(match_str)

        if injection_matches:
            warnings.append(
                "Suspicious instructional text detected inside document (potential prompt injection attempt). "
                "Document content is strictly treated as untrusted data."
            )

        # 2. Sensitive Patterns / PII Checks
        for label, pattern in cls.SENSITIVE_PATTERNS.items():
            if re.search(pattern, text):
                sensitive_matches.append(label)
                warnings.append(f"Potential sensitive information detected: {label}")

        has_prompt_injection = len(injection_matches) > 0
        has_sensitive_data = len(sensitive_matches) > 0
        passed = not has_prompt_injection

        return {
            "scanned": True,
            "passed": passed,
            "has_prompt_injection": has_prompt_injection,
            "injection_matches": injection_matches[:5],
            "has_sensitive_data": has_sensitive_data,
            "sensitive_matches": sensitive_matches,
            "warnings": warnings
        }
