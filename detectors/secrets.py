import re

class SecretDetector:
    RULES = {
        "Google API Key": (r"AIza[0-9A-Za-z\\-_]{35}", "HIGH", "CWE-798"),
        "AWS Access Key ID": (r"AKIA[0-9A-Z]{16}", "CRITICAL", "CWE-798"),
        "Firebase DB Endpoint": (r"[a-z0-9\-]+\.firebaseio\.com", "MEDIUM", "CWE-200"),
        "JSON Web Token (JWT)": (r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "HIGH", "CWE-798")
    }

    @staticmethod
    def run(dex_strings):
        findings = []
        blob = " ".join(dex_strings)
        for name, (regex, severity, cwe) in SecretDetector.RULES.items():
            matches = re.findall(regex, blob)
            if matches:
                findings.append({
                    "rule_id": "MASVS-STORAGE-1",
                    "title": f"Exposed {name} ({len(matches)} instance(s))",
                    "severity": severity,
                    "cwe": cwe,
                    "description": f"Hardcoded credential/secret exposed in compiled DEX strings."
                })
        return findings
