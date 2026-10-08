class CryptoAPIDetector:
    INSECURE_PATTERNS = {
        "Weak Cipher: DES/3DES": ("DES", "CRITICAL", "CWE-327", "MASVS-CRYPTO-1"),
        "Broken Hash: MD5/SHA1": ("(MD5|SHA-1)", "HIGH", "CWE-328", "MASVS-CRYPTO-1"),
        "ECB Mode Cipher": ("AES/ECB", "HIGH", "CWE-327", "MASVS-CRYPTO-1"),
        "Command Execution": ("Runtime.getRuntime().exec", "HIGH", "CWE-78", "MASVS-PLATFORM-2"),
        "Insecure WebView JS": ("setJavaScriptEnabled(true)", "MEDIUM", "CWE-749", "MASVS-PLATFORM-2"),
        "Permissive SSL TrustManager": ("TrustAllCertificates", "CRITICAL", "CWE-295", "MASVS-NETWORK-1")
    }

    @staticmethod
    def run(dex_strings):
        findings = []
        blob = " ".join(dex_strings)
        import re
        for title, (pattern, severity, cwe, rule_id) in CryptoAPIDetector.INSECURE_PATTERNS.items():
            if re.search(pattern, blob, re.IGNORECASE):
                findings.append({
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "description": f"Identified dangerous API or insecure crypto reference in bytecode."
                })
        return findings
