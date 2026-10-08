import re

class NetworkDetector:
    @staticmethod
    def run(dex_strings):
        findings = []
        urls = set()
        cleartext_endpoints = set()

        url_regex = re.compile(r"https?://[a-zA-Z0-9\.\-_/]+", re.IGNORECASE)
        ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

        for s in dex_strings:
            for match in url_regex.findall(s):
                if not match.startswith(("http://schemas.android.com", "http://www.w3.org")):
                    urls.add(match)
                    if match.startswith("http://"):
                        cleartext_endpoints.add(match)

        if cleartext_endpoints:
            findings.append({
                "rule_id": "MASVS-NETWORK-1",
                "title": f"Hardcoded Cleartext HTTP Endpoints ({len(cleartext_endpoints)} found)",
                "severity": "HIGH",
                "cwe": "CWE-319",
                "description": f"Bytecode contains unencrypted HTTP traffic endpoints: {list(cleartext_endpoints)[:3]}"
            })

        return findings, list(urls)
