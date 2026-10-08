#!/usr/bin/env python3
import os
import sys
import re
import json
import zipfile
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime

class APKSecurityAnalyzer:
    def __init__(self, target_path):
        self.target_path = target_path
        self.findings = []
        self.base_score = 100
        self.metadata = {
            "package": "Unknown",
            "target_sdk": "Unknown",
            "min_sdk": "Unknown",
            "total_permissions": 0,
            "exported_components": 0
        }

    def log_finding(self, rule_id, title, severity, penalty, cwe, description):
        self.findings.append({
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "cwe": cwe,
            "description": description
        })
        self.base_score = max(0, self.base_score - penalty)

    def audit_manifest(self, manifest_content):
        try:
            root = ET.fromstring(manifest_content)
        except Exception as e:
            print(f"[-] XML parsing error: {e}")
            return

        ns = "{http://schemas.android.com/apk/res/android}"
        self.metadata["package"] = root.attrib.get("package", "Unknown")

        # 1. SDK Level Check
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            self.metadata["min_sdk"] = uses_sdk.attrib.get(f"{ns}minSdkVersion", "N/A")
            self.metadata["target_sdk"] = uses_sdk.attrib.get(f"{ns}targetSdkVersion", "N/A")

        # 2. Application Security Flags
        app = root.find("application")
        if app is not None:
            if app.attrib.get(f"{ns}debuggable") == "true":
                self.log_finding(
                    "MASVS-RESILIENCE-1",
                    "Application is Debuggable in Production",
                    "HIGH", 15, "CWE-215",
                    "android:debuggable is enabled, allowing runtime debugging and memory dumping."
                )

            if app.attrib.get(f"{ns}allowBackup") == "true":
                self.log_finding(
                    "MASVS-STORAGE-2",
                    "ADB Backup Enabled",
                    "LOW", 5, "CWE-200",
                    "android:allowBackup is true, permitting full application data extraction via ADB."
                )

            if app.attrib.get(f"{ns}usesCleartextTraffic") == "true":
                self.log_finding(
                    "MASVS-NETWORK-1",
                    "Cleartext HTTP Traffic Permitted",
                    "HIGH", 15, "CWE-319",
                    "android:usesCleartextTraffic is enabled, allowing unencrypted HTTP transmission."
                )

            # 3. Exported Components (Attack Surface)
            components = ["activity", "service", "receiver", "provider"]
            for comp_type in components:
                for item in app.findall(comp_type):
                    name = item.attrib.get(f"{ns}name", "Unknown").split(".")[-1]
                    exported = item.attrib.get(f"{ns}exported")
                    has_intent_filter = item.find("intent-filter") is not None

                    # If exported is explicitly true, or implicit export via intent-filter
                    if exported == "true" or (exported is None and has_intent_filter):
                        self.metadata["exported_components"] += 1
                        self.log_finding(
                            f"MASVS-PLATFORM-1",
                            f"Exported {comp_type.capitalize()}: {name}",
                            "MEDIUM", 4, "CWE-926",
                            f"{comp_type.capitalize()} is exposed to external application IPC triggers."
                        )

        # 4. Permission Profiler
        high_priv_perms = {
            "REQUEST_INSTALL_PACKAGES": ("HIGH", 10, "Allows silent or secondary APK installations."),
            "WRITE_EXTERNAL_STORAGE": ("MEDIUM", 5, "Grants shared public storage write access."),
            "SYSTEM_ALERT_WINDOW": ("HIGH", 10, "Allows overlay creation (clickjacking risk)."),
            "READ_SMS": ("HIGH", 10, "Access to inbound SMS messages."),
            "ACCESS_FINE_LOCATION": ("MEDIUM", 5, "Exposes precise GPS coordinates.")
        }

        perms = [p.attrib.get(f"{ns}name") for p in root.findall("uses-permission")]
        self.metadata["total_permissions"] = len(perms)

        for p in perms:
            if not p:
                continue
            short_p = p.split(".")[-1]
            if short_p in high_priv_perms:
                sev, pen, desc = high_priv_perms[short_p]
                self.log_finding(
                    "MASVS-PLATFORM-2",
                    f"High-Privilege Permission: {short_p}",
                    sev, pen, "CWE-276", desc
                )

    def scan_secrets(self, archive):
        patterns = {
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic Bearer Token": r"Bearer\s+[A-Za-z0-9\-\._~\+\/]{20,}",
            "Hardcoded Private Key": r"-----BEGIN (RSA|EC|PRIVATE) KEY-----"
        }

        for fname in archive.namelist():
            if fname.startswith("assets/") or fname.endswith((".json", ".xml", ".properties")):
                try:
                    data = archive.read(fname).decode("utf-8", errors="ignore")
                except Exception:
                    continue

                for secret_type, regex in patterns.items():
                    matches = re.findall(regex, data)
                    if matches:
                        self.log_finding(
                            "MASVS-STORAGE-1",
                            f"Hardcoded {secret_type} Detected",
                            "CRITICAL", 25, "CWE-798",
                            f"Exposed secret signature located inside: {fname}"
                        )

    def run(self):
        print(f"[*] Starting audit on: {self.target_path}")
        if os.path.isdir(self.target_path):
            manifest_path = os.path.join(self.target_path, "resources/AndroidManifest.xml")
            if not os.path.exists(manifest_path):
                manifest_path = os.path.join(self.target_path, "AndroidManifest.xml")

            if os.path.exists(manifest_path):
                with open(manifest_path, "r", encoding="utf-8") as f:
                    self.audit_manifest(f.read())
            else:
                print("[-] AndroidManifest.xml not found in directory.")
        elif zipfile.is_zipfile(self.target_path):
            with zipfile.ZipFile(self.target_path, "r") as archive:
                self.scan_secrets(archive)
                # APK files store AndroidManifest in compiled binary AXML format
                if "AndroidManifest.xml" in archive.namelist():
                    print("[*] Note: For compiled APKs, run through apktool or pass decompiled directory for full manifest parsing.")

        self.display_summary()
        self.save_reports()

    def display_summary(self):
        print("\n" + "=" * 55)
        print("          SECURITY THREAT ASSESSMENT REPORT          ")
        print("=" * 55)
        print(f"Target:             {self.metadata['package']}")
        print(f"Permissions:        {self.metadata['total_permissions']}")
        print(f"Exported IPC:       {self.metadata['exported_components']}")
        print(f"Threat Score:       {self.base_score} / 100")
        print("-" * 55)
        print(f"{'SEVERITY':<10} | {'FINDING':<40}")
        print("-" * 55)
        for f in self.findings:
            print(f"{f['severity']:<10} | {f['title'][:40]}")
        print("=" * 55 + "\n")

    def save_reports(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"reports/audit_{timestamp}.json"
        md_path = f"reports/audit_{timestamp}.md"

        # Save JSON
        report_data = {
            "metadata": self.metadata,
            "threat_score": self.base_score,
            "findings_count": len(self.findings),
            "findings": self.findings
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)

        # Save Markdown
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(f"# Mobile Threat Assessment: {self.metadata['package']}\n\n")
            f.write(f"- **Final Threat Score:** {self.base_score} / 100\n")
            f.write(f"- **Total Findings:** {len(self.findings)}\n\n")
            f.write("## Findings Detail\n\n")
            for f_item in self.findings:
                f.write(f"### [{f_item['severity']}] {f_item['title']}\n")
                f.write(f"- **Framework:** `{f_item['rule_id']}`\n")
                f.write(f"- **CWE:** `{f_item['cwe']}`\n")
                f.write(f"- **Description:** {f_item['description']}\n\n")

        print(f"[+] JSON report saved: {json_path}")
        print(f"[+] Markdown report saved: {md_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Android APK Security & Threat Assessment CLI")
    parser.add_argument("target", help="Path to decompiled APK directory or raw APK file")
    args = parser.parse_args()

    analyzer = APKSecurityAnalyzer(args.target)
    analyzer.run()
