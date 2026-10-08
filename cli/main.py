import sys
import os
import json
from datetime import datetime

# Enable relative package imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.apk import APKContainer
from core.scoring import ScoringEngine
from detectors.crypto_apis import CryptoAPIDetector
from detectors.network import NetworkDetector
from detectors.secrets import SecretDetector

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cli/main.py <target.apk>")
        sys.exit(1)

    target_path = sys.argv[1]
    if not os.path.exists(target_path):
        print(f"[-] Target {target_path} not found.")
        sys.exit(1)

    print(f"[*] Ingesting APK: {target_path}")
    apk = APKContainer(target_path)
    apk.parse()

    print(f"[*] Extracted {len(apk.dex_strings)} unique bytecode string references.")
    print("[*] Executing security detectors...")

    all_findings = []
    all_findings.extend(CryptoAPIDetector.run(apk.dex_strings))
    net_findings, urls = NetworkDetector.run(apk.dex_strings)
    all_findings.extend(net_findings)
    all_findings.extend(SecretDetector.run(apk.dex_strings))

    score, posture = ScoringEngine.calculate(all_findings)

    print("\n" + "=" * 60)
    print("     APK THREAT INTELLIGENCE & SAST ASSESSMENT     ")
    print("=" * 60)
    print(f"Target Binary:     {apk.filename}")
    print(f"SHA-256 Hash:      {apk.sha256[:20]}...")
    print(f"Threat Score:      {score} / 100")
    print(f"Risk Posture:      {posture}")
    print(f"Total Findings:    {len(all_findings)}")
    print(f"Total URLs Mapped: {len(urls)}")
    print("-" * 60)
    print(f"{'SEVERITY':<10} | {'FINDING'}")
    print("-" * 60)
    for f in all_findings:
        print(f"{f['severity']:<10} | {f['title']}")
    print("=" * 60)

    # Save automated report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"reports/sast_{apk.filename}_{ts}.json"
    with open(report_file, "w") as out:
        json.dump({
            "target": apk.filename,
            "sha256": apk.sha256,
            "score": score,
            "posture": posture,
            "findings": all_findings,
            "endpoints": urls
        }, out, indent=4)
    print(f"\n[+] Structured report generated: {report_file}")

if __name__ == "__main__":
    main()
