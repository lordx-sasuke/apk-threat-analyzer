# Android APK Security Analyzer & Threat Assessment Platform

An automated static application security testing (SAST) tool designed for Android APKs, auditing entry points, component exposure, and secret leakage mapped to the OWASP MASVS standard.

## Features
- **Manifest Attack Surface Profiling:** Detects exposed Activities, Receivers, Services, and Providers (CWE-926).
- **High-Risk Permission Auditing:** Analyzes high-privilege permissions including installer requests and storage access (CWE-276).
- **Security Flag Validation:** Identifies debuggable builds, cleartext network traffic, and insecure backup policies.
- **Automated Risk Scoring:** Calculates a deterministic threat score (0–100) and exports structured JSON/Markdown reports.

## Usage
```bash
python3 apk_analyzer.py /path/to/decompiled_apk_or_folder
