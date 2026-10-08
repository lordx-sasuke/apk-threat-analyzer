# APK Threat Intelligence & Malware Analysis Platform

A modular static application security testing (SAST) framework designed to ingest raw Android APK binaries, extract compiled DEX bytecode, and identify hardcoded secrets, network IOCs, and insecure cryptographic implementations. 

## Architecture
This tool abandons the monolithic script approach for a scalable, modular detection engine:
*   `core/`: Handles raw APK ingestion, SHA-256 fingerprinting, and direct ZIP/DEX extraction.
*   `detectors/`: Independent analysis modules for Cryptography, Network IOCs, and High-Confidence Secrets.
*   `cli/`: Orchestrates the analysis pipeline and calculates a weighted CVSS-aligned risk severity score.

## Capabilities
*   **Direct Binary Analysis:** Parses compiled `classes.dex` strings without requiring external decompilers (e.g., JADX/Apktool).
*   **IOC Extraction:** Pulls cleartext HTTP endpoints, Firebase URLs, and IP addresses embedded in bytecode.
*   **Secret Detection:** Uses regex heuristics to identify exposed AWS keys, Google API tokens, and JWTs.
*   **Risk Correlation:** Outputs a definitive risk posture rather than arbitrary point deductions.

## Usage
`python3 cli/main.py target.apk`

