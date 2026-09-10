# 🛡️ IP Threat Intelligence Analyzer

An automated Threat Intelligence tool written in Python that reads network/security log files or list files (`ips.txt`), automatically extracts unique IPv4 addresses using Regex, queries public Threat Intelligence APIs (**AbuseIPDB**, **VirusTotal**, and **AlienVault OTX**), correlates threat metrics, and generates an ordered risk assessment report in **JSON** and **CSV** formats.

---

## 📌 Features

- **Automated Log Parsing & Regex Extraction**:
  - Automatically extracts IPv4 addresses directly from raw log files or plain list files (`ips.txt`).
  - Deduplicates addresses and filters out private/loopback ranges (`127.x.x.x`, `10.x.x.x`, `192.168.x.x`).
- **Multi-Source Intelligence Collection**:
  - **AbuseIPDB**: Retrieves abuse confidence score and country of origin.
  - **VirusTotal**: Fetches engine detection ratios (malicious/suspicious vs. total).
  - **AlienVault OTX**: Queries active threat pulses referencing the IP indicator.
- **Risk Scoring Engine**: Calculates a normalized `overall_risk_score` (0–100) using a weighted average algorithm across all integrated sources.
- **Geolocation Resolution**: Identifies the IP's country of origin.
- **Automated Ranking**: Orders results from highest risk (most dangerous) to lowest risk.
- **Dual Export Options**: Saves output seamlessly in both **JSON** (structured/nested) and **CSV** (flat/spreadsheet-ready) formats.
- **Rate-Limit Safe**: Configured with smart delays to respect free API tier constraints.

---

## 🏗️ Project Architecture

```plain
                  ┌──────────────────────┐
                  │ ips.txt / Log File   │
                  │  (Raw Network Logs)  │
                  └──────────┬───────────┘
                             │
                             ▼
             ┌───────────────────────────────┐
             │ Regex Extractor & Filter      │
             │  (Extracts & Deduplicates)    │
             └───────────────┬───────────────┘
                             │
                             ▼
             ┌───────────────────────────────┐
             │    ip_threat_intel.py         │
             └───────┬───────┬───────┬───────┘
                     │       │       │
       ┌─────────────┘       │       └─────────────┐
       ▼                     ▼                     ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  AbuseIPDB   │     │  VirusTotal  │     │  AlienVault OTX  │
│     API      │     │     API      │     │       API        │
└──────┬───────┘     └──────┬───────┘     └────────┬─────────┘
       │                    │                      │
       └─────────────┬──────┴──────────────────────┘
                     │
                     ▼
             ┌───────────────────────────────┐
             │ Risk Scoring & Data Merging   │
             └───────────────┬───────────────┘
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
┌───────────────────────┐         ┌───────────────────────┐
│ threat_intel_report   │         │ threat_intel_report   │
│        .json          │         │        .csv           │
└───────────────────────┘         └───────────────────────┘