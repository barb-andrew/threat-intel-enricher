# Threat Intel Enricher

A practical Python CLI tool for automated threat intelligence enrichment, local persistence, and custom tagging.

## Project Summary

I built a Python CLI tool that enriches IP addresses using public APIs (AbuseIPDB + ip-api.com), stores results in SQLite, and supports custom tagging so context persists even when infrastructure changes. It includes batch processing from files, exporting to JSON/CSV, and clean terminal output.

This type of work (IP intelligence, proxy/VPN context, persistent profiling) directly aligns with what Digital Envoy / Digital Element does.

## Features
- Single IP enrichment with geolocation, ASN/ISP, abuse score, and usage type
- Custom tagging system
- Local caching with SQLite
- `--force` flag to refresh data
- Query and filter by IP or tag
- Batch processing from a text file
- Export to JSON or CSV
- Clean, colored output using Rich

## Installation & Usage

```powershell
git clone https://github.com/barb-andrew/threat-intel-enricher.git
cd threat-intel-enricher

python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
