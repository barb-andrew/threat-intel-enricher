# Threat Intel Enricher

A clean, practical Python CLI tool for automated threat intelligence enrichment with local persistence and custom tagging.

## Project Summary

I built a Python CLI tool that takes IP addresses, enriches them using public APIs (AbuseIPDB + ip-api.com), and stores the results locally in SQLite. The tool supports custom tagging, force-refreshing data, querying/filtering, batch processing from files, and exporting results to JSON or CSV.

The goal was to reduce manual research time while building persistent, queryable profiles on indicators — similar to how real threat intelligence platforms maintain context on IPs even when they rotate. This type of work directly aligns with IP intelligence, proxy/VPN detection, and historical tracking done at Digital Envoy / Digital Element.

## Features

- Enrich single IPs with geolocation, ASN/ISP, abuse score, and usage type
- Custom tagging system (e.g. “Residential Proxy”, “Known VPN”, “Suspicious”)
- Local SQLite database with caching
- `--force` flag to bypass cache and re-query APIs
- Query and filter by IP or tag
- Batch processing from a text file
- Export to JSON or CSV
- Clean, colored terminal output using Rich

## Installation

```bash
git clone <your-repo-url>
cd threat-intel-enricher

python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Mac/Linux

pip install -r requirements.txt
