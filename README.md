# splunk-security-labs

This repository contains my Splunk work from TryHackMe labs: sample data, configuration examples, SPL queries, dashboards, and notes. Use this repo to reproduce key parts of the exercises, or as a reference for building Splunk detection/use-case workflows.

## What’s included
- `data/` — sample log files used for ingestion and testing
- `configs/` — sample `inputs.conf`, `props.conf` / `transforms.conf` examples for field extraction
- `spl/` — curated SPL queries and alert definitions with explanations
- `spl/dashboards/` — exported dashboard JSON + panel descriptions
- `screenshots/` — dashboard previews and query screenshots
- `NOTES.md` — my summary, lessons learned, and improvement ideas

## Highlights / Key use-cases
- Ingested web and security logs, normalized fields (IP, user, status, URI).
- Created SPL searches for:
  - Failed logins & brute force indicators
  - High request rates from single IPs (possible DDoS / scraping)
  - Suspicious process creation / malware indicators
- Built a correlation dashboard for incident triage with drill-down panels.
- Implemented threshold-based alerts and example alert actions.

## How to reproduce (overview)
1. Start a Splunk instance (Splunk Enterprise or Splunk Cloud trial).
2. Upload `data/*.log` via Monitoring Console or `Add Data`.
3. Apply example configs from `configs/` if using Splunk forwarders or local props/transforms.
4. Import `spl/dashboards/dashboard.json` or recreate panels using provided SPL in `spl/searches.md`.
5. Run searches and adjust time ranges as needed.

