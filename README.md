# AeroGuard SIEM Lab: End-to-End Threat Detection Engineering

## Overview
This lab implements an air-gapped SIEM architecture, isolating detection capabilities from external threats. Telemetry flows from a hardened Windows 10 endpoint running Sysmon, feeding encrypted logs to an Ubuntu server running the Wazuh Manager and Suricata IDS. This setup validates end-to-end detection engineering by parsing proprietary aviation telemetry and triggering verified security alerts.

## Architecture Topology
![Architecture Topology](architecture.JPG)

*Air-gapped network flow from the Windows 10 endpoint to the Ubuntu Wazuh server.*

### Telemetry Pipeline
1. **Endpoint Collection:** The Wazuh agent on the Windows 10 endpoint collects Sysmon and Windows Security Event logs, shipping them encrypted over **TCP/1514** to the Ubuntu server.
2. **Network Monitoring:** Suricata monitors local network traffic on the Ubuntu host, writing alerts to `eve.json`, which the Wazuh Logcollector ingests for correlation.
3. **Custom Decoding & Correlation:** A custom XML decoder parses proprietary **AeroGuard EFB** telemetry streams into structured fields, allowing localized rules to trigger high-priority alerts on authentication anomalies.

## Key Takeaways
* **Protocol Familiarity:** Mastery over custom XML decoding and regex optimization for non-standard telemetry.
* **Defense-in-Depth Validation:** Using controlled, non-destructive threat emulation to verify end-to-end detection logic.
* **Operational Hardening:** Balancing strict endpoint security posture with localized, process-scoped execution policies.

## Repository Structure
```text
aeroguard-siem-lab/
├── architecture/
│   └── diagram.png            # Air-gapped network topology
├── config/
│   ├── aeroguard_decoder.xml  # Custom telemetry decoders
│   └── local_rules.xml        # Correlation and alerting rules
├── scripts/
│   └── sim-test.ps1           # PowerShell threat emulation script
├── validation/
│   ├── figure_1_execution.png # Execution policy bypass evidence
│   └── figure_2_alert.png     # Wazuh Discover dashboard hit
└── README.md                  # Project overview and runbook


Deployment Runbook
To replicate this detection pipeline on an existing Wazuh Manager:

1.    Copy config/aeroguard_decoder.xml to /var/ossec/etc/decoders/.
2.    Copy config/local_rules. xml to / var/ossec/etc/rules/.
3.    Validate the configuration syntax and restart the manager:

sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager

Validation & Proof of Work
Step 1: Controlled Telemetry Generation (Windows 10)
To safely validate the detection pipeline without introducing live malware into the lab, a custom PowerShell script (C:\Tools\sim-test.ps1) emits simulated aviation telemetry:

AEROGUARD_EFB|admin|403|AUTH_FAIL|SIMULATED THREAT

When Windows blocked execution under default security settings (PSSecurityException), a process-scoped bypass was applied to run the test safely while preserving the endpoint's persistent security baseline:

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

Step 2: SIEM Ingestion & Rule Correlation (Wazuh)
Following script execution, real-time telemetry ingestion was verified inside the Wazuh Discover dashboard. The dashboard confirms active communication from the Windows 10 endpoint (Agent ID 005) to the Ubuntu Wazuh Manager and displays correlated authentication failure alerts (rule.level: 5, syslog, access_control), proving the detection pipeline operates end-to-end across the air-gapped network.
