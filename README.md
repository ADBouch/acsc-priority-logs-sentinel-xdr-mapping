# Microsoft Sentinel & Defender XDR — ACSC Priority Logs Mapping Guide

> **Audience**: SOC Engineers · Security Architects · Sentinel Administrators · Compliance Teams  
> **Regulatory basis**: [ASD/ACSC — Priority logs for SIEM ingestion: Practitioner guidance](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/implementing-siem-soar-platforms/priority-logs-for-siem-ingestion-practitioner-guidance) (May 2025)

---

## What is this?

The Australian Signals Directorate (ASD) / Australian Cyber Security Centre (ACSC) publishes a prioritised list of 14 log categories that organisations should ingest into a Security Information and Event Management (SIEM) platform. This repository provides a **practitioner-ready mapping** of every ACSC log category to:

- **Microsoft Sentinel** Log Analytics tables
- **Microsoft Defender XDR** Advanced Hunting tables
- Data connectors and **Content Hub solutions**
- Out-of-the-box (OOTB) analytics rules
- **KQL validation queries** to confirm data is flowing

Whether you are building a new Sentinel deployment, validating an existing one against the ACSC framework, or preparing for an Australian government security assessment, this guide gives you the complete connector and table mapping in one place.

---

## Key Documents

| File | Description |
|------|-------------|
| [acsc-priority-logs-sentinel-xdr-mapping.md](acsc-priority-logs-sentinel-xdr-mapping.md) | Full mapping across all 14 ACSC priority log categories with tables, connectors, KQL validation queries, and coverage ratings |

---

## Coverage at a Glance

| # | ACSC Priority Log Category | Microsoft 1P Coverage | Coverage Level |
|---|---|---|---|
| 1 | EDR Logs | Full — Microsoft Defender for Endpoint | ██████████ 100% |
| 2 | Network Device Logs | Partial — Azure Firewall, NSG, WAF native; 3P connectors for Palo Alto, Fortinet, Cisco, Check Point, Zscaler | ████████░░ 80% |
| 3 | Domain Controller Logs | Full — Windows Security Events + Defender for Identity | ██████████ 100% |
| 4 | AD & Domain Service Security | Full — Windows Security Events + Defender for Identity | ██████████ 100% |
| 5 | Windows Endpoint Logs | Full — Windows Security Events + MDE | ██████████ 100% |
| 6 | Virtualisation System Logs | Partial — Azure Activity (Azure VMs); 3P connectors for VMware, Citrix | ██████░░░░ 60% |
| 7 | OT Logging | Good — Microsoft Defender for IoT; 3P connectors for Claroty, Nozomi, Dragos | ████████░░ 75% |
| 8 | Cloud Platform Logging | Full — Azure/M365 native; Good — AWS, GCP connectors | █████████░ 95% |
| 9 | Container Logs | Full — AKS native + Defender for Containers | ██████████ 100% |
| 10 | Database Logs | Good — Azure SQL/PaaS native; 3P for Oracle, MongoDB, on-prem PostgreSQL | ████████░░ 80% |
| 11 | MDM | Good — Intune + MDE Mobile; 3P for Jamf, Zimperium, Lookout | ████████░░ 80% |
| 12 | DNS Server Logs | Full — Windows Server DNS + MDE endpoint DNS | ██████████ 100% |
| 13 | Linux Endpoint Logs | Good — Syslog via AMA + MDE Linux + Sysmon for Linux | ████████░░ 85% |
| 14 | Apple macOS Endpoint Logs | Good — MDE macOS; 3P for NXLog BSM, Jamf Protect | ███████░░░ 75% |

---

## How to Use This Mapping

### 1. Identify your priority gaps

Start with the coverage table above. Microsoft's first-party (1P) solutions deliver full or near-full coverage for the highest-priority categories (EDR, Domain Controllers, Cloud Platform). Categories 6, 7, and 14 require either third-party connectors or additional custom data collection rules (DCRs).

### 2. Deploy the right data connectors

For each category you need to cover, the mapping document identifies:
- **1P Native** — data flows automatically when the Microsoft product (e.g. MDE, Entra ID) is licensed and connected
- **1P Solution** — deploy from Microsoft Sentinel Content Hub (e.g. Windows Security Events, DNS)
- **3P Solution** — install the relevant third-party Content Hub solution (e.g. Palo Alto PAN-OS for firewall logs)
- **Custom** — requires a custom DCR via Azure Monitor Agent or a third-party NetFlow/syslog collector

### 3. Validate with KQL

Every row in the mapping includes a **KQL Validation** query you can run directly in Microsoft Sentinel (Log Analytics) or Defender XDR Advanced Hunting to confirm that events are flowing. Run these after enabling each connector.

### 4. Understand the table column meanings

| Column | Description |
|--------|-------------|
| **ACSC Log Requirement** | The specific log type from the ACSC guidance |
| **Microsoft Table(s)** | Sentinel Log Analytics or XDR Advanced Hunting table |
| **Source Type** | `1P Native`, `1P Solution`, `3P Solution`, or `Custom` |
| **Connector / Solution** | The specific data connector or Content Hub solution name |
| **OOTB Detections** | Whether out-of-the-box analytics rules ship with the solution |
| **KQL Validation** | A query to confirm events are being ingested |
| **Mapping Notes** | How this maps to the ACSC requirement and any caveats |
| **Reference** | Microsoft Learn schema/connector page link |

---

## ACSC Log Categories — Quick Links

1. [EDR Logs](acsc-priority-logs-sentinel-xdr-mapping.md#1-endpoint-detection-and-response-edr-logs)
2. [Network Device Logs](acsc-priority-logs-sentinel-xdr-mapping.md#2-network-device-logs)
3. [Domain Controller Logs](acsc-priority-logs-sentinel-xdr-mapping.md#3-microsoft-domain-controller-logs)
4. [AD & Domain Service Security Logs](acsc-priority-logs-sentinel-xdr-mapping.md#4-active-directory-and-domain-service-security-logs)
5. [Windows Endpoint Logs](acsc-priority-logs-sentinel-xdr-mapping.md#5-microsoft-windows-endpoint-logs)
6. [Virtualisation System Logs](acsc-priority-logs-sentinel-xdr-mapping.md#6-virtualisation-system-logs)
7. [OT Logging](acsc-priority-logs-sentinel-xdr-mapping.md#7-operational-technology-ot-logging)
8. [Cloud Platform Logging](acsc-priority-logs-sentinel-xdr-mapping.md#8-cloud-platform-logging)
9. [Container Logs](acsc-priority-logs-sentinel-xdr-mapping.md#9-container-logs)
10. [Database Logs](acsc-priority-logs-sentinel-xdr-mapping.md#10-database-logs)
11. [MDM Logs](acsc-priority-logs-sentinel-xdr-mapping.md#11-mobile-device-management-mdm)
12. [Windows DNS Server Logs](acsc-priority-logs-sentinel-xdr-mapping.md#12-windows-dns-server-analytic-event-logs)
13. [Linux Endpoint Logs](acsc-priority-logs-sentinel-xdr-mapping.md#13-linux-endpoint-auditing-logs)
14. [Apple macOS Endpoint Logs](acsc-priority-logs-sentinel-xdr-mapping.md#14-apple-macos-endpoint-logs)

---

## Prerequisites

- **Microsoft Sentinel** workspace (Log Analytics)
- **Microsoft Defender XDR** unified portal access
- Appropriate Microsoft 365 / Azure licensing for each product (MDE, Defender for Identity, Defender for Office 365, Defender for IoT, Intune)
- Azure Monitor Agent (AMA) deployed on Windows/Linux endpoints for custom log collection
- Third-party Content Hub solutions installed for non-Microsoft security tools

---

## Glossary

| Term | Meaning |
|------|---------|
| **ACSC** | Australian Cyber Security Centre |
| **ASD** | Australian Signals Directorate |
| **AMA** | Azure Monitor Agent |
| **DCR** | Data Collection Rule |
| **MDE** | Microsoft Defender for Endpoint |
| **MDI** | Microsoft Defender for Identity |
| **MDO** | Microsoft Defender for Office 365 |
| **OOTB** | Out of the box |
| **XDR** | Extended Detection and Response (Microsoft Defender XDR) |
| **1P Native** | First-party Microsoft data, no extra connector required |
| **1P Solution** | Microsoft Content Hub solution required |
| **3P Solution** | Third-party Content Hub solution required |
| **KQL** | Kusto Query Language (used in Sentinel and XDR Advanced Hunting) |

---

## References

- [ASD/ACSC — Priority logs for SIEM ingestion: Practitioner guidance](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/implementing-siem-soar-platforms/priority-logs-for-siem-ingestion-practitioner-guidance)
- [ASD/ACSC — Best practices for event logging and threat detection](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/best-practices-event-logging-threat-detection)
- [ASD/ACSC — Detecting and mitigating Active Directory compromises](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/detecting-and-mitigating-active-directory-compromises)
- [Microsoft Sentinel Content Hub Solutions](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions)
- [Microsoft Sentinel Content Hub Catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog)
- [Microsoft Sentinel Data Connectors Reference](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference)
- [Defender XDR Advanced Hunting Schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [Log Analytics Table Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/tables-category)

---

## Disclaimer

This document is provided for informational and guidance purposes only. Log coverage and connector availability change as Microsoft releases new features. Always verify connector and solution availability in the [Microsoft Sentinel Content Hub](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) and [Data Connectors Reference](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference) at the time of deployment. This is not an official Microsoft or ASD/ACSC publication.
