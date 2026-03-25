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
- An **Azure Monitor Workbook** for live coverage, gap analysis, event volume, retention posture, and detection rule health

Whether you are building a new Sentinel deployment, validating an existing one against the ACSC framework, or preparing for an Australian government security assessment, this guide gives you the complete connector and table mapping — and a ready-to-deploy dashboard — in one place.

---

## Key Documents

| File | Description |
|------|-------------|
| [acsc-priority-logs-sentinel-xdr-mapping.md](acsc-priority-logs-sentinel-xdr-mapping.md) | Full mapping across all 14 ACSC priority log categories with tables, connectors, KQL validation queries, and coverage ratings |
| [acsc-priority-logs-coverage.workbook](acsc-priority-logs-coverage.workbook) | Azure Monitor Workbook JSON — import directly into Microsoft Sentinel for a live coverage dashboard |
| [deploy-acsc-workbook.json](deploy-acsc-workbook.json) | ARM template for automated workbook deployment via Azure CLI or Azure DevOps |
| [workbook_deployment.md](workbook_deployment.md) | Standalone workbook deployment guide (content also merged below) |

---

## Coverage at a Glance

Coverage percentages are **data-driven** using the formula:

> **Coverage % = (Full + Partial × 0.5) / Total sub-requirements × 100**

Across all 14 categories: **113 total ACSC sub-requirements** — 88 fully covered, 25 partially covered, 0 gaps — giving a **weighted average of 89%**. See the [Partial Coverage Notes](#partial-coverage-notes) table below for every sub-requirement that scored Partial and the specific action needed to close the gap.

| # | ACSC Priority Log Category | Microsoft 1P Coverage | Full | Partial | Total | Coverage |
|---|---|---|:---:|:---:|:---:|---|
| 1 | EDR Logs | Full — Microsoft Defender for Endpoint | — | — | — | █████████░ 93% |
| 2 | Network Device Logs | Partial — Azure Firewall, NSG, WAF native; 3P for Palo Alto, Fortinet, Cisco, Check Point, Zscaler | — | — | — | █████████░ 88% |
| 3 | Domain Controller Logs | Full — Windows Security Events + Defender for Identity | — | — | — | █████████░ 89% |
| 4 | AD & Domain Service Security | Full — Windows Security Events + Defender for Identity | — | — | — | ██████████ 100% |
| 5 | Windows Endpoint Logs | Full — Windows Security Events + MDE | — | — | — | ██████████ 100% |
| 6 | Virtualisation System Logs | Partial — Azure Activity (Azure VMs); 3P for VMware, Citrix | — | — | — | ███████░░░ 70% |
| 7 | OT Logging | Good — Microsoft Defender for IoT; 3P for Claroty, Nozomi, Dragos | — | — | — | ████████░░ 75% |
| 8 | Cloud Platform Logging | Full — Azure/M365 native; Good — AWS, GCP connectors | — | — | — | █████████░ 97% |
| 9 | Container Logs | Full — AKS native + Defender for Containers | — | — | — | ██████████ 100% |
| 10 | Database Logs | Good — Azure SQL/PaaS native; 3P for Oracle, MongoDB, on-prem PostgreSQL | — | — | — | ████████░░ 80% |
| 11 | MDM | Good — Intune + MDE Mobile; 3P for Jamf, Zimperium, Lookout | — | — | — | █████████░ 92% |
| 12 | DNS Server Logs | Full — Windows Server DNS + MDE endpoint DNS | — | — | — | ██████████ 100% |
| 13 | Linux Endpoint Logs | Good — Syslog via AMA + MDE Linux + Sysmon for Linux | — | — | — | ████████░░ 83% |
| 14 | Apple macOS Endpoint Logs | Good — MDE macOS; 3P for NXLog BSM, Jamf Protect | — | — | — | ██████░░░░ 67% |
| | **Overall** | **89% weighted average · 113 sub-requirements · 88 full · 25 partial · 0 gaps** | | | | **█████████░ 89%** |

---

## Partial Coverage Notes

The table below lists every sub-requirement that scored **Partial** and the specific action needed to reach Full coverage. These are the targeted gaps to close.

| # | Category | Sub-requirement | Why Partial | Action to Close Gap |
|---|---|---|---|---|
| 1 | EDR Logs | Browser History (typed URLs) | MDE captures `BrowserLaunchedToOpenUrl` events only; full browser history requires investigation package or web content filtering | Enable Defender for Endpoint web content filtering; use Live Response investigation package for forensic browser history |
| 1 | EDR Logs | LNK files, Shellbags, ShimCache, BAM | LNK creation in `DeviceFileEvents`; deep forensic artefacts (ShimCache, BAM, Shellbags) not in streaming telemetry | Collect via Live Response investigation package or deploy a third-party forensic collector (e.g. Velociraptor) |
| 2 | Network Device Logs | Core/border router & switch logs | Generic Syslog ingestion; no structured parsing or dedicated solution for most router/switch vendors | Deploy a vendor-specific Syslog parser DCR or use a third-party network observability tool (e.g. Corelight, Gigamon) |
| 2 | Network Device Logs | NetFlow (ingress/egress per subnet) | NetFlow is not natively ingested by Sentinel; requires a collector appliance | Deploy a NetFlow collector (e.g. Corelight, nProbe) that converts to Syslog/CEF or a custom table via DCR |
| 3 | Domain Controller Logs | AD FS event IDs (307, 510, 1007, 1200, 1202) | Requires custom Windows Event Forwarding from AD FS servers; not collected by default AMA DCR | Deploy AMA on AD FS servers with a custom DCR targeting the AD FS admin/audit event logs |
| 3 | Domain Controller Logs | LSASS protection events (3033, 3063) | Limited OOTB detection; requires LSA protection mode enabled on DCs | Enable LSA protection (RunAsPPL) via GPO; add a custom DCR to forward System log events 3033/3063 |
| 3 | Domain Controller Logs | Unsigned LDAP bind events (2889) | Requires Directory Services diagnostic logging enabled on each DC | Enable LDAP interface events logging (`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics`) and forward via AMA |
| 6 | Virtualisation | Non-Azure hypervisors (VMware, Citrix) | Requires 3P Content Hub solution and Syslog/CEF configuration on each hypervisor | Install `VMWareESXi` and/or `Citrix ADC`/`Citrix Analytics for Security` Content Hub solutions; configure Syslog forwarding |
| 8 | Cloud Platform Logging | Entra Connect sync events (611, 650–657) | `AADProvisioningLogs` ingested natively but Entra Connect server Application/Security event IDs require AMA on the Connect server | Deploy AMA on the Entra Connect server with a DCR capturing Application and Security logs targeting event IDs 611, 650–657 |
| 11 | MDM | Wi-Fi / cellular connection event detail | Intune provides device compliance and policy status but does not stream per-connection Wi-Fi/cellular telemetry | Use MDE Network Protection events (`DeviceNetworkEvents`) or a dedicated MDM/UEM solution with network telemetry (e.g. Jamf) |
| 13 | Linux Endpoint Logs | File access denied events | auditd SYSCALL denied events require auditd rules deployed and forwarding via rsyslog/AMA; not enabled by default | Deploy auditd rules for file access monitoring and configure AMA to forward the audit log |
| 13 | Linux Endpoint Logs | Recon tool detection (ncat, nmap, netcat) | Relies on Syslog process names; MDE on Linux provides richer coverage but agent deployment is required | Deploy MDE for Linux agent to get `DeviceProcessEvents` and `DeviceNetworkEvents` for all Linux hosts |
| 14 | macOS Endpoint Logs | Keychain access events | Keychain events are not captured by MDE telemetry | Requires Apple BSM audit trail via NXLog BSM macOS connector or a custom `auditpipe` collector |
| 14 | macOS Endpoint Logs | Volume mount/unmount events | MDE `ActionType` coverage for volume events is limited on macOS | Deploy NXLog BSM macOS connector for full BSM event coverage including volume events |
| 14 | macOS Endpoint Logs | Full CLI (Terminal) audit trail | MDE captures process creation but does not provide shell history equivalent | Deploy NXLog BSM macOS for OpenBSM audit trail covering all Terminal command execution |

---

## Coverage & Posture Workbook

The [`acsc-priority-logs-coverage.workbook`](acsc-priority-logs-coverage.workbook) file is an **Azure Monitor Workbook** that provides a live dashboard inside Microsoft Sentinel, automatically querying your Log Analytics workspace to show real-time ACSC coverage posture.

### Workbook Tabs

| Tab | What it Shows | Key Metrics |
|-----|---------------|-------------|
| **Overview** | Summary tiles and per-category status table | Coverage %, active tables, total events, total data size |
| **Coverage Heatmap** | Category-level coverage with Full/Partial/No Data status | Expected vs active tables, data volume per category, daily ingestion trend |
| **Event Volume & Size** | Per-table breakdown of event counts and billable data | Total size (MB/GB), days reporting, avg daily volume, est. monthly cost proxy |
| **Retention & Freshness** | Data age per table vs ACSC recommendations | Last event time, hours since last event, retention window, gap to 18-month target |
| **Gap Analysis** | Missing tables, silent connectors, unmapped data | Tables with no data, connectors that stopped sending, data outside ACSC mapping |
| **Detection Posture** | Analytics rule coverage per ACSC category | Alert counts by product/severity, rule health/drift status, coverage recommendations |

### Deployment Options

#### Option 1: Import via Azure Portal (Recommended)

1. Navigate to **Microsoft Sentinel** → **Workbooks** → **Add workbook**
2. Click **Advanced Editor** (the `</>` icon in the toolbar)
3. Delete the default JSON
4. Paste the contents of [`acsc-priority-logs-coverage.workbook`](acsc-priority-logs-coverage.workbook)
5. Click **Apply** → **Done Editing** → **Save**
6. Name it: `ACSC Priority Logs — Coverage & Posture`
7. Save to the resource group containing your Sentinel workspace

#### Option 2: Import via Defender Portal

1. Navigate to **security.microsoft.com** → **Microsoft Sentinel** → **Threat Management** → **Workbooks**
2. Click **Add workbook** → **Advanced Editor**
3. Paste the workbook JSON
4. Click **Apply** → **Save**

#### Option 3: ARM Template Deployment

```bash
# Replace with your values
SUBSCRIPTION_ID="your-subscription-id"
RESOURCE_GROUP="your-sentinel-rg"
WORKSPACE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/your-workspace"

az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --template-file deploy-acsc-workbook.json \
  --parameters workspaceResourceId="$WORKSPACE_ID"
```

> **Note**: The ARM template deploys a placeholder workbook. After deployment, open the workbook in the portal and paste the full JSON from `acsc-priority-logs-coverage.workbook` via the Advanced Editor.

### Workbook Customisation

#### Adding Custom Tables

The workbook uses inline `datatable()` mappings to associate tables with ACSC categories. To add a table:

1. Open the workbook in edit mode
2. Find the `ACSCMapping` datatable in any query
3. Add a row: `'YourTableName','CategoryNumber. Category Name',Priority,`
4. Save

Example — adding CrowdStrike:
```kql
'CrowdStrikeReplicatorV2_CL','1. EDR',1,
```

#### Adding Custom ACSC Categories

If your organisation tracks additional log categories (e.g. "15. PAM Logs"), add them to:
1. The `ACSCMapping` datatable in each query
2. The `AllCategories` datatable in the overview queries
3. The `ACSCExpected` datatable in the gap analysis query

#### Adjusting Retention Targets

The retention tab uses these defaults based on ACSC guidance:
- **18 months (547 days)** for priority 1–5 categories
- **12 months (365 days)** for priority 6–14 categories

To adjust, modify the `ACSCRetention` datatable in the Retention tab queries.

### Workbook Table Mapping Reference

The following tables are pre-mapped in the workbook:

| ACSC # | Category | Mapped Tables |
|--------|----------|--------------|
| 1 | EDR | `DeviceProcessEvents`, `DeviceEvents`, `DeviceNetworkEvents`, `DeviceImageLoadEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceInfo`, `DeviceLogonEvents` |
| 2 | Network | `CommonSecurityLog`, `AZFWNetworkRule`, `AZFWApplicationRule`, `AZFWThreatIntel`, `WindowsFirewall`, `AzureNetworkAnalytics_CL`, `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` |
| 3 | DC | `SecurityEvent`, `WindowsEvent`, `IdentityLogonEvents`, `IdentityDirectoryEvents` |
| 4 | AD Security | `IdentityQueryEvents` + (`SecurityEvent`, `IdentityDirectoryEvents` shared with #3) |
| 5 | Windows Endpoint | `Event` + (`SecurityEvent` shared with #3) |
| 6 | Virtualisation | `AzureActivity` |
| 7 | OT | `SecurityAlert` (IoT product filter) |
| 8 | Cloud | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADManagedIdentitySignInLogs`, `AADServicePrincipalSignInLogs`, `AuditLogs`, `ADFSSignInLogs`, `AADProvisioningLogs`, `AzureDiagnostics`, `StorageBlobLogs`, `OfficeActivity`, `AWSCloudTrail` |
| 9 | Container | `ContainerLog`, `ContainerLogV2`, `KubeAuditLogs`, `ContainerInventory` |
| 10 | Database | `AzureDiagnostics` with SQL category filter (shared with #8) |
| 11 | MDM | `IntuneAuditLogs`, `IntuneOperationalLogs`, `IntuneDevices` |
| 12 | DNS | `DnsEvents`, `DnsInventory` |
| 13 | Linux | `Syslog` |
| 14 | macOS | `DeviceProcessEvents`, `DeviceFileEvents` (shared with #1, filtered by `OSPlatform == "macOS"`) |

> **Shared tables note**: Some tables (e.g. `SecurityEvent`, `AzureDiagnostics`, `Device*`) cover multiple ACSC categories. The workbook maps them to their primary category. Use KQL filters like `OSPlatform == "macOS"` or `EventID in (...)` to drill into specific sub-categories.

---

## How to Use This Mapping

### 1. Identify your priority gaps

Start with the coverage table above. Microsoft's first-party (1P) solutions deliver full or near-full coverage for the highest-priority categories (EDR, Domain Controllers, Cloud Platform). Categories 6 (Virtualisation) and 14 (macOS) have the most third-party dependencies. Consult the [Partial Coverage Notes](#partial-coverage-notes) table to find the exact sub-requirements still requiring action.

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

### Mapping Guide
- **Microsoft Sentinel** workspace (Log Analytics)
- **Microsoft Defender XDR** unified portal access
- Appropriate Microsoft 365 / Azure licensing for each product (MDE, Defender for Identity, Defender for Office 365, Defender for IoT, Intune)
- Azure Monitor Agent (AMA) deployed on Windows/Linux endpoints for custom log collection
- Third-party Content Hub solutions installed for non-Microsoft security tools

### Workbook
- Microsoft Sentinel workspace with the **Unified Security Operations Platform** (Defender portal) or classic Sentinel
- **Reader** permissions on the Log Analytics workspace
- Data connectors deployed and actively ingesting data for the ACSC categories you want to track (the workbook reflects real telemetry — categories with no connector will show as gaps)

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
