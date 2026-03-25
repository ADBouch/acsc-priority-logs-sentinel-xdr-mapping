# ACSC Priority Logs — Sentinel Workbook Deployment Guide

## Overview

This workbook provides a visual dashboard for tracking your coverage against the [ASD/ACSC Priority Logs for SIEM Ingestion](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/implementing-siem-soar-platforms/priority-logs-for-siem-ingestion-practitioner-guidance) guidance across your Microsoft Sentinel and Defender XDR environment.

## Workbook Tabs

| Tab | What it Shows | Key Metrics |
|---|---|---|
| **Overview** | Summary tiles and per-category status table | Coverage %, active tables, total events, total data size |
| **Coverage Heatmap** | Category-level coverage with Full/Partial/No Data status | Expected vs active tables, data volume per category, daily ingestion trend |
| **Event Volume & Size** | Per-table breakdown of event counts and billable data | Total size (MB/GB), days reporting, avg daily volume, est. monthly cost proxy |
| **Retention & Freshness** | Data age per table vs ACSC recommendations | Last event time, hours since last event, retention window, gap to 18-month target |
| **Gap Analysis** | Missing tables, silent connectors, unmapped data | Tables with no data, connectors that stopped sending, data outside ACSC mapping |
| **Detection Posture** | Analytics rule coverage per ACSC category | Alert counts by product/severity, rule health/drift status, coverage recommendations |

## Prerequisites

- Microsoft Sentinel workspace with the **Unified Security Operations Platform** (Defender portal) or classic Sentinel
- Reader permissions on the Log Analytics workspace
- Data connectors deployed for the ACSC categories you want to track

## Deployment Options

### Option 1: Import via Azure Portal (Recommended)

1. Navigate to **Microsoft Sentinel** → **Workbooks** → **Add workbook**
2. Click **Advanced Editor** (the `</>` icon in the toolbar)
3. Delete the default JSON
4. Paste the contents of [`acsc-priority-logs-coverage.workbook`](acsc-priority-logs-coverage.workbook)
5. Click **Apply** → **Done Editing** → **Save**
6. Name it: `ACSC Priority Logs — Coverage & Posture`
7. Save to the resource group containing your Sentinel workspace

### Option 2: Import via Defender Portal

1. Navigate to **security.microsoft.com** → **Microsoft Sentinel** → **Threat Management** → **Workbooks**
2. Click **Add workbook** → **Advanced Editor**
3. Paste the workbook JSON
4. Click **Apply** → **Save**

### Option 3: ARM Template Deployment

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

## Customisation

### Adding Custom Tables

The workbook uses inline `datatable()` mappings to associate tables with ACSC categories. To add a table:

1. Open the workbook in edit mode
2. Find the `ACSCMapping` datatable in any query
3. Add a row: `'YourTableName','CategoryNumber. Category Name',Priority,`
4. Save

Example — adding CrowdStrike:
```kql
'CrowdStrikeReplicatorV2_CL','1. EDR',1,
```

### Adding Custom ACSC Categories

If your organisation tracks additional log categories (e.g., "15. PAM Logs"), add them to:
1. The `ACSCMapping` datatable in each query
2. The `AllCategories` datatable in the overview queries
3. The `ACSCExpected` datatable in the gap analysis query

### Adjusting Retention Targets

The retention tab uses these defaults based on ACSC guidance:
- **18 months (547 days)** for priority 1–5 categories
- **12 months (365 days)** for priority 6–14 categories

To adjust, modify the `ACSCRetention` datatable in the Retention tab queries.

## ACSC Table Mapping Reference

The following tables are pre-mapped in the workbook:

| ACSC # | Category | Mapped Tables |
|---|---|---|
| 1 | EDR | DeviceProcessEvents, DeviceEvents, DeviceNetworkEvents, DeviceImageLoadEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceInfo, DeviceLogonEvents |
| 2 | Network | CommonSecurityLog, AZFWNetworkRule, AZFWApplicationRule, AZFWThreatIntel, WindowsFirewall, AzureNetworkAnalytics_CL, EmailEvents, EmailAttachmentInfo, EmailUrlInfo |
| 3 | DC | SecurityEvent, WindowsEvent, IdentityLogonEvents, IdentityDirectoryEvents |
| 4 | AD Security | IdentityQueryEvents + (SecurityEvent, IdentityDirectoryEvents shared with #3) |
| 5 | Windows Endpoint | Event + (SecurityEvent shared with #3) |
| 6 | Virtualisation | AzureActivity |
| 7 | OT | SecurityAlert (IoT product filter) |
| 8 | Cloud | SigninLogs, AADNonInteractiveUserSignInLogs, AADManagedIdentitySignInLogs, AADServicePrincipalSignInLogs, AuditLogs, ADFSSignInLogs, AADProvisioningLogs, AzureDiagnostics, StorageBlobLogs, OfficeActivity, AWSCloudTrail |
| 9 | Container | ContainerLog, ContainerLogV2, KubeAuditLogs, ContainerInventory |
| 10 | Database | (AzureDiagnostics with SQL filter — shared with #8) |
| 11 | MDM | IntuneAuditLogs, IntuneOperationalLogs, IntuneDevices |
| 12 | DNS | DnsEvents, DnsInventory |
| 13 | Linux | Syslog |
| 14 | macOS | (DeviceProcessEvents, DeviceFileEvents — shared with #1, filtered by OSPlatform) |

> **Shared tables note**: Some tables (SecurityEvent, AzureDiagnostics, Device* tables) cover multiple ACSC categories. The workbook maps them to their primary category. Use the KQL filter `OSPlatform == "macOS"` or `EventID in (...)` to drill into specific sub-categories.

## Companion Documents

- [ACSC Priority Logs — Sentinel & XDR Mapping Guide](../acsc-priority-logs-sentinel-xdr-mapping.md) — Full mapping with per-table KQL validation queries, connector names, and OOTB detection counts
- [Defender for Cloud & CrowdStrike EDR Overlap Guidance](../defender-for-cloud-crowdstrike-edr-overlap-guidance.md) — For customers running CrowdStrike alongside Microsoft

## Version History

| Date | Change |
|---|---|
| 2026-03-25 | Initial release — 6 tabs, 45 mapped tables, 14 ACSC categories |
