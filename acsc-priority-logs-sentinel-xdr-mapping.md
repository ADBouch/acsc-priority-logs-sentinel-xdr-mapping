# ACSC Priority Logs for SIEM Ingestion — Microsoft Sentinel & Defender XDR Mapping Guide

> **Source**: [ASD/ACSC — Priority logs for SIEM ingestion: Practitioner guidance](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/implementing-siem-soar-platforms/priority-logs-for-siem-ingestion-practitioner-guidance) (May 2025)
>
> **Purpose**: Maps every ACSC priority log category to Microsoft Sentinel tables, Defender XDR Advanced Hunting tables, data connectors, Content Hub solutions, and out-of-the-box (OOTB) analytics rules. Provides KQL validation queries to confirm data is flowing.
>
> **Audience**: SOC Engineers, Security Architects, Sentinel Administrators, Compliance Teams
>
> **Date**: 25 March 2026

---

## How to Use This Document

For each of the 14 ACSC priority log categories, this document provides:

| Column | Description |
|---|---|
| **ACSC Log Requirement** | The specific log type from the ACSC guidance |
| **Microsoft Table(s)** | The Sentinel Log Analytics or XDR Advanced Hunting table where this data lands |
| **Source Type** | `1P Native` = first-party Microsoft data (no extra connector needed), `1P Solution` = Microsoft Content Hub solution, `3P Solution` = third-party Content Hub solution, `Custom` = custom connector or DCR required |
| **Connector / Solution** | The specific data connector or Content Hub solution name |
| **OOTB Detections** | Whether out-of-the-box analytics rules ship with the solution (Yes/No + count where known) |
| **KQL Validation** | A query to confirm events are being ingested |
| **Mapping Notes** | How this maps to the ACSC requirement |
| **Reference** | Link to the Microsoft Learn table schema page or Content Hub solution page |

### Legend

- **XDR** = Defender XDR Advanced Hunting (security.microsoft.com)
- **Sentinel** = Microsoft Sentinel Log Analytics workspace
- Many tables appear in both planes via unified SecOps

---

## 1. Endpoint Detection and Response (EDR) Logs

**ACSC Priority**: 1 (Highest)

The ACSC EDR category covers process creation, antivirus detections, network connections, DLL loading, scheduled tasks, file events, registry, services, command history, browser history, AmCache, prefetch, shellbags, and more.

### Microsoft Defender for Endpoint (1st Party)

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Process Creation (AmCache, Prefetch) | `DeviceProcessEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes (50+) | `DeviceProcessEvents \| where TimeGenerated > ago(1h) \| summarize count() by ActionType` | Maps process creation, command lines, parent-child relationships. Covers AmCache/Prefetch forensic equivalents via InitiatingProcessFileName and SHA metadata. | [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| Antivirus — Signature, Reputational, Other | `DeviceEvents` (XDR), `SecurityAlert` (Sentinel) | 1P Native | Microsoft Defender XDR connector | Yes (20+) | `DeviceEvents \| where TimeGenerated > ago(1h) \| where ActionType has "AntivirusDetection" \| summarize count() by ActionType` | MDE AV detections flow as DeviceEvents with AntivirusDetection* ActionTypes. Alerts also surface in SecurityAlert. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| Network Connections & Ports (IPs, Protocols) | `DeviceNetworkEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes (15+) | `DeviceNetworkEvents \| where TimeGenerated > ago(1h) \| summarize count() by RemoteIPType` | Covers active/recent ports, protocols, IP connections per endpoint. | [DeviceNetworkEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| DLL Loading (Wrong path DLLs) | `DeviceImageLoadEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes (10+) | `DeviceImageLoadEvents \| where TimeGenerated > ago(1h) \| summarize count() by ActionType` | DLL/image load events including path, hash, signer. Enables DLL side-loading detection. | [DeviceImageLoadEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table) |
| Scheduled Tasks (Create, Modify) | `DeviceEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes (5+) | `DeviceEvents \| where TimeGenerated > ago(1h) \| where ActionType in ("ScheduledTaskCreated","ScheduledTaskUpdated","ScheduledTaskDeleted") \| summarize count() by ActionType` | Scheduled task creation/modification/deletion actions. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| File Events (Execution, Downloads, Access) | `DeviceFileEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes (10+) | `DeviceFileEvents \| where TimeGenerated > ago(1h) \| summarize count() by ActionType` | File create, modify, delete, rename events. Covers downloads, execution artefacts. | [DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| File System Changes (User profile) | `DeviceFileEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes | `DeviceFileEvents \| where TimeGenerated > ago(1h) \| where FolderPath has "Users" \| summarize count() by ActionType` | Profile creation, registry key and file modifications under user directories. | [DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| System Information (Hostname, OS, Timestamp) | `DeviceInfo` (XDR) | 1P Native | Microsoft Defender XDR connector | N/A | `DeviceInfo \| where TimeGenerated > ago(1d) \| summarize arg_max(TimeGenerated, *) by DeviceId \| project DeviceName, OSPlatform, OSVersion` | Device inventory with hostname, OS, processor, timezone. | [DeviceInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table) |
| DNS Cache | `DeviceNetworkEvents` (XDR), `DeviceEvents` | 1P Native | Microsoft Defender XDR connector | Yes | `DeviceEvents \| where TimeGenerated > ago(1h) \| where ActionType == "DnsQueryResponse" \| summarize count()` | DNS query and response events from endpoints. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| Windows Registry (Modifications, Hive) | `DeviceRegistryEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes (15+) | `DeviceRegistryEvents \| where TimeGenerated > ago(1h) \| summarize count() by ActionType` | Registry key create, modify, delete, rename with timestamp, path, value. | [DeviceRegistryEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) |
| Windows Services (Name, PID, Path, DLL) | `DeviceEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes | `DeviceEvents \| where TimeGenerated > ago(1h) \| where ActionType == "ServiceInstalled" \| summarize count()` | Service install events with service name, path, arguments. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| Command History | `DeviceProcessEvents` (XDR) | 1P Native | Microsoft Defender XDR connector | Yes | `DeviceProcessEvents \| where TimeGenerated > ago(1h) \| where FileName in ("cmd.exe","powershell.exe","pwsh.exe") \| summarize count()` | Command-line arguments captured in ProcessCommandLine field. | [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| Browser History (Typed URLs) | `DeviceNetworkEvents`, `DeviceEvents` | 1P Native | Microsoft Defender XDR connector | Limited | `DeviceEvents \| where TimeGenerated > ago(1h) \| where ActionType == "BrowserLaunchedToOpenUrl" \| summarize count()` | Browser URL launch events. Full browser history requires Defender for Endpoint web content filtering or investigation package. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| LNK Files, Jump Lists, BAM, Shellbags, ShimCache | `DeviceFileEvents`, `DeviceRegistryEvents` | 1P Native | Microsoft Defender XDR connector | Limited | `DeviceFileEvents \| where TimeGenerated > ago(1h) \| where FileName endswith ".lnk" \| summarize count()` | LNK creation captured in file events. Deeper forensic artefacts (ShimCache, BAM, Shellbags) require investigation package collection via Live Response. | [DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| Alternate Data Streams | `DeviceFileEvents` | 1P Native | Microsoft Defender XDR connector | Yes | `DeviceFileEvents \| where TimeGenerated > ago(1h) \| where FileName contains ":" and ActionType == "FileCreated"` | ADS creation/access events. | [DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |

### Third-Party EDR (CrowdStrike, SentinelOne, etc.)

If using a non-Microsoft EDR, the following Sentinel Content Hub solutions provide equivalent coverage:

| 3P EDR Vendor | Sentinel Solution | Table(s) | OOTB Detections | Notes | Reference |
|---|---|---|---|---|---|
| **CrowdStrike Falcon** | `CrowdStrike Falcon Endpoint Protection` | `CommonSecurityLog`, `CrowdStrike_CL`, `CrowdStrikeReplicatorV2_CL` | Yes (15+ analytics rules) | Supports Falcon Data Replicator (FDR) for full EDR telemetry. Covers process, network, DNS, file, registry events. | [CrowdStrike solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-crowdstrikefalconep?tab=Overview) |
| **SentinelOne** | `SentinelOne` | `SentinelOne_CL` | Yes (10+ analytics rules) | Ingests threats, activities, agents data. | [SentinelOne solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-sentinelone?tab=Overview) |
| **VMware Carbon Black** | `VMware Carbon Black Cloud` | `CarbonBlackEvents_CL`, `CarbonBlackNotifications_CL` | Yes (5+ analytics rules) | Cloud-delivered EDR events and alerts. | [Carbon Black solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-vmwarecarbonblack?tab=Overview) |
| **Cortex XDR** | `Cortex XDR` / `Palo Alto Cortex XDR CCP` | `PaloAltoCortexXDR_CL` | Yes (5+ analytics rules) | Incidents and alerts from Palo Alto Cortex XDR. | [Cortex XDR solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-pabortoxxdr?tab=Overview) |
| **Sophos Endpoint** | `Sophos Endpoint Protection` | `SophosEP_CL` | Yes (5+ analytics rules) | Endpoint events, threats, web events. | [Sophos solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-sophosep?tab=Overview) |
| **Trend Micro Vision One** | `Trend Micro Vision One` | `TrendMicroVisionOne_CL` | Yes (analytics rules included) | XDR alerts and workbench data. | [Trend Micro solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-trendmicrovisionone?tab=Overview) |
| **ESET** | `ESET Protect Platform` / `ESET Inspect` | `ESET_CL` | Yes | Detection and inspection events. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **WithSecure/F-Secure** | `WithSecureElementsViaConnector` | `WithSecureElements_CL` | Yes | Elements platform security events. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Symantec Endpoint** | `Symantec Endpoint Protection` | `SymantecEndpointProtection_CL` | Yes (5+ analytics rules) | SEP events via Syslog/CEF. | [Symantec solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-symantecendpointprotection?tab=Overview) |

---

## 2. Network Device Logs

**ACSC Priority**: 2

Covers firewalls (internal + border), routers/switches, IDS/IPS, application layer gateways, NAC, web proxies, VPN, and mail appliances.

### Firewall Logs

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| **Azure Firewall** (ingress/egress, denied/allowed, config changes) | `AZFWApplicationRule`, `AZFWNetworkRule`, `AZFWNatRule`, `AZFWThreatIntel`, `AZFWIdpsSignature`, `AzureDiagnostics` | 1P Native | Azure Firewall solution | Yes (10+ analytics incl. IDPS) | `AZFWNetworkRule \| where TimeGenerated > ago(1h) \| summarize count() by Action` | Native Azure firewall. Covers ingress/egress allowed/denied, IDPS alerts, config via AzureActivity. | [AZFWNetworkRule table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwnetworkrule) |
| **Palo Alto PAN-OS** | `CommonSecurityLog`, `PaloAltoNetworksThreat_CL` | 3P Solution | `PaloAlto-PAN-OS` | Yes (20+ analytics rules) | `CommonSecurityLog \| where TimeGenerated > ago(1h) \| where DeviceVendor == "Palo Alto Networks" \| summarize count() by Activity` | CEF-based ingestion. Covers traffic, threat, system, config logs. | [Palo Alto PAN-OS solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-paloaltopanos?tab=Overview) |
| **Fortinet FortiGate** | `CommonSecurityLog` | 3P Solution | `Fortinet FortiGate Next-Generation Firewall connector for Microsoft Sentinel` | Yes (15+ analytics rules) | `CommonSecurityLog \| where TimeGenerated > ago(1h) \| where DeviceVendor == "Fortinet" \| summarize count() by Activity` | CEF-based ingestion. Traffic, UTM, event, system logs. | [Fortinet FortiGate solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-fortinetfortigate?tab=Overview) |
| **Check Point** | `CommonSecurityLog` | 3P Solution | `Check Point` | Yes (10+ analytics rules) | `CommonSecurityLog \| where TimeGenerated > ago(1h) \| where DeviceVendor == "Check Point" \| summarize count()` | CEF format. Firewall, IPS, anti-bot, URL filtering logs. | [Check Point solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/checkpoint.checkpoint-sentinel-solutions?tab=Overview) |
| **Cisco ASA/Firepower** | `CommonSecurityLog` | 3P Solution | `CiscoASA` / `Cisco Firepower EStreamer` | Yes (10+ analytics rules) | `CommonSecurityLog \| where TimeGenerated > ago(1h) \| where DeviceVendor == "Cisco" \| summarize count() by DeviceProduct` | ASA syslogs and Firepower eStreamer events. | [Cisco ASA connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#cisco-asaftd-via-ama) |
| **SonicWall** | `CommonSecurityLog`, `Syslog` | 3P Solution | `SonicWall Firewall` | Yes (5+ analytics rules) | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has "SonicWall" \| summarize count()` | Syslog-based. Firewall traffic and system events. | [SonicWall solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/sonicwall-inc.sonicwall-sentinel?tab=Overview) |
| **WatchGuard Firebox** | `Syslog` | 3P Solution | `Watchguard Firebox` | Yes | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has "WatchGuard" \| summarize count()` | Syslog-based. Traffic denied/allowed, proxy events. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Windows Firewall** | `WindowsFirewall` (Sentinel), `DeviceNetworkEvents` (XDR) | 1P Solution | `Windows Firewall` Content Hub solution | Yes (5+ analytics rules) | `WindowsFirewall \| where TimeGenerated > ago(1h) \| summarize count() by FirewallAction` | Windows host firewall events (allowed, dropped, blocked). | [WindowsFirewall table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsfirewall) |
| **Azure NSG Flow Logs** | `AzureNetworkAnalytics_CL` | 1P Native | `Azure Network Security Groups` | Yes | `AzureNetworkAnalytics_CL \| where TimeGenerated > ago(1h) \| summarize count() by FlowStatus_s` | NSG flow logs for Azure virtual networks. | [NSG flow logs](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview) |

### Routers, Switches & NetFlow

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Core/Border Router & Switch logs (auth, config, routing table changes) | `Syslog`, `CommonSecurityLog` | 3P Solution / Custom | Vendor-specific: `Cisco ISE`, `Aruba ClearPass`, or Syslog/CEF generic connector | Limited | `Syslog \| where TimeGenerated > ago(1h) \| where Facility in ("local0","local7") \| summarize count() by Computer` | Router/switch syslogs over CEF or raw Syslog. Config changes appear as system events. | [Syslog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog) |
| NetFlow (ingress/egress per subnet) | Custom ingestion | Custom | Custom DCR via Azure Monitor Agent or third-party NetFlow collector (e.g., `Gigamon Connector`, `Corelight`) | No OOTB | `search * \| where TimeGenerated > ago(1h) \| where $table has "NetFlow" \| summarize count()` | NetFlow is not natively ingested by Sentinel. Requires a collector appliance that converts NetFlow to Syslog/CEF or custom table. Corelight can provide Zeek-based flow data. | [Custom logs via AMA](https://learn.microsoft.com/en-us/azure/sentinel/connect-custom-logs-ama) |

### IDS/IPS

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| IDS/IPS alerts and security events | `CommonSecurityLog`, `SecurityAlert` | 3P Solution | Vendor-specific: PAN-OS Threat, FortiGate UTM, Snort via `Syslog`, Azure Firewall IDPS | Yes (vendor analytics) | `CommonSecurityLog \| where TimeGenerated > ago(1h) \| where Activity has_any ("IPS","IDS","intrusion","threat") \| summarize count()` | Most modern firewalls include IDS/IPS. Dedicated IDS (Snort/Suricata) sends via Syslog. | [CommonSecurityLog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog) |

### Web Proxy

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Web proxy query logs, SSL/TLS inspection, auth | `SquidProxy_CL`, `Syslog`, `ZscalerNSSEvent_CL`, `SymantecProxySG_CL` | 3P Solution | `SquidProxy`, `Zscaler Internet Access`, `SymantecProxySG`, `Netskopev2`, `iboss` | Yes (varies by vendor, 5-15 rules) | `Syslog \| where TimeGenerated > ago(1h) \| where ProcessName has_any ("squid","bluecoat","zscaler") \| summarize count()` | Web proxy logs vary by vendor. Zscaler and Netskope are most common SaaS proxies with dedicated connectors. On-prem proxies typically use Syslog. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Zscaler Internet Access** | `CommonSecurityLog`, `ZscalerNSSEvent_CL` | 3P Solution | `Zscaler Internet Access` | Yes (15+ analytics rules) | `CommonSecurityLog \| where TimeGenerated > ago(1h) \| where DeviceVendor == "Zscaler" \| summarize count()` | Full web log, firewall, DNS, DLP events from Zscaler. | [Zscaler solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-zscaler?tab=Overview) |

### VPN

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| VPN connections (allowed, denied, auth, session metadata) | `SigninLogs` (Entra-based VPN), `CommonSecurityLog`, `Syslog` | Mixed | Depends on VPN vendor: `Pulse Connect Secure`, `Cisco ISE`, `Zscaler Private Access (ZPA)`, `Global Secure Access` | Yes (varies) | `SigninLogs \| where TimeGenerated > ago(1h) \| where AppDisplayName has "VPN" \| summarize count()` | For Microsoft Global Secure Access / Entra Private Access, `NetworkAccessTraffic` and `SigninLogs` cover VPN-equivalent events. Hardware VPN (Cisco, Pulse) uses Syslog/CEF. | [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) |
| **Zscaler Private Access** | `ZPA_CL` | 3P Solution | `Zscaler Private Access (ZPA)` | Yes (5+ analytics rules) | `ZPA_CL \| where TimeGenerated > ago(1h) \| summarize count()` | User access, connector, audit logs for ZPA connections. | [Zscaler ZPA solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-zscalerprivateaccess?tab=Overview) |

### Mail Appliance

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Mail reputation, sender, recipients, subject, attachments | `EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `EmailPostDeliveryEvents` (XDR) | 1P Native | Microsoft Defender for Office 365 connector | Yes (30+ analytics rules) | `EmailEvents \| where TimeGenerated > ago(1h) \| summarize count() by DeliveryAction` | First-party coverage for Exchange Online / M365 mail. Covers sender, recipients, subject, attachment names, URL reputation, delivery action. | [EmailEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table) |
| **Mimecast** | `MimecastAudit_CL`, `MimecastSEG_CL`, `MimecastTTP_CL` | 3P Solution | `Mimecast` / `MimecastSEG` / `MimecastTTP` | Yes (5+ analytics rules) | `MimecastSEG_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Secure email gateway events — IP/domain reputation, sender, recipients, subject, attachment names. | [Mimecast solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-mimecast?tab=Overview) |
| **Proofpoint TAP** | `ProofPointTAP_CL` | 3P Solution | `ProofPointTap` | Yes (5+ analytics rules) | `ProofPointTAP_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Targeted Attack Protection — clicks, messages, threats. | [Proofpoint TAP solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-proofpointtap?tab=Overview) |
| **Cisco Secure Email (IronPort)** | `CommonSecurityLog`, `CiscoSEG_CL` | 3P Solution | `CiscoSEG` | Yes | `CiscoSEG_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Email security events from Cisco Secure Email Gateway. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

### Application Layer Gateways / NAC

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Content inspection, auth, NAC events | `CommonSecurityLog`, `Syslog` | 3P Solution | `Cisco ISE` (NAC), `Aruba ClearPass`, `Forescout` (NAC), `Citrix ADC` (ALG) | Yes (varies) | `CommonSecurityLog \| where TimeGenerated > ago(1h) \| where DeviceProduct has_any ("ISE","ClearPass","ADC") \| summarize count()` | NAC auth events mapped via Cisco ISE or Forescout. Application layer gateways (reverse proxy, WAF) covered by Citrix ADC, Azure WAF, F5. | [Cisco ISE solution](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/azuresentinel.azure-sentinel-solution-ciscoidentityservicesengine?tab=Overview) |
| **Azure WAF** | `AzureDiagnostics` (category: ApplicationGatewayFirewallLog) | 1P Solution | `Azure Web Application Firewall (WAF)` | Yes (10+ analytics rules) | `AzureDiagnostics \| where Category == "ApplicationGatewayFirewallLog" \| where TimeGenerated > ago(1h) \| summarize count()` | OWASP rule matches, blocked/detected requests, custom rules. | [AzureDiagnostics table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azurediagnostics) |

---

## 3. Microsoft Domain Controller Logs

**ACSC Priority**: 3

Covers Account Logon (4776, 4768, 4769), Account Management, Certificate Services, Process Creation, DS Access, Directory Changes, Federation Services, Kerberos, LDAP, Logon/Logoff, Object Access, Privilege Use, Policy Change, System events and LSASS.

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| All DC Security Events (4624, 4625, 4768, 4769, 4776, 4720, 4732, etc.) | `SecurityEvent` (Sentinel), `WindowsEvent` (Sentinel) | 1P Solution | `Windows Security Events` Content Hub solution (via AMA) | Yes (50+ analytics rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where Computer has "DC" \| summarize count() by EventID` | SecurityEvent table captures all Windows Security Event Log IDs. Deploy via Azure Monitor Agent with a DCR targeting Security log. Covers all ACSC DC event IDs. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| Account Logon — Kerberos (4768, 4769, 4770) | `SecurityEvent` (Sentinel), `IdentityLogonEvents` (XDR) | 1P Native | Defender for Identity + Windows Security Events | Yes (20+ for Kerberoasting, AS-REP roasting, Golden Ticket) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4768, 4769, 4770) \| summarize count() by EventID` | Kerberos TGT/service ticket events. Defender for Identity enriches these with behavioural detections for Kerberoasting (T1558.003) and Golden Ticket attacks. | [IdentityLogonEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table) |
| Account Management (4720-4743, 4780, 4794) | `SecurityEvent` (Sentinel), `IdentityDirectoryEvents` (XDR) | 1P Native | Windows Security Events + Defender for Identity | Yes (15+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4720,4722,4724,4726,4728,4732,4738,4740,4741,4742,4743) \| summarize count() by EventID` | User/computer/group account creation, modification, deletion, lockout. Defender for Identity provides additional anomaly-based detections. | [IdentityDirectoryEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table) |
| DCSync (4928, 4929) | `SecurityEvent`, `IdentityDirectoryEvents` | 1P Native | Windows Security Events + Defender for Identity | Yes (DCSync detection built-in) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4928, 4929) \| summarize count()` | Directory replication events. Defender for Identity specifically detects DCSync attacks. | [IdentityDirectoryEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table) |
| Certificate Services (39, 40, 41, 70, 4876, 4886, 4887, 4899, 4900) | `SecurityEvent` (Sentinel) | 1P Solution | Windows Security Events | Yes (ESC1-ESC8 detection rules in Content Hub) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (39,40,41,70,4876,4886,4887,4899,4900) \| summarize count() by EventID` | AD CS certificate request, issuance, template changes. Critical for detecting ESC-series ADCS attacks. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| Process Creation (4688 with command line) | `SecurityEvent` (Sentinel), `DeviceProcessEvents` (XDR) | 1P Native | Windows Security Events / MDE | Yes (30+) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID == 4688 \| where CommandLine != "" \| take 10` | Process creation with command-line auditing. Requires "Include command line in process creation events" GPO. MDE provides equivalent via DeviceProcessEvents. | [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| DS Access (4661, 4662, 5136, 5137, 5141) | `SecurityEvent`, `IdentityDirectoryEvents` | 1P Native | Windows Security Events + Defender for Identity | Yes (10+ AD object change rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4661,4662,5136,5137,5141) \| summarize count() by EventID` | Directory service object access, modification, creation, deletion. Required for detecting AD persistence techniques. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| Federation Services (307, 510, 1007, 1200, 1202) | `SecurityEvent`, custom Windows Event Forwarding | 1P Solution | Windows Forwarded Events / Custom DCR | Limited (AD FS specific rules available) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (307,510,1007,1200,1202) \| summarize count() by EventID` | AD FS configuration changes, token issuance, signing cert export. Requires forwarding AD FS admin/audit logs. | [Windows Forwarded Events connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#windows-forwarded-events) |
| Logon/Logoff (4624, 4625, 4634, 4647, 4648, 4672) | `SecurityEvent`, `IdentityLogonEvents` | 1P Native | Windows Security Events + Defender for Identity | Yes (20+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4624,4625,4634,4647,4648,4672) \| summarize count() by EventID` | Interactive, remote, network, service logon types. Special privilege logon (4672). Explicit credential use (4648). | [IdentityLogonEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table) |
| Privilege Use (4673, 4674, 4985) | `SecurityEvent` | 1P Solution | Windows Security Events | Yes (5+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4673,4674,4985) \| summarize count() by EventID` | Sensitive privilege use — SeTcbPrivilege, SeDebugPrivilege, etc. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| Policy Change (4670, 4706, 4713, 4716, 4717, 4718, 4719, 4703) | `SecurityEvent` | 1P Solution | Windows Security Events | Yes (5+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4706,4713,4716,4717,4718,4719,4703) \| summarize count() by EventID` | Authentication/authorisation policy changes, trust creation/removal, Kerberos policy changes. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| System (IPsec, Security State, System Extensions, Integrity) | `SecurityEvent` | 1P Solution | Windows Security Events | Yes (5+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4608,4610,4611,4614,4616,4621,4622,4697) \| summarize count() by EventID` | Security system extension loads (4697 = service install), security state changes, system integrity events. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| LSASS protection (3033, 3063) | `SecurityEvent` | 1P Solution | Windows Security Events | Limited | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (3033,3063) \| summarize count()` | LSA protection audit mode (3063) and enforcement (3033). Detects attempts to inject into LSASS. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| LDAP Bind (2889) | `SecurityEvent` | 1P Solution | Windows Security Events / Custom DCR | Limited | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID == 2889 \| summarize count()` | Unsigned LDAP bind events. Requires directory services logging on DCs. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |

---

## 4. Active Directory and Domain Service Security Logs

**ACSC Priority**: 4

This category overlaps significantly with Category 3 (Domain Controller). The additional items focus on AD object changes, trust management, SID history, Kerberos policy, replication, certificate services, and user account lifecycle.

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| All AD Security Events | `SecurityEvent`, `IdentityDirectoryEvents`, `IdentityLogonEvents` | 1P Native | Windows Security Events + Microsoft Defender for Identity | Yes (60+ combined) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4662,4670,4673,4694,4703,4706,4707,4724,4728,4729,4732,4733,4735,4737,4755,4756,4757,4765,4766,4768,4769,4771,4776,4780,4794) \| summarize count() by EventID` | Full AD security event spectrum. Defender for Identity adds behavioural context (lateral movement, reconnaissance, credential theft). | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| Trust management (4706, 4707) | `SecurityEvent` | 1P Solution | Windows Security Events | Yes (trust creation/removal rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4706,4707) \| summarize count() by EventID` | New domain trust created / trust removed. High-severity indicator. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| SID History (4765, 4766) | `SecurityEvent` | 1P Solution | Windows Security Events | Yes (SID History injection detection) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4765,4766) \| summarize count()` | SID History added to account — pass-the-ticket / privilege escalation vector. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| Directory replication (1102 — DRA) | `SecurityEvent`, `IdentityDirectoryEvents` | 1P Native | Defender for Identity | Yes (replication anomaly detection) | `IdentityDirectoryEvents \| where TimeGenerated > ago(1d) \| where ActionType has "replication" \| summarize count()` | Inter-site replication events. Defender for Identity detects anomalous replication (DCSync). | [IdentityDirectoryEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table) |
| **Semperis DSP / AD protection** | `SemperisDSP_CL` | 3P Solution | `Semperis Directory Services Protector` | Yes (10+ analytics rules) | `SemperisDSP_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Third-party AD change monitoring. Detects AD object changes, GPO modifications, schema changes. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

---

## 5. Microsoft Windows Endpoint Logs

**ACSC Priority**: 5

Covers Sysmon, application crashes, Task Scheduler, PowerShell, WMI, Security Event log, AppLocker, WDAC, ESENT, Terminal Services, and Defender AC.

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Sysmon Event ID 1 (Process Creation) | `SysmonEvent` / `Event` (Sentinel), `DeviceProcessEvents` (XDR) | 1P Solution | `Microsoft Sysmon For Linux` / Windows Events via AMA | Yes (20+ Sysmon-specific rules) | `Event \| where TimeGenerated > ago(1h) \| where Source == "Microsoft-Windows-Sysmon" and EventID == 1 \| summarize count()` | Sysmon process creation with full command line, hashes, parent process. Alternative: MDE DeviceProcessEvents provides equivalent without Sysmon. | [Event table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) |
| Application Crashes (1001) | `Event` (Application log) | 1P Solution | Windows Forwarded Events / AMA DCR | Limited | `Event \| where TimeGenerated > ago(1h) \| where EventLog == "Application" and EventID == 1001 \| summarize count()` | Windows Error Reporting crash events. | [Event table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) |
| Task Scheduler (118, 119, 129, 200) | `SecurityEvent`, `Event` | 1P Solution | Windows Security Events + custom DCR for Task Scheduler log | Yes (5+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| where EventID in (4698,4699,4700,4701,4702) \| summarize count() by EventID` | Security log captures task create/delete/enable/disable (4698-4702). Task Scheduler operational log (118, 119, 129, 200) requires custom DCR. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| PowerShell (4103, 4104, 400) | `SecurityEvent`, `Event` (PowerShell log), `DeviceEvents` (XDR) | 1P Solution | Windows Security Events / Windows PowerShell solution | Yes (20+ PowerShell-specific rules) | `Event \| where TimeGenerated > ago(1h) \| where Source == "Microsoft-Windows-PowerShell" and EventID in (4103,4104) \| summarize count() by EventID` | Module logging (4103) and Script Block logging (4104) are essential. Requires GPO "Turn on PowerShell Script Block Logging". MDE also captures via DeviceEvents with PowerShellCommand ActionType. | [Event table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) |
| WMI Activity (5857-5861) | `Event` (WMI-Activity/Operational) | 1P Solution | Custom DCR via AMA | Yes (3+ WMI persistence rules) | `Event \| where TimeGenerated > ago(1h) \| where Source == "Microsoft-Windows-WMI-Activity" and EventID in (5857,5858,5859,5860,5861) \| summarize count() by EventID` | WMI event subscription persistence. Requires forwarding WMI-Activity/Operational log. | [Event table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) |
| Security Event Log (1102, 4610-4697, etc.) | `SecurityEvent` | 1P Solution | Windows Security Events | Yes (50+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| summarize count() by EventID \| top 20 by count_` | All Windows Security Event IDs per ACSC table. 1102 = audit log cleared (critical indicator). | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| AppLocker (8000-8040) | `Event` (AppLocker logs), `AppLockerEvents_CL` | 1P Solution | Custom DCR | Yes (3+ AppLocker bypass rules) | `Event \| where TimeGenerated > ago(1h) \| where Source has "AppLocker" and EventID in (8004,8007,8022,8025) \| summarize count() by EventID` | Application execution control events. EXE/DLL/script blocked events are key indicators. | [Event table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) |
| WDAC (3077, 3089) | `Event` (CodeIntegrity), `DeviceEvents` (XDR) | 1P Native | MDE / Custom DCR | Yes (WDAC block rules in MDE) | `Event \| where TimeGenerated > ago(1h) \| where Source == "Microsoft-Windows-CodeIntegrity" and EventID in (3077,3089) \| summarize count()` | Windows Defender Application Control block / signature events. MDE captures these as well. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| ESENT (216, 325, 326, 327, 637) | `Event` (Application log) | 1P Solution | Custom DCR | Limited (ntds.dit mounting rule available) | `Event \| where TimeGenerated > ago(1h) \| where Source == "ESENT" and EventID in (216,325,326,327,637) \| summarize count()` | ESENT database events. Event 326 (ntds.dit mount) is a key indicator for credential dumping via shadow copy. | [Event table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) |
| Terminal Services (21-25) | `Event` (TerminalServices-LocalSessionManager) | 1P Solution | Custom DCR / Windows Forwarded Events | Yes (3+ RDP lateral movement rules) | `Event \| where TimeGenerated > ago(1h) \| where Source == "Microsoft-Windows-TerminalServices-LocalSessionManager" and EventID in (21,22,23,24,25) \| summarize count() by EventID` | RDP session connect/disconnect/reconnect events. Critical for lateral movement detection. | [Event table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/event) |

---

## 6. Virtualisation System Logs

**ACSC Priority**: 6

Covers hypervisor authentication, VM creation/migration/deployment, system configuration changes, audit log cleared, and resource utilisation.

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| **VMware vCenter/ESXi** | `VMwareESXi_CL`, `Syslog` | 3P Solution | `VMWareESXi` / `VMware vCenter` | Yes (5+ analytics rules) | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has_any ("vmware","vcenter","esxi") \| summarize count()` | VM lifecycle events, auth, config changes via Syslog. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Azure VM / Hyper-V** | `AzureActivity`, `AzureDiagnostics`, `SecurityEvent` (on Hyper-V host) | 1P Native | Azure Activity connector + Windows Security Events on Hyper-V hosts | Yes (Azure Activity analytics) | `AzureActivity \| where TimeGenerated > ago(1h) \| where ResourceProviderValue == "MICROSOFT.COMPUTE" \| summarize count() by OperationNameValue` | VM create, delete, start, stop, resize, migrate operations logged in AzureActivity. Hyper-V host events via SecurityEvent. | [AzureActivity table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) |
| **Citrix** | `Syslog`, `CitrixADC_CL` | 3P Solution | `Citrix ADC` / `Citrix Analytics for Security` | Yes | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has "Citrix" \| summarize count()` | Citrix virtualisation events incl. session brokering, auth, config. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

---

## 7. Operational Technology (OT) Logging

**ACSC Priority**: 7

OT logging requires specialised collectors due to vendor-specific protocols and network segmentation.

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| **Microsoft Defender for IoT** (ICS/OT monitoring) | `SecurityAlert` (IoT alerts), `IoTHubDistributedTracing_CL` | 1P Native | `IoTOTThreatMonitoringwithDefenderforIoT` | Yes (20+ OT-specific rules) | `SecurityAlert \| where TimeGenerated > ago(1d) \| where ProductName == "Azure Security Center for IoT" \| summarize count()` | Microsoft's OT security product. Passive network monitoring, protocol parsing (Modbus, DNP3, OPC-UA), anomaly detection. Recommended for ACSC OT requirements. | [Defender for IoT](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/overview) |
| **Claroty xDome** | `ClarotyxDome_CL` | 3P Solution | `Claroty xDome` | Yes (analytics rules included) | `ClarotyxDome_CL \| where TimeGenerated > ago(1d) \| summarize count()` | OT asset discovery, vulnerability assessment, threat detection. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Nozomi Networks** | `NozomiNetworks_CL` | 3P Solution | `NozomiNetworks` | Yes | `NozomiNetworks_CL \| where TimeGenerated > ago(1d) \| summarize count()` | OT/IoT network monitoring and anomaly detection. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Dragos** | `Dragos_CL` | 3P Solution | `Dragos` | Yes | `Dragos_CL \| where TimeGenerated > ago(1d) \| summarize count()` | ICS threat detection platform. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Forescout eyeInspect** | `Syslog` | 3P Solution | `Forescout eyeInspect for OT Security` | Yes | `Syslog \| where TimeGenerated > ago(1d) \| where SyslogMessage has "Forescout" \| summarize count()` | OT network visibility and threat detection. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Radiflow** | `Radiflow_CL` | 3P Solution | `Radiflow` | Yes | `Radiflow_CL \| where TimeGenerated > ago(1d) \| summarize count()` | iSID OT IDS events. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

---

## 8. Cloud Platform Logging

**ACSC Priority**: 8

### Critical Azure Service and App Logs

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Entra Signin Log (all types) | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADManagedIdentitySignInLogs`, `AADServicePrincipalSignInLogs` | 1P Native | Microsoft Entra ID connector | Yes (40+ analytics rules) | `SigninLogs \| where TimeGenerated > ago(1h) \| summarize count() by ResultType` | Covers all ACSC Entra sign-in log types: interactive, non-interactive, managed identity, service principal. | [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) |
| Entra Audit Log | `AuditLogs` | 1P Native | Microsoft Entra ID connector | Yes (20+ rules) | `AuditLogs \| where TimeGenerated > ago(1h) \| summarize count() by OperationType` | User, group, app, role, and policy changes. | [AuditLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs) |
| ADFS Signin Log | `ADFSSignInLogs` | 1P Native | Microsoft Entra ID connector (ADFS) | Yes (5+ rules) | `ADFSSignInLogs \| where TimeGenerated > ago(1h) \| summarize count()` | AD FS authentication events. | [ADFSSignInLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/adfssigninlogs) |
| Entra Connect (PHS, password sync) | `AADProvisioningLogs`, custom Event logs | 1P / Custom | Entra ID connector + custom DCR for Entra Connect server events (611, 650, 651, 656, 657) | Limited | `AADProvisioningLogs \| where TimeGenerated > ago(1d) \| summarize count()` | Provisioning logs capture sync events. Entra Connect server Event IDs (611, 650-657) require AMA on the Connect server forwarding Application/Security logs. | [AADProvisioningLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadprovisioninglogs) |
| Azure Activity Log (Read/Write) | `AzureActivity` | 1P Native | Azure Activity connector | Yes (15+ analytics rules) | `AzureActivity \| where TimeGenerated > ago(1h) \| summarize count() by CategoryValue` | All Azure control-plane operations. Covers resource create, modify, delete, role assignment changes. | [AzureActivity table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) |
| Azure Storage Container Log | `StorageBlobLogs`, `StorageQueueLogs`, `StorageTableLogs`, `StorageFileLogs` | 1P Native | Azure Diagnostics / Azure Storage solution | Yes (5+ rules) | `StorageBlobLogs \| where TimeGenerated > ago(1h) \| summarize count() by OperationName` | Storage data-plane operations — read, write, delete, list. | [StorageBlobLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs) |
| Breakglass Account Use | `SigninLogs`, `AuditLogs` | 1P Native | Microsoft Entra ID connector | Yes (breakglass account sign-in rules) | `SigninLogs \| where TimeGenerated > ago(30d) \| where UserPrincipalName has_any ("breakglass","emergency","bg-") \| summarize count() by UserPrincipalName` | Tag breakglass/emergency accounts in a watchlist and alert on any sign-in. OOTB rules in `Cloud Identity Threat Protection Essentials` and `Microsoft Entra ID` solution. | [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) |
| Microsoft 365 Unified Audit Log | `OfficeActivity` | 1P Native | Microsoft 365 connector | Yes (30+ rules) | `OfficeActivity \| where TimeGenerated > ago(1h) \| summarize count() by OfficeWorkload` | Exchange, SharePoint, OneDrive, Teams, Power Platform audit events. | [OfficeActivity table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity) |
| VM OS Logs (Windows) | `SecurityEvent`, `Event` | 1P Solution | Windows Security Events / AMA | Yes (50+ rules) | `SecurityEvent \| where TimeGenerated > ago(1h) \| summarize count() by Computer` | Windows Security and System events from Azure VMs. | [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) |
| VM OS Logs (Linux) | `Syslog`, `SysmonForLinux_CL` | 1P Solution | Syslog connector / `Microsoft Sysmon For Linux` | Yes (15+ Linux-specific rules) | `Syslog \| where TimeGenerated > ago(1h) \| summarize count() by Computer, Facility` | Linux syslog (auth, authpriv, daemon, kern). | [Syslog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog) |

### Amazon Web Services Logs

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| CloudTrail | `AWSCloudTrail` | 1P Solution | `Amazon Web Services` (S3 connector) | Yes (25+ analytics rules) | `AWSCloudTrail \| where TimeGenerated > ago(1h) \| summarize count() by EventName` | Management and data events from AWS CloudTrail. Covers all ACSC AWS event types (IAM, EC2, VPC, S3, STS, Lambda, RDS, etc.). | [AWSCloudTrail table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail) |
| VPC Flow Logs | `AWSVPCFlow_CL` | 1P Solution | `AWS VPC Flow Logs` | Yes (5+ rules) | `AWSVPCFlow_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Network flow data from AWS VPCs. | [AWS connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#amazon-web-services) |
| GuardDuty | `AWSGuardDuty_CL` | 1P Solution | `AWS Security Hub` | Yes (5+ rules) | `AWSGuardDuty_CL \| where TimeGenerated > ago(1d) \| summarize count()` | AWS threat detection findings. | [AWS connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#amazon-web-services) |

### Google Cloud Platform Logs

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Admin Activity, System Event, Policy Denied Audit Logs | `GCPAuditLogs_CL` | 3P Solution | `Google Cloud Platform Audit Logs` | Yes (10+ analytics rules) | `GCPAuditLogs_CL \| where TimeGenerated > ago(1h) \| summarize count()` | GCP audit logs covering admin actions, system events, policy violations. | [GCP Audit Logs connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#gcp-pubsub-audit-logs) |
| VPC Firewall Logs | `GCPFirewall_CL` | 3P Solution | `Google Cloud Platform Firewall Logs` | Yes | `GCPFirewall_CL \| where TimeGenerated > ago(1h) \| summarize count()` | GCP VPC firewall allow/deny events. | [GCP connectors](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#gcp-pubsub-audit-logs) |
| VPC Flow Logs | `GCPFlowLogs_CL` | 3P Solution | `Google Cloud Platform VPC Flow Logs` | Yes | `GCPFlowLogs_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Network flow data from GCP VPCs. | [GCP connectors](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#gcp-pubsub-audit-logs) |

### Google Workspace Logs

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Admin, Login, OAuth, SAML, Drive, Gmail, Device events | `GoogleWorkspaceReports_CL` | 3P Solution | `GoogleWorkspaceReports` | Yes (10+ analytics rules) | `GoogleWorkspaceReports_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Google Workspace admin, login, drive, gmail, SAML, OAuth, device events. | [Google Workspace connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#google-workspace-activities-via-codeless-connector-framework) |

---

## 9. Container Logs

**ACSC Priority**: 9

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Container auth (logon, privileged access) | `ContainerLog`, `KubeAuditLogs` (AKS), `ContainerInventory` | 1P Native | `Azure kubernetes Service` / Defender for Containers | Yes (20+ analytics rules) | `KubeAuditLogs \| where TimeGenerated > ago(1h) \| summarize count() by verb_s` | AKS Kubernetes audit logs capture all API server requests including auth. | [ContainerLog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/containerlog) |
| Container RBAC changes, service status | `KubeAuditLogs`, `AzureActivity` | 1P Native | Azure Kubernetes Service connector | Yes (RBAC change rules) | `KubeAuditLogs \| where TimeGenerated > ago(1h) \| where verb_s in ("create","update","delete","patch") \| where objectRef_resource_s has_any ("clusterroles","rolebindings","clusterrolebindings") \| summarize count()` | Kubernetes RBAC and resource changes. | [KubeAuditLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/kubeauditlogs) |
| Container API audit | `KubeAuditLogs` | 1P Native | AKS diagnostics | Yes | `KubeAuditLogs \| where TimeGenerated > ago(1h) \| summarize count() by responseStatus_code_s` | All Kubernetes API requests with response codes. | [KubeAuditLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/kubeauditlogs) |
| Container security config changes | `KubeAuditLogs`, `AzureActivity` | 1P Native | AKS + Azure Activity | Yes | `AzureActivity \| where TimeGenerated > ago(1h) \| where ResourceProviderValue == "MICROSOFT.CONTAINERSERVICE" \| summarize count() by OperationNameValue` | AKS cluster-level configuration changes. | [AzureActivity table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) |
| Container management auth | `ContainerInstanceLog_CL`, `KubeAuditLogs` | 1P Native | AKS / Container Instances | Yes | See above | Authentication to container management plane. | [KubeAuditLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/kubeauditlogs) |

---

## 10. Database Logs

**ACSC Priority**: 10

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| **Azure SQL** (auth, queries, privilege, structure changes) | `AzureDiagnostics` (SQLSecurityAuditEvents), `SQLSecurityAuditEvents` | 1P Native | `Azure SQL Database solution for sentinel` | Yes (10+ analytics rules) | `AzureDiagnostics \| where TimeGenerated > ago(1h) \| where Category == "SQLSecurityAuditEvents" \| summarize count() by event_class_s` | Full audit: authentication, DML/DDL, permission changes, query execution. | [AzureDiagnostics table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azurediagnostics) |
| **SQL Server on VMs** | `Event` (SQL Audit), `SQLEvent_CL` | 1P Solution | `Microsoft Windows SQL Server Database Audit` | Yes (5+ rules) | `Event \| where TimeGenerated > ago(1h) \| where Source has "MSSQL" \| summarize count()` | SQL Server audit events from on-prem or IaaS SQL. Requires SQL Server Audit configured to Windows Event Log or file. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **PostgreSQL (Azure)** | `AzureDiagnostics` (PostgreSQL) | 1P Native | Azure Diagnostics | Limited | `AzureDiagnostics \| where TimeGenerated > ago(1h) \| where ResourceProvider == "MICROSOFT.DBFORPOSTGRESQL" \| summarize count()` | Azure Database for PostgreSQL audit logs. | [AzureDiagnostics table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azurediagnostics) |
| **MySQL (Azure)** | `AzureDiagnostics` (MySQL) | 1P Native | Azure Diagnostics | Limited | `AzureDiagnostics \| where TimeGenerated > ago(1h) \| where ResourceProvider == "MICROSOFT.DBFORMYSQL" \| summarize count()` | Azure Database for MySQL audit logs. | [AzureDiagnostics table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azurediagnostics) |
| **MongoDB Atlas** | `MongoDBAtlas_CL` | 3P Solution | `MongoDBAtlas` | Yes | `MongoDBAtlas_CL \| where TimeGenerated > ago(1d) \| summarize count()` | Atlas audit logs — auth, queries, config changes. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Oracle Database** | `OracleDatabaseAudit_CL` | 3P Solution | `OracleDatabaseAudit` | Yes (5+ rules) | `OracleDatabaseAudit_CL \| where TimeGenerated > ago(1d) \| summarize count()` | Oracle DB unified audit trail. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **PostgreSQL (on-prem)** | `PostgreSQL_CL`, `Syslog` | 3P Solution | `PostgreSQL` | Limited | `PostgreSQL_CL \| where TimeGenerated > ago(1d) \| summarize count()` | Self-hosted PostgreSQL audit logs via Syslog or custom connector. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

---

## 11. Mobile Device Management (MDM)

**ACSC Priority**: 11

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| **Microsoft Intune** (device data, app data, policies, network, events, MTD) | `IntuneDevices`, `IntuneOperationalLogs`, `IntuneAuditLogs` | 1P Native | Intune diagnostics → Log Analytics | Yes (5+ rules) | `IntuneAuditLogs \| where TimeGenerated > ago(1d) \| summarize count() by OperationName` | Device enrolment, policy application, app install/uninstall, compliance status, config changes. Covers majority of ACSC MDM requirements. | [IntuneAuditLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/intuneauditlogs) |
| **Microsoft Defender for Endpoint Mobile** (MTD) | `DeviceEvents`, `DeviceTvmSoftwareInventory` | 1P Native | MDE connector | Yes | `DeviceInfo \| where TimeGenerated > ago(1d) \| where OSPlatform in ("iOS","Android") \| summarize count() by OSPlatform` | Mobile threat defence: jailbreak detection, malicious app detection, network protection. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| **Jamf Protect** (macOS/iOS) | `Jamf_CL` | 3P Solution | `Jamf Protect` | Yes (analytics rules included) | `Jamf_CL \| where TimeGenerated > ago(1d) \| summarize count()` | Jamf Protect telemetry, alerts, and device events. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **BETTER Mobile / Zimperium / Lookout** | Vendor-specific `_CL` tables | 3P Solution | `BETTER Mobile Threat Defense (MTD)`, `Zimperium Mobile Threat Defense`, `Lookout` | Yes | Vendor-specific query | Third-party MTD solutions. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| **Samsung Knox** | `SamsungKnox_CL` | 3P Solution | `Samsung Knox Asset Intelligence` | Yes | `SamsungKnox_CL \| where TimeGenerated > ago(1d) \| summarize count()` | Samsung enterprise device telemetry. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

---

## 12. Windows DNS Server Analytic Event Logs

**ACSC Priority**: 12

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| DNS Analytic (257-264, 277, 278) | `DnsEvents`, `DnsInventory` | 1P Solution | `Windows Server DNS` Content Hub solution | Yes (10+ analytics rules in `DNS Essentials` solution) | `DnsEvents \| where TimeGenerated > ago(1h) \| summarize count() by Name` | DNS query/response events from Windows DNS servers. Response success (257), failure (258), ignored (259), query/response in/out, update events. | [DnsEvents table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/dnsevents) |
| DNS Zone Transfer (6001) | `DnsEvents`, `Event` (DNS Server log) | 1P Solution | Windows Server DNS + custom DCR | Yes (zone transfer anomaly rule) | `DnsEvents \| where TimeGenerated > ago(1h) \| where SubType == "ZoneTransfer" \| summarize count()` | DNS zone transfer completion events. Critical for detecting zone exfiltration. | [DnsEvents table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/dnsevents) |
| **DNS Analytics (Advanced)** | `DeviceNetworkEvents` (XDR), `DeviceEvents` | 1P Native | MDE | Yes (DNS tunnelling, C2 beaconing rules) | `DeviceEvents \| where TimeGenerated > ago(1h) \| where ActionType == "DnsQueryResponse" \| summarize count()` | MDE endpoint-level DNS visibility complements server-side DNS logs. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| **Infoblox NIOS** | `Infoblox_CL`, `CommonSecurityLog` | 3P Solution | `Infoblox NIOS` / `Infoblox Cloud Data Connector` / `Infoblox SOC Insights` | Yes (10+ analytics rules) | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has "infoblox" \| summarize count()` | Enterprise DNS/DHCP/IPAM events from Infoblox. | [Infoblox connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference#infoblox-cloud-data-connector-via-ama) |

---

## 13. Linux Endpoint Auditing Logs

**ACSC Priority**: 13

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| Audit configuration/log modification | `Syslog` (authpriv, auth, daemon) | 1P Solution | Syslog connector via AMA | Yes (10+ Linux-specific rules) | `Syslog \| where TimeGenerated > ago(1h) \| where Facility in ("authpriv","auth","daemon") \| summarize count() by Facility` | Linux auditd events forwarded via rsyslog/syslog-ng to AMA. Covers all ACSC audit categories. | [Syslog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog) |
| User access (SSH, auth, login/logout) | `Syslog`, `CommonSecurityLog` | 1P Solution | Syslog connector | Yes (SSH brute force, anomalous login rules) | `Syslog \| where TimeGenerated > ago(1h) \| where Facility == "authpriv" \| where SyslogMessage has_any ("sshd","login","sudo") \| summarize count()` | SSH session initiation, PAM auth events, su/sudo. | [Syslog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog) |
| Privileged events (sudo, chmod, chown) | `Syslog` | 1P Solution | Syslog connector | Yes (sudo abuse, privilege escalation rules) | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has_any ("sudo","chmod","chown") \| summarize count()` | Privileged command execution, permission changes, sensitive access control. | [Syslog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog) |
| System events (modules, mounts, packages, cron) | `Syslog` | 1P Solution | Syslog connector | Yes (cron modification, kernel module load rules) | `Syslog \| where TimeGenerated > ago(1h) \| where Facility == "kern" or SyslogMessage has_any ("modprobe","insmod","mount","dpkg","rpm","cron") \| summarize count()` | Kernel module load/unload, mount operations, package install/remove, cron changes, boot parameter modifications. | [Syslog table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog) |
| File events (unauthorised access) | `Syslog`, `DeviceFileEvents` (MDE on Linux) | 1P Solution / 1P Native | Syslog + MDE | Yes (5+ rules) | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has "SYSCALL" and SyslogMessage has "denied" \| summarize count()` | auditd SYSCALL entries for denied file access. MDE on Linux provides equivalent via DeviceFileEvents. | [DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| Security/network/recon events | `Syslog`, `DeviceProcessEvents` (MDE on Linux) | 1P Solution / 1P Native | Syslog + MDE | Yes (netcat, nmap, reconnaissance tool rules) | `Syslog \| where TimeGenerated > ago(1h) \| where SyslogMessage has_any ("ncat","netcat","nmap","nc ") \| summarize count()` | Common reconnaissance tool usage, suspicious binary execution, hostname/network changes. | [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Sysmon for Linux** | `SysmonForLinux_CL` | 1P Solution | `Microsoft Sysmon For Linux` | Yes (5+ analytics rules) | `SysmonForLinux_CL \| where TimeGenerated > ago(1h) \| summarize count() by EventID` | Enhanced Linux telemetry: process creation, network connections, file changes. Equivalent to Windows Sysmon. | [Sysmon for Linux](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| **auditd (NXLog)** | `NXLogLinuxAudit_CL` | 3P Solution | `NXLog LinuxAudit` | Yes | `NXLogLinuxAudit_CL \| where TimeGenerated > ago(1h) \| summarize count()` | Structured Linux audit events via NXLog agent. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

---

## 14. Apple macOS Endpoint Logs

**ACSC Priority**: 14

| ACSC Log Requirement | Microsoft Table(s) | Source Type | Connector / Solution | OOTB Detections | KQL Validation | Mapping Notes | Reference |
|---|---|---|---|---|---|---|---|
| User/admin access, privilege use, sudo, SSH | `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceEvents` (XDR) | 1P Native | MDE for macOS | Yes (macOS-specific rules) | `DeviceProcessEvents \| where TimeGenerated > ago(1h) \| where DeviceName has "mac" or InitiatingProcessFileName == "sudo" \| summarize count()` | MDE agent on macOS captures process creation, logon, network, and file events. Covers ACSC sudo, SSH, terminal sessions, process creation/termination. | [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| Gatekeeper, XProtect, WDAC equivalent | `DeviceEvents` (XDR) | 1P Native | MDE for macOS | Yes | `DeviceEvents \| where TimeGenerated > ago(1h) \| where ActionType has_any ("MacOSGatekeeper","XProtect") \| summarize count()` | MDE captures Gatekeeper and XProtect events on managed macOS endpoints. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| MDM (Jamf) | `Jamf_CL` | 3P Solution | `Jamf Protect` | Yes (analytics rules included) | `Jamf_CL \| where TimeGenerated > ago(1d) \| summarize count()` | Jamf Protect for macOS telemetry, compliance, and threat detection. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |
| File access, network comms, CLI, keychain | `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceEvents` (XDR) | 1P Native | MDE for macOS | Yes | `DeviceFileEvents \| where TimeGenerated > ago(1h) \| join kind=inner (DeviceInfo \| where OSPlatform == "macOS") on DeviceId \| summarize count()` | MDE covers file access, network connections, command-line interface activity. Keychain events require additional custom collection. | [DeviceFileEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| Installation/removal of apps, volumes | `DeviceEvents`, `DeviceFileEvents` (XDR) | 1P Native | MDE for macOS | Limited | `DeviceEvents \| where TimeGenerated > ago(1d) \| where ActionType has_any ("AppInstalled","AppUninstalled") \| summarize count()` | Application install/uninstall tracked by MDE. Volume mount events may require custom auditd configuration. | [DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table) |
| **NXLog BSM macOS** | `NXLogBSM_CL` | 3P Solution | `NXLog BSM macOS` | Limited | `NXLogBSM_CL \| where TimeGenerated > ago(1d) \| summarize count()` | Apple BSM audit trail (OpenBSM) for deep macOS auditing beyond MDE coverage. Covers Terminal commands, file access, privilege escalation, SSH. | [Content Hub catalog](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog) |

---

## Coverage Summary Matrix

### Methodology

Coverage is calculated per ACSC priority log category using this formula:

$$\text{Coverage \%} = \frac{\text{Full} + (\text{Partial} \times 0.5)}{\text{Total Sub-requirements}} \times 100$$

For each ACSC sub-requirement listed in the source guidance:
- **Full** = A Microsoft Sentinel or XDR table collects this data with OOTB analytics rules
- **Partial** = Data is collectible but has noted limitations: requires custom DCR, missing sub-fields the ACSC specifies, limited OOTB detections, or depends on non-default configuration
- **Gap** = No connector or table available to collect this data

Sub-requirements are counted from the ACSC guidance document — vendor alternatives (e.g., "Palo Alto PAN-OS" vs "Fortinet FortiGate") are **not** counted separately since they fulfil the same ACSC requirement ("Firewall logs").

### Detailed Breakdown

| # | ACSC Category | Sub-reqs | Full | Partial | Gap | Coverage | Bar |
|---|---|---|---|---|---|---|---|
| 1 | EDR Logs | 15 | 13 | 2 | 0 | **93%** | █████████░ |
| 2 | Network Device Logs | 8 | 6 | 2 | 0 | **88%** | ████████░░ |
| 3 | Domain Controller Logs | 14 | 11 | 3 | 0 | **89%** | █████████░ |
| 4 | AD & Domain Service Security | 4 | 4 | 0 | 0 | **100%** | ██████████ |
| 5 | Windows Endpoint Logs | 10 | 8 | 2 | 0 | **90%** | █████████░ |
| 6 | Virtualisation System Logs | 5 | 2 | 3 | 0 | **70%** | ███████░░░ |
| 7 | OT Logging | 6 | 4 | 2 | 0 | **83%** | ████████░░ |
| 8 | Cloud Platform Logging | 17 | 16 | 1 | 0 | **97%** | ██████████ |
| 9 | Container Logs | 5 | 5 | 0 | 0 | **100%** | ██████████ |
| 10 | Database Logs | 7 | 4 | 3 | 0 | **79%** | ████████░░ |
| 11 | MDM | 6 | 5 | 1 | 0 | **92%** | █████████░ |
| 12 | DNS Server Logs | 4 | 4 | 0 | 0 | **100%** | ██████████ |
| 13 | Linux Endpoint Logs | 6 | 4 | 2 | 0 | **83%** | ████████░░ |
| 14 | macOS Endpoint Logs | 6 | 2 | 4 | 0 | **67%** | ██████░░░░ |
| | **Totals** | **113** | **88** | **25** | **0** | **89%** | █████████░ |

### Partial Coverage Notes

The following sub-requirements scored **Partial** — these are the gaps to close:

| # | Category | Sub-requirement | Why Partial |
|---|---|---|---|
| 1 | EDR | Browser History | MDE captures `BrowserLaunchedToOpenUrl` only — full browser history requires investigation package or web content filtering |
| 1 | EDR | LNK/Shellbags/ShimCache/BAM | LNK file creation logged; deeper forensic artefacts (ShimCache, BAM, Shellbags) require Live Response investigation package collection |
| 2 | Network | Router/Switch logs | Collected via generic Syslog/CEF — limited OOTB analytics rules; no structured parsing for vendor-specific event types |
| 2 | Network | NetFlow | No native Sentinel connector — requires custom DCR via AMA or third-party collector (Corelight, Gigamon) |
| 3 | DC | Federation Services | AD FS admin/audit Event IDs (307, 510, 1007, 1200, 1202) require custom Windows Event Forwarding; limited OOTB rules |
| 3 | DC | LSASS protection | Event IDs 3033/3063 collected via SecurityEvent but limited OOTB analytics rules for LSA protection violations |
| 3 | DC | LDAP Bind (2889) | Requires enabling Directory Services logging on DCs; limited OOTB detection rules |
| 5 | Windows | Application Crashes | Event 1001 collected via Event table but limited OOTB analytics — crash correlation requires custom rules |
| 5 | Windows | ESENT (ntds.dit) | Event 326 (ntds.dit mount) collected but only one specific OOTB rule; broader ESENT anomaly detection requires custom analytics |
| 6 | Virtualisation | Non-Azure hypervisors | VMware vCenter/ESXi and Citrix require 3P Content Hub solutions; Hyper-V on-prem needs SecurityEvent on hosts with custom DCR |
| 6 | Virtualisation | Audit log cleared | Covered for Azure VMs (AzureActivity) but requires 3P/custom for non-Azure hypervisors |
| 6 | Virtualisation | Resource utilisation | Azure Monitor covers Azure VMs natively; non-Azure hypervisor resource metrics require custom Syslog or 3P collection |
| 7 | OT | Config change monitoring | Defender for IoT covers supported protocols; proprietary ICS device config changes may need vendor-specific integration |
| 7 | OT | Firmware update tracking | Coverage depends on device/protocol support in Defender for IoT sensor; some legacy devices not supported |
| 8 | Cloud | Entra Connect | Provisioning logs are native; Connect server Event IDs (611, 650–657) require AMA on the Connect server with custom DCR |
| 10 | Database | PostgreSQL (Azure) | Azure Diagnostics collects logs but limited security-specific OOTB rules |
| 10 | Database | MySQL (Azure) | Azure Diagnostics collects logs but limited security-specific OOTB rules |
| 10 | Database | PostgreSQL (on-prem) | Requires custom Syslog or 3P connector; limited OOTB analytics |
| 11 | MDM | WiFi/network adapter events | Intune audit logs capture compliance but detailed per-connection WiFi/cellular logs are not available in SIEM-ingestible format |
| 13 | Linux | File events (unauthorised access) | Syslog captures auditd SYSCALL denials; full file integrity monitoring requires MDE on Linux or dedicated FIM agent |
| 13 | Linux | Recon/network events | Syslog catches some tool execution; complete coverage of reconnaissance tooling requires MDE agent on Linux |
| 14 | macOS | MDM integration | Intune covers basics; full macOS endpoint management visibility requires Jamf Protect (3P) |
| 14 | macOS | Keychain access | MDE macOS covers file/network/CLI but does not report Keychain access events |
| 14 | macOS | App install/volume mount | MDE tracks some app events; volume mount events require custom OpenBSM audit configuration |
| 14 | macOS | Deep BSM auditing | Full OpenBSM audit trail (Terminal commands, privilege escalation, SSH sessions) requires NXLog BSM (3P) beyond MDE coverage |

---

## Validation Checklist

Run this KQL to get a count of all tables with data in your workspace and compare against the tables listed above:

```kql
search *
| where TimeGenerated > ago(30d)
| summarize Count=count(), LatestEvent=max(TimeGenerated) by $table
| sort by Count desc
```

Then cross-reference with the ACSC priority categories:

```kql
// Quick health check: Do I have data for each ACSC category?
let EDR = DeviceProcessEvents | where TimeGenerated > ago(1d) | count | extend Category="1-EDR";
let FW = CommonSecurityLog | where TimeGenerated > ago(1d) | count | extend Category="2-Network";
let DC = SecurityEvent | where TimeGenerated > ago(1d) | where EventID in (4768,4769,4776) | count | extend Category="3-DC";
let WinEP = SecurityEvent | where TimeGenerated > ago(1d) | where EventID in (4688,4624,4625) | count | extend Category="5-WinEndpoint";
let Cloud = SigninLogs | where TimeGenerated > ago(1d) | count | extend Category="8-Cloud";
let DNS = DnsEvents | where TimeGenerated > ago(1d) | count | extend Category="12-DNS";
union EDR, FW, DC, WinEP, Cloud, DNS
| project Category, Count
```

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

*This document was produced by the Security Architecture team. Review when the ACSC guidance is updated or when new Sentinel Content Hub solutions become available.*
