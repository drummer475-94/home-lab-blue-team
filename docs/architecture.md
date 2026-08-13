# Active Directory & Wazuh SIEM Architecture Blueprint

This document specifies the enterprise architecture for Active Directory Domain Services (`CORP.LOCAL`), Group Policy baselines, Local Administrator Password Solution (LAPS), Sysmon telemetry integration, Windows Event Forwarding (WEF), and custom Wazuh SIEM rulesets.

---

## 1. Active Directory Domain Services (`CORP.LOCAL`) Setup

### Domain Infrastructure Overview
- **Root Domain Name**: `CORP.LOCAL` (NetBIOS: `CORP`)
- **Forest & Domain Functional Level**: Windows Server 2022
- **Directory Administrative Tiering**:
  - **Tier 0**: Domain Controllers (`DC01`, `DC02`), PKI/CA, Domain Admin accounts. Restricted to console logons on DCs; zero outbound internet access.
  - **Tier 1**: Server Infrastructure (Web, App, DB, Storage). Managed by Tier 1 Admin accounts.
  - **Tier 2**: Endpoints (`WKSTN01-05`), Workstations, Printers, End Users. Managed by Tier 2 Support accounts.

### Organizational Unit (OU) Tree Structure

The Active Directory hierarchy enforces strict administrative boundaries and GPO inheritance scopes:

```text
DC=CORP,DC=LOCAL
├── OU=CORP
│   ├── OU=Executive
│   │   ├── CN=ExecUser01 (C-Suite Accounts, Strict Conditional Access)
│   │   └── CN=ExecUser02
│   ├── OU=IT
│   │   ├── OU=Admins
│   │   │   ├── CN=admin_t0_jsmith (Tier 0 Domain Admin)
│   │   │   └── CN=admin_t1_jdoe   (Tier 1 Server Admin)
│   │   └── OU=Helpdesk
│   │       └── CN=tech_t2_agarcia (Tier 2 Endpoint Support)
│   ├── OU=Finance
│   │   ├── CN=FinAnalyst01
│   │   └── CN=PayrollUser01
│   ├── OU=Workstations
│   │   ├── OU=Windows_10_11
│   │   │   ├── CN=WKSTN01 (Win10 Exec)
│   │   │   ├── CN=WKSTN02 (Win11 Finance)
│   │   │   └── CN=WKSTN03 (Win11 IT)
│   │   └── OU=Linux_Dev
│   │       └── CN=DEV-LX01 (Ubuntu Dev)
│   ├── OU=Servers
│   │   ├── OU=Domain_Controllers (Built-in)
│   │   │   ├── CN=DC01
│   │   │   └── CN=DC02
│   │   ├── OU=App_Servers
│   │   │   └── CN=WEF01
│   │   └── OU=DMZ_Servers
│   │       └── CN=PROXY01
│   ├── OU=Service_Accounts
│   │   ├── CN=gmsa_wazuh$ (Group Managed Service Account for Wazuh Agent)
│   │   └── CN=gmsa_wef$   (Group Managed Service Account for WEF Collector)
│   ├── OU=Security_Groups
│   │   ├── CN=SG_Exec_Users
│   │   ├── CN=SG_Finance_Users
│   │   ├── CN=SG_Tier0_Admins
│   │   └── CN=SG_LAPS_Readers
│   └── OU=Disabled_Accounts
```

### Baseline Group Policy Objects (GPOs)

The following core GPOs are linked across the domain tree:

#### 1. `GPO-Domain-Password-Policy` (Linked to `OU=CORP`)
- **Minimum Password Length**: 15 characters
- **Password Complexity Requirements**: Enabled (Uppercase, Lowercase, Digits, Special)
- **Account Lockout Threshold**: 5 failed logon attempts
- **Account Lockout Duration**: 30 minutes
- **Reset Lockout Counter After**: 30 minutes
- **Password History Enforced**: 24 previous passwords remembered

#### 2. `GPO-Advanced-Audit-Policy` (Linked to `OU=CORP`)
Configures granular auditing for Security Event Log ingestion:
- **Account Logon**: Audit Kerberos Authentication Service (Success/Failure), Audit Kerberos Service Ticket Operations (Success/Failure - Event ID 4769).
- **Account Management**: Audit User Account Management (Success/Failure), Audit Security Group Management (Success).
- **Detailed Tracking**: Audit Process Creation (Success - Event ID 4688 with **Include command line in process creation events** enabled).
- **Directory Service**: Audit Directory Service Changes (Success/Failure - Event ID 5136).
- **Logon/Logoff**: Audit Logon (Success/Failure - Event IDs 4624, 4625), Audit Special Logon (Success - Event ID 4672).
- **Object Access**: Audit File Share (Success/Failure - Event IDs 5140, 5145).
- **System**: Audit Security State Change (Success), Audit Security System Extension (Success - Event ID 7045 Service Creation).

#### 3. `GPO-LAPS-Deployment` (Linked to `OU=Workstations` and `OU=Servers`)
Enforces Microsoft LAPS (Local Administrator Password Solution) for local `Administrator` accounts:
- **Password Complexity**: Large letters, Small letters, Numbers, Special characters
- **Password Length**: 20 characters
- **Password Age (Days)**: 30 days
- **Administrator Account Name**: `LocalAdmin_CORP` (Renamed from default `Administrator` to prevent automated targeting).

#### 4. `GPO-Windows-Firewall-Baseline` (Linked to `OU=CORP`)
- **Domain, Private, Public Profiles**: Firewall ON.
- **Inbound Default**: Block all inbound connections unless explicitly allowed.
- **Outbound Default**: Allow outbound connections.
- **Rules**:
  - Allow ICMPv4 Echo Request from `10.0.10.0/24` (Management Subnet).
  - Allow WinRM (TCP 5985/5986) from `Management` and `WEF Server` only.
  - Block inbound SMB (TCP 445) between Workstations (`10.0.40.0/24`).

#### 5. `GPO-Protocol-Hardening` (Linked to `OU=CORP`)
- Disable **SMBv1** (Registry key `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` `SMB1` = `0`).
- Disable **LLMNR** (Registry key `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` `EnableMulticast` = `0`).
- Disable **NBT-NS** (NetBIOS over TCP/IP disabled on all network adapters).
- Restrict **NTLM**: Refuse NTLMv1, require NTLMv2 with extended session security.

### LAPS (Local Administrator Password Solution) Deployment Specification

LAPS automates local administrator password management, eliminating shared credentials across domain machines.

#### PowerShell Schema Extension & Permission Setup:
```powershell
# Import LAPS PowerShell Module
Import-Module LAPS

# Extend Active Directory Schema for LAPS attributes (ms-Mcs-AdmPwd & ms-Mcs-AdmPwdExpirationTime)
Update-AdmPwdADSchema

# Delegate Rights to Computers in Workstations OU to store their own passwords
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,OU=CORP,DC=CORP,DC=LOCAL"

# Delegate Read Rights exclusively to SG_LAPS_Readers security group (Tier 1/2 Admins)
Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Workstations,OU=CORP,DC=CORP,DC=LOCAL" -AllowedPrincipals "SG_LAPS_Readers"
Set-AdmPwdResetPasswordPermission -OrgUnit "OU=Workstations,OU=CORP,DC=CORP,DC=LOCAL" -AllowedPrincipals "SG_LAPS_Readers"
```

---

## 2. Wazuh SIEM & Sysmon Log Collection Pipeline

### Telemetry Architecture Diagram

```text
[ Windows 10/11 Endpoints ]    [ Windows Domain Controllers ]
           │                                 │
   (Sysmon + Windows Logs)           (Security Audit Logs)
           │                                 │
           ├──► [ WEF Collector Server ] ────┤
           │    (WinRM / Event Subscriptions)│
           │                                 │
           ▼                                 ▼
   [ Wazuh Agent 4.7 ]               [ Wazuh Agent 4.7 ]
   (Port 1514/TCP Encrypted)         (Port 1514/TCP Encrypted)
           │                                 │
           └──────────────────┬──────────────┘
                              │
                              ▼
                     [ Wazuh Manager 4.7 ]
                     (Decoders & Rules Engine)
                              │
                              ▼
                   [ Wazuh Search Indexer ]
                   (OpenSearch Storage & UI)
```

### Sysmon Modular Configuration Schema (`sysmonconfig.xml`)

Sysmon v15+ is deployed on all endpoints and domain controllers using a modular rule schema tailored for MITRE ATT&CK coverage:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256,imphash</HashAlgorithms>
  <EventFiltering>

    <!-- Event ID 1: Process Creation -->
    <RuleGroup groupRelation="or">
      <ProcessCreate onmatch="include">
        <Rule name="Technique_T1059_Command_and_Scripting_Interpreter" groupRelation="or">
          <Image condition="end with">cmd.exe</Image>
          <Image condition="end with">powershell.exe</Image>
          <Image condition="end with">pwsh.exe</Image>
          <Image condition="end with">wscript.exe</Image>
          <Image condition="end with">cscript.exe</Image>
          <Image condition="end with">mshta.exe</Image>
        </Rule>
        <Rule name="Technique_T1021_PsExec_Execution" groupRelation="or">
          <Image condition="end with">psexec.exe</Image>
          <Image condition="end with">psexesvc.exe</Image>
        </Rule>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection -->
    <RuleGroup groupRelation="or">
      <NetworkConnect onmatch="include">
        <Rule name="Network_SMB_RPC" groupRelation="or">
          <DestinationPort condition="is">445</DestinationPort>
          <DestinationPort condition="is">135</DestinationPort>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 11: File Creation (SYSVOL / Startup / Temp) -->
    <RuleGroup groupRelation="or">
      <FileCreate onmatch="include">
        <Rule name="SYSVOL_Modification" groupRelation="or">
          <TargetFilename condition="contains">\SYSVOL\Policies\</TargetFilename>
        </Rule>
        <Rule name="Startup_Persistence" groupRelation="or">
          <TargetFilename condition="contains">\Microsoft\Windows\Start Menu\Programs\Startup\</TargetFilename>
        </Rule>
      </FileCreate>
    </RuleGroup>

    <!-- Event ID 13: Registry Event (Persistence / Security Tampering) -->
    <RuleGroup groupRelation="or">
      <RegistryEvent onmatch="include">
        <Rule name="RunKeys_Persistence" groupRelation="or">
          <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        </Rule>
      </RegistryEvent>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

### Wazuh Agent Deployment (`ossec.conf`)

The Wazuh Agent configuration file (`C:\Program Files (x86)\ossec-agent\ossec.conf`) on Windows Endpoints and Domain Controllers ingests Sysmon and Windows Event Logs:

```xml
<ossec_config>
  <client>
    <server>
      <address>10.0.30.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- Ingest Windows Security Log -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Ingest Windows System Log (Service Creation 7045) -->
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Ingest Sysmon Operational Log -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Ingest Directory Service Log (GPO Tampering 5136) -->
  <localfile>
    <location>Directory Service</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

### Custom Wazuh Ruleset (`/var/ossec/etc/rules/local_rules.xml`)

Custom security detection rules deployed on the Wazuh Manager (`10.0.30.10`) for custom alerts:

```xml
<group name="windows,enterprise_soc,">

  <!-- Base Rule for Sysmon Ingestion -->
  <rule id="100100" level="0">
    <if_sid>60000</if_sid>
    <field name="win.system.providerName">Microsoft-Windows-Sysmon</field>
    <description>Sysmon event received.</description>
  </rule>

  <!-- UC-01: Password Spraying Detection Rule -->
  <rule id="100101" level="10">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^4625$</field>
    <same_source_ip />
    <different_user />
    <frequency>8</frequency>
    <timeframe>300</timeframe>
    <description>Password Spraying attack detected: Multiple failed logons across different accounts from single IP ($(win.eventdata.ipAddress)).</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
  </rule>

  <!-- UC-02: Kerberoasting RC4 Request Rule -->
  <rule id="100102" level="12">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <field name="win.eventdata.serviceName" type="pcre2">^(?!.*\$).*$</field>
    <description>Kerberoasting Activity Detected: TGS ticket requested with weak RC4 encryption (0x17) for non-machine service account ($(win.eventdata.serviceName)).</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>

  <!-- UC-03: GPO Tampering Rule -->
  <rule id="100103" level="13">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^5136$</field>
    <field name="win.eventdata.attributeLDAPDisplayName">^gPCFileSysPath$|^gPCMachineExtensionNames$</field>
    <description>Group Policy Object Tampering: Directory Service modification to GPO attribute ($(win.eventdata.attributeLDAPDisplayName)) by $(win.eventdata.subjectUserName).</description>
    <mitre>
      <id>T1484.001</id>
    </mitre>
  </rule>

  <!-- UC-04: PsExec Lateral Movement Service Creation Rule -->
  <rule id="100104" level="12">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^7045$</field>
    <field name="win.eventdata.serviceName">^PSEXESVC$</field>
    <description>PsExec Service Creation Detected: Remote service installation (PSEXESVC) on endpoint $(win.system.computer).</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
  </rule>

</group>
```
