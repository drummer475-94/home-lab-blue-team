# Enterprise SOC Detection Use-Cases & Incident Response Blueprints

This document details 4 production-grade threat detection use-cases deployed in the SOC home lab environment (`CORP.LOCAL`). Each use-case maps explicitly to MITRE ATT&CK techniques, Windows/Sysmon telemetry fields, Wazuh SIEM detection rules, and complete NIST SP 800-61 Rev 2 incident response workflows.

---

## Use-Case Index

| Use-Case ID | Title | MITRE ATT&CK ID | Primary Telemetry | Risk Level |
|---|---|---|---|---|
| **UC-01** | Password Spraying Attack | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Event ID 4625 (Failed Logon) | **HIGH** |
| **UC-02** | Kerberoasting Attack | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Event ID 4769 (RC4 TGS Request) | **HIGH** |
| **UC-03** | Group Policy Object Tampering | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) | Event ID 5136 & Sysmon ID 11 | **CRITICAL** |
| **UC-04** | PsExec Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Event ID 7045 & Sysmon IDs 1/3 | **HIGH** |

---

## UC-01: Password Spraying Attack

### 1. Overview & Threat Vector
Password spraying is an authentication-based attack where an adversary attempts a small set of commonly used passwords (e.g., `Summer2026!`, `Welcome123!`, `Password123!`) against a large population of domain user accounts. By spreading attempts over time and across multiple usernames, the attacker attempts to remain below lockout thresholds (e.g., 5 attempts per single account).

### 2. Log Telemetry & Event Analysis
- **Primary Event**: Windows Security Event ID **4625** (*An account failed to log on*).
- **Critical Event Fields**:
  - `TargetUserName`: Target account identity.
  - `WorkstationName`: Originating caller hostname.
  - `IpAddress`: Source IP address initiating logon attempt.
  - `IpPort`: Source ephemeral network port.
  - `SubStatus`: Error code providing exact cause:
    - `0xC000006A`: User name exists, but password was incorrect.
    - `0xC0000064`: User name does not exist (User Enumeration indicator).
    - `0xC0000234`: User account locked out.
  - `LogonType`:
    - Type `3`: Network (SMB / NTLM / Kerberos).
    - Type `10`: RemoteInteractive (RDP).

### 3. Detection Logic & Aggregation Rules
- **Threshold Condition**: Alert if `>8` failed logon events (`4625`) occur within `300 seconds` (5 minutes) from the same `IpAddress` targeting different `TargetUserName` values.

### 4. Custom Wazuh Rule XML
```xml
<group name="windows,authentication,password_spray,">
  <rule id="100201" level="10">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^4625$</field>
    <same_source_ip />
    <different_user />
    <frequency>8</frequency>
    <timeframe>300</timeframe>
    <description>Password Spraying Attack Detected: High rate of failed logons from single source IP ($(win.eventdata.ipAddress)) targeting multiple domain accounts.</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
  </rule>
</group>
```

### 5. NIST SP 800-61 Rev 2 Incident Response Workflow

#### Phase 1: Preparation
- Enforce Fine-Grained Password Policies (FGPP) requiring minimum 15-character passwords.
- Configure Account Lockout Threshold to 5 attempts with 30-minute lockout window.
- Ingest Windows Security Event ID 4625 via WEF / Wazuh agents on all DCs (`DC01`, `DC02`).

#### Phase 2: Detection & Analysis
1. **Alert Triage**: Verify source IP `win.eventdata.ipAddress`. Check whether source IP is internal (`10.0.40.0/24`) or external/VPN.
2. **Impact Assessment**: Query Security Event ID **4624** (*Successful Logon*) for the same source IP within the surrounding timeframe to determine if any password attempt succeeded.
3. **Target Scope**: Extract all targeted usernames to check if compromised accounts belong to privileged groups (`OU=Executive`, `OU=IT`).

#### Phase 3: Containment, Eradication & Recovery
1. **Network Containment**: Block source IP address on pfSense firewall (`10.0.10.1`) and core switches.
2. **Credential Eradication**: For any user account that had a successful 4624 logon following a spray alert:
   - Immediately force password reset in Active Directory (`Set-ADAccountPassword`).
   - Revoke active Kerberos TGTs (`klist purge`) and invalidate active Entra ID/Web sessions.
   - Enforce MFA re-enrollment.
3. **Account Unlocking**: Audit locked-out accounts (`Search-ADAccount -LockedOut`) and unlock after verifying identity.

#### Phase 4: Post-Incident Activity
- Perform root-cause analysis on how external/internal host reached logon interfaces.
- Update threat intelligence feed with malicious IP address.
- Review and refine password spraying detection threshold if false positives occurred due to vulnerability scanners.

---

## UC-02: Kerberoasting Attack

### 1. Overview & Threat Vector
Kerberoasting (MITRE T1558.003) enables an authenticated attacker to request a Kerberos Ticket Granting Service (TGS) ticket for any domain service account associated with a Service Principal Name (SPN). The requested TGS ticket is encrypted with the service account's NTLM password hash. The attacker extracts the ticket offline and uses tools like `John the Ripper` or `hashcat` to crack the cleartext password.

### 2. Log Telemetry & Event Analysis
- **Primary Event**: Windows Security Event ID **4769** (*A Kerberos service ticket was requested*).
- **Critical Event Fields**:
  - `ServiceName`: Target service account receiving the TGS request.
  - `ServiceSid`: Security Identifier of the target service.
  - `TicketEncryptionType`: Encryption cipher requested:
    - `0x17` (23): **RC4-HMAC** (Weak, vulnerable to rapid offline cracking).
    - `0x12` (18): AES256-CTS-HMAC-SHA1-96 (Secure).
    - `0x11` (17): AES128-CTS-HMAC-SHA1-96 (Secure).
  - `TicketOptions`: `0x40810000` or similar flags.
  - `IpAddress`: Client IP requesting the TGS ticket.

### 3. Detection Logic
- **Condition**: Event ID `4769` where `TicketEncryptionType == 0x17` AND `ServiceName` is NOT a computer account (does NOT end with `$`) AND `ServiceName` is not `krbtgt`.

### 4. Custom Wazuh Rule XML
```xml
<group name="windows,kerberos,kerberoast,">
  <rule id="100202" level="12">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <field name="win.eventdata.serviceName" type="pcre2">^(?!.*\$).*$</field>
    <field name="win.eventdata.serviceName" type="pcre2">^(?!krbtgt).*$</field>
    <description>Kerberoasting Attack Detected: TGS ticket requested with weak RC4 encryption (0x17) for service account ($(win.eventdata.serviceName)) from IP ($(win.eventdata.ipAddress)).</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>
</group>
```

### 5. NIST SP 800-61 Rev 2 Incident Response Workflow

#### Phase 1: Preparation
- Convert legacy service accounts to **Group Managed Service Accounts (gMSAs)** with 128-character auto-rotating passwords.
- Configure Active Directory domain controller policy to disable RC4-HMAC for Kerberos ticket requests where supported.
- Enable Advanced Audit Policy: *Audit Kerberos Service Ticket Operations* (Success).

#### Phase 2: Detection & Analysis
1. **Identify Source Account**: Extract requesting user account (`TargetUserName`) and source IP (`IpAddress`) from Event 4769.
2. **Evaluate Target Service**: Check permissions of `ServiceName` (e.g., MSSQL service accounts with Domain Admin rights).
3. **Volume Analysis**: Check if the requesting account issued multiple 4769 RC4 requests across various SPNs within a brief period (mass Kerberoasting).

#### Phase 3: Containment, Eradication & Recovery
1. **Service Account Rotation**: Immediately change password of targeted service account to a complex 32+ character random string.
2. **Account Isolation**: Disable or reset credentials for the requesting user account (`TargetUserName`).
3. **Session Termination**: Purge Kerberos tickets on host and disconnect active SMB/RDP sessions from source IP.

#### Phase 4: Post-Incident Activity
- Audit all SPNs in Active Directory (`Get-ADUser -Filter {ServicePrincipalName -ne "$null"}`).
- Migrate any remaining legacy password-based service accounts to gMSAs.
- Document incident timeline and report findings to IAM governance team.

---

## UC-03: Group Policy Object Tampering

### 1. Overview & Threat Vector
Adversaries with compromised administrative credentials modify Group Policy Objects (GPOs) to execute commands across domain endpoints, create persistence mechanisms, disable security controls, or deploy ransomware (MITRE T1484.001). GPO tampering occurs either via Active Directory LDAP attribute modifications or direct file creation/edits within the SYSVOL share (`\\CORP.LOCAL\SYSVOL\Policies\...`).

### 2. Log Telemetry & Event Analysis
- **Directory Audit Event**: Windows Security Event ID **5136** (*A directory service object was modified*).
  - `AttributeLDAPDisplayName`: `gPCFileSysPath`, `gPCMachineExtensionNames`, or `versionNumber`.
  - `ObjectDN`: Distinguished Name of modified GPO object.
  - `SubjectUserName`: Account executing the modification.
- **Endpoint File Audit Event**: Sysmon Event ID **11** (*FileCreate*).
  - `TargetFilename`: File path matching `*\SYSVOL\Policies\{GUID}\*` (e.g., `GptTmpl.inf`, `Groups.xml`, `ScheduledTasks.xml`).
  - `Image`: Process modifying file (e.g., `mmc.exe`, `powershell.exe`).

### 3. Detection Logic
- **Condition**: Trigger critical alert when Event `5136` modifies `gPCFileSysPath` OR Sysmon ID `11` creates/modifies files under `\SYSVOL\Policies\` outside of scheduled maintenance windows or by non-Domain Admin accounts.

### 4. Custom Wazuh Rule XML
```xml
<group name="windows,active_directory,gpo_tampering,">
  <!-- GPO LDAP Attribute Modification Rule -->
  <rule id="100203" level="13">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^5136$</field>
    <field name="win.eventdata.attributeLDAPDisplayName">^gPCFileSysPath$|^gPCMachineExtensionNames$</field>
    <description>CRITICAL: Group Policy Object LDAP Attribute Tampered: GPO attribute ($(win.eventdata.attributeLDAPDisplayName)) modified by $(win.eventdata.subjectUserName).</description>
    <mitre>
      <id>T1484.001</id>
    </mitre>
  </rule>

  <!-- SYSVOL File Creation/Modification Rule -->
  <rule id="100204" level="12">
    <if_sid>100100</if_sid>
    <field name="win.system.eventId">^11$</field>
    <field name="win.eventdata.targetFilename" type="pcre2">\\SYSVOL\\Policies\\</field>
    <description>SYSVOL File Creation Detected: File created under SYSVOL policy path ($(win.eventdata.targetFilename)) by $(win.eventdata.image).</description>
    <mitre>
      <id>T1484.001</id>
    </mitre>
  </rule>
</group>
```

### 5. NIST SP 800-61 Rev 2 Incident Response Workflow

#### Phase 1: Preparation
- Enable Directory Service Changes auditing on Domain Controllers.
- Deploy Sysmon with file creation monitoring enabled for SYSVOL paths.
- Take automated nightly backups of AD GPO state (`Backup-GPO -All`).

#### Phase 2: Detection & Analysis
1. **Identify Modified GPO**: Extract GPO GUID from `ObjectDN` / `TargetFilename`.
2. **Diff Baseline**: Compare modified SYSVOL files (`ScheduledTasks.xml`, `Scripts`) against nightly GPO backup baselines to identify malicious scripts or registry changes.
3. **Actor Identification**: Identify `SubjectUserName` and IP address responsible for modification.

#### Phase 3: Containment, Eradication & Recovery
1. **GPO Rollback**: Restore clean GPO baseline from backup using `Restore-GPO`.
2. **Force Refresh**: Issue `gpupdate /force` across endpoint subnets to purge malicious GPO state.
3. **Account Revocation**: Disable the administrative account used for tampering and revoke all active kerberos admin sessions.

#### Phase 4: Post-Incident Activity
- Conduct full audit of Active Directory GPO Delegation permissions (`Get-GPO -All | Get-GPOACL`).
- Enforce Advanced Group Policy Management (AGPM) workflow requiring approval for GPO modifications.

---

## UC-04: PsExec Lateral Movement

### 1. Overview & Threat Vector
PsExec is a legitimate Sysinternals utility frequently abused by threat actors for lateral movement (MITRE T1021.002). PsExec connects to a remote host over SMB (Port 445), writes the `PSEXESVC.exe` binary to `C:\Windows\`, registers a Windows Service named `PSEXESVC`, and executes commands under `NT AUTHORITY\SYSTEM`.

### 2. Log Telemetry & Event Analysis
- **Service Creation Event**: Windows System Event ID **7045** (*A service was installed in the system*).
  - `ServiceName`: `PSEXESVC` (or randomized name in custom PsExec variants).
  - `ImagePath`: `%SystemRoot%\PSEXESVC.exe`.
  - `ServiceType`: `user mode service`.
  - `StartType`: `demand start`.
  - `AccountName`: `LocalSystem`.
- **Sysmon Process Creation**: Event ID **1**.
  - `Image`: `*\psexec.exe` or `*\psexesvc.exe`.
  - `ParentImage`: `services.exe` -> `psexesvc.exe` -> `cmd.exe`.
- **Sysmon Network Connection**: Event ID **3**.
  - `DestinationPort`: `445` (SMB) or `135` (RPC).

### 3. Detection Logic
- **Condition**: High-priority alert when Event `7045` installs service `PSEXESVC` OR Sysmon Event ID `1` detects execution of `psexesvc.exe`.

### 4. Custom Wazuh Rule XML
```xml
<group name="windows,lateral_movement,psexec,">
  <!-- Windows System 7045 Service Creation Rule -->
  <rule id="100205" level="12">
    <if_sid>60109</if_sid>
    <field name="win.system.eventId">^7045$</field>
    <field name="win.eventdata.serviceName">^PSEXESVC$</field>
    <description>PsExec Service Installation Detected: Remote execution service (PSEXESVC) installed on endpoint $(win.system.computer).</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
  </rule>

  <!-- Sysmon Process Execution Rule for PsExec -->
  <rule id="100206" level="12">
    <if_sid>100100</if_sid>
    <field name="win.system.eventId">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)psexesvc\.exe</field>
    <description>PsExec Remote Execution Active: Process psexesvc.exe executed under services.exe on $(win.system.computer).</description>
    <mitre>
      <id>T1021.002</id>
    </mitre>
  </rule>
</group>
```

### 5. NIST SP 800-61 Rev 2 Incident Response Workflow

#### Phase 1: Preparation
- Implement Workstation-to-Workstation SMB blocking via Windows Firewall GPO (`GPO-Windows-Firewall-Baseline`).
- Deploy LAPS to prevent local admin password reuse across endpoints.
- Configure WEF and Sysmon auditing for Event IDs 7045, 1, and 3.

#### Phase 2: Detection & Analysis
1. **Identify Source & Destination**: Match Sysmon Event ID 3 network connection on port 445 to determine initiating source host (`10.0.40.X`) and target host.
2. **Inspect Executed Commands**: Review Sysmon Event ID 1 process tree under `psexesvc.exe` (e.g., `cmd.exe /c whoami`, `powershell -enc ...`).
3. **Credential Audit**: Identify which account initiated the SMB connection.

#### Phase 3: Containment, Eradication & Recovery
1. **Host Isolation**: Isolate both source and destination endpoints from the network using Wazuh Active Response / Firewall drop rules.
2. **Service Termination**: Stop `PSEXESVC` service (`sc stop PSEXESVC`), delete service (`sc delete PSEXESVC`), and remove `C:\Windows\PSEXESVC.exe`.
3. **Credential Reset**: Force immediate password reset for compromised user account and rotate LAPS passwords (`Reset-AdmPwdPassword`).

#### Phase 4: Post-Incident Activity
- Verify firewall rules preventing lateral SMB traffic between endpoints.
- Review SOC alerts for prior stages of attack (e.g., initial access, credential dumping).
- Update SIEM rules to detect randomized PsExec service names.
