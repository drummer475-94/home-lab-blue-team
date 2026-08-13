# Automated Verification Suite for Enterprise SOC & Blue Team Blueprint
# Validates Markdown files, Mermaid diagrams, Subnet IP allocations, Wazuh rulesets, and NIST IR workflows.

$ErrorActionPreference = "Stop"
$script:testCount = 0
$script:passCount = 0
$script:failCount = 0

function Assert-Check {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$Message = ""
    )
    $script:testCount++
    if ($Condition) {
        $script:passCount++
        Write-Host "  [PASS] Test $script:testCount : $TestName" -ForegroundColor Green
    } else {
        $script:failCount++
        Write-Host "  [FAIL] Test $script:testCount : $TestName - $Message" -ForegroundColor Red
    }
}

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " Starting Enterprise SOC & Blue Team Blueprint Verification Suite " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$baseDir = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $baseDir "README.md"))) {
    $baseDir = Get-Location
}

$readmePath    = Join-Path $baseDir "README.md"
$archPath      = Join-Path $baseDir "docs\architecture.md"
$topoPath      = Join-Path $baseDir "docs\topology.md"
$useCasesPath  = Join-Path $baseDir "docs\detection_use_cases.md"

# Tier 1: File Existence & Basic Structure
Write-Host "`n--- TIER 1: Core File Structure & File Existence ---" -ForegroundColor Yellow
Assert-Check "README.md exists" (Test-Path $readmePath)
Assert-Check "docs/architecture.md exists" (Test-Path $archPath)
Assert-Check "docs/topology.md exists" (Test-Path $topoPath)
Assert-Check "docs/detection_use_cases.md exists" (Test-Path $useCasesPath)

# Tier 2: README & Quick Review Guide Verification
Write-Host "`n--- TIER 2: README & Quick Review Guide ---" -ForegroundColor Yellow
$readmeContent = Get-Content $readmePath -Raw
Assert-Check "README contains 60-Second Quick Review Guide" ($readmeContent -match "Quick Review Guide")
Assert-Check "README targets SOC Tier 1 / IAM / Security Engineering roles" ($readmeContent -match "SOC Tier 1 Analyst" -and $readmeContent -match "Cybersecurity Engineer")
Assert-Check "README contains high-level Mermaid data flow diagram" ($readmeContent -match '```mermaid' -and $readmeContent -match "WazuhMgr")
Assert-Check "README contains badges and link navigation matrix" ($readmeContent -match "docs/architecture.md" -and $readmeContent -match "docs/topology.md")

# Tier 3: Network Topology & 5-Subnet Layout Verification
Write-Host "`n--- TIER 3: Network Topology & 5-Subnet IP Layout ---" -ForegroundColor Yellow
$topoContent = Get-Content $topoPath -Raw
Assert-Check "topology.md contains valid Mermaid flowchart diagram" ($topoContent -match '```mermaid' -and $topoContent -match "flowchart TD")
Assert-Check "Subnet 1: 10.0.10.0/24 Management Subnet present" ($topoContent -match "10\.0\.10\.0/24")
Assert-Check "Subnet 2: 10.0.20.0/24 Core AD Subnet present" ($topoContent -match "10\.0\.20\.0/24" -and $topoContent -match "DC01\.CORP\.LOCAL")
Assert-Check "Subnet 3: 10.0.30.0/24 SOC/SIEM Subnet present" ($topoContent -match "10\.0\.30\.0/24" -and $topoContent -match "Wazuh Manager")
Assert-Check "Subnet 4: 10.0.40.0/24 Endpoints Subnet present" ($topoContent -match "10\.0\.40\.0/24" -and $topoContent -match "WKSTN01")
Assert-Check "Subnet 5: 10.0.50.0/24 DMZ Subnet present" ($topoContent -match "10\.0\.50\.0/24" -and $topoContent -match "Nginx Reverse Proxy")
Assert-Check "topology.md contains Firewall Policy Matrix" ($topoContent -match "Firewall Policy Matrix" -and $topoContent -match "ALLOW" -and $topoContent -match "DENY")
Assert-Check "topology.md contains Virtualization Host Specs" ($topoContent -match "Virtualization Host Specifications" -and $topoContent -match "Proxmox")

# Tier 4: Active Directory & Wazuh SIEM Architecture Verification
Write-Host "`n--- TIER 4: Active Directory DS & Wazuh SIEM Architecture ---" -ForegroundColor Yellow
$archContent = Get-Content $archPath -Raw
Assert-Check "architecture.md specifies CORP.LOCAL domain" ($archContent -match "CORP\.LOCAL")
Assert-Check "architecture.md defines complete OU tree structure" ($archContent -match "OU=Executive" -and $archContent -match "OU=IT" -and $archContent -match "OU=Finance" -and $archContent -match "OU=Workstations" -and $archContent -match "OU=Servers")
Assert-Check "architecture.md details GPO baseline policies" ($archContent -match "GPO-Domain-Password-Policy" -and $archContent -match "GPO-Advanced-Audit-Policy")
Assert-Check "architecture.md details LAPS deployment and permissions" ($archContent -match "LAPS" -and $archContent -match "Update-AdmPwdADSchema")
Assert-Check "architecture.md includes Sysmon modular configuration schema" ($archContent -match '<Sysmon schemaversion=' -and $archContent -match "Event ID 1: Process Creation")
Assert-Check "architecture.md details Wazuh agent ossec.conf" ($archContent -match '<ossec_config>' -and $archContent -match "10\.0\.30\.10")
Assert-Check "architecture.md contains custom Wazuh local_rules.xml" ($archContent -match '<group name=' -and $archContent -match "rule id=")

# Tier 5: Detection Use-Cases & NIST SP 800-61 Rev 2 IR Playbooks
Write-Host "`n--- TIER 5: Detection Use-Cases & NIST Incident Response ---" -ForegroundColor Yellow
$ucContent = Get-Content $useCasesPath -Raw
Assert-Check "UC-01: Password Spraying Attack (T1110.003) present" ($ucContent -match "UC-01: Password Spraying Attack" -and $ucContent -match "T1110\.003" -and $ucContent -match "4625")
Assert-Check "UC-02: Kerberoasting Attack (T1558.003) present" ($ucContent -match "UC-02: Kerberoasting Attack" -and $ucContent -match "T1558\.003" -and $ucContent -match "4769" -and $ucContent -match "0x17")
Assert-Check "UC-03: GPO Tampering (T1484.001) present" ($ucContent -match "UC-03: Group Policy Object Tampering" -and $ucContent -match "T1484\.001" -and $ucContent -match "5136")
Assert-Check "UC-04: PsExec Lateral Movement (T1021.002) present" ($ucContent -match "UC-04: PsExec Lateral Movement" -and $ucContent -match "T1021\.002" -and $ucContent -match "7045")
Assert-Check "Use cases contain custom Wazuh XML rules" ($ucContent -match '<group name=' -and $ucContent -match '<rule id=')
Assert-Check "All 4 NIST SP 800-61 Rev 2 IR phases present across use-cases" ($ucContent -match "Phase 1: Preparation" -and $ucContent -match "Phase 2: Detection" -and $ucContent -match "Phase 3: Containment" -and $ucContent -match "Phase 4: Post-Incident Activity")

# Summary Results
Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host " Verification Summary: Total: $script:testCount | Passed: $script:passCount | Failed: $script:failCount " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

if ($script:failCount -eq 0) {
    Write-Host " SUCCESS: All enterprise SOC blueprint assertions passed! (100% PASS)" -ForegroundColor Green
    exit 0
} else {
    Write-Host " FAILURE: $script:failCount assertion(s) failed." -ForegroundColor Red
    exit 1
}

