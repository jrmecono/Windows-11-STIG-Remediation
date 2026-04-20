<#
.SYNOPSIS
    STIG ID   : WN11-CC-000327
    Rule Title: PowerShell Transcription must be enabled on Windows 11
    Severity  : MEDIUM
    Author    : [Your Name]
    Tested On : Windows 11

.DESCRIPTION
    Transcription writes a complete record of every PowerShell session to disk —
    input, output, and errors. Transcript files survive event log clearing,
    making them critical for incident response and forensic timelines.

.NOTES
    Run as Administrator. No reboot required.
    Transcript output path: C:\PSTranscripts
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$regPath       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$transcriptDir = "C:\PSTranscripts"

Write-Host "`n======================================================" -ForegroundColor DarkCyan
Write-Host "  STIG WN11-CC-000327 | PS Transcription Logging" -ForegroundColor Cyan
Write-Host "======================================================`n" -ForegroundColor DarkCyan

# --- PRE-CHECK ---
Write-Host "[PRE-CHECK] Reading current Transcription state..." -ForegroundColor Cyan
$pre = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
Write-Host "  EnableTranscripting    : $($pre.EnableTranscripting)"
Write-Host "  OutputDirectory        : $($pre.OutputDirectory)"
Write-Host "  EnableInvocationHeader : $($pre.EnableInvocationHeader)"

# --- REMEDIATION: Create and lock transcript directory ---
if (-not (Test-Path $transcriptDir)) {
    New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
    Write-Host "[REMEDIATED] Created transcript directory: $transcriptDir" -ForegroundColor Green
}

# Restrict directory to Administrators and SYSTEM only
$acl = Get-Acl $transcriptDir
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")))
Set-Acl -Path $transcriptDir -AclObject $acl
Write-Host "[REMEDIATED] Transcript directory locked to Administrators/SYSTEM only." -ForegroundColor Green

# --- REMEDIATION: Enable transcription via registry ---
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "EnableTranscripting"    -Value 1             -Type DWord
Set-ItemProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1             -Type DWord
Set-ItemProperty -Path $regPath -Name "OutputDirectory"        -Value $transcriptDir -Type String
Write-Host "[REMEDIATED] Transcription enabled. Output directory: $transcriptDir" -ForegroundColor Green

# --- VERIFICATION ---
$val = (Get-ItemProperty -Path $regPath).EnableTranscripting
if ($val -eq 1) {
    Write-Host "[VERIFIED] PASSED — PS Transcription is ENABLED. Sessions logged to $transcriptDir`n" -ForegroundColor Green
} else {
    Write-Host "[VERIFIED] FAILED — PS Transcription NOT enabled!`n" -ForegroundColor Red
    exit 1
}
