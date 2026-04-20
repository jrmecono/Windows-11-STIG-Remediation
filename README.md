# 🛡️ Windows 11 STIG Remediation Lab

**Real vulnerability findings. Real fixes. Fully documented.**

This project remediates **10 failed DISA STIG findings** discovered during a live Tenable vulnerability scan against a Windows 11 system. Every fix is automated with PowerShell and verified with before/after evidence.

---

## 📊 Results at a Glance

| | Before | After |
|---|---|---|
| **Failed STIGs** | 10 | 0 |
| **HIGH severity** | 6 | 0 |
| **MEDIUM severity** | 4 | 0 |
| **Method** | — | PowerShell (automated) |
| **Evidence** | Tenable scan screenshots | Re-scan + terminal output |


---

## 🔍 What Was Fixed & Why It Matters

Each STIG was selected because it maps to a **real-world attack technique** used in modern intrusions.

---

### 1 — PowerShell Script Block Logging
**STIG:** `WN11-CC-000326` &nbsp;|&nbsp; **Severity:** MEDIUM

**The risk:** Without this, PowerShell attacks run invisibly. Attackers routinely use obfuscated or base64-encoded PS commands to evade detection — and none of it gets logged.

**The fix:** Enables Event ID **4104**, which captures the *decoded* content of every PS command executed — including payloads that were obfuscated before delivery.

**Script:** [`STIG-001_WN11-CC-000326_PSScriptBlockLogging.ps1`](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/STIG-001_WN11-CC-000326_PSScriptBlockLogging.ps1)

| Before | After |
|--------|-------|
| ![Before](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/WN11-CC-000326-Failed.png) | ![After](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/WN11-CC-000326.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/WN11-CC-000326-PS-output.png)

</details>

---

### 2 — PowerShell Transcription Logging
**STIG:** `WN11-CC-000327` &nbsp;|&nbsp; **Severity:** MEDIUM

**The risk:** An attacker who clears Windows Event Logs destroys forensic evidence. If PS sessions were never written to disk, incident responders have no timeline to work from.

**The fix:** Writes complete PS session records (input, output, errors) to `C:\PSTranscripts`. Transcript files survive log clearing — critical for post-incident forensics.

**Script:** [`STIG-002_WN11-CC-000327_PSTranscription.ps1`](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/STIG-002_WN11-CC-000327_PSTranscription.ps1)

| Before | After |
|--------|-------|
| ![Before](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/WN11-CC-000327-Failed.png) | ![After](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/WN11-CC-000327-Pass.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](https://github.com/jrmecono/Windows-11-STIG-Remediation/blob/main/WN11-CC-000327-PS-output.png)

</details>

---

### 3 — Disable WinRM Basic Authentication ⭐
**STIG:** `WN11-CC-000345` &nbsp;|&nbsp; **Severity:** HIGH
> **Bonus:** Also remediates `WN11-CC-000360` (WinRM Client Digest auth) in the same script.

**The risk:** WinRM Basic auth encodes credentials in Base64 — not encryption. Any network observer can decode them with a single command. Classic man-in-the-middle credential theft.

**The fix:** Disables Basic and Digest auth on both WinRM Service and Client, forcing Kerberos. Also disables unencrypted WinRM traffic.

**Script:** [`STIG-003_WN11-CC-000345_WinRM-BasicAuth.ps1`](scripts/STIG-003_WN11-CC-000345_WinRM-BasicAuth.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-003_WN11-CC-000345_before.png) | ![After](screenshots/after/STIG-003_WN11-CC-000345_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-003_WN11-CC-000345_terminal_after.png)

</details>

---

### 4 — Audit Process Creation (Event ID 4688)
**STIG:** `WN11-AU-000050` &nbsp;|&nbsp; **Severity:** MEDIUM

**The risk:** Without process creation logging, there is no record of what was executed on the system. Living-off-the-Land attacks (`certutil`, `mshta`, `wscript`) go completely undetected.

**The fix:** Enables Event ID **4688** with full command-line argument logging — the foundation of nearly every SIEM detection rule for endpoint threats and the #1 data source for incident response timelines.

**Script:** [`STIG-004_WN11-AU-000050_AuditProcessCreation.ps1`](scripts/STIG-004_WN11-AU-000050_AuditProcessCreation.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-004_WN11-AU-000050_before.png) | ![After](screenshots/after/STIG-004_WN11-AU-000050_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-004_WN11-AU-000050_terminal_after.png)

</details>

---

### 5 — Disable AlwaysInstallElevated ⭐
**STIG:** `WN11-CC-000315` &nbsp;|&nbsp; **Severity:** HIGH

**The risk:** When this is set in both `HKLM` and `HKCU`, *any standard user* can install a malicious MSI package and receive a SYSTEM shell. This is one of the first checks run by `PowerUp.ps1` and has a dedicated Metasploit module.

**The fix:** Sets the value to `0` in both registry hives. Must be disabled in both — one alone is not sufficient.

**Script:** [`STIG-005_WN11-CC-000315_AlwaysInstallElevated.ps1`](scripts/STIG-005_WN11-CC-000315_AlwaysInstallElevated.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-005_WN11-CC-000315_before.png) | ![After](screenshots/after/STIG-005_WN11-CC-000315_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-005_WN11-CC-000315_terminal_after.png)

</details>

---

### 6 — Enable Remote Credential Guard ⭐
**STIG:** `WN11-CC-000068` &nbsp;|&nbsp; **Severity:** HIGH

**The risk:** Without this, your credentials are copied into the remote host's LSASS memory during every RDP session. If that machine is compromised, Mimikatz can harvest your credentials — even domain admin ones.

**The fix:** Enables non-exportable credential delegation. Credentials stay on *your* machine and are never materialized in remote LSASS — blocking pass-the-hash from the remote end entirely.

**Script:** [`STIG-006_WN11-CC-000068_RemoteCredentialGuard.ps1`](scripts/STIG-006_WN11-CC-000068_RemoteCredentialGuard.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-006_WN11-CC-000068_before.png) | ![After](screenshots/after/STIG-006_WN11-CC-000068_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-006_WN11-CC-000068_terminal_after.png)

</details>

---

### 7 — Disable Kerberos DES and RC4 Encryption ⭐
**STIG:** `WN11-SO-000190` &nbsp;|&nbsp; **Severity:** HIGH

**The risk:** RC4 Kerberos tickets can be requested by *any* authenticated domain user and cracked offline with Hashcat. This is **Kerberoasting** ([MITRE T1558.003](https://attack.mitre.org/techniques/T1558/003/)) — one of the most common Active Directory attacks.

**The fix:** Disables DES (`0x1`, `0x2`) and RC4 (`0x4`), forcing AES-128 and AES-256 only. AES Kerberos tickets are computationally infeasible to crack offline.

**Script:** [`STIG-007_WN11-SO-000190_KerberosDES-RC4.ps1`](scripts/STIG-007_WN11-SO-000190_KerberosDES-RC4.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-007_WN11-SO-000190_before.png) | ![After](screenshots/after/STIG-007_WN11-SO-000190_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-007_WN11-SO-000190_terminal_after.png)

</details>

---

### 8 — Enforce NTLM Minimum Session Security ⭐
**STIG:** `WN11-SO-000220` &nbsp;|&nbsp; **Severity:** HIGH

**The risk:** Without enforced NTLM session security, systems can be downgraded to weak or unsigned authentication — enabling NTLM relay attacks using tools like Responder and ntlmrelayx. This class of attack appears in virtually every internal penetration test.

**The fix:** Enforces NTLMv2 + 128-bit encryption (`0x20080000`) on both server and client sides, preventing authentication downgrade attacks.

**Script:** [`STIG-008_WN11-SO-000220_NTLMSessionSecurity.ps1`](scripts/STIG-008_WN11-SO-000220_NTLMSessionSecurity.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-008_WN11-SO-000220_before.png) | ![After](screenshots/after/STIG-008_WN11-SO-000220_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-008_WN11-SO-000220_terminal_after.png)

</details>

---

### 9 — Account Lockout Threshold
**STIG:** `WN11-AC-000010` &nbsp;|&nbsp; **Severity:** MEDIUM

**The risk:** Without an account lockout policy, brute-force and password spraying attacks can run indefinitely with no consequence.

**The fix:** Sets lockout after **3 invalid attempts**, with a 15-minute lockout duration and observation window — stopping automated credential attacks cold.

**Script:** [`STIG-009_WN11-AC-000010_AccountLockout.ps1`](scripts/STIG-009_WN11-AC-000010_AccountLockout.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-009_WN11-AC-000010_before.png) | ![After](screenshots/after/STIG-009_WN11-AC-000010_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-009_WN11-AC-000010_terminal_after.png)

</details>

---

### 10 — Disable AutoRun for All Drive Types
**STIG:** `WN11-CC-000185` &nbsp;|&nbsp; **Severity:** HIGH

**The risk:** AutoRun executes code the moment a USB drive is plugged in — before the user does anything. This is the delivery mechanism behind USB drop attacks, Rubber Ducky, and BadUSB. Even air-gapped networks have been compromised through this vector.

**The fix:** Sets `NoDriveTypeAutoRun = 255` (all drive types disabled) and blocks `autorun.inf` execution entirely via both the user policy and Group Policy registry paths.

**Script:** [`STIG-010_WN11-CC-000185_DisableAutoRun.ps1`](scripts/STIG-010_WN11-CC-000185_DisableAutoRun.ps1)

| Before | After |
|--------|-------|
| ![Before](screenshots/before/STIG-010_WN11-CC-000185_before.png) | ![After](screenshots/after/STIG-010_WN11-CC-000185_tenable_after.png) |

<details>
<summary>📟 View PowerShell Output</summary>

![Terminal output](screenshots/after/STIG-010_WN11-CC-000185_terminal_after.png)

</details>

---

## 🚀 How to Run

> **Requirement:** PowerShell must be run as Administrator.

### Run all 10 scripts at once (recommended)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Run-AllRemediations.ps1
```

### Run a single script
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\STIG-007_WN11-SO-000190_KerberosDES-RC4.ps1
```

### What the output looks like
```
[PRE-CHECK]   Shows the current non-compliant state       (cyan)
[REMEDIATED]  Confirms the fix was applied                (green)
[BONUS]       Additional STIG fixed in the same script    (magenta)
[VERIFIED]    Confirms the setting is now compliant       (green)
[FAILED]      If the verification check does not pass     (red)
[NOTE]        Any reboot or follow-up required            (yellow)
```

---

## 📁 Repository Structure

```
WN11-STIG-Remediation/
│
├── Run-AllRemediations.ps1              ← Runs all 10 scripts + prints summary table
│
├── scripts/
│   ├── STIG-001_WN11-CC-000326_PSScriptBlockLogging.ps1
│   ├── STIG-002_WN11-CC-000327_PSTranscription.ps1
│   ├── STIG-003_WN11-CC-000345_WinRM-BasicAuth.ps1
│   ├── STIG-004_WN11-AU-000050_AuditProcessCreation.ps1
│   ├── STIG-005_WN11-CC-000315_AlwaysInstallElevated.ps1
│   ├── STIG-006_WN11-CC-000068_RemoteCredentialGuard.ps1
│   ├── STIG-007_WN11-SO-000190_KerberosDES-RC4.ps1
│   ├── STIG-008_WN11-SO-000220_NTLMSessionSecurity.ps1
│   ├── STIG-009_WN11-AC-000010_AccountLockout.ps1
│   └── STIG-010_WN11-CC-000185_DisableAutoRun.ps1
│
├── screenshots/
│   ├── before/    ← Tenable scan showing each STIG as Failed
│   └── after/     ← Tenable re-scan (Passed) + PowerShell terminal output per script
│
└── docs/
    └── STIG-References.md    ← Full attack mapping and interview talking points
```

---

## 📚 References

- [DISA STIG Library — Windows 11](https://public.cyber.mil/stigs/downloads/)
- [STIG Viewer 3.x](https://public.cyber.mil/stigs/stig-viewing-tools/)
- [MITRE ATT&CK — Kerberoasting T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK — NTLM Relay T1557.001](https://attack.mitre.org/techniques/T1557/001/)
- [MITRE ATT&CK — PowerShell T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

> ⚠️ **Disclaimer:** Scripts were developed and tested against a live Windows 11 VM. Always test in a lab environment before deploying to production systems.
