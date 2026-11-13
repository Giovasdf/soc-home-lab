# 03 · Encoded PowerShell Command

## Objective

Trigger PowerShell's Base64-encoded command execution pattern — a technique commonly used to obscure a command's real content from casual log review — and confirm Wazuh/Sysmon flags it, then investigate every alert it produces rather than taking the alert descriptions at face value.

## Environment

- Wazuh 4.14.10 on Ubuntu Server 24.04 ARM64 (`192.168.154.10`)
- Windows 11 ARM victim (`192.168.154.20`) with Sysmon (SwiftOnSecurity config) + Wazuh agent

## Attack

Run directly on the victim, in a normal (non-admin) PowerShell prompt:

```
powershell -EncodedCommand dwBoAG8AYQBtAGkA
```

The Base64 string decodes to `whoami` — the command itself is harmless. The exercise is about the *encoding pattern*, not the payload: encoded commands are a standard way real attackers hide intent from a human glancing at process command lines, and it's a pattern worth confirming gets flagged regardless of what's inside it.

Run: 2026-11-13, 15:06:31–33 UTC.

## Evidence

Two alerts fired within the same second:

**Alert 1 — the expected one**
```
15:06:33.352 UTC
rule.id: 92057, level 12
"Powershell.exe spawned a powershell process which executed a base64 encoded command"
```

**Alert 2 — unexpected, the interesting one**
```
15:06:33.352 UTC
rule.id: 92213, level 15 (the highest severity seen anywhere in this lab)
"Executable file dropped in folder commonly used by malware"
rule.mitre.id: T1105 (Ingress Tool Transfer), tactic: Command and Control
```

I didn't assume the second alert was accurate just because it fired alongside the first. Pulling the full raw event (Sysmon Event ID 11, FileCreate) behind rule 92213:

```
data.win.eventdata.image:          C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
data.win.eventdata.targetFilename: C:\Users\gmoli\AppData\Local\Temp\__PSScriptPolicyTest_fxu0zyqf.3xl.ps1
data.win.eventdata.user:           Giovanni\gmoli
data.win.eventdata.utcTime:        2026-11-13 15:06:31.709
```

## Analysis

`__PSScriptPolicyTest_*.ps1` is not a malicious payload or a dropped tool — it's a temporary file that Windows PowerShell creates internally, on its own, as part of evaluating the local script execution policy (an AMSI/Script Block policy check) every time PowerShell starts with certain parameters, `-EncodedCommand` among them. The command I ran never wrote, downloaded, or dropped anything; this file is a side effect of PowerShell's own startup routine, not of the `whoami` payload.

Rule `92213`'s underlying logic is reasonable in general: `.ps1`/`.exe`/`.dll` and similar files appearing in a user's `Temp` folder *is* a common indicator of malware staging. The rule just has no exception for this one specific, well-known, benign filename pattern that PowerShell itself generates constantly — meaning this exact alert will likely fire on *any* encoded (or even some non-encoded) PowerShell invocation on this host, true attack or not.

This is the difference between an alert and a finding: the alert said "possible malware drop, Command and Control technique, severity 15." The finding, after checking the raw event data, is "this is normal PowerShell startup behavior, and the rule needs a documented exception." Treating the first as the second without checking would have been a false positive escalated as a true one.

## MITRE ATT&CK

- `T1059.001` · PowerShell (the intended exercise — correctly detected, rule 92057)
- `T1105` · Ingress Tool Transfer (rule 92213's own mapping — **not applicable here**; see Analysis)

## Detection improvement

Exclude the `__PSScriptPolicyTest_.*\.ps1$` filename pattern from rule `92213`'s match condition (or add a lower-severity, informational rule specifically for this known-benign artifact so it's still visible in a hunt but doesn't inflate the alert queue at the highest severity tier). Any SOC running Sysmon's standard FileCreate-in-Temp detection against a fleet of Windows 11 hosts running PowerShell regularly would otherwise see this exact false positive repeatedly, at the highest severity level available in the ruleset — exactly the kind of noise that trains analysts to stop trusting high-severity alerts.

## Lessons

- A high `rule.level` is not the same as a confirmed finding. The level reflects how bad the *pattern* would be if the alert's assumption holds — not whether it actually does, in this specific event.
- Checking the raw event fields (`targetFilename`, `image`, `user`, timestamps) behind an alert description takes under a minute and is the difference between writing "detected malware drop" and writing an accurate, defensible report.
- A rule that's logically sound in general can still produce a predictable false positive against a specific, well-known artifact — and naming that gap, with a concrete fix, is more useful to a team than either ignoring the alert or escalating it uncritically.
