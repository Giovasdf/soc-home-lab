# 01 · Network Reconnaissance with Nmap

## Objective

Confirm which services are reachable on the Windows victim VM before attacking any of them, the way a real reconnaissance phase would, and see whether Wazuh/Sysmon surfaces a port scan as suspicious activity.

## Environment

- Wazuh 4.14.10 on Ubuntu Server 24.04 ARM64 (`192.168.154.10`)
- Windows 11 ARM victim with Sysmon + Wazuh agent (`192.168.154.20`)
- Kali Linux ARM64 attacker (`192.168.154.132`, DHCP)
- VMware Fusion host-only network `Private to my Mac`, `192.168.154.0/24`, no internet access for Kali or the victim

## Attack

```
sudo nmap -sT -Pn -n -sV -T4 -p 21,22,23,80,135,139,443,445,3389,5985,5986 192.168.154.20
```
Run: 2026-11-13, 14:51 UTC.

## Troubleshooting (the real story here)

My first several attempts — plain `-sV` default scan, then a targeted connect scan, then even a single-port scan with `--host-timeout 15s` — all hung indefinitely. `ps aux` showed the nmap process in state `R+` at 99.9% CPU, not blocked waiting on the network — it was spinning, and `--host-timeout` never kicked in to stop it.

Isolating the cause: `nmap --version` and a scan against `127.0.0.1` completed instantly, so nmap itself wasn't broken — only scans against the remote victim were affected. Running with `--packet-trace` against a single port showed the actual sequence:

```
SENT (0.0388s) ARP who-has 192.168.154.20 tell 192.168.154.132
RCVD (0.0392s) ARP reply 192.168.154.20 is-at 00:0C:29:D8:0B:2C
NSOCK INFO ... nsock_connect_udp(): UDP connection requested to 192.168.154.1:53 ...
NSOCK INFO ... READ ERROR [Connection refused (111)] for EID 18 [192.168.154.1:53]
```

Nmap was attempting a reverse-DNS lookup of the target IP against `192.168.154.1:53` — the gateway address Fusion's isolated network implies, which runs no DNS server at all. The lookup is refused cleanly, but something downstream of that failure never recovers.

**Fix:** the `-n` flag, which disables DNS resolution entirely. With it, the single-port scan completed in 0.02 seconds; the full multi-port scan above completed in 7.37 seconds.

## Evidence

```
PORT     STATE    SERVICE       VERSION
21/tcp   filtered ftp
22/tcp   open     ssh           (protocol 2.0)
23/tcp   filtered telnet
80/tcp   filtered http
135/tcp  filtered msrpc
139/tcp  filtered netbios-ssn
443/tcp  filtered https
445/tcp  filtered microsoft-ds
3389/tcp filtered ms-wbt-server
5985/tcp filtered wsman
5986/tcp filtered wsmans
```

SSH banner fingerprint: `SSH-2.0-OpenSSH_for_Windows_10.4 Win32-OpenSSH-GitHub`

I did not find a distinct Wazuh/Sysmon alert tied specifically to this scan. Sysmon's default configuration (SwiftOnSecurity ruleset) does not include a network-connection-based port-scan detection rule out of the box, and the Windows agent wasn't configured with a dedicated network IDS rule for this. The only visible footprint was the ARP reply and the single successful TCP handshake against port 22 — not enough traffic against a single, already-open port to look anomalous.

## Analysis

The only genuinely open service is SSH, which matches the environment I built for the lab (OpenSSH Server, installed to stand in for RDP — see the main README for why). Every other probed port is "filtered" rather than "closed," meaning the Windows Defender Firewall is silently dropping the packets rather than sending a TCP RST — standard default-deny firewall behavior, and the reason my earlier timing issues were so confusing (silently dropped packets look identical to "still working" from nmap's perspective until a timeout is reached).

The nmap hang was the most interesting finding of this exercise, and not one I anticipated: it's a reminder that tooling assumptions (DNS will resolve, or will at least fail fast) don't always hold in an isolated lab network, and that diagnosing *why* a tool is stuck is itself a transferable skill — I used `ps aux` to confirm it was CPU-bound rather than network-blocked, then `--packet-trace` to see the actual failing call, rather than guessing at fixes.

## MITRE ATT&CK

`T1046` · Network Service Discovery

## Detection improvement

Sysmon's SwiftOnSecurity baseline config doesn't flag a single-target, low-port-count TCP scan like this one — and arguably shouldn't, since the traffic volume is tiny and the pattern (several sequential SYNs to different ports within a short window) is the real signal, not any individual connection attempt. A practical Wazuh rule here would correlate "N distinct destination ports contacted by the same source IP within M seconds" from Windows firewall logs (which do log blocked connection attempts) rather than relying on Sysmon alone, which has no visibility into traffic Windows's own firewall already dropped before the OS stack event-logs it.

## Lessons

- A hung tool deserves the same triage discipline as a hung production service: check CPU/wait state first, then trace the actual syscalls/packets, before changing random flags.
- `-n` (no DNS resolution) is worth defaulting to in any isolated lab network that has no real DNS infrastructure — it would have saved real time if I'd set it from the first attempt.
- Not every attacker action leaves an alert. A clean reconnaissance scan against a single open port, with no unusual volume, is a legitimate detection gap worth naming honestly rather than implying coverage that doesn't exist.
