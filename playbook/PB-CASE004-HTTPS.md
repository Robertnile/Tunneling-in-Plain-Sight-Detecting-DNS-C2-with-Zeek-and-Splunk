# PB-CASE004-HTTPS — Meterpreter HTTPS C2 Incident Response Playbook

**Technique:** C2 over Encrypted HTTPS Channel
**MITRE ATT&CK:** T1071.001, T1573.002, T1105
**Severity:** High
**Lab Reference:** CASE-004 HTTPS Extension

---

## Preparation

Before this incident type can be detected, a few things need to be in place. I learned this the hard way building the lab — the detection pipeline has to exist before you can catch anything.

- Zeek deployed on the network with both `ssl.log` and `conn.log` being ingested into Splunk
- `[zeek:ssl]` stanza correctly configured in props.conf with `FIELD_HEADER_REGEX = ^#fields\t(.*)` — without this, field names misalign and every SPL query returns wrong results
- `ssl.log` monitored in inputs.conf and forwarded to the Splunk indexer
- Baseline established for normal HTTPS connection volume, destination distribution, and certificate validation status per host
- Detection alerts saved in Splunk for D1 (self-signed cert), D2 (repeated connections to same dest), D3 (beaconing interval)

---

## Identification

**Trigger:** One or more of the following Splunk detections fires:

- D1 — A host making HTTPS connections where `validation_status != "ok"`, especially to an internal IP on a non-standard port
- D2 — A host making more than 10 HTTPS connections to the same destination on a port other than 443
- D3 — A host with connection count > 5 and average interval < 60 seconds to port 4443 (or any non-standard HTTPS port)

**First questions I ask when one of these fires:**

- Which source IP is generating the traffic?
- What port is the destination using — is it 443 or non-standard?
- Is the destination an internal IP or external domain?
- Is the certificate self-signed or from an untrusted issuer?
- Are all three detections firing from the same source IP? If yes, confidence is very high.
- What time did the activity start — is it still ongoing?
- Has this host communicated with this destination before?

**Confidence levels:**

- D1 alone — investigate, not enough to confirm C2 on its own
- D1 + D2 — strong signal, escalate
- All three from the same source IP — near-certain C2, treat as confirmed until proven otherwise

---

## Containment

**Move fast here — an active Meterpreter session gives the attacker real-time access.**

- Isolate the affected host from the network immediately — pull the network cable or disable the NIC if remote isolation isn't available
- If it's a VM, suspend it rather than shutting it down — memory-resident payloads like Meterpreter disappear on reboot, and you want memory artifacts preserved for forensics
- Block outbound connections from the affected IP at the firewall as a backup measure
- If the C2 handler IP is identified (as in this lab, 192.168.122.3), block that destination across the entire network — other hosts may be compromised too

**What not to do:**
- Don't reboot the machine before forensic capture
- Don't delete the payload binary if it's on disk — it's evidence
- Don't assume only one host is affected

---

## Eradication

- Identify the process running the C2 agent — check running processes for anything unusual, especially processes with no legitimate parent, running from /tmp or other writable directories
- Locate the payload on disk if it touched disk — in this lab it was `/tmp/update-helper`, named to look like a legitimate system file
- Check for persistence — cron jobs, systemd services, startup entries, anything that would restart the payload after removal
- Remove the payload and any persistence mechanisms
- Rotate credentials for any accounts that were accessible during the C2 session — if the attacker had a root shell, assume all credentials on that machine are compromised
- Check for lateral movement — Meterpreter gives the attacker full access, so look for connections from the compromised host to other internal machines during the session window

---

## Recovery

- Restore the host from a known clean snapshot or rebuild if the depth of compromise is uncertain — if the attacker had root access for any meaningful period, a clean rebuild is safer than trying to clean up
- Re-enable network access only after confirming clean state
- Re-run D1, D2, D3 detections against the recovered host to confirm no residual beaconing
- Monitor the host closely for 24-48 hours after recovery

---

## Lessons Learned

**From building this lab:**

The most important thing I learned is that encryption protects the *content*, not the *behavior*. Meterpreter's payload is completely hidden inside TLS — but the certificate it uses is self-signed, it connects to the same destination hundreds of times, and it does so at machine speed. None of that changes because the channel is encrypted.

The User-Agent masquerading was interesting to observe — Meterpreter sends a real Windows Edge browser string to make the traffic look like normal browsing. That kind of evasion works against basic inspection but doesn't change the metadata signals at all. The certificate is still self-signed. The beaconing interval is still 2 seconds. The destination is still an internal IP on port 4443.

Comparing this to the DNS tunneling lab: DNS had more obvious signals (encoded query names, unusual record types) but the detection methodology is identical. Watch what the channel does, not what it carries. That approach works across both protocols and would work against other C2 protocols too.

**The gap this lab exposed:**

My detections work well against Meterpreter using a non-standard port and self-signed cert — which covers a significant portion of real-world commodity malware. They would struggle against a sophisticated attacker using port 443 with a valid certificate and jittered intervals. That's the honest limitation, and closing that gap requires endpoint telemetry (EDR) in addition to network detection — which is exactly what the Velociraptor lab (CASE-002) provides.

The two labs together — network detection and endpoint detection — are significantly stronger than either alone.

**Recommended follow-up:**
- Add cert fingerprint tracking to flag when the same certificate hash appears across multiple source IPs — a single Meterpreter cert being used across multiple compromised hosts is a strong lateral movement indicator
- Consider adding JA3 fingerprinting to Zeek — it fingerprints the TLS handshake itself and can identify Meterpreter even when using a valid certificate on port 443
- Document this playbook alongside PB-CASE004 as the HTTPS-specific companion to the DNS tunneling playbook

---

*PB-CASE004-HTTPS | CASE-004 Extension — Meterpreter HTTPS C2 | robertnile.github.io*
