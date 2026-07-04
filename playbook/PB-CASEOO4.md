# PB-CASE004 — Tunneling in Plain Sight: DNS C2 Incident Response Playbook

**Technique:** DNS Tunneling / C2 over DNS
**MITRE ATT&CK:** T1071.004, T1048.003, T1572
**Severity:** High
**Lab Reference:** CASE-004

---

## Preparation

Before this incident type can be detected, the following must be in place:

- Zeek deployed on network with `dns.log` ingestion into Splunk configured and field parsing verified (see CASE-004 props.conf fix)
- Splunk sourcetype `zeek:dns` correctly parsing TSV fields including `qtype_name`, `query`, `id_orig_h`
- Baseline established for normal DNS query volume and record type distribution per host
- Detection alerts saved in Splunk for D1 (unusual record types), D2 (long query length), D3 (high query rate)

---

## Identification

**Trigger:** One or more of the following Splunk detections fires:

- D1 — Single host generating TXT, MX, CNAME, or NULL queries in high volume
- D2 — Query names exceeding 50 characters, majority in the 200+ range, from a single source IP
- D3 — Source IP with query count > 100 and average interval < 5 seconds

**Initial triage questions:**
- Which source IP is generating the anomalous traffic?
- What time did the activity start and is it still ongoing?
- Are all three detections firing from the same source IP? (If yes, confidence is high)
- Is the destination DNS server internal or external?
- Has this host generated this type of traffic before?

**Confidence is high when:**
All three detections fire from the same source IP within the same time window. A single detection alone warrants investigation but not immediate escalation.

---

## Containment

**Short-term — isolate the host:**
- Remove the affected host from the network immediately
- If the host is a VM, suspend it rather than shutting down to preserve memory artifacts
- Block outbound UDP port 53 from the affected IP at the firewall if full isolation is not immediately possible

**Do not:**
- Reboot the machine before forensic capture — memory-resident payloads will be lost
- Delete or overwrite logs on the affected host

---

## Eradication

- Identify the process responsible for the DNS queries using endpoint tooling (EDR, Velociraptor, or manual process enumeration)
- Locate the binary or script generating the traffic — check common masquerading paths (`/tmp`, `/usr/lib`, `/var/tmp`, scheduled tasks, startup entries)
- Remove the malicious binary or script
- Check for persistence mechanisms: cron jobs, systemd services, registry run keys (Windows), startup folders
- Rotate any credentials that may have been accessed during the C2 session
- Review what commands were executed during the tunnel session if shell history or logs are available

---

## Recovery

- Restore the host from a known clean snapshot or rebuild if compromise depth is uncertain
- Re-enable network access only after clean state is confirmed
- Verify DNS traffic from the host returns to baseline after recovery
- Re-run D1, D2, D3 detections against the recovered host to confirm no residual activity

---

## Lessons Learned

**From CASE-004:**

The most important finding from this lab was that behavioral detection works regardless of how the C2 agent was deployed. The three detections caught the tunnel based on network behavior — record types, query length, query rate — none of which change based on the binary name, file path, or delivery method. This approach is more durable than signature-based detection in real environments where attackers actively evade known IOCs.

The CV-based beaconing filter required tuning. Standard CV < 1.0 thresholds assume periodic implants. Interactive C2 shells produce bursty traffic that inflates CV well above 1.0. Detection 3 was adjusted to use volume and average interval instead, which correctly isolated the tunnel without false positives.

The Zeek TSV field parsing issue (`FIELD_HEADER_REGEX`) is a configuration requirement that should be part of any standard Zeek/Splunk deployment checklist. Without it, all field-based detections fail silently.

**Recommended follow-up actions:**
- Add `tonumber()` wrappers to any SPL queries doing numeric comparisons on `avg()` or `stdev()` output
- Document the props.conf fix as a standard deployment step for all future Zeek sourcetypes
- Consider adding a DNS response size detection to complement the existing three query-side detections
- Evaluate endpoint visibility gap — network-only detection cannot catch the deployment phase of C2 tooling

---

*PB-CASE004 | CASE-004 — Tunneling in Plain Sight | robertnile.github.io*
