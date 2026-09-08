# PLAN_PLAYBOOKS_2.md — IP & Person Playbooks

## Scope

Add two YAML recipes (`ip.yaml`, `person.yaml`) and the minimal runner extensions
to make them produce high-quality Markdown/PDF reports. No engine (loader/CLI)
changes required — all tooling is already wired.

---

## Verified facts from exploration

### Tools already in TOOL_MAP + TOOL_REQUIREMENTS (runner.py lines 35–77)

| Recipe tool key    | Function              | Requirement              | Zero-config? |
|--------------------|-----------------------|--------------------------|--------------|
| `search_ip`        | `run_ip_osint`        | none (ipinfo.io free)    | YES          |
| `generate_dorks`   | `run_dork_osint`      | none (no network)        | YES          |
| `search_shodan`    | `run_shodan_osint`    | env `SHODAN_API_KEY`     | NO           |
| `search_virustotal`| `run_virustotal_osint`| env `VIRUSTOTAL_API_KEY` | NO           |
| `search_paste`     | `run_paste_osint`     | none (psbdmp.ws public)  | YES          |
| `search_username`  | `run_username_osint`  | binary `sherlock`        | NO           |
| `search_email`     | `run_email_osint`     | binary `holehe`          | NO           |

### Extractors already in EXTRACTOR_REGISTRY (extractors.py lines 524–539)
`search_ip`, `search_shodan`, `search_virustotal`, `search_username`, `search_email` — all present.
`generate_dorks` and `search_paste` have **no** extractor → they contribute 0 counts in
the summary (safe — matches domain recipe behaviour for `generate_dorks`).

### CLI wiring (cli.py lines 534–550, 783–800, 1033)
`openosint playbook <name> <target>` dispatches to `load_recipe(name)` then
`run_playbook(recipe, target)`. Adding a new YAML file is all that's needed for
the CLI to accept `openosint playbook ip <ip>` and `openosint playbook person <username>`.

### Confirmed output formats (source-verified)
| Tool key           | Output prefix pattern                         |
|--------------------|-----------------------------------------------|
| `search_ip`        | `[+] Key: Value` (same structure as WHOIS)    |
| `search_shodan`    | `[+] Key: Value` (same structure as WHOIS)    |
| `search_virustotal`| `[VirusTotal] Key: Value`                     |
| `search_paste`     | `Found in N paste(s)…` then `[+] URL (date)` |
| `search_username`  | `[+] Platform: https://…` (sherlock format)   |
| `search_email`     | `[+] platform.com` / `[-] platform.com`       |

---

## Files to create / modify

### 1 — NEW: `openosint/playbooks/recipes/ip.yaml`

```yaml
name: ip
label: "IP Address Investigation"
target_type: ip
steps:
  - id: geolocation
    tool: search_ip
    section: "Geolocation & ASN"
  - id: dorks
    tool: generate_dorks
    section: "Google Dork URLs"
  - id: shodan
    tool: search_shodan
    section: "Shodan Host Intelligence"
  - id: virustotal
    tool: search_virustotal
    section: "VirusTotal Reputation"
```

Cold-start (no keys): `geolocation` + `dorks` always succeed; `shodan` + `virustotal`
render NOT_CONFIGURED info blocks.

### 2 — NEW: `openosint/playbooks/recipes/person.yaml`

```yaml
name: person
label: "Person / Username Investigation"
target_type: username
steps:
  - id: dorks
    tool: generate_dorks
    section: "Google Dork URLs"
  - id: pastes
    tool: search_paste
    section: "Paste Site Mentions"
  - id: username
    tool: search_username
    section: "Username Enumeration"
  - id: email
    tool: search_email
    section: "Email Account Enumeration"
```

Cold-start (no binaries): `dorks` + `pastes` always succeed; `username` (needs
`sherlock`) + `email` (needs `holehe`) render NOT_CONFIGURED info blocks.

### 3 — EDIT: `openosint/playbooks/runner.py`

#### A. Five new formatters (inserted after `_format_footprint`)

**`_format_ip_info(output)`**
Parses `[+] Key: Value` lines into a two-column Markdown table. Falls back to
fenced code block. (Same structural pattern as `_format_whois`; kept separate so
each can diverge without touching the other.)

**`_format_virustotal(output)`**
Parses `[VirusTotal] Key: Value` lines into a two-column table. Lines without
the `[VirusTotal]` prefix are ignored.

**`_format_paste(output)`**
- Header `Found in N paste(s) for '…':` → bold sentence.
- `[+] URL (date)` lines → numbered hyperlink list.
- `No pastes found…` → italicised note.
- Falls back to fenced code.

**`_format_username(output)`**
Parses sherlock `[+] Platform: https://…` lines into a `| Platform | Profile URL |`
table. Falls back to fenced code.

**`_format_holehe(output)`**
Parses holehe `[+] platform` (found) lines into a bullet list of
`[platform](https://platform)`. Ignores `[-]` lines (not found = noise).
Falls back to fenced code.

Note: **no `_format_shodan`** added — Shodan output is `[+] Key: Value` so the
generic fenced-code fallback is readable. Adding a dedicated formatter can be done
in a future PR when the full Shodan output schema is confirmed stable (YAGNI).

#### B. Updated `_format_step_output` dispatch

```python
def _format_step_output(tool_name: str, output: str) -> str:
    if tool_name == "search_whois":
        return _format_whois(output)
    if tool_name == "search_dns":
        return _format_dns(output)
    if tool_name == "generate_dorks":
        return _format_dorks(output)
    if tool_name == "search_domain":
        return _format_subdomains(output)
    if tool_name == "search_footprint":
        return _format_footprint(output)
    if tool_name == "search_ip":
        return _format_ip_info(output)
    if tool_name == "search_virustotal":
        return _format_virustotal(output)
    if tool_name == "search_paste":
        return _format_paste(output)
    if tool_name == "search_username":
        return _format_username(output)
    if tool_name == "search_email":
        return _format_holehe(output)
    return f"```\n{output.strip()}\n```"  # covers search_shodan + any future tools
```

#### C. Extended `_build_summary` entity counts

Appended after the existing `related` count block:

```python
# ISP/org from IP geolocation
ip_orgs = len(tool_entities.get("search_ip", {}).get(EntityType.ORG, set()))
if ip_orgs:
    lines.append(f"- **ISP / Hosting org:** {ip_orgs}")

# ASN — union of search_ip and search_virustotal (deduplicated by value)
ip_asns = len(
    tool_entities.get("search_ip", {}).get(EntityType.ASN, set())
    | tool_entities.get("search_virustotal", {}).get(EntityType.ASN, set())
)
if ip_asns:
    lines.append(f"- **ASNs identified:** {ip_asns}")

# Hostnames from Shodan
shodan_hostnames = len(tool_entities.get("search_shodan", {}).get(EntityType.DOMAIN, set()))
if shodan_hostnames:
    lines.append(f"- **Hostnames from Shodan:** {shodan_hostnames}")

# Platform accounts from sherlock
accounts = len(tool_entities.get("search_username", {}).get(EntityType.URL, set()))
if accounts:
    lines.append(f"- **Platform accounts found:** {accounts}")

# Registered platforms from holehe
registered = len(tool_entities.get("search_email", {}).get(EntityType.URL, set()))
if registered:
    lines.append(f"- **Email registrations found:** {registered}")
```

All lines are guarded by `if <count>`, so existing domain-recipe tests are
unaffected (they never populate these tool buckets).

### 4 — EDIT: `tests/test_playbooks.py`

Two new test classes appended to the existing file.

**Synthetic tool outputs (added to module-level constants):**

```python
_IP_OUTPUT = (
    "[+] IP: 1.2.3.4\n"
    "[+] Hostname: ptr.example.net\n"
    "[+] Org: AS12345 Example ISP\n"
    "[+] City: London\n"
    "[+] Country: GB\n"
)
_SHODAN_OUTPUT = (
    "[+] Org: Example ISP\n"
    "[+] Hostnames: mail.example.com, cdn.example.net\n"
    "[+] Open ports: 80, 443\n"
)
_VT_OUTPUT = (
    "[VirusTotal] IP: 1.2.3.4\n"
    "[VirusTotal] ASN: AS12345 Example ISP\n"
    "[VirusTotal] Malicious votes: 0/91\n"
)
_PASTE_OUTPUT = (
    "Found in 2 paste(s) for 'johndoe99':\n\n"
    "[+] https://pastebin.com/abc123 (2024-01-15)\n"
    "[+] https://pastebin.com/def456 (2024-02-20)\n"
)
_USER_OUTPUT = (
    "[+] Twitter: https://twitter.com/johndoe99\n[+] GitHub: https://github.com/johndoe99\n"
)
_HOLEHE_OUTPUT = "[+] twitter.com\n[+] github.com\n[-] facebook.com\n"
```

**`TestIPPlaybook` (5 tests):**

| Test | What it asserts |
|------|-----------------|
| `test_ip_cold_start_all_sections_present` | All 4 `## ` headings in output; SHODAN_API_KEY + VIRUSTOTAL_API_KEY removed via monkeypatch |
| `test_ip_gated_steps_render_info_block` | `ℹ️ Skipped` present; `⚠ Step error` absent |
| `test_ip_summary_counts_correct` | `ISP / Hosting org:** 1` and `ASNs identified:** 1` with all tools mocked |
| `test_ip_report_filename_convention` | Filename matches `r"\d{4}-\d{2}-\d{2}_.*_ip_report\.md"` |
| `test_ip_cold_start_no_crash` | `report_path.exists()` is True |

**`TestPersonPlaybook` (5 tests):**

| Test | What it asserts |
|------|-----------------|
| `test_person_cold_start_all_sections_present` | All 4 `## ` headings present; sherlock + holehe removed from PATH |
| `test_person_gated_steps_render_info_block` | `ℹ️ Skipped` present; `⚠ Step error` absent |
| `test_person_summary_counts_correct` | `Platform accounts found:** 2` and `Email registrations found:** 2` with all tools mocked |
| `test_person_report_filename_convention` | Filename matches `r"\d{4}-\d{2}-\d{2}_.*_person_report\.md"` |
| `test_person_cold_start_no_crash` | `report_path.exists()` is True |

Cold-start binary removal strategy: `monkeypatch.setattr(shutil, "which",
lambda b: None if b in {"sherlock", "holehe"} else shutil.which(b))`

### 5 — EDIT: `pyproject.toml`

```
version = "2.24.1"  →  version = "2.25.0"
```

---

## What does NOT change

| Component      | Reason                                                      |
|----------------|-------------------------------------------------------------|
| `loader.py`    | Already validates any tool name against TOOL_MAP            |
| `cli.py`       | Generic `playbook <name> <target>` dispatch needs no change |
| `extractors.py`| All needed extractors already registered                    |
| `mcp_server.py`| Playbooks are not exposed via MCP                           |
| `agent.py`     | No agentic loop involved                                    |

---

## Implementation order

1. Write `recipes/ip.yaml` and `recipes/person.yaml`
2. Add five new formatters to `runner.py`
3. Update `_format_step_output` dispatch in `runner.py`
4. Extend `_build_summary` counts in `runner.py`
5. Append tests to `tests/test_playbooks.py`
6. Bump version in `pyproject.toml`
7. `pytest tests/test_playbooks.py -v` — must be all green
8. Cold-start demo runs (evidence)
9. Commit `feat(playbooks): add ip and person investigation recipes`

---

## Risk / edge cases

- **ASN union edge case:** `search_ip` emits an ASN entity only when `[+] Org:` contains
  `AS<digits>`. If the ISP omits the ASN prefix, `ip_asns` will be 0 — correct behaviour.
- **Shodan fenced-code fallback:** raw Shodan output is readable text; the fenced code
  block is acceptable and avoids formatter drift risk until the format is confirmed stable.
- **`search_paste` not in EXTRACTOR_REGISTRY:** step renders its section normally; just
  contributes 0 summary entity counts, which is correct (no pivot-worthy entity type).
- **`generate_dorks` not in EXTRACTOR_REGISTRY:** same safe behaviour as in domain recipe.
- **`_build_summary` additions are additive-only:** all new lines are guarded by `if count`,
  so existing domain-recipe tests remain green without any changes.
