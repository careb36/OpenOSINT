# Playbooks Feature — Implementation Plan

## Overview

A new `openosint/playbooks/` package that executes deterministic, fixed-order
investigation pipelines ("playbooks") without any LLM or API key.  The only
public surface is:

```
openosint playbook <recipe> <target>
```

No AI agent is involved; no `ANTHROPIC_API_KEY` required.

---

## 1. Recipe-as-Data YAML Format

A recipe lives in `openosint/playbooks/recipes/<name>.yaml`.

```yaml
name: domain
label: "Domain Investigation"
target_type: domain
steps:
  - id: whois
    tool: search_whois
    section: "WHOIS Registration"
  - id: dns
    tool: search_dns
    section: "DNS Records"
  - id: dorks
    tool: generate_dorks
    section: "Google Dork URLs"
  - id: subdomains
    tool: search_domain
    section: "Subdomain Enumeration"
  - id: footprint
    tool: search_footprint
    section: "Search Engine Footprint"
```

**Field definitions:**

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | str | yes | Identifier (must match filename stem) |
| `label` | str | yes | Human-readable title used in the report |
| `target_type` | str | yes | Informational tag (`domain`, `email`, `ip`, etc.) |
| `steps[].id` | str | yes | Unique step identifier within this recipe |
| `steps[].tool` | str | yes | Key in `TOOL_MAP` (matches tool module stem) |
| `steps[].section` | str | yes | Markdown section heading for this step's output |

`generate_dorks` (`run_dork_osint`) requires no network and no key — it is a
zero-config step that always produces output, ensuring a useful cold-start run
on a machine with no API keys configured.

**MVP scope:** every step receives the raw target string.  A future
`from_artifact` field (e.g. `whois.emails`) can enable pivot steps without
breaking existing recipes.

---

## 2. Package Layout

```
openosint/playbooks/
    __init__.py          # empty
    loader.py            # load + validate YAML → Recipe dataclass
    runner.py            # execute steps, build Markdown, call pdf_report
    recipes/
        domain.yaml      # "Domain Investigation" — the only Phase-3 recipe
```

---

## 3. Module Specifications

### 3a. `loader.py`

**Responsibilities:** read a YAML file by name or path, validate required
fields, return an immutable `Recipe` dataclass.

```python
@dataclass(frozen=True)
class PlaybookStep:
    id: str
    tool: str
    section: str


@dataclass(frozen=True)
class Recipe:
    name: str
    label: str
    target_type: str
    steps: tuple[PlaybookStep, ...]
```

Public API:
```python
def load_recipe(name_or_path: str) -> Recipe:
    """
    Load a recipe by name (looks in openosint/playbooks/recipes/<name>.yaml)
    or by explicit file path.  Raises ValueError with a clear message on
    validation failure.
    """
```

Validation rules (raise `ValueError` on violation):
- `name`, `label`, `target_type` must be non-empty strings.
- `steps` must be a non-empty list.
- Each step must have `id`, `tool`, `section` as non-empty strings.
- `id` values must be unique within the recipe.
- `tool` must be a key in `TOOL_MAP` (imported from `runner`).

`PyYAML` (`import yaml`) is added to `pyproject.toml` core dependencies
(`pyyaml>=6.0`).  The YAML recipe files are included via `pyproject.toml`
`[tool.setuptools.package-data]` under `openosint.playbooks`.

### 3b. `runner.py`

**Responsibilities:** execute a `Recipe` against a target, assemble the
Markdown report, compute a deterministic executive summary, write the `.md`
file to `reports/`, call `pdf_report.generate_pdf_report()`.

---

#### Step result states

Each step produces one of three states — never a pass/fail binary:

```python
class StepState(Enum):
    NOT_CONFIGURED = "not_configured"  # required env var or binary absent
    EMPTY = "empty"  # tool ran, returned no output
    ERROR = "error"  # unexpected exception
    # (implicit SUCCESS: tool ran and returned non-empty output)
```

A NOT_CONFIGURED result is not a failure; it renders an informational block,
not a warning.

---

#### Tool requirements map

Checked **before** calling the tool — env vars via `os.environ.get`, binaries
via `shutil.which`.  If any requirement is missing the step is marked
NOT_CONFIGURED and the tool is **not called**.

```python
# Each entry: (env_vars: list[str], binaries: list[str], note: str | None)
TOOL_REQUIREMENTS: dict[str, tuple[list[str], list[str], str | None]] = {
    "search_whois": ([], [], None),
    "search_dns": ([], [], None),
    "generate_dorks": ([], [], None),
    "search_domain": ([], ["sublist3r"], None),
    "search_footprint": (
        ["BRIGHTDATA_API_KEY", "BRIGHTDATA_SERP_ZONE"],
        [],
        "Sign up at brightdata.com to obtain your API key and SERP zone.",
    ),
    "search_email": ([], ["holehe"], None),
    "search_breach": (["HIBP_API_KEY"], [], None),
    "search_ip": ([], [], None),  # IPINFO_TOKEN optional
    "search_shodan": (["SHODAN_API_KEY"], [], None),
    "search_virustotal": (["VIRUSTOTAL_API_KEY"], [], None),
    "search_paste": ([], [], None),
    "search_username": ([], ["sherlock"], None),
    "search_phone": ([], ["phoneinfoga"], None),
}
```

---

#### Tool registry

```python
TOOL_MAP: dict[str, Callable[..., Awaitable[str]]] = {
    "search_whois": run_whois_osint,
    "search_dns": run_dns_osint,
    "generate_dorks": run_dork_osint,
    "search_domain": run_domain_osint,
    "search_footprint": run_footprint_osint,
    "search_email": run_email_osint,
    "search_breach": run_breach_osint,
    "search_ip": run_ip_osint,
    "search_shodan": run_shodan_osint,
    "search_virustotal": run_virustotal_osint,
    "search_paste": run_paste_osint,
    "search_username": run_username_osint,
    "search_phone": run_phone_osint,
}
```

---

#### Execution model

Steps run **sequentially** in declaration order (MVP).  Each step goes through
this decision tree:

```
1. check TOOL_REQUIREMENTS[step.tool]
   → any missing?  → StepState.NOT_CONFIGURED  (skip call)
2. try: output = await TOOL_MAP[step.tool](target)
   except Exception → StepState.ERROR
3. output.strip() == ""  → StepState.EMPTY
4. else                  → SUCCESS  (output rendered verbatim)
```

---

#### Markdown report structure

```markdown
# {recipe.label} — {target}

**Target:** {target}
**Target type:** {recipe.target_type}
**Date:** {YYYY-MM-DD HH:MM UTC}
**Recipe:** {recipe.name}

---

## Executive Summary

{deterministic summary — see below}

---

## {step.section}

```  ← fenced block for SUCCESS steps

{tool output}

```  ← close fence

> ℹ️ Skipped — set BRIGHTDATA_API_KEY and BRIGHTDATA_SERP_ZONE to enable this section.
> Sign up at brightdata.com to obtain your API key and SERP zone.
   ← for NOT_CONFIGURED steps

> No results found.
   ← for EMPTY steps

> ⚠ Step error: {exception message}
   ← for ERROR steps

---
```

---

#### Executive summary (via `EXTRACTOR_REGISTRY`, no ad-hoc regex)

The summary is built entirely from `openosint.extractors.EXTRACTOR_REGISTRY`
so there is zero duplicated parsing logic.

```python
from openosint.extractors import EXTRACTOR_REGISTRY
from openosint.correlation import EntityType, make_entity

# seed entity type derived from recipe.target_type
seed = make_entity(EntityType.DOMAIN, target, 1.0, "playbook")

# For each SUCCESS step that has a registered extractor:
#   entities, _ = EXTRACTOR_REGISTRY[step.tool](output, seed)
# Aggregate entity counts by EntityType across all steps.
```

Summary rendered as a bullet list per entity type, e.g.:
- **Steps completed:** 3/5 (2 skipped — not configured)
- **Subdomains found:** 12  (from `search_domain` → DOMAIN entities)
- **IP addresses found:** 4  (from `search_dns` → IP entities)
- **Registrant emails:** 1  (from `search_whois` → EMAIL entities)
- **SERP URLs found:** 8   (from `search_footprint` → URL entities)

Steps with no extractor entry (e.g. `generate_dorks`) contribute nothing to
the summary counts and that is correct — dork output is informational, not a
structured finding.

---

#### Public API

```python
async def run_playbook(
    recipe: Recipe,
    target: str,
    is_pdf_disabled: bool = False,
    reports_dir: Path | None = None,
) -> Path:
    """
    Execute recipe against target.

    Returns the Path to the written Markdown report.
    Never raises — all step outcomes are captured in the report.
    """
```

---

#### File naming (matches `multi_target.py` convention, adds recipe name)

```
reports/{YYYY-MM-DD}_{safe_target}_{recipe.name}_report.md
reports/{YYYY-MM-DD}_{safe_target}_{recipe.name}_report.pdf
```

### 3c. `recipes/domain.yaml`

```yaml
name: domain
label: "Domain Investigation"
target_type: domain
steps:
  - id: whois
    tool: search_whois
    section: "WHOIS Registration"
  - id: dns
    tool: search_dns
    section: "DNS Records"
  - id: dorks
    tool: generate_dorks
    section: "Google Dork URLs"
  - id: subdomains
    tool: search_domain
    section: "Subdomain Enumeration"
  - id: footprint
    tool: search_footprint
    section: "Search Engine Footprint"
```

`whois`, `dns`, and `dorks` require nothing beyond a working Python install —
a cold-start run with no API keys produces a three-section report immediately.

---

## 4. CLI Subcommand

**Location:** `openosint/cli.py` — add inside `_build_parser()` after the
`history` subcommand, and add an `elif args.command == "playbook":` branch in
the main dispatch.

```python
playbook_cmd = subparsers.add_parser(
    "playbook",
    help="Run a deterministic investigation playbook (no AI required).",
)
playbook_cmd.add_argument(
    "recipe",
    type=str,
    metavar="RECIPE",
    help="Recipe name (e.g. 'domain') or path to a YAML file.",
)
playbook_cmd.add_argument(
    "target",
    type=str,
    metavar="TARGET",
    help="Investigation target (e.g. example.com).",
)
```

The global `--no-pdf` flag (`is_pdf_disabled`) is already parsed at the parent
level and flows through unchanged.

**Dispatch handler** (placed with the other `_handle_*` functions):

```python
async def _handle_playbook(
    recipe_name: str,
    target: str,
    is_pdf_disabled: bool,
) -> None:
    from openosint.playbooks.loader import load_recipe
    from openosint.playbooks.runner import run_playbook

    recipe = load_recipe(recipe_name)
    report_path = await run_playbook(recipe, target, is_pdf_disabled=is_pdf_disabled)
    print(f"\n[+] Playbook complete. Report: {report_path}", file=sys.stderr)
```

---

## 5. Tests — `tests/test_playbooks.py`

All tests use `unittest.mock.AsyncMock`/`patch`; no real tool binaries or API
keys are required.  Test style mirrors `tests/test_v240.py`: class-based,
async methods, imports inside test functions, `monkeypatch` for env vars.

### Test classes and cases

```
class TestPlaybookLoader
    test_loads_built_in_domain_recipe
        — load "domain"; assert name=="domain", 5 steps, ids include dorks
    test_raises_on_unknown_recipe
        — load "nonexistent"; assert ValueError with helpful message
    test_raises_on_missing_required_field
        — pass YAML string missing "label"; assert ValueError
    test_raises_on_duplicate_step_ids
        — pass YAML with two steps sharing same id; assert ValueError
    test_raises_on_unknown_tool
        — pass YAML with tool="search_unicorn"; assert ValueError

class TestPlaybookRunner
    test_produces_markdown_with_all_sections
        — mock all 5 tools via AsyncMock returning canned strings
        — run_playbook on tmp_path
        — assert all 5 section headings present in MD

    test_report_written_to_reports_dir
        — assert the returned Path exists and ends with "_report.md"

    test_executive_summary_present
        — assert "## Executive Summary" in report MD

    test_executive_summary_counts_correct
        — provide synthetic search_whois output with 2 "[+] Emails:" lines and
          2 "[+] Name Servers:" lines (matching _extract_whois prefixes)
        — provide synthetic search_dns output with 3 "[DNS] A:" IP entries
        — provide synthetic search_domain output with 4 "[+] sub.example.com" lines
        — assert summary contains "Subdomains found: 4"
        — assert summary contains "IP addresses found: 3"
        — assert summary contains "Registrant emails: 2"

    test_not_configured_step_renders_info_block
        — set BRIGHTDATA_API_KEY absent (monkeypatch.delenv or never set)
        — run_playbook; assert "ℹ️ Skipped" in MD for the footprint section
        — assert "⚠ Step error" NOT in MD for that section
        — assert report still contains the other 4 section headings

    test_not_configured_footprint_includes_brightdata_note
        — same setup as above
        — assert "brightdata" (case-insensitive) appears in the footprint section

    test_error_step_renders_error_block
        — mock search_domain to raise RuntimeError("binary missing")
        — assert "⚠ Step error" in MD
        — assert run_playbook does not raise

    test_all_steps_error_or_not_configured_does_not_crash
        — all tools either raise or have missing requirements
        — assert run_playbook returns without raising

    test_empty_step_renders_no_results
        — mock search_domain to return ""
        — assert "No results found" in the subdomains section

    test_pdf_skipped_when_disabled
        — patch openosint.playbooks.runner.generate_pdf_report with AsyncMock
        — call run_playbook(is_pdf_disabled=True)
        — assert mock not called

    test_pdf_called_when_enabled
        — patch generate_pdf_report with AsyncMock
        — call run_playbook(is_pdf_disabled=False)
        — assert mock called once with the .md Path

    test_report_filename_follows_convention
        — assert filename matches r"\d{4}-\d{2}-\d{2}_.*_domain_report\.md"

class TestPlaybookCLI
    test_playbook_subcommand_registered
        — parse ["playbook", "domain", "example.com"] against _build_parser()
        — assert args.command == "playbook"
        — assert args.recipe == "domain"
        — assert args.target == "example.com"
```

---

## 6. Scope Constraints

- **No LLM, no agent:** `openosint.agent` is never imported inside `playbooks/`.
- **No new heavy dependencies beyond PyYAML:** `pyyaml>=6.0` added to core
  deps in `pyproject.toml`; no `pydantic`, no `jsonschema`.
- **No mutation:** `Recipe` and `PlaybookStep` are frozen dataclasses.
- **Reuse, not reinvent:**
  - `pdf_report.generate_pdf_report` called as-is.
  - `reports/` dir, date prefix, and safe-filename pattern mirror `multi_target.py`.
  - `EXTRACTOR_REGISTRY` from `openosint.extractors` drives all summary counts.

---

## 7. Version Bump & Dependency Addition

- `pyproject.toml` `version`: `2.23.0` → `2.24.0` (minor bump).
- `pyproject.toml` `dependencies`: add `"pyyaml>=6.0"`.
- `pyproject.toml` `[tool.setuptools.package-data]`: add
  `"openosint.playbooks" = ["recipes/*.yaml"]` so YAML files are included in
  the installed package.
