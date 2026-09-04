# openosint/investigate.py
"""
Public Python API for OpenOSINT investigations.

This module exposes a single, stable, high-level function — ``investigate()``
— that the osint-orchestrator (and any other Python consumer) can call
directly without going through the REPL, CLI, or MCP server.

WHY this module exists
----------------------
``pivot.investigate_graph()`` is the correct underlying engine, but it is not
a stable public API: its signature may change between releases, its defaults
are tuned for interactive use, and it lives inside an implementation module.
This wrapper:
  1. Provides a single named entry point that downstream code can pin against.
  2. Documents the ``kind`` parameter (auto-detect vs explicit EntityType).
  3. Normalises ``budget`` into the four budget knobs that investigate_graph
     understands, preventing callers from having to know the internal names.
  4. Adds ``run_id`` support: a caller-supplied identifier that can be
     propagated to provenance records and log messages for correlation.
  5. Validates inputs before any async work begins, giving callers early
     errors rather than silent empty graphs.

USAGE
-----
Minimal (auto-detects entity type, uses default budget):

    import asyncio
    from openosint.investigate import investigate

    graph = asyncio.run(investigate("example.com"))
    print(graph.summary())
    print(graph.to_json())

With explicit kind and custom budget:

    from openosint.investigate import investigate, InvestigationBudget, EntityKind

    budget = InvestigationBudget(max_depth=3, max_entities=60, max_tool_calls=80)
    graph = asyncio.run(investigate(
        "johndoe99",
        kind=EntityKind.USERNAME,
        budget=budget,
        run_id="daily-2026-09-04",
    ))

Export to STIX 2.1 (requires openosint[stix]):

    from openosint.graph.export.stix import to_stix_json
    print(to_stix_json(graph))

RETURN VALUE
------------
Always returns an ``openosint.correlation.EntityGraph``.  Never raises on
tool failures (tools that fail contribute nothing to the graph, see
pivot.py's _run_tool_safe).  Raises ``ValueError`` only on bad arguments
(unknown kind string, budget values out of range).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class EntityKind(str, Enum):
    """The semantic kind of the investigation target.

    ``AUTO`` (the default) triggers the same regex-based type detection that
    the REPL and agent use (``openosint.regexes.detect_entity_kind``).
    All other values bypass detection and route directly to the specified
    tool set.
    """

    AUTO = "auto"
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    IP = "ip"
    PHONE = "phone"
    HASH = "hash"
    URL = "url"
    PERSON = "person"


_KIND_TO_ENTITY_TYPE_STR: dict[EntityKind, str] = {
    EntityKind.EMAIL: "email",
    EntityKind.USERNAME: "username",
    EntityKind.DOMAIN: "domain",
    EntityKind.IP: "ip",
    EntityKind.PHONE: "phone",
    EntityKind.HASH: "hash",
    EntityKind.URL: "url",
    EntityKind.PERSON: "person",
}

# Budget presets — callers can use these directly or build their own
_BUDGET_DEFAULTS = dict(max_depth=2, max_entities=40, max_tool_calls=60, timeout_seconds=30)
_BUDGET_CONSERVATIVE = dict(max_depth=1, max_entities=15, max_tool_calls=20, timeout_seconds=30)
_BUDGET_DEEP = dict(max_depth=3, max_entities=80, max_tool_calls=120, timeout_seconds=45)


@dataclass(frozen=True)
class InvestigationBudget:
    """Budget caps for an investigation run.

    All values are non-negotiable upper bounds to prevent runaway cost or
    latency.  Use the class-level factory methods for common presets.

    Parameters
    ----------
    max_depth:
        Maximum BFS hops from the seed entity.  Each hop may enqueue newly
        discovered entities for further investigation.
    max_entities:
        Hard cap on distinct entities investigated (not total in the graph —
        many more entities may appear as neighbours without being pivoted from).
    max_tool_calls:
        Hard cap on total tool invocations across the entire run.
    timeout_seconds:
        Per-tool-call timeout.  Tools that exceed this are silently skipped.
    """

    max_depth: int = 2
    max_entities: int = 40
    max_tool_calls: int = 60
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError(f"max_depth must be >= 0, got {self.max_depth!r}")
        if self.max_entities < 1:
            raise ValueError(f"max_entities must be >= 1, got {self.max_entities!r}")
        if self.max_tool_calls < 1:
            raise ValueError(f"max_tool_calls must be >= 1, got {self.max_tool_calls!r}")
        if self.timeout_seconds < 1:
            raise ValueError(f"timeout_seconds must be >= 1, got {self.timeout_seconds!r}")

    @classmethod
    def default(cls) -> "InvestigationBudget":
        """Standard budget for interactive investigations."""
        return cls(**_BUDGET_DEFAULTS)

    @classmethod
    def conservative(cls) -> "InvestigationBudget":
        """Conservative budget for agent-loop use (low cost/latency)."""
        return cls(**_BUDGET_CONSERVATIVE)

    @classmethod
    def deep(cls) -> "InvestigationBudget":
        """Deep budget for batch/overnight investigations."""
        return cls(**_BUDGET_DEEP)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def investigate(
    target: str,
    *,
    kind: EntityKind | Literal["auto", "email", "username", "domain", "ip",
                                "phone", "hash", "url", "person"] = EntityKind.AUTO,
    budget: InvestigationBudget | None = None,
    run_id: str = "",
) -> "openosint.correlation.EntityGraph":  # noqa: F821 — forward ref, not imported at module level
    """Run an OSINT investigation on *target* and return the entity graph.

    Parameters
    ----------
    target:
        The value to investigate: an email address, domain, IP, username,
        phone number, URL, hash, or plain text (person/org name).
    kind:
        The semantic kind of *target*.  ``EntityKind.AUTO`` (the default)
        auto-detects the kind via regex.  Pass an explicit value to bypass
        detection when you already know the type.
    budget:
        Budget caps.  Defaults to ``InvestigationBudget.default()``.
    run_id:
        Optional caller-supplied correlation identifier (e.g. a daily-run
        timestamp or task UUID).  Logged with investigation events; not used
        to affect tool routing.

    Returns
    -------
    openosint.correlation.EntityGraph
        The populated graph.  Always returns a graph (never raises) — tools
        that fail contribute nothing; the graph may be empty if all tools
        failed or no keys were configured.

    Raises
    ------
    ValueError
        If *target* is empty, *kind* is an unrecognised string, or *budget*
        values are out of range.
    """
    if not target or not target.strip():
        raise ValueError("target must be a non-empty string")

    # Normalise kind to EntityKind enum
    if isinstance(kind, str):
        try:
            kind = EntityKind(kind.lower())
        except ValueError:
            valid = [e.value for e in EntityKind]
            raise ValueError(
                f"Unknown kind {kind!r}. Valid values: {valid}"
            )

    if budget is None:
        budget = InvestigationBudget.default()

    log_prefix = f"[investigate run_id={run_id!r}]" if run_id else "[investigate]"
    logger.info("%s target=%r kind=%s", log_prefix, target, kind.value)

    from openosint.pivot import investigate_graph

    if kind == EntityKind.AUTO:
        # investigate_graph auto-detects the seed entity type
        graph = await investigate_graph(
            target,
            max_depth=budget.max_depth,
            max_entities=budget.max_entities,
            max_tool_calls=budget.max_tool_calls,
            timeout_seconds=budget.timeout_seconds,
        )
    else:
        # Build a typed seed entity and let the BFS take it from there
        from openosint.correlation import EntityType, make_entity
        from openosint.pivot import investigate_graph

        entity_type_str = _KIND_TO_ENTITY_TYPE_STR[kind]
        entity_type = EntityType(entity_type_str)

        # investigate_graph always auto-detects; inject the typed seed by
        # running the BFS starting from a pre-typed entity (same code path,
        # just forces the entity type for the seed).
        graph = await _investigate_typed(
            target,
            entity_type=entity_type,
            budget=budget,
        )

    logger.info("%s done — %s", log_prefix, graph.summary())
    return graph


# ---------------------------------------------------------------------------
# Typed-seed BFS (internal)
# ---------------------------------------------------------------------------


async def _investigate_typed(
    target: str,
    entity_type: "openosint.correlation.EntityType",  # noqa: F821
    budget: InvestigationBudget,
) -> "openosint.correlation.EntityGraph":  # noqa: F821
    """Run the BFS starting from a pre-typed seed entity.

    Mirrors investigate_graph() but bypasses its auto-detection so the
    caller's explicit ``kind`` is honoured even when the regex would guess
    differently (e.g. a username that looks like an email prefix).
    """
    import asyncio

    from openosint.correlation import EntityGraph, EntityType, Relationship, make_entity
    from openosint.extractors import EXTRACTOR_REGISTRY
    from openosint.pivot import (
        _PIVOT_MIN_CONFIDENCE,
        _get_routable_tools,
        _run_tool_safe,
    )
    from collections import deque

    graph = EntityGraph()
    seed_entity = make_entity(entity_type, target.strip(), 1.0)
    graph.add_entity(seed_entity)

    queue: deque = deque([(seed_entity, 0)])
    investigated: set = set()
    queued: set = {(seed_entity.type, seed_entity.normalized)}
    call_count = 0
    entities_investigated = 0

    while queue:
        if call_count >= budget.max_tool_calls:
            break

        entity, depth = queue.popleft()
        key = (entity.type, entity.normalized)

        if key in investigated:
            continue
        investigated.add(key)

        if depth >= budget.max_depth:
            continue

        if entities_investigated >= budget.max_entities:
            break
        entities_investigated += 1

        tools = _get_routable_tools(entity)
        if not tools:
            continue

        remaining = budget.max_tool_calls - call_count
        batch = tools[:remaining]
        call_count += len(batch)

        results = await asyncio.gather(
            *[_run_tool_safe(t, entity, budget.timeout_seconds) for t in batch]
        )

        for tool_name, raw in zip(batch, results):
            extractor = EXTRACTOR_REGISTRY.get(tool_name)
            if extractor is None or not raw:
                continue

            try:
                new_entities, new_rels = extractor(raw, entity)
            except Exception:
                continue

            for new_e in new_entities:
                canonical = graph.add_entity(new_e)
                ekey = (canonical.type, canonical.normalized)
                should_enqueue = (
                    canonical.confidence >= _PIVOT_MIN_CONFIDENCE
                    and ekey not in investigated
                    and ekey not in queued
                    and len(graph._entities) <= budget.max_entities
                    and call_count < budget.max_tool_calls
                )
                if should_enqueue:
                    queued.add(ekey)
                    queue.append((canonical, depth + 1))

            for rel in new_rels:
                canonical_src = graph.add_entity(rel.source)
                canonical_tgt = graph.add_entity(rel.target)
                graph.add_relationship(
                    Relationship(
                        source=canonical_src,
                        target=canonical_tgt,
                        kind=rel.kind,
                        source_tool=rel.source_tool,
                        confidence=rel.confidence,
                    )
                )

    return graph
