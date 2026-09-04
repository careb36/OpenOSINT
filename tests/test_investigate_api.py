# tests/test_investigate_api.py
"""
Tests for openosint.investigate — public Python API.

All tool calls are mocked; no network, no API keys, no binaries required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from openosint.investigate import (
    EntityKind,
    InvestigationBudget,
    investigate,
)

# ---------------------------------------------------------------------------
# InvestigationBudget
# ---------------------------------------------------------------------------


class TestInvestigationBudget:
    def test_default_preset(self):
        b = InvestigationBudget.default()
        assert b.max_depth == 2
        assert b.max_entities == 40
        assert b.max_tool_calls == 60

    def test_conservative_preset(self):
        b = InvestigationBudget.conservative()
        assert b.max_depth == 1
        assert b.max_entities <= 20

    def test_deep_preset(self):
        b = InvestigationBudget.deep()
        assert b.max_depth >= 3

    def test_custom_values(self):
        b = InvestigationBudget(
            max_depth=5, max_entities=100, max_tool_calls=200, timeout_seconds=60
        )
        assert b.max_depth == 5

    def test_negative_depth_raises(self):
        with pytest.raises(ValueError, match="max_depth"):
            InvestigationBudget(max_depth=-1)

    def test_zero_entities_raises(self):
        with pytest.raises(ValueError, match="max_entities"):
            InvestigationBudget(max_entities=0)

    def test_zero_tool_calls_raises(self):
        with pytest.raises(ValueError, match="max_tool_calls"):
            InvestigationBudget(max_tool_calls=0)

    def test_zero_timeout_raises(self):
        with pytest.raises(ValueError, match="timeout_seconds"):
            InvestigationBudget(timeout_seconds=0)

    def test_frozen(self):
        b = InvestigationBudget()
        with pytest.raises(Exception):
            b.max_depth = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# EntityKind
# ---------------------------------------------------------------------------


class TestEntityKind:
    def test_enum_values(self):
        assert EntityKind.AUTO.value == "auto"
        assert EntityKind.EMAIL.value == "email"
        assert EntityKind.DOMAIN.value == "domain"

    def test_string_is_valid_kind(self):
        assert EntityKind("email") == EntityKind.EMAIL

    def test_unknown_string_raises(self):
        with pytest.raises(ValueError):
            EntityKind("notakind")


# ---------------------------------------------------------------------------
# investigate() — argument validation
# ---------------------------------------------------------------------------


class TestInvestigateValidation:
    @pytest.mark.asyncio
    async def test_empty_target_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            await investigate("")

    @pytest.mark.asyncio
    async def test_whitespace_target_raises(self):
        with pytest.raises(ValueError, match="non-empty"):
            await investigate("   ")

    @pytest.mark.asyncio
    async def test_unknown_kind_string_raises(self):
        with pytest.raises(ValueError, match="Unknown kind"):
            await investigate("example.com", kind="unicorn")  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_budget_validation_propagated(self):
        with pytest.raises(ValueError, match="max_depth"):
            await investigate("example.com", budget=InvestigationBudget(max_depth=-1))


# ---------------------------------------------------------------------------
# investigate() — return type and graph shape
# ---------------------------------------------------------------------------


class TestInvestigateReturnType:
    @pytest.mark.asyncio
    async def test_returns_entity_graph(self):
        from openosint.correlation import EntityGraph

        with patch("openosint.pivot.investigate_graph", new_callable=AsyncMock) as mock_ig:
            mock_ig.return_value = EntityGraph()
            result = await investigate("example.com")
        assert isinstance(result, EntityGraph)

    @pytest.mark.asyncio
    async def test_auto_kind_calls_investigate_graph(self):
        from openosint.correlation import EntityGraph

        with patch("openosint.pivot.investigate_graph", new_callable=AsyncMock) as mock_ig:
            mock_ig.return_value = EntityGraph()
            await investigate("example.com", kind=EntityKind.AUTO)
            assert mock_ig.called

    @pytest.mark.asyncio
    async def test_auto_kind_passes_budget_knobs(self):
        from openosint.correlation import EntityGraph

        budget = InvestigationBudget(
            max_depth=3, max_entities=50, max_tool_calls=70, timeout_seconds=45
        )
        with patch("openosint.pivot.investigate_graph", new_callable=AsyncMock) as mock_ig:
            mock_ig.return_value = EntityGraph()
            await investigate("example.com", budget=budget)
            call_kwargs = mock_ig.call_args.kwargs
            assert call_kwargs["max_depth"] == 3
            assert call_kwargs["max_entities"] == 50
            assert call_kwargs["max_tool_calls"] == 70
            assert call_kwargs["timeout_seconds"] == 45

    @pytest.mark.asyncio
    async def test_explicit_domain_kind_returns_entity_graph(self):
        """Explicit kind uses _investigate_typed, which also returns EntityGraph."""
        from openosint.correlation import EntityGraph

        # Mock _run_tool_safe to return empty (no tools configured)
        with patch("openosint.pivot._run_tool_safe", new_callable=AsyncMock) as mock_tool:
            mock_tool.return_value = ""
            result = await investigate(
                "example.com",
                kind=EntityKind.DOMAIN,
                budget=InvestigationBudget.conservative(),
            )
        assert isinstance(result, EntityGraph)

    @pytest.mark.asyncio
    async def test_explicit_email_kind_seeds_email_entity(self):
        """With kind=EMAIL, the seed entity in the graph should be an EMAIL type."""
        from openosint.correlation import EntityType

        with patch("openosint.pivot._run_tool_safe", new_callable=AsyncMock) as mock_tool:
            mock_tool.return_value = ""
            graph = await investigate(
                "user@example.com",
                kind=EntityKind.EMAIL,
                budget=InvestigationBudget.conservative(),
            )

        entity_types = {e.type for e in graph._entities.values()}
        assert EntityType.EMAIL in entity_types

    @pytest.mark.asyncio
    async def test_explicit_ip_kind_seeds_ip_entity(self):
        from openosint.correlation import EntityType

        with patch("openosint.pivot._run_tool_safe", new_callable=AsyncMock) as mock_tool:
            mock_tool.return_value = ""
            graph = await investigate(
                "1.2.3.4",
                kind=EntityKind.IP,
                budget=InvestigationBudget.conservative(),
            )

        entity_types = {e.type for e in graph._entities.values()}
        assert EntityType.IP in entity_types

    @pytest.mark.asyncio
    async def test_username_kind_bypasses_auto_detect(self):
        """A value like 'user99' could be auto-detected as username; with explicit
        kind=USERNAME it must seed a USERNAME entity regardless of regex."""
        from openosint.correlation import EntityType

        with patch("openosint.pivot._run_tool_safe", new_callable=AsyncMock) as mock_tool:
            mock_tool.return_value = ""
            graph = await investigate(
                "user99",
                kind=EntityKind.USERNAME,
                budget=InvestigationBudget.conservative(),
            )

        entity_types = {e.type for e in graph._entities.values()}
        assert EntityType.USERNAME in entity_types

    @pytest.mark.asyncio
    async def test_kind_as_string_accepted(self):
        """Kind may be passed as a plain string."""
        from openosint.correlation import EntityGraph

        with patch("openosint.pivot.investigate_graph", new_callable=AsyncMock) as mock_ig:
            mock_ig.return_value = EntityGraph()
            result = await investigate("example.com", kind="auto")  # type: ignore[arg-type]
        assert isinstance(result, EntityGraph)

    @pytest.mark.asyncio
    async def test_default_budget_used_when_none(self):
        from openosint.correlation import EntityGraph

        with patch("openosint.pivot.investigate_graph", new_callable=AsyncMock) as mock_ig:
            mock_ig.return_value = EntityGraph()
            await investigate("example.com")
            call_kwargs = mock_ig.call_args.kwargs
            default = InvestigationBudget.default()
            assert call_kwargs["max_depth"] == default.max_depth
            assert call_kwargs["max_tool_calls"] == default.max_tool_calls

    @pytest.mark.asyncio
    async def test_run_id_does_not_affect_graph(self):
        """run_id is a logging/correlation aid; the returned graph is unaffected."""
        from openosint.correlation import EntityGraph

        with patch("openosint.pivot.investigate_graph", new_callable=AsyncMock) as mock_ig:
            mock_ig.return_value = EntityGraph()
            result = await investigate("example.com", run_id="daily-2026-09-04")
        assert isinstance(result, EntityGraph)

    @pytest.mark.asyncio
    async def test_never_raises_on_all_tools_returning_empty(self):
        """If all tools return empty (no results/keys), investigate() returns a valid graph."""
        with patch("openosint.pivot._run_tool_safe", new_callable=AsyncMock) as mock_tool:
            mock_tool.return_value = ""
            graph = await investigate(
                "1.2.3.4",
                kind=EntityKind.IP,
                budget=InvestigationBudget.conservative(),
            )
        from openosint.correlation import EntityGraph

        assert isinstance(graph, EntityGraph)

    @pytest.mark.asyncio
    async def test_seed_entity_always_in_graph(self):
        """The seed is added before any tool calls — it must be in the graph even
        when all tools return empty results."""
        with patch("openosint.pivot._run_tool_safe", new_callable=AsyncMock) as mock_tool:
            mock_tool.return_value = ""
            graph = await investigate(
                "johndoe",
                kind=EntityKind.USERNAME,
                budget=InvestigationBudget.conservative(),
            )
        assert len(graph._entities) >= 1


# ---------------------------------------------------------------------------
# Integration: investigate → to_stix_bundle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_investigate_result_exportable_to_stix():
    """Graph returned by investigate() can be passed straight to to_stix_bundle."""
    pytest.importorskip("stix2", reason="requires the 'stix' extra")

    from openosint.graph.export.stix import to_stix_bundle

    with patch("openosint.pivot._run_tool_safe", new_callable=AsyncMock) as mock_tool:
        mock_tool.return_value = ""
        graph = await investigate(
            "example.com",
            kind=EntityKind.DOMAIN,
            budget=InvestigationBudget.conservative(),
        )

    bundle = to_stix_bundle(graph)
    import json

    parsed = json.loads(bundle.serialize())
    assert parsed["type"] == "bundle"
    # domain-name SCO must be present
    types = {o["type"] for o in parsed["objects"]}
    assert "domain-name" in types
