# tests/test_graph_stix_export.py
"""
Tests for openosint.graph.export.stix — STIX 2.1 export of EntityGraph.

All tests skip when stix2 is not installed (requires openosint[stix] extra).
No network, no tool binaries, no API keys needed.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("stix2", reason="requires the 'stix' extra: pip install openosint[stix]")

from openosint.correlation import (  # noqa: E402
    EntityGraph,
    EntityType,
    Relationship,
    make_entity,
)
from openosint.graph.export.stix import (  # noqa: E402
    _OPENOSINT_IDENTITY_ID,
    _confidence_int,
    _safe_kind,
    _stix_id,
    to_stix_bundle,
    to_stix_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _graph_with(*entities, relationships=()) -> EntityGraph:
    g = EntityGraph()
    for e in entities:
        g.add_entity(e)
    for r in relationships:
        g.add_relationship(r)
    return g


def _bundle_objects(graph: EntityGraph) -> list[dict]:
    bundle = to_stix_bundle(graph)
    return json.loads(bundle.serialize())["objects"]


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_stix_id_is_deterministic(self):
        a = _stix_id("email-addr", "test@example.com")
        b = _stix_id("email-addr", "test@example.com")
        assert a == b

    def test_stix_id_differs_by_type(self):
        a = _stix_id("email-addr", "test@example.com")
        b = _stix_id("domain-name", "test@example.com")
        assert a != b

    def test_stix_id_has_correct_prefix(self):
        sid = _stix_id("domain-name", "example.com")
        assert sid.startswith("domain-name--")

    def test_confidence_int_clamps(self):
        assert _confidence_int(0.0) == 0
        assert _confidence_int(1.0) == 100
        assert _confidence_int(0.85) == 85
        assert _confidence_int(1.5) == 100
        assert _confidence_int(-0.1) == 0

    def test_safe_kind_lowercases_and_replaces_spaces(self):
        assert _safe_kind("registrant email") == "registrant-email"
        assert _safe_kind("FOUND_IN_BREACH") == "found-in-breach"

    def test_safe_kind_strips_leading_trailing_hyphens(self):
        assert not _safe_kind("!!!").startswith("-")

    def test_safe_kind_empty_falls_back(self):
        assert _safe_kind("") == "related-to"


# ---------------------------------------------------------------------------
# Bundle structure
# ---------------------------------------------------------------------------


class TestBundleStructure:
    def test_empty_graph_has_only_identity(self):
        g = EntityGraph()
        objs = _bundle_objects(g)
        assert len(objs) == 1
        assert objs[0]["type"] == "identity"
        assert objs[0]["id"] == _OPENOSINT_IDENTITY_ID

    def test_bundle_type_is_bundle(self):
        g = EntityGraph()
        raw = json.loads(to_stix_bundle(g).serialize())
        assert raw["type"] == "bundle"

    def test_openosint_identity_always_present(self):
        e = make_entity(EntityType.DOMAIN, "example.com", 1.0)
        g = _graph_with(e)
        objs = _bundle_objects(g)
        identity_ids = [o["id"] for o in objs if o["type"] == "identity"]
        assert _OPENOSINT_IDENTITY_ID in identity_ids


# ---------------------------------------------------------------------------
# SCO mapping — one test per entity type
# ---------------------------------------------------------------------------


class TestEntityTypeMapping:
    def test_email_becomes_email_addr(self):
        e = make_entity(EntityType.EMAIL, "user@example.com", 0.9, "search_breach")
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "email-addr")
        assert sco["value"] == "user@example.com"
        assert sco["confidence"] == 90
        assert sco["created_by_ref"] == _OPENOSINT_IDENTITY_ID

    def test_username_becomes_user_account(self):
        e = make_entity(EntityType.USERNAME, "johndoe", 0.85)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "user-account")
        assert sco["user_id"] == "johndoe"

    def test_domain_becomes_domain_name(self):
        e = make_entity(EntityType.DOMAIN, "example.com", 1.0)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "domain-name")
        assert sco["value"] == "example.com"

    def test_ipv4_becomes_ipv4_addr(self):
        e = make_entity(EntityType.IP, "1.2.3.4", 0.95)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "ipv4-addr")
        assert sco["value"] == "1.2.3.4"

    def test_ipv6_becomes_ipv6_addr(self):
        e = make_entity(EntityType.IP, "2001:db8::1", 0.95)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "ipv6-addr")
        assert sco["value"] == "2001:db8::1"

    def test_url_becomes_url(self):
        e = make_entity(EntityType.URL, "https://example.com/path", 0.8)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "url")
        assert "example.com" in sco["value"]

    def test_md5_hash_becomes_file_with_md5(self):
        e = make_entity(EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e", 0.9)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "file")
        assert "MD5" in sco["hashes"]

    def test_sha1_hash_becomes_file_with_sha1(self):
        e = make_entity(EntityType.HASH, "da39a3ee5e6b4b0d3255bfef95601890afd80709", 0.9)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "file")
        assert "SHA-1" in sco["hashes"]

    def test_sha256_hash_becomes_file_with_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        e = make_entity(EntityType.HASH, h, 0.9)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "file")
        assert "SHA-256" in sco["hashes"]

    def test_person_becomes_identity_individual(self):
        e = make_entity(EntityType.PERSON, "John Doe", 0.7)
        objs = _bundle_objects(_graph_with(e))
        person = next(
            (o for o in objs if o["type"] == "identity" and o["id"] != _OPENOSINT_IDENTITY_ID),
            None,
        )
        assert person is not None
        assert person["identity_class"] == "individual"
        assert person["name"] == "John Doe"

    def test_org_becomes_identity_organization(self):
        e = make_entity(EntityType.ORG, "Acme Corp", 0.8)
        objs = _bundle_objects(_graph_with(e))
        org = next(
            (o for o in objs if o["type"] == "identity" and o["id"] != _OPENOSINT_IDENTITY_ID),
            None,
        )
        assert org is not None
        assert org["identity_class"] == "organization"

    def test_asn_becomes_autonomous_system(self):
        e = make_entity(EntityType.ASN, "AS12345", 0.9)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "autonomous-system")
        assert sco["number"] == 12345

    def test_asn_numeric_string_parsed(self):
        e = make_entity(EntityType.ASN, "65000", 0.9)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "autonomous-system")
        assert sco["number"] == 65000


# ---------------------------------------------------------------------------
# Provenance encoding
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_confidence_encoded_as_integer(self):
        e = make_entity(EntityType.EMAIL, "a@b.com", 0.75)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "email-addr")
        assert sco["confidence"] == 75

    def test_x_opencti_score_equals_confidence(self):
        e = make_entity(EntityType.DOMAIN, "example.com", 0.6)
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "domain-name")
        assert sco["x_opencti_score"] == sco["confidence"]

    def test_source_tools_become_labels(self):
        e = make_entity(EntityType.IP, "1.2.3.4", 0.9, "search_shodan")
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "ipv4-addr")
        assert "search_shodan" in sco.get("labels", [])

    def test_no_labels_key_when_no_source_tools(self):
        e = make_entity(EntityType.DOMAIN, "example.com", 1.0)
        # make_entity with empty source_tool produces empty source_tools set
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "domain-name")
        assert not sco.get("labels")

    def test_provenance_note_created_when_source_tools_present(self):
        e = make_entity(EntityType.IP, "1.2.3.4", 0.9, "search_ip")
        objs = _bundle_objects(_graph_with(e))
        notes = [o for o in objs if o["type"] == "note"]
        assert len(notes) == 1
        assert "search_ip" in notes[0]["content"]

    def test_no_note_when_source_tools_empty(self):
        e = make_entity(EntityType.DOMAIN, "example.com", 1.0)
        objs = _bundle_objects(_graph_with(e))
        notes = [o for o in objs if o["type"] == "note"]
        assert notes == []

    def test_note_references_entity_id(self):
        e = make_entity(EntityType.EMAIL, "a@b.com", 0.9, "search_email")
        objs = _bundle_objects(_graph_with(e))
        sco = next(o for o in objs if o["type"] == "email-addr")
        note = next(o for o in objs if o["type"] == "note")
        assert sco["id"] in note["object_refs"]


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


class TestRelationships:
    def _rel_graph(self) -> tuple[EntityGraph, str, str]:
        """Graph with one email→domain relationship; returns graph + ids."""
        email = make_entity(EntityType.EMAIL, "a@example.com", 0.9, "search_email")
        domain = make_entity(EntityType.DOMAIN, "example.com", 0.9, "search_whois")
        rel = Relationship(source=email, target=domain, kind="registered_at", source_tool="search_whois")
        g = _graph_with(email, domain, relationships=[rel])
        return g, email, domain

    def test_relationship_sdo_present(self):
        g, _, _ = self._rel_graph()
        objs = _bundle_objects(g)
        rels = [o for o in objs if o["type"] == "relationship"]
        assert len(rels) == 1

    def test_relationship_type_normalized(self):
        g, _, _ = self._rel_graph()
        objs = _bundle_objects(g)
        rel = next(o for o in objs if o["type"] == "relationship")
        assert rel["relationship_type"] == "registered-at"

    def test_relationship_source_and_target_refs_valid(self):
        g, email_e, domain_e = self._rel_graph()
        objs = _bundle_objects(g)
        rel = next(o for o in objs if o["type"] == "relationship")
        object_ids = {o["id"] for o in objs}
        assert rel["source_ref"] in object_ids
        assert rel["target_ref"] in object_ids

    def test_relationship_with_unresolvable_entity_skipped(self):
        """Relationships whose source or target are not in the STIX map are dropped."""
        email = make_entity(EntityType.EMAIL, "a@example.com", 0.9)
        domain = make_entity(EntityType.DOMAIN, "example.com", 0.9)
        rel = Relationship(source=email, target=domain, kind="at", source_tool="")
        # Add only email to the graph, not domain
        g = EntityGraph()
        g.add_entity(email)
        g.add_relationship(rel)
        objs = _bundle_objects(g)
        rels = [o for o in objs if o["type"] == "relationship"]
        assert rels == []

    def test_relationship_confidence_encoded(self):
        email = make_entity(EntityType.EMAIL, "a@example.com", 0.9)
        domain = make_entity(EntityType.DOMAIN, "example.com", 0.8)
        rel = Relationship(
            source=email, target=domain, kind="at", source_tool="", confidence=0.75
        )
        g = _graph_with(email, domain, relationships=[rel])
        objs = _bundle_objects(g)
        stix_rel = next(o for o in objs if o["type"] == "relationship")
        assert stix_rel["confidence"] == 75

    def test_source_tool_in_relationship_labels(self):
        email = make_entity(EntityType.EMAIL, "a@example.com", 0.9)
        domain = make_entity(EntityType.DOMAIN, "example.com", 0.8)
        rel = Relationship(source=email, target=domain, kind="at", source_tool="search_whois")
        g = _graph_with(email, domain, relationships=[rel])
        objs = _bundle_objects(g)
        stix_rel = next(o for o in objs if o["type"] == "relationship")
        assert "search_whois" in stix_rel.get("labels", [])


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_same_entity_ids_across_two_bundle_calls(self):
        """The same graph always produces the same object IDs (idempotent ingestion)."""
        e1 = make_entity(EntityType.DOMAIN, "example.com", 0.9, "search_dns")
        e2 = make_entity(EntityType.IP, "1.2.3.4", 0.8, "search_ip")
        rel = Relationship(source=e1, target=e2, kind="resolves_to", source_tool="search_dns")
        g = _graph_with(e1, e2, relationships=[rel])

        objs1 = _bundle_objects(g)
        objs2 = _bundle_objects(g)
        ids1 = sorted(o["id"] for o in objs1)
        ids2 = sorted(o["id"] for o in objs2)
        assert ids1 == ids2

    def test_same_entity_in_two_graphs_gets_same_id(self):
        e = make_entity(EntityType.IP, "10.0.0.1", 1.0)
        g1 = _graph_with(e)
        g2 = _graph_with(e)
        objs1 = _bundle_objects(g1)
        objs2 = _bundle_objects(g2)
        id1 = next(o["id"] for o in objs1 if o["type"] == "ipv4-addr")
        id2 = next(o["id"] for o in objs2 if o["type"] == "ipv4-addr")
        assert id1 == id2


# ---------------------------------------------------------------------------
# to_stix_json convenience wrapper
# ---------------------------------------------------------------------------


class TestToStixJson:
    def test_returns_valid_json_string(self):
        e = make_entity(EntityType.DOMAIN, "example.com", 1.0)
        result = to_stix_json(_graph_with(e))
        parsed = json.loads(result)
        assert parsed["type"] == "bundle"

    def test_pretty_false_produces_compact_json(self):
        e = make_entity(EntityType.DOMAIN, "example.com", 1.0)
        result = to_stix_json(_graph_with(e), pretty=False)
        assert "\n" not in result


# ---------------------------------------------------------------------------
# Import error when stix2 absent
# ---------------------------------------------------------------------------


class TestImportError:
    def test_importerror_message_mentions_extra(self, monkeypatch):
        import sys
        original = sys.modules.get("stix2")
        sys.modules["stix2"] = None  # type: ignore[assignment]
        try:
            import importlib

            import openosint.graph.export.stix as stix_mod

            importlib.reload(stix_mod)
            from openosint.graph.export.stix import to_stix_bundle as _tsb

            g = EntityGraph()
            with pytest.raises(ImportError, match="stix"):
                _tsb(g)
        finally:
            if original is None:
                del sys.modules["stix2"]
            else:
                sys.modules["stix2"] = original
