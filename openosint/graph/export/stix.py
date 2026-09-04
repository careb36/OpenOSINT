# openosint/graph/export/stix.py
"""
STIX 2.1 export for openosint.correlation.EntityGraph.

Converts the lightweight EntityGraph (the in-memory graph returned by
investigate_graph / pivot.py) into a valid STIX 2.1 Bundle that can be
ingested directly by OpenCTI, MISP connectors, or any STIX-aware platform.

DESIGN CHOICES
--------------
* Requires the optional `stix` extra (`pip install openosint[stix]`).
  Import-guarded so the rest of openosint works without stix2 installed.
* EntityType → STIX 2.1 SCO / SDO mapping:
    EMAIL    → EmailAddress        (SCO)
    USERNAME → UserAccount         (SCO)
    DOMAIN   → DomainName          (SCO)
    IP       → IPv4Address or      (SCO, auto-detected)
               IPv6Address
    PHONE    → PhoneNumber         (SCO)
    URL      → URL                 (SCO)
    HASH     → File (hashes dict)  (SCO)
    PERSON   → Identity(class=individual) (SDO)
    ORG      → Identity(class=organization) (SDO)
    ASN      → AutonomousSystem    (SCO)
* Relationships in EntityGraph become STIX Relationship SDOs with the
  `relationship_type` set to the EntityGraph `kind` string (lowercased,
  spaces → hyphens). Unresolvable source/target references are silently
  skipped.
* Provenance is encoded as:
    - `confidence` (0-100 int): entity.confidence * 100, clamped.
    - `labels`: sorted list of source_tools.
    - `x_opencti_score` (extension property): same int as confidence.
    - A STIX Note SDO per entity when source_tools is non-empty, linking
      tools and entity type as structured context for OpenCTI.
* A single Identity SDO representing "OpenOSINT" is added as the
  `created_by_ref` for all objects so OpenCTI attributes findings correctly.
* Bundle id and object ids are deterministic: SHA-256 of the
  (type, value) pair for SCOs/SDOs, so re-exporting the same graph
  produces the same bundle, enabling idempotent OpenCTI ingestion.

USAGE
-----
    from openosint.graph.export.stix import to_stix_bundle
    bundle = to_stix_bundle(graph)
    print(bundle.serialize(pretty=True))       # JSON string
    # or pass directly to pycti:
    # opencti_api_client.stix2.import_bundle_from_dict(bundle.serialize())
"""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from openosint.correlation import EntityGraph

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OPENOSINT_IDENTITY_ID = "identity--b6e6b5e7-1234-5000-8000-6f70656e6f73"
_OPENOSINT_IDENTITY_NAME = "OpenOSINT"

# IPv6 quick-detect: contains ':' and no dot (avoids false-positives on
# domain names that happen to look like IPs).
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Namespace UUID for OpenOSINT STIX id generation (stable, arbitrary v4 sentinel)
_OPENOSINT_NS = uuid.UUID("b6e6b5e7-0000-4000-8000-6f70656e6f73")


def _stix_id(stix_type: str, value: str) -> str:
    """Return a deterministic STIX 2.1 id for a (type, value) pair.

    Uses uuid5 (name-based SHA-1) with a fixed OpenOSINT namespace UUID so
    the same (type, value) pair always produces the same UUID across runs —
    enabling idempotent OpenCTI ingestion.  stix2 library accepts uuid5.
    """
    uid = uuid.uuid5(_OPENOSINT_NS, f"{stix_type}:{value}")
    return f"{stix_type}--{uid}"


def _confidence_int(confidence: float) -> int:
    """Convert [0.0, 1.0] float to STIX integer confidence [0, 100]."""
    return max(0, min(100, round(confidence * 100)))


def _safe_kind(kind: str) -> str:
    """Convert relationship kind string to a valid STIX relationship_type."""
    return re.sub(r"[^a-z0-9-]", "-", kind.lower().replace(" ", "-")).strip("-") or "related-to"


# ---------------------------------------------------------------------------
# STIX object builders (return plain dicts; stix2 validates on Bundle creation)
# ---------------------------------------------------------------------------


def _openosint_identity() -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _OPENOSINT_IDENTITY_ID,
        "name": _OPENOSINT_IDENTITY_NAME,
        "identity_class": "system",
        "description": "OpenOSINT automated OSINT collection system.",
    }


def _entity_to_stix(entity: "Any") -> dict[str, Any] | None:
    """Convert one EntityGraph Entity to a STIX 2.1 object dict.

    Returns None for entity types that have no reasonable SCO/SDO mapping.
    """
    from openosint.correlation import EntityType

    v = entity.value
    conf = _confidence_int(entity.confidence)
    labels = sorted(entity.source_tools) if entity.source_tools else []
    common: dict[str, Any] = {
        "spec_version": "2.1",
        "confidence": conf,
        "created_by_ref": _OPENOSINT_IDENTITY_ID,
        "x_opencti_score": conf,
    }
    if labels:
        common["labels"] = labels

    t = entity.type

    if t == EntityType.EMAIL:
        sid = _stix_id("email-addr", entity.normalized)
        return {"type": "email-addr", "id": sid, "value": v, **common}

    if t == EntityType.USERNAME:
        sid = _stix_id("user-account", entity.normalized)
        return {
            "type": "user-account",
            "id": sid,
            "user_id": v,
            "account_type": "generic",
            **common,
        }

    if t == EntityType.DOMAIN:
        sid = _stix_id("domain-name", entity.normalized)
        return {"type": "domain-name", "id": sid, "value": v, **common}

    if t == EntityType.IP:
        if _IPV6_RE.match(v.strip()):
            sid = _stix_id("ipv6-addr", entity.normalized)
            return {"type": "ipv6-addr", "id": sid, "value": v, **common}
        sid = _stix_id("ipv4-addr", entity.normalized)
        return {"type": "ipv4-addr", "id": sid, "value": v, **common}

    if t == EntityType.PHONE:
        sid = _stix_id("x-openosint-phone-number", entity.normalized)
        # phone-number is not an official SCO; encode as a custom SCO
        return {
            "type": "x-openosint-phone-number",
            "id": sid,
            "number": v,
            **common,
        }

    if t == EntityType.URL:
        sid = _stix_id("url", entity.normalized)
        return {"type": "url", "id": sid, "value": v, **common}

    if t == EntityType.HASH:
        # Detect hash algorithm by length (MD5=32, SHA1=40, SHA256=64)
        h = v.lower().strip()
        if len(h) == 32:
            hashes = {"MD5": v}
        elif len(h) == 40:
            hashes = {"SHA-1": v}
        elif len(h) == 64:
            hashes = {"SHA-256": v}
        else:
            hashes = {"UNKNOWN": v}
        sid = _stix_id("file", entity.normalized)
        return {"type": "file", "id": sid, "hashes": hashes, **common}

    if t == EntityType.PERSON:
        sid = _stix_id("identity", entity.normalized)
        return {
            "type": "identity",
            "id": sid,
            "name": v,
            "identity_class": "individual",
            **common,
        }

    if t == EntityType.ORG:
        sid = _stix_id("identity", entity.normalized)
        return {
            "type": "identity",
            "id": sid,
            "name": v,
            "identity_class": "organization",
            **common,
        }

    if t == EntityType.ASN:
        # Normalize "AS12345" or "12345" → integer
        asn_str = v.upper().lstrip("AS").strip()
        try:
            number = int(asn_str)
        except ValueError:
            number = 0
        sid = _stix_id("autonomous-system", entity.normalized)
        return {"type": "autonomous-system", "id": sid, "number": number, "name": v, **common}

    return None


def _note_for_entity(stix_id: str, entity: "Any") -> dict[str, Any]:
    """Build a STIX Note SDO that documents provenance for one entity."""
    tools_str = ", ".join(sorted(entity.source_tools))
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": _stix_id("note", f"provenance:{stix_id}"),
        "abstract": f"OpenOSINT provenance for {entity.type.value}: {entity.value}",
        "content": (
            f"Entity type: {entity.type.value}\n"
            f"Value: {entity.value}\n"
            f"Confidence: {entity.confidence:.2f}\n"
            f"Source tools: {tools_str}"
        ),
        "object_refs": [stix_id],
        "created_by_ref": _OPENOSINT_IDENTITY_ID,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def to_stix_bundle(graph: "EntityGraph") -> "Any":
    """Convert an EntityGraph to a stix2.Bundle.

    Parameters
    ----------
    graph:
        An openosint.correlation.EntityGraph populated by investigate_graph()
        or any other means.

    Returns
    -------
    stix2.Bundle
        A valid STIX 2.1 Bundle. Call ``.serialize(pretty=True)`` for JSON.

    Raises
    ------
    ImportError
        If the ``stix2`` package is not installed. Install with:
        ``pip install openosint[stix]`` or ``pip install stix2>=3.0.0``.
    """
    try:
        import stix2
    except ImportError as exc:
        raise ImportError(
            "STIX 2.1 export requires the 'stix' extra. "
            "Install with: pip install openosint[stix]"
        ) from exc

    objects: list[Any] = [_openosint_identity()]

    # Build entity dict lookup: (EntityType, normalized) -> stix_id
    stix_id_map: dict[tuple, str] = {}

    for entity in graph._sorted_entities():
        obj = _entity_to_stix(entity)
        if obj is None:
            continue
        objects.append(obj)
        stix_id_map[(entity.type, entity.normalized)] = obj["id"]

        # Add provenance Note when source_tools is populated
        if entity.source_tools:
            objects.append(_note_for_entity(obj["id"], entity))

    # Relationships
    for rel in graph._sorted_relationships():
        src_id = stix_id_map.get((rel.source.type, rel.source.normalized))
        tgt_id = stix_id_map.get((rel.target.type, rel.target.normalized))
        if src_id is None or tgt_id is None:
            continue
        rel_id = _stix_id(
            "relationship",
            f"{src_id}:{rel.kind}:{tgt_id}",
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "relationship_type": _safe_kind(rel.kind),
                "source_ref": src_id,
                "target_ref": tgt_id,
                "confidence": _confidence_int(rel.confidence),
                "created_by_ref": _OPENOSINT_IDENTITY_ID,
                "labels": [rel.source_tool] if rel.source_tool else [],
            }
        )

    # Build Bundle with allow_custom=True to support x_opencti_score and
    # x-openosint-phone-number custom objects
    return stix2.Bundle(objects=objects, allow_custom=True)


def to_stix_json(graph: "EntityGraph", *, pretty: bool = True) -> str:
    """Serialize an EntityGraph to a STIX 2.1 JSON string.

    Convenience wrapper around to_stix_bundle().serialize().
    Raises ImportError if stix2 is not installed.
    """
    bundle = to_stix_bundle(graph)
    return bundle.serialize(pretty=pretty)
