# openosint/tools/search_username.py
"""
Username OSINT module.

Wraps the 'sherlock' binary to enumerate social networks and platforms where a
target username is registered. Returns a formatted string; never raises.
"""

from __future__ import annotations

import logging

from openosint.proxy import get_sherlock_proxy_args
from openosint.tools.exceptions import OSINTError
from openosint.utils import run_subprocess

logger = logging.getLogger(__name__)

_BINARY = "sherlock"
_DEFAULT_TIMEOUT = 180
_INSTALL_HINT = "Install it with: pip install sherlock-project"
_PER_SITE_TIMEOUT = "3"  # seconds per site, passed to sherlock --timeout


async def _run_sherlock(username: str, timeout_seconds: int) -> str:
    """Execute sherlock against username and return raw stdout."""
    result = await run_subprocess(
        binary=_BINARY,
        args=[
            username,
            "--print-found",
            "--timeout",
            _PER_SITE_TIMEOUT,
            *get_sherlock_proxy_args(),
        ],
        timeout_seconds=timeout_seconds,
        install_hint=_INSTALL_HINT,
    )
    return result.stdout


def _format_username_results(raw: str, username: str) -> str:
    """Return a structured string suitable for CLI display and LLM consumption."""
    if not raw:
        return f"No accounts found for username '{username}'."
    return f"OSINT results for username '{username}':\n\n{raw}"


async def run_username_osint(
    username: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Run a username OSINT scan and return a formatted result string.

    Calls sherlock to enumerate platforms where the username is registered.
    Returns a descriptive error string on failure rather than raising.

    Parameters
    ----------
    username:
        Target username or alias.
    timeout_seconds:
        Maximum execution time for the sherlock subprocess.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    logger.info("Starting username OSINT scan for: %s", username)
    try:
        raw = await _run_sherlock(username, timeout_seconds)
        result = _format_username_results(raw, username)
        logger.info("Username scan complete for: %s", username)
        return result
    except OSINTError as exc:
        logger.warning("Username scan failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during username scan.")
        return f"Internal error: {exc}"
