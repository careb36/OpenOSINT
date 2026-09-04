from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from openosint.investigate import EntityKind, InvestigationBudget, investigate

try:
    __version__ = _pkg_version("openosint")
except PackageNotFoundError:
    __version__ = "unknown"

version = __version__

__all__ = [
    "EntityKind",
    "InvestigationBudget",
    "__version__",
    "investigate",
    "version",
]
