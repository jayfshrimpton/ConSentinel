"""Source-extraction layer.

The :class:`~consentinel.extract.base.LanguageBackend` ABC is the seam that lets
additional languages be added later. v1 ships the Python backend only.
"""

from consentinel.extract.base import LanguageBackend
from consentinel.extract.python_ast import PythonBackend

__all__ = ["LanguageBackend", "PythonBackend"]
