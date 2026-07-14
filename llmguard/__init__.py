"""LLMGuard - Enterprise LLM Firewall SDK.

Use LLMGuard as a library to scan and redact sensitive data before sending
to LLMs. Works standalone (no proxy required) or as a LiteLLM callback.

Quick Start:
    from llmguard import scan, redact, is_safe

    # Check if text contains sensitive data
    result = scan("My SSN is 123-45-6789")
    if not result.is_safe:
        print(f"Blocked: {result.categories}")

    # Redact and get safe text
    safe = redact("Email me at john@corp.com")
    print(safe.text)  # "Email me at [EMAIL_1]"

    # De-tokenize LLM response
    restored = safe.restore("Contact [EMAIL_1] for details")
    print(restored)  # "Contact john@corp.com for details"

LiteLLM Integration:
    import litellm
    from llmguard import LLMGuardCallback

    litellm.callbacks = [LLMGuardCallback()]
    # All LLM calls are now automatically scanned
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

__version__ = "0.1.0"

if TYPE_CHECKING:
    from llmguard.callback import LLMGuardCallback
    from llmguard.sdk import RedactResult, ScanResult, is_safe, redact, scan

__all__ = [
    "scan",
    "redact",
    "is_safe",
    "ScanResult",
    "RedactResult",
    "LLMGuardCallback",
    "__version__",
]

# The SDK (scan/redact/LLMGuardCallback) and its detokenization engine live in
# ``llmguard.sdk`` / ``llmguard.callback``, which currently depend on the
# separate ``app`` package. Import them lazily so the CLI wedge
# (``llmguard.gateway`` / ``llmguard.cli``) and a bare ``import llmguard`` work
# in a standalone install where ``app`` is not present.
_LAZY_EXPORTS = {
    "scan": "llmguard.sdk",
    "redact": "llmguard.sdk",
    "is_safe": "llmguard.sdk",
    "ScanResult": "llmguard.sdk",
    "RedactResult": "llmguard.sdk",
    "LLMGuardCallback": "llmguard.callback",
}


def __getattr__(name: str) -> Any:
    module = _LAZY_EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module), name)
