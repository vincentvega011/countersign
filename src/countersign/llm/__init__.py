"""The model gateway (docs/PROTOCOL.md Decisions 94 to 97).

One interface for every model call (the shopping agent, the adversary, Ask Countersign). Output is
validated, structured, untrusted data. Nothing under `llm` may be imported by an authorization module and
`llm` imports none of them: `tests/unit/test_llm_boundary.py` enforces both.
"""

from countersign.llm.cassette import CassetteStore, scrub
from countersign.llm.config import LlmConfig
from countersign.llm.errors import (
    LlmBudgetExceededError,
    LlmConfigError,
    LlmError,
    LlmOutputTooLargeError,
    LlmProviderError,
    LlmRateLimitedError,
    LlmReplayMissingError,
    LlmSchemaError,
    LlmTimeoutError,
)
from countersign.llm.fake import FakeProvider
from countersign.llm.gateway import LlmGateway, parse_output
from countersign.llm.openai_compat import OpenAICompatProvider
from countersign.llm.request import LlmRequest, LlmResult, request_key


def build_gateway(config: LlmConfig | None = None) -> LlmGateway:
    """A gateway from the environment: replay by default, a real provider only in live or record mode."""
    config = config or LlmConfig.from_env()
    if config.mode == "replay":
        return LlmGateway(config)
    return LlmGateway(
        config,
        OpenAICompatProvider(
            config.base_url, config.api_key, response_format=config.response_format
        ),
    )


__all__ = [
    "CassetteStore",
    "FakeProvider",
    "LlmBudgetExceededError",
    "LlmConfig",
    "LlmConfigError",
    "LlmError",
    "LlmGateway",
    "LlmOutputTooLargeError",
    "LlmProviderError",
    "LlmRateLimitedError",
    "LlmReplayMissingError",
    "LlmRequest",
    "LlmResult",
    "LlmSchemaError",
    "LlmTimeoutError",
    "OpenAICompatProvider",
    "build_gateway",
    "parse_output",
    "request_key",
    "scrub",
]
