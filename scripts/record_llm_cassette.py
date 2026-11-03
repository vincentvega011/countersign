"""Record one named smoke request against the configured provider into eval/cassettes/llm/.

Run it yourself once a provider is chosen (docs/PROTOCOL.md Decision 97). It forces `LLM_MODE=record` and
reads the provider settings from the environment only (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, see
`.env.example`). It prints the task, the model and the cassette key, never the key or a header. The file it
writes goes through the scrubber; do not edit cassettes by hand.

    LLM_BASE_URL=... LLM_MODEL=... LLM_API_KEY=... uv run python scripts/record_llm_cassette.py smoke-json
"""

from __future__ import annotations

import os
import sys

from countersign.llm import LlmConfig, LlmError, LlmRequest, build_gateway

SMOKES = {
    "smoke-json": LlmRequest(
        task="smoke",
        system="You answer with one JSON object and nothing else.",
        user='Return {"ok": true}.',
        schema={
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
        timeout_s=60.0,
    ),
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in SMOKES:
        print("usage: record_llm_cassette.py <" + "|".join(SMOKES) + ">", file=sys.stderr)
        return 2
    try:
        config = LlmConfig.from_env({**os.environ, "LLM_MODE": "record"})
        result = build_gateway(config).complete(SMOKES[argv[1]])
    except LlmError as error:
        print(f"{error.code}: {error}", file=sys.stderr)
        return 1
    print(f"recorded task={result.task} model={result.model} key={result.request_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
