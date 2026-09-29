"""Tokenizer: maps normalized AgentEvents to a discrete token vocabulary.

Design decisions (see docs/ADR-004):
- Token format: "<kind>:<name>" e.g. "tool:verify_id", "llm:call", "net:egress_new_domain"
- Special tokens: <SOS>, <EOS> bracket every session; <UNK> for out-of-vocabulary
  events seen at inference time but not during vocab fitting.
- Vocab is frozen after fit(); new tools appearing later map to <UNK> so the model
  never crashes on unseen behavior — instead, <UNK> itself carries surprise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

SOS = "<SOS>"
EOS = "<EOS>"
UNK = "<UNK>"
SPECIAL_TOKENS = (SOS, EOS, UNK)


def event_to_token(event: Mapping) -> str:
    """Convert a normalized AgentEvent dict to a token string.

    Expected event keys (subset of the AgentEvent schema):
      - kind: "tool" | "llm" | "net"
      - name: tool name / model action / egress label
    """
    kind = str(event.get("kind", "unknown")).lower().strip()
    name = str(event.get("name", "unknown")).lower().strip()
    if not kind or not name:
        raise ValueError(f"Event missing kind/name: {event!r}")
    return f"{kind}:{name}"


@dataclass
class Tokenizer:
    """Frozen-vocabulary tokenizer with OOV handling."""

    token_to_id: dict[str, int] = field(default_factory=dict)
    _fitted: bool = False

    def fit(self, sessions: Iterable[Sequence[Mapping]]) -> "Tokenizer":
        """Build the vocabulary from training sessions (lists of events)."""
        vocab: dict[str, int] = {tok: i for i, tok in enumerate(SPECIAL_TOKENS)}
        for session in sessions:
            for event in session:
                tok = event_to_token(event)
                if tok not in vocab:
                    vocab[tok] = len(vocab)
        self.token_to_id = vocab
        self._fitted = True
        return self

    @property
    def id_to_token(self) -> dict[int, str]:
        return {i: t for t, i in self.token_to_id.items()}

    @property
    def vocab_size(self) -> int:
        return len(self.token_to_id)

    def encode_session(self, session: Sequence[Mapping]) -> list[int]:
        """Encode one session of events into token ids, bracketed by SOS/EOS.

        Unknown events map to <UNK> rather than raising.
        """
        if not self._fitted:
            raise RuntimeError("Tokenizer must be fitted before encoding.")
        unk_id = self.token_to_id[UNK]
        ids = [self.token_to_id[SOS]]
        for event in session:
            tok = event_to_token(event)
            ids.append(self.token_to_id.get(tok, unk_id))
        ids.append(self.token_to_id[EOS])
        return ids

    def decode(self, ids: Sequence[int]) -> list[str]:
        rev = self.id_to_token
        return [rev.get(i, UNK) for i in ids]

    # -- persistence -------------------------------------------------------
    def to_dict(self) -> dict:
        return {"token_to_id": self.token_to_id}

    @classmethod
    def from_dict(cls, d: Mapping) -> "Tokenizer":
        if "token_to_id" not in d:
            raise ValueError("Tokenizer.from_dict: missing 'token_to_id' key")
        t2i = d["token_to_id"]
        if not isinstance(t2i, Mapping):
            raise ValueError(
                f"Tokenizer.from_dict: 'token_to_id' must be a mapping, got {type(t2i).__name__}"
            )
        for k, v in t2i.items():
            if not isinstance(k, str):
                raise ValueError(f"Tokenizer.from_dict: non-str token key: {k!r}")
            if not (isinstance(v, int) and not isinstance(v, bool)):
                raise ValueError(f"Tokenizer.from_dict: non-int id value for token {k!r}: {v!r}")
        for tok in SPECIAL_TOKENS:
            if tok not in t2i:
                raise ValueError(f"Tokenizer.from_dict: missing required special token {tok!r}")
        ids = list(t2i.values())
        n = len(t2i)
        if sorted(ids) != list(range(n)):
            raise ValueError(
                f"Tokenizer.from_dict: id space is not contiguous 0..{n - 1}: got {sorted(ids)}"
            )
        tk = cls(token_to_id=dict(t2i))
        tk._fitted = True
        return tk
