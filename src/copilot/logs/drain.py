"""Log template extraction, Drain-style.

The problem: a million log lines are a few hundred distinct *templates* with variables
substituted in. Nobody can read a million lines; everybody can read "this template
fired 40,000 times today and never before".

    Connection to db-7 failed after 3021ms
    Connection to db-2 failed after 1180ms
        -> Connection to db-<*> failed after <*>ms

Drain does this with a fixed-depth parse tree rather than clustering: bucket by token
count, then by the first few tokens, then compare against the small number of
candidates in that leaf. That makes it O(1)-ish per line instead of comparing against
every template seen so far, which is what makes it usable on a real log stream.

Implemented from the paper's description rather than wrapped, because the parameters
that matter - depth, similarity threshold, what counts as a variable - are exactly the
ones you need to tune for your own logs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

WILDCARD = "<*>"

# Tokens that are variable by construction. Masking them before matching stops a
# template exploding into thousands of near-identical variants.
_MASKS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
        "<UUID>",
    ),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<HEX>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"), "<TS>"),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|kb|mb|gb|%)\b", re.I), "<NUM>"),
    # Plain numbers, including scientific notation (1.5e10) - without the exponent
    # part a value like that was left completely unmasked.
    (re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?![\w.])"), "<NUM>"),
    (re.compile(r"\b[\w.]+@[\w.]+\.\w+\b"), "<EMAIL>"),
    (re.compile(r"(/[\w.\-]+){2,}"), "<PATH>"),
    # Windows-style paths (C:\Users\ops\app.log). Without this, a username or
    # hostname embedded in a Windows path leaked straight into the template and
    # lines differing only by that path never collapsed.
    (re.compile(r"\b[A-Za-z]:(?:\\[\w.\-]+)+"), "<PATH>"),
]


def mask(line: str) -> str:
    if not isinstance(line, str):
        raise TypeError(f"mask() expects a str, got {type(line).__name__} instead: {line!r}")
    for pattern, token in _MASKS:
        line = pattern.sub(token, line)
    return line


@dataclass
class Template:
    id: int
    tokens: list[str]
    count: int = 0
    examples: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(self.tokens)

    def similarity(self, tokens: list[str]) -> float:
        """Fraction of positions that agree. A wildcard position is free - it has
        already been generalised, so it should not penalise a match."""
        if len(tokens) != len(self.tokens):
            return 0.0
        if not tokens:
            return 1.0
        same = sum(1 for a, b in zip(self.tokens, tokens, strict=False) if a in (b, WILDCARD))
        return same / len(tokens)

    def merge(self, tokens: list[str]) -> None:
        """Generalise positions that disagree into wildcards."""
        self.tokens = [a if a == b else WILDCARD for a, b in zip(self.tokens, tokens, strict=False)]


@dataclass
class DrainParser:
    # Tree depth beyond the token-count level. Deeper is more precise and more
    # fragmented; 4 is the paper's default and holds up well in practice.
    depth: int = 4
    similarity_threshold: float = 0.5
    max_children: int = 100

    _tree: dict = field(default_factory=dict)
    _templates: dict[int, Template] = field(default_factory=dict)
    _next_id: int = 0

    def _tokenise(self, line: str) -> list[str]:
        return mask(line.strip()).split()

    def _leaf(self, tokens: list[str], *, create: bool) -> list[Template] | None:
        node = self._tree.setdefault(len(tokens), {}) if create else self._tree.get(len(tokens))
        if node is None:
            return None

        # The prefix must not consume the whole line. If it does, two lines
        # differing in one position can never reach the same leaf, and no
        # template can ever generalise - which defeats the purpose.
        prefix_len = max(1, min(self.depth - 1, len(tokens) - 2))
        for i in range(prefix_len):
            token = tokens[i]
            # A token that is already a variable would fragment the tree, so every
            # such line shares one branch.
            key = WILDCARD if any(c.isdigit() for c in token) else token
            if key not in node:
                if not create:
                    key = WILDCARD if WILDCARD in node else key
                    if key not in node:
                        return None
                elif len(node) >= self.max_children:
                    key = WILDCARD
                    node.setdefault(key, {})
                else:
                    node[key] = {}
            node = node[key]

        if "__leaf__" not in node:
            if not create:
                return None
            node["__leaf__"] = []
        return node["__leaf__"]

    def add(self, line: str) -> Template:
        if not isinstance(line, str):
            raise TypeError(
                f"DrainParser.add() expects a str, got {type(line).__name__} instead: {line!r}"
            )
        tokens = self._tokenise(line)
        leaf = self._leaf(tokens, create=True)
        assert leaf is not None

        best, best_score = None, 0.0
        for template in leaf:
            score = template.similarity(tokens)
            if score > best_score:
                best, best_score = template, score

        if best is not None and best_score >= self.similarity_threshold:
            best.merge(tokens)
            best.count += 1
            if len(best.examples) < 3:
                best.examples.append(line.strip())
            return best

        template = Template(id=self._next_id, tokens=tokens, count=1, examples=[line.strip()])
        self._next_id += 1
        self._templates[template.id] = template
        leaf.append(template)
        return template

    def parse(self, lines: list[str]) -> list[Template]:
        for i, line in enumerate(lines):
            if not isinstance(line, str):
                raise TypeError(
                    f"log line {i} is not a str (got {type(line).__name__} instead: "
                    f"{line!r}); DrainParser.parse() expects an iterable of strings"
                )
            if line.strip():
                self.add(line)
        return self.templates()

    def templates(self) -> list[Template]:
        return sorted(self._templates.values(), key=lambda t: -t.count)

    def match(self, line: str) -> Template | None:
        """Find the template for a line without creating one. Used to detect a line
        whose shape has never been seen before - often the first sign of a new fault."""
        tokens = self._tokenise(line)
        leaf = self._leaf(tokens, create=False)
        if not leaf:
            return None
        best, best_score = None, 0.0
        for template in leaf:
            score = template.similarity(tokens)
            if score > best_score:
                best, best_score = template, score
        return best if best_score >= self.similarity_threshold else None
