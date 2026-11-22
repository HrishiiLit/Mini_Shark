"""Safe filter language for Engine E4.

Supported expression shape (recursive descent, no ``eval`` anywhere)::

    protocol == "TCP"
    ip.src == 10.0.0.1 && tcp.port == 443
    bytes > 1000 || duration >= 1.5
    ip.dst startswith "10.0." && protocol != UDP

Grammar::

    expr    := or
    or      := and ( "||" and )*
    and     := primary ( "&&" primary )*
    primary := "(" expr ")" | cmp
    cmp     := field op literal
    op      := "==" | "!=" | ">" | ">=" | "<" | "<=" | contains | startswith | endswith
    literal := "quoted" | number | bare_word

The AST is compiled into a parameterised SQL ``WHERE`` clause: values always
travel as bound parameters, so a filter can never inject SQL (NFR-05).
Malformed input raises :class:`~backend.errors.FilterSyntaxError`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from backend.errors import FilterSyntaxError

_TOKEN_RE = re.compile(
    r"""(?P<ws>\s+)
      | (?P<logic>&&|\|\|)
      | (?P<op>==|!=|>=|<=|>|<)
      | (?P<string>"[^"]*"|'[^']*')
      | (?P<number>-?\d+(?:\.\d+)*)
      | (?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
      | (?P<lparen>\()
      | (?P<rparen>\))
    """,
    re.VERBOSE,
)

_SQL_OPS = {"==": "=", "!=": "<>", ">": ">", ">=": ">=", "<": "<", "<=": "<="}
_WORD_OPS = frozenset({"contains", "startswith", "endswith"})
_TEXT_OPS = frozenset({"==", "!=", *_WORD_OPS})


@dataclass(frozen=True)
class _Field:
    """How one filter field maps onto the ``flows`` table."""

    column: str
    kind: str  # "text" or "number"
    ports: bool = False
    protocol: str | None = None


_FIELDS: dict[str, _Field] = {
    "ip.src": _Field("src_ip", "text"),
    "ip.dst": _Field("dst_ip", "text"),
    "protocol": _Field("protocol", "text"),
    "tcp.port": _Field("src_port", "number", ports=True, protocol="TCP"),
    "udp.port": _Field("src_port", "number", ports=True, protocol="UDP"),
    "port": _Field("src_port", "number", ports=True),
    "packets": _Field("packet_count", "number"),
    "flow.packet_count": _Field("packet_count", "number"),
    "bytes": _Field("byte_count", "number"),
    "flow.byte_count": _Field("byte_count", "number"),
    "duration": _Field("duration", "number"),
    "flow.id": _Field("flow_id", "number"),
}

FILTER_FIELDS: tuple[str, ...] = tuple(sorted(_FIELDS))


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str


def compile_filter(expression: str) -> tuple[str, list[Any]]:
    """Compile a filter into ``(where_sql, params)``.

    An empty expression compiles to no restriction at all.
    """
    tokens = _tokenize(expression)
    if not tokens:
        return "", []
    node = _Parser(tokens).parse()
    return _compile(node)


def _number(text: str) -> str | int | float:
    """``42``/``1.5`` become numbers; dotted quads stay strings."""
    try:
        return int(text) if "." not in text else float(text)
    except ValueError:
        return text


def _tokenize(expression: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(expression):
        match = _TOKEN_RE.match(expression, position)
        if match is None:
            raise FilterSyntaxError(
                f"unexpected character {expression[position]!r} at position {position}"
            )
        position = match.end()
        if match.lastgroup != "ws":
            tokens.append(_Token(match.lastgroup or "ident", match.group()))
    return tokens


class _Parser:
    """Recursive-descent parser producing a tuple AST."""

    def __init__(self, tokens: Sequence[_Token]) -> None:
        self._tokens = list(tokens)
        self._pos = 0

    def parse(self) -> tuple[Any, ...]:
        node = self._parse_or()
        token = self._peek()
        if token is not None:
            raise FilterSyntaxError(f"unexpected token {token.value!r}")
        return node

    def _peek(self) -> _Token | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _take(self) -> _Token:
        token = self._peek()
        if token is None:
            raise FilterSyntaxError("filter ended unexpectedly")
        self._pos += 1
        return token

    def _parse_or(self) -> tuple[Any, ...]:
        node = self._parse_and()
        while (token := self._peek()) is not None and token.value == "||":
            self._pos += 1
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> tuple[Any, ...]:
        node = self._parse_primary()
        while (token := self._peek()) is not None and token.value == "&&":
            self._pos += 1
            node = ("and", node, self._parse_primary())
        return node

    def _parse_primary(self) -> tuple[Any, ...]:
        token = self._peek()
        if token is None:
            raise FilterSyntaxError("filter ended unexpectedly")
        if token.kind == "lparen":
            self._pos += 1
            node = self._parse_or()
            closing = self._take()
            if closing.kind != "rparen":
                raise FilterSyntaxError(f"expected ')', got {closing.value!r}")
            return node
        return self._parse_cmp()

    def _parse_cmp(self) -> tuple[Any, ...]:
        field = self._take()
        if field.kind != "ident":
            raise FilterSyntaxError(f"expected a field name, got {field.value!r}")
        op = self._take_operator(field)
        return ("cmp", field.value, op, self._take_literal())

    def _take_operator(self, field: _Token) -> str:
        token = self._peek()
        if token is None:
            raise FilterSyntaxError(f"missing operator after {field.value!r}")
        if token.kind == "op":
            self._pos += 1
            return token.value
        if token.kind == "ident" and token.value in _WORD_OPS:
            self._pos += 1
            return token.value
        raise FilterSyntaxError(
            f"expected an operator after {field.value!r}, got {token.value!r}"
        )

    def _take_literal(self) -> str | int | float:
        token = self._take()
        if token.kind == "string":
            return token.value[1:-1]
        if token.kind == "number":
            return _number(token.value)
        if token.kind == "ident":
            return token.value
        raise FilterSyntaxError(f"expected a value, got {token.value!r}")


def _compile(node: tuple[Any, ...]) -> tuple[str, list[Any]]:
    kind = node[0]
    if kind in ("and", "or"):
        left_sql, left_params = _compile(node[1])
        right_sql, right_params = _compile(node[2])
        joiner = " AND " if kind == "and" else " OR "
        return f"({left_sql}{joiner}{right_sql})", [*left_params, *right_params]
    return _compile_cmp(node[1], node[2], node[3])


def _compile_cmp(name: str, op: str, value: Any) -> tuple[str, list[Any]]:
    field = _FIELDS.get(name)
    if field is None:
        raise FilterSyntaxError(
            f"unknown field {name!r}; known fields: {', '.join(FILTER_FIELDS)}"
        )
    if field.ports:
        return _compile_ports(field, op, _coerce(value, field, name))
    allowed = _TEXT_OPS if field.kind == "text" else frozenset(_SQL_OPS)
    if op not in allowed:
        raise FilterSyntaxError(f"operator {op!r} is not valid for field {name!r}")
    if field.kind == "text":
        return _compile_text(field.column, op, str(_coerce(value, field, name)))
    return _comparison(field.column, op, _coerce(value, field, name))


def _compile_text(column: str, op: str, value: str) -> tuple[str, list[Any]]:
    if op in ("==", "!="):
        return _comparison(column, op, value)
    if op == "contains":
        return f"{column} LIKE ? ESCAPE '\\'", [f"%{_escape_like(value)}%"]
    if op == "startswith":
        return f"{column} LIKE ? ESCAPE '\\'", [f"{_escape_like(value)}%"]
    return f"{column} LIKE ? ESCAPE '\\'", [f"%{_escape_like(value)}"]


def _compile_ports(field: _Field, op: str, value: Any) -> tuple[str, list[Any]]:
    if op == "!=":
        sql, params = "NOT (src_port = ? OR dst_port = ?)", [value, value]
    elif op == "==":
        sql, params = "(src_port = ? OR dst_port = ?)", [value, value]
    elif op in _SQL_OPS:
        sql, params = (
            f"(src_port {_SQL_OPS[op]} ? OR dst_port {_SQL_OPS[op]} ?)",
            [value, value],
        )
    else:
        raise FilterSyntaxError(f"operator {op!r} is not valid for a port field")
    if field.protocol:
        return f"(protocol = ? AND {sql})", [field.protocol, *params]
    return sql, params


def _comparison(column: str, op: str, value: Any) -> tuple[str, list[Any]]:
    return f"{column} {_SQL_OPS[op]} ?", [value]


def _coerce(value: Any, field: _Field, name: str) -> Any:
    if field.kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise FilterSyntaxError(f"field {name!r} expects a number")
        if isinstance(value, str):
            try:
                value = float(value) if "." in value else int(value)
            except ValueError as exc:
                raise FilterSyntaxError(
                    f"field {name!r} expects a number, got {value!r}"
                ) from exc
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value
    return str(value)


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
