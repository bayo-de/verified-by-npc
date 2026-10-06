"""Minimal YAML-subset parser (stdlib only).

Handles exactly the YAML style used by this package's specs:
2-space-indented block mappings and lists, `- ` list items, nested
mappings/lists, `|` and `>` block scalars, single/double-quoted and plain
scalars, and inline flow collections (`[a, b]`, `{a: b}`).

It is NOT a general YAML parser. Anything outside the subset raises
YAMLError, which is itself a useful validity signal: the specs in this
package must stay within the subset so the stdlib validator can read them.
"""
import re


class YAMLError(Exception):
    pass


def _strip_comment(line):
    out = []
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            out.append(c)
            if c == quote:
                quote = None
            i += 1
        elif c in ("'", '"'):
            quote = c
            out.append(c)
            i += 1
        elif c == '#':
            break
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _flow_scalar(text):
    """Parse a scalar or inline flow collection."""
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [] if not inner else [_scalar(p) for p in _split_flow(inner)]
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        result = {}
        if inner:
            for part in _split_flow(inner):
                k, _, v = part.partition(":")
                result[_scalar(k)] = _scalar(v)
        return result
    return _scalar(text)


def _bracket_depth(text):
    depth, quote = 0, None
    for c in text:
        if quote:
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
    return depth


def _split_flow(text):
    parts, depth, quote, cur = [], 0, None, []
    for c in text:
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
            cur.append(c)
        elif c in "[{":
            depth += 1
            cur.append(c)
        elif c in "]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return parts


def _scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    low = text.lower()
    if low in ("null", "~", ""):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


class _Parser:
    def __init__(self, text):
        self.lines = []
        for raw in text.splitlines():
            if "\t" in raw:
                raise YAMLError("tabs are not allowed")
            stripped = _strip_comment(raw)
            if not stripped.strip():
                continue
            indent = len(stripped) - len(stripped.lstrip(" "))
            self.lines.append((indent, stripped.strip()))
        self.pos = 0

    def parse(self):
        if not self.lines:
            return None
        value = self._block(self.lines[0][0])
        if self.pos != len(self.lines):
            raise YAMLError("trailing content after document")
        return value

    def _block(self, indent):
        if self.pos >= len(self.lines):
            raise YAMLError("unexpected end of document")
        ind, text = self.lines[self.pos]
        if ind != indent:
            raise YAMLError(f"bad indent: expected {indent}, got {ind}")
        if text == "-" or text.startswith("- "):
            return self._list(indent)
        return self._map(indent)

    def _value(self, indent, rest):
        """Resolve a mapping/list value, joining multi-line flow collections."""
        if (rest.startswith("[") or rest.startswith("{")) \
                and _bracket_depth(rest) > 0:
            rest = self._finish_flow(indent, rest)
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            return self._block_scalar(indent, rest[0])
        if rest == "":
            return self._nested(indent)
        return _flow_scalar(rest)

    def _finish_flow(self, indent, rest):
        while _bracket_depth(rest) > 0 and self.pos < len(self.lines):
            ind, text = self.lines[self.pos]
            if ind <= indent:
                raise YAMLError("unbalanced flow collection")
            rest += " " + text
            self.pos += 1
        if _bracket_depth(rest) != 0:
            raise YAMLError("unbalanced flow collection")
        return rest

    def _map(self, indent):
        result = {}
        while self.pos < len(self.lines):
            ind, text = self.lines[self.pos]
            if ind != indent:
                break
            if text == "-" or text.startswith("- "):
                raise YAMLError("list item inside mapping")
            key, sep, rest = text.partition(":")
            if not sep:
                raise YAMLError(f"expected 'key: value', got {text!r}")
            key = _scalar(key)
            rest = rest.strip()
            self.pos += 1
            result[key] = self._value(indent, rest)
        return result

    def _list(self, indent):
        result = []
        while self.pos < len(self.lines):
            ind, text = self.lines[self.pos]
            if ind != indent:
                break
            if not (text == "-" or text.startswith("- ")):
                break
            item = text[1:].strip()
            self.pos += 1
            if item == "":
                result.append(self._nested(indent))
            elif item.startswith(("[", "{")):
                # bare flow collection as a list item
                result.append(self._value(indent, item))
            elif re.match(r"^[^\s:]+:(\s|$)", item) or ": " in item:
                # list item that is a mapping: "- key: value"
                key, _, rest = item.partition(":")
                sub = { _scalar(key): None }
                rest = rest.strip()
                if rest in ("|", ">"):
                    sub[_scalar(key)] = self._block_scalar(indent + 2, rest[0])
                elif rest == "":
                    sub[_scalar(key)] = self._nested(indent)
                else:
                    sub[_scalar(key)] = self._value(indent, rest)
                # continuation lines of the same mapping
                while self.pos < len(self.lines):
                    ind2, text2 = self.lines[self.pos]
                    if ind2 <= indent or (text2 == "-" or text2.startswith("- ")):
                        break
                    k2, sep2, r2 = text2.partition(":")
                    if not sep2:
                        raise YAMLError(f"expected 'key: value', got {text2!r}")
                    r2 = r2.strip()
                    self.pos += 1
                    if r2 in ("|", ">"):
                        sub[_scalar(k2)] = self._block_scalar(ind2, r2[0])
                    else:
                        sub[_scalar(k2)] = self._value(ind2, r2)
                result.append(sub)
            else:
                result.append(_flow_scalar(item))
        return result

    def _nested(self, indent):
        if self.pos >= len(self.lines):
            return None
        ind, _ = self.lines[self.pos]
        if ind <= indent:
            return None
        return self._block(ind)

    def _block_scalar(self, indent, style):
        chunks = []
        first_indent = None
        while self.pos < len(self.lines):
            ind, text = self.lines[self.pos]
            if ind <= indent:
                break
            if first_indent is None:
                first_indent = ind
            chunks.append(" " * (ind - first_indent) + text)
            self.pos += 1
        if style == "|":
            return "\n".join(chunks) + ("\n" if chunks else "")
        # folded: join lines with spaces, keep blank-line paragraph breaks
        out, para = [], []
        for c in chunks:
            if c.strip():
                para.append(c.strip())
            else:
                if para:
                    out.append(" ".join(para))
                    para = []
                out.append("")
        if para:
            out.append(" ".join(para))
        return "\n".join(out)


def parse(text):
    """Parse restricted-subset YAML. Raises YAMLError on anything else."""
    return _Parser(text).parse()
