# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""The RemoteRF labelled panel, matching the client's banner frame.

    ╭─ LABEL ──────────────────────────╮
    │ text                             │
    ╰──────────────────────────────────╯

Same glyphs and same ASCII fallback as the client banner, so a server console
and a client session look like one product. Unlike the client's fixed-width
info card, the width here follows the content: these panels wrap prose.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap

MIN_CONTENT_WIDTH = 24
MAX_CONTENT_WIDTH = 72
# Indent at or beyond this is preformatted and never reflowed.
PREFORMATTED_INDENT = 4
MARKER = "◆"  # the client's bullet
ASCII_MARKER = "*"


def supports_unicode(encoding: str | None = None) -> bool:
    """Whether the output encoding can represent the rounded frame."""
    if os.environ.get("REMOTERF_ASCII", "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        return False
    encoding = encoding or getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "╭─╮│╰╯◆".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def marker(unicode_supported: bool | None = None) -> str:
    if unicode_supported is None:
        unicode_supported = supports_unicode()
    return MARKER if unicode_supported else ASCII_MARKER


def _terminal_columns() -> int:
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except OSError:
        return 80


def panel_lines(
    label: str,
    lines,
    *,
    unicode_supported: bool | None = None,
    literal: bool = False,
    max_width: int | None = MAX_CONTENT_WIDTH,
) -> list[str]:
    """Render one labelled panel around `lines`, returned without a trailing newline.

    `literal` turns off paragraph reflow for callers passing rows that are
    already laid out -- a field table, for instance, where every line break
    and every column of padding is deliberate.
    """
    if unicode_supported is None:
        unicode_supported = supports_unicode()
    horizontal = "─" if unicode_supported else "-"
    vertical = "│" if unicode_supported else "|"
    top_left, top_right = ("╭", "╮") if unicode_supported else ("+", "+")
    bottom_left, bottom_right = ("╰", "╯") if unicode_supported else ("+", "+")

    label_text = f"{horizontal} {label.strip().upper()} " if label else horizontal
    # Room for the frame and one space of padding either side. Prose stops at
    # MAX_CONTENT_WIDTH for readability; a table (max_width=None) may use the
    # whole terminal.
    target = _terminal_columns() - 4
    if max_width is not None:
        target = min(max_width, target)
    target = max(MIN_CONTENT_WIDTH, target)
    # Reflow rather than clip: a panel carries consent and licence text, so
    # dropping the end of a sentence is not an acceptable way to make it fit.
    # Consecutive lines at the same indent are one paragraph and rewrap
    # together, which keeps the source free to be hard-wrapped for readability.
    body: list[str] = []
    paragraph: list[str] = []
    indent = ""

    def flush() -> None:
        if not paragraph:
            return
        pieces = textwrap.wrap(
            " ".join(paragraph), width=max(1, target - len(indent))
        )
        body.extend(indent + piece for piece in pieces or [""])
        paragraph.clear()

    for raw in lines:
        line = str(raw).replace("\t", "    ").rstrip()
        if not line.strip():
            flush()
            body.append("")
            continue
        line_indent = line[: len(line) - len(line.lstrip())]
        if literal or len(line_indent) >= PREFORMATTED_INDENT:
            # Deeply indented lines are preformatted -- commands, samples,
            # anything where the line break is the point. Same rule as
            # Markdown, so it needs no explanation at the call site.
            flush()
            body.append(line)
            continue
        if paragraph and line_indent != indent:
            flush()
        indent = line_indent
        paragraph.append(line.strip())
    flush()
    while body and not body[-1]:
        body.pop()
    widest = max([len(label_text), *(len(line) for line in body)] or [0])
    content_width = max(MIN_CONTENT_WIDTH, min(widest, target))

    inner = content_width + 2
    # A label longer than the panel would push the top border past every other
    # row, so it is clipped to the frame rather than widening it.
    label_text = label_text[:inner]
    top = top_left + label_text + horizontal * (inner - len(label_text)) + top_right
    rendered = [
        f"{vertical} {line[:content_width]:<{content_width}} {vertical}" for line in body
    ]
    bottom = bottom_left + horizontal * inner + bottom_right
    return [top, *rendered, bottom]


def print_panel(
    label: str,
    text,
    *,
    style=None,
    literal: bool = False,
    max_width: int | None = MAX_CONTENT_WIDTH,
) -> None:
    """Print a labelled panel. `text` may be a string block or a line iterable."""
    if isinstance(text, str):
        text = text.strip("\n").splitlines()
    lines = panel_lines(label, text, literal=literal, max_width=max_width)
    try:
        from .ansi_codes import Sty, printf
    except Exception:  # noqa: BLE001 - styling is never worth failing a prompt
        print("\n".join(lines))
        return
    for index, line in enumerate(lines):
        if index in (0, len(lines) - 1):
            printf(line, style or Sty.DEFAULT)
        else:
            printf(line[0], style or Sty.DEFAULT,
                   line[1:-1], Sty.GRAY,
                   line[-1], style or Sty.DEFAULT)


def confirm(question: str, *, default: bool | None = None, ask=None) -> bool | None:
    """One consistent yes/no prompt for the whole server.

    The default, if any, is shown by capitalising it -- `(y/N)` -- and both the
    short and long spellings are accepted. Returns None if the operator aborts.
    """
    # Resolved per call, not bound at definition: a caller (or a test) that
    # replaces builtins.input must actually be seen.
    ask = ask or input
    hint = {True: "(Y/n)", False: "(y/N)", None: "(y/n)"}[default]
    while True:
        try:
            answer = ask(f"  {question} {hint}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if not answer and default is not None:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("  Please answer y or n.")


# -----------------------------
# Lists
# -----------------------------

def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def table_lines(rows, columns, *, width: int) -> list[str]:
    """Rows of a list as panel content: a table when it fits in `width`,
    otherwise one card per record so nothing is clipped on a narrow console.

    `rows` are dicts; `columns` is the display order. A column that is empty
    in every row is dropped -- optional fields should cost nothing when unused.
    """
    cells = [{name: _cell(row.get(name)) for name in columns} for row in rows]
    columns = [name for name in columns if any(row[name] for row in cells)]
    if not columns:
        return []
    widths = {name: max(len(name), *(len(row[name]) for row in cells)) for name in columns}
    if sum(widths.values()) + 2 * (len(columns) - 1) <= width:
        out = [
            "  ".join(name.ljust(widths[name]) for name in columns),
            "  ".join("-" * widths[name] for name in columns),
        ]
        out += ["  ".join(row[name].ljust(widths[name]) for name in columns) for row in cells]
        return out
    # Card layout: every value gets the full width, long ones wrap.
    key_width = max(len(name) for name in columns)
    value_width = max(8, width - key_width - 2)
    out = []
    for row in cells:
        if out:
            out.append("")
        for name in columns:
            pieces = textwrap.wrap(row[name], width=value_width) or [""]
            out.append(f"{name:<{key_width}}  {pieces[0]}")
            out += [" " * (key_width + 2) + piece for piece in pieces[1:]]
    return out


def content_width() -> int:
    """Widest content a full-terminal panel can carry right now."""
    return max(MIN_CONTENT_WIDTH, _terminal_columns() - 4)


def print_table(label: str, rows, columns, *, empty: str = "(none)") -> None:
    """Print a list of records in a labelled panel; see `table_lines`."""
    width = content_width()
    body = table_lines(list(rows), list(columns), width=width) or [empty]
    print(flush=True)
    print_panel(label, body, literal=True, max_width=None)
    print(flush=True)
