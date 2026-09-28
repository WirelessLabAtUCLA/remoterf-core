"""The shared RemoteRF console panel."""

import unittest
from unittest import mock

from remoteRF_server.common.utils import panel


class PanelTests(unittest.TestCase):
    def render(self, label, lines, **kwargs):
        kwargs.setdefault("unicode_supported", True)
        return panel.panel_lines(label, lines, **kwargs)

    def test_every_row_is_the_same_width(self):
        for label, lines in (
            ("Terms of Service", ["short"]),
            ("", ["a", "b" * 200]),
            ("A label far longer than the panel will ever be allowed to grow", ["x"]),
            ("Empty", []),
        ):
            rows = self.render(label, lines)
            with self.subTest(label=label):
                self.assertEqual(len({len(row) for row in rows}), 1, rows)

    def test_prose_is_reflowed_never_truncated(self):
        sentence = (
            "In return, once a RemoteRF admin approves your request, this "
            "deployment gets a public address name.global.remoterf.net so your "
            "users can reach it from any network."
        )
        rows = self.render("Notice", [sentence])
        body = " ".join(row[1:-1].strip() for row in rows[1:-1])
        # Every word survives, regardless of where the frame had to break.
        self.assertEqual(body.split(), sentence.split())

    def test_hard_wrapped_source_reflows_as_one_paragraph(self):
        rows = self.render("Notice", ["one two", "three four", "", "second para"])
        body = [row[1:-1].strip() for row in rows[1:-1]]
        self.assertEqual(body, ["one two three four", "", "second para"])

    def test_indented_blocks_keep_their_indent(self):
        rows = self.render("Notice", ["intro", "", "  bullet text", "  continues"])
        body = [row[1:-1] for row in rows[1:-1]]
        self.assertTrue(body[2].startswith("   bullet"), body)

    def test_ascii_fallback_uses_plain_glyphs(self):
        rows = self.render("Notice", ["text"], unicode_supported=False)
        self.assertTrue(rows[0].startswith("+-"))
        self.assertNotIn("─", "".join(rows))
        self.assertEqual(len({len(row) for row in rows}), 1)

    def test_ascii_is_forced_by_environment(self):
        with mock.patch.dict("os.environ", {"REMOTERF_ASCII": "1"}):
            self.assertFalse(panel.supports_unicode())
            self.assertEqual(panel.marker(), "*")


class ConfirmTests(unittest.TestCase):
    def ask(self, *replies):
        return mock.Mock(side_effect=replies)

    def test_both_spellings_are_accepted(self):
        for reply in ("y", "yes", "Y", " YES "):
            self.assertTrue(panel.confirm("Go?", ask=self.ask(reply)))
        for reply in ("n", "no", "N", " No "):
            self.assertFalse(panel.confirm("Go?", ask=self.ask(reply)))

    def test_the_default_is_shown_and_applied(self):
        asked = self.ask("")
        self.assertFalse(panel.confirm("Join?", default=False, ask=asked))
        self.assertIn("(y/N)", asked.call_args.args[0])

        asked = self.ask("")
        self.assertTrue(panel.confirm("Keep?", default=True, ask=asked))
        self.assertIn("(Y/n)", asked.call_args.args[0])

    def test_without_a_default_a_bare_enter_reprompts(self):
        asked = self.ask("", "maybe", "y")
        self.assertTrue(panel.confirm("Agree?", ask=asked))
        self.assertIn("(y/n)", asked.call_args.args[0])
        self.assertEqual(asked.call_count, 3)

    def test_aborting_is_distinct_from_answering_no(self):
        self.assertIsNone(panel.confirm("Go?", ask=self.ask(EOFError())))
        self.assertIsNone(panel.confirm("Go?", ask=self.ask(KeyboardInterrupt())))




class PreformattedTests(unittest.TestCase):
    def test_deeply_indented_lines_keep_their_own_breaks(self):
        rows = panel.panel_lines(
            "Notice",
            ["Run one of:", "", "    serverrf global join", "    serverrf global leave"],
            unicode_supported=True,
        )
        body = [row[1:-1].strip() for row in rows[1:-1]]
        self.assertEqual(body[-2:], ["serverrf global join", "serverrf global leave"])



class LiteralRowTests(unittest.TestCase):
    def test_literal_rows_are_not_reflowed_into_a_paragraph(self):
        """A field table's line breaks and padding are the whole point."""
        rows = ["name      ucla", "email     lab@ucla.edu", "tunnel    up"]
        rendered = panel.panel_lines("Status", rows, literal=True, unicode_supported=True)
        body = [line[1:-1].rstrip() for line in rendered[1:-1]]
        self.assertEqual(body, [" " + row for row in rows])

    def test_the_same_rows_would_otherwise_merge(self):
        rows = ["name      ucla", "email     lab@ucla.edu"]
        rendered = panel.panel_lines("Status", rows, unicode_supported=True)
        self.assertEqual(len(rendered), 3)  # one merged line, plus the frame

if __name__ == "__main__":
    unittest.main()


class TableTests(unittest.TestCase):
    ROWS = [
        {"code_name": "RERGSOQ5", "group_id": 1, "uses": 1, "federation_contract_id": None,
         "note": "a fairly long value that has to wrap when the console is narrow"},
    ]
    COLUMNS = ["code_name", "group_id", "uses", "federation_contract_id", "note"]

    def test_wide_console_gets_a_table_without_empty_columns(self):
        from remoteRF_server.common.utils.panel import table_lines

        lines = table_lines(self.ROWS, self.COLUMNS, width=200)
        self.assertEqual(len(lines), 3)  # header, rule, one row
        self.assertNotIn("federation_contract_id", lines[0])
        self.assertTrue(lines[2].startswith("RERGSOQ5"))

    def test_narrow_console_gets_cards_and_wraps_values(self):
        from remoteRF_server.common.utils.panel import table_lines

        lines = table_lines(self.ROWS, self.COLUMNS, width=40)
        self.assertEqual(lines[0], "code_name  RERGSOQ5")
        self.assertTrue(all(len(line) <= 40 for line in lines))
        self.assertGreater(sum(line.startswith("note") or line.startswith("           ") for line in lines), 1)

    def test_nothing_to_show(self):
        from remoteRF_server.common.utils.panel import table_lines

        self.assertEqual(table_lines([], self.COLUMNS, width=80), [])
