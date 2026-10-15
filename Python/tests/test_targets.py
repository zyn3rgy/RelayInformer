import tempfile
import unittest
from pathlib import Path

import typer

from relayinformer.targets import parse_targets


class ParseTargetsTests(unittest.TestCase):
    def test_single_target(self):
        self.assertEqual(parse_targets("192.168.1.10"), ["192.168.1.10"])

    def test_comma_separated_targets(self):
        self.assertEqual(
            parse_targets("192.168.1.10, sql01.domain.local,,192.168.1.11"),
            ["192.168.1.10", "sql01.domain.local", "192.168.1.11"],
        )

    def test_targets_file_skips_blank_lines_and_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text("# servers\n192.168.1.10\n\n  sql01.domain.local  \n")

            self.assertEqual(
                parse_targets(str(path)),
                ["192.168.1.10", "sql01.domain.local"],
            )

    def test_empty_targets_file_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "targets.txt"
            path.write_text("# nothing here\n\n")

            with self.assertRaises(typer.Exit):
                parse_targets(str(path))

    def test_directory_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(typer.Exit):
                parse_targets(tmp)

    def test_empty_comma_list_exits(self):
        with self.assertRaises(typer.Exit):
            parse_targets(" , ")


if __name__ == "__main__":
    unittest.main()
