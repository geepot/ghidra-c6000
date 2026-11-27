# SPDX-License-Identifier: Apache-2.0
"""No constructor may print operand text inside its mnemonic.

Ghidra takes a constructor's display up to the first unquoted space as the mnemonic. A display
that joins its operands to the mnemonic with ^ (":MVK^CUnitLSD^\" 0, \"^RA97") makes the operands
part of it, so instructions of one prototype print different mnemonics. C6000CallAnalyzer.mnemonic()
keeps one mnemonic per prototype and relies on that not happening.
"""
from pathlib import Path
import re
import unittest

LANGUAGES = Path(__file__).resolve().parents[1] / "data" / "languages"


def mnemonic_spec(line):
    """The mnemonic part of a constructor's display: up to the first unquoted space."""
    display = line[1:line.index(" is ")] if " is " in line else line[1:]
    quoted = False
    for i, ch in enumerate(display):
        if ch == '"':
            quoted = not quoted
        elif ch == " " and not quoted:
            return display[:i]
    return display


def offenders(paths):
    found = []
    for path in paths:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.startswith(":"):
                continue
            literals = re.findall(r'"([^"]*)"', mnemonic_spec(line))
            if any(" " in text or "," in text for text in literals):
                found.append(f"{path.name}:{number}: {line[:80]}")
    return found


class SleighMnemonicsTest(unittest.TestCase):
    def test_no_operand_text_in_mnemonics(self):
        paths = sorted(LANGUAGES.glob("*.sinc")) + sorted(LANGUAGES.glob("*.slaspec"))
        self.assertTrue(paths)
        self.assertEqual(offenders(paths), [])

    def test_detects_joined_operands(self):
        sample = LANGUAGES.parent.parent / "tests" / "_mnemonic_sample.sinc"
        try:
            sample.write_text(':MVK^CUnitLSD^" 0, "^RA97 is c_is16=1 { }\n'
                              ':MVK^CUnitLSD "0, "^RA97 is c_is16=1 { }\n')
            self.assertEqual(len(offenders([sample])), 1)
        finally:
            sample.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
