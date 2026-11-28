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


# The nine constructors as fb5e495 had them, before gen_compact.py put a space after the mnemonic.
BEFORE_THE_FIX = [
    ':ADDAW^CUnitDB15^" B15, "^Cucst5d^", "^RA97 is c_is16=1 { }',
    ':ADDAW^CUnitD^" B15, "^Cucst5p^", B15" is c_is16=1 { }',
    ':SUBAW^CUnitD^" B15, "^Cucst5p^", B15" is c_is16=1 { }',
    ':SUB^CUnitL^" 0, "^RA97^", "^RB97 is c_is16=1 { }',
    ':ADD^CUnitL^" -1, "^RA97^", "^RB97 is c_is16=1 { }',
    ':SUB^CUnitS^" 0, "^RA97^", "^RB97 is c_is16=1 { }',
    ':ADD^CUnitS^" -1, "^RA97^", "^RB97 is c_is16=1 { }',
    ':MVK^CUnitLSD^" 0, "^RA97 is c_is16=1 { }',
    ':MVK^CUnitLSD^" 1, "^RA97 is c_is16=1 { }',
]


def offenders_in(lines):
    sample = LANGUAGES.parent.parent / "tests" / "_mnemonic_sample.sinc"
    try:
        sample.write_text("\n".join(lines) + "\n")
        return offenders([sample])
    finally:
        sample.unlink(missing_ok=True)


class SleighMnemonicsTest(unittest.TestCase):
    def test_no_operand_text_in_mnemonics(self):
        paths = sorted(LANGUAGES.glob("*.sinc")) + sorted(LANGUAGES.glob("*.slaspec"))
        self.assertTrue(paths)
        self.assertEqual(offenders(paths), [])

    def test_detects_joined_operands(self):
        self.assertEqual(len(offenders_in([':MVK^CUnitLSD^" 0, "^RA97 is c_is16=1 { }',
                                           ':MVK^CUnitLSD "0, "^RA97 is c_is16=1 { }'])), 1)

    def test_detects_the_nine_before_the_fix(self):
        self.assertEqual(len(offenders_in(BEFORE_THE_FIX)), 9)

    @unittest.expectedFailure
    def test_before_the_fix_is_rejected(self):
        # Must fail: the constructors before the fix print operand text in their mnemonics. If it
        # passes, the check has gone blind, and unittest reports an unexpected success.
        self.assertEqual(offenders_in(BEFORE_THE_FIX), [])


if __name__ == "__main__":
    unittest.main()
