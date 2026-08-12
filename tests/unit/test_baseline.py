from __future__ import annotations

import contextlib
import io
import unittest

from oh_my_misc.cli import main


class BaselineCliTest(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_context:
            main(["--version"])
        self.assertEqual(exit_context.exception.code, 0)
        self.assertEqual(output.getvalue(), "omm 0.1.0\n")


if __name__ == "__main__":
    unittest.main()
