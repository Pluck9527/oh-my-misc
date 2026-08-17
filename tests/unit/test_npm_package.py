from __future__ import annotations

import json
from pathlib import Path

from oh_my_misc import __version__

ROOT = Path(__file__).resolve().parents[2]


def test_npm_package_metadata_matches_python_project() -> None:
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))

    assert package["name"] == "oh-my-misc"
    assert package["version"] == __version__
    assert package["bin"] == {
        "omm": "bin/omm.js",
        "oh-my-misc": "bin/omm.js",
    }
    assert package["license"] == "GPL-3.0-only"


def test_npm_package_includes_python_project_files() -> None:
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))

    assert "bin/" in package["files"]
    assert "src/" in package["files"]
    assert "pyproject.toml" in package["files"]
    assert "README.md" in package["files"]
    assert "LICENSE" in package["files"]


def test_npm_launcher_is_executable_node_script() -> None:
    launcher = ROOT / "bin" / "omm.js"
    text = launcher.read_text(encoding="utf-8")

    assert text.startswith("#!/usr/bin/env node")
    assert "python3.11" in text
    assert '"-m", "oh_my_misc"' in text
