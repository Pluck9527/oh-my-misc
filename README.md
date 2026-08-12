# oh-my-misc

A native, extensible CLI toolkit for CTF Misc analysis and forensics.

`oh-my-misc` provides deterministic file inspection, image analysis and artifact extraction with both human-readable and stable JSON output. It runs directly on Python without requiring Docker.

## Install for development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Current CLI

```bash
omm --version
omm inspect challenge.png
omm inspect challenge.png --json
python -m oh_my_misc inspect challenge.png --json
```

## Planned commands

```text
omm inspect FILE
omm image analyze FILE [--quick|--full]
omm image planes FILE
omm image lsb scan|extract FILE
omm image frames FILE
omm image repair FILE
omm image carve FILE
```

## Design principles

- Native installation; no Docker runtime requirement.
- Stable JSON for agents and readable terminal output for humans.
- Deterministic, bounded analysis with explicit evidence and artifacts.
- Independent implementations informed by format specifications and public test vectors.
- Extensible analyzers for images, audio, archives, traffic and documents.

## License

GPL-3.0-only.
