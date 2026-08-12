# Contributing

Use Python 3.11 or newer. Keep analyzers deterministic, bounded and independently testable. Every new analyzer must include positive, negative and malformed-input tests, a stable JSON result, and a documented success criterion.

```bash
python -m unittest discover -s tests -v
ruff check src tests
```
