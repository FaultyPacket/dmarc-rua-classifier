# Contributing

Thanks for helping. Every message the tool prints cites the RFC section it
relies on; keep it that way. Tests run offline (no live DNS).

```
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt -e .
python -m pytest -q
```

By contributing you agree your contribution is licensed under AGPL-3.0-or-later.
