# Contributing

## Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates
```bash
make lint
make test
```

## Pull requests
- Keep changes small and focused.
- Add tests for behavioral changes.
- Avoid introducing new network dependencies unless necessary.
