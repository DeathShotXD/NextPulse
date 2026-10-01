# Contributing

Thanks for wanting to help. A few ground rules keep the project clean.

## Commits

- one change per commit, present tense: "add ...", "fix ...", "docs ..."
- keep the subject under 72 characters, no trailing period
- do not mix a refactor with a behaviour change

## Checks

```
python3 -m py_compile nextpulse.py
python3 -m unittest discover -s tests
```

## Style

- plain ASCII in code, comments, and documents
- Python 3.10 or later, standard library unless a dependency earns its place
- keep the framework to the WebSocket Upgrade SSRF path; do not widen scope
  without a clear reason
- never print or store a real credential in full
