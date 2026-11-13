# Feedback task starting environment

Upstream: https://github.com/dajiaji/python-cwt
Upstream commit: `63a29d31b7e2ebdf9f9fb658f6372f3247ad9ca4`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests
```

Scope note: Complete offline upstream test scope specified by argv.

Observed baseline (2026-11-13): `1544 passed in 4.49s`
Whole-command wall time: 4.852 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
