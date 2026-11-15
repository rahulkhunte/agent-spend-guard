# Each target has a plain `python -m` / `uv run` equivalent (see docs/WALKTHROUGH.md),
# so nothing here is needed on a machine without make.

.PHONY: setup demo mock seed mcp test lint rules evals mutation readme reconcile check

setup:  ## install pinned dependencies into .venv
	uv sync

demo:  ## a narrated end-to-end story in the terminal (no network, no real money)
	uv run python -m demo

mock:  ## run the local mock API on http://127.0.0.1:8787
	uv run python -m mock_api

seed:  ## create an agent and a mandate on the running mock, for the MCP server
	uv run python scripts/seed_mock.py

mcp:  ## run the MCP server on stdio (needs `make mock` and `make seed` first)
	SPEND_GUARD_ENV_FILE=.mock/agent.env uv run python -m mcp_server

test:  ## run the deterministic test suite (no network, no API keys)
	uv run pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

rules:  ## check docs/RULES.md against docs/SPEC.md, the code and the tests
	uv run python scripts/check_rules.py

evals:  ## run the deterministic evals and write EVALS.md (no API key needed)
	uv run python -m evals.report

mutation:  ## break safety-critical lines one at a time; a test must fail each time
	uv run python scripts/mutation_check.py

readme:  ## check that the numbers in README.md match the repo
	uv run python scripts/check_readme.py

reconcile:  ## list provider payments not backed by an allow in the decision log
	uv run python -m spend_guard.reconcile

check: lint test rules evals mutation readme
