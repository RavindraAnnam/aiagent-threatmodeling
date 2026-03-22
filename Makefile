install:
	pip install -e .[dev]

test:
	pytest -q

lint:
	ruff check src tests examples

run-demo:
	agent-threatlab run-suite scenarios/
