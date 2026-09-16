# MicroShield Polyglot Root Makefile
# Orchestrates C99 bare-metal edge firmware and Python MLOps supervisory tier

.PHONY: all test test-c test-py typecheck clean

all: test

# 1. Edge C99 Verification Suite
test-c:
	@echo "=== [1/3] Running Bare-Metal C99 Edge Test Suite ==="
	$(MAKE) -C edge test

# 2. Supervisory Python Test Suite (inside Poetry virtual environment)
test-py:
	@echo "=== [2/3] Running Python Supervisory Test Suite ==="
	cd supervisor && poetry run pytest -v tests/

# 3. Static Type Verification (strict mode PEP 484/526)
typecheck:
	@echo "=== [3/3] Running Strict Static Typecheck (mypy) ==="
	cd supervisor && poetry run mypy --strict dashield/ tests/

# Universal Regression Gate
test: test-c test-py typecheck
	@echo ""
	@echo "============================================================"
	@echo "  ALL MICROSHIELD TESTS & STATIC GATES PASSED (C99 + PYTHON)"
	@echo "============================================================"

clean:
	$(MAKE) -C edge clean
	rm -rf supervisor/.pytest_cache supervisor/.mypy_cache
