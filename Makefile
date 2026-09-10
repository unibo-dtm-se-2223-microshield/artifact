.PHONY: help test test-c test-py typecheck lint clean

help:
	@echo "MicroShield Artifact Build System"
	@echo "---------------------------------"
	@echo "make test-c      : Compila ed esegue i test di unità del motore C99"
	@echo "make test-py     : Esegue i test di unità Python con pytest"
	@echo "make typecheck   : Esegue il type checker statico mypy (strict)"
	@echo "make lint        : Verifica la formattazione con flake8 e black"
	@echo "make test        : Esegue tutti i test (C + Python)"
	@echo "make clean       : Pulisce file binari e cache di compilazione"

test-c:
	@$(MAKE) -C edge test

test-py:
	cd supervisor && pytest tests/

typecheck:
	cd supervisor && mypy dashield/

lint:
	cd supervisor && flake8 dashield/ tests/
	cd supervisor && black --check dashield/ tests/

test: test-c test-py typecheck

clean:
	@$(MAKE) -C edge clean || true
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
