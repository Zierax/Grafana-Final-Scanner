#!/usr/bin/env make
# Grafana Final Scanner - Development Makefile
# ==============================================
# Targets:
#   help        - Show this help message
#   install     - Install production dependencies
#   install-dev - Install all dependencies (including dev)
#   test        - Run test suite with coverage
#   lint        - Run flake8 linting
#   lint-ruff   - Run ruff linting (faster alternative)
#   check       - Run lint + test
#   clean       - Remove build artifacts and cache
#   dist        - Build source and wheel distribution
#   docker      - Build Docker image
#   format      - Auto-format code with ruff
#   security    - Run basic security checks
#   coverage-html - Generate HTML coverage report

.PHONY: help install install-dev test lint lint-ruff check clean dist docker format security coverage-html

VENV_DIR = .venv
PYTHON = python3
PIP = pip3
INSTALL_FLAGS = --break-system-packages

help:
	@echo "Grafana Final Scanner - Development Help"
	@echo "========================================"
	@echo ""
	@sed -n '/^# Targets:/,/^$$/ p' Makefile | head -n -1 | tail -n +3 | sed 's/^#   /  /'

install:
	$(PIP) install $(INSTALL_FLAGS) -r requirements.txt

install-dev:
	$(PIP) install $(INSTALL_FLAGS) -r requirements.txt
	$(PIP) install $(INSTALL_FLAGS) pytest pytest-cov flake8 ruff

test:
	$(PYTHON) -m pytest tests/ -v --cov=scanner --cov-report=term-missing --cov-fail-under=56

lint:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics --exclude=.git,__pycache__,tests/,venv,.venv
	flake8 . --count --exit-zero --max-complexity=12 --max-line-length=127 --statistics --exclude=.git,__pycache__,tests/,venv,.venv

lint-ruff:
	ruff check . --exclude=.git,__pycache__,tests/,venv,.venv

check: lint test

clean:
	rm -rf __pycache__ .pytest_cache .ruff_cache .mypy_cache
	rm -rf *.egg-info dist build
	rm -rf htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.~" -delete
	@echo "✓ Cleanup complete"

dist: clean
	$(PYTHON) -m build

docker:
	docker build -t grafana-scanner:latest .

format:
	ruff check --fix --exclude=.git,__pycache__,tests/,venv,.venv . || true
	ruff format --exclude=.git,__pycache__,tests/,venv,.venv . || true

security:
	$(PYTHON) -c "from scanner import GrafanafinalScanner; print('✓ Import check passed')"
	$(PYTHON) -c "
import ast
import glob
files = glob.glob('**/*.py', recursive=True)
errors = []
for f in files:
    try:
        ast.parse(open(f).read())
    except SyntaxError as e:
        errors.append(f'{f}: {e}')
if errors:
    print('ERROR: Syntax errors found:')
    for e in errors:
        print(f'  {e}')
else:
    print(f'✓ All {len(files)} Python files have valid syntax')
"

coverage-html:
	$(PYTHON) -m pytest tests/ --cov=scanner --cov-report=html
	@echo "✓ HTML coverage report generated in htmlcov/"
