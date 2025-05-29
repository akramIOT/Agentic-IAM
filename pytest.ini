[tool:pytest]
# Pytest configuration for Agentic-IAM

# Test discovery
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*

# Minimum version
minversion = 7.0

# Add options
addopts = 
    --strict-markers
    --strict-config
    --verbose
    --tb=short
    --cov-report=term-missing
    --cov-report=html:htmlcov
    --cov-report=xml
    --cov-branch
    --cov-fail-under=80
    --durations=10
    --maxfail=5

# Test markers
markers =
    unit: Unit tests
    integration: Integration tests
    api: API endpoint tests
    security: Security-related tests
    slow: Slow running tests
    asyncio: Async tests
    database: Database tests
    redis: Redis tests
    performance: Performance tests
    smoke: Smoke tests

# Asyncio configuration
asyncio_mode = auto

# Filterwarnings
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
    ignore:.*cryptography.*:UserWarning

# Test timeout
timeout = 300

# Coverage configuration
[coverage:run]
source = core, api, dashboard
omit = 
    */tests/*
    */venv/*
    */env/*
    */__pycache__/*
    */migrations/*
    */scripts/*
    conftest.py
    setup.py

[coverage:report]
exclude_lines =
    pragma: no cover
    def __repr__
    if self.debug:
    if settings.DEBUG
    raise AssertionError
    raise NotImplementedError
    if 0:
    if __name__ == .__main__.:
    class .*\bProtocol\):
    @(abc\.)?abstractmethod

[coverage:html]
directory = htmlcov

[coverage:xml]
output = coverage.xml