[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "agentic-iam"
version = "1.0.0"
description = "Comprehensive Agent Identity & Access Management Platform"
readme = "README.md"
requires-python = ">=3.9"
license = {text = "MIT"}
authors = [
    {name = "Agentic-IAM Team", email = "team@agentic-iam.com"},
]
keywords = ["identity", "access-management", "agents", "security", "authentication", "authorization"]
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Topic :: Security",
    "Topic :: System :: Systems Administration :: Authentication/Directory",
    "Topic :: Software Development :: Libraries :: Python Modules",
]

dependencies = [
    "cryptography>=41.0.0",
    "PyJWT>=2.8.0",
    "requests>=2.31.0",
    "pydantic>=2.0.0",
    "pydantic-settings>=2.0.0",
    "python-dotenv>=1.0.0",
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "python-multipart>=0.0.6",
    "jinja2>=3.1.0",
    "SQLAlchemy>=2.0.0",
    "aiosqlite>=0.19.0",
    "redis>=4.5.0",
    "numpy>=1.24.0",
    "pandas>=2.0.0",
    "python-dateutil>=2.8.0",
    "streamlit>=1.28.0",
    "plotly>=5.15.0",
    "streamlit-authenticator>=0.2.3",
    "streamlit-option-menu>=0.3.6",
    "nest-asyncio>=1.5.8",
    "python-jose[cryptography]>=3.3.0",
    "passlib[bcrypt]>=1.7.4",
    "httpx>=0.25.0",
    "prometheus-client>=0.17.0",
    "structlog>=23.1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.11.0",
    "pytest-xdist>=3.3.0",
    "pytest-timeout>=2.1.0",
    "black>=23.0.0",
    "flake8>=6.0.0",
    "mypy>=1.4.0",
    "isort>=5.12.0",
    "pre-commit>=3.0.0",
    "safety>=2.3.0",
    "bandit>=1.7.0",
]

database = [
    "psycopg2-binary>=2.9.0",
    "mysql-connector-python>=8.0.33",
    "pymongo>=4.5.0",
    "asyncpg>=0.28.0",
    "aiomysql>=0.2.0",
    "motor>=3.0.0",
]

ml = [
    "scikit-learn>=1.3.0",
    "tensorflow>=2.13.0",
    "torch>=2.0.0",
    "transformers>=4.21.0",
    "numpy>=1.24.0",
]

security = [
    "python3-saml>=1.15.0",
    "keyring>=24.0.0",
    "cryptography>=41.0.0",
]

monitoring = [
    "prometheus-client>=0.17.0",
    "grafana-api>=1.0.3",
    "elasticsearch>=8.0.0",
    "jaeger-client>=4.8.0",
]

cloud = [
    "boto3>=1.28.0",
    "azure-identity>=1.14.0",
    "google-cloud-core>=2.3.0",
    "kubernetes>=27.2.0",
]

deployment = [
    "gunicorn>=21.0.0",
    "gevent>=23.0.0",
    "docker>=6.1.0",
]

docs = [
    "sphinx>=7.0.0",
    "sphinx-rtd-theme>=1.3.0",
    "mkdocs>=1.5.0",
    "mkdocs-material>=9.0.0",
]

all = [
    "agentic-iam[dev,database,ml,security,monitoring,cloud,deployment,docs]"
]

[project.urls]
Homepage = "https://github.com/your-org/agentic-iam-python"
Documentation = "https://docs.agentic-iam.com"
Repository = "https://github.com/your-org/agentic-iam-python"
Issues = "https://github.com/your-org/agentic-iam-python/issues"
Changelog = "https://github.com/your-org/agentic-iam-python/blob/main/CHANGELOG.md"

[project.scripts]
agentic-iam = "main:main"
agentic-iam-migrate = "scripts.migrate:main"
agentic-iam-admin = "scripts.admin:main"

[tool.setuptools]
package-dir = {"" = "."}

[tool.setuptools.packages.find]
where = ["."]
include = ["core*", "api*", "dashboard*", "config*", "utils*", "scripts*"]
exclude = ["tests*", "docs*", "htmlcov*", ".github*"]

# Black configuration
[tool.black]
line-length = 100
target-version = ['py39', 'py310', 'py311']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | build
  | dist
  | migrations
)/
'''

# isort configuration
[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 100
known_first_party = ["core", "api", "dashboard", "config", "utils", "scripts"]
known_third_party = ["fastapi", "pydantic", "sqlalchemy", "redis", "streamlit"]
sections = ["FUTURE", "STDLIB", "THIRDPARTY", "FIRSTPARTY", "LOCALFOLDER"]

# MyPy configuration
[tool.mypy]
python_version = "3.9"
warn_return_any = true
warn_unused_configs = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true
no_implicit_optional = true
disallow_untyped_defs = false
disallow_incomplete_defs = false
check_untyped_defs = true
disallow_untyped_decorators = false
ignore_missing_imports = true
show_error_codes = true

[[tool.mypy.overrides]]
module = [
    "tests.*",
    "conftest",
]
ignore_errors = true

# Flake8 configuration (in setup.cfg since flake8 doesn't support pyproject.toml)
[tool.flake8]
max-line-length = 100
extend-ignore = [
    "E203",  # whitespace before ':'
    "W503",  # line break before binary operator
    "E501",  # line too long (handled by black)
]
exclude = [
    ".git",
    "__pycache__",
    "build",
    "dist",
    ".venv",
    ".env",
    "migrations",
]
per-file-ignores = [
    "__init__.py:F401",
    "tests/*:S101",
]

# Bandit configuration
[tool.bandit]
exclude_dirs = ["tests", "docs", "scripts"]
skips = ["B101", "B601"]

# Coverage configuration
[tool.coverage.run]
source = ["core", "api", "dashboard"]
omit = [
    "*/tests/*",
    "*/venv/*",
    "*/env/*",
    "*/__pycache__/*",
    "*/migrations/*",
    "*/scripts/*",
    "conftest.py",
    "setup.py",
]
branch = true

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "if self.debug:",
    "if settings.DEBUG",
    "raise AssertionError",
    "raise NotImplementedError",
    "if 0:",
    "if __name__ == .__main__.:",
    "class .*\\bProtocol\\):",
    "@(abc\\.)?abstractmethod",
]
ignore_errors = true
show_missing = true
skip_covered = false

[tool.coverage.html]
directory = "htmlcov"

[tool.coverage.xml]
output = "coverage.xml"