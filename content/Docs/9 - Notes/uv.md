+++
title = "uv"
+++

* https://github.com/astral-sh/uv
* Reference: https://0xdf.gitlab.io/cheatsheets/uv

Modern replacement for `pip`, `pipx`, `venv`, `virtualenv`, `poetry`. Handles tool installation, script execution with inline dependencies, and Python version management.

## Installation

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh && curl -LsSf https://astral.sh/uv/install.sh | sudo sh
````

## Python Version

```bash
# Specify Python version for any uv command
uv <COMMAND> --python <VERSION>
```

## Tool Installation

### Install from PyPI

```bash
uv tool install <PACKAGE>
# Install from Github
uv tool install git+<REPO_URL>
uv tool install git+<REPO_URL>@<BRANCH>
# Install from dir (git clone)
uv tool install .
```

### List Installed Tools

```bash
uv tool list
```

### Update Tools

```bash
# Update specific tool
uv tool upgrade <PACKAGE>

# Update all
uv tool upgrade --all
```

### Inject Missing Dependency

```bash
uv tool install --with <MISSING_PACKAGE> <PACKAGE>
```

## Scripts (PEP 723 Inline Dependencies)

Run scripts with their requirements declared inline. Sometimes, tools don't declare their dependencies well.

### Add Single Dependency

```bash
uv add --script <SCRIPT> <PACKAGE>
```

### Add from requirements.txt

```bash
uv add --script <SCRIPT> -r <REQUIREMENTS_FILE>
```

### Run Script

```bash
uv run <SCRIPT>
```

## REPL with Dependencies

```bash
uv run --with <PACKAGE> --python <VERSION> python
```
