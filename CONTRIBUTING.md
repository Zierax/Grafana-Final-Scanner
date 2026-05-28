# How to Contribute

First off, thank you for considering contributing to **Grafana Final Scanner**. Contributions like yours help make security assessment tools more reliable and effective for everyone who uses them responsibly.

This document covers the key guidelines for contributing. Whether you're a first-time contributor or a seasoned open source veteran, you're welcome here.

</br>

## Table of Contents

- [Ways to Contribute](#ways-to-contribute)
  - [Report a Bug](#report-a-bug)
  - [Suggest an Enhancement](#suggest-an-enhancement)
  - [Contribute Code](#contribute-code)
- [Getting Started](#getting-started)
  - [Local Development Setup](#local-development-setup)
  - [Branching Strategy](#branching-strategy)
  - [Writing Commit Messages](#writing-commit-messages)
  - [Submitting a Pull Request](#submitting-a-pull-request)
  - [PR Checklist](#pr-checklist)
- [Coding Standards](#coding-standards)
  - [Python Style](#python-style)
  - [Code Organization](#code-organisation)
- [Adding Tests for New Features](#adding-tests-for-new-features)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [Getting Help](#getting-help)
- [Recognition](#recognition)

</br>

## Ways to Contribute

**There are many ways to contribute, not just by writing code.**

### Report a Bug

Found something unexpected? Please open an issue with:

- **Use a clear and descriptive title** for the issue to identify the problem.
- **Describe the exact steps which reproduce the problem** in as many details as possible.
- **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
- **Include screenshots and animated GIFs** which show you following the described steps and clearly demonstrate the problem.
- **Describe your environment** (e.g., OS, Python version, Grafana version being scanned).
- **Include relevant logs or error messages** that may help us understand the situation.

### Suggest an Enhancement

Have an idea to make the scanner better? Open an issue with:

- A clear description of the feature or improvement
- Why this would be valuable
- Any implementation ideas you might have (not required, but appreciated)

### Contribute Code

Ready to write some code? Great! Here's what we're looking for:

- New CVE detection modules
- False positive / false negative fixes
- Configuration analysis enhancements
- Web dashboard improvements
- Documentation updates
- Test cases
- Performance optimizations

</br>

**Before diving into a large change, please open an issue first to discuss your approach. This ensures we're aligned and saves you potential rework.**

</br>

## Getting Started

### Local Development Setup

1. **Clone the repository**  
   `git clone https://github.com/Zierax/Grafana-Final-Scanner.git`

2. **Set up a virtual environment** (recommended)  
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```

3. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   # Also install development dependencies:
   pip install flake8 pytest pytest-cov
   ```

4. **Run the scanner locally**  
   ```bash
   python scanner.py --help
   ```

5. **Run tests**
   + We use `pytest` with coverage. The CI requires at least 70% coverage.
   
   + ```bash
     pytest tests/ -v --cov=scanner --cov-report=term-missing --cov-fail-under=70
     ```

7. **Lint your code**
   - We use `flake8` (the same checks as in CI):  
   + ```bash
     flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics --exclude=.git,__pycache__,tests/
     flake8 . --count --exit-zero --max-complexity=12 --max-line-length=127 --statistics --exclude=.git,__pycache__
     ```

- **Minimum Python version:** 3.9
  - the CI tests versions: 3.9, 3.10, 3.11, 3.12 (your code should work on all of them)

### Branching Strategy

</br>

> [!important]
> For a single feature, fix, or refactor you can simply create one feature branch per logical change and submit a pull request directly against `main`. This is the recommended approach for most contributions. The more detailed consolidation workflow below is only needed if you are working on multiple related changes that you want to combine before merging.

</br>

- **`main`** – Stable, production‑ready code. Everything here should work.

- **Create separate branches other than main**
  – Group related commits into a single, focused branch.  
  For example, if you are working on UI improvements for the web dashboard, create a branch like `ui/improve-dashboard-readability` and commit only UI‑related changes there.

- **Consolidate related work**
  – After finishing work on several branches that belong to the same feature area (e.g., multiple UI improvements), create a *consolidation branch* named like `ui/latest-changes`. Then merge all `ui/*` branches (excluding `ui/latest-changes` itself) into `ui/latest-changes`. This branch represents the complete set of UI changes up to that moment.

  >> **What this is for:** It allows you to keep smaller, logical branches during development, then combine them before a final merge. This rule applies to all feature, fix, or other change branches - **except documentation branches** (see below).

- **Documentation branches** are branches that contain **only** changes to `*.md` files. These do **not** need a `latest-changes` consolidation branch. You may merge each documentation branch directly into `main` when ready.

- **Merging into `main`**
  – Once you have completed all work on a specific functionality or area (including consolidation), merge your `*-latest-changes` branch into `main`. For documentation branches, merge them directly (one by one) into `main` as soon as they are ready.

</br>

> [!important]
>  Keep your local `main` branch up‑to‑date with the upstream repository before creating new branches.

</br>

### Writing Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) format with a **custom spacing**: instead of `<type>: <subject>` (no space before colon), we write **`<type> : <subject>`** (space before *and* after the colon).

```
<type>(<scope optional>) : <subject>

<body optional>

<footer optional>
```

**Types**:
- `feat` - A new feature
- `fix` - A bug fix
- `docs` - Documentation updates
- `style` - Code style changes (formatting, semicolons, etc.)
- `refactor` - Code changes that neither fix bugs nor add features
- `test` - Adding or updating tests
- `chore` - Maintenance tasks (dependencies, config, etc.)

**Examples** (custom spacing shown):
```
feat : add detection for CVE-2025-1234
```
```
fix : correct version detection for Grafana
```
```
style(ui) : improve banner options

'python' was missing in usage examples
```
```
docs(readme) : update installation instructions for Windows
```
```
docs : update README.md

An update for Command-Line Options of v3.1
```

</br>

> [!note]
>  If you prefer the standard Conventional Commits format (`<type>: <subject>` with no space before the colon), that is also acceptable. Both styles are welcome. The key is to write clear, atomic commits - one logical change per commit.

</br>

### Submitting a Pull Request

When you're ready to submit your changes after reviewing our [pull request checklist](#pr-checklist), follow these steps:

1. **Keep your fork synchronized**
   - Ensure your local `main` is up to date with the upstream repository.

3. **Create a feature branch**
   - Use a clear name (e.g., `feature/add-cve-1234` or `fix/false-positive-issue`).

5. **Test your changes thoroughly**
   - Run the scanner against test instances. Ensure existing functionality remains unaffected. **Also run the full test suite locally** (see [Local Development Setup](#local-development-setup)).

7. **Write clear commit messages**
   - Follow the commit format described above.

9. **Push your branch to your fork**
   - Upload it to Github.

11. **Open a Pull Request**
    - Go to the original repository, click `Compare & pull request`, select your feature branch as the source. In the PR description, include:
      - What your changes do
      - Why they are needed
      - Any testing you performed
      - Screenshots for UI changes (if applicable)

11. **Respond to feedback**
    - Be open to questions and suggestions. You may need to update your branch based on review comments.

13. **Keep your branch updated**
    - If `main` advances while your PR is open, rebase your feature branch on the latest `main` and push the updated version.

Once approved, a maintainer will merge your contribution. Thank you!

### PR Checklist

Before submitting a pull request, please ensure:

- [ ] Your code follows the project’s coding standards (PEP 8, flake8 rules)
- [ ] You have added or updated tests where appropriate
- [ ] You have updated documentation (README, comments, etc.)
- [ ] Your commits are atomic and well‑described (one logical change per commit)
- [ ] Your branch is based on the latest `main`
- [ ] All existing tests pass **and coverage remains ≥70%** (`pytest tests/ --cov=scanner --cov-fail-under=70`)
- [ ] No flake8 errors or warnings (the two flake8 commands above produce zero output)
- [ ] You have run the scanner locally against a known vulnerable instance to verify detection (if adding a CVE)
- [ ] Your changes do **not** introduce new dependencies without justification (if they do, discuss in the PR)
- [ ] For CLI or output changes, you have updated the README accordingly

</br>

## Coding Standards

**We value clean, readable, and maintainable code.**

### Python Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use 4 spaces for indentation (no tabs)
- Maximum line length of 127 characters (as allowed by our flake8 configuration)
- Use meaningful variable and function names
- Include docstrings for public functions and classes

### Code Organisation

- Add new CVEs in the appropriate module
- Keep detection logic focused and testable
- Avoid duplication (reuse existing helper functions)
- Handle errors gracefully (use try/except where network or file I/O occurs)

</br>

## Adding Tests for New Features

**Our CI pipeline** (`.github/workflows/python-package.yml`) automatically runs:

- Tests on Python 3.9, 3.10, 3.11, 3.12
- `flake8` linting (syntax errors, undefined names, complexity ≤12, line length ≤127)
- `pytest` with coverage (minimum 70%)
- Syntax validation (AST check on every `.py` file)
- Docker image build and basic smoke test

When adding a new CVE detection:

1. Test against a known vulnerable Grafana instance (in a controlled environment)
2. Test against a patched version to verify no false positives
3. Document your test cases in the PR description
4. Ensure your new code does not drop the overall coverage below 70% (if necessary, add more tests)

When fixing false positives:

1. Reproduce the issue
2. Verify your fix resolves it
3. Confirm you did not introduce new false positives
4. Add a regression test that would have caught the false positive

**Running tests locally** (exactly as CI does):
```bash
pytest tests/ -v --cov=scanner --cov-report=term-missing --cov-fail-under=70
```

</br>

## Reporting Security Vulnerabilities

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, follow responsible disclosure:

1. **Create a private security advisory** on GitHub (`Security -> Advisories -> New draft security advisory`).
2. **Provide details**
    - steps to reproduce, affected versions, potential impact.
3. **Allow time for a fix**
    - We will work on a patch and coordinate disclosure.

</br>

> [!important]
> As stated in the README, this tool is only for authorized security assessments. **Never use it against systems you do not own or lack explicit permission to test.**


</br>

## Recognition

Every contribution matters. Contributors will be:

- Listed in the project's **Contributors** section
- Mentioned in release notes for significant changes
- Recognized in the repository's GitHub Insights

---

_<p align=center>This guide is inspired by the best practices of the open source community. Questions or suggestions for improving it? Open an issue!</p>_
