# Contributing to Security Knowledge Graph

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing](#testing)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/codewatch.git
   cd codewatch
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/tarun27in/codewatch.git
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

## Development Setup

### Prerequisites

- **Backend**: Python 3.11+
- **Frontend**: Node.js 18+ and npm
- **Docker** (optional, for containerized development)

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

### Running the Application

**Using Docker Compose** (recommended):
```bash
docker-compose up
```

**Manual setup**:
```bash
# Terminal 1 - Backend
cd backend
uvicorn app.main:app --reload --port 8000

# Terminal 2 - Frontend
cd frontend
npm run dev
```

Access the application at `http://localhost:5173`

## How to Contribute

### Areas for Contribution

We welcome contributions in the following areas:

1. **New Language Analyzers** - Add deep analysis for Go, Java, Rust, etc.
2. **Vulnerability Patterns** - Add detection for CSRF, race conditions, timing attacks
3. **CI/CD Integration** - GitHub Actions, GitLab CI, etc.
4. **Documentation** - Improve docs, add examples, write tutorials
5. **Bug Fixes** - Fix reported issues
6. **Performance** - Optimize scanning speed, memory usage
7. **UI/UX** - Improve visualization, add new features

### Good First Issues

Look for issues labeled `good first issue` or `help wanted` to get started.

## Pull Request Process

### Before Submitting

1. **Sync with upstream** to ensure you're working with the latest code:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Test your changes** thoroughly:
   - Run backend tests: `pytest` (if available)
   - Run frontend tests: `npm test` (if available)
   - Manually test the feature/fix

3. **Follow code style guidelines** (see below)

4. **Update documentation** if needed:
   - Update README.md if adding new features
   - Add comments for complex logic
   - Update API documentation if changing endpoints

### Submitting a Pull Request

1. **Push your changes** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub:
   - Use a clear, descriptive title
   - Fill out the PR template completely
   - Reference any related issues (e.g., "Fixes #123")
   - Add screenshots/GIFs for UI changes
   - Explain WHY the change is needed, not just WHAT changed

3. **Respond to review feedback**:
   - Address all comments from reviewers
   - Push additional commits to the same branch
   - Request re-review when ready

4. **Wait for approval** - PRs require at least one approval before merging

### PR Title Format

Use conventional commit format:
- `feat: Add support for Go analysis`
- `fix: Resolve memory leak in scanner`
- `docs: Update installation instructions`
- `refactor: Simplify graph layout logic`
- `test: Add tests for CVE lookup`
- `chore: Update dependencies`

## Code Style Guidelines

### Python (Backend)

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints where appropriate
- Maximum line length: 100 characters
- Use meaningful variable and function names
- Add docstrings for functions and classes:
  ```python
  def analyze_code(file_path: str, language: str) -> Dict[str, Any]:
      """
      Analyze source code file for security issues.

      Args:
          file_path: Path to the source code file
          language: Programming language (e.g., 'python', 'javascript')

      Returns:
          Dictionary containing analysis results
      """
  ```

### TypeScript/React (Frontend)

- Use **TypeScript** for all new code
- Follow the existing component structure
- Use functional components with hooks
- Maximum line length: 100 characters
- Use meaningful variable and component names
- Export types/interfaces when needed:
  ```typescript
  interface NodeData {
    id: string;
    type: string;
    label: string;
    metadata?: Record<string, any>;
  }
  ```

### General Guidelines

- Write self-documenting code
- Add comments only when necessary to explain "why", not "what"
- Keep functions small and focused (single responsibility)
- Avoid premature optimization
- Don't commit commented-out code
- Don't commit `console.log()` or `print()` debugging statements

## Testing

### Backend Tests

```bash
cd backend
pytest
```

### Frontend Tests

```bash
cd frontend
npm test
```

### Manual Testing Checklist

Before submitting a PR, manually test:
- [ ] Scan a local directory
- [ ] Scan a GitHub repository
- [ ] Graph visualization renders correctly
- [ ] Filtering works as expected
- [ ] No console errors in browser
- [ ] No errors in backend logs

## Reporting Bugs

Found a bug? Please create an issue using the **Bug Report** template.

**Before submitting**:
1. Search existing issues to avoid duplicates
2. Ensure you're using the latest version
3. Collect relevant information:
   - Operating system
   - Python version
   - Node.js version
   - Error messages and stack traces
   - Steps to reproduce

## Suggesting Features

Have an idea? Create an issue using the **Feature Request** template.

**Good feature requests include**:
- Clear description of the problem it solves
- Expected behavior
- Potential implementation approach (optional)
- Willingness to contribute the feature yourself

## Questions?

- Open a **Discussion** on GitHub
- Check existing documentation
- Look at closed issues for similar questions

## Recognition

Contributors will be recognized in the README.md and release notes. Thank you for making this project better!

---

**Happy Contributing!** 🎉
