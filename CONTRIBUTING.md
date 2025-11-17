# Contributing to Network Reconnaissance Suite

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a positive environment
- Report unacceptable behavior

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported
2. Use the bug report template
3. Include:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - System information
   - Logs and screenshots

### Suggesting Features

1. Check if the feature has been suggested
2. Use the feature request template
3. Explain:
   - Use case
   - Expected behavior
   - Possible implementation

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Write or update tests
5. Update documentation
6. Commit with clear messages
7. Push to your fork
8. Create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/Advanced-Network-Reconnaissance-Attack-Surface-Mapping-Suite.git

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
pytest

# Run with coverage
pytest --cov=recon_suite
```

## Coding Standards

### Python Style Guide

- Follow PEP 8
- Use type hints where possible
- Write docstrings for all functions/classes
- Maximum line length: 100 characters

### Documentation

- Update README.md for major changes
- Update USAGE.md for new features
- Add inline comments for complex logic
- Include examples in docstrings

### Testing

- Write unit tests for new features
- Maintain test coverage above 80%
- Test edge cases and error handling
- Use pytest fixtures for common setups

## Security

- Never commit API keys or credentials
- Use environment variables for sensitive data
- Follow security best practices
- Report security issues privately

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
