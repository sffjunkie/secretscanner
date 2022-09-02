# Secret Scanner

A simple tool to scan directories for secrets using regular expressions.

## Install

Install using either [`pip`](https://pypi.org/project/pip/), [`pipx`](https://pypi.org/project/pipx/) or your Python installer of choice

```
pipx install secretscanner
```

## Usage

To scan a directory and print the files with secrets

```
secretscanner DIRECTORY
```

To also display info on the tokens that have been found pass the `-v`/`--verbose` flag.

To hide the output pass the `-q`/`--quiet` flag.

If secrets are found the tool exits with exit code `1`

## Recognized Secrets

The tool currently recognizes the following secret types

- Github access tokens
- PyPI access tokens
- Digital Ocean access tokens
