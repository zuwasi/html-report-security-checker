#!/usr/bin/env bash
set -e

if [ ! -d ".git" ]; then
    echo "Error: this directory is not a Git repository." >&2
    exit 1
fi

mkdir -p .git/hooks
cp hooks/pre-commit hooks/pre-push .git/hooks/
chmod +x .git/hooks/pre-commit .git/hooks/pre-push

echo "Git hooks installed! Pre-commit and pre-push hooks are now active."
