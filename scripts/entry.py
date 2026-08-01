#!/usr/bin/env python3
"""Standalone entry point for PyInstaller builds."""
import sys
import os

# Add the src directory to the path so absolute imports work
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from html_security_checker.cli import main

if __name__ == '__main__':
    raise SystemExit(main())
