#!/usr/bin/env python3
"""
AssetMonitor — continuous security asset monitoring tool.

This is the main entry point.  It simply imports and invokes the Click CLI
defined in src/cli.py so that the tool can be called as:

    python assetmonitor.py [COMMAND] [OPTIONS]

or, after chmod +x:

    ./assetmonitor.py [COMMAND] [OPTIONS]
"""

from src.cli import cli

if __name__ == "__main__":
    cli()
