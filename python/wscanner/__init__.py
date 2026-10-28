"""wscanner: inventory this machine and its git repos, check only what is
installed against OSV.dev, CISA KEV and endoflife.date, and cache the answers
in a local SQLite database. Standard library only, Python 3.9+."""

__version__ = "0.1.1"
IMPL = "python"
SCHEMA = 1  # the CLI contract's JSON schema (specs/cli-contract.md)
