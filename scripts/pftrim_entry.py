"""PyInstaller entry point for pftrim.exe (no arguments -> web UI)."""
from pftrim.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
