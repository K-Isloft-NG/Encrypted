"""
Entry point for running Codificator V2 as a module.

Usage:
    python -m codificator_v2           # TUI mode
    python -m codificator_v2 --help    # CLI help
    python -m codificator_v2 encrypt-file ...  # CLI mode
"""

import sys


def main():
    """Main entry point."""
    # Check if CLI arguments provided
    if len(sys.argv) > 1 and not sys.argv[1].startswith('--tui'):
        # CLI mode
        from .cli import main_cli
        return main_cli()
    else:
        # TUI mode
        try:
            from .tui import run_tui
            return run_tui()
        except ImportError:
            print("Error: Textual library not installed.")
            print("Install with: pip install textual")
            print("")
            print("Or use CLI mode: python -m codificator_v2 --help")
            return 1


if __name__ == "__main__":
    sys.exit(main())
