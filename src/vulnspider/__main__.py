"""Module entrypoint for `python -m vulnspider`."""

#from vulnspider.cli import main
from vulnspider.run_progress import main
if __name__ == "__main__":
    raise SystemExit(main())

