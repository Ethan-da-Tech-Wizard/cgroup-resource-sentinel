"""
cgroupsentinel.__main__
=======================

Executable entrypoint for `python3 -m cgroupsentinel`.
"""

import sys
from cgroupsentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
