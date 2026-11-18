# ==============================================================================
# Program: __main__.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Direct execution entrypoint for Cgroup Resource Sentinel.
#          Inputs: Command line arguments supplied via sys.argv.
#          Outputs: Standard system process exit code returned by main().
#          Design Rationale: Enables direct invocation via `python3 -m cgroupsentinel`
#                            conforming to standard Python package CLI execution idioms.
# ==============================================================================

## System-specific parameters and functions for exit codes and process termination
import sys

## Import the primary command-line parser and command dispatcher
from cgroupsentinel.cli import main

## Check if this module is being executed directly from the terminal
if __name__ == "__main__":
    ## Execute main CLI handler and exit with the returned integer status code
    sys.exit(main())
