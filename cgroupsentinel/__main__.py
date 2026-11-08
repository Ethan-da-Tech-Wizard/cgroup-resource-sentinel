"""
Program: Cgroup Resource Sentinel - Main Execution Entrypoint
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Provide direct CLI execution support when invoked via `python3 -m cgroupsentinel`.
"""

## System-specific parameters and functions for exit codes and process termination
import sys

## Import the primary command-line parser and command dispatcher
from cgroupsentinel.cli import main

## Check if this module is being executed directly from the terminal
if __name__ == "__main__":
    ## Execute main CLI handler and exit with the returned integer status code
    sys.exit(main())
