# Cgroup Resource Sentinel

A Python project for inspecting Linux cgroup v2 resources, reviewing systemd service settings, and generating proposed resource-limit overrides.

## What’s included

- Inspect a cgroup path or a process’s cgroup and read Linux pressure information.
- Audit service unit files and generate an override using a selected profile.
- Preview generated configuration by default; `--apply` writes a drop-in file.

## Getting started

From the repository root, use Python 3.9 or later:

```sh
python3 -m cgroupsentinel --help
python3 -m cgroupsentinel report
python3 -m cgroupsentinel pressure
```

To review a proposed drop-in without writing it:

```sh
python3 -m cgroupsentinel generate-override example.service --profile standard
```

The CLI also provides `audit`, `inspect`, and JSON output for supported commands. Use each subcommand’s `--help` for options. Applying an override changes systemd configuration and may affect a service; review the generated file, destination and rollback plan first. Applying a file does not itself establish that it is appropriate for the workload.

## Scope

Cgroup and systemd behavior depend on the host and its configuration. Limits can affect workloads and do not guarantee a stable desktop or prevent every out-of-memory event. Verify the generated settings and observe the workload on the target machine.

The repository includes [tests](tests/), runnable with `python3 -m unittest discover -s tests -v`. Test results apply to the revision and environment tested.

## License

[MIT](LICENSE)
