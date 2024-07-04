# Various Scripts

This crate contains a bunch of scripts for development purposes.
Run them from the repo root folder with `cargo run --bin ${SCRIPT_NAME}`
or compile them if you want.

## find_sig_matches

Finds RVAs for the target exe file that match the given signature.

Example usage:
```bash
cargo run --bin find_sig_matches "C:\path\to\file.exe" "E8 $ { ' } ? ? ? ?"
```

## signal_exit

Given a process ID, signals Deucalion to exit if it is running in the target
process. WARNING: This will break applications that use Deucalion!

Example usage:
```bash
cargo run --bin signal_exit 12345
```