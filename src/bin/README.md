# Various Scripts

This folder contains a bunch of scripts for development purposes.
Run them from the repo root folder with `cargo run --bin ${SCRIPT_NAME}`
or compile them if you want.

## find_sig_matches

Finds RVAs for the target exe file that match the given signature.

Example usage:
```bash
cargo run --bin find_sig_matches "C:\path\to\file.exe" "E8 $ { ' } ? ? ? ?"
```