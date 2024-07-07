# Deucalion Client

An implementation of a Deucalion client that is used to validate Deucalion.

## Usage

### Simple Injection
```bash
cargo run --bin deucalion_client -- path/to/deucalion.dll
# or
deucalion_client path/to/deucalion.dll
```

### Injection into Notepad
```bash
deucalion_client path/to/deucalion.dll -t notepad.exe
```

### Force Injection

This calls LoadLibrary again on the same module.

```bash
deucalion_client path/to/deucalion.dll -f
```

### Force ejection

**If Deucalion is still running, it may crash the game**

```bash
deucalion_client deucalion-1.1.0.dll -e
```