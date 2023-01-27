# deucalion

High-performance library for message capture for FFXIV. This library is fairly
limited in scope and it is intended to be used in conjunction with other message
handling applications.

## Features

  - This library can be used as message sniffer for FFXIV without having to worry about
    out-of-order TCP packets.
  - The hook server supports multiple clients connecting to the named pipe at once.
  - This method of capture is not susceptible to the limitations of
    libpcap-based capture.

## Building

1. Install [Rust](https://www.rust-lang.org/tools/install) for Windows.

2. `git clone` this repo.

3. `cd` into `deucalion` and run `cargo build`. The DLL will be located in
  `target/debug/deucalion.dll`.

## Usage

This hook exposes a very basic
[Named Pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
protocol for reading and writing packets.

1. Inject this DLL into `ffxiv_dx11.exe` with any method you choose. If built
  in debug mode, then a console window will appear after attaching.
2. Initiate a Named pipe session with the hook by connecting to
  `\\.\pipe\deucalion-{FFXIV PID}`. For example, if the PID of a running
  FFXIV process is 9000, then the name of the pipe is
  `\\.\pipe\deucalion-9000`.
3. The hook will begin logging all calls to the FFXIV message handler through
  the pipe.

## Message Format

All communication with deucalion follows this length-delimited protocol:

| bytes 0 - 3  | byte 4 | bytes 5 - 8 | bytes 9 - N |
| ------------ | ------ | ----------- | ----------- |
| LENGTH (u32) | OP     | CHANNEL     | PAYLOAD     |

### Length

This is the total length of the entire message, including the length bytes.

### OP Types

| OP  | Name  | Description                                                                                                                             |
| --- | ----- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 0   | Debug | Used for passing debug text messages.                                                                                                   |
| 1   | Ping  | Used to maintain a connection between client and the hook server. The hook will echo a "pong" with the same op when it receives a ping. |
| 2   | Exit  | Used to signal the hook to unload itself from the host process.                                                                         |
| 3   | Recv  | When sent from the hook, contains the FFXIV message received by the host process.                                                       |

### Channel

This is an identifier for the channel used for the FFXIV message. Used to
distinguish between packet data on the Zone channel and other channels like the
Chat channel.

### Payload

For messages with op "Debug", the payload is simply logged. For messages with op
"Recv", the payload is the FFXIV message sent by the host process.  Because this
is a hook and not a packet capture sniffer, the messages are already in the
correct order, but they still need to be decoded by the client.

