# Deucalion

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

1. Install the nightly version of
  [Rust](https://www.rust-lang.org/tools/install) for Windows.

2. `git clone` this repo.

3. `cd` into `deucalion` and run `cargo build`. The DLL will be located in
  `target/debug/deucalion.dll`.

## Usage

This hook runs as part of a server which exposes a very basic
[Named Pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
protocol for reading and writing packets.

1. Inject this DLL into `ffxiv_dx11.exe` with any method you choose. If built
  in debug mode, then a console window will appear after attaching.
1. Initiate a Named pipe session with the hook by connecting to
  `\\.\pipe\deucalion-{FFXIV PID}`. For example, if the PID of a running
  FFXIV process is 9000, then the name of the pipe is
  `\\.\pipe\deucalion-9000`.
  1. Send a `Recv`-OP Payload request to the hook server with the function
  signature for `RecvZonePacket` in the DATA field. If signature is accepted,
  then the server will reply with an `OK` response. Please see [Client-to-Server
  Protocol](#client-to-server-protocol) for more info.
1. The hook will begin logging all calls to the FFXIV message handler through
  the pipe.

## Payload Format

All communication with Deucalion follows this length-delimited protocol (ranges
are inclusive):

| bytes [0, 3] | byte 4 | bytes [5, 8] | bytes [9, N] |
| ------------ | ------ | ------------ | ------------ |
| LENGTH (u32) | OP     | CHANNEL      | DATA         |

### Length

This is the total length of the entire payload, including the length bytes.

### OP Types

| OP  | Name  | Description                                                                                                                             |
| --- | ----- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 0   | Debug | Used for passing debug text messages.                                                                                                   |
| 1   | Ping  | Used to maintain a connection between client and the hook server. The hook will echo a "pong" with the same op when it receives a ping. |
| 2   | Exit  | Used to signal the hook to unload itself from the host process.                                                                         |
| 3   | Recv  | When sent from the hook, contains the FFXIV message received by the host process.                                                       |

### Channel

This is an identifier for the channel used for the payload. It is used to
distinguish between streams of data. When set from the client, the CHANNEL
is treated as a request ID.

#### Recv OP

When broadcasted from the hook server, the CHANNEL denotes one of these three
packet types:

| CHANNEL | Name  | Description                                                   |
| ------- | ----- | ------------------------------------------------------------- |
| 0       | Lobby | Unused                                                        |
| 1       | Zone  | Packets coming from the Zone channel.                         |
| 2       | Chat  | Packets coming from the Chat channel. Currently unimplemented |


### Data

For payloads with OP `Debug`, the payload is simply debug-logged.

For payloads with OP `Recv`, the data is the FFXIV message sent by the host
process.  Because this is a hook and not a packet capture sniffer, the messages
are already in the correct order, but they still need to be decoded by the
client.

## Client-to-Server Protocol

The named pipe server is capable of receiving and handling requests from the
client. The CHANNEL field is used to send the request ID, and the server will
reply to the requesting client with a `Debug`-OP payload with the same request
ID sent in the CHANNEL field.

### Debug OP

Any payload sent with the `Debug` OP will be simply be debug-logged and an `OK`
response will be sent back to the requesting client.

### Ping OP

The server will respond back with the same payload.

### Exit OP

The server will immediately begin unloading the hook and cleaning itself from
the host process without sending a response back to the client.

### Recv OP

Payloads sent with the `Recv` OP will be handled as a Recv-hook initialization
request, where the DATA is a UTF-8-encoded string containing the function
signature for `RecvZonePacket`.

As of 6.31, this signature is
`"E8 $ { ' } 84 C0 0F 85 ? ? ? ? 44 0F B6 64 24 ?"`, where $ { ' } is the desired
target. Please see https://docs.rs/pelite/latest/pelite/pattern/fn.parse.html
for more information on the signature format.

The server will gracefully handle error cases by responding with a `Debug`-OP
Payload with the request ID and error message as the data. The error cases that
are handled include but are not limited to:
  - DATA could not be decoded as a string.
  - The string could not be parsed as a valid signature.
  - The signature could not be found in memory.
  - The `RecvZonePacket` hook was already initialized.

Here is an example interaction between the server and client:

```c
// Server: Connection established message.
Payload { OP: OP.Debug, CHANNEL: 0, DATA: u8"SERVER HELLO" }
// Client: Request with an invalid sig.
Payload { OP: OP.Recv, CHANNEL: 123, DATA: u8"invalid sig" }
// Server: Response with an invalid sig.
Payload { OP: OP.Debug, CHANNEL: 123, DATA: u8"Error setting up hook: Invalid signature: \"invalid sig\"..." }
// Client: Request with a valid sig. Note that it is still possible to attempt
//         to set up the hook again after an error like an invalid sig.
Payload { OP: OP.Recv, CHANNEL: 124, DATA: u8"E8 $ { ' } ..." }
Payload { OP: OP.Debug, CHANNEL: 124, DATA: u8"OK" }
Payload { OP: OP.Recv, CHANNEL: 1, DATA: "(Insert block data here)" }
```

