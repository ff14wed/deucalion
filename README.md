# Deucalion

High-performance Windows library for capturing decoded FFXIV packets. This
library is fairly limited in scope and it is intended to be used in conjunction
with other packet handling applications.

## Features

  - This library can be used as a sniffer on the FFXIV packet protocol layer
    without concern for the lower-level TCP layer.
  - Deucalion runs as an injected DLL and hooks the function responsible for
    reading decoded packets. Therefore, this method of capture is not susceptible
    to the limitations of libpcap-based capture.
  - Deucalion functions as a broadcast server that streams captured packets to
    one or many subscribers.

## Building

1. Install the nightly version of
  [Rust](https://www.rust-lang.org/tools/install) for Windows.

2. `git clone` this repo.

3. `cd` into `deucalion` and run `cargo build`. The DLL will be located in
  `target/debug/deucalion.dll`.

## Usage

On initialization, Deucalion exposes a
[Named Pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
server that follows a length-delimited protocol for capturing packets or for
subscriber requests.

1. Inject `deucalion.dll` into `ffxiv_dx11.exe` with any method you choose. If
   built in debug mode, a console window will appear after attaching.
1. Initiate a Named pipe session with Deucalion by connecting to
  `\\.\pipe\deucalion-{FFXIV PID}`. For example, if the PID of a running
  FFXIV process is 9000, then the name of the pipe is
  `\\.\pipe\deucalion-9000`.
  1. Send a `Recv`-OP Payload request to Deucalion with the function
  signature for `RecvZonePacket` in the DATA field. If signature is accepted,
  then Deucalion will reply with an `OK` response. Please see [Subscriber
  Protocol](#subscriber-protocol) for more info.
1. Deucalion will begin logging all calls to the FFXIV packet handler through
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

| OP  | Name  | Description                                                                                                                       |
| --- | ----- | --------------------------------------------------------------------------------------------------------------------------------- |
| 0   | Debug | Used for passing debug text messages.                                                                                             |
| 1   | Ping  | Used to maintain a connection between the subscriber and Deucalion. Deucalion will echo the same payload when it receives a ping. |
| 2   | Exit  | Used to signal Deucalion to unload itself from the host process.                                                                  |
| 3   | Recv  | When sent from Deucalion, contains the FFXIV packet received by the host process.                                                 |

### Channel

This is an identifier for the channel used for the payload. It is used to
distinguish between streams of data. When set from the subscriber, the CHANNEL
is treated as a request ID.

#### Recv OP

When broadcasted from Deucalion, the CHANNEL denotes one of these three packet
types:

| CHANNEL | Name  | Description                                                   |
| ------- | ----- | ------------------------------------------------------------- |
| 0       | Lobby | Unused                                                        |
| 1       | Zone  | Packets coming from the Zone channel.                         |
| 2       | Chat  | Packets coming from the Chat channel. Currently unimplemented |


### Data

For payloads with OP `Debug`, the payload is simply debug-logged.

For payloads with OP `Recv`, the data is the FFXIV packet sent by the host
process. The packets are already in the correct order, but they still need to be
decoded by your application. See [FFXIV Packet Data
Format](#ffxiv-packet-data-format) for more information on how to handle this
data.

## Subscriber Protocol

The Deucalion server is capable of receiving and handling requests from the
subscriber. The CHANNEL field is used to send the request ID, and Deucalion
will reply to the requesting subscriber with a `Debug`-OP payload with the same
request ID sent in the CHANNEL field.

### Debug OP

Any payload sent with the `Debug` OP will be simply be debug-logged and an `OK`
response will be sent back to the requesting subscriber.

### Ping OP

Any `Ping`-OP payload sent to Deucalion will be echoed back to the requesting
subscriber.

### Exit OP

Deucalion will immediately begin unloading all hooks and cleaning itself from
the host process without sending a response back to the subscriber.

### Recv OP

Payloads sent with the `Recv` OP will be handled as a Recv-hook initialization
request, where the DATA is a UTF-8-encoded string containing the function
signature for `RecvZonePacket`.

As of 6.31, this signature is
`"E8 $ { ' } 84 C0 0F 85 ? ? ? ? 44 0F B6 64 24 ?"`, where $ { ' } is the desired
target. Please see https://docs.rs/pelite/latest/pelite/pattern/fn.parse.html
for more information on the signature format.

Deucalion will gracefully handle error cases by responding with a `Debug`-OP
Payload with the request ID and error message as the data. The error cases that
are handled include but are not limited to:
  - DATA could not be decoded as a string.
  - The string could not be parsed as a valid signature.
  - The signature could not be found in memory.
  - The `RecvZonePacket` hook was already initialized.

Here is an example interaction between Deucalion and a subscriber:

```c
// Deucalion: Connection established message.
Payload { OP: OP.Debug, CHANNEL: 0, DATA: u8"SERVER HELLO" }
// Subscriber: Request with an invalid sig.
Payload { OP: OP.Recv, CHANNEL: 123, DATA: u8"invalid sig" }
// Deucalion: Response with an invalid sig.
Payload { OP: OP.Debug, CHANNEL: 123, DATA: u8"Error setting up hook: Invalid signature: \"invalid sig\"..." }
// Subscriber: Request with a valid sig. Note that it is still possible to
//             attempt to set up the hook again after an error like an invalid
//             sig.
Payload { OP: OP.Recv, CHANNEL: 124, DATA: u8"E8 $ { ' } ..." }
// Deucalion: OK response
Payload { OP: OP.Debug, CHANNEL: 124, DATA: u8"OK" }
// Deucalion: Data streamed from hook
Payload { OP: OP.Recv, CHANNEL: 1, DATA: "(Insert block data here)" }
```

## FFXIV Packet Data Format

Data broadcasted with the `Recv` OP is sent to all subscribers in a
Deucalion-specific format:

```c
struct DEUCALION_SEGMENT {
  uint32_t source_actor;
  uint32_t target_actor;
  FFXIVARR_IPC_HEADER ipc_header; // Includes opcode, serverId
  uint8_t packet_data[];
}
```

### Details

There are a multitude of terms out there for describing the same data
structures and it may sometimes be confusing, so let's clarify what we mean by
*FFXIV packet*.

TCP data arrives in individual units called *segments*, which may also be called
*TCP packets*.

FFXIV data arrives in containers that are called a multitude of
different things, but ultimately it does not matter so we'll call them *frames*
here.  On the wire, they may be split across multiple TCP segments, but this is
a detail that is abstracted away here.

Each frame contains data that is potentially compressed, and this data typically
includes one or more *FFXIV segments*. Each segment encapulates segment header
information and the data, which is what we actually refer to as the *FFXIV
packet data*.

Using names from https://xiv.dev/network/packet-structure, the following is a
diagram of what this looks like. Deucalion extracts the innermost packet data
after it has been decoded and decompressed.

```
┌───────────────────────────────────────────────┐
│  Frame                                        │
│ ┌───────────────────────────────────────────┐ │
│ │ FFXIVARR_PACKET_HEADER                    │ │
│ │                                           │ │
│ │ ...                                       │ │
│ │ uint32_t size;                            │ │
│ │ uint16_t connectionType;                  │ │
│ │ uint16_t segmentCount;                    │ │
│ │ ...                                       │ │
│ │ uint8_t isCompressed;                     │ │
│ │ ...                                       │ │
│ │ uint32_t decompressedSize;                │ │
│ └───────────────────────────────────────────┘ │
│ ┌───────────────────────────────────────────┐ │
│ │ Compressed Data                           │ │
│ │ ┌───────────────────────────────────────┐ │ │
│ │ │ Segment 1                             │ │ │
│ │ │ ┌───────────────────────────────────┐ │ │ │
│ │ │ │ FFXIVARR_PACKET_SEGMENT_HEADER    │ │ │ │
│ │ │ │                                   │ │ │ │
│ │ │ │ uint32_t size;                    │ │ │ │
│ │ │ │ uint32_t source_actor;            │ │ │ │
│ │ │ │ uint32_t target_actor;            │ │ │ │
│ │ │ │ uint16_t type; // SEGMENTTYPE_IPC │ │ │ │
│ │ │ │ ...                               │ │ │ │
│ │ │ ├───────────────────────────────────┤ │ │ │
│ │ │ │ FFXIVARR_IPC_HEADER               │ │ │ │
│ │ │ │                                   │ │ │ │
│ │ │ │ uint16_t reserved; // 0x0014      │ │ │ │
│ │ │ │ uint16_t type; // Opcode          │ │ │ │
│ │ │ │ uint16_t padding;                 │ │ │ │
│ │ │ │ uint16_t serverId;                │ │ │ │
│ │ │ │ uint32_t timestamp;               │ │ │ │
│ │ │ │ uint32_t padding1;                │ │ │ │
│ │ │ ├───────────────────────────────────┤ │ │ │
│ │ │ │ PACKET_DATA                       │ │ │ │
│ │ │ │ ...                               │ │ │ │
│ │ │ └───────────────────────────────────┘ │ │ │
│ │ └───────────────────────────────────────┘ │ │
│ │ ┌───────────────────────────────────────┐ │ │
│ │ │ Segment 2                             │ │ │
│ │ │ ...                                   │ │ │
│ │ └───────────────────────────────────────┘ │ │
│ └───────────────────────────────────────────┘ │
└───────────────────────────────────────────────┘
```
