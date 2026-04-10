# TSP Transport: SSE-based Intermediary Mode

## Overview

Replace WebSocket-based message delivery in TSP intermediary mode with
Server-Sent Events (SSE). This fixes message loss due to zombie connections,
eliminates the need for application-level reconnect timers, and aligns
with MCP Streamable HTTP patterns.

## Design Principles

1. **P (intermediary) is the buffer authority.** Messages are retained by
   monotonic ID until TTL expires, regardless of transport delivery status.

2. **Client is the acknowledgment authority.** Only the client knows what
   it actually received. It communicates this via `Last-Event-ID` on each
   new SSE connection.

3. **Transport is untrusted.** Whether the SSE write succeeds, fails, or
   goes into a zombie — P keeps the message. The client's next reconnect
   recovers anything missed.

4. **Client initiates the receive.** HTTP GET opens the SSE stream. The
   client controls when to connect. P responds with buffered + live messages.

5. **SSE spec handles reconnection.** No application-level timers needed.
   Spec-compliant SSE client libraries auto-reconnect with `Last-Event-ID`.
   Server keepalive comments break zombie connections.

## Protocol

### Sending a message (unchanged)

```
POST /endpoint/{recipient_did}
Content-Type: application/octet-stream
Body: <CESR-encoded TSP message>

Response: 200 OK
```

Same as today. Stateless HTTP POST. No changes.

### Receiving messages (new: SSE replaces WebSocket)

```
GET /messages/{my_did}
Accept: text/event-stream
Last-Event-ID: <last-received-id>  (optional, on reconnect)

Response: 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no

:keepalive

id: msg-001
data: <CESR text-encoded TSP message>

id: msg-002
data: <CESR text-encoded TSP message>

:keepalive

id: msg-003
data: <CESR text-encoded TSP message>
```

- Each message gets a monotonic ID assigned by P
- `Last-Event-ID` on reconnect triggers replay from that point
- `:keepalive` comment lines every 15-30 seconds prevent proxy timeouts
- Server can send `retry: 3000` to control client reconnect delay (ms)
- CESR text mode used for message encoding — no base64 needed

### Buffer management at P

```
Buffer: ordered list of (id, recipient_did, message, timestamp)

On POST received:
  1. Assign next monotonic ID for this recipient
  2. Store (id, recipient, message, now) in buffer
  3. Push to any active SSE streams for this recipient

On SSE GET received:
  1. If Last-Event-ID present: replay all messages after that ID
  2. If no Last-Event-ID: replay all buffered messages
  3. Keep SSE stream open for new messages

Buffer cleanup (periodic):
  - Remove messages older than TTL (default: 5 minutes)
  - If buffer exceeds max size, remove oldest messages

CRITICAL: Never remove messages based on SSE write success.
Only remove based on TTL or max buffer size.
```

### Client deduplication

When a client reconnects with `Last-Event-ID: msg-005` and P replays
msg-006, msg-007 — the client may have already received some of these
before the connection dropped. The client must deduplicate by tracking
the highest ID it has processed.

The transport layer handles this transparently:
```
Client tracks: last_processed_id = msg-007
On receiving SSE event with id <= last_processed_id: skip
On receiving SSE event with id > last_processed_id: yield to application
```

## Comparison with Current WebSocket Approach

| Aspect | WebSocket (current) | SSE (proposed) |
|--------|-------------------|---------------|
| Zombie connections | Fatal: messages lost | Harmless: buffer retains, client replays |
| Reconnection | Manual, application-level | Built into SSE spec |
| Message loss | P removes on write | P retains until TTL |
| Proxy/firewall | Often blocked | Standard HTTP, works everywhere |
| Keepalive | None (source of bugs) | Comment lines, standard |
| Binary support | Native | CESR text mode (already in TSP) |
| Complexity | High (ping/pong, reconnect) | Low (spec handles it) |
| MCP alignment | None | Same pattern |

## Implementation Plan

### Phase 1: Intermediary SSE endpoint

File: `examples/src/intermediary.rs`

1. Replace `websocket_handler` with SSE handler using `axum::response::sse::Sse`
2. Add monotonic ID per recipient to `QueuedWsMessage` (or new struct)
3. Add `Last-Event-ID` header parsing
4. Implement buffer replay from a given ID
5. Add periodic `:keepalive` comment emission
6. Add `retry:` field in first event
7. Keep POST handler unchanged
8. Buffer cleanup: TTL-based expiry, no removal on send

### Phase 2: TSP SDK SSE client

File: `tsp_sdk/src/transport/http.rs`

1. Replace `receive_messages` WebSocket implementation with SSE client
2. Use `reqwest-eventsource` crate for spec-compliant SSE with auto-reconnect
3. Parse SSE events, decode CESR text, yield as `BytesMut`
4. Track `last_processed_id` for deduplication
5. `send_message` stays unchanged (HTTP POST)

### Phase 3: Remove WebSocket dependencies

1. Remove `tokio-tungstenite` from receive path
2. Feature-gate WebSocket for backward compatibility if needed
3. Update intermediary to no longer use `WebSocketUpgrade`

### Phase 4: Testing

1. Update intermediary stress test
2. Test reconnect with `Last-Event-ID` replay
3. Test zombie connection recovery
4. Test buffer TTL expiry
5. Test multiple clients for same DID
6. TEAgent integration test (transparent — no TEAgent changes)

## Direct Mode

Direct mode (no intermediary) does not use SSE. Both parties run HTTP
servers and exchange messages via POST:

```
Harry → Ted:  HTTP POST to Ted's endpoint
Ted → Harry:  HTTP POST to Harry's endpoint
```

No persistent connections. No buffering. Both parties must be online.
Connection refused = immediate error to the sender.

Same POST format as intermediary mode. The only difference is the URL
(Ted's address vs P's address).

## Impact

| Component | Change |
|-----------|--------|
| `transport/http.rs` | Replace WS receive with SSE client |
| `intermediary.rs` | Replace WS handler with SSE handler |
| `transport/mod.rs` | No change |
| `async_store.rs` | No change |
| TEAgent | No change (transparent) |
| tspchat | No change (transparent) |
| tsp_gateway | No change (transparent) |
| TCP/TLS/QUIC transports | No change |
