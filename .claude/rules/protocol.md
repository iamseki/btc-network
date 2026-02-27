## Bitcoin P2P Protocol

Reference: https://developer.bitcoin.org/reference/p2p_networking.html

### Handshake flow (`session.rs`)

```
→ send version
← recv version
→ send sendaddrv2      ← MUST be before verack for BIP 155 signaling
→ send verack
← recv verack          ← handshake complete
```

### Address discovery flow (CLI/crawler)

After handshake:

```
→ send getaddr
← recv addrv2 or addr
```

If peer supports BIP 155 and `sendaddrv2` was signaled before `verack`, prefer `addrv2`.
Otherwise peer may respond with legacy `addr`.

BIP 155: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki

### Headers sync flow (`cli last-block-header`)

- Client sends `getheaders(locator)` repeatedly.
- Peer returns up to 2000 headers per response.
- Client advances locator to last received header hash.
- Sync stops when response count `< 2000` (reached peer tip).

### Block fetch flow (`cli get-block`)

- Parse user-provided hash hex (display endianness), reverse to internal wire order.
- Send `getdata` with inventory type `MSG_BLOCK`.
- Decode incoming `block` payload into typed `Block` (header, tx count, transactions, serialized size).
- Display hash/size/tx info using decoded data.

### Message decode status

| Message       | Status |
|---------------|--------|
| `version`     | decoded |
| `verack`      | decoded (unit variant) |
| `addr`        | decoded |
| `addrv2`      | decoded |
| `headers`     | decoded |
| `block`       | decoded |
| many others   | raw `Vec<u8>` variants (incrementally promotable to typed decode) |

### In-progress / known state

- `Message` still includes multiple raw command payload variants (`Vec<u8>`) not yet typed.
- `cli::recv_until` auto-responds to `Ping` with `Pong`; this behavior should be preserved.
- Hash byte order must stay explicit at input/output boundaries (wire/internal vs display hex).
