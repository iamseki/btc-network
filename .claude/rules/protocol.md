## Bitcoin P2P Protocol

Reference: https://developer.bitcoin.org/reference/p2p_networking.html

### Handshake flow (main.rs)

```
→ send version
← recv version
→ send verack
← recv verack          ← handshake complete
→ send getaddr
← recv addr / addrv2
```

### addrv2 flow (BIP 155)

To receive `addrv2` instead of the legacy `addr`, send `sendaddrv2` (empty payload)
**before** your own `verack`:

```
→ send version
← recv version
→ send sendaddrv2      ← BEFORE verack; signals BIP 155 support
→ send verack
← recv verack
→ send getaddr
← recv addrv2          ← if peer is Bitcoin Core 22.0+
```

https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki

### Message decode status

| Message    | Status                    |
|------------|---------------------------|
| `version`  | ✅ decoded                |
| `verack`   | ✅ decoded (empty)        |
| `addr`     | ✅ decoded                |
| `addrv2`   | ✅ decoded (all BIP 155 network IDs) |
| all others | `Vec<u8>` raw — TODO      |

### In-progress / known state

- `src/main.rs` still contains `parse_version`, `parse_verack`, `parse_net_addr`, `read_varint`
  — defined but not yet called. These are candidates to be removed once the `Message` dispatch
  is wired into the main loop properly.
- `src/mod.rs` is an orphaned file with no effect on compilation.
- The IPv4 detection in `decode_net_addr` checks for 12 zero bytes, but the standard Bitcoin
  P2P encoding uses the `::ffff:` prefix (10 zeros + `0xFF 0xFF`). Real nodes' IPv4 addresses
  currently decode as IPv6. A test pins this known behaviour.
