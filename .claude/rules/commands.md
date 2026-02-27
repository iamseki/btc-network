## Commands

```bash
make build                                            # compile all binaries
make test                                             # run unit tests
make crawler                                          # run crawler binary
make listener                                         # run listener binary
make cli ARGS="--node seed.bitcoin.sipa.be:8333 ping"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-addr"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-headers"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 last-block-header"
make cli ARGS="--node seed.bitcoin.sipa.be:8333 get-block --hash <block-hash>"

# direct cargo equivalents
cargo build --bins
cargo run --bin cli -- --node seed.bitcoin.sipa.be:8333 ping
cargo run --bin crawler
cargo run --bin listener
cargo check
cargo clippy
cargo test                      # currently 32 tests under src/wire/*
cargo test wire::               # focus on wire module tests
```
