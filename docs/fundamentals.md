# Bitcoin Data Structures & Consensus Fundamentals


## Overview

Bitcoin is not just a Merkle tree and not just a list of transactions.

It is:

> A chain of blocks (linked by hash),  
> where each block commits to a Merkle tree of transactions,  
> and state is enforced through the UTXO model and consensus rules.

Understanding these layers is essential when implementing or analyzing the Bitcoin P2P protocol.

---

# Architecture Summary

Bitcoin combines multiple data structures:

| Component        | Purpose |
|------------------|----------|
| Linked list (blocks) | Global ordering & immutability |
| Merkle tree | Efficient transaction commitment |
| Proof-of-work | Sybil resistance & fork resolution |
| UTXO model | Stateless validation & supply enforcement |
| Subsidy schedule | Fixed monetary issuance |

Each layer solves a different distributed systems problem.

---

# 1. Blockchain Structure

Bitcoin maintains a **chain of blocks**:

```
Block 0 (Genesis)
↓
Block 1
↓
...
↓
Block N (tip)
```

Each block header contains:

- Previous block hash
- Merkle root
- Timestamp
- Difficulty target
- Nonce

This creates:

- Immutability (changing one block breaks all following blocks)
- Global ordering of history
- Proof-of-work security (TODO?)

---

# 2. Merkle Tree (Inside Each Block)

Transactions inside a block are organized into a **Merkle tree**.

Example:

```
    Merkle Root
       /     \
    H12       H34
   /  \      /   \
 Tx1  Tx2   Tx3  Tx4
```


- Leaves = transaction hashes
- Parents = hash(left || right)
- Root = single commitment to all transactions

The Merkle root is stored in the block header.

## Why use a Merkle tree?

1. Efficient verification (SPV clients)
2. Cryptographic commitment to all transactions
3. Compact block headers (fixed 80 bytes)

If any transaction changes → the Merkle root changes → block hash changes → chain breaks.

---

# 3. Best Chain & Height

Each node maintains multiple possible forks internally but selects one as:

> The best chain (the valid chain with the most cumulative proof-of-work).

## Block Height

Block height is the position of a block in the active chain.

- Genesis block → height 0
- Next block → height 1
- Current tip → height N

If a node reports: start_height = 830210


It means:

> "The tip of my best chain is block number 830210."

Total blocks = height + 1.

Height is:

- A sequential index
- Used for confirmations
- Used for halving schedule
- Used for difficulty adjustment

Height is **not** stored in the block header — it is derived from position in the chain.

---

# 4. 21 Million BTC Limit

Bitcoin has a fixed monetary supply capped at ~21 million BTC.

This is enforced through consensus rules:

- Each block contains a coinbase transaction.
- Coinbase creates new BTC (block subsidy).
- Subsidy halves every 210,000 blocks.
- Eventually subsidy becomes zero.

If a miner creates more BTC than allowed:

→ Full nodes reject the block  
→ The block is invalid  
→ The miner loses the reward  

Supply is enforced by validation, not trust.

---

# 5. Transactions vs Supply

Transaction count is unrelated to money supply.

You can have:

- 2 billion transactions
- 20 billion transactions

But total BTC in circulation is determined only by:

- Block subsidy schedule
- Consensus rules

Normal transactions:

- Consume UTXOs
- Create new UTXOs
- Do not create new BTC

---

# 6. The UTXO Model

Bitcoin does not track balances.

Instead, it tracks:

> Unspent Transaction Outputs (UTXOs)

Each transaction:

- Spends previous outputs
- Creates new outputs

Validation rule: `sum(inputs) ≥ sum(outputs)`


Except coinbase, which is limited by subsidy rules.

Total BTC supply = sum of all existing UTXOs.

---

# 7. Block Size & Transaction Limits

Originally, Bitcoin enforced a **hard 1 MB block size limit**.  
Before the activation of Segregated Witness (BIP-141), blocks could not exceed **1,000,000 bytes** in serialized size. This limit was part of the consensus rules to bound resource usage and reduce denial-of-service risk.

With the activation of **BIP-141 (Segregated Witness)**, the fixed 1 MB size limit was replaced by the concept of **block weight**.

This allows blocks containing SegWit transactions to exceed 1 MB in raw byte size (often ~1.3–1.6 MB in practice), while remaining within the 4,000,000 weight unit limit.

There is no fixed limit on the number of transactions per block — only the total block weight limit.

---

# 8. Consensus & Convergence

There is no global authority for "current height".

Each node independently:

- Validates blocks
- Computes cumulative proof-of-work
- Selects the most-work valid chain

Under normal conditions:

> Honest nodes converge to the same best chain.

But convergence is:

- Eventual
- Not instantaneous
- Based on propagation and proof-of-work

---
