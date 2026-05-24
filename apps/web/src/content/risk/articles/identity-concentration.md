---
id: identity-concentration
title: Identity Concentration Signals
category: Sybil-oriented evidence
status: draft
summary: Shows when many reachable peers share the same network home or software shape, so the cluster can be reviewed without assuming who operates it.
---

# Overview

Identity inflation is the core distributed-systems problem.

A Sybil problem starts when one real participant can look like many independent participants. In a peer-to-peer network this matters because software often makes decisions from the identities it can see: which peers to connect to, which addresses to learn from, and how diverse the surrounding network appears.

A Bitcoin crawler cannot see the person or organization behind an endpoint. It sees reachable addresses, protocol handshakes, software fingerprints, and network-location metadata. That is enough to ask a careful question: do many visible identities cluster in ways that reduce the practical independence a node might expect from the network?

In Bitcoin, proof-of-work protects block production, but the peer-to-peer network still depends on diverse reachable peers for block relay, transaction propagation, address discovery, and eclipse resistance. These metrics are about network-layer visibility and redundancy, not miner voting power and not proof of common ownership.

# Dashboard

::widget{type="sybil-dashboard"}

# Signals

::widget{type="sybil-signals"}

# Interpretation

What the dashboard teaches.

Douceur's result is a warning about redundancy: if the system cannot distinguish entities, a small actor can appear as many identities. In crawler terms, we cannot prove entity distinctness, but we can show where endpoint identities become concentrated enough to deserve review.

Behavior monitoring adds a second lens. Repeated fingerprints, start-height bands, and relay settings can reveal common deployment behavior. For Bitcoin P2P analysis, that means watching for clusters that are both dense and operationally similar while still treating popular clients and hosting providers as normal explanations.

# Boundaries

::widget{type="sybil-boundaries"}

# References

::widget{type="sybil-references"}
