# Splicing Tests

This file details various [splicing](../02-peer-protocol.md#channel-splicing) protocol flows.
We detail the exact flow of messages for each scenario, and highlight several edge cases that must be correctly handled by implementations.

## Table of Contents

* [Terminology](#terminology)
* [Test Vectors](#test-vectors)
  * [Successful single splice](#successful-single-splice)
  * [Multiple splices with concurrent `splice_locked`](#multiple-splices-with-concurrent-splice_locked)
  * [Disconnection with one side sending `commit_sig`](#disconnection-with-one-side-sending-commit_sig)
  * [Disconnection with both sides sending `commit_sig`](#disconnection-with-both-sides-sending-commit_sig)
  * [Disconnection with one side sending `tx_signatures`](#disconnection-with-one-side-sending-tx_signatures)
  * [Disconnection with both sides sending `tx_signatures`](#disconnection-with-both-sides-sending-tx_signatures)
  * [Disconnection with both sides sending `tx_signatures` and channel updates](#disconnection-with-both-sides-sending-tx_signatures-and-channel-updates)
  * [Disconnection with concurrent `splice_locked`](#disconnection-with-concurrent-splice_locked)

## Terminology

We call "active commitments" the set of valid commitment transactions to which updates (`update_add_htlc`, `update_fulfill_htlc`, `update_fail_htlc`, `update_fail_malformed_htlc`, `update_fee`) must be applied.
While a funding transaction is not locked (ie `splice_locked` hasn't been exchanged), updates must be valid for all active commitments.

When representing active commitments, we will only draw the corresponding funding transactions for simplicity.
The related commitment transaction simply spends that funding transaction.

For example, the following diagram displays the active commitments when we have an unconfirmed splice (`FundingTx2a`) and 2 RBF attempts for that splice (`FundingTx2b` and `FundingTx2c`).
We thus have 4 active commitments:

* the commitment spending `FundingTx1`
* the commitments spending each splice transaction (`FundingTx2a`, `FundingTx2b` and `FundingTx2c`)

```text
+------------+                +-------------+
| FundingTx1 |--------+------>| FundingTx2a |
+------------+        |       +-------------+
                      |
                      |       +-------------+
                      +------>| FundingTx2b |
                      |       +-------------+
                      |
                      |       +-------------+
                      +------>| FundingTx2c |
                              +-------------+
```

**Peers must always agree on the set of active commitments**, otherwise one side will expect signatures that the other side will not send, which will lead to force-closing the channel.

## Test Vectors

In the protocol flows below, we omit the `interactive-tx` messages that build the transaction.
The only `interactive-tx` messages we explicitly list are the consecutive `tx_complete` that mark the end of the `interactive-tx` construction.

We also assume that both peers use the same `commitment_number` for simplicity.

### Successful single splice

Let's warm up with the simplest possible flow: a splice transaction that confirms without any disconnection.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |        tx_signatures         |
     |<-----------------------------|
     |                              | The channel is no longer quiescent at that point.
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |       update_add_htlc        | Alice and Bob use the channel while the splice transaction is unconfirmed.
     |----------------------------->|
     |       update_add_htlc        |
     |----------------------------->|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx1, commitment_number = 11
     |----------------------------->|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx2, commitment_number = 11
     |----------------------------->|
     |       revoke_and_ack         |
     |<-----------------------------|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx1, commitment_number = 11
     |<-----------------------------|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx2, commitment_number = 11
     |<-----------------------------|
     |       revoke_and_ack         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 11
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |        splice_locked         | The splice transaction confirms.
     |----------------------------->|
     |        splice_locked         |
     |<-----------------------------|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 11
     |                              |    +------------+
     |                              |    | FundingTx2 |
     |                              |    +------------+
     |                              | 
     |       update_add_htlc        | Alice and Bob can use the channel and forget the previous FundingTx1.
     |----------------------------->|
     |         commit_sig           |
     |----------------------------->|
     |       revoke_and_ack         |
     |<-----------------------------|
     |         commit_sig           |
     |<-----------------------------|
     |       revoke_and_ack         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 12
     |                              |    +------------+
     |                              |    | FundingTx2 |
     |                              |    +------------+
```

### Multiple splices with concurrent `splice_locked`

Since nodes have different views of the blockchain, they may send `splice_locked` at slightly different times.
Moreover, nodes may send `splice_locked` concurrently with other channel updates, in which case they will receive some `commit_sig` messages for obsolete commitments.
This is fine: nodes know how many `commit_sig` messages to expect thanks to the `batch_size` field, and they can simply ignore `commit_sig` messages for which the `funding_txid` cannot be found in the active commitments.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |        tx_signatures         |
     |<-----------------------------|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +-------------+
     |                              |    | FundingTx1 |------->| FundingTx2a |
     |                              |    +------------+        +-------------+
     |                              |
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          tx_init_rbf         | Alice RBFs the splice attempt.
     |----------------------------->|
     |          tx_ack_rbf          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |        tx_signatures         |
     |<-----------------------------|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +-------------+
     |                              |    | FundingTx1 |---+--->| FundingTx2a |
     |                              |    +------------+   |    +-------------+
     |                              |                     |
     |                              |                     |    +-------------+
     |                              |                     +--->| FundingTx2b |
     |                              |                          +-------------+
     |                              |
     |       update_add_htlc        | Alice and Bob use the channel while the splice transactions are unconfirmed.
     |----------------------------->|
     |       update_add_htlc        |
     |----------------------------->|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx1, commitment_number = 11
     |----------------------------->|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx2a, commitment_number = 11
     |----------------------------->|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx2b, commitment_number = 11
     |----------------------------->|
     |       revoke_and_ack         |
     |<-----------------------------|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx1, commitment_number = 11
     |<-----------------------------|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx2a, commitment_number = 11
     |<-----------------------------|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx2b, commitment_number = 11
     |<-----------------------------|
     |       revoke_and_ack         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 11
     |                              |    +------------+        +-------------+
     |                              |    | FundingTx1 |---+--->| FundingTx2a |
     |                              |    +------------+   |    +-------------+
     |                              |                     |
     |                              |                     |    +-------------+
     |                              |                     +--->| FundingTx2b |
     |                              |                          +-------------+
     |                              |
     |        splice_locked         | splice_txid = FundingTx2a
     |----------------------------->|
     |       update_add_htlc        |
     |----------------------------->|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx1, commitment_number = 12 -> this message will be ignored by Bob since FundingTx2a will be locked before the end of the batch
     |----------------------------->|
     |        splice_locked         | splice_txid = FundingTx2a
     |<-----------------------------|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx2a, commitment_number = 12
     |----------------------------->|
     |         commit_sig           | batch_size = 3, funding_txid = FundingTx2b, commitment_number = 12 -> this message can be ignored by Bob since FundingTx2a has been locked
     |----------------------------->|
     |       revoke_and_ack         |
     |<-----------------------------|
     |         commit_sig           |
     |<-----------------------------|
     |       revoke_and_ack         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 12
     |                              |    +-------------+
     |                              |    | FundingTx2b |
     |                              |    +-------------+
```

### Disconnection with one side sending `commit_sig`

In this scenario, a disconnection happens when one side has sent `commit_sig` but not the other.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice, but disconnects before receiving Bob's tx_complete:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |       X----------------------|
     |         commit_sig           |
     |       X----------------------|
     |                              | Active commitments for Alice:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+
     |                              |    | FundingTx1 |
     |                              |    +------------+
     |                              | 
     |                              | Active commitments for Bob:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = FundingTx2, next_commitment_number = 10, next_revocation_number = 10
     |<-----------------------------|
     |           tx_abort           |
     |----------------------------->|
     |           tx_abort           |
     |<-----------------------------|
     |                              | Bob can safely forget the splice attempt because he hasn't sent tx_signatures.
     |                              | Active commitments for Alice and Bob:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+
     |                              |    | FundingTx1 |
     |                              |    +------------+
```

### Disconnection with both sides sending `commit_sig`

In this scenario, a disconnection happens when both sides have sent `commit_sig`.
They are able to resume the signatures exchange on reconnection.
In this example, Bob is supposed to send `tx_signatures` first.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice, but disconnects before receiving Bob's commit_sig:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |--------------------X         |
     |         commit_sig           |
     |       X----------------------|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |      channel_reestablish     | next_funding_txid = FundingTx2, next_commitment_number = 10, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = FundingTx2, next_commitment_number = 10, next_revocation_number = 10
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
```

### Disconnection with one side sending `tx_signatures`

In this scenario, a disconnection happens when one side has sent `tx_signatures` but not the other.
They are able to resume the signatures exchange on reconnection.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice, but disconnects before receiving Bob's tx_signatures:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |       X----------------------|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |      channel_reestablish     | next_funding_txid = FundingTx2, next_commitment_number = 11, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = FundingTx2, next_commitment_number = 11, next_revocation_number = 10
     |<-----------------------------|
     |        tx_signatures         |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
```

### Disconnection with both sides sending `tx_signatures`

In this scenario, a disconnection happens when both sides have sent `tx_signatures`, but one side has not received it.
They are able to resume the signatures exchange on reconnection.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice, but disconnects before Bob receives her tx_signatures:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------X       |
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = FundingTx2, next_commitment_number = 11, next_revocation_number = 10
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
```

### Disconnection with both sides sending `tx_signatures` and channel updates

In this scenario, a disconnection happens when both sides have sent `tx_signatures`, but one side has not received it.
The second signer also sent a new signature for additional changes to apply after their `tx_signatures`.
They are able to resume the signatures exchange on reconnection and retransmit new updates.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice, but disconnects before Bob receives her tx_signatures and new updates:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------X       |
     |       update_add_htlc        |
     |----------------------X       |
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx1, commitment_number = 11
     |----------------------X       |
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx2, commitment_number = 11
     |----------------------X       |
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = FundingTx2, next_commitment_number = 11, next_revocation_number = 10
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |       update_add_htlc        |
     |----------------------------->|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx1, commitment_number = 11
     |----------------------------->|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx2, commitment_number = 11
     |----------------------------->|
     |       revoke_and_ack         |
     |<-----------------------------|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx1, commitment_number = 11
     |<-----------------------------|
     |         commit_sig           | batch_size = 2, funding_txid = FundingTx2, commitment_number = 11
     |<-----------------------------|
     |       revoke_and_ack         |
     |----------------------------->|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 11
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
```

### Disconnection with concurrent `splice_locked`

In this scenario, disconnections happen while nodes are exchanging `splice_locked`.
The `splice_locked` message must be retransmitted on reconnection until new commitments have been signed.

```text
Initial active commitments:

   commitment_number = 10
   +------------+
   | FundingTx1 |
   +------------+

Alice initiates a splice, but disconnects before Bob receives her splice_locked:

   Alice                           Bob
     |             stfu             |
     |----------------------------->|
     |             stfu             |
     |<-----------------------------|
     |          splice_init         |
     |----------------------------->|
     |          splice_ack          |
     |<-----------------------------|
     |                              |
     |       <interactive-tx>       |
     |<---------------------------->|
     |                              |
     |         tx_complete          |
     |----------------------------->|
     |         tx_complete          |
     |<-----------------------------|
     |         commit_sig           |
     |----------------------------->|
     |         commit_sig           |
     |<-----------------------------|
     |        tx_signatures         |
     |<-----------------------------|
     |        tx_signatures         |
     |----------------------------->|
     |        splice_locked         |
     |---------------------X        |
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+        +------------+
     |                              |    | FundingTx1 |------->| FundingTx2 |
     |                              |    +------------+        +------------+
     |                              |
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |<-----------------------------|
     |        splice_locked         |
     |----------------------------->|
     |        splice_locked         |
     |       X----------------------|
     |                              |
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |<-----------------------------|
     |        splice_locked         |
     |----------------------------->|
     |        splice_locked         |
     |<-----------------------------|
     |                              | Active commitments:
     |                              | 
     |                              |    commitment_number = 10
     |                              |    +------------+
     |                              |    | FundingTx2 |
     |                              |    +------------+
     |       update_add_htlc        |
     |----------------------X       |
     |         commit_sig           |
     |----------------------X       |
     |                              |
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 11, next_revocation_number = 10
     |<-----------------------------|
     |        splice_locked         |
     |----------------------------->|
     |        splice_locked         |
     |<-----------------------------|
     |       update_add_htlc        |
     |----------------------------->|
     |         commit_sig           |
     |----------------------------->|
     |       revoke_and_ack         |
     |<-----------------------------|
     |         commit_sig           |
     |<-----------------------------|
     |       revoke_and_ack         |
     |----------------------------->|
     |                              | Active commitments:
     |                              |
     |                              |    commitment_number = 11
     |                              |    +------------+
     |                              |    | FundingTx2 |
     |                              |    +------------+
     |                              |
     |                              | A new commitment was signed, implicitly acknowledging splice_locked.
     |                              | We thus don't need to retransmit splice_locked on reconnection.
     |       update_add_htlc        |
     |----------------------X       |
     |         commit_sig           |
     |----------------------X       |
     |                              |
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 12, next_revocation_number = 11
     |----------------------------->|
     |      channel_reestablish     | next_funding_txid = null, next_commitment_number = 12, next_revocation_number = 11
     |<-----------------------------|
     |       update_add_htlc        |
     |----------------------------->|
     |         commit_sig           |
     |----------------------------->|
```
