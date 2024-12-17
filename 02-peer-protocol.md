# BOLT #2: Peer Protocol for Channel Management

The peer channel protocol has three phases: establishment, normal
operation, and closing.

# Table of Contents

  * [Channel](#channel)
    * [Definition of `channel_id`](#definition-of-channel_id)
    * [Interactive Transaction Construction](#interactive-transaction-construction)
      * [Set-Up and Vocabulary](#set-up-and-vocabulary)
      * [Fee Responsibility](#fee-responsibility)
      * [Overview](#overview)
      * [The `tx_add_input` Message](#the-tx_add_input-message)
      * [The `tx_add_output` Message](#the-tx_add_output-message)
      * [The `tx_remove_input` and `tx_remove_output` Messages](#the-tx_remove_input-and-tx_remove_output-messages)
      * [The `tx_complete` Message](#the-tx_complete-message)
      * [The `tx_signatures` Message](#the-tx_signatures-message)
      * [The `tx_init_rbf` Message](#the-tx_init_rbf-message)
      * [The `tx_ack_rbf` Message](#the-tx_ack_rbf-message)
      * [The `tx_abort` Message](#the-tx_abort-message)
    * [Channel Establishment v1](#channel-establishment-v1)
      * [The `open_channel` Message](#the-open_channel-message)
      * [The `accept_channel` Message](#the-accept_channel-message)
      * [The `funding_created` Message](#the-funding_created-message)
      * [The `funding_signed` Message](#the-funding_signed-message)
      * [The `channel_ready` Message](#the-channel_ready-message)
    * [Channel Establishment v2](#channel-establishment-v2)
      * [The `open_channel2` Message](#the-open_channel2-message)
      * [The `accept_channel2` Message](#the-accept_channel2-message)
      * [Funding Composition](#funding-composition)
      * [The `commitment_signed` Message](#the-commitment_signed-message)
      * [Sharing funding signatures: `tx_signatures`](#sharing-funding-signatures-tx_signatures)
      * [Fee bumping: `tx_init_rbf` and `tx_ack_rbf`](#fee-bumping-tx_init_rbf-and-tx_ack_rbf)
    * [Channel Quiescence](#channel-quiescence)
    * [Channel Close](#channel-close)
      * [Closing Initiation: `shutdown`](#closing-initiation-shutdown)
      * [Closing Negotiation: `closing_signed`](#closing-negotiation-closing_signed)
      * [Closing Negotiation: `closing_complete` and `closing_sig`](#closing-negotiation-closing_complete-and-closing_sig)
    * [Normal Operation](#normal-operation)
      * [Forwarding HTLCs](#forwarding-htlcs)
      * [`cltv_expiry_delta` Selection](#cltv_expiry_delta-selection)
      * [Adding an HTLC: `update_add_htlc`](#adding-an-htlc-update_add_htlc)
      * [Removing an HTLC: `update_fulfill_htlc`, `update_fail_htlc`, and `update_fail_malformed_htlc`](#removing-an-htlc-update_fulfill_htlc-update_fail_htlc-and-update_fail_malformed_htlc)
      * [Committing Updates So Far: `commitment_signed`](#committing-updates-so-far-commitment_signed)
      * [Completing the Transition to the Updated State: `revoke_and_ack`](#completing-the-transition-to-the-updated-state-revoke_and_ack)
      * [Updating Fees: `update_fee`](#updating-fees-update_fee)
    * [Message Retransmission: `channel_reestablish` message](#message-retransmission)
  * [Authors](#authors)

# Channel

## Definition of `channel_id`

Some messages use a `channel_id` to identify the channel. It's
derived from the funding transaction by combining the `funding_txid`
and the `funding_output_index`, using big-endian exclusive-OR
(i.e. `funding_output_index` alters the last 2 bytes).

Prior to channel establishment, a `temporary_channel_id` is used,
which is a random nonce.

Note that as duplicate `temporary_channel_id`s may exist from different
peers, APIs which reference channels by their channel id before the funding
transaction is created are inherently unsafe. The only protocol-provided
identifier for a channel before funding_created has been exchanged is the
(source_node_id, destination_node_id, temporary_channel_id) tuple. Note that
any such APIs which reference channels by their channel id before the funding
transaction is confirmed are also not persistent - until you know the script
pubkey corresponding to the funding output nothing prevents duplicative channel
ids.

### `channel_id`, v2

For channels established using the v2 protocol, the `channel_id` is the
`SHA256(lesser-revocation-basepoint || greater-revocation-basepoint)`,
where the lesser and greater is based off the order of the basepoint.

When sending `open_channel2`, the peer's revocation basepoint is unknown.
A `temporary_channel_id` must be computed by using a zeroed out basepoint
for the non-initiator.

When sending `accept_channel2`, the `temporary_channel_id` from `open_channel2`
must be used, to allow the initiator to match the response to its request.

#### Rationale

The revocation basepoints must be remembered by both peers for correct
operation anyway. They're known after the first exchange of messages,
obviating the need for a `temporary_channel_id` in subsequent messages.
By mixing information from both sides, they avoid `channel_id` collisions,
and they remove the dependency on the funding txid.

## Interactive Transaction Construction

Interactive transaction construction allows two peers to collaboratively
build a transaction for broadcast.  This protocol is the foundation
for dual-funded channels establishment (v2).

### Set-Up and Vocabulary

There are two parties to a transaction construction: an *initiator*
and a *non-initiator*.
The *initiator* is the peer which initiates the protocol, e.g.
for channel establishment v2 the *initiator* would be the peer which
sends `open_channel2`.

The protocol makes the following assumptions:

- The `feerate` for the transaction is known.
- The `dust_limit` for the transaction is known.
- The `nLocktime` for the transaction is known.
- The `nVersion` for the transaction is known.

### Fee Responsibility

The *initiator* is responsible for paying the fees for the following fields,
to be referred to as the `common fields`.

  - version
  - segwit marker + flag
  - input count
  - output count
  - locktime

The rest of the transaction bytes' fees are the responsibility of
the peer who contributed that input or output via `tx_add_input` or
`tx_add_output`, at the agreed upon `feerate`.

### Overview

The *initiator* initiates the interactive transaction construction
protocol with `tx_add_input`. The *non-initiator* responds with any
of `tx_add_input`, `tx_add_output`, `tx_remove_input`, `tx_remove_output`, or
`tx_complete`. The protocol continues with the synchronous exchange
of interactive transaction protocol messages until both nodes have sent
and received a consecutive `tx_complete`. This is a turn-based protocol.

Once peers have exchanged consecutive `tx_complete`s, the
interactive transaction construction protocol is considered concluded.
Both peers should construct the transaction and fail the negotiation
if an error is discovered.

This protocol is expressly designed to allow for parallel, multi-party
sessions to collectively construct a single transaction. This preserves
the ability to open multiple channels in a single transaction. While
`serial_id`s are generally chosen randomly, to maintain consistent transaction
ordering across all peer sessions, it is simplest to reuse received
`serial_id`s when forwarding them to other peers, inverting the bottom bit as
necessary to satisfy the parity requirement.

Here are a few example exchanges.

#### *initiator* only

A, the *initiator*, has two inputs and an output (the funding output).
B, the *non-initiator* has nothing to contribute.

        +-------+                       +-------+
        |       |--(1)- tx_add_input -->|       |
        |       |<-(2)- tx_complete ----|       |
        |       |--(3)- tx_add_input -->|       |
        |   A   |<-(4)- tx_complete ----|   B   |
        |       |--(5)- tx_add_output ->|       |
        |       |<-(6)- tx_complete ----|       |
        |       |--(7)- tx_complete --->|       |
        +-------+                       +-------+

#### *initiator* and *non-initiator*

A, the *initiator*, contributes 2 inputs and an output that they
then remove.  B, the *non-initiator*, contributes 1 input and an output,
but waits until A adds a second input before contributing.

Note that if A does not send a second input, the negotiation will end without
B's contributions.

        +-------+                         +-------+
        |       |--(1)- tx_add_input ---->|       |
        |       |<-(2)- tx_complete ------|       |
        |       |--(3)- tx_add_output --->|       |
        |       |<-(4)- tx_complete ------|       |
        |       |--(5)- tx_add_input ---->|       |
        |   A   |<-(6)- tx_add_input -----|   B   |
        |       |--(7)- tx_remove_output >|       |
        |       |<-(8)- tx_add_output ----|       |
        |       |--(9)- tx_complete ----->|       |
        |       |<-(10) tx_complete ------|       |
        +-------+                         +-------+

### The `tx_add_input` Message

This message contains a transaction input.

1. type: 66 (`tx_add_input`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`u64`:`serial_id`]
    * [`u16`:`prevtx_len`]
    * [`prevtx_len*byte`:`prevtx`]
    * [`u32`:`prevtx_vout`]
    * [`u32`:`sequence`]

#### Requirements

The sending node:
  - MUST add all sent inputs to the transaction
  - MUST use a unique `serial_id` for each input currently added to the
    transaction
  - MUST set `sequence` to be less than or equal to 4294967293 (`0xFFFFFFFD`)
  - MUST NOT re-transmit inputs it has received from the peer
  - if is the *initiator*:
    - MUST send even `serial_id`s
  - if is the *non-initiator*:
    - MUST send odd `serial_id`s

The receiving node:
  - MUST add all received inputs to the transaction
  - MUST fail the negotiation if:
    - `sequence` is set to `0xFFFFFFFE` or `0xFFFFFFFF`
    - the `prevtx` and `prevtx_vout` are identical to a previously added
      (and not removed) input's
    - `prevtx` is not a valid transaction
    - `prevtx_vout` is greater or equal to the number of outputs on `prevtx`
    - the `scriptPubKey` of the `prevtx_vout` output of `prevtx` is not exactly a 1-byte push opcode (for the numeric values `0` to `16`) followed by a data push between 2 and 40 bytes
    - the `serial_id` is already included in the transaction
    - the `serial_id` has the wrong parity
    - if has received 4096 `tx_add_input` messages during this negotiation

#### Rationale

Each node must know the set of the transaction inputs. The *non-initiator*
MAY omit this message.

`serial_id` is a randomly chosen number which uniquely identifies this input.
Inputs in the constructed transaction MUST be sorted by `serial_id`.

`prevtx` is the serialized transaction that contains the output
this input spends. Used to verify that the input is non-malleable.

`prevtx_vout` is the index of the output being spent.

`sequence` is the sequence number of this input: it must signal
replaceability, and the same value should be used across implementations
to avoid on-chain fingerprinting.

#### Liquidity griefing

When sending `tx_add_input`, senders have no guarantee that the remote node
will complete the protocol in a timely manner. Malicious remote nodes could
delay messages or stop responding, which can result in a partially created
transaction that cannot be broadcast by the honest node. If the honest node
is locking the corresponding UTXO exclusively for this remote node, this can
be exploited to lock up the honest node's liquidity.

It is thus recommended that implementations keep UTXOs unlocked and actively
reuse them in concurrent sessions, which guarantees that transactions created
with honest nodes double-spend pending transactions with malicious nodes at
no additional cost for the honest node.

Unfortunately, this will also create conflicts between concurrent sessions
with honest nodes. This is a reasonable trade-off though because:

* on-chain funding attempts are relatively infrequent operations
* honest nodes should complete the protocol quickly, reducing the risk of
  conflicts
* failed attempts can simply be retried at no cost

### The `tx_add_output` Message

This message adds a transaction output.

1. type: 67 (`tx_add_output`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`u64`:`serial_id`]
    * [`u64`:`sats`]
    * [`u16`:`scriptlen`]
    * [`scriptlen*byte`:`script`]

#### Requirements

Either node:
  - MAY omit this message

The sending node:
  - MUST add all sent outputs to the transaction
  - if is the *initiator*:
    - MUST send even `serial_id`s
  - if is the *non-initiator*:
    - MUST send odd `serial_id`s

The receiving node:
  - MUST add all received outputs to the transaction
  - MUST accept P2WSH, P2WPKH, P2TR `script`s
  - MAY fail the negotiation if `script` is non-standard
  - MUST fail the negotiation if:
    - the `serial_id` is already included in the transaction
    - the `serial_id` has the wrong parity
    - it has received 4096 `tx_add_output` messages during this negotiation
    - the `sats` amount is less than the `dust_limit`
    - the `sats` amount is greater than 2,100,000,000,000,000 (`MAX_MONEY`)

#### Rationale

Each node must know the set of the transaction outputs.

`serial_id` is a randomly chosen number which uniquely identifies this output.
Outputs in the constructed transaction MUST be sorted by `serial_id`.

`sats` is the satoshi value of the output.

`script` is the scriptPubKey for the output (with its length omitted).
`script`s are not required to follow standardness rules: non-standard
scripts such as `OP_RETURN` may be accepted, but the corresponding
transaction may fail to relay across the network.

### The `tx_remove_input` and `tx_remove_output` Messages

This message removes an input from the transaction.

1. type: 68 (`tx_remove_input`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`u64`:`serial_id`]

This message removes an output from the transaction.

1. type: 69 (`tx_remove_output`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`u64`:`serial_id`]

#### Requirements

The sending node:
  - MUST NOT send a `tx_remove` with a `serial_id` it did not add
    to the transaction or has already been removed

The receiving node:
  - MUST remove the indicated input or output from the transaction
  - MUST fail the negotiation if:
    - the input or output identified by the `serial_id` was not added by the
      sender
    - the `serial_id` does not correspond to a currently added input (or output)

### The `tx_complete` Message

This message signals the conclusion of a peer's transaction
contributions.

1. type: 70 (`tx_complete`)
2. data:
    * [`channel_id`:`channel_id`]

#### Requirements

The nodes:
  - MUST send this message in succession to conclude this protocol

The receiving node:
  - MUST use the negotiated inputs and outputs to construct a transaction
  - MUST fail the negotiation if:
    - the peer's total input satoshis is less than their outputs. One MUST
      account for the peer's portion of the funding output when verifying
      compliance with this requirement.
    - the peer's paid feerate does not meet or exceed the agreed `feerate`
      (based on the `minimum fee`).
    - if is the *non-initiator*:
      - the *initiator*'s fees do not cover the `common` fields
    - there are more than 252 inputs
    - there are more than 252 outputs
    - the estimated weight of the tx is greater than 400,000 (`MAX_STANDARD_TX_WEIGHT`)

#### Rationale

To signal the conclusion of exchange of transaction inputs and outputs.

Upon successful exchange of `tx_complete` messages, both nodes
should construct the transaction and proceed to the next portion of the
protocol. For channel establishment v2, exchanging commitment transactions.

For the `minimum fee` calculation see [BOLT #3](03-transactions.md#calculating-fees-for-collaborative-transaction-construction).

The maximum inputs and outputs are capped at 252. This effectively fixes
the byte size of the input and output counts on the transaction to one (1).

### The `tx_signatures` Message

1. type: 71 (`tx_signatures`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`sha256`:`txid`]
    * [`u16`:`num_witnesses`]
    * [`num_witnesses*witness`:`witnesses`]

1. subtype: `witness`
2. data:
    * [`u16`:`len`]
    * [`len*byte`:`witness_data`]

#### Requirements

The sending node:
  - if it has the lowest total satoshis contributed, as defined by total
    `tx_add_input` values, or both peers have contributed equal amounts
    but it has the lowest `node_id` (sorted lexicographically):
    - MUST transmit their `tx_signatures` first
  - MUST order the `witnesses` by the `serial_id` of the input they
    correspond to
  - `num_witnesses`s MUST equal the number of inputs they added
  - MUST use the `SIGHASH_ALL` (0x01) flag on each signature

The receiving node:
  - MUST fail the negotiation if:
    - the message contains an empty `witness`
    - the number of `witnesses` does not equal the number of inputs
      added by the sending node
    - the `txid` does not match the txid of the transaction
    - the `witnesses` are non-standard
    - a signature uses a flag that is not `SIGHASH_ALL` (0x01)
  - SHOULD apply the `witnesses` to the transaction and broadcast it
  - MUST reply with their `tx_signatures` if not already transmitted

#### Rationale

A strict ordering is used to decide which peer sends `tx_signatures` first.
This prevents deadlocks where each peer is waiting for the other peer to
send `tx_signatures`, and enables multiparty tx collaboration.

The `witness_data` is encoded as per bitcoin's wire protocol (a CompactSize number
of elements, with each element a CompactSize length and that many bytes following).

While the `minimum fee` is calculated and verified at `tx_complete` conclusion,
it is possible for the fee for the exchanged witness data to be underpaid.
It is the responsibility of the sending peer to correctly account for the
required fee.

### The `tx_init_rbf` Message

This message initiates a replacement of the transaction after it's been
completed.

1. type: 72 (`tx_init_rbf`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u32`:`locktime`]
   * [`u32`:`feerate`]
   * [`tx_init_rbf_tlvs`:`tlvs`]

1. `tlv_stream`: `tx_init_rbf_tlvs`
2. types:
    1. type: 0 (`funding_output_contribution`)
    2. data:
        * [`s64`:`satoshis`]
   1. type: 2 (`require_confirmed_inputs`)

#### Requirements

The sender:
  - MUST set `feerate` greater than or equal to 25/24 times the `feerate`
    of the previously constructed transaction, rounded down.
  - If it contributes to the transaction's funding output:
    - MUST set `funding_output_contribution`
  - If it requires the receiving node to only use confirmed inputs:
    - MUST set `require_confirmed_inputs`

The recipient:
  - MUST respond either with `tx_abort` or with `tx_ack_rbf`
  - MUST respond with `tx_abort` if:
    - the `feerate` is not greater than or equal to 25/24 times `feerate`
      of the last successfully constructed transaction
  - MAY send `tx_abort` for any reason
  - MUST fail the negotiation if:
    - `require_confirmed_inputs` is set but it cannot provide confirmed inputs

#### Rationale

`feerate` is the feerate this transaction will pay. It must be at least
1/24 greater than the last used `feerate`, rounded down to the nearest
satoshi to ensure there is progress.

E.g. if the last `feerate` was 520, the next sent `feerate` must be 541
(520 * 25 / 24 = 541.667, rounded down to 541).

If the previous transaction confirms in the middle of an RBF attempt,
the attempt MUST be abandoned.

`funding_output_contribution` is the amount of satoshis that this peer
will contribute to the funding output of the transaction, when there is
such an output. Note that it may be different from the contribution
made in the previously completed transaction. If omitted, the sender is
not contributing to the funding output.

### The `tx_ack_rbf` Message

1. type: 73 (`tx_ack_rbf`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`tx_ack_rbf_tlvs`:`tlvs`]


1. `tlv_stream`: `tx_ack_rbf_tlvs`
2. types:
    1. type: 0 (`funding_output_contribution`)
    2. data:
        * [`s64`:`satoshis`]
   1. type: 2 (`require_confirmed_inputs`)

#### Requirements

The sender:
  - If it contributes to the transaction's funding output:
    - MUST set `funding_output_contribution`
  - If it requires the receiving node to only use confirmed inputs:
    - MUST set `require_confirmed_inputs`

The recipient:
  - MUST respond with `tx_abort` or with a `tx_add_input` message,
    restarting the interactive tx collaboration protocol.
  - MUST fail the negotiation if:
    - `require_confirmed_inputs` is set but it cannot provide confirmed inputs

#### Rationale

`funding_output_contribution` is the amount of satoshis that this peer
will contribute to the funding output of the transaction, when there is
such an output. Note that it may be different from the contribution
made in the previously completed transaction. If omitted, the sender is
not contributing to the funding output.

It's recommended that a peer, rather than fail the RBF negotiation due to
a large feerate change, instead stop contributing to the funding output,
and decline to participate further in the transaction (by not contributing,
they may obtain incoming liquidity at no cost).

### The `tx_abort` Message

1. type: 74 (`tx_abort`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u16`:`len`]
   * [`len*byte`:`data`]

#### Requirements

A sending node:
  - MUST NOT have already transmitted `tx_signatures`
  - SHOULD forget the current negotiation and reset their state.
  - MAY send an empty `data` field.
  - when failure was caused by an invalid signature check:
    - SHOULD include the raw, hex-encoded transaction in reply to a
      `tx_signatures` or `commitment_signed` message.

A receiving node:
  - if they have already sent `tx_signatures` to the peer:
    - MUST NOT forget the channel until any inputs to the negotiated tx
      have been spent.
  - if they have not sent `tx_signatures`:
    - SHOULD forget the current negotiation and reset their state.
  - if they have not sent `tx_abort`:
    - MUST echo back `tx_abort`
  - if `data` is not composed solely of printable ASCII characters (For
    reference: the printable character set includes byte values 32 through
    126, inclusive):
    - SHOULD NOT print out `data` verbatim.

#### Rationale

A receiving node, if they've already sent their `tx_signatures` has no guarantee
that the transaction won't be signed and published by their peer. They must remember
the transaction and channel (if appropriate) until the transaction is no longer
eligible to be spent (i.e. any input has been spent in a different transaction).

The `tx_abort` message allows for the cancellation of an in progress negotiation,
and a return to the initial starting state. It is distinct from the `error`
message, which triggers a channel close.

Echoing back `tx_abort` allows the peer to ack that they've seen the abort message,
permitting the originating peer to terminate the in-flight process without
worrying about stale messages.

## Channel Establishment v1

After authenticating and initializing a connection ([BOLT #8](08-transport.md)
and [BOLT #1](01-messaging.md#the-init-message), respectively), channel establishment may begin.

There are two pathways for establishing a channel, a legacy version presented here,
and a second version ([below](#channel-establishment-v2)). Which channel
establishment protocols are available for use is negotiated in the `init` message.

This consists of the funding node (funder) sending an `open_channel` message,
followed by the responding node (fundee) sending `accept_channel`. With the
channel parameters locked in, the funder is able to create the funding
transaction and both versions of the commitment transaction, as described in
[BOLT #3](03-transactions.md#bolt-3-bitcoin-transaction-and-script-formats).
The funder then sends the outpoint of the funding output with the `funding_created`
message, along with the signature for the fundee's version of the commitment
transaction. Once the fundee learns the funding outpoint, it's able to
generate the signature for the funder's version of the commitment transaction and send it
over using the `funding_signed` message.

Once the channel funder receives the `funding_signed` message, it
must broadcast the funding transaction to the Bitcoin network. After
the `funding_signed` message is sent/received, both sides should wait
for the funding transaction to enter the blockchain and reach the
specified depth (number of confirmations). After both sides have sent
the `channel_ready` message, the channel is established and can begin
normal operation. The `channel_ready` message includes information
that will be used to construct channel authentication proofs.


        +-------+                              +-------+
        |       |--(1)---  open_channel  ----->|       |
        |       |<-(2)--  accept_channel  -----|       |
        |       |                              |       |
        |   A   |--(3)--  funding_created  --->|   B   |
        |       |<-(4)--  funding_signed  -----|       |
        |       |                              |       |
        |       |--(5)---  channel_ready  ---->|       |
        |       |<-(6)---  channel_ready  -----|       |
        +-------+                              +-------+

        - where node A is 'funder' and node B is 'fundee'

If this fails at any stage, or if one node decides the channel terms
offered by the other node are not suitable, the channel establishment
fails.

Note that multiple channels can operate in parallel, as all channel
messages are identified by either a `temporary_channel_id` (before the
funding transaction is created) or a `channel_id` (derived from the
funding transaction).

### The `open_channel` Message

This message contains information about a node and indicates its
desire to set up a new channel. This is the first step toward creating
the funding transaction and both versions of the commitment transaction.

1. type: 32 (`open_channel`)
2. data:
   * [`chain_hash`:`chain_hash`]
   * [`32*byte`:`temporary_channel_id`]
   * [`u64`:`funding_satoshis`]
   * [`u64`:`push_msat`]
   * [`u64`:`dust_limit_satoshis`]
   * [`u64`:`max_htlc_value_in_flight_msat`]
   * [`u64`:`channel_reserve_satoshis`]
   * [`u64`:`htlc_minimum_msat`]
   * [`u32`:`feerate_per_kw`]
   * [`u16`:`to_self_delay`]
   * [`u16`:`max_accepted_htlcs`]
   * [`point`:`funding_pubkey`]
   * [`point`:`revocation_basepoint`]
   * [`point`:`payment_basepoint`]
   * [`point`:`delayed_payment_basepoint`]
   * [`point`:`htlc_basepoint`]
   * [`point`:`first_per_commitment_point`]
   * [`byte`:`channel_flags`]
   * [`open_channel_tlvs`:`tlvs`]

1. `tlv_stream`: `open_channel_tlvs`
2. types:
    1. type: 0 (`upfront_shutdown_script`)
    2. data:
        * [`...*byte`:`shutdown_scriptpubkey`]
    1. type: 1 (`channel_type`)
    2. data:
        * [`...*byte`:`type`]

The `chain_hash` value denotes the exact blockchain that the opened channel will
reside within. This is usually the genesis hash of the respective blockchain.
The existence of the `chain_hash` allows nodes to open channels
across many distinct blockchains as well as have channels within multiple
blockchains opened to the same peer (if it supports the target chains).

The `temporary_channel_id` is used to identify this channel on a per-peer basis until the
funding transaction is established, at which point it is replaced
by the `channel_id`, which is derived from the funding transaction.

`funding_satoshis` is the amount the sender is putting into the
channel. `push_msat` is an amount of initial funds that the sender is
unconditionally giving to the receiver. `dust_limit_satoshis` is the
threshold below which outputs should not be generated for this node's
commitment or HTLC transactions (i.e. HTLCs below this amount plus
HTLC transaction fees are not enforceable on-chain). This reflects the
reality that tiny outputs are not considered standard transactions and
will not propagate through the Bitcoin network. `channel_reserve_satoshis`
is the minimum amount that the other node is to keep as a direct
payment. `htlc_minimum_msat` indicates the smallest value HTLC this
node will accept.

`max_htlc_value_in_flight_msat` is a cap on total value of outstanding
HTLCs offered by the remote node, which allows the local node to limit its
exposure to HTLCs; similarly, `max_accepted_htlcs` limits the number of
outstanding HTLCs the remote node can offer.

`feerate_per_kw` indicates the initial fee rate in satoshi per 1000-weight
(i.e. 1/4 the more normally-used 'satoshi per 1000 vbytes') that this
side will pay for commitment and HTLC transactions, as described in
[BOLT #3](03-transactions.md#fee-calculation) (this can be adjusted
later with an `update_fee` message).

`to_self_delay` is the number of blocks that the other node's to-self
outputs must be delayed, using `OP_CHECKSEQUENCEVERIFY` delays; this
is how long it will have to wait in case of breakdown before redeeming
its own funds.

`funding_pubkey` is the public key in the 2-of-2 multisig script of
the funding transaction output.

The various `_basepoint` fields are used to derive unique
keys as described in [BOLT #3](03-transactions.md#key-derivation) for each commitment
transaction. Varying these keys ensures that the transaction ID of
each commitment transaction is unpredictable to an external observer,
even if one commitment transaction is seen; this property is very
useful for preserving privacy when outsourcing penalty transactions to
third parties.

`first_per_commitment_point` is the per-commitment point to be used
for the first commitment transaction,

Only the least-significant bit of `channel_flags` is currently
defined: `announce_channel`. This indicates whether the initiator of
the funding flow wishes to advertise this channel publicly to the
network, as detailed within [BOLT #7](07-routing-gossip.md#bolt-7-p2p-node-and-channel-discovery).

The `shutdown_scriptpubkey` allows the sending node to commit to where
funds will go on mutual close, which the remote node should enforce
even if a node is compromised later.

The `option_support_large_channel` is a feature used to let everyone 
know this node will accept `funding_satoshis` greater than or equal to 2^24.
Since it's broadcast in the `node_announcement` message other nodes can use it to identify peers 
willing to accept large channel even before exchanging the `init` message with them. 

#### Defined Channel Types

Channel types are an explicit enumeration: for convenience of future
definitions they reuse even feature bits, but they are not an
arbitrary combination (they represent the persistent features which
affect the channel operation).

The currently defined basic types are:
  - `option_static_remotekey` (bit 12)
  - `option_anchors` and `option_static_remotekey` (bits 22 and 12)

Each basic type has the following variations allowed:
  - `option_scid_alias` (bit 46)
  - `option_zeroconf` (bit 50)

#### Requirements

The sending node:
  - MUST ensure the `chain_hash` value identifies the chain it wishes to open the channel within.
  - MUST ensure `temporary_channel_id` is unique from any other channel ID with the same peer.
  - if both nodes advertised `option_support_large_channel`:
    - MAY set `funding_satoshis` greater than or equal to 2^24 satoshi.
  - otherwise:
    - MUST set `funding_satoshis` to less than 2^24 satoshi.
  - MUST set `push_msat` to equal or less than 1000 * `funding_satoshis`.
  - MUST set `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`, `payment_basepoint`, and `delayed_payment_basepoint` to valid secp256k1 pubkeys in compressed format.
  - MUST set `first_per_commitment_point` to the per-commitment point to be used for the initial commitment transaction, derived as specified in [BOLT #3](03-transactions.md#per-commitment-secret-requirements).
  - MUST set `channel_reserve_satoshis` greater than or equal to `dust_limit_satoshis`.
  - MUST set undefined bits in `channel_flags` to 0.
  - if both nodes advertised the `option_upfront_shutdown_script` feature:
    - MUST include `upfront_shutdown_script` with either a valid `shutdown_scriptpubkey` as required by `shutdown` `scriptpubkey`, or a zero-length `shutdown_scriptpubkey` (ie. `0x0000`).
  - otherwise:
    - MAY include `upfront_shutdown_script`.
  - if it includes `open_channel_tlvs`:
    - MUST include `upfront_shutdown_script`.
  - if `option_channel_type` is negotiated:
    - MUST set `channel_type`
  - if it includes `channel_type`:
    - MUST set it to a defined type representing the type it wants.
    - MUST use the smallest bitmap possible to represent the channel type.
    - SHOULD NOT set it to a type containing a feature which was not negotiated.
    - if `announce_channel` is `true` (not `0`):
      - MUST NOT send `channel_type` with the `option_scid_alias` bit set.

The sending node SHOULD:
  - set `to_self_delay` sufficient to ensure the sender can irreversibly spend a commitment transaction output, in case of misbehavior by the receiver.
  - set `feerate_per_kw` to at least the rate it estimates would cause the transaction to be immediately included in a block.
  - set `dust_limit_satoshis` to a sufficient value to allow commitment transactions to propagate through the Bitcoin network.
  - set `htlc_minimum_msat` to the minimum value HTLC it's willing to accept from this peer.

The receiving node MUST:
  - ignore undefined bits in `channel_flags`.
  - if the connection has been re-established after receiving a previous
 `open_channel`, BUT before receiving a `funding_created` message:
    - accept a new `open_channel` message.
    - discard the previous `open_channel` message.
  - if `option_dual_fund` has been negotiated:
    - fail the channel.

The receiving node MAY fail the channel if:
  - `option_channel_type` was negotiated but the message doesn't include a `channel_type`
  - `announce_channel` is `false` (`0`), yet it wishes to publicly announce the channel.
  - `funding_satoshis` is too small.
  - it considers `htlc_minimum_msat` too large.
  - it considers `max_htlc_value_in_flight_msat` too small.
  - it considers `channel_reserve_satoshis` too large.
  - it considers `max_accepted_htlcs` too small.
  - it considers `dust_limit_satoshis` too large.

The receiving node MUST fail the channel if:
  - the `chain_hash` value is set to a hash of a chain that is unknown to the receiver.
  - `push_msat` is greater than `funding_satoshis` * 1000.
  - `to_self_delay` is unreasonably large.
  - `max_accepted_htlcs` is greater than 483.
  - it considers `feerate_per_kw` too small for timely processing or unreasonably large.
  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`, `payment_basepoint`, or `delayed_payment_basepoint`
are not valid secp256k1 pubkeys in compressed format.
  - `dust_limit_satoshis` is greater than `channel_reserve_satoshis`.
  - `dust_limit_satoshis` is smaller than `354 satoshis` (see [BOLT 3](03-transactions.md#dust-limits)).
  - the funder's amount for the initial commitment transaction is not sufficient for full [fee payment](03-transactions.md#fee-payment).
  - both `to_local` and `to_remote` amounts for the initial commitment transaction are less than or equal to `channel_reserve_satoshis` (see [BOLT 3](03-transactions.md#commitment-transaction-outputs)).
  - `funding_satoshis` is greater than or equal to 2^24 and the receiver does not support `option_support_large_channel`. 
  - It supports `channel_type` and `channel_type` was set:
    - if `type` is not suitable.
    - if `type` includes `option_zeroconf` and it does not trust the sender to open an unconfirmed channel.

The receiving node MUST NOT:
  - consider funds received, using `push_msat`, to be received until the funding transaction has reached sufficient depth.

#### Rationale

The requirement for `funding_satoshis` to be less than 2^24 satoshi was a temporary self-imposed limit while implementations were not yet considered stable, it can be lifted by advertising `option_support_large_channel`.

The *channel reserve* is specified by the peer's `channel_reserve_satoshis`: 1% of the channel total is suggested. Each side of a channel maintains this reserve so it always has something to lose if it were to try to broadcast an old, revoked commitment transaction. Initially, this reserve may not be met, as only one side has funds; but the protocol ensures that there is always progress toward meeting this reserve, and once met, it is maintained.

The sender can unconditionally give initial funds to the receiver using a non-zero `push_msat`, but even in this case we ensure that the funder has sufficient remaining funds to pay fees and that one side has some amount it can spend (which also implies there is at least one non-dust output). Note that, like any other on-chain transaction, this payment is not certain until the funding transaction has been confirmed sufficiently (with a danger of double-spend until this occurs) and may require a separate method to prove payment via on-chain confirmation.

The `feerate_per_kw` is generally only of concern to the sender (who pays the fees), but there is also the fee rate paid by HTLC transactions; thus, unreasonably large fee rates can also penalize the recipient.

Separating the `htlc_basepoint` from the `payment_basepoint` improves security: a node needs the secret associated with the `htlc_basepoint` to produce HTLC signatures for the protocol, but the secret for the `payment_basepoint` can be in cold storage.

The requirement that `channel_reserve_satoshis` is not considered dust
according to `dust_limit_satoshis` eliminates cases where all outputs
would be eliminated as dust.  The similar requirements in
`accept_channel` ensure that both sides' `channel_reserve_satoshis`
are above both `dust_limit_satoshis`.

The receiver should not accept large `dust_limit_satoshis`, as this could be
used in griefing attacks, where the peer publishes its commitment with a lot
of dust htlcs, which effectively become miner fees.

Details for how to handle a channel failure can be found in [BOLT 5:Failing a Channel](05-onchain.md#failing-a-channel).

### The `accept_channel` Message

This message contains information about a node and indicates its
acceptance of the new channel. This is the second step toward creating the
funding transaction and both versions of the commitment transaction.

1. type: 33 (`accept_channel`)
2. data:
   * [`32*byte`:`temporary_channel_id`]
   * [`u64`:`dust_limit_satoshis`]
   * [`u64`:`max_htlc_value_in_flight_msat`]
   * [`u64`:`channel_reserve_satoshis`]
   * [`u64`:`htlc_minimum_msat`]
   * [`u32`:`minimum_depth`]
   * [`u16`:`to_self_delay`]
   * [`u16`:`max_accepted_htlcs`]
   * [`point`:`funding_pubkey`]
   * [`point`:`revocation_basepoint`]
   * [`point`:`payment_basepoint`]
   * [`point`:`delayed_payment_basepoint`]
   * [`point`:`htlc_basepoint`]
   * [`point`:`first_per_commitment_point`]
   * [`accept_channel_tlvs`:`tlvs`]

1. `tlv_stream`: `accept_channel_tlvs`
2. types:
    1. type: 0 (`upfront_shutdown_script`)
    2. data:
        * [`...*byte`:`shutdown_scriptpubkey`]
    1. type: 1 (`channel_type`)
    2. data:
        * [`...*byte`:`type`]

#### Requirements

The `temporary_channel_id` MUST be the same as the `temporary_channel_id` in
the `open_channel` message.

The sender:
  - if `channel_type` includes `option_zeroconf`:
    - MUST set `minimum_depth` to zero.
  - otherwise:
    - SHOULD set `minimum_depth` to a number of blocks it considers reasonable to avoid double-spending of the funding transaction.
  - MUST set `channel_reserve_satoshis` greater than or equal to `dust_limit_satoshis` from the `open_channel` message.
  - MUST set `dust_limit_satoshis` less than or equal to `channel_reserve_satoshis` from the `open_channel` message.
  - if `option_channel_type` was negotiated:
    - MUST set `channel_type` to the `channel_type` from `open_channel`

The receiver:
  - if `minimum_depth` is unreasonably large:
    - MAY fail the channel.
  - if `channel_reserve_satoshis` is less than `dust_limit_satoshis` within the `open_channel` message:
    - MUST fail the channel.
  - if `channel_reserve_satoshis` from the `open_channel` message is less than `dust_limit_satoshis`:
    - MUST fail the channel.
  - if `channel_type` is set, and `channel_type` was set in `open_channel`, and they are not equal types:
    - MUST fail the channel.
  - if `option_channel_type` was negotiated but the message doesn't include a `channel_type`:
    - MAY fail the channel.

Other fields have the same requirements as their counterparts in `open_channel`.

### The `funding_created` Message

This message describes the outpoint which the funder has created for
the initial commitment transactions. After receiving the peer's
signature, via `funding_signed`, it will broadcast the funding transaction.

1. type: 34 (`funding_created`)
2. data:
    * [`32*byte`:`temporary_channel_id`]
    * [`sha256`:`funding_txid`]
    * [`u16`:`funding_output_index`]
    * [`signature`:`signature`]

#### Requirements

The sender MUST set:
  - `temporary_channel_id` the same as the `temporary_channel_id` in the `open_channel` message.
  - `funding_txid` to the transaction ID of a non-malleable transaction,
    - and MUST NOT broadcast this transaction.
  - `funding_output_index` to the output number of that transaction that corresponds the funding transaction output, as defined in [BOLT #3](03-transactions.md#funding-transaction-output).
  - `signature` to the valid signature using its `funding_pubkey` for the initial commitment transaction, as defined in [BOLT #3](03-transactions.md#commitment-transaction).

The sender:
  - when creating the funding transaction:
    - SHOULD use only BIP141 (Segregated Witness) inputs.
    - SHOULD ensure the funding transaction confirms in the next 2016 blocks.

The recipient:
  - if `signature` is incorrect OR non-compliant with LOW-S-standard rule<sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.

#### Rationale

The `funding_output_index` can only be 2 bytes, since that's how it's packed into the `channel_id` and used throughout the gossip protocol. The limit of 65535 outputs should not be overly burdensome.

A transaction with all Segregated Witness inputs is not malleable, hence the funding transaction recommendation.

The funder may use CPFP on a change output to ensure that the funding transaction confirms before 2016 blocks,
otherwise the fundee may forget that channel.

### The `funding_signed` Message

This message gives the funder the signature it needs for the first
commitment transaction, so it can broadcast the transaction knowing that funds
can be redeemed, if need be.

This message introduces the `channel_id` to identify the channel. It's derived from the funding transaction by combining the `funding_txid` and the `funding_output_index`, using big-endian exclusive-OR (i.e. `funding_output_index` alters the last 2 bytes).

1. type: 35 (`funding_signed`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`signature`:`signature`]

#### Requirements

Both peers:
  - if `channel_type` was present in both `open_channel` and `accept_channel`:
    - This is the `channel_type` (they must be equal, required above)
  - otherwise:
    - if `option_anchors` was negotiated:
      - the `channel_type` is `option_anchors` and `option_static_remotekey` (bits 22 and 12)
    - otherwise:
      - the `channel_type` is `option_static_remotekey` (bit 12)
  - MUST use that `channel_type` for all commitment transactions.

The sender MUST set:
  - `channel_id` by exclusive-OR of the `funding_txid` and the `funding_output_index` from the `funding_created` message.
  - `signature` to the valid signature, using its `funding_pubkey` for the initial commitment transaction, as defined in [BOLT #3](03-transactions.md#commitment-transaction).

The recipient:
  - if `signature` is incorrect OR non-compliant with LOW-S-standard rule<sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - MUST NOT broadcast the funding transaction before receipt of a valid `funding_signed`.
  - on receipt of a valid `funding_signed`:
    - SHOULD broadcast the funding transaction.

#### Rationale

We decide on `option_static_remotekey` or `option_anchors` at this point
when we first have to generate the commitment transaction. The feature
bits that were communicated in the `init` message exchange for the current
connection determine the channel commitment format for the total lifetime
of the channel. Even if a later reconnection does not negotiate this
parameter, this channel will continue to use `option_static_remotekey` or
`option_anchors`; we don't support "downgrading".

`option_anchors` is considered superior to `option_static_remotekey`,
and the superior one is favored if more than one is negotiated.

### The `channel_ready` Message

This message (which used to be called `funding_locked`) indicates that the funding transaction has sufficient confirms for channel use. Once both nodes have sent this, the channel enters normal operating mode.

Note that the opener is free to send this message at any time (since it presumably trusts itself), but the
accepter would usually wait until the funding has reached the `minimum_depth` asked for in `accept_channel`.

1. type: 36 (`channel_ready`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`point`:`second_per_commitment_point`]
    * [`channel_ready_tlvs`:`tlvs`]

1. `tlv_stream`: `channel_ready_tlvs`
2. types:
    1. type: 1 (`short_channel_id`)
    2. data:
        * [`short_channel_id`:`alias`]

#### Requirements

The sender:
  - MUST NOT send `channel_ready` unless outpoint of given by `funding_txid` and
   `funding_output_index` in the `funding_created` message pays exactly `funding_satoshis` to the scriptpubkey specified in [BOLT #3](03-transactions.md#funding-transaction-output).
  - if it is not the node opening the channel:
    - SHOULD wait until the funding transaction has reached `minimum_depth` before
      sending this message.
  - MUST set `second_per_commitment_point` to the per-commitment point to be used
  for commitment transaction #1, derived as specified in
  [BOLT #3](03-transactions.md#per-commitment-secret-requirements).
  - if `option_scid_alias` was negotiated:
    - MUST set `short_channel_id` `alias`.
  - otherwise:
    - MAY set `short_channel_id` `alias`.
  - if it sets `alias`:
    - if the `announce_channel` bit was set in `open_channel`:
      - SHOULD initially set `alias` to value not related to the real `short_channel_id`.
    - otherwise:
      - MUST set `alias` to a value not related to the real `short_channel_id`.
    - MUST NOT send the same `alias` for multiple peers or use an alias which
      collides with a `short_channel_id`  of a channel on the same node.
    - MUST always recognize the `alias` as a `short_channel_id` for incoming HTLCs to this channel.
    - if `channel_type` has `option_scid_alias` set:
      - MUST NOT allow incoming HTLCs to this channel using the real `short_channel_id`
    - MAY send multiple `channel_ready` messages to the same peer with different `alias` values.
  - otherwise:
    - MUST wait until the funding transaction has reached `minimum_depth` before sending this message.


The sender:

A non-funding node (fundee):
  - SHOULD forget the channel if it does not see the correct funding
    transaction after a timeout of 2016 blocks.

The receiver:
  - MAY use any of the `alias` it received, in BOLT 11 `r` fields.
  - if `channel_type` has `option_scid_alias` set:
    - MUST NOT use the real `short_channel_id` in BOLT 11 `r` fields.

From the point of waiting for `channel_ready` onward, either node MAY
send an `error` and fail the channel if it does not receive a required response from the
other node after a reasonable timeout.

#### Rationale

The non-funder can simply forget the channel ever existed, since no
funds are at risk. If the fundee were to remember the channel forever, this
would create a Denial of Service risk; therefore, forgetting it is recommended
(even if the promise of `push_msat` is significant).

If the fundee forgets the channel before it was confirmed, the funder will need
to broadcast the commitment transaction to get his funds back and open a new
channel. To avoid this, the funder should ensure the funding transaction
confirms in the next 2016 blocks.

The `alias` here is required for two distinct use cases. The first one is
for routing payments through channels that are not confirmed yet (since
the real `short_channel_id` is unknown until confirmation). The second one
is to provide one or more aliases to use for private channels (even once
a real `short_channel_id` is available).

While a node can send multiple `alias`, it must remember all of the
ones it has sent so it can use them should they be requested by
incoming HTLCs.  The recipient only need remember one, for use in
`r` route hints in BOLT 11 invoices.

If an RBF negotiation is in progress when a `channel_ready` message is
exchanged, the negotiation must be abandoned.

## Channel Establishment v2

This is a revision of the channel establishment protocol.
It changes the previous protocol to allow the `accept_channel2` peer
(the *accepter*/*non-initiator*) to contribute inputs to the funding
transaction, via the interactive transaction construction protocol.

        +-------+                              +-------+
        |       |--(1)--- open_channel2  ----->|       |
        |       |<-(2)--- accept_channel2 -----|       |
        |       |                              |       |
    --->|       |      <tx collaboration>      |       |
    |   |       |                              |       |
    |   |       |--(3)--  commitment_signed -->|       |
    |   |       |<-(4)--  commitment_signed ---|       |
    |   |   A   |                              |   B   |
    |   |       |<-(5)--  tx_signatures -------|       |
    |   |       |--(6)--  tx_signatures ------>|       |
    |   |       |                              |       |
    |   |       |--(a)--- tx_init_rbf -------->|       |
    ----|       |<-(b)--- tx_ack_rbf ----------|       |
        |       |                              |       |
        |       |    <tx rbf collaboration>    |       |
        |       |                              |       |
        |       |--(c)--  commitment_signed -->|       |
        |       |<-(d)--  commitment_signed ---|       |
        |       |                              |       |
        |       |<-(e)--  tx_signatures -------|       |
        |       |--(f)--  tx_signatures ------>|       |
        |       |                              |       |
        |       |--(7)--- channel_ready  ----->|       |
        |       |<-(8)--- channel_ready  ------|       |
        +-------+                              +-------+

        - where node A is *opener*/*initiator* and node B is
          *accepter*/*non-initiator*

### The `open_channel2` Message

This message initiates the v2 channel establishment workflow.

1. type: 64 (`open_channel2`)
2. data:
   * [`chain_hash`:`chain_hash`]
   * [`channel_id`:`temporary_channel_id`]
   * [`u32`:`funding_feerate_perkw`]
   * [`u32`:`commitment_feerate_perkw`]
   * [`u64`:`funding_satoshis`]
   * [`u64`:`dust_limit_satoshis`]
   * [`u64`:`max_htlc_value_in_flight_msat`]
   * [`u64`:`htlc_minimum_msat`]
   * [`u16`:`to_self_delay`]
   * [`u16`:`max_accepted_htlcs`]
   * [`u32`:`locktime`]
   * [`point`:`funding_pubkey`]
   * [`point`:`revocation_basepoint`]
   * [`point`:`payment_basepoint`]
   * [`point`:`delayed_payment_basepoint`]
   * [`point`:`htlc_basepoint`]
   * [`point`:`first_per_commitment_point`]
   * [`point`:`second_per_commitment_point`]
   * [`byte`:`channel_flags`]
   * [`opening_tlvs`:`tlvs`]

1. `tlv_stream`: `opening_tlvs`
2. types:
   1. type: 0 (`upfront_shutdown_script`)
   2. data:
       * [`...*byte`:`shutdown_scriptpubkey`]
   1. type: 1 (`channel_type`)
   2. data:
        * [`...*byte`:`type`]
   1. type: 2 (`require_confirmed_inputs`)

Rationale and Requirements are the same as for [`open_channel`](#the-open_channel-message),
with the following additions.

#### Requirements

If nodes have negotiated `option_dual_fund`:
  - the opening node:
    - MUST NOT send `open_channel`

The sending node:
  - MUST set `funding_feerate_perkw` to the feerate for this transaction
  - If it requires the receiving node to only use confirmed inputs:
    - MUST set `require_confirmed_inputs`

The receiving node:
  - MAY fail the negotiation if:
    - the `locktime` is unacceptable
    - the `funding_feerate_perkw` is unacceptable
  - MUST fail the negotiation if:
    - `require_confirmed_inputs` is set but it cannot provide confirmed inputs

#### Rationale

`temporary_channel_id` MUST be derived using a zeroed out basepoint for the
peer's revocation basepoint. This allows the peer to return channel-assignable
errors before the *accepter*'s revocation basepoint is known.

`funding_feerate_perkw` indicates the fee rate that the opening node will
pay for the funding transaction in satoshi per 1000-weight, as described
in [BOLT-3, Appendix F](03-transactions.md#appendix-f-dual-funded-transaction-test-vectors).

`locktime` is the locktime for the funding transaction.

The receiving node, if the `locktime` or `funding_feerate_perkw` is considered
out of an acceptable range, may fail the negotiation. However, it is
recommended that the *accepter* permits the channel open to proceed
without their participation in the channel's funding.

Note that `open_channel`'s `channel_reserve_satoshi` has been omitted.
Instead, the channel reserve is fixed at 1% of the total channel balance
(`open_channel2`.`funding_satoshis` + `accept_channel2`.`funding_satoshis`)
rounded down to the nearest whole satoshi or the `dust_limit_satoshis`,
whichever is greater.

Note that `push_msat` has been omitted.

`second_per_commitment_point` is now sent here (as well as in `channel_ready`)
as a convenience for implementations.

The sending node may require the other participant to only use confirmed inputs.
This ensures that the sending node doesn't end up paying the fees of a low
feerate unconfirmed ancestor of one of the other participant's inputs.

### The `accept_channel2` Message

This message contains information about a node and indicates its
acceptance of the new channel.

1. type: 65 (`accept_channel2`)
2. data:
    * [`channel_id`:`temporary_channel_id`]
    * [`u64`:`funding_satoshis`]
    * [`u64`:`dust_limit_satoshis`]
    * [`u64`:`max_htlc_value_in_flight_msat`]
    * [`u64`:`htlc_minimum_msat`]
    * [`u32`:`minimum_depth`]
    * [`u16`:`to_self_delay`]
    * [`u16`:`max_accepted_htlcs`]
    * [`point`:`funding_pubkey`]
    * [`point`:`revocation_basepoint`]
    * [`point`:`payment_basepoint`]
    * [`point`:`delayed_payment_basepoint`]
    * [`point`:`htlc_basepoint`]
    * [`point`:`first_per_commitment_point`]
    * [`point`:`second_per_commitment_point`]
    * [`accept_tlvs`:`tlvs`]

1. `tlv_stream`: `accept_tlvs`
2. types:
   1. type: 0 (`upfront_shutdown_script`)
   2. data:
       * [`...*byte`:`shutdown_scriptpubkey`]
   1. type: 1 (`channel_type`)
   2. data:
        * [`...*byte`:`type`]
   1. type: 2 (`require_confirmed_inputs`)

Rationale and Requirements are the same as listed above,
for [`accept_channel`](#the-accept_channel-message) with the following
additions.

#### Requirements

The accepting node:
  - MUST use the `temporary_channel_id` of the `open_channel2` message
  - MAY respond with a `funding_satoshis` value of zero.
  - If it requires the opening node to only use confirmed inputs:
    - MUST set `require_confirmed_inputs`

The receiving node:
  - MUST fail the negotiation if:
    - `require_confirmed_inputs` is set but it cannot provide confirmed inputs

#### Rationale

The `funding_satoshis` is the amount of bitcoin in satoshis
the *accepter* will be contributing to the channel's funding transaction.

Note that `accept_channel`'s `channel_reserve_satoshi` has been omitted.
Instead, the channel reserve is fixed at 1% of the total channel balance
(`open_channel2`.`funding_satoshis` + `accept_channel2`.`funding_satoshis`)
rounded down to the nearest whole satoshi or the `dust_limit_satoshis`,
whichever is greater.

### Funding Composition

Funding composition for channel establishment v2 makes use of the
[Interactive Transaction Construction](#interactive-transaction-construction)
protocol, with the following additional caveats.

#### The `tx_add_input` Message

##### Requirements

The sending node:
  - if the receiver set `require_confirmed_inputs` in `open_channel2`,
    `accept_channel2`, `tx_init_rbf` or `tx_ack_rbf`:
    - MUST NOT send a `tx_add_input` that contains an unconfirmed input

#### The `tx_add_output` Message

##### Requirements

The sending node:
  - if is the *opener*:
    - MUST send at least one `tx_add_output`,  which contains the
      channel's funding output

##### Rationale

The channel funding output must be added by the *opener*, who pays its fees.

#### The `tx_complete` Message

Upon receipt of consecutive `tx_complete`s, the receiving node:
  - if is the *accepter*:
    - MUST fail the negotiation if:
      - no funding output was received
      - the value of the funding output is not equal to the sum of
        `open_channel2`.`funding_satoshis` and `accept_channel2`.
        `funding_satoshis`
      - the value of the funding output is less than the `dust_limit`
  - if this is an RBF attempt:
    - MUST fail the negotiation if:
      - the transaction's total fees is less than the last
        successfully negotiated transaction's fees
      - the transaction does not share at least one input with
        each previous funding transaction
  - if it has sent `require_confirmed_inputs` in `open_channel2`,
    `accept_channel2`, `tx_init_rbf` or `tx_ack_rbf`:
    - MUST fail the negotiation if:
      - one of the inputs added by the other peer is unconfirmed

### The `commitment_signed` Message

This message is exchanged by both peers. It contains the signatures for
the first commitment transaction.

Rationale and Requirements are the same as listed below,
for [`commitment_signed`](#committing-updates-so-far-commitment_signed) with the following additions.

#### Requirements

The sending node:
  - MUST send zero HTLCs.
  - MUST remember the details of this funding transaction.

The receiving node:
  - if the message has one or more HTLCs:
    - MUST fail the negotiation
  - if it has not already transmitted its `commitment_signed`:
    - MUST send `commitment_signed`
  - Otherwise:
    - MUST send `tx_signatures` if it should sign first, as specified
      in the [`tx_signatures` requirements](#the-tx_signatures-message)

#### Rationale

The first commitment transaction has no HTLCs.

Once peers are ready to exchange commitment signatures, they must remember
the details of the funding transaction to allow resuming the signatures
exchange if a disconnection happens.

### Sharing funding signatures: `tx_signatures`

After a valid `commitment_signed` has been received
from the peer and a `commitment_signed` has been sent, a peer:
  - MUST transmit `tx_signatures` with their signatures for the funding
    transaction, following the order specified in the
    [`tx_signatures` requirements](#the-tx_signatures-message)

#### Requirements

The sending node:
  - MUST verify it has received a valid commitment signature from its peer
  - MUST remember the details of this funding transaction
  - if it has NOT received a valid `commitment_signed` message:
    - MUST NOT send a `tx_signatures` message

The receiving node:
  - if has already sent or received a `channel_ready` message for this
    channel:
    - MUST ignore this message
  - if the `witness` weight lowers the effective `feerate`
    below the *opener*'s feerate for the funding transaction and the effective
    `feerate` is determined by the receiving node to be insufficient for
    getting the transaction confirmed in a timely manner:
    - SHOULD broadcast their commitment transaction, closing the channel
    - SHOULD double-spend their channel inputs when there is a productive
      opportunity to do so; effectively canceling this channel open
  - SHOULD apply `witnesses` to the funding transaction and broadcast it

#### Rationale

A peer sends their `tx_signatures` after receiving a valid `commitment_signed`
message, following the order specified in the [`tx_signatures` section](#the-tx_signatures-message).

In the case where a peer provides valid witness data that causes their paid
feerate to fall beneath the `open_channel2.funding_feerate_perkw`, the channel
should be considered failed and the channel should be double-spent when
there is a productive opportunity to do so. This should disincentivize
peers from underpaying fees.

### Fee bumping: `tx_init_rbf` and `tx_ack_rbf`

After the funding transaction has been broadcast, it can be replaced by
a transaction paying more fees to make the channel confirm faster.

#### Requirements

The sender of `tx_init_rbf`:
  - MUST be the *initiator*
  - MUST NOT have sent or received a `channel_ready` message.

The recipient:
  - MUST fail the negotiation if they have already sent or received
    `channel_ready`
  - MAY fail the negotiation for any reason

#### Rationale

If a valid `channel_ready` message is received in the middle of an
RBF attempt, the attempt MUST be abandoned.

Peers can use different values in `tx_init_rbf.funding_output_contribution`
and `tx_ack_rbf.funding_output_contribution` from the amounts transmitted
in `open_channel2` and `accept_channel2`: they are allowed to change how
much they wish to commit to the funding output.

It's recommended that a peer, rather than fail the RBF negotiation due to
a large feerate change, instead sets their `sats` to zero, and decline to
participate further in the channel funding: by not contributing, they
may obtain incoming liquidity at no cost.

## Channel Quiescence

Various fundamental changes, in particular protocol upgrades, are
easiest on channels where both commitment transactions match, and no
pending updates are in flight.  We define a protocol to quiesce the
channel by indicating that "SomeThing Fundamental is Underway".

### `stfu`

1. type: 2 (`stfu`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`u8`:`initiator`]

### Requirements

The sender of `stfu`:
  - MUST NOT send `stfu` unless `option_quiesce` is negotiated.
  - MUST NOT send `stfu` if any of the sender's htlc additions, htlc removals
    or fee updates are pending for either peer.
  - MUST NOT send `stfu` twice.
  - if it is replying to an `stfu`:
    - MUST set `initiator` to 0
  - otherwise:
    - MUST set `initiator` to 1
  - MUST set `channel_id` to the id of the channel to quiesce.
  - MUST now consider the channel to be quiescing.
  - MUST NOT send an update message after `stfu`.

The receiver of `stfu`:
  - if it has sent `stfu` then:
    - MUST now consider the channel to be quiescent
  - otherwise:
    - SHOULD NOT send any more update messages.
    - MUST reply with `stfu` once it can do so.

Both nodes:
  - MUST disconnect after 60 seconds of quiescence if the HTLCs are pending.

Upon disconnection:
  - the channel is no longer considered quiescent.

Dependent Protocols:
  - MUST specify all states that terminate quiescence.
    - NOTE: this prevents batching executions of protocols that depend on
      quiescence.

### Rationale

The normal use would be to cease sending updates, then wait for all
the current updates to be acknowledged by both peers, then start
quiescence.  For some protocols, choosing the initiator matters,
so this flag is sent.

If both sides send `stfu` simultaneously, they will both set
`initiator` to `1`, in which case the "initiator" is arbitrarily
considered to be the channel funder (the sender of `open_channel`).
The quiescence effect is exactly the same as if one had replied to the
other.

Dependent protocols have to specify termination conditions to prevent the need
for disconnection to resume channel traffic. An explicit resume message was
[considered but rejected](https://github.com/rustyrussell/lightning-rfc/pull/14)
since it introduces a number of edge cases that make bilateral consensus of
channel state significantly more complex to maintain. This introduces the
derivative property that it is impossible to batch multiple downstream protocols
in the same quiescence session.

## Channel Close

Nodes can negotiate a mutual close of the connection, which unlike a
unilateral close, allows them to access their funds immediately and
can be negotiated with lower fees.

Closing happens in two stages:
1. one side indicates it wants to clear the channel (and thus will accept no new HTLCs)
2. once all HTLCs are resolved, the final channel close negotiation begins.

        +-------+                                                          +-------+
        |       | shutdown(scriptA1)                                       |       |
        |       |--------------------------------------------------------->|       |
        |       |                                       shutdown(scriptB1) |       |
        |       |<---------------------------------------------------------|       |
        |       |                                                          |       |
        |       |               <complete all pending HTLCs>               |       |
        |   A   |                           ....                           |   B   |
        |       |                                                          |       |
        |       | closing_complete(scriptA1, scriptB1, 1000 sat)           |       |
        |       |--------------------------------------------------------->|       |
        |       |            closing_complete(scriptB1, scriptA1, 750 sat) |       |
        |       |<---------------------------------------------------------|       |
        |       |                closing_sig(scriptA1, scriptB1, 1000 sat) |       |
        |       |<---------------------------------------------------------|       |
        |       | closing_sig(scriptB1, scriptA1, 750 sat)                 |       |
        |       |--------------------------------------------------------->|       |
        |       |                                                          |       |
        |       |                 <A updates their script>                 |       |
        |       |                                                          |       |
        |       | closing_complete(scriptA2, scriptB1, 1100 sat)           |       |
        |       |--------------------------------------------------------->|       |
        |       |                closing_sig(scriptA2, scriptB1, 1100 sat) |       |
        |       |<---------------------------------------------------------|       |
        |       |                                                          |       |
        |       |                           ....                           |       |
        |       |                                                          |       |
        |       |                 <B RBFs their previous tx>               |       |
        |       |                                                          |       |
        |       |            closing_complete(scriptB1, scriptA2, 850 sat) |       |
        |       |<---------------------------------------------------------|       |
        |       | closing_sig(scriptB1, scriptA2, 850 sat)                 |       |
        |       |--------------------------------------------------------->|       |
        |       |                                                          |       |
        |       |                           ....                           |       |
        |       |                                                          |       |
        |       |        <A and B concurrently update their script>        |       | (*) Note that this is a very rare race condition
        |       |                                                          |       |
        |       | closing_complete(scriptA3, scriptB1, 1250 sat)           |       |
        |       |----------------------------->                            |       |
        |       |            closing_complete(scriptB2, scriptA2, 900 sat) |       |
        |       |                   <--------------------------------------|       |
        |       |                                         closing_complete |       |
        |       |                              --------------------------->|       |
        |       |                                                  warning |       | (*) B sends a warning because A is not using scriptB2
        |       |                   <--------------------------------------|       |
        |       | closing_complete                                         |       |
        |       |<------------------                                       |       |
        |       | warning                                                  |       | (*) A sends a warning because B is not using scriptA3
        |       |--------------------------------------------------------->|       |
        |       | warning                                                  |       |
        |       |<------------------                                       |       |
        |       |                                                          |       |
        |       |                       <disconnect>                       |       | (*) A and B reconnect to resolve the race condition
        |       |                                                          |       |
        |       | channel_reestablish                                      |       |
        |       |--------------------------------------------------------->|       |
        |       |                                      channel_reestablish |       |
        |       |<---------------------------------------------------------|       |
        |       | shutdown(scriptA3)                                       |       |
        |       |--------------------------------------------------------->|       |
        |       |                                       shutdown(scriptB2) |       |
        |       |<---------------------------------------------------------|       |
        |       |                                                          |       |
        |       |            <A retries with B's latest script>            |       |
        |       |                                                          |       |
        |       | closing_complete(scriptA3, scriptB2, 1250 sat)           |       |
        |       |--------------------------------------------------------->|       |
        |       |                closing_sig(scriptA3, scriptB2, 1250 sat) |       |
        |       |<---------------------------------------------------------|       |
        |       |                                                          |       |
        |       |            <B retries with A's latest script>            |       |
        |       |                                                          |       |
        |       |            closing_complete(scriptB2, scriptA3, 900 sat) |       |
        |       |<---------------------------------------------------------|       |
        |       | closing_sig(scriptB2, scriptA3, 900 sat)                 |       |
        |       |--------------------------------------------------------->|       |
        |       |                                                          |       |
        +-------+                                                          +-------+

### Closing Initiation: `shutdown`

Either node (or both) can send a `shutdown` message to initiate closing,
along with the `scriptpubkey` it wants to be paid to.

1. type: 38 (`shutdown`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u16`:`len`]
   * [`len*byte`:`scriptpubkey`]

#### Requirements

A sending node:
  - if it hasn't sent a `funding_created` (if it is a funder) or a `funding_signed` (if it is a fundee):
    - MUST NOT send a `shutdown`
  - MAY send a `shutdown` before a `channel_ready`, i.e. before the funding transaction has reached `minimum_depth`.
  - if there are updates pending on the receiving node's commitment transaction:
    - MUST NOT send a `shutdown`.
  - MUST NOT send multiple `shutdown` messages.
  - MUST NOT send an `update_add_htlc` after a `shutdown`.
  - if no HTLCs remain in either commitment transaction (including dust HTLCs)
    and neither side has a pending `revoke_and_ack` to send:
    - MUST NOT send any `update` message after that point.
  - SHOULD fail to route any HTLC added after it has sent `shutdown`.
  - if it sent a non-zero-length `shutdown_scriptpubkey` in `open_channel` or `accept_channel`:
    - MUST send the same value in `scriptpubkey`.
  - MUST set `scriptpubkey` in one of the following forms:

    1. `OP_0` `20` 20-bytes (version 0 pay to witness pubkey hash), OR
    2. `OP_0` `32` 32-bytes (version 0 pay to witness script hash), OR
    3. if (and only if) `option_shutdown_anysegwit` is negotiated:
      * `OP_1` through `OP_16` inclusive, followed by a single push of 2 to 40 bytes
        (witness program versions 1 through 16)
    4. if (and only if) `option_simple_close` is negotiated:
      * `OP_RETURN` followed by one of:
        * `6` to `75` inclusive followed by exactly that many bytes
        * `76` followed by `76` to `80` followed by exactly that many bytes

A receiving node:
  - if it hasn't received a `funding_signed` (if it is a funder) or a `funding_created` (if it is a fundee):
    - SHOULD send an `error` and fail the channel.
  - if the `scriptpubkey` is not in one of the above forms:
    - SHOULD send a `warning`.
  - if it hasn't sent a `channel_ready` yet:
    - MAY reply to a `shutdown` message with a `shutdown`
  - once there are no outstanding updates on the peer, UNLESS it has already sent a `shutdown`:
    - MUST reply to a `shutdown` message with a `shutdown`
  - if both nodes advertised the `option_upfront_shutdown_script` feature, and the receiving node received a non-zero-length `shutdown_scriptpubkey` in `open_channel` or `accept_channel`, and that `shutdown_scriptpubkey` is not equal to `scriptpubkey`:
    - MAY send a `warning`.
    - MUST fail the connection.

#### Rationale

If channel state is always "clean" (no pending changes) when a
shutdown starts, the question of how to behave if it wasn't is avoided:
the sender always sends a `commitment_signed` first.

As shutdown implies a desire to terminate, it implies that no new
HTLCs will be added or accepted.  Once any HTLCs are cleared, there are no commitments
for which a revocation is owed, and all updates are included on both commitment
transactions, the peer may immediately begin closing negotiation, so we ban further
updates to the commitment transaction (in particular, `update_fee` would be
possible otherwise). However, while there are HTLCs on the commitment transaction,
the initiator may find it desirable to increase the feerate as there may be pending
HTLCs on the commitment which could timeout.

The `scriptpubkey` forms include only standard segwit forms accepted by
the Bitcoin network, which ensures the resulting transaction will
propagate to miners. However old nodes may send non-segwit scripts, which
may be accepted for backwards-compatibility (with a caveat to force-close
if this output doesn't meet dust relay requirements).

The `option_upfront_shutdown_script` feature means that the node
wanted to pre-commit to `shutdown_scriptpubkey` in case it was
compromised somehow.  This is a weak commitment (a malevolent
implementation tends to ignore specifications like this one!), but it
provides an incremental improvement in security by requiring the cooperation
of the receiving node to change the `scriptpubkey`.

The `shutdown` response requirement implies that the node sends `commitment_signed` to commit any outstanding changes before replying; however, it could theoretically reconnect instead, which would simply erase all outstanding uncommitted changes.

### Closing Negotiation: `closing_signed`

Once shutdown is complete, the channel is empty of HTLCs, there are no commitments
for which a revocation is owed, and all updates are included on both commitments,
the final current commitment transactions will have no HTLCs, and closing fee
negotiation begins.  The funder chooses a fee it thinks is fair, and
signs the closing transaction with the `scriptpubkey` fields from the
`shutdown` messages (along with its chosen fee) and sends the signature;
the other node then replies similarly, using a fee it thinks is fair.  This
exchange continues until both agree on the same fee or when one side fails
the channel.

In the modern method, the funder sends its permissible fee range, and the
non-funder has to pick a fee in this range. If the non-funder chooses the same
value, negotiation is complete after two messages, otherwise the funder will
reply with the same value (completing after three messages).

1. type: 39 (`closing_signed`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u64`:`fee_satoshis`]
   * [`signature`:`signature`]
   * [`closing_signed_tlvs`:`tlvs`]

1. `tlv_stream`: `closing_signed_tlvs`
2. types:
    1. type: 1 (`fee_range`)
    2. data:
        * [`u64`:`min_fee_satoshis`]
        * [`u64`:`max_fee_satoshis`]

#### Requirements

The funding node:
  - after `shutdown` has been received, AND no HTLCs remain in either commitment transaction:
    - SHOULD send a `closing_signed` message.

The sending node:
  - SHOULD set the initial `fee_satoshis` according to its estimate of cost of
  inclusion in a block.
  - SHOULD set `fee_range` according to the minimum and maximum fees it is
  prepared to pay for a close transaction.
  - if it doesn't receive a `closing_signed` response after a reasonable amount of time:
    - MUST fail the channel
  - if it is not the funder:
    - SHOULD set `max_fee_satoshis` to at least the `max_fee_satoshis` received
    - SHOULD set `min_fee_satoshis` to a fairly low value
  - MUST set `signature` to the Bitcoin signature of the close transaction,
  as specified in [BOLT #3](03-transactions.md#closing-transaction).

The receiving node:
  - if the `signature` is not valid for either variant of closing transaction
  specified in [BOLT #3](03-transactions.md#closing-transaction) OR non-compliant with LOW-S-standard rule<sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if `fee_satoshis` is equal to its previously sent `fee_satoshis`:
    - SHOULD sign and broadcast the final closing transaction.
    - MAY close the connection.
  - if `fee_satoshis` matches its previously sent `fee_range`:
    - SHOULD use `fee_satoshis` to sign and broadcast the final closing transaction
    - SHOULD reply with a `closing_signed` with the same `fee_satoshis` value if it is different from its previously sent `fee_satoshis`
    - MAY close the connection.
  - if the message contains a `fee_range`:
    - if there is no overlap between that and its own `fee_range`:
      - SHOULD send a warning
      - MUST fail the channel if it doesn't receive a satisfying `fee_range` after a reasonable amount of time
    - otherwise:
      - if it is the funder:
        - if `fee_satoshis` is not in the overlap between the sent and received `fee_range`:
          - MUST fail the channel
        - otherwise:
          - MUST reply with the same `fee_satoshis`.
      - otherwise (it is not the funder):
        - if it has already sent a `closing_signed`:
          - if `fee_satoshis` is not the same as the value it sent:
            - MUST fail the channel
        - otherwise:
          - MUST propose a `fee_satoshis` in the overlap between received and (about-to-be) sent `fee_range`.
  - otherwise, if `fee_satoshis` is not strictly between its last-sent `fee_satoshis`
  and its previously-received `fee_satoshis`, UNLESS it has since reconnected:
    - SHOULD send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - otherwise, if the receiver agrees with the fee:
    - SHOULD reply with a `closing_signed` with the same `fee_satoshis` value.
  - otherwise:
    - MUST propose a value "strictly between" the received `fee_satoshis`
    and its previously-sent `fee_satoshis`.

The receiving node:
  - if one of the outputs in the closing transaction is below the dust limit for its `scriptpubkey` (see [BOLT 3](03-transactions.md#dust-limits)):
    - MUST fail the channel

#### Rationale

When `fee_range` is not provided, the "strictly between" requirement ensures
that forward progress is made, even if only by a single satoshi at a time.
To avoid keeping state and to handle the corner case, where fees have shifted
between disconnection and reconnection, negotiation restarts on reconnection.

Note there is limited risk if the closing transaction is
delayed, but it will be broadcast very soon; so there is usually no
reason to pay a premium for rapid processing.

Note that the non-funder is not paying the fee, so there is no reason for it
to have a maximum feerate. It may want a minimum feerate, however, to ensure
that the transaction propagates. It can always use CPFP later to speed up
confirmation if necessary, so that minimum should be low.

It may happen that the closing transaction doesn't meet bitcoin's default relay
policies (e.g. when using a non-segwit shutdown script for an output below 546
satoshis, which is possible if `dust_limit_satoshis` is below 546 satoshis).
No funds are at risk when that happens, but the channel must be force-closed as
the closing transaction will likely never reach miners.

`OP_RETURN` is only standard if followed by PUSH opcodes, and the total script
is 83 bytes or less. We are slightly stricter, to only allow a single PUSH, but
there are two forms in script: one which pushes up to 75 bytes, and a longer
one (`OP_PUSHDATA1`) which is needed for 76-80 bytes.

### Closing Negotiation: `closing_complete` and `closing_sig`

Once shutdown is complete, the channel is empty of HTLCs, there are no commitments
for which a revocation is owed, and all updates are included on both commitments,
the final current commitment transactions will have no HTLCs.

Each peer creates their own closing transaction where they pay the fee, and sends
`closing_complete` to the other peer with the transaction details. The other peer
simply signs that transaction and sends back `closing_sig`. Each peer will thus
independently send `closing_complete` and receive `closing_sig`, resulting in two
independent (but conflicting) closing transactions being created.

The lesser-paid peer (if either is) can opt to omit their own output from the
closing transaction.

This process can be repeated multiple times by sending `closing_complete` again,
which allows increasing the fees and changing the output script.

1. type: 40 (`closing_complete`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u16`:`closer_scriptpubkey_len`]
   * [`closer_scriptpubkey_len*byte`:`closer_scriptpubkey`]
   * [`u16`:`closee_scriptpubkey_len`]
   * [`closee_scriptpubkey_len*byte`:`closee_scriptpubkey`]
   * [`u64`:`fee_satoshis`]
   * [`u32`:`locktime`]
   * [`closing_tlvs`:`tlvs`]

1. type: 41 (`closing_sig`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u16`:`closer_scriptpubkey_len`]
   * [`closer_scriptpubkey_len*byte`:`closer_scriptpubkey`]
   * [`u16`:`closee_scriptpubkey_len`]
   * [`closee_scriptpubkey_len*byte`:`closee_scriptpubkey`]
   * [`u64`:`fee_satoshis`]
   * [`u32`:`locktime`]
   * [`closing_tlvs`:`tlvs`]

1. `tlv_stream`: `closing_tlvs`
2. types:
    1. type: 1 (`closer_output_only`)
    2. data:
        * [`signature`:`sig`]
    1. type: 2 (`closee_output_only`)
    2. data:
        * [`signature`:`sig`]
    1. type: 3 (`closer_and_closee_outputs`)
    2. data:
        * [`signature`:`sig`]

#### Requirements

Note: the details and requirements for the transaction being signed are in [BOLT 3](03-transactions.md#closing-transaction).

An output is *dust* if the amount is less than the [Bitcoin Core Dust Thresholds](03-transactions.md#dust-limits).

Both nodes:
  - After a `shutdown` has been sent and received, AND no HTLCs remain in either commitment transaction:
    - SHOULD send a `closing_complete` message.

The sender of `closing_complete` (aka. "the closer"):
  - MUST set `fee_satoshis` to a fee less than or equal to its outstanding balance, rounded down to whole satoshis.
  - MUST set `fee_satoshis` so that at least one output is not dust.
  - MUST set `closer_scriptpubkey` to its desired output script.
  - MUST set `closee_scriptpubkey` to the last script it received from its peer (from `closing_complete` or from the initial `shutdown`).
  - MUST set `locktime` to the desired `nLockTime` of the closing transaction.
  - MUST generate its closing transaction as specified in [BOLT #3](03-transactions.md#closing-transaction).
  - MUST set `signature` fields as valid signature using its `funding_pubkey` of:
    - `closer_output_only`: closing transaction with only the local ("closer") output.
    - `closee_output_only`: closing transaction with only the remote ("closee") output.
    - `closer_and_closee_outputs`: closing transaction with both the closer and closee outputs.
  - If the local outstanding balance (in millisatoshi) is less than the remote outstanding balance:
    - MUST NOT set `closer_output_only`.
    - MUST set `closee_output_only` if the local output amount is dust.
    - MAY set `closee_output_only` if it considers the local output amount uneconomical AND its `closer_scriptpubkey` is not `OP_RETURN`.
  - Otherwise (not lesser amount, cannot remove its own output):
    - MUST NOT set `closee_output_only`.
    - If the closee's output amount is dust:
      - MUST set `closer_output_only`.
      - SHOULD NOT set `closer_and_closee_outputs`.
    - Otherwise:
      - MUST set both `closer_output_only` and `closer_and_closee_outputs`.
  - If it wants to send another `closing_complete` (e.g. with a different `fee_satoshis` or `closer_scriptpubkey`):
    - MUST wait until it has received `closing_sig` first.
    - SHOULD close the connection if it doesn't receive `closing_sig`.

The receiver of `closing_complete` (aka. "the closee"):
  - If `fee_satoshis` is greater than the closer's outstanding balance:
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - If `closee_scriptpubkey` does not match the last script it sent (from `closing_complete` or from the initial `shutdown`):
    - SHOULD ignore `closing_complete`.
    - SHOULD send a `warning`.
    - SHOULD close the connection.
  - MUST generate the remote closing transaction as specified in [BOLT #3](03-transactions.md#closing-transaction).
  - Select a signature for validation:
    - If the local output amount is dust:
      - MUST use `closer_output_only`.
    - Otherwise, if it considers the local output amount uneconomical AND its `closee_scriptpubkey` is not `OP_RETURN`:
      - MUST use `closer_output_only`.
    - Otherwise, if `closer_and_closee_outputs` is present:
      - MUST use `closer_and_closee_outputs`.
    - Otherwise:
      - MUST use `closee_output_only`.
  - If the selected signature field does not exist:
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - If the signature field is not valid for the corresponding closing transaction specified in [BOLT #3](03-transactions.md#closing-transaction):
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - If the signature field is non-compliant with LOW-S-standard rule<sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>:
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - MUST sign and broadcast the corresponding closing transaction.
  - MUST send `closing_sig` with a single valid signature in the same TLV field as the `closing_complete`.
  - MUST use `closer_scriptpubkey` for its own future `closing_complete` messages.

The receiver of `closing_sig`:
  - If `closer_scriptpubkey`, `closee_scriptpubkey`, `fee_satoshis` or `locktime` don't match what was sent in `closing_complete`:
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - If `tlvs` does not contain exactly one signature:
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - If `tlvs` does not contain one of the TLV fields sent in `closing_complete`:
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - If the signature field is not valid for the corresponding closing transaction specified in [BOLT #3](03-transactions.md#closing-transaction):
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - If the signature field is non-compliant with LOW-S-standard rule<sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>:
    - MUST either send a `warning` and close the connection, or send an `error` and fail the channel.
  - otherwise:
    - MUST broadcast the corresponding closing transaction.
  - MAY send another `closing_complete` (e.g. with a different `fee_satoshis` or `closer_scriptpubkey`).

### Rationale

The close protocol is designed to avoid any failure scenarios caused by fee disagreement,
since each side offers to pay its own desired fee.

If one side has less funds than the other, it may choose to omit its own output, and in this case
dust MUST be omitted, to ensure that the resulting transaction can be broadcast.

The corner case where fees are so high that both outputs are dust is addressed in two ways: paying
a low fee to avoid the problem, or using an `OP_RETURN` (which is never "dust"). If one side
chooses to use an `OP_RETURN` output, its amount must be 0 to ensure that the resulting transaction
can be broadcast.

Note that there is usually no reason to pay a high fee for rapid processing, since an urgent child
could pay the fee on the closing transactions' behalf. If rapid processing is desired and CPFP is
not an option, the closer can RBF its previous closing transactions by sending `closing_complete`
again.

Sending a new `closing_complete` message overrides previous ones, so you can negotiate again (even
changing the output address if `upfront_shutdown_script` was not negotiated). This creates a rare
race condition if both nodes send `closing_complete` to change their `closer_scriptpubkey` at the
same time: when that happens, the `closing_complete` they receive will be using their previous
output script, so they shouldn't sign the corresponding transaction. When that happens, we simply
reconnect, which provides the opportunity for both nodes to send their latest output script in
`shutdown` and restart the signing flow.

If the closer proposes a transaction which will not relay (an output is dust, or the fee rate it
proposes is too low), it doesn't harm the closee to sign the transaction.

Similarly, if the closer proposes a high fee, it doesn't harm the closee to sign the transaction,
as the closer is paying.

There's a slight game where each side would prefer the other side pay the fee, and proposes a
minimal fee. If neither side proposes a fee which will relay, the negotiation can occur again,
or the final commitment transaction can be spent. In practice, the opener has an incentive to
offer a reasonable closing fee, as they would pay the fee for the commitment transaction, which
also costs more to spend.

## Normal Operation

Once both nodes have exchanged `channel_ready` (and optionally [`announcement_signatures`](07-routing-gossip.md#the-announcement_signatures-message)), the channel can be used to make payments via Hashed Time Locked Contracts.

Changes are sent in batches: one or more `update_` messages are sent before a
`commitment_signed` message, as in the following diagram:

        +-------+                               +-------+
        |       |--(1)---- update_add_htlc ---->|       |
        |       |--(2)---- update_add_htlc ---->|       |
        |       |<-(3)---- update_add_htlc -----|       |
        |       |                               |       |
        |       |--(4)--- commitment_signed --->|       |
        |   A   |<-(5)---- revoke_and_ack ------|   B   |
        |       |                               |       |
        |       |<-(6)--- commitment_signed ----|       |
        |       |--(7)---- revoke_and_ack ----->|       |
        |       |                               |       |
        |       |--(8)--- commitment_signed --->|       |
        |       |<-(9)---- revoke_and_ack ------|       |
        +-------+                               +-------+

Counter-intuitively, these updates apply to the *other node's*
commitment transaction; the node only adds those updates to its own
commitment transaction when the remote node acknowledges it has
applied them via `revoke_and_ack`.

Thus each update traverses through the following states:

1. pending on the receiver
2. in the receiver's latest commitment transaction
3. ... and the receiver's previous commitment transaction has been revoked,
   and the update is pending on the sender
4. ... and in the sender's latest commitment transaction
5. ... and the sender's previous commitment transaction has been revoked


As the two nodes' updates are independent, the two commitment
transactions may be out of sync indefinitely. This is not concerning:
what matters is whether both sides have irrevocably committed to a
particular update or not (the final state, above).

### Forwarding HTLCs

In general, a node offers HTLCs for two reasons: to initiate a payment of its own,
or to forward another node's payment. In the forwarding case, care must
be taken to ensure the *outgoing* HTLC cannot be redeemed unless the *incoming*
HTLC can be redeemed. The following requirements ensure this is always true.

The respective **addition/removal** of an HTLC is considered *irrevocably committed* when:

1. The commitment transaction **with/without** it is committed to by both nodes, and any
previous commitment transaction **without/with** it has been revoked, OR
2. The commitment transaction **with/without** it has been irreversibly committed to
the blockchain.

#### Requirements

A node:
  - until an incoming HTLC has been irrevocably committed:
    - MUST NOT offer the corresponding outgoing HTLC (`update_add_htlc`) in response to that incoming HTLC.
  - until the removal of an outgoing HTLC is irrevocably committed, OR until the outgoing on-chain HTLC output has been spent via the HTLC-timeout transaction (with sufficient depth):
    - MUST NOT fail the incoming HTLC (`update_fail_htlc`) that corresponds
to that outgoing HTLC.
  - once the `cltv_expiry` of an incoming HTLC has been reached, OR if `cltv_expiry` minus `current_height` is less than `cltv_expiry_delta` for the corresponding outgoing HTLC:
    - MUST fail that incoming HTLC (`update_fail_htlc`).
  - if an incoming HTLC's `cltv_expiry` is unreasonably far in the future:
    - SHOULD fail that incoming HTLC (`update_fail_htlc`).
  - upon receiving an `update_fulfill_htlc` for an outgoing HTLC, OR upon discovering the `payment_preimage` from an on-chain HTLC spend:
    - MUST fulfill the incoming HTLC that corresponds to that outgoing HTLC.

#### Rationale

In general, one side of the exchange needs to be dealt with before the other.
Fulfilling an HTLC is different: knowledge of the preimage is, by definition,
irrevocable and the incoming HTLC should be fulfilled as soon as possible to
reduce latency.

An HTLC with an unreasonably long expiry is a denial-of-service vector and
therefore is not allowed. Note that the exact value of "unreasonable" is currently unclear
and may depend on network topology.

### `cltv_expiry_delta` Selection

Once an HTLC has timed out, it can either be fulfilled or timed-out;
care must be taken around this transition, both for offered and received HTLCs.

Consider the following scenario, where A sends an HTLC to B, who
forwards to C, who delivers the goods as soon as the payment is
received.

1. C needs to be sure that the HTLC from B cannot time out, even if B becomes
   unresponsive; i.e. C can fulfill the incoming HTLC on-chain before B can
   time it out on-chain.

2. B needs to be sure that if C fulfills the HTLC from B, it can fulfill the
   incoming HTLC from A; i.e. B can get the preimage from C and fulfill the incoming
   HTLC on-chain before A can time it out on-chain.

The critical settings here are the `cltv_expiry_delta` in
[BOLT #7](07-routing-gossip.md#the-channel_update-message) and the
related `min_final_cltv_expiry_delta` in [BOLT #11](11-payment-encoding.md#tagged-fields).
`cltv_expiry_delta` is the minimum difference in HTLC CLTV timeouts, in
the forwarding case (B). `min_final_cltv_expiry_delta` is the minimum difference
between HTLC CLTV timeout and the current block height, for the
terminal case (C).

Note that a node is at risk if it accepts an HTLC in one channel and
offers an HTLC in another channel with too small of a difference between
the CLTV timeouts.  For this reason, the `cltv_expiry_delta` for the
*outgoing* channel is used as the delta across a node.

The worst-case number of blocks between outgoing and
incoming HTLC resolution can be derived, given a few assumptions:

* a worst-case reorganization depth `R` blocks
* a grace-period `G` blocks after HTLC timeout before giving up on
  an unresponsive peer and dropping to chain
* a number of blocks `S` between transaction broadcast and the
  transaction being included in a block

The worst case is for a forwarding node (B) that takes the longest
possible time to spot the outgoing HTLC fulfillment and also takes
the longest possible time to redeem it on-chain:

1. The B->C HTLC times out at block `N`, and B waits `G` blocks until
   it gives up waiting for C. B or C commits to the blockchain,
   and B spends HTLC, which takes `S` blocks to be included.
2. Bad case: C wins the race (just) and fulfills the HTLC, B only sees
   that transaction when it sees block `N+G+S+1`.
3. Worst case: There's reorganization `R` deep in which C wins and
   fulfills. B only sees transaction at `N+G+S+R`.
4. B now needs to fulfill the incoming A->B HTLC, but A is unresponsive: B waits `G` more
   blocks before giving up waiting for A. A or B commits to the blockchain.
5. Bad case: B sees A's commitment transaction in block `N+G+S+R+G+1` and has
   to spend the HTLC output, which takes `S` blocks to be mined.
6. Worst case: there's another reorganization `R` deep which A uses to
   spend the commitment transaction, so B sees A's commitment
   transaction in block `N+G+S+R+G+R` and has to spend the HTLC output, which
   takes `S` blocks to be mined.
7. B's HTLC spend needs to be at least `R` deep before it times out,
   otherwise another reorganization could allow A to timeout the
   transaction.

Thus, the worst case is `3R+2G+2S`, assuming `R` is at least 1. Note that the
chances of three reorganizations in which the other node wins all of them is
low for `R` of 2 or more. Since high fees are used (and HTLC spends can use
almost arbitrary fees), `S` should be small during normal operation; although,
given that block times are irregular, empty blocks still occur, fees may vary
greatly, and the fees cannot be bumped on HTLC transactions, `S=12` should be
considered a minimum. `S` is also the parameter that may vary the most under
attack, so a higher value may be desirable when non-negligible amounts are at
risk. The grace period `G` can be low (1 or 2), as nodes are required to timeout
or fulfill as soon as possible; but if `G` is too low it increases the risk of
unnecessary channel closure due to networking delays.

There are four values that need be derived:

1. the `cltv_expiry_delta` for channels, `3R+2G+2S`: if in doubt, a
   `cltv_expiry_delta` of at least 34 is reasonable (R=2, G=2, S=12).

2. the deadline for offered HTLCs: the deadline after which the channel has to
   be failed and timed out on-chain. This is `G` blocks after the HTLC's
   `cltv_expiry`: 1 or 2 blocks is reasonable.

3. the deadline for received HTLCs this node has fulfilled: the deadline after
   which the channel has to be failed and the HTLC fulfilled on-chain before
   its `cltv_expiry`. See steps 4-7 above, which imply a deadline of `2R+G+S`
   blocks before `cltv_expiry`: 18 blocks is reasonable.

4. the minimum `cltv_expiry` accepted for terminal payments: the
   worst case for the terminal node C is `2R+G+S` blocks (as, again, steps
   1-3 above don't apply). The default in [BOLT #11](11-payment-encoding.md) is
   18, which matches this calculation.

#### Requirements

An offering node:
  - MUST estimate a timeout deadline for each HTLC it offers.
  - MUST NOT offer an HTLC with a timeout deadline before its `cltv_expiry`.
  - if an HTLC which it offered is in either node's current
  commitment transaction, AND is past this timeout deadline:
    - SHOULD send an `error` to the receiving peer (if connected).
    - MUST fail the channel.

A fulfilling node:
  - for each HTLC it is attempting to fulfill:
    - MUST estimate a fulfillment deadline.
  - MUST fail (and not forward) an HTLC whose fulfillment deadline is already past.
  - if an HTLC it has fulfilled is in either node's current commitment
  transaction, AND is past this fulfillment deadline:
    - SHOULD send an `error` to the offering peer (if connected).
    - MUST fail the channel.

### Bounding exposure to trimmed in-flight HTLCs: `max_dust_htlc_exposure_msat`

When an HTLC in a channel is below the "trimmed" threshold in [BOLT3 #3](03-transactions.md),
the HTLC cannot be claimed on-chain, instead being turned into additional miner
fees if either party unilaterally closes the channel. Because the threshold is
per-HTLC, the total exposure to such HTLCs may be substantial if there are many
dust HTLCs committed when the channel is force-closed.

This can be exploited in griefing attacks or even in miner-extractable-value attacks,
if the malicious entity wins <sup>[mining capabilities](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-May/002714.html)</sup>.

The total exposure is given by the following back-of-the-envelope computation:

	remote `max_accepted_htlcs` * (`HTLC-success-kiloweight` * `feerate_per_kw` + remote `dust_limit_satoshis`)
		+ local `max_accepted_htlcs` * (`HTLC-timeout-kiloweight` * `feerate_per_kw` + remote `dust_limit_satoshis`)

To mitigate this scenario, a `max_dust_htlc_exposure_msat` threshold can be
applied when sending, forwarding and receiving HTLCs.

A node:
  - when receiving an HTLC:
    - if the HTLC's `amount_msat` is smaller than the remote `dust_limit_satoshis` plus the HTLC-timeout fee at `feerate_per_kw`:
      - if the `amount_msat` plus the dust balance of the remote transaction is greater than `max_dust_htlc_exposure_msat`:
        - SHOULD fail this HTLC once it's committed
        - SHOULD NOT reveal a preimage for this HTLC
    - if the HTLC's `amount_msat` is smaller than the local `dust_limit_satoshis` plus the HTLC-success fee at `feerate_per_kw`:
      - if the `amount_msat` plus the dust balance of the local transaction is greater than `max_dust_htlc_exposure_msat`:
        - SHOULD fail this HTLC once it's committed
        - SHOULD NOT reveal a preimage for this HTLC
  - when offering an HTLC:
    - if the HTLC's `amount_msat` is smaller than the remote `dust_limit_satoshis` plus the HTLC-success fee at `feerate_per_kw`:
      - if the `amount_msat` plus the dust balance of the remote transaction is greater than `max_dust_htlc_exposure_msat`:
        - SHOULD NOT send this HTLC
        - SHOULD fail the corresponding incoming HTLC (if any)
    - if the HTLC's `amount_msat` is inferior to the holder's `dust_limit_satoshis` plus the HTLC-timeout fee at the `feerate_per_kw`:
      - if the `amount_msat` plus the dust balance of the local transaction is greater than `max_dust_htlc_exposure_msat`:
        - SHOULD NOT send this HTLC
        - SHOULD fail the corresponding incoming HTLC (if any)

The `max_dust_htlc_exposure_msat` is an upper bound on the trimmed balance from
dust exposure. The exact value used is a matter of node policy.

For channels that don't use `option_anchors`, an increase of
the `feerate_per_kw` may trim multiple htlcs from commitment transactions,
which could create a large increase in dust exposure.

### Adding an HTLC: `update_add_htlc`

Either node can send `update_add_htlc` to offer an HTLC to the other,
which is redeemable in return for a payment preimage. Amounts are in
millisatoshi, though on-chain enforcement is only possible for whole
satoshi amounts greater than the dust limit (in commitment transactions these are rounded down as
specified in [BOLT #3](03-transactions.md)).

The format of the `onion_routing_packet` portion, which indicates where the payment
is destined, is described in [BOLT #4](04-onion-routing.md).

1. type: 128 (`update_add_htlc`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u64`:`id`]
   * [`u64`:`amount_msat`]
   * [`sha256`:`payment_hash`]
   * [`u32`:`cltv_expiry`]
   * [`1366*byte`:`onion_routing_packet`]

1. `tlv_stream`: `update_add_htlc_tlvs`
2. types:
    1. type: 0 (`blinded_path`)
    2. data:
        * [`point`:`path_key`]

#### Requirements

A sending node:
  - if it is _responsible_ for paying the Bitcoin fee:
    - MUST NOT offer `amount_msat` if, after adding that HTLC to its commitment
    transaction, it cannot pay the fee for either the local or remote commitment
    transaction at the current `feerate_per_kw` while maintaining its channel
    reserve (see [Updating Fees](#updating-fees-update_fee)).
    - if `option_anchors` applies to this commitment transaction and the sending
    node is the funder:
      - MUST be able to additionally pay for `to_local_anchor` and 
      `to_remote_anchor` above its reserve.
    - SHOULD NOT offer `amount_msat` if, after adding that HTLC to its commitment
    transaction, its remaining balance doesn't allow it to pay the commitment
    transaction fee when receiving or sending a future additional non-dust HTLC
    while maintaining its channel reserve. It is recommended that this "fee spike
    buffer" can handle twice the current `feerate_per_kw` to ensure predictability
    between implementations.
  - if it is _not responsible_ for paying the Bitcoin fee:
    - SHOULD NOT offer `amount_msat` if, once the remote node adds that HTLC to
    its commitment transaction, it cannot pay the fee for the updated local or
    remote transaction at the current `feerate_per_kw` while maintaining its
    channel reserve.
  - MUST offer `amount_msat` greater than 0.
  - MUST NOT offer `amount_msat` below the receiving node's `htlc_minimum_msat`
  - MUST set `cltv_expiry` less than 500000000.
  - if result would be offering more than the remote's
  `max_accepted_htlcs` HTLCs, in the remote commitment transaction:
    - MUST NOT add an HTLC.
  - if the total value of offered HTLCs would exceed the remote's
`max_htlc_value_in_flight_msat`:
    - MUST NOT add an HTLC.
  - for the first HTLC it offers:
    - MUST set `id` to 0.
  - MUST increase the value of `id` by 1 for each successive offer.
  - if it is relaying a payment inside a blinded route:
    - MUST set `path_key` (see [Route Blinding](04-onion-routing.md#route-blinding))

`id` MUST NOT be reset to 0 after the update is complete (i.e. after `revoke_and_ack` has
been received). It MUST continue incrementing instead.

A receiving node:
  - receiving an `amount_msat` equal to 0, OR less than its own `htlc_minimum_msat`:
    - SHOULD send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - receiving an `amount_msat` that the sending node cannot afford at the current `feerate_per_kw` (while maintaining its channel reserve and any `to_local_anchor` and `to_remote_anchor` costs):
    - SHOULD send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if a sending node adds more than receiver `max_accepted_htlcs` HTLCs to
    its local commitment transaction, OR adds more than receiver `max_htlc_value_in_flight_msat` worth of offered HTLCs to its local commitment transaction:
    - SHOULD send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if sending node sets `cltv_expiry` to greater or equal to 500000000:
    - SHOULD send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - MUST allow multiple HTLCs with the same `payment_hash`.
  - if the sender did not previously acknowledge the commitment of that HTLC:
    - MUST ignore a repeated `id` value after a reconnection.
  - if other `id` violations occur:
    - MAY send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - MUST decrypt `onion_routing_packet` as described in [Onion Decryption](04-onion-routing.md#onion-decryption) to extract a `payload`.
    - MUST use `path_key` (if specified).
    - MUST use `payment_hash` as `associated_data`.
  - If decryption fails, the result is not a valid `payload` TLV, or it contains unknown even types:
    - MUST respond with an error as detailed in [Failure Messages](04-onion-routing.md#failure-messages)
  - Otherwise:
    - MUST follow the requirements for the reader of `payload` in [Payload Format](04-onion-routing.md#payload-format)

The `onion_routing_packet` contains an obfuscated list of hops and instructions for each hop along the path.
It commits to the HTLC by setting the `payment_hash` as associated data, i.e. includes the `payment_hash` in the computation of HMACs.
This prevents replay attacks that would reuse a previous `onion_routing_packet` with a different `payment_hash`.

#### Rationale

Invalid amounts are a clear protocol violation and indicate a breakdown.

If a node did not accept multiple HTLCs with the same payment hash, an
attacker could probe to see if a node had an existing HTLC. This
requirement, to deal with duplicates, leads to the use of a separate
identifier; it's assumed a 64-bit counter never wraps.

Retransmissions of unacknowledged updates are explicitly allowed for
reconnection purposes; allowing them at other times simplifies the
recipient code (though strict checking may help debugging).

`max_accepted_htlcs` is limited to 483 to ensure that, even if both
sides send the maximum number of HTLCs, the `commitment_signed` message will
still be under the maximum message size. It also ensures that
a single penalty transaction can spend the entire commitment transaction,
as calculated in [BOLT #5](05-onchain.md#penalty-transaction-weight-calculation).

`cltv_expiry` values equal to or greater than 500000000 would indicate a time in
seconds, and the protocol only supports an expiry in blocks.

The node _responsible_ for paying the Bitcoin fee should maintain a "fee
spike buffer" on top of its reserve to accommodate a future fee increase.
Without this buffer, the node _responsible_ for paying the Bitcoin fee may
reach a state where it is unable to send or receive any non-dust HTLC while
maintaining its channel reserve (because of the increased weight of the
commitment transaction), resulting in a degraded channel. See [#728](https://github.com/lightningnetwork/lightning-rfc/issues/728)
for more details.

### Removing an HTLC: `update_fulfill_htlc`, `update_fail_htlc`, and `update_fail_malformed_htlc`

For simplicity, a node can only remove HTLCs added by the other node.
There are four reasons for removing an HTLC: the payment preimage is supplied,
it has timed out, it has failed to route, or it is malformed.

To supply the preimage:

1. type: 130 (`update_fulfill_htlc`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u64`:`id`]
   * [`32*byte`:`payment_preimage`]

For a timed out or route-failed HTLC:

1. type: 131 (`update_fail_htlc`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u64`:`id`]
   * [`u16`:`len`]
   * [`len*byte`:`reason`]

The `reason` field is an opaque encrypted blob for the benefit of the
original HTLC initiator, as defined in [BOLT #4](04-onion-routing.md);
however, there's a special malformed failure variant for the case where
the peer couldn't parse it: in this case the current node instead takes action, encrypting
it into a `update_fail_htlc` for relaying.

For an unparsable HTLC:

1. type: 135 (`update_fail_malformed_htlc`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u64`:`id`]
   * [`sha256`:`sha256_of_onion`]
   * [`u16`:`failure_code`]

#### Requirements

A node:
  - SHOULD remove an HTLC as soon as it can.
  - SHOULD fail an HTLC which has timed out.
  - until the corresponding HTLC is irrevocably committed in both sides'
  commitment transactions:
    - MUST NOT send an `update_fulfill_htlc`, `update_fail_htlc`, or
`update_fail_malformed_htlc`.
  - When failing an incoming HTLC:
    - If `current_path_key` is set in the onion payload and it is not the
      final node:
      - MUST send an `update_fail_htlc` error using the `invalid_onion_blinding`
        failure code for any local or downstream errors.
      - SHOULD use the `sha256_of_onion` of the onion it received.
      - MAY use an all zero `sha256_of_onion`.
      - SHOULD add a random delay before sending `update_fail_htlc`.
    - If `path_key` is set in the incoming `update_add_htlc`:
      - MUST send an `update_fail_malformed_htlc` error using the
        `invalid_onion_blinding` failure code for any local or downstream errors.
      - SHOULD use the `sha256_of_onion` of the onion it received.
      - MAY use an all zero `sha256_of_onion`.

A receiving node:
  - if the `id` does not correspond to an HTLC in its current commitment transaction:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if the `payment_preimage` value in `update_fulfill_htlc`
  doesn't SHA256 hash to the corresponding HTLC `payment_hash`:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if the `BADONION` bit in `failure_code` is not set for
  `update_fail_malformed_htlc`:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if the `sha256_of_onion` in `update_fail_malformed_htlc` doesn't match the
  onion it sent and is not all zero:
    - MAY retry or choose an alternate error response.
  - otherwise, a receiving node which has an outgoing HTLC canceled by `update_fail_malformed_htlc`:
    - MUST return an error in the `update_fail_htlc` sent to the link which
      originally sent the HTLC, using the `failure_code` given and setting the
      data to `sha256_of_onion`.

#### Rationale

A node that doesn't time out HTLCs risks channel failure (see
[`cltv_expiry_delta` Selection](#cltv_expiry_delta-selection)).

A node that sends `update_fulfill_htlc`, before the sender, is also
committed to the HTLC and risks losing funds.

If the onion is malformed, the upstream node won't be able to extract
the shared key to generate a response — hence the special failure message, which
makes this node do it.

The node can check that the SHA256 that the upstream is complaining about
does match the onion it sent, which may allow it to detect random bit
errors. However, without re-checking the actual encrypted packet sent,
it won't know whether the error was its own or the remote's; so
such detection is left as an option.

Nodes inside a blinded route must use `invalid_onion_blinding` to avoid
leaking information to senders trying to probe the blinded route.

### Committing Updates So Far: `commitment_signed`

When a node has changes for the remote commitment, it can apply them,
sign the resulting transaction (as defined in [BOLT #3](03-transactions.md)), and send a
`commitment_signed` message.

1. type: 132 (`commitment_signed`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`signature`:`signature`]
   * [`u16`:`num_htlcs`]
   * [`num_htlcs*signature`:`htlc_signature`]

#### Requirements

A sending node:
  - MUST NOT send a `commitment_signed` message that does not include any
updates.
  - MAY send a `commitment_signed` message that only
alters the fee.
  - MAY send a `commitment_signed` message that doesn't
change the commitment transaction aside from the new revocation number
(due to dust, identical HTLC replacement, or insignificant or multiple
fee changes).
  - MUST include one `htlc_signature` for every HTLC transaction corresponding
    to the ordering of the commitment transaction (see [BOLT #3](03-transactions.md#transaction-input-and-output-ordering)).
  - if it has not recently received a message from the remote node:
      - SHOULD use `ping` and await the reply `pong` before sending `commitment_signed`.

A receiving node:
  - once all pending updates are applied:
    - if `signature` is not valid for its local commitment transaction OR non-compliant with LOW-S-standard rule <sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>:
      - MUST send a `warning` and close the connection, or send an
        `error` and fail the channel.
    - if `num_htlcs` is not equal to the number of HTLC outputs in the local
    commitment transaction:
      - MUST send a `warning` and close the connection, or send an
        `error` and fail the channel.
  - if any `htlc_signature` is not valid for the corresponding HTLC transaction OR non-compliant with LOW-S-standard rule <sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - MUST respond with a `revoke_and_ack` message.

#### Rationale

There's little point offering spam updates: it implies a bug.

The `num_htlcs` field is redundant, but makes the packet length check fully self-contained.

The recommendation to require recent messages recognizes the reality
that networks are unreliable: nodes might not realize their peers are
offline until after sending `commitment_signed`.  Once
`commitment_signed` is sent, the sender considers itself bound to
those HTLCs, and cannot fail the related incoming HTLCs until the
output HTLCs are fully resolved.

Note that the `htlc_signature` implicitly enforces the time-lock mechanism in
the case of offered HTLCs being timed out or received HTLCs being spent. This
is done to reduce fees by creating smaller scripts compared to explicitly
stating time-locks on HTLC outputs.

The `option_anchors` allows HTLC transactions to "bring their own fees" by
attaching other inputs and outputs, hence the modified signature flags.

### Completing the Transition to the Updated State: `revoke_and_ack`

Once the recipient of `commitment_signed` checks the signature and knows
it has a valid new commitment transaction, it replies with the commitment
preimage for the previous commitment transaction in a `revoke_and_ack`
message.

This message also implicitly serves as an acknowledgment of receipt
of the `commitment_signed`, so this is a logical time for the `commitment_signed` sender
to apply (to its own commitment) any pending updates it sent before
that `commitment_signed`.

The description of key derivation is in [BOLT #3](03-transactions.md#key-derivation).

1. type: 133 (`revoke_and_ack`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`32*byte`:`per_commitment_secret`]
   * [`point`:`next_per_commitment_point`]

#### Requirements

A sending node:
  - MUST set `per_commitment_secret` to the secret used to generate keys for
  the previous commitment transaction.
  - MUST set `next_per_commitment_point` to the values for its next commitment
  transaction.

A receiving node:
  - if `per_commitment_secret` is not a valid secret key or does not generate the previous `per_commitment_point`:
    - MUST send an `error` and fail the channel.
  - if the `per_commitment_secret` was not generated by the protocol in [BOLT #3](03-transactions.md#per-commitment-secret-requirements):
    - MAY send a `warning` and close the connection, or send an
      `error` and fail the channel.

A node:
  - MUST NOT broadcast old (revoked) commitment transactions,
    - Note: doing so will allow the other node to seize all channel funds.
  - SHOULD NOT sign commitment transactions, unless it's about to broadcast
  them (due to a failed connection),
    - Note: this is to reduce the above risk.

### Updating Fees: `update_fee`

An `update_fee` message is sent by the node which is paying the
Bitcoin fee. Like any update, it's first committed to the receiver's
commitment transaction and then (once acknowledged) committed to the
sender's. Unlike an HTLC, `update_fee` is never closed but simply
replaced.

There is a possibility of a race, as the recipient can add new HTLCs
before it receives the `update_fee`. Under this circumstance, the sender may
not be able to afford the fee on its own commitment transaction, once the `update_fee`
is finally acknowledged by the recipient. In this case, the fee will be less
than the fee rate, as described in [BOLT #3](03-transactions.md#fee-payment).

The exact calculation used for deriving the fee from the fee rate is
given in [BOLT #3](03-transactions.md#fee-calculation).

1. type: 134 (`update_fee`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u32`:`feerate_per_kw`]

#### Requirements

The node _responsible_ for paying the Bitcoin fee:
  - SHOULD send `update_fee` to ensure the current fee rate is sufficient (by a
      significant margin) for timely processing of the commitment transaction.

The node _not responsible_ for paying the Bitcoin fee:
  - MUST NOT send `update_fee`.

A sending node:
  - if `option_anchors` was not negotiated:
    - if the `update_fee` increases `feerate_per_kw`:
      - if the dust balance of the remote transaction at the updated `feerate_per_kw` is greater than `max_dust_htlc_exposure_msat`:
        - MAY NOT send `update_fee`
        - MAY fail the channel
      - if the dust balance of the local transaction at the updated `feerate_per_kw` is greater than `max_dust_htlc_exposure_msat`:
        - MAY NOT send `update_fee`
        - MAY fail the channel

A receiving node:
  - if the `update_fee` is too low for timely processing, OR is unreasonably large:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if the sender is not responsible for paying the Bitcoin fee:
    - MUST send a `warning` and close the connection, or send an
      `error` and fail the channel.
  - if the sender cannot afford the new fee rate on the receiving node's
  current commitment transaction:
    - SHOULD send a `warning` and close the connection, or send an
      `error` and fail the channel.
      - but MAY delay this check until the `update_fee` is committed.
    - if `option_anchors` was not negotiated:
      - if the `update_fee` increases `feerate_per_kw`:
        - if the dust balance of the remote transaction at the updated `feerate_per_kw` is greater then `max_dust_htlc_exposure_msat`:
          - MAY fail the channel
      - if the dust balance of the local transaction at the updated `feerate_per_kw` is greater than `max_dust_htlc_exposure_msat`:
          - MAY fail the channel

#### Rationale

Bitcoin fees are required for unilateral closes to be effective.
With `option_anchors`, `feerate_per_kw` is not as critical anymore to guarantee
confirmation as it was in the legacy commitment format, but it still needs to
be enough to be able to enter the mempool (satisfy min relay fee and mempool
min fee).

For the legacy commitment format, there is no general method for the
broadcasting node to use child-pays-for-parent to increase its effective fee.

Given the variance in fees, and the fact that the transaction may be
spent in the future, it's a good idea for the fee payer to keep a good
margin (say 5x the expected fee requirement) for legacy commitment txes; but, due to differing methods of
fee estimation, an exact value is not specified.

Since the fees are currently one-sided (the party which requested the
channel creation always pays the fees for the commitment transaction),
it's simplest to only allow it to set fee levels; however, as the same
fee rate applies to HTLC transactions, the receiving node must also
care about the reasonableness of the fee.

If on-chain fees increase while commitments contain many HTLCs that will
be trimmed at the updated feerate, this could overflow the configured
`max_dust_htlc_exposure_msat`. Whether to close the channel preemptively
or not is left as a matter of node policy.

## Message Retransmission

Because communication transports are unreliable, and may need to be
re-established from time to time, the design of the transport has been
explicitly separated from the protocol.

Nonetheless, it's assumed our transport is ordered and reliable.
Reconnection introduces doubt as to what has been received, so there are
explicit acknowledgments at that point.

This is fairly straightforward in the case of channel establishment
and close, where messages have an explicit order, but during normal
operation, acknowledgments of updates are delayed until the
`commitment_signed` / `revoke_and_ack` exchange; so it cannot be assumed
that the updates have been received. This also means that the receiving
node only needs to store updates upon receipt of `commitment_signed`.

Note that messages described in [BOLT #7](07-routing-gossip.md) are
independent of particular channels; their transmission requirements
are covered there, and besides being transmitted after `init` (as all
messages are), they are independent of requirements here.

1. type: 136 (`channel_reestablish`)
2. data:
   * [`channel_id`:`channel_id`]
   * [`u64`:`next_commitment_number`]
   * [`u64`:`next_revocation_number`]
   * [`32*byte`:`your_last_per_commitment_secret`]
   * [`point`:`my_current_per_commitment_point`]

1. `tlv_stream`: `channel_reestablish_tlvs`
2. types:
    1. type: 0 (`next_funding`)
    2. data:
        * [`sha256`:`next_funding_txid`]

`next_commitment_number`: A commitment number is a 48-bit
incrementing counter for each commitment transaction; counters
are independent for each peer in the channel and start at 0.
They're only explicitly relayed to the other node in the case of
re-establishment, otherwise they are implicit.

### Requirements

A funding node:
  - upon disconnection:
    - if it has broadcast the funding transaction:
      - MUST remember the channel for reconnection.
    - otherwise:
      - SHOULD NOT remember the channel for reconnection.

A non-funding node:
  - upon disconnection:
    - if it has sent the `funding_signed` message:
      - MUST remember the channel for reconnection.
    - otherwise:
      - SHOULD NOT remember the channel for reconnection.

A node:
  - MUST handle continuation of a previous channel on a new encrypted transport.
  - upon disconnection:
    - MUST reverse any uncommitted updates sent by the other side (i.e. all
    messages beginning with `update_` for which no `commitment_signed` has
    been received).
      - Note: a node MAY have already used the `payment_preimage` value from
    the `update_fulfill_htlc`, so the effects of `update_fulfill_htlc` are not
    completely reversed.
  - upon reconnection:
    - if a channel is in an error state:
      - SHOULD retransmit the error packet and ignore any other packets for
      that channel.
    - otherwise:
      - MUST transmit `channel_reestablish` for each channel.
      - MUST wait to receive the other node's `channel_reestablish`
        message before sending any other messages for that channel.

The sending node:
  - MUST set `next_commitment_number` to the commitment number of the
  next `commitment_signed` it expects to receive.
  - MUST set `next_revocation_number` to the commitment number of the
  next `revoke_and_ack` message it expects to receive.
  - MUST set `my_current_per_commitment_point` to a valid point.
  - if `next_revocation_number` equals 0:
    - MUST set `your_last_per_commitment_secret` to all zeroes
  - otherwise:
    - MUST set `your_last_per_commitment_secret` to the last `per_commitment_secret` it received
  - if it has sent `commitment_signed` for an interactive transaction construction but
    it has not received `tx_signatures`:
    - MUST set `next_funding_txid` to the txid of that interactive transaction.
  - otherwise:
    - MUST NOT set `next_funding_txid`.

A node:
  - if `next_commitment_number` is 1 in both the `channel_reestablish` it
  sent and received:
    - MUST retransmit `channel_ready`.
  - otherwise:
    - MUST NOT retransmit `channel_ready`, but MAY send `channel_ready` with
      a different `short_channel_id` `alias` field.
  - upon reconnection:
    - MUST ignore any redundant `channel_ready` it receives.
  - if `next_commitment_number` is equal to the commitment number of
  the last `commitment_signed` message the receiving node has sent:
    - MUST reuse the same commitment number for its next `commitment_signed`.
  - otherwise:
    - if `next_commitment_number` is not 1 greater than the
  commitment number of the last `commitment_signed` message the receiving
  node has sent:
      - SHOULD send an `error` and fail the channel.
    - if it has not sent `commitment_signed`, AND `next_commitment_number`
    is not equal to 1:
      - SHOULD send an `error` and fail the channel.
  - if `next_revocation_number` is equal to the commitment number of
  the last `revoke_and_ack` the receiving node sent, AND the receiving node
  hasn't already received a `closing_signed`:
    - MUST re-send the `revoke_and_ack`.
    - if it has previously sent a `commitment_signed` that needs to be
    retransmitted:
      - MUST retransmit `revoke_and_ack` and `commitment_signed` in the same
      relative order as initially transmitted.
  - otherwise:
    - if `next_revocation_number` is not equal to 1 greater than the
    commitment number of the last `revoke_and_ack` the receiving node has sent:
      - SHOULD send an `error` and fail the channel.
    - if it has not sent `revoke_and_ack`, AND `next_revocation_number`
    is not equal to 0:
      - SHOULD send an `error` and fail the channel.

 A receiving node:
  - MUST ignore `my_current_per_commitment_point`, but MAY require it to be a valid point.
  - if `next_revocation_number` is greater than expected above, AND
    `your_last_per_commitment_secret` is correct for that
    `next_revocation_number` minus 1:
    - MUST NOT broadcast its commitment transaction.
    - SHOULD send an `error` to request the peer to fail the channel.
  - otherwise:
    - if `your_last_per_commitment_secret` does not match the expected values:
      - SHOULD send an `error` and fail the channel.

A receiving node:
  - if `next_funding_txid` is set:
    - if `next_funding_txid` matches the latest interactive funding transaction:
      - if it has not received `tx_signatures` for that funding transaction:
        - MUST retransmit its `commitment_signed` for that funding transaction.
        - if it has already received `commitment_signed` and it should sign first,
          as specified in the [`tx_signatures` requirements](#the-tx_signatures-message):
          - MUST send its `tx_signatures` for that funding transaction.
      - if it has already received `tx_signatures` for that funding transaction:
        - MUST send its `tx_signatures` for that funding transaction.
    - otherwise:
      - MUST send `tx_abort` to let the sending node know that they can forget
        this funding transaction.

A node:
  - MUST NOT assume that previously-transmitted messages were lost,
    - if it has sent a previous `commitment_signed` message:
      - MUST handle the case where the corresponding commitment transaction is
      broadcast at any time by the other side,
        - Note: this is particularly important if the node does not simply
        retransmit the exact `update_` messages as previously sent.
  - upon reconnection:
    - if it has sent a previous `shutdown`:
      - MUST retransmit `shutdown`.

### Rationale

The requirements above ensure that the opening phase is nearly
atomic: if it doesn't complete, it starts again. The only exception
is if the `funding_signed` message is sent but not received. In
this case, the funder will forget the channel, and presumably open
a new one upon reconnection; meanwhile, the other node will eventually forget
the original channel, due to never receiving `channel_ready` or seeing
the funding transaction on-chain.

There's no acknowledgment for `error`, so if a reconnect occurs it's
polite to retransmit before disconnecting again; however, it's not a MUST,
because there are also occasions where a node can simply forget the
channel altogether.

`closing_signed` also has no acknowledgment so must be retransmitted
upon reconnection (though negotiation restarts on reconnection, so it needs
not be an exact retransmission).
The only acknowledgment for `shutdown` is `closing_signed`, so one or the other
needs to be retransmitted.

The handling of updates is similarly atomic: if the commit is not
acknowledged (or wasn't sent) the updates are re-sent. However, it's not
insisted they be identical: they could be in a different order,
involve different fees, or even be missing HTLCs which are now too old
to be added. Requiring they be identical would effectively mean a
write to disk by the sender upon each transmission, whereas the scheme
here encourages a single persistent write to disk for each
`commitment_signed` sent or received. But if you need to retransmit both a
`commitment_signed` and a `revoke_and_ack`, the relative order of these two
must be preserved, otherwise it will lead to a channel closure.

A re-transmittal of `revoke_and_ack` should never be asked for after a
`closing_signed` has been received, since that would imply a shutdown has been
completed — which can only occur after the `revoke_and_ack` has been received
by the remote node.

Note that the `next_commitment_number` starts at 1, since
commitment number 0 is created during opening.
`next_revocation_number` will be 0 until the
`commitment_signed` for commitment number 1 is send and then
the revocation for commitment number 0 is received.

`channel_ready` is implicitly acknowledged by the start of normal
operation, which is known to have begun after a `commitment_signed` has been
received — hence, the test for a `next_commitment_number` greater
than 1.

A previous draft insisted that the funder "MUST remember ...if it has
broadcast the funding transaction, otherwise it MUST NOT": this was in
fact an impossible requirement. A node must either firstly commit to
disk and secondly broadcast the transaction or vice versa. The new
language reflects this reality: it's surely better to remember a
channel which hasn't been broadcast than to forget one which has!
Similarly, for the fundee's `funding_signed` message: it's better to
remember a channel that never opens (and times out) than to let the
funder open it while the fundee has forgotten it.

A node, which has somehow fallen
behind (e.g. has been restored from old backup), can detect that it has fallen
behind. A fallen-behind node must know it cannot broadcast its current
commitment transaction — which would lead to total loss of funds — as the
remote node can prove it knows the revocation preimage. The `error` returned by
the fallen-behind node should make the other node drop its current commitment
transaction to the chain. The other node should wait for that `error` to give
the fallen-behind node an opportunity to fix its state first (e.g by restarting
with a different backup).

`next_funding_txid` allows peers to finalize the signing steps of an
interactive transaction construction, or safely abort that transaction
if it was not signed by one of the peers, who has thus already removed
it from its state.

# Authors

[ FIXME: Insert Author List ]

![Creative Commons License](https://i.creativecommons.org/l/by/4.0/88x31.png "License CC-BY")
<br>
This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
