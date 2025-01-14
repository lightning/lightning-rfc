# Extension Bolt ZZZ: Dynamic Funding Outputs

Authors:
  * Keagan McClelland <keagan@lightning.engineering>
  * Olaoluwa Osuntokun <roasbeef@lightning.engineering>
  * Eugene Siegel <eugene@lightning.engineering>

Created: TODO

# Table of Contents

TODO

# Introduction

## Abstract

This document describes a protocol for changing channel parameters that affect
the funding output script of the channel. Implementation of the protocol
described in this document will enable channel peers to re-negotiate and update
the `funding_pubkey` as well as certain conversions between `channel_type`s
while avoiding UTXO churn therefore preserving the continuity of identity for
the channel whose terms are being changed. This proposal depends on
[Dynamic Commitments](/ext-dynamic-commitments.md).

## Motivation

While the Dynamic Commitments proposal allows for a number of channel parameters
to be changed after it has been opened, it leaves a few of them out because
changing these parameters would require a funding output change.

Notable in particular, is that one of the channel parameters we wish to
renegotiate is the the `channel_type` itself. While certain `channel_type`
conversions are possible with the Dynamic Commitments proposal, one of them that
isn't is converting to Simple Taproot Channels (STCs). With STCs, we have the
opportunity to take advantage of the cost savings and privacy capabilities
afforded by the 2021 Taproot Soft Fork, with further aspirations to be able to
deploy Point Time-Lock Contracts (PTLCs) to the Lightning Network. The sooner
that network participants can upgrade to STCs the more we will have the
necessary network infrastructure to be able to make effective use of PTLCs when
the protocols for them are ready for deployment.

Due to the design of STCs, and the fact that they take full advantage of the
capabilities afforded by Schnorr Signatures, there is no way to construct a
valid `channel_announcement` message that references the output corresponding to
the nodes' joint public key. As such, even if we were to directly spend an
existing funding output to a new STC funding output, and even with the provision
in BOLT 7 to delay graph pruning by 12 blocks after the channel point is spent,
we have no way of advertising the STC to the network at the time of writing of
this proposal.

That said, there is a development effort, concurrent with this, for a new gossip
system that is capable of understanding the announcements of new STCs. However,
even with a new gossip system capable of understanding the STC construction and
announcement, it will take quite some time for such a system to be broadly
deployed across the Lightning Network. In the interim, to combat the
disincentive of upgrading to STCs, this proposal to enable the change of these
channel parameters (including channel types) without requiring channel turnover
is submitted.

## Preliminaries

This proposal includes a detailed section on the preliminaries to document some
of the rationale for the design that is presented later. If you are a Bitcoin
and Lightning Network protocol expert or you are uninterested in the thought
process behind what is presented here, you may wish to skip to the Design
Overview section to save time.

### Channel Opening Parameters

As described in the Dynamic Commitments proposal, during the channel opening
procedure there are a number of parameters specified in the `open_channel` and
`accept_channel` messages that remain static over the lifetime of the channel.
A subset of these are updatable using other messages defined in the protocol.
However, after accounting for the channel parameters that can be changed using
existing mechanisms, there remains a list of parameters which are unchangeable.

- funding_pubkey
- revocation_basepoint
- payment_basepoint
- delayed_payment_basepoint
- htlc_basepoint
- first_per_commitment_point
- channel_flags
- upfront_shutdown
- channel_type<sup>*</sup>

<sup>*</sup>`channel_type` can be updated using Dynamic Commitments only if the
funding output scripts are identical between the `channel_type` prior to the
change and following it.

As mentioned in Dynamic Commitments, we determined that the basepoint values
don't make sense to rotate. There is no obvious value in doing so and it carries
additional administrative costs to rotate them. Finally, changing the
`upfront_shutdown` script over the lifetime of the channel is self-defeating and
so we continue to exclude it as well. The list of channel parameters
remaining after we filter out these values is thus:

- funding_pubkey
- channel_type (~Musig2 Taproot -> Musig2 Taproot)

### Gossip Verification

It is at this point that we need to take a brief detour and review how the
broader Lightning Network comes to discover and verify the existence of public
channels. When the funding transaction for a channel has confirmed, the
participating parties will jointly produce a message that attests to their
ownership of the UTXO and its viability as a routing edge for payment senders.

BOLT 7 details all of the specifics of this message and how it is computed but
one of the notable aspects of this process is that the receivers of these gossip
messages verify that the UTXO underwriting the channel must be a P2WSH output
with a pre-defined script using the participants' public keys, specified in
BOLT 3. This will present issues for us which will become clearer in the next
section.

While alternative gossip systems that can describe STCs are being designed, they
have not been deployed in any known implementation of the Lightning Network
Protocol and even when such a design is implemented, there will be a prolonged
period of time wherein a substantial number of nodes on the network will remain
unable to process messages of this variety, rendering useless any channels that
can only be announced in this manner.

### Taproot

This brings us to talking about what channel constructions are actually
inexpressible by the existing gossip system. As we alluded to earlier, Taproot
channels cannot be discovered using the existing gossip message structure and
interpretation.

In November of 2021 the "Taproot" upgrade was activated on Bitcoin's mainnet,
creating a new output type that is subsequently useful to higher layer protocols
such as the Lightning Network. Since then, the Lightning Network protocol
designers have offered a proposal for a channel construction that makes use of
the Taproot output type. It is beyond the scope of this document to make a
thorough case for why such a channel construction is useful but we assume that
it is for our purposes here.

While Taproot channels are useful, they present some novel challenges with
respect to network-wide interoperability. Notably, a useful Taproot channel
construction must by definition make use of the new Taproot output type, which
does not and cannot use the output script format detailed in BOLT 3 for the
funding output. Pairing this fact with what we described in the previous
section, it is necessarily the case that the funding output of a Taproot channel
cannot be properly announced by the current gossip system.

## Design Overview

The main goal of this proposal is to be able to change all of the channel
parameters that affect the funding output script of the channel.

The key insight in this design is that we extend the concept of a commitment
transaction to include the possibility of a pair of transactions wherein we have
a "kickoff transaction" that is comprised of a single input (the original
funding output) and a single output (the new funding output) and then building
the new commitment transaction off of the new funding output in whatever manner
is detailed in the specification for the target channel type. This may not
always be necessary, but it is certainly necessary for using this proposal to
convert existing channels into Taproot channels.

# Specification

There are two phases to this channel upgrade process: proposal, and execution.
During the proposal phase the only goal is to agree on a set of updates to the
current channel state machine.  The proposal phase is identical to that of
Dynamic Commitments and can be rolled into the same negotiation.

Assuming an agreement can be reached, we will proceed to the execution phase.
During the execution phase, we apply the updates to the channel state machine,
exchanging the necessary information to be able to apply those updates.

## Proposal Phase

As a prerequisite to the proposal phase of a Dynamic Commitment negotiation, the
channel must be in a [quiesced](https://github.com/lightning/bolts/pull/869)
state.

### Node Roles

In every dynamic commitment negotiation, there are two roles: the `initiator`
and the `responder`. It is necessary for both nodes to agree on which node is
the `initiator` and which node is the `responder`. This is important because if
this flavor of dynamic commitment negotiation results in a re-anchoring step
and it is the `initiator` that is responsible for paying the fees for the
kickoff transaction. The `initiator` is determined by who has the `initiator`
role established by the quiescence process.

### Additional Negotiation TLVs

The following TLVs are used throughout the negotiation phase of the protocol
and are common to all messages in the negotiation phase.

#### channel_type

- type: 10
  data:
    * [`...*byte`:`channel_type`]

#### funding_pubkey

- type: 12
  data:
    * [`point`:`funding_pubkey`]

- #### kickoff_feerate_per_kw

- type: 14
  data:
    * [`u32`:`kickoff_feerate_per_kw`]

### Proposal Messages

The proposal messages are reused from Dynamic Commitments.

#### `chan_param_propose`

This message is sent to negotiate the parameters of a dynamic commitment
upgrade. The overall protocol flow is depicted below. This message is always
sent by the `initiator`. The new TLVs above can be sent along with the TLVs
detailed in the original Dynamic Commitments proposal.

        +-------+                                             +-------+
        |       |--(1)---------- chan_param_propose --------->|       |
        |   A   |                                             |   B   |
        |       |<-(4)---{chan_param_ack|chan_param_reject}---|       |
        +-------+                                             +-------+

1. type: 111 (`chan_param_propose`)
2. data:
   * [`32*byte`:`channel_id`]
   * [`chan_param_propose_tlvs`:`tlvs`]

1. `tlv_stream`: `chan_param_propose_tlvs`
2. types:
    1. type: 0 (`dust_limit_satoshis`)
    2. data:
        * [`u64`:`dust_limit_satoshis`]
    1. type: 2 (`max_htlc_value_in_flight_msat`)
    2. data:
        * [`u64`:`senders_max_htlc_value_in_flight_msat`]
    1. type: 4 (`channel_reserve_satoshis`)
    2. data:
        * [`u64`:`recipients_channel_reserve_satoshis`]
    1. type: 6 (`to_self_delay`)
    2. data:
        * [`u16`:`recipients_to_self_delay`]
    1. type: 8 (`max_accepted_htlcs`)
    2. data:
        * [`u16`:`senders_max_accepted_htlcs`]
    1. type: 10 (`channel_type`)
    2. data:
        * [`...*byte`:`channel_type`]
    1. type: 12 (`funding_pubkey`)
    2. data:
        * [`point`:`senders_funding_pubkey`]
    1. type: 14 (`kickoff_feerate_per_kw`)
    2. data:
        * [`u32`:`kickoff_feerate_per_kw`]

##### Requirements

The sending node:
  - MUST conform to all requirements in Dynamic Commitments
  - if either `funding_pubkey` is set or the new `channel_type` and the old
    `channel_type` differ in their funding output scripts:
    - MUST set `kickoff_feerate_per_kw`

The receiving node:
  - MUST conform to all requirements in Dynamic Commitments

##### Rationale

Since the funding output change implies a new transaction that is used to move
the channel funds from the old funding output script to the new one, this
transaction needs to have a mutually agreed upon feerate.

#### `chan_param_ack`

This message is sent in response to a `chan_param_propose` indicating that it
has accepted the proposal.

1. type: 113 (`chan_param_ack`)
2. data:
   * [`32*byte`:`channel_id`]

##### Requirements

The requirements for `chan_param_ack` are identical to those in Dynamic
Commitments.

#### `chan_param_reject`

This message is sent in response to a `chan_param_propose` indicating that it
rejects the proposal.

1. type: 115 (`chan_param_reject`)
2. data:
    * [`32*byte`:`channel_id`]
    * [`...*byte`:`update_rejections`]

##### Requirements

The requirements for `chan_param_reject` are identical to those in Dynamic
Commitments.

## Reestablish

### `channel_reestablish`

A new TLV that denotes the node's current `chan_param_epoch_height` is included.

1. `tlv_stream`: `channel_reestablish_tlvs`
2. types:
    1. type: 20 (`chan_param_epoch_height`)
    2. data:
        * [`u64`:`chan_param_epoch_height`]

#### Requirements

The requirements for `channel_reestablish` are identical to those in Dynamic
Commitments.

## Execution Phase

A Funding Output Update is executed by exchanging signatures for a transaction
that spends the original funding output into a new funding output.
  - NOTE FOR REVIEWERS: This transaction is currently symmetric which burdens
  us with the constraint that a reanchoring step can only be done once over the
  lifetime of the channel. If we want to be able to securely do this multiple
  times, we must make kickoff transactions revocable, and therefore asymmetric,
  and therefore must start issuing commitment signatures in pairs. See Appendix
  for details.

To remain congruent with the Dynamic Commitments proposal, these extra
signature messages should be exchanged exactly once per funding output change
and they should be exchanged during the next commitment signature exchange.

### Funding Output Change: General Protocol

If a Funding Output Change is required, then new commitment signatures AND
kickoff signatures MUST be exchanged. To accomplish this, the following steps
are taken:

1. Build kickoff transaction
1. Build commitment transaction that spends kickoff output
1. Issue a `commitment_signed` message _according to new channel parameters_
1. Upon receipt of the remote party's `commitment_signed` message, issue a
`kickoff_sig` message.
1. Upon receipt of the remote party's `kickoff_sig` message, issue a
`revoke_and_ack` for the _final commitment_ built off of the _original funding
output_.

#### Message flow to upgrade a channel to simple-taproot:

        +-------+                               +-------+
        |       |--(1)---- commit_signed------->|       |
        |       |                               |       |
        |       |<-(2)---- commit_signed -------|       |
        |       |                               |       |
        |       |                               |       |
        |       |<-(3)----- kickoff_sig --------|       |
        |   A   |                               |   B   |
        |       |--(4)----- kickoff_sig ------->|       |
        |       |                               |       |
        |       |                               |       |
        |       |--(5)---- revoke_and_ack ----->|       |
        |       |                               |       |
        |       |<-(6)---- revoke_and_ack ------|       |
        +-------+                               +-------+

##### Rationale

The commitment signed message has to be issued first to ensure that the money
locked to the new funding output (created by the kickoff transaction) can be
unilaterally recovered. If the `kickoff_sig` were sent first, the receiver could
stop responding and broadcast the kickoff transaction, burning the funds for
both parties. If the channel balance is overwhelmingly imbalanced towards the
side issuing the `kickoff_sig`, this could be costly to the victim while being
comparatively cheap for the attacker.

Similarly, if we `revoke_and_ack` prior to receiving a `kickoff_sig` then we
may have a situation where we remove our ability to broadcast the old commitment
transaction before the path to the new commitment transaction has been fully
signed.

#### Building the Kickoff Transaction

##### Kickoff Transaction Structure

* version: 2
* locktime: 0
* txin count: 1
  * `txin[0]` outpoint: `txid` and `output_index` from `funding_created` message
  * `txin[0]` sequence: 0xfffffffd
  * `txin[0]` script bytes: 0
  * `txin[0]` witness: `0 <signature_for_pubkey1> <signature_for_pubkey2>`
* txout count: 3
  * `txout[0]`: `anchor_output_1` or `anchor_output_2`
  * `txout[1]`: `anchor_output_1` or `anchor_output_2`
  * `txout[2]`: `kickoff_funding_output`

The anchor outputs have a value of 330 satoshis. They are encumbered by a
version 1 witness script:
* `OP_1 anchor_output_key`
* where:
  * `anchor_internal_key = original_local_funding_pubkey/original_remote_funding_pubkey`
  * `anchor_output_key = anchor_internal_key + tagged_hash("TapTweak", anchor_internal_key || anchor_script_root)`
  * `anchor_script_root = tapscript_root([anchor_script])`
  * `anchor_script`:
        ```
        OP_16 OP_CHECKSEQUENCEVERIFY
        ```

The new funding output has a value of the original funding output minus the sum
of 660 satoshis and this kickoff transaction's fee. It is encumbered by a
version 1 witness script where `taproot_funding_key1/taproot_funding_key2` are
from `chan_param_ack`:
* `OP_1 funding_key`
* where:
  * `funding_key = combined_funding_key + tagged_hash("TapTweak", combined_funding_key)*G`
  * `combined_funding_key = musig2.KeyAgg(musig2.KeySort(taproot_funding_key1, taproot_funding_key2))`

##### Kickoff Transaction Construction Algorithm

1. Initialize the commitment transaction version and locktime.
2. Initialize the commitment transaction input.
3. Calculate this kickoff transaction's fee via `kickoff_feerate_per_kw`*
  `kickoff_transaction_weight`/1000, making sure to round down. Subtract this
  value from the new funding output.
5. Subtract two times the fixed anchor size of 330 satoshis from the new funding
  output.
6. Add a funding output with the new funding amount.
7. Add an anchor output for each party.
8. Sort the outputs into BIP 69+CLTV order.

#### Building the Commitment Transaction

##### Commitment Transaction Structure

* version: 2
* locktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the
  obscured commitment number
* txin count: 1
  * `txin[0]` outpoint: the `kickoff_funding_output`
  * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits
    of the obscured commitment number
  * `txin[0]` script bytes: 0
  * `txin[0]` witness: `<key_path_sig>`

The 48-bit commitment number is computed by `XOR` as described in BOLT#03.

##### Commitment Transaction Construction Algorithm

1. Initialize the commitment transaction version and locktime.
2. Initialize the commitment transaction input.
3. Calculate which committed HTLCs need to be trimmed.
4. Calculate the commitment transaction fee via
  commitment feerate * `commitment_transaction_weight`/1000, making sure to
  round down. Subtract this from the funder's output.
5. Subtract four times the fixed anchor size of 330 satoshis from the funder's
  output. Two of the anchors are from the commitment transaction and two are
  from the kickoff transaction.
6. Subtract the matching kickoff transaction's fee from the funder's output.
7. For every offered HTLC, if it is not trimmed, add an offered HTLC output.
8. For every received HTLC, if it is not trimmed, add a received HTLC output.
9. If the `to_local` output is greater or equal to the dust limit, add a
  `to_local` output.
10. If the `to_remote` output is greater or equal to the dust limit, add a
  `to_remote` output.
11. If `to_local` exists or there are untrimmed HTLCs, add a `to_local_anchor`.
12. If `to_remote` exists or there are untrimmed HTLCs, add a
  `to_remote_anchor`. The `to_remote_anchor` uses the remote party's
  `taproot_funding_key`.
13. Sort the outputs into BIP 69+CLTV order.

#### Issuing the `commitment_signed` message

Commitment signed messages are exchanged as normal with the exception of a
different construction procedure detailed in the prior step. NOTE: "as normal"
means that this message MUST include all TLVs that would be required for
the updated `channel_type` e.g. Musig2 Taproot.

#### Issuing the `kickoff_sig` message

##### kickoff_sig

The kickoff_sig is a message containing a signature that the fundee sends to the
funder who then combines it with their own signature to spend from the original
funding outpoint into the new musig2 output. To keep things simple, no
additional inputs are added to the intermediate transaction. An anchor output is
attached to either side for fee-bumping.

![Cannot display image](./dynamic-commits/kickoff%20tx.png "Kickoff transaction")

1. type: 777 (`kickoff_sig`)
2. data:
   * [`32*byte`:`channel_id`]
   * [`signature`:`signature`]

##### Requirements

The sending node:
  - MUST set `channel_id` to a valid channel it has with the recipient.
  - MUST NOT send this message before receiving the peer's `commitment_signed`.

The receiving node:
  - MUST send an `error` and fail the channel if `channel_id` does not match an
    existing channel it has with the sender.
  - MUST send an `error` and fail the channel if `signature` is not valid for
    the kickoff transaction as constructed above OR non-compliant with the
    LOW-S-standard rule. <sup>[LOWS](https://github.com/bitcoin/bitcoin/pull/6769)</sup>
  - MUST NOT send a `revoke_and_ack` for the final pre-dynamic commitment
    transaction until it has received a valid `kickoff_sig`

##### Rationale

The `kickoff_sig` cannot be issued until the `commitment_signed` message has
been received to prevent griefing by broadcasting a kickoff for which there is
no exit. The `revoke_and_ack` for the last pre-dynamic commitment has to wait
for the `kickoff_sig` because if the last commitment built off of the original
funding output is revoked before the `kickoff_sig` has been received, then if
a peer becomes non-cooperative from that point forward, funds are effectively
burned.

### Additional Requirements: ~Musig2 Taproot -> Musig2 Taproot

This section describes how dynamic commitments can upgrade regular channels to
simple taproot channels. The regular dynamic proposal phase is executed followed
by a signing phase. A `channel_type` of `option_taproot` will be included in
`chan_param_propose` and both sides must agree on it. The `initiator` of the upgrade
will also propose a feerate to use for an intermediate "kickoff" transaction.

#### Required `chan_param_propose` TLVs:

1. `tlv_stream`: `chan_param_propose_tlvs`
2. types:
    1. type: 10 (`channel_type`)
    2. data:
        * [`...*byte`:`type`]
    1. type: 12 (`funding_pubkey`)
    2. data:
        * [`point`:`senders_funding_pubkey`]
    1. type: 14 (`kickoff_feerate`)
    2. data:
        * [`u32`:`kickoff_feerate_per_kw`]
    1. type: 16 (`local_musig2_pubnonce`)
    2. data:
        * [`66*byte`:`nonces`]

#### Requirements

The sending node:
  - if it is the `initiator`:
    - MUST only send `kickoff_feerate` if they can pay for the kickoff
      transaction fee and the anchor outputs, while adhering to the
      `channel_reserve` restriction.
  - MUST set `funding_pubkey` to a valid secp256k1 compressed public key.
  - MUST set `local_musig2_pubnonce` to the nonce that it will use to verify
    local commitments.
  - SHOULD use a sufficiently high `kickoff_feerate` to be prepared for
    worst-case fee environment scenarios.
    - *NOTE FOR REVIEWERS*: We can also add a message to update the kickoff fee
    rate if we have revocable kickoffs, similar to `update_fee` for commitment
    transactions to make sure the kickoff has a sufficient fee to enter the
    mempool. Anchors can be used to fee bump the kickoff beyond the min mempool
    fee. Revocable kickoffs are possible but significantly increase the design
    complexity.
  - if it is proposing a `channel_type` of `simple_taproot_channel`:

The receiving node:
  - if it is the `responder`:
    - MUST reject the `chan_param_propose` if the `initiator` cannot pay for the kickoff
      transaction fee and the anchor outputs.
    - MUST reject the `chan_param_propose` if, after calculating the amount of the new
      funding output, the new commmitment transaction would not be able to pay
      for any outputs at the current commitment feerate.
  - MUST reject the `chan_param_propose` if `taproot_funding_key` is not a valid
    secp256k1 compressed public key.
  - MAY reject the `chan_param_propose` if it does not agree with the `channel_type`
  - MUST send an `error` and fail the channel if `local_musig2_pubnonce` cannot
    be parsed as two compressed secp256k1 points.

#### Rationale

The `chan_param_propose` renegotiates the funding keys as otherwise signatures for the
funding keys would be exchanged in both the ECDSA and Schnorr contexts. This can
lead to an attack outlined in [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#alternative-signing).
Renegotiating funding keys avoids this issue. Note that the various basepoints
exchanged in `open_channel` and `accept_channel` are not renegotiated. Because
the private keys _change_ with each commitment transaction they sign due to the
`per_commitment_point` construction, the basepoints can be used in both ECDSA
and Schnorr contexts.

#### Extensions to `chan_param_ack`:

1. `tlv_stream`: `chan_param_ack_tlvs`
2. types:
    1. type: 0 (`local_musig2_pubnonce`)
    2. data:
        * [`66*byte`:`nonces`]

#### Requirements

The sending node:
  - if it is accepting a `channel_type` of `simple_taproot_channel`:
    - MUST set `local_musig2_pubnonce` to the nonce that it will use to verify
      local commitments.

The receiving node:
  - MUST send an `error` and fail the channel if `local_musig2_pubnonce` cannot
    be parsed as two compressed secp256k1 points.

# Appendix

## Pinning

![Cannot display image](./dynamic-commits/kickoff%20pinning.png "Kickoff transaction pinned")

Originally, Bitcoin Core's default mempool settings allowed an unconfirmed
transaction to have up to 25 decendants in the mempool. Past this limit, any
descendants would be rejected. This was used as a DoS mitigation in Bitcoin Core
and affected the security of LN channels. Before the anchors commitment type was
introduced, pinning in the LN was where a counterparty broadcasted the
commitment transaction and created a chain of 25 descendants spending from one
of the commitment's outputs. The time-sensitive commitment transaction could be
"pinned" to the bottom of the mempool.  This was addressed with a change to
Bitcoin Core called CPFP Carve-out.

### CPFP Carve-out

CPFP Carve-out was introduced to Bitcoin Core in
https://github.com/bitcoin/bitcoin/pull/15681. If a Bitcoin node receives a
transaction that is rejected due to any of the mempool size or
ancestor/descendant restrictions being hit, it will try to accept the
transaction again. This second try will succeed only if:
  - the transaction is 40kWU or less
  - it has only one ancestor in the mempool

This change, in conjunction with the anchor commitment type, decreases the
efficacy of the pinning attack since the honest party can still attach an anchor
despite the descendant size limit being hit.

### Dynamic Commitments & CPFP Carve-out

The safety guarantees of CPFP Carve-out break due to the structure of the
kickoff transaction.  The kickoff transaction contains 3 spendable outputs: the
local party's anchor, the remote party's anchor, and the new funding output. All
three of these outputs can be spent immediately.  A malicious counterparty can
pin the kickoff transaction by:
  - spending from their anchor output to create a descendant chain of 25
    transactions _AND_
  - spending from the new funding output using the new commitment transaction,
    "using up" the CPFP Carve-out slot designated for the honest party.
_NOTE FOR REVIEWERS_: The semantics of CPFP carve-out are not entirely clear
as to whether or not there is only _one_ CPFP-Carve-Out "slot" or if the only
two requirements are the 40kWU limit and a single unconfirmed ancestor. If we
have more than one "slot" available, this is no longer a concern.

Depending on fee conditions, it may not be possible for the honest party to get
these transactions confirmed until the mempool clears up.

If we were to get rid of the kickoff transaction's anchor outputs, the problem
still arises. A malicious counterparty could still pin the kickoff transaction
by:
  - broadcasting the commitment transaction
  - spending from their commitment anchor output and creating a descendant chain
    of 25 transactions

The honest party is unable to use their anchor on the commitment transaction as:
  - the descendant limit of 25 transactions has been hit
  - the anchor spend would have 2 ancestors (the commitment and kickoff
    transactions)

### Reducing Risk

The above pinning scenarios highlight the complexity of second-layer protocols
and mempool restrictions. In this proposal, pinning is _still_ possible, but
risk can be controlled if nodes reduce their max_htlc_value_in_flight_msat
values while the kickoff transaction is unconfirmed

If we allow adding HTLCs _before_ the kickoff transaction confirmed on-chain,
the pinning attack has a tangible benefit: the ability to steal the value of an
HTLC.

### Asymmetric Kickoffs

The above proposal specifies a process wherein we can reanchor the funding
output exactly once. This is because even if we revoke all commitment
transactions built off of the first kickoff transaction, we still are vulnerable
to griefing if we do not revoke the kickoff transaction itself. In this case
one party may choose to burn all funds in a channel by broadcasting the kickoff
transaction when no unrevoked commitment transactions remain. To deal with this
we can either only reanchor once, as proposed above, allowing us to guarantee we
will never encounter a situation where there are no valid commitment
transactions, or we can make the kickoff transactions revocable.

To make them revocable we can reuse the same scheme that we use for commitment
transactions. In this case Alice's kickoff transaction would allow Bob to claim
all funds if Bob knows Alice's revocation secret. Similarly, Alice could claim
all channel funds if Bob broadcasts his kickoff transaction and Alice knows
Bob's revocation secret.

An unfortunate consequence of this scheme is that since we now have two possible
"new" funding outputs (one for each of the potential kickoff transactions), we
now have to send all of our commitment signatures in pairs. At any given time
there would be four valid commitment transactions:

1. Alice's commitment built off of Alice's kickoff
2. Alice's commitment built off of Bob's kickoff
3. Bob's commitment built off of Alice's kickoff
4. Bob's commitment built off of Bob's kickoff

_NOTE FOR REVIEWERS_: There may be an opportunity to make the kickoff
transactions symmetric while still allowing them to be revocable using adaptor
signature tricks, but this will require more research from those with a deeper
understanding of the cryptographic primitives.

## Weights

Since DER-encoded signatures vary in size, we assume a worst-case signature size
of 73 bytes to keep things simple. The kickoff transaction has an
_expected weight_ of 944WU and the commitment transaction has an
_expected weight_ of 960WU.

General weights:
  * p2tr: 34 bytes
      - OP_1: 1 byte
      - OP_DATA: 1 byte (witness_script_SHA256 length)
      - witness_script_SHA256: 32 bytes

  * witness_header: 2 bytes
      - flag: 1 byte
      - marker: 1 byte

### Kickoff Transaction Weights

  * funding_output_script: 71 bytes
    - OP_2: 1 byte
    - OP_DATA: 1 byte (pub_key_alice length)
    - pub_key_alice: 33 bytes
    - OP_DATA: 1 byte (pub_key_bob length)
    - pub_key_bob: 33 bytes
    - OP_2: 1 byte
    - OP_CHECKMULTISIG: 1 byte

  * funding_input_witness: 222 bytes
    - number_of_witness_elements: 1 byte
    - nil_length: 1 byte
    - sig_alice_length: 1 byte
    - sig_alice: 73 bytes
    - sig_bob_length: 1 byte
    - sig_bob: 73 bytes
    - witness_script_length: 1 byte
    - witness_script: 71 bytes (funding_output_script)

  * kickoff_txin_0: 41 bytes (excl. witness)
    - previous_out_point: 36 bytes
      - hash: 32 bytes
      - index: 4 bytes
    - var_int: 1 byte (script_sig length)
    - script_sig: 0 bytes
    - witness: <---- part of the witness data
    - sequence: 4 bytes

  * musig2_funding_output: 43 bytes
    - value: 8 bytes
    - var_int: 1 byte (pk_script length)
    - pk_script (p2tr): 34 bytes

  * anchor_output: 43 bytes
    - value: 8 bytes
    - var_int: 1 byte (pk_script length)
    - pk_script (p2tr): 34 bytes

  * kickoff_transaction: 180 bytes (excl. witness)
    - version: 4 bytes
    - witness_header: <---- part of the witness data
    - count_tx_in: 1 byte
    - tx_in: 41 bytes
      - kickoff_txin_0: 41 bytes
    - count_tx_out: 1 byte
    - tx_out: 129 bytes
      - musig2_funding_output: 43 bytes
      - anchor_output_local: 43 bytes
      - anchor_output_remote: 43 bytes
    - lock_time: 4 bytes

  - Multiplying non-witness data by 4 gives a weight of:
    - kickoff_transaction_weight = 180vbytes * 4 = 720WU
  - Adding the witness data:
    - kickoff_transaction_weight += (funding_input_witness + witness_header)
    - kickoff_transaction_weight = 944WU

### Commitment Transaction Weights

Here we assume that both parties have an output on the commitment transaction.
This is to keep the weight consistent across potentially different commitment
transactions.

  * musig2_funding_input_witness: 66 bytes
    - number_of_witness_elements: 1 byte
    - musig2_signature_length: 1 byte
    - musig2_signature: 64 bytes

  * commitment_txin_0: 41 bytes (excl. witness)
    - previous_out_point: 36 bytes
      - hash: 32 bytes
      - index: 4 bytes
    - var_int: 1 byte (script_sig length)
    - script_sig: 0 bytes
    - witness: <---- part of the witness data
    - sequence: 4 bytes

  * to_local: 43 bytes
    - value: 8 bytes
    - var_int: 1 byte (pk_script length)
    - pk_script (p2tr): 34 bytes

  * to_remote: 43 bytes
    - value: 8 bytes
    - var_int: 1 byte (pk_script length)
    - pk_script (p2tr): 34 bytes

  * to_local_anchor: 43 bytes
    - value: 8 bytes
    - var_int: 1 byte (pk_script length)
    - pk_script (p2tr): 34 bytes

  * to_remote_anchor: 43 bytes
    - value: 8 bytes
    - var_int: 1 byte (pk_script length)
    - pk_script (p2tr): 34 bytes

  * commitment_transaction: 225 bytes (excl. witness)
    - version: 4 bytes
    - witness_header: <---- part of the witness data
    - count_tx_in: 1 byte
    - tx_in: 41 bytes
      - commitment_txin_0: 41 bytes
    - count_tx_out: 3 byte
    - tx_out: 172 bytes
      - to_local: 43 bytes
      - to_remote: 43 bytes
      - to_local_anchor: 43 bytes
      - to_remote_anchor: 43 bytes
    - lock_time: 4 bytes

  - Multiplying non-witness data by 4 gives a weight of:
    - commitment_transaction_weight = 223vbytes * 4 = 892WU
  - Adding the witness data:
    - commitment_transaction_weight += (musig2_funding_input_witness + witness_header)
    - commitment_transaction_weight = 960WU
