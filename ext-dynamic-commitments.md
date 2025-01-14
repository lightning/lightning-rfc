# Extension Bolt ZZZ: Dynamic Commitments

Authors:
  * Keagan McClelland <keagan@lightning.engineering>
  * Olaoluwa Osuntokun <roasbeef@lightning.engineering>
  * Eugene Siegel <eugene@lightning.engineering>

Created: TODO

# Table of Contents

TODO

# Introduction

## Abstract

This document describes a protocol for changing channel parameters that were
negotiated at the conception of the channel. Implementation of the protocol
described in this document will enable channel peers to re-negotiate and update
channel terms as if the channel was being opened for the first time while
avoiding UTXO churn whenever possible and therefore preserving the continuity of
identity for the channel whose terms are being changed.

## Motivation

It is well understood that closing channels is a costly thing to do. Not only is
it costly from a chain fees perspective (where we pay for moving the funds from
the channel UTXO back to the main wallet collection), it is also costly from a
service availability and reputation perspective.

After channels are closed, they are no longer usable for forwarding HTLC traffic
and even if we were to immediately replace the channel with another equally
capable one, the closure event is visible to the entire network. Since routes
are computed by the source, the network-wide visibility of channel closures
directly impacts whether or not the sender will be able to use a channel.

Beyond that, one of the pathfinding heuristics that is frequently used to assess
channel reliability is the channel age. The longevity of a channel is therefore
a key asset that any running Lightning node should want to preserve, if
possible.

It follows from the above that we should try to minimize channel closure events
when we can manage to do so. This is the main motivation of this proposal. Prior
to this extension BOLT, there hasn't been a way to change some of the channel
parameters established in the `{open|accept}_channel` messages without resorting
to a full channel closure, even if the channel counterparty consents. This
limitation can be remediated by introducing a protocol to renegotiate these
parameters.

## Preliminaries

This proposal includes a detailed section on the preliminaries to document some
of the rationale for the design that is presented later. If you are a Bitcoin
and Lightning Network protocol expert or you are uninterested in the thought
process behind what is presented here, you may wish to skip to the Design
Overview section to save time.

### Channel Opening Parameters

As described in BOLT 2, during the channel opening procedure there are a number
of parameters specified in the `open_channel` and `accept_channel` messages that
remain static over the lifetime of the channel. A subset of these are updatable
using other messages defined in the protocol. However, after accounting for the
channel parameters that can be changed using existing mechanisms, there remains
a list of parameters which are unchangeable. We list these below:

- dust_limit_satoshis
- max_htlc_value_in_flight_msat
- htlc_minimum_msat
- channel_reserve_satoshis
- to_self_delay
- max_accepted_htlcs
- funding_pubkey
- revocation_basepoint
- payment_basepoint
- delayed_payment_basepoint
- htlc_basepoint
- first_per_commitment_point
- channel_flags
- upfront_shutdown
- channel_type

After some analysis during the development of this proposal, we determined that
the basepoint values don't make sense to rotate. There is no obvious value in
doing so and it carries additional administrative costs to rotate them. Finally,
changing the upfront_shutdown script over the lifetime of the channel is
self-defeating and so we exclude it as well. The list of channel parameters
remaining after we filter out these values is thus:

- dust_limit_satoshis
- max_htlc_value_in_flight_msat
- htlc_minimum_msat
- channel_reserve_satoshis
- to_self_delay
- max_accepted_htlcs
- funding_pubkey
- channel_type

The design presented here is intended to allow for arbitrary changes to these
values that currently have no facilities for change in any other way.

## Design Overview

The main goal of this proposal is to be able to change all of the historically
"static" channel parameters, including the channel type, in a world where we are
trying to preserve the channel identity of the original channel.

Most of these parameters can be changed by simply expressing the desire to
change them, and if the responder agrees, we proceed with a mutual understanding
of the new parameters.

However, there are exceptions to this protocol flow. Changing the funding pubkey
and in certain cases, changing the channel type requires a funding output
conversion. This proposal does not cover how to safely accomplish a funding
output conversion and so for the purposes of the remainder of this document, it
is considered prohibited. NOTE: follow-on documents will elaborate on how to
execute changes that require funding output conversions.

# Specification

There are two phases to this channel upgrade process: proposal, and execution.
During the proposal phase the only goal is to agree on a set of updates to the
current channel state machine. Assuming an agreement can be reached, we will
proceed to the execution phase. During the execution phase, we apply the updates
to the channel state machine.

## Proposal Phase

As a prerequisite to the proposal phase of a Dynamic Commitment negotiation, the
channel must be in a [quiesced](https://github.com/lightning/bolts/pull/869)
state.

### Node Roles

In every dynamic commitment negotiation, there are two roles: the `initiator`
and the `responder`. It is necessary for both nodes to agree on which node is
the `initiator` and which node is the `responder`.

### Negotiation TLVs

The following TLVs are used throughout the negotiation phase of the protocol
and are common to all messages in the negotiation phase.

#### dust_limit_satoshis

- type: 0
  data:
    * [`u64`:`senders_dust_limit_satoshis`]

#### max_htlc_value_in_flight_msat

- type: 2
  data:
    * [`u64`:`senders_max_htlc_value_in_flight_msat`]

#### channel_reserve_satoshis

- type: 4
  data:
    * [`u64`:`recipients_channel_reserve_satoshis`]

#### to_self_delay

- type: 6
  data:
    * [`u16`:`recipients_to_self_delay`]

#### max_accepted_htlcs

- type: 8
  data:
    * [`u16`:`senders_max_accepted_htlcs`]

#### channel_type

- type: 10
  data:
    * [`...*byte`:`channel_type`]

### Proposal Messages

Three new messages are introduced that are common to all dynamic commitment
flows. They let each channel party propose which channel parameters they wish to
change as well as accept or reject the proposal made by their counterparty.

#### `chan_param_propose`

This message is sent to negotiate the parameters of a dynamic commitment
upgrade. The overall protocol flow is depicted below. This message is always
sent by the `initiator`.

        +-------+                                             +-------+
        |       |--(1)---------- chan_param_propose --------->|       |
        |       |                                             |       |
        |   A   |<-(2)---{chan_param_ack|chan_param_reject}---|   B   |
        |       |                                             |       |
        |       |--(3)----------- chan_param_commit --------->|       |
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

##### Requirements

The sending node:
  - MUST be the `initiator` established in the preceding quiescence protocol.
  - MUST set `channel_id` to an existing one it has with the recipient.
  - MUST NOT send a set of TLV parameters that would violate the requirements
    of the identically named parameters in BOLT 2 or associated extensions.
  - MUST remember its last sent `chan_param_propose` parameters.
  - if it is currently waiting for a response (`chan_param_ack` or
    `chan_param_reject`):
    - MUST NOT send another `chan_param_propose`.
    - SHOULD close the connection if it exceeds an acceptable time frame.
  - MUST NOT set a `channel_type` with a different funding output script than
    the current funding output script UNLESS otherwise negotiated by another
    feature bit.

The receiving node:
  - if `channel_id` does not match an existing channel it has with the sender:
    - SHOULD send an `error` and close the connection.
  - MUST respond with either a `chan_param_ack` or `chan_param_reject`.
  - if the TLV parameters of the `chan_param_propose` are acceptable and the
    receiver intends to execute those parameter changes:
    - MUST respond with `chan_param_ack`.
  - if the TLV parameters of the `chan_param_propose` are NOT acceptable and the
    receiver refuses to execute those parameter changes:
    - MUST respond with `chan_param_reject`.

_NOTE FOR REVIEWERS_: These messages all interact with each other, so feedback
is welcome for how to restructure this section so that the invariants it
prescribes are found in the most intuitive place.

##### Rationale

The set of parameters used in this message to renegotiate channel parameters
can't violate the invariants set out in BOLT 2. This is because we are simply
trying change channel parameters without a close event. BOLT 2 specifies
constraints on these parameters to make sure they are internally consistent and
secure in all contexts.

#### `chan_param_ack`

This message is sent in response to a `chan_param_propose` indicating that it
has accepted the proposal.

1. type: 113 (`chan_param_ack`)
2. data:
   * [`32*byte`:`channel_id`]
   * [`signature`:`signature`]

##### Requirements

The sending node:
  - MUST set `channel_id` to the `channel_id` it received in the
    `chan_param_propose`.
  - MUST NOT send this message if it has not received a `chan_param_propose` for
    this `channel_id`
  - MUST NOT send this message if it has already sent a `chan_param_ack` for the
    current negotiation.
  - MUST NOT send this message if it has already sent a `chan_param_reject` for
    the current negotiation.
  - MUST set the `signature` field to a valid signature described in
    [Appendix A](#appendix-a-chan_param_ack-signature-definition)

The receiving node:
  - if `channel_id` does not match an existing channel it has with the peer:
    - MUST send an `error` and close the connection.
  - if there isn't an outstanding `chan_param_propose` it has sent:
    - MUST send an `error` and fail the channel.
  - MUST verify the `signature` is valid for the same set of parameters proposed
    and signed by the channel peer's node identity private key.
  - MUST respond with a `chan_param_commit` message.

##### Rationale

We include a signature here so that during the reestablish process we can
dispense with having to renegotiate quiescence and parameters. This allows the
`responder` to commit to its acceptance of the new parameters in a way that the
`initiator` can later _unilaterally_ recall.

#### `chan_param_reject`

This message is sent in response to a `chan_param_propose` indicating that it
rejects the proposal.

1. type: 115 (`chan_param_reject`)
2. data:
    * [`32*byte`:`channel_id`]
    * [`...*byte`:`update_rejections`]

##### Requirements

The sending node:
  - MUST set `channel_id` to the `channel_id` it received in the
    `chan_param_propose`.
  - MUST NOT send this message if it has not received a `chan_param_propose`
  - MUST NOT send this message if it has already sent a `chan_param_ack` for the
    current negotiation.
  - MUST NOT send this message if it has already sent a `chan_param_reject` for
    the current negotiation.
  - if it will not accept **any** dynamic commitment negotiation:
    - SHOULD send a `chan_param_reject` with zero value for `update_rejections`
  - if it does not agree with one or more parameters:
    - MUST send a `chan_param_reject` with the bit index (using the same layout
      as feature negotiation) set corresponding to the TLV type number.
      - Example: an objection to the `dust_limit` would be encoded as
        0b00000001, an objection to `max_value_in_flight` would be encoded as
        0b00000100, and an objection to both would be encoded as 0b00000101.
  - MUST forget the parameters of the `chan_param_propose` message to which the
    `chan_param_reject` is responding.

The receiving node:
  - if `channel_id` does not match an existing channel it has with the peer
    - MUST close the connection
  - if there isn't an outstanding `chan_param_propose` it has sent
    - MUST send an `error` and fail the channel
  - MUST forget its last sent `chan_param_propose` parameters.
  - if the `update_rejections` is a zero value
    - SHOULD NOT re-attempt another dynamic commitment negotation for the
      remaining lifecycle of the connection
  - if the `update_rejections` is a non-zero value:
    - MAY re-attempt another dynamic commitment negotiation
    - if a dynamic commitment negotiation is re-attempted:
      - SHOULD relax the parameters whose TLV types match the bits that were set
        in the `update_rejections` value.
      - if no sensible interpretation of "relax" exists:
        - SHOULD NOT re-attempt a dynamic commitment negotiation with this
          parameter set.

##### Rationale

By sending back the TLVs that a node explicitly rejects makes it easier to come
to an agreement on a proposal that will work. By sending back a zero value for
`update_rejections`, a node signals it is not interested in moving any dynamic
commitment negotiation forward at all and further negotiation should not be
attempted.

#### `chan_param_commit`

This message is sent after receiving a `chan_param_ack` to unify the parameters
and the signature into a single message.

1. type: 117
2. data:
   * [`32*byte`:`channel_id`]
   * [`signature`:`chan_param_ack_signature`]
   * [`chan_param_propose_tlvs`:`tlvs`]

##### Requirements

The sending node:
  - MUST set `channel_id` to a valid channel id that it has with a peer.
  - MUST set `signature` to a valid signature that matches the
    `chan_param_propose_tlvs` and the receiver's node identity private key.
    message.
  - MUST NOT send `chan_param_commit` with a signature that is not valid for the
    next commitment number that the receiving node expects to receive.
  - MAY send `chan_param_commit` _even if_ the channel is NOT quiescent.
  - MUST proceed to the Execution Phase.

The receiving node:
  - MUST validate that the `signature` was previously signed by its own node
    identity pubkey for the next commitment number it expects to receive for
    the `channel_id` specified.
  - MUST consider this message an "update" for the purposes of retransmission
    as well as allowing enabling the receipt of a `commitment_signed` message.
  - MUST proceed to the Execution Phase.

##### Rationale

This message simplifies the process of resolving issues with retransmission.
This message captures all of the necessary information to resolve honest
discrepencies in channel state. With this message the effects of the Dynamic
Commitment negotiation can be reapplied without retransmitting the negotiation
messages themselves.

## Reestablish

The channel reestablish that needs to include a Dynamic Commitment upgrade
proceeds similarly to the way other updates are retransmitted, though not
identically.

### Requirements

If a node has previously sent a `chan_param_commit` message that contains a
signature bound to the commitment number that its channel peer specified in the
`channel_reestablish` message:
  - MUST retransmit `chan_param_commit`
  - MUST NOT retransmit `chan_param_propose`
  - MUST proceed to Execution Phase

#### Rationale

During the reestablish process we explicitly specify the next commitment
numbers we expect to receive. Since the new parameter changes are locked in
by an exchange of `commitment_signed` messages, if our channel peer tells us
that the next commit number it expects is the same one as the commit number
bound in the signature in `chan_param_commit` we need to reissue that commitment
as well as all of the updates that commitment includes.

As a side note, since we establish quiescence prior to Dynamic Commitment
negotiation, there cannot be any `update_` messages in the batch that the
`commitment_signed` message covers if it covers a `chan_param_commit`. This may
be a useful invariant to check during implementation.

## Execution Phase

For the parameter changes outlined in this proposal, the specific execution
required is simply to exchange `commitment_signed` and `revoke_and_ack`
messages. After the `responder` has issued a `revoke_and_ack` these parameters
are considered locked in on the `responder`'s side. From there, the
`responder`'s subsequent updates will be expected to abide by the new
constraints. A sketch is provided below:

        +-------+                               +-------+
        |       |--(1)--- chan_param_commit --->|       |
        |       |                               |       |
        |   A   |--(2)------ commit_sig ------->|   B   |
        |       |                               |       |
        |       |<-(3)---- revoke_and_ack ------|       |
        +-------+                               +-------+

At this point the channel is no longer considered quiescent.

_NOTE FOR REVIEWERS_: Should we require that the `responder` immediately issues
a `commitment_signed` of its own? As far as I can tell this doesn't accomplish
anything except in the case where the `initiator` requests a change to its
`dust_limit` which would give it _immediate_ (as opposed to _eventual_) access
to a commitment transaction that abided by the new limit.

## Appendix A: `chan_param_ack` signature definition

The signature included in the `chan_param_ack` message covers the following
message:

`channel_id || u64(next_commitment_number) || chan_param_propose_tlvs`

Like with `channel_reestablish`, the `next_commitment_number` refers to the
immediate next commitment number the responder expects to receive. For the
TLV stream, since BOLT1 specifies that types must be sent in strictly ascending
order, the encoding is fully deterministic and will ensure that the signature
can be verified without ambiguity.

The key used to sign this message is the node's identity private key.
