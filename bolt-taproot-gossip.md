# Extension BOLT XX: Taproot Gossip

# Table of Contents

  * [Aim](#aim)
  * [Overview](#overview)
  * [Terminology](#terminology)
  * [Type Definitions](#type-definitions)
  * [TLV Based Messages](#tlv-based-messages)
  * [Taproot Channel Proof and Verification](#taproot-channel-proof-and-verification)
  * [Timestamp fields](#timestamp-fields)
  * [Bootstrapping Taproot Gossip](#bootstrapping-taproot-gossip)
  * [Specification](#specification)
    * [Feature Bits](#feature-bits)
    * [The `announcement_signatures_2` message](#the-announcement_signatures_2-message)
    * [The `channel_announcement_2` message](#the-channel_announcement_2-message)
    * [The `node_announcement_2` message](#the-node_announcement_2-message)
    * [The `channel_update_2` message](#the-channel_update_2-message)
  * [Appendix A: Algorithms](#appendix-a-algorithms)
      * [Partial Signature Calculation](#partial-signature-calculation)
      * [Partial Signature Verification](#partial-signature-verification)
  * [Appendix B: Test Vectors](#appendix-b-test-vectors)
  * [Acknowledgements](#acknowledgements)

## Aim 

This document aims to update the gossip protocol defined in [BOLT 7][bolt-7] to
allow for advertisement and verification of taproot channels. An entirely new
set of gossip messages are defined that use [BIP-340][bip-340] signatures and
that use a purely TLV based schema.

## Overview

The initial version of the Lightning Network gossip protocol as defined in
[BOLT 7][bolt-7] was designed around P2WSH funding transactions. For these
channels, the `channel_announcement` message is used to advertise the channel to
the rest of the network. Nodes in the network use the content of this message to
prove that the channel is sufficiently bound to the Lightning Network context
by being provided enough information to prove that the script is a 2-of-2 
multi-sig and that it is owned by the nodes advertising the channel. This 
ownership proof is done by including signatures in the `channel_announcement` 
from both the node ID keys along with the bitcoin keys used in the P2WSH script. 
This proof and verification protocol is, however, not compatible with SegWit V1 
(P2TR) outputs and so cannot be used to advertise the channels defined in the 
[Simple Taproot Channel][simple-taproot-chans] proposal. This document thus aims 
to define an updated gossip protocol that will allow nodes to both advertise and 
verify taproot channels. This part of the update affects the 
`announcement_signatures` and `channel_announcement` messages.

The opportunity is also taken to rework the `node_announcement` and
`channel_update` messages to take advantage of [BIP-340][bip-340] signatures and
TLV fields. Timestamp fields are also updated to be block heights instead of
Unix timestamps.

## Terminology

- Collectively, the set of new gossip messages will be referred to as 
  `taproot gossip`.
- `node_1` and `node_2` refer to the two parties involved in opening a channel.
- `node_ID_1` and `node_ID_2` respectively refer to the public keys that
  `node_1` and `node_2` use to identify their nodes in the network.
- `bitcoin_key_1` and `bitcoin_key_2` respectively refer to the public keys
  that `node_1` and `node_2` will use for the specific channel being opened.
  The funding transaction's output will be derived from these two keys.

## Type Definitions

The following convenient types are defined:

* `bip340_sig`: a 64-byte bitcoin Elliptic Curve Schnorr signature as
  per [BIP-340][bip-340].
* `partial_signature`: a 32-byte partial MuSig2 signature as defined
  in [BIP-MuSig2][bip-musig2].
* `public_nonce`: a 66-byte public nonce as defined in [BIP-MuSig2][bip-musig2].
* `utf8`: a byte as part of a UTF-8 string. A writer MUST ensure an array of
  these is a valid UTF-8 string, a reader MAY reject any messages containing an
  array of these which is not a valid UTF-8 string.

## TLV Based Messages

The initial set of Lightning Network messages consisted of fields that had to 
be present. Later on, TLV encoding was introduced which provided a backward 
compatible way to extend messages. To ensure that the new messages defined in 
this document remain as future-proof as possible, the messages will be pure TLV
streams. By making all fields in the messages TLV records, fields that we
consider mandatory today can easily be dropped in future (when coupled with a 
new feature bit) without needing to completely redefine the gossip message in 
order to make the field optional.

## Taproot Channel Proof and Verification

Taproot channel funding transaction outputs will be SegWit V1 (P2TR) outputs of
the following form:

```
OP_1 <taproot_output_key> 
```

where 
```
taproot_internal_key = MuSig2.KeyAgg(MuSig2.KeySort(bitcoin_key_1, bitcoin_key_2))

taproot_output_key = taproot_internal_key + tagged_hash("TapTweak", taproot_internal_key) * G
```

`taproot_interal_key` is the aggregate key of `bitcoin_key_1` and
`bitcoin_key_2` after first sorting the keys using the
[MuSig2 KeySort][musig-keysort] algorithm and then running the
[MuSig2 KeyAgg][musig-keyagg] algorithm.

Then, to commit to spending the taproot output via the keyspend path, a
[BIP86][bip86-tweak] tweak is added to the internal key to calculate the
`taproot_output_key`.

As with legacy channels, nodes will want to perform some checks before adding 
an announced taproot channel to their routing graph:

1. The funding output of the channel being advertised exists on-chain, is an
   unspent UTXO and has a sufficient number of confirmations. To allow this 
   check, the SCID of the channel will continue to be included in the channel
   announcement.
2. The funding transaction is sufficiently bound to the Lightning context. 
   Nodes will do this by checking that they are able to derive the output key 
   found on-chain by using the advertised `bitcoin_key_1` and `bitcoin_key_2` 
   along with a [BIP86 tweak][bip86-tweak]. This provides a slightly weaker
   binding to the LN context than legacy channels do but at least somewhat 
   limits how the output can be spent due to the script-path being disabled.
   The context binding with legacy channels is greater because an attacker 
   trying to create gossip spam would need to create 2-of-2 multisig P2WSH 
   outputs on-chain that would require them to then pay for the bytes of two
   signatures at the time of spending the output. This extra cost provided some
   extra deterrence for attackers. This deterrence is not present with P2TR 
   transactions.
3. The owners of `bitcoin_key_1` and `bitcoin_key_2` agree to be associated with  
   a channel owned by `node_1` and `node_2`.
4. The owners of `node_ID_1` and `node_ID_2` agree to being associated with the 
   output paying to `bitcoin_key_1` and `bitcoin_key_2`. 

For legacy channels, these last two proofs are made possible by including four
separate signatures in the `channel_announcement`. However, [BIP-340][bip-340]
signatures and the MuSig2 protocol allow us to now aggregate these four
signatures into a single one. Verifiers will then be able to aggregate the four
keys (`bitcoin_key_1`, `bitcoin_key_2`, `node_ID_1` and `node_ID_2`) using
MuSig2 key aggregation, and then they can do a single signature verification
check instead of four individual checks.

## Block-height fields

In the messages defined in this document, block heights are used as timestamps
instead of the UNIX timestamps used in the legacy set of gossip messages. 

### Rate Limiting

A block height based timestamp results in more natural rate limiting for gossip
messages: nodes are allowed to send at most one announcement and update per
block. To allow for bursts, nodes are encouraged not to use the latest block
height for their latest announcements/updates but rather to backdate and use
older block heights that they have not used in an announcement/update. There of
course needs to be a limit on the start block height that the node can use:
for `channel_update_2` messages, the first timestamp must be the block height in
which the channel funding transaction was mined and all updates after the
initial one must have increasing timestamps. Nodes are then responsible for
building up their own timestamp buffer: if they want to be able to send
multiple `channel_update_2` messages per block, then they will need to ensure 
that there are blocks during which they do not broadcast any updates. This 
provides an incentive for nodes not to spam the network with too many updates.

To also prevent nodes from building up too large of a burst-buffer with which 
they can spam the network and to give a limit to how low the block height on a 
`node_announcement_2` can be: nodes should not be allowed to use a block height
smaller 2016 (~ one week worth of blocks) below the current block height.

### Simplifies Channel Announcement Queries

In the legacy gossip protocol, the timestamp of the `channel_announcement` is
hard to define since the message itself does not have a `timestamp` field. This
makes timestamp based gossip queries tricky. By using block heights as 
timestamps instead, there is an implicit timestamp associated with the 
`channel_announcement_2`: the block in which the funding transaction is mined.

## Bootstrapping Taproot Gossip

While the network upgrades from the legacy gossip protocol to the taproot gossip
protocol, the following scenarios may exist for any node on the network:

| scenario | has legacy channels | has taproot channels  | should send `node_announcement` | should send `node_announcement_2` |
|----------|---------------------|-----------------------|---------------------------------|-----------------------------------|
| 1        | no                  | no                    | no                              | no                                |
| 2        | yes                 | no                    | yes                             | no                                |
| 3        | yes                 | yes                   | yes                             | no                                |
| 4        | no                  | yes                   | no                              | yes                               |

### Scenario 1

These nodes have no announced channels and so should not be broadcasting legacy
or new node announcement messages.

### Scenario 2

If a node has legacy channels but no taproot channels, they should broadcast
only a legacy `node_announcement` message. Both taproot-gossip aware and unaware
nodes will be able to verify the node announcement since both groups are able to
process the `channel_announcement` for the legacy channel(s). The reason why 
upgraded nodes should continue to broadcast the legacy announcement is because 
this is the most effective way of spreading the `option_taproot_gossip` feature 
bit since un-upgraded nodes can assist in spreading the message. 

### Scenario 3

If a node has both legacy channels and taproot channels, then like Scenario 2 
nodes, they should continue broadcasting the legacy `node_announcement` 
message.

### Scenario 4

In this scenario, a node has only taproot channels and no legacy channels. This
means that they cannot broadcast a legacy `node_announcement` message since 
un-upgraded nodes will drop this message due to the fact that no legacy 
`channel_announcement` message would have been received for that node. These 
nodes will also not be able to use a legacy `node_announcement` to propagate 
their new `node_announcement_2` message.

### Considerations & Suggestions

While the network is in the upgrade phase, the following suggestions apply:

- Keeping at least a single, announced, legacy channel open during the initial 
  phase of the transition to the new gossip protocol could be very beneficial 
  since nodes can continue to broadcast their legacy `node_announcement` and 
  thus more effectively advertise their support for `option_taproot_gossip`. 
- Nodes are encouraged to actively connect to other nodes that advertise the 
  `option_taproot_gossip` feature bit as this is the only way in which they 
  will learn about taproot channel announcements and updates.
- Nodes should not use the new `node_announcement_2` message until they have
  no more announced legacy channels.

### Alternative Approaches

An alternative approach would be to add an optional TLV to the legacy
`node_annoucement` that includes the serialised `node_announcement_2`. The nice
thing about this is that it allows the new `node_announcement_2` message to
propagate quickly through the network before the upgrade is complete. The
downside of this approach is that it would more than double the size of the
legacy `node_announcement` and most of the information would be duplicated. It
also makes gossip queries tricky since `node_announcement_2` uses a block-height
based timestamp instead of the unix timestamp used by the legacy message.
There also does not seem to be a big benefit in spreading the 
`node_announcement_2` message quickly since the speed of propagation of the 
`channel_announcement_2` and `channel_update_2` messages will still depend on a
network wide upgrade.

## Specification

### Feature Bits

Unlike the original set of gossip messages, it needs to be explicitly advertised
that nodes are aware of the new gossip messages defined in this document at
least until the whole network has upgraded to only using taproot gossip. We thus
define a new feature bit, `option_taproot_gossip` to be included in the `init`
message as well as the _old_ `node_announcement` message. Note that for all
other feature bits with the `N` and `C` contexts, it can be assumed that those
contexts will switch to the new `node_announcement_2` and
`channel_announcement_2` messages for all feature bits _except_ for
`option_taproot_gossip` which only makes sense in the context of the old
`node_announcement` message and not the new `node_announcement_v2` message.
The `option_taproot` feature bit can also be implied when using the new taproot 
gossip messages. 

| Bits  | Name                    | Description                                       | Context | Dependencies     |
|-------|-------------------------|---------------------------------------------------|---------|------------------|
| 32/33 | `option_taproot_gossip` | Nodes that understand the taproot gossip messages | IN      | `option_taproot` | 

A node can be assumed to understand the new gossip v2 messages if:

- They advertise `option_taproot_gossip` in the `init` or 
  legacy `node_announcement` messages
  OR
- They have broadcast one of the new gossip messages defined in this document.

Advertisement of the `option_taproot_gossip` feature bit should be taken to 
mean:

- The node understands and is able to forward all the taproot gossip messages.
- The node may be willing to open an announced taproot channel.

### `open_channel` Extra Requirements

These extra requirements only apply if the `option_taproot` channel type is set
in the `open_channel` message.

The sender:

- if `option_taproot_gossip` was negotiated:
    - MAY set the `announce_channel` bit in `channel_flags`
- otherwise:
    - MUST NOT set the `announce_channel` bit.

The receiving node MUST fail the channel if:

- if `option_taproot_gossip` was not negotiated and the `announce_channel`
  bit in the `channel_flags` was set.

### `channel_ready` Extensions

These extensions only apply if the `option_taproot` channel type was set in the
`open_channel` message along with the `announce_channel` channel flag.

1. `tlv_stream`: `channel_ready_tlvs`
2. types:
   1. type: 0 (`announcement_node_pubnonce`)
   2. data:
      * [`66*byte`: `public_nonce`]
   3. type: 2 (`announcement_bitcoin_pubnonce`)
   4. data:
      * [`66*byte`: `public_nonce`]
   
### Requirements

The sender: 

  - MUST set the `announcement_node_pubnonce` and 
    `announcement_bitcoin_pubnonce` tlv fields in `channel_ready`.
  - SHOULD use the MuSig2 `NonceGen` algorithm to generate two unique secret 
    nonces and use these to determine the corresponding public nonces: 
    `announcement_node_pubnonce` and `announcement_bitcoin_pubnonce`.
  
The recipient: 

  - MUST fail the channel if: 
    - if the `announcement_node_pubnonce` or `announcement_bitcoin_pubnonce` tlv 
      fields are missing.
    - if the `announcement_node_pubnonce` and `announcement_bitcoin_pubnonce` 
      are equal.
    
### Rationale

The final signature included in the `channel_announcement_v2` message will be a
single [BIP-340][bip-340] signature that needs to be valid for a public key
derived by aggregating all the `node_ID` and `bitcoin_key` public keys. The
signature for this key will thus be created by aggregating (via MuSig2) four
partial signatures. One for each of the keys: `node_ID_1`, `node_ID_2`, 
`bitcoin_key_1` and `bitcoin_key_2`. A nonce will need to be generated and
exchanged for each of the keys and so each node will need to send the other node
two nonces. The `announcement_node_nonce` is for `node_ID_x` and the 
`announcement_bitcoin_nonce` is for `bitcoin_key_x`.

Since the channel can only be announced once the `channel_ready` messages have 
been exchanged and since it is generally preferred to keep nonce exchanges as 
Just In Time as possible, the nonces are exchanged via the `channel_ready` 
message.

## The `announcement_signatures_2` Message

Like the legacy `announcement_signatures` message, this is a direct message
between the two endpoints of a channel and serves as an opt-in mechanism to
allow the announcement of the channel to the rest of the network. 

1. type: xxx (`announcement_signatures_2`)
2. data (tlv_stream):
   1. type: 0 (`channel_id`)
   2. data:
       * [`channel_id`:`channel_id`]
   3. type: 2 (`short_channel_id`)
   4. data:
       * [`short_channel_id`:`short_channel_id`]
   5. type: 4 (`partial_signature`)
   6. data:
       * [`partial_signature`:`partial_signature`]

### Requirements

The requirements are similar to the ones defined for the legacy 
`announcement_signatures`. The below requirements assume that the 
`option_taproot` channel type was set in `open_channel`.

A node:
- if the `open_channel` message has the `announce_channel` bit set AND a 
  `shutdown` message has not been sent:
  - MUST send the `announcement_signatures_2` message once `channel_ready`
      has been sent and received AND the funding transaction has at least six 
      confirmations.
  - MUST set the `partial_signature` field to the 32-byte `partial_sig` value of
    the partial signature calculated as described in [Partial Signature 
    Calculation](#partial-signature-calculation). The message to be signed is
    `MsgHash("channel_announcement", "announcement_sig", m)` where `m` is the
    serialisation of the `channel_announcement_2` message excluding the
    `announcement_sig` field (see the
    [`MsgHash`](#signature-message-construction) definition).
- otherwise:
    - MUST NOT send the `announcement_signatures_2` message.
- upon reconnection (once the above timing requirements have been met):
    - MUST respond to the first `announcement_signatures_2` message with its own
      `announcement_signatures_2` message.
    - if it has NOT received an `announcement_signatures_2` message:
        - SHOULD retransmit the `announcement_signatures_2` message.

A recipient node:
- if the `short_channel_id` is NOT correct:
    - SHOULD send a `warning` and close the connection, or send an
      `error` and fail the channel.
- if the `partial_signature` is NOT valid as
  per [Partial Signature Verification](#partial-signature-verification):
    - MAY send a `warning` and close the connection, or send an
      `error` and fail the channel.
- if it has sent AND received a valid `announcement_signatures_2` message:
    - SHOULD queue the `channel_announcement_2` message for its peers.
- if it has not sent `channel_ready`:
    - MAY send a `warning` and close the connection, or send an `error` and fail
      the channel.

### Rationale

The message contains the necessary partial signature, by the sender, that the
recipient will be able to combine with their own partial signature to construct
the signature to put in the `channel_announcement_v2` message. Unlike the legacy
`announcement_signatures` message, `announcement_signatures_v2` only has one
signature field. This field is a MuSig2 partial signature which is the
aggregation of the two signatures that the sender would have created (one for
`bitcoin_key_x` and another for `node_ID_x`).

## The `channel_announcement_2` Message

This gossip message contains ownership information regarding a taproot channel. 
It ties each on-chain Bitcoin key that makes up the taproot output key to the 
associated Lightning node key, and vice-versa. The channel is not practically 
usable until at least one side has announced its fee levels and expiry, using 
`channel_update_2`.

See [Taproot Channel Proof and Verification](#taproot-channel-proof-and-verification)
for more information regarding the requirements for proving the existence of a
channel.

1. type: xxx (`channel_announcement_2`)
2. data: (tlv_stream):
   1. type: 0 (`announcement_sig`)
   2. data:
        * [`bip340_sig`:`bip340_sig`]
   3. type: 1 (`chain_hash`)
   4. data:
       * [`chain_hash`:`chain_hash`]
   5. type: 2 (`features`)
   6. data:
        * [`...*byte`: `features`]
   7. type: 4 (`short_channel_id`)
   8. data:
        * [`short_channel_id`:`short_channel_id`]
   9. type: 6 (`node_id_1`)
   10. data:
        * [`point`:`point`]
   11. type: 8 (`node_id_2`)
   12. data:
       * [`point`:`point`]
   13. type: 3 (`bitcoin_key_1`)
   14. data:
       * [`point`:`point`]
   15. type: 5 (`bitcoin_key_2`)
   16. data:
       * [`point`:`point`]
   17. type: 7 (`tap_tweak`)
   18. data:
       * [`point`:`point`]

### Requirements

The origin node:

- If the chain being referred to is not the Bitcoin blockchain:
  - MUST set `chain_hash` to the 32-byte hash that uniquely identifies the chain
    that the channel was opened within:
- otherwise, MUST not set `chain_has` as the _Bitcoin blockchain_ is assumed. 
- MUST set `short_channel_id` to refer to the confirmed funding transaction, as
  specified in [BOLT #2](02-peer-protocol.md#the-channel_ready-message).
    - Note: the corresponding output MUST be a P2TR, as described
      in [Taproot Channel Proof and Verification](#taproot-channel-proof-and-verification).
- MUST set `node_id_1` and `node_id_2` to the public keys of the two nodes
  operating the channel, such that `node_id_1` is the lexicographically-lesser
  of the two compressed keys sorted in ascending lexicographic order.
- MUST set `bitcoin_key_1` and `bitcoin_key_2` to `node_id_1` and `node_id_2`'s
  respective `funding_pubkey`s.
- MUST set `features` based on what features were negotiated for this channel,
  according to [BOLT #9](09-features.md#assigned-features-flags)
- MUST set `announcement_sig` signature to the [BIP-340][bip-340] signature
  calculated by passing the partial signatures sent and received during the
  `announcement_signatures_2` exchange to the
  [MuSig2 PartialSigAgg][musig-partial-sig-agg] function.

The receiving node:

- If any even typed messages are not present:
    - SHOULD send a `warning`.
    - MAY close the connection.
    - MUST ignore the message.
- MUST verify the integrity AND authenticity of the message by verifying the
  `announcement_sig` as per [BIP 340][bip-340-verify].
- if there is an unknown even bit in the `features` field:
    - MUST NOT attempt to route messages through the channel.
- if the `short_channel_id`'s output does NOT correspond to a P2TR (using
  `bitcoin_key_1` and `bitcoin_key_2`, as specified in
  [BOLT #3](03-transactions.md#funding-transaction-output)) OR the output is
  spent:
    - MUST ignore the message.
- if the specified `chain_hash` is unknown to the receiver:
    - MUST ignore the message.
- otherwise:
    - if `announcement_sig` is invalid OR NOT correct:
        - SHOULD send a `warning`.
        - MAY close the connection.
        - MUST ignore the message.
    - otherwise:
        - if `node_id_1` OR `node_id_2` are blacklisted:
            - SHOULD ignore the message.
        - otherwise:
            - if the transaction referred to was NOT previously announced as a
              channel:
                - SHOULD queue the message for rebroadcasting.
                - MAY choose NOT to for messages longer than the minimum
                  expected length.
        - if it has previously received a valid `channel_announcement_2`, for
          the same transaction, in the same block, but for a
          different `node_id_1` or `node_id_2`:
            - SHOULD blacklist the previous message's `node_id_1`
              and `node_id_2`, as well as this `node_id_1` and `node_id_2` AND
              forget any channels connected to them.
        - otherwise:
            - SHOULD store this `channel_announcement_2`.
- once its funding output has been spent OR reorganized out:
    - SHOULD forget a channel after a 12-block delay.

### Rationale

Both nodes are required to sign to indicate they are willing to route other
payments via this channel (i.e. be part of the public network); requiring their
aggregated MuSig2 Schnorr signature proves that they control the channel.

The blacklisting of conflicting nodes disallows multiple different
announcements. Such conflicting announcements should never be broadcast by any
node, as this implies that keys have leaked.

While channels should not be advertised before they are sufficiently deep, the
requirement against rebroadcasting only applies if the transaction has not moved
to a different block.

In order to avoid storing excessively large messages, yet still allow for
reasonable future expansion, nodes are permitted to restrict rebroadcasting
(perhaps statistically).

New channel features are possible in the future: backwards compatible (or
optional) features will have _odd_ feature bits, while incompatible features
will have _even_ feature bits
(["It's OK to be odd!"](00-introduction.md#glossary-and-terminology-guide)).

A delay of 12-blocks is used when forgetting a channel on funding output spend
as to permit a new `channel_announcement_2` to propagate which indicates this
channel was spliced.

## The `node_announcement_2` Message

This gossip message, like the legacy `node_announcement` message, allows a node 
to indicate extra data associated with it, in addition to its public key. 
To avoid trivial denial of service attacks, nodes not associated with an already
known channel (legacy or taproot) are ignored.

Unlike the legacy `node_announcement` message, this message makes use of a 
Schnorr signature instead of an ECDSA one. This will allow nodes to be backed 
by multiple keys since MuSig2 can be used to construct the single signature.

The other two main differences from the legacy message are that the timestamp 
is now a block height and that the message is purely TLV based.

1. type: xxx (`node_announcement_2`)
2. data: (tlv_stream):
    1. type: 0 (`announcement_sig`)
    2. data:
        * [`bip340_sig`:`bip340_sig`]
    3. type: 2 (`features`)
    4. data:
        * [`...*byte`: `features`]
    5. type: 4 (`block_height`)
    6. data:
        * [`u32`: `block_height`]
    7. type: 6 (`node_ID`)
    8. data: 
        * [`point`:`node_id`]
    9. type: 1 (`color`)
    10. data:
         * [`rgb_color`:`rgb_color`]
    11. type: 3 (`alias`)
    12. data:
         * [`...*utf8`:`alias`]
    13. type: 5 (`ipv4_addrs`)
    14. data: 
         * [`...*ipv4_addr`: `ipv4_addresses`]  
    15. type: 7 (`ipv6_addrs`)
    16. data:
         * [`...*ipv6_addr`: `ipv6_addresses`]
    17. type: 9 (`tor_v3_addrs`)
    18. data: 
         * [`...*tor_v3_addr`: `tor_v3_addresses`]
    19. type: 11 (`dns_hostname`)
    20. data:
         * [`dns_hostname`: `dns_hostname`]

The following subtypes are defined:

1. subtype: `rgb_color`
2. data:
   * [`byte`:`red`]
   * [`byte`:`green`]
   * [`byte`:`blue`]

3. subtype: `ipv4_addr`
4. data:
    * [`u32`:`addr`]
    * [`tu16`:`port`]

5. subtype: `ipv6_addr`
6. data:
    * [`16*byte`:`addr`]
    * [`tu16`:`port`]
 
7. subtype: `tor_v3_addr`
8. data:
    * [`35*utf8`:`onion_addr`]
    * [`tu16`:`port`]

9. subtype: `dns_hostname`
10. data:
     * [`...*utf8`:`hostname`]
     * [`tu16`:`port`]

`tor_v3_address` is a Tor version 3 ([prop224]) onion service address;
Its `onion_addr` encodes:
`[32:32_byte_ed25519_pubkey] || [2:checksum] || [1:version]`, where
`checksum = sha3(".onion checksum" | pubkey || version)[:2]`.

The `dns_hostname` `hostname` MUST be ASCII characters. Non-ASCII characters
MUST be encoded using [Punycode][punycode]. The length of the `hostname` cannot
exceed 255 bytes.

### Requirements

The sender:

- MUST set `announcement_sig` to a valid [BIP340][bip-340] signature for the
  `node_id` key. The message to be signed is
  `MsgHash("node_announcement_2", "announcement_sig", m)` where `m` is the
  serialisation of the `node_announcement_2` message excluding the
  `announcement_sig` field (see the
  [`MsgHash`](#signature-message-construction) definition).
- MAY set `color` and `alias` to customise appearance in maps and graphs.
- If the node sets the `alias`:
  - MUST use 32 utf8 characters or less. 
- MUST set `block_height` to be greater than that of any previous
  `node_announcement_2` it has previously created.
    - MUST set it to a block height less than the latest block's height but no
      more than 1440 lower.
- If the node wishes to announce its willingness to accept incoming network
  connections:
    - SHOULD set at least one of types 7-10.
- SHOULD set an address type (`ipv4_address`, `ipv6_address`, `tor_v3_address`
  and/or `dns_hostname`) for each public network address that expects incoming
  connections.
- SHOULD ensure that any specified `ipv4_addr` AND `ipv6_addr` are routable
  addresses.
- MUST not create a `ipv4_addr`, `ipv6_addr` or `dns_hostname` with a `port`
  equal to 0.
- MUST set `features` according to [BOLT #9][bolt-9-features].
- SHOULD only start using this message once they no longer have announced legacy
  channels.
    
The receiving node:

- If any type between even-typed values are missing:
    - SHOULD send a `warning`.
    - MAY close the connection.
    - MUST ignore the message.
- if `alias` is set and is larger than 32 utf8 characters:
    - SHOULD send a `warning`.
    - MAY close the connection.
    - MUST ignore the message.
- if `node_id` is NOT a valid compressed public key:
    - SHOULD send a `warning`.
    - MAY close the connection.
    - MUST NOT process the message further.
- if `announcement_sig` is NOT a valid [BIP340][bip-340] signature (using 
  `node_id` over the message):
    - SHOULD send a `warning`.
    - MAY close the connection.
    - MUST NOT process the message further.
- if `features` field contains _unknown even bits_:
    - SHOULD NOT connect to the node.
    - Unless paying a [BOLT #11][bolt-11] invoice which does not have the same
      bit(s) set, MUST NOT attempt to send payments _to_ the node.
    - MUST NOT route a payment _through_ the node.
- if `port` is equal to 0 for any `ipv6_addr` OR `ipv4_addr` OR `hostname`:
    - SHOULD ignore that address.
- if `node_id` is NOT previously known from a `channel_announcement` OR 
  `channel_announcement_2` message, OR if `blockheight` is NOT greater than the 
  last-received `node_announcement_2` from this `node_id`:
      - SHOULD ignore the message.
- otherwise:
    - if `block_height` is greater than the last-received `node_announcement_2` 
      from this `node_id`:
          - SHOULD queue the message for rebroadcasting.
- MAY use `rgb_color` AND `alias` to reference nodes in interfaces.
    - SHOULD insinuate their self-signed origins.
- SHOULD ignore any legacy `node_announcement` message for this `node_ID`.

### Rationale

New node features are possible in the future: backwards compatible (or
optional) ones will have _odd_ `feature` _bits_, incompatible ones will have
_even_ `feature` _bits_. These will be propagated normally; incompatible feature
bits here refer to the nodes, not the `node_announcement_2` message itself.

Since the legacy `node_announcement` uses a UNIX based `timestamp` field and 
this message uses block heights, deciding which message is the latest one could
be tricky. To simplify the logic, the decision is made that once a 
`node_announcement_2` is received, then any legacy `node_announcement` messages 
received for the same `node_id` can be ignored.

### Security Considerations for Node Aliases

The security considerations for node aliases mentioned in 
[BOLT #7][bolt-7-alias-security] apply here too.

## The `channel_update_2` Message

After a channel has been initially announced via `channel_announcement_2`, each 
side independently announces the fees and minimum expiry delta it requires to 
relay HTLCs through this channel. Each uses the 8-byte short channel id that 
matches the `channel_announcement_2` and the 1-bit `channel_flags` field to 
indicate which end of the channel it's on (origin or final). A node can do this 
multiple times, in order to change fees.

Note that the `channel_update` gossip message is only useful in the context
of *relaying* payments, not *sending* payments. When making a payment
`A` -> `B` -> `C` -> `D`, only the `channel_update`s related to channels
`B` -> `C` (announced by `B`) and `C` -> `D` (announced by `C`) will
come into play. When building the route, amounts and expiries for HTLCs need
to be calculated backward from the destination to the source. The exact initial
value for `amount_msat` and the minimal value for `cltv_expiry`, to be used for
the last HTLC in the route, are provided in the payment request
(see [BOLT #11][[bolt-11-tagged-fields]]).

1. type: xxx (`channel_update_2`)
2. data: (tlv_stream):
    1. type: 0 (`update_sig`)
    2. data:
        * [`bip340_sig`:`bip340_sig`]
    3. type: 1 (`chain_hash`)
    4. data:
        * [`chain_hash`:`chain_hash`]
    5. type: 2 (`block_height`)
    6. data:
        * [`u32`: `block_height`]
    7. type: 4 (`channel_flags`)
    8. data:
       * [`...*byte`, `channel_flags`]
    9. type: 6 (`cltv_expiry_delta`)
    10. data:
        * [`tu32`, `cltv_expiry_delta`]
    11. type: 8 (`htlc_min_msat`)
    12. data: 
        * [`tu64`, `htlc_min_msat`]
    13. type: 10 (`htlc_max_msat`)
    14. data:
       * [`tu64`, `htlc_max_msat`]
    15. type: 12 (`fee_base_msat`)
    16. data:
       * [`tu32`, `fee_base_msat`]
    17. type: 14 (`fee_prop_millionths`)
    18. data:
      * [`tu32`, `fee_prop_millionths`]

The `channel_flags` bitfield is used to indicate the direction of the channel:
it identifies the node that this update originated from and signals various
options concerning the channel. The following table specifies the meaning of its
individual bits:

| Bit Position | Name        | Meaning                          |
|--------------|-------------|----------------------------------|
| 0            | `direction` | Direction this update refers to. |
| 1            | `disable`   | Disable the channel.             |

The `node_id` for the signature verification is taken from the corresponding
`channel_announcement_2`: `node_id_1` if the least-significant bit of flags is
0 or `node_id_2` otherwise.

### Requirements

The origin node:
- If the chain being referred to is not the Bitcoin blockchain:
    - MUST set `chain_hash` to the 32-byte hash that uniquely identifies the 
      chain that the channel was opened within:
- otherwise, MUST not set `chain_hash` as the _Bitcoin blockchain_ is assumed.
- MUST NOT send `channel_update_2` before `channel_ready` has been received. 
- MUST NOT send `channel_update_2` for legacy (non-taproot) channels.
- MAY create a `channel_update_2` to communicate the channel parameters to the
  channel peer, even though the channel has not yet been announced (i.e. the
  `announce_channel` bit was not set).
    - MUST set the `short_channel_id` to either an `alias` it has received from
      the peer, or the real channel `short_channel_id`.
    - MUST NOT forward such a `channel_update` to other peers, for privacy
      reasons.
    - Note: such a `channel_update`, one not preceded by a
      `channel_announcement`, is invalid to any other peer and would be
      discarded.
- MUST set `update_sig` to a valid [BIP340][bip-340] signature for its own
  `node_id` key. The message to be signed is
  `MsgHash("channel_update_2", "update_sig", m)` where `m` is the serialisation
  of the `channel_update` message excluding the `update_sig` field (see the
  [`MsgHash`](#signature-message-construction) definition).
- MUST set `chain_hash` AND `short_channel_id` to match the 32-byte hash AND
  8-byte channel ID that uniquely identifies the channel specified in the
  `channel_announcement_2` message.
- if the origin node is `node_id_1` in the message:
    - MUST set the `direction` bit of `channel_flags` to 0.
- otherwise:
    - MUST set the `direction` bit of `channel_flags` to 1.
- MUST set `htlc_maximum_msat` to the maximum value it will send through this
  channel for a single HTLC.
    - MUST set this to less than or equal to the channel capacity.
    - MUST set this to less than or equal to `max_htlc_value_in_flight_msat` it
      received from the peer.
- MAY create and send a `channel_update_2` with the `disable` bit set to 1, to
  signal a channel's temporary unavailability (e.g. due to a loss of
  connectivity) OR permanent unavailability (e.g. prior to an on-chain
  settlement).
    - MAY send a subsequent `channel_update_2` with the `disable` bit set to 0
      to re-enable the channel.
- MUST set `block_height` greater or equal to the block height that the 
  channel's funding transaction was mined in AND to greater than any 
  previously-sent `channel_update_2` for this `short_channel_id` AND no less 
  than 1440 blocks below the current best block height . 
- MUST set `cltv_expiry_delta` to the number of blocks it will subtract from
  an incoming HTLC's `cltv_expiry`.
- MUST set `htlc_minimum_msat` to the minimum HTLC value (in millisatoshi)
  that the channel peer will accept.
- MUST set `fee_base_msat` to the base fee (in millisatoshi) it will charge
  for any HTLC.
- MUST set `fee_proportional_millionths` to the amount (in millionths of a
  satoshi) it will charge per transferred satoshi.
- SHOULD NOT create redundant `channel_update_2`s
- If it creates a new `channel_update_2` with updated channel parameters:
    - SHOULD keep accepting the previous channel parameters for 10 minutes

The receiving node:

- if the `short_channel_id` does NOT match a previous `channel_announcement_2`,
  OR if the channel has been closed in the meantime:
    - MUST ignore `channel_update_2`s that do NOT correspond to one of its own
      channels.
- SHOULD accept `channel_update_2`s for its own taproot channels (even if
  non-public), in order to learn the associated origin nodes' forwarding
  parameters.
- if `update_sig` is NOT a valid [BIP340][bip-340] signature (using `node_id`
  over the message):
    - SHOULD send a `warning` and close the connection.
    - MUST NOT process the message further.
- if the specified `chain_hash` value is unknown (meaning it isn't active on
  the specified chain):
    - MUST ignore the channel update.
- if the `block_height` is equal to the last-received `channel_update_2` for 
  this `short_channel_id` AND `node_id`:
    - if the fields below `block_height` differ:
        - MAY blacklist this `node_id`.
        - MAY forget all channels associated with it.
    - if the fields below `block_height` are equal:
        - SHOULD ignore this message
- if `block_height` is lower than that of the last-received
  `channel_update_2` for this `short_channel_id` AND for `node_id`:
    - SHOULD ignore the message.
- otherwise:
    - if the `block_height` is a block height greater than the current best block
      height:
      - MAY discard the `channel_update_2`.
    - if the `block_height` block height is more than 1440 blocks less than the 
      current best block height:
        - MAY discard the `channel_update_2`.
    - otherwise:
        - SHOULD queue the message for rebroadcasting.
- if `htlc_maximum_msat` is greater than channel capacity:
    - MAY blacklist this `node_id`
    - SHOULD ignore this channel during route considerations.
- otherwise:
    - SHOULD consider the `htlc_maximum_msat` when routing.
  
### Rationale

TODO

## Query Messages

TODO: any updates that need to happen to this section? 

# Appendix A: Algorithms

### Partial Signature Calculation

When both nodes have exchanged `channel_ready` then they will each have the
following information:

- `node_1` will know:
    - `bitcoin_priv_key_1`, `node_ID_priv_key_1`,
    - `bitcoin_key_2`,
    - `node_ID_1`,
    - `announcement_node_secnonce_1` and `announcement_node_pubnonce_1`,
    - `announcement_bitcoin_secnonce_1` and `announcement_bitcoin_pubnonce_1`,
    - `announcement_node_pubnonce_2`,
    - `announcement_bitcoin_pubnonce_2`,

- `node_2` will know:
    - `bitcoin_priv_key_2`, `node_ID_priv_key_2`,
    - `bitcoin_key_1`,
    - `node_ID_1`,
    - `announcement_node_secnonce_2` and `announcement_node_pubnonce_2`,
    - `announcement_bitcoin_secnonce_2` and `announcement_bitcoin_pubnonce_2`,
    - `announcement_node_pubnonce_1`,
    - `announcement_bitcoin_pubnonce_1`,

With the above information, both nodes can now start calculating the partial
signatures that will be exchanged in the `announcement_signatures_v2` message.

Firstly, the aggregate public key, `P_agg`, that the signature will be valid for
can be calculated as follows:

```
P_agg = Musig2.KeyAgg(Musig2.KeySort(node_ID_1, node_ID_2, bitcoin_key_1, bitcoin_key_2))
```

Next, the aggregate public nonce, `aggnonce`, can be calculated:

```
aggnonce = Musig2.NonceAgg(announcement_node_secnonce_1, announcement_bitcoin_pubnonce_1, announcement_node_secnonce_2, announcement_bitcoin_pubnonce_2)
```

The message, `msg` that the peers will sign is the serialisation of
`channel_announcement_2` _without_ the `announcement_sig` field (i.e. without
type 0)

With all the information mentioned, both peers can now construct the
[`Session Context`][musig-session-ctx] defined by the MuSig2 protocol which is
necessary for as an input to the `Musig2.Sign` algorithm. The following members
of the `Session Context`, which we will call `session_ctx`, can be defined:

- `aggnonce`: `aggnonce`
- `u`: 2
- `pk1..u`: [`node_ID_1`, `node_ID_2`, `bitcoin_key_1`, `bitcoin_key_2`]
- `v`: 0
- `m`: `msg`

Both peers, `node_1` and `node_2` will need to construct two partial signatures.
One for their `bitcoin_key` and one for their `node_ID` and aggregate those.

- `node_1`:
    - calculates a partial signature for `node_ID_1` as follows:
       ```
       partial_sig_node_1 = MuSig2.Sign(announcement_node_secnonce_1, node_ID_priv_key_1, session_ctx) 
       ```
    - calculates a partial signature for `bitcoin_ID_1` as follows:
       ```
       partial_sig_bitcoin_1 = MuSig2.Sign(announcement_bitcoin_secnonce_1, bitcoin_priv_key_1, session_ctx) 
       ```
    - calculates `partial_sig_1` as follows:
       ```
       partial_sig_1 =  MuSig2.PartialSigAgg(partial_sig_node_1, partial_sig_bitcoin_1, session_ctx)
       ```

- `node_2`:
    - calculates a partial signature for `node_ID_2` as follows:
       ```
       partial_sig_node_2 = MuSig2.Sign(announcement_node_secnonce_2, node_ID_priv_key_2, session_ctx) 
       ```
    - calculates a partial signature for `bitcoin_ID_2` as follows:
       ```
       partial_sig_bitcoin_2 = MuSig2.Sign(announcement_bitcoin_secnonce_2, bitcoin_priv_key_2, session_ctx) 
       ```
    - calculates `partial_sig_2` as follows:
       ```
       partial_sig_2 =  MuSig2.PartialSigAgg(partial_sig_node_2, partial_sig_bitcoin_2, session_ctx)
       ```     

Note that since there are no tweaks involved in this MuSig2 signing flow,
signature aggregation is simply the addition of the two signatures:

```
    partial_sig = (partial_sig_node + partial_sig_bitcoin) % n
```

Where `n` is the [secp256k1][secp256k1] curve order.

### Partial Signature Verification

Since the partial signature put in `announcement_signatures_2` is the addition
of two of four signatures required to make up the final MuSig2 signature, the
verification of the partial signature is slightly different from what is
specified in the MuSig2 spec. The slightly adjusted algorithm will be defined
here. The notation used is the same as defined in the [MuSig2][musig-notation]
spec.

The inputs are:

- `partial_sig` sent by the peer in the `announcement_signatures_2` message.
- The `node_ID` and `bitcoin_key` of the peer.
- The `announcement_node_pubnonce` and `announcement_bitcoin_pubnonce` sent by
  the peer in the `channel_ready` message.
- The `session_ctx` as shown
  in [Partial Signature Calculation](#partial-signature-calculation).

Verification steps:

Note that the `GetSessionValues` and `GetSessionKeyAggCoeff` definitions can be
found in the [MuSig2][musig-session-ctx] spec.

- Let `(Q, _, _, b, R, e) = GetSessionValues(session_ctx)`
- Let `s = int(psig); fail if s >= n`
- Let `R_n1 = cpoint(announcement_node_pubnonce[0:33])`
- Let `R_n2 = cpoint(announcement_node_pubnonce[33:66])`
- Let `R_b1 = cpoint(announcement_bitcoin_pubnonce[0:33])`
- Let `R_b2 = cpoint(announcement_bitcoin_pubnonce[33:66])`
- Let `R_1 = R_n1 + R_b1`
- Let `R_2 = b*(R_n2 + R_b2)`
- Let `R_e' = R_1 + R_2`
- Let `R_e = R_e'` if `has_even_y(R)`, otherwise let `R_e = -R_e'`
- Let `P_n = node_ID`
- Let `P_b = bitcoin_key`
- Let `a_n = GetSessionKeyAggCoeff(session_ctx, P_n)`
- Let `a_b = GetSessionKeyAggCoeff(session_ctx, P_b)`
- Let `P = a_n*P_n + a_b*P_b`
- Let `g = 1` if `has_even_y(Q)`, otherwise `let g = -1 mod n`
- Fail if `s*G != R_e + e*g*P`

### Signature Message Construction

The following `MsgHash` function is defined which can be used to construct a
32-byte message that can be used as a valid input to the [BIP-340][bip-340]
signing and verification algorithms.

_MsgHash:_
  - _inputs_:
    * `message_name`: UTF-8 string
    * `field_name`: UTF-8 string
    * `message`: byte array

  - Let `tag` = "lightning" || `message_name` || `field_name`
  - return SHA256(SHA256(`tag`) || SHA256(`tag`) || SHA256(`message`))


# Appendix B: Test Vectors

TODO(elle)

# Acknowledgements

The ideas in this document are largely a consolidation and filtering of the
ideas mentioned in the following references:

- [Rusty's initial Gossip v2 proposal][ml-rusty-2019-gossip-v2] where the idea
  of replacing all gossip messages with new ones that use Schnorr signatures was
  first mentioned (in public writing). This post also included the idea of using
  block heights instead of Unix timestamps for timestamp fields as well as the
  idea of moving some optional fields to TLVs.
- [Roasbeef's post][ml-roasbeef-2022-tr-chan-announcement] on Taproot-aware
  Channel Announcements + Proof Verification which expands on the details of how
  taproot channel verification should work.

[bolt-7]: ./07-routing-gossip.md
[bolt-7-alias-security]: ./07-routing-gossip.md#security-considerations-for-node-aliases
[bolt-9-features]: ./09-features.md#bolt-9-assigned-feature-flags
[bolt-11]: ./11-payment-encoding.md
[bolt-11-tagged-fields]: ./11-payment-encoding.md#tagged-fields
[open-chan-msg]: ./02-peer-protocol.md#the-open_channel-message
[ml-rusty-2019-gossip-v2]: https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-July/002065.html
[ml-roasbeef-2022-tr-chan-announcement]: https://lists.linuxfoundation.org/pipermail/lightning-dev/2022-March/003526.html
[bip-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[bip-340-verify]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
[simple-taproot-chans]: https://github.com/lightning/bolts/pull/995
[musig-keysort]: https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki#key-sorting
[musig-keyagg]: https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki#key-aggregation
[musig-signing]: https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki#signing
[bip86-tweak]: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#address-derivation
[bip-musig2]: https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki
[musig-session-ctx]: https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki#session-context
[musig-notation]: https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki#notation
[musig-partial-sig-agg]: https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki#partial-signature-aggregation
[secp256k1]: https://www.secg.org/sec2-v2.pdf
[punycode]: https://en.wikipedia.org/wiki/Punycode
[prop224]: https://gitweb.torproject.org/torspec.git/tree/proposals/224-rend-spec-ng.txt
