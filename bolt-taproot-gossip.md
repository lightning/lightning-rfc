# Extension BOLT XX: Taproot Gossip

This document aims to update the gossip protocol defined in [BOLT 7][bolt-7] to
allow for advertisement and verification of taproot channels. An entirely new
set of gossip messages are defined that use [BIP-340][bip-340] signatures and
that use a mostly TLV based structure.

# Table Of Contents

* [Terminology](#terminology)
* [Taproot Channel Proof and Verification](#taproot-channel-proof-and-verification)
* [TLV Based Messages](#tlv-based-messages)
* [Block-height fields](#block-height-fields)
* [Bootstrapping Taproot Gossip](#bootstrapping-taproot-gossip)
* [Specification](#specification)
    * [Type Definitions](#type-definitions)
    * [Features Bits](#feature-bits)
    * [Features Bit Contexts](#feature-bit-contexts)
    * [`open_channel` Extra Requirements](#openchannel-extra-requirements)
    * [`channel_ready` Extensions](#channelready-extensions)
    * [The `announcement_signatures_2` Message](#the-announcementsignatures2-message)
    * [The `channel_announcement_2` Message](#the-channelupdate2-message)
    * [The `node_announcement_2` Message](#the-nodeannouncement2-message)
    * [The `channel_update_2` Message](#the-channelupdate2-message)
* [Appendix A: Algorithms](#appendix-a-algorithms)
    * [Partial Signature Calculation](#partial-signature-calculation)
    * [Partial Signature Verification](#partial-signature-verification)
    * [Verifying the `channel_announcement_2` signature](#verifying-the-channelannouncement2-signature)
        * [The 3-of-3 MuSig2 Scenario](#the-3-of-3-musig2-scenario)
        * [The 4-of-4 MuSig2 Scenario](#the-4-of-4-musig2-scenario)
    * [Signature Message Construction](#signature-message-construction)
* [Appendix B: Test Vectors](#appendix-b-test-vectors)
* [Acknowledgements](#acknowledgements)

## Terminology

- Collectively, the set of new gossip messages will be referred to as
  `taproot gossip`.
- `node_1` and `node_2` refer to the two parties involved in opening a channel.
- `node_ID_1` and `node_ID_2` respectively refer to the public keys that
  `node_1` and `node_2` use to identify their nodes in the network.
- `bitcoin_key_1` and `bitcoin_key_2` respectively refer to the public keys
  that `node_1` and `node_2` will use for the specific channel being opened.
  The funding transaction's output will be derived from these two keys.

## Taproot Channel Proof and Verification

All Taproot channel funding transaction outputs are SegWit V1 (P2TR) outputs of
the following form:

```
OP_1 <taproot_output_key> 
```

Ideally, the construction of the `taproot_output_key` should not matter to a
verifier of a channel. What a verifier cares about is whether the UTXO is
unspent and if the associated channel announcement contains a signature that
proves that the owner of the UTXO has participated in the signature
construction.

The simplest verification of a channel-announcement signature would then be to
check that the signature is valid for the following aggregate 3-of-3 MuSig2
public key:

```
P_agg = MuSig2.KeyAgg(MuSig2.KeySort(node_id_1, node_id_2, taproot_output_key))
```

This is simple and the spec can cater for this verification method today.
However, the spec must also contain recommendations for the construction of a
channel along with recommendations for the construction of a channel
announcement signature. The `taproot_output_key` will most likely be constructed
out of two or more keys where both channel peers own at least one key each and
so to compute a valid signature for the `P_agg` key noted above, the two channel
parties would need to make use of a nested MuSig2 protocol. Such a protocol has
yet to be specified and so this document can not yet rely on or reference such
a protocol.

Therefore, this document will also cater for the verification and construction
of a channel announcement signature for the following 4-of-4 MuSig2 public key:

```
P_agg = MuSig2.KeyAgg(MuSig2.KeySort(node_id_1, node_id_2, bitcoin_key_1, bitcoin_key_2))
```

In this case, the `taproot_output_key` is expected to be constructed in one of
two ways. The first way is as a pure key path spend output as follows:

```
taproot_output_key = MuSig2.KeyAgg(MuSig2.KeySort(bitcoin_key_1, bitcoin_key_2))
```

The second way includes a possible tweak:

```
taproot_internal_key = MuSig2.KeyAgg(MuSig2.KeySort(bitcoin_key_1, bitcoin_key_2))

taproot_output_key = taproot_internal_key + tagged_hash("TapTweak", merkle_root_hash) * G
```

In the case of Simple Taproot Channels, the `merkle_root_hash` will be equal to
the serialisation of the `taproot_internal_key`.

The verification method used all depends on which information is provided in the
`channel_announcement_2` message. All of these verification methods require
the `node_id_1` and `node_id_2` to be provided along with a `short_channel_id`
that will allow the verifier to fetch the funding output from which the
`taproot_output_key` can be extracted.

1. If no bitcoin keys are provided, then the signature must be verified against
   the following public key:

   ```
   P_agg = MuSig2.KeyAgg(MuSig2.KeySort(node_id_1, node_id_2, taproot_output_key)) 
   ```

   Allowing this proof type allows nodes to be somewhat future-proof since they
   will be able to verify and make use of channels using a proof construction
   not yet defined.

2. If the two bitcoin keys (`bitcoin_key_1` and `bitcoin_key_2`) are provided
   but no `merkle_root_hash` is provided then the verification steps are as
   follows:

    1. Compute the following aggregate 2-of-2 MuSig2 public key:
       ```
       P_agg_out = MuSig2.KeyAgg(MuSig2.KeySort(bitcoin_key_1, bitcoin_key_2))
       ```
    2. Assert that `P_agg_out` is equal to `taproot_output_key`.
    3. Now, compute the following aggregate 4-of-4 MuSig2 public key:
       ```
       P_agg = MuSig2.KeyAgg(MuSig2.KeySort(node_id_1, node_id_2, bitcoin_key_1, bitcoin_key_2))
       ```
    4. The signature must then be verified against `P_agg`.

3. If the two bitcoin keys and the `merkle_root_hash` is provided, then the
   verification steps are as follows:

    1. Compute the following aggregate 2-of-2 MuSig2 public key:
       ```
       P_internal = MuSig2.KeyAgg(MuSig2.KeySort(bitcoin_key_1, bitcoin_key_2))
       ``` 
    2. The compute the following output public key:
       ```
       P_output = P_internal + tagged_hash("TapTweak", merkle_root_hash) * G
       ```
    3. Assert that `P_output` is equal to `taproot_output_key`.
    4. Now, compute the following aggregate 4-of-4 MuSig2 public key:
       ```
       P_agg = MuSig2.KeyAgg(MuSig2.KeySort(node_id_1, node_id_2, bitcoin_key_1, bitcoin_key_2))
       ```
    5. The signature must then be verified against `P_agg`.

In terms of construction of the proofs, this document covers case 2 and 3.

## TLV Based Messages

The initial set of Lightning Network messages consisted of a flat set of
serialised fields that were mandatory. Later on, TLV encoding was introduced
which provided a backward compatible way to extend messages. To ensure that the
new messages defined in this document remain as future-proof as possible, the
messages will mostly be pure TLV streams with a fixed 64-byte signature over the
tlv stream appended at the front of the message. By making all fields in the
messages TLV records, fields that we consider mandatory today can easily be
dropped in future (when coupled with a new feature bit) without needing to
completely redefine the gossip message in order to make the field optional.

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
for `channel_update_2` messages, the first `blockheight` must be the block
height in which the channel funding transaction was mined and all updates after
the initial one must have increasing block heights. Nodes are then responsible
for building up their own timestamp buffer: if they want to be able to send
multiple `channel_update_2` messages per block, then they will need to ensure
that there are blocks during which they do not broadcast any updates. This
provides an incentive for nodes not to spam the network with too many updates.

TODO:
- how do we choose a minimum block-height for `node_announcement_2`?

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
| 2        | yes                 | no                    | yes                             | ?                                 |
| 3        | yes                 | yes                   | yes                             | ?                                 |
| 4        | no                  | yes                   | no                              | yes                               |

### Scenario 1

These nodes have no announced channels and so should not be broadcasting legacy
or new node announcement messages.

### Scenario 2

If a node has legacy channels but no taproot channels, they should continue to
broadcast the legacy `node_announcement` message so that un-upgraded nodes can
continue to receive `node_annoucement`s from these nodes which will initially
also be the most effective way to spread the `option_taproot_gossip` feature
bit to the rest of the network which will then allow upgraded nodes to find
each-other.

TODO: should these nodes also send the new node announcement? if so:
- how do we deal with differences in the two announcements?
- also, how does a receiving node confirm which announcement is the latest
one given that they don't use the same timestamp type?

### Scenario 3

Similar to scenario 2.

### Scenario 4

If a node has no more legacy channels, then it will not be able to advertise
a legacy `node_announcement` since un-upgraded nodes will drop the announcements
due to no open channel will be known for that node. So in this case, only a
new `node_announcement_2` can be used.

### Considerations & Suggestions

While the network is in the upgrade phase, the following suggestions apply:

- Nodes are encouraged to actively connect to other nodes that advertise the
  `option_taproot_gossip` feature bit as this is the only way in which they
  will learn about taproot channel announcements and updates. This should be
  done while taking care not to split the network.

## Specification

### Type Definitions

The following convenient types are defined:

* `bip340sig`: a 64-byte bitcoin Elliptic Curve Schnorr signature as
  per [BIP-340][bip-340].
* `partial_signature`: a 32-byte partial MuSig2 signature as defined
  in [BIP-MuSig2][bip-musig2].
* `public_nonce`: a 66-byte public nonce as defined in [BIP-MuSig2][bip-musig2].
* `utf8`: a byte as part of a UTF-8 string. A writer MUST ensure an array of
  these is a valid UTF-8 string, a reader MAY reject any messages containing an
  array of these which is not a valid UTF-8 string.

### Feature Bits

A new feature bit, `option_taproot_gossip`, is introduced. Nodes can use this
feature bit in the `init` and _legacy_ `node_announcement` messages to advertise
that they understand the new set of taproot gossip messages and that will
therefore be able to route over Taproot Channels. If a node advertises
both the `option_taproot_gossip`  _and_ the `option_taproot` feature bits, then
that node has the ability to open and announce a Simple Taproot Channel.

| Bits  | Name                    | Description                               | Context | Dependencies |
|-------|-------------------------|-------------------------------------------|---------|--------------|
| 32/33 | `option_taproot_gossip` | Node understands taproot gossip messages  | IN      |              | 

### Feature Bit Contexts

For all feature bits other than `option_taproot_gossip` defined in
[Bolt 9][bolt-9-features] with the `N` and `C` contexts, it can be assumed that
those contexts will now refer to the new `node_announcement_2` and
`channel_announcement_2` messages defined in this document. The
`option_taproot_gossip` feature bit only makes sense in the context of the
legacy messages since it can be implied with the new taproot gossip messages.

### `open_channel` Extra Requirements

These extra requirements only apply if the `option_taproot` channel type is set
in the `open_channel` message.

The sender:
- if `option_taproot_gossip` was negotiated:
    - MAY set the `announce_channel` bit in `channel_flags`
- otherwise:
    - MUST NOT set the `announce_channel` bit.

The receiver:
- if `option_taproot_gossip` was not negotiated and the `announce_channel` bit
  in `channel_flags` was set, MUST fail the channel.

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

#### Requirements

The sender:

- MAY send `channel_ready` message without the `announcement_node_pubnonce` and
  `announcement_bitcoin_pubnonce` fields.
- Once the channel is ready to be announced, the node:
    - SHOULD send `channel_ready` with the `announcement_node_pubnonce` and
      `announcement_bitcoin_pubnonce` fields set. The `announcement_node_pubnonce`
      must be set to the public nonce to be used for signing with the node's
      bitcoin key and the `announcement_bitcoin_pubnonce` must be set to the
      public nonce to be used for signing with the node's node ID key.
    - Upon reconnection, if a fully signed `channel_announcement_2` has not yet
      been constructed:
        - SHOULD re-send `channel_ready` with the nonce fields set.
- Once a `channel_ready` message with announcement nonces has been both sent and
  received:
    - MUST proceed with constructing and sending the `announcement_signatures_2`
      message.

- TODO: recommend nonce generation technique.
- TODO: can we guarantee progress here?

The recipient:

- If the nonce fields are set:
    - If only one of the nonce fields are set:
        - MUST ignore the message.
        - SHOULD send a warning.
        - MAY fail the connection.
    - If the channel has not reached sufficient confirmations:
        - SHOULD ignore the message.
    - Otherwise:
        - MUST store the nonces so that they can be used for the partial signature
          construction required for constructing the `announcement_signatures_2`
          message.
        - If it has not yet done so, SHOULD respond with its own `channel_ready`
          message with the nonce fields set.

#### Rationale

It cannot be a requirement that a node include the nonce fields in the
`channel_ready` since for cases such as zero-conf channels, nodes may send
`channel_ready` multiple times throughout the life of the channel to update it's
preferred channel alias, and it does not make sense to require that the nonce
fields be populated once the channel has already been announced.

### The `announcement_signatures_2` Message

Like the legacy `announcement_signatures` message, this is a direct message
between the two endpoints of a channel and serves as an opt-in mechanism to
allow the announcement of the channel to the rest of the network.

1. type: 260 (`announcement_signatures_2`)
2. data:
    * [`channel_id`:`channel_id`]
    * [`short_channel_id`:`short_channel_id`]
    * [`partial_signature`:`partial_signature`]

#### Requirements

The requirements are similar to the ones defined for the legacy
`announcement_signatures`. The below requirements assume that the
`option_taproot` channel type was set in `open_channel`.

A node:
- if the `open_channel` message has the `announce_channel` bit set AND a
  `shutdown` message has not been sent:
    - MUST send the `announcement_signatures_2` message once a `channel_ready`
      message containing the announcement nonces has been sent and received AND
      the funding transaction has at least six confirmations.
    - MUST set the `partial_signature` field to the 32-byte `partial_sig` value
      of the partial signature calculated as described in [Partial Signature
      Calculation](#partial-signature-calculation). The message to be signed is
      `MsgHash("channel_announcement", "signature", m)` where `m` is the
      serialisation of the `channel_announcement_2` message tlv stream (see the
      [`MsgHash`](#signature-message-construction) definition).
- otherwise:
    - MUST NOT send the `announcement_signatures_2` message.
- upon reconnection (once the above timing requirements have been met):
    - MUST re-send a `channel_ready` message with the nonce fields set and await
      a reply.
    - Then, MUST respond to the first `announcement_signatures_2` message with
      its own `announcement_signatures_2` message.
    - if it has NOT received an `announcement_signatures_2` message:
        - SHOULD retransmit the `channel_ready` and `announcement_signatures_2`
          messages.

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

#### Rationale

The message contains the necessary partial signature, by the sender, that the
recipient will be able to combine with their own partial signature to construct
the signature to put in the `channel_announcement_2` message. Unlike the legacy
`announcement_signatures` message, `announcement_signatures_2` only has one
signature field. This field is a MuSig2 partial signature which is the
aggregation of the two signatures that the sender would have created (one for
`bitcoin_key_x` and another for `node_ID_x`).

### The `channel_announcement_2` Message

This gossip message contains ownership information regarding a taproot channel.
It ties each on-chain Bitcoin key that makes up the taproot output key to the
associated Lightning node key, and vice-versa. The channel is not practically
usable until at least one side has announced its fee levels and expiry, using
`channel_update_2`.

See [Taproot Channel Proof and Verification](#taproot-channel-proof-and-verification)
for more information regarding the requirements for proving the existence of a
channel.

1. type: 267 (`channel_announcement_2`)
2. data:
    * [`bip340sig`:`signature`]
    * [`channel_announcement_2_tlvs`:`tlvs`]

1. `tlv_stream`: `channel_announcement_2_tlvs`
2. types:
    1. type: 0 (`chain_hash`)
    2. data:
        * [`chain_hash`:`chain_hash`]
    1. type: 2 (`features`)
    2. data:
        * [`...*byte`:`features`]
    1. type: 4 (`short_channel_id`)
    2. data:
        * [`short_channel_id`:`short_channel_id`]
    1. type: 6 (`capacity_satoshis`)
    2. data:
        * [`u64`:`capacity_satoshis`]
    1. type: 8 (`node_id_1`)
    2. data:
        * [`point`:`node_id_1`]
    1. type: 10 (`node_id_2`)
    2. data:
        * [`point`:`node_id_2`]
    1. type: 12 (`bitcoin_key_1`)
    2. data:
        * [`point`:`bitcoin_key_1`]
    1. type: 14 (`bitcoin_key_2`)
    2. data:
        * [`point`:`bitcoin_key_2`]
    1. type: 16 (`merkle_root_hash`)
    2. data:
        * [`32*byte`:`hash`]

#### Message Field Descriptions

TODO

#### Requirements

TODO

### The `node_announcement_2` Message

This gossip message, like the legacy `node_announcement` message, allows a node
to indicate extra data associated with it, in addition to its public key.
To avoid trivial denial of service attacks, nodes not associated with an already
known channel (legacy or taproot) are ignored.

Unlike the legacy `node_announcement` message, this message makes use of a
BIP340 signature instead of an ECDSA one. This will allow nodes to be backed
by multiple keys since MuSig2 can be used to construct the single signature.

1. type: 269 (`node_announcement_2`)
2. data:
    * [`bip340sig`:`signature`]
    * [`node_announcement_2_tlvs`:`tlvs`]

1. `tlv_stream`: `node_announcement_2_tlvs`
2. types:
    1. type: 0 (`features`)
    1. type: 1 (`color`)
    2. data:
        * [`rgb_color`:`rgb_color`]
    2. data:
        * [`...*byte`: `features`]
    1. type: 2 (`block_height`)
    1. type: 3 (`alias`)
    2. data:
        * [`...*utf8`:`alias`]
    2. data:
        * [`u32`: `block_height`]
    1. type: 4 (`node_id`)
    2. data:
        * [`point`:`node_id`]
    1. type: 5 (`ipv4_addrs`)
    2. data:
        * [`...*ipv4_addr`: `ipv4_addresses`]
    1. type: 7 (`ipv6_addrs`)
    2. data:
        * [`...*ipv6_addr`: `ipv6_addresses`]
    1. type: 9 (`tor_v3_addrs`)
    2. data:
        * [`...*tor_v3_addr`: `tor_v3_addresses`]
    1. type: 11 (`dns_hostnames`)
    2. data:
        * [`...*dns_hostname`: `dns_hostnames`]

The following subtypes are defined:

1. subtype: `rgb_color`
2. data:
    * [`byte`:`red`]
    * [`byte`:`green`]
    * [`byte`:`blue`]

1. subtype: `ipv4_addr`
2. data:
    * [`u32`:`addr`]
    * [`u16`:`port`]

1. subtype: `ipv6_addr`
2. data:
    * [`16*byte`:`addr`]
    * [`u16`:`port`]

1. subtype: `tor_v3_addr`
2. data:
    * [`35*utf8`:`onion_addr`]
    * [`u16`:`port`]

1. subtype: `dns_hostname`
2. data:
    * [`u16`:`len`]
    * [`len*utf8`:`hostname`]
    * [`u16`:`port`]

#### Message Field Descriptions

- `signature` is the [BIP340][bip-340] signature for the `node_id` key. The
  message to be signed is `MsgHash("node_announcement_2", "signature", m)`
  where `m` is the serialised TLV stream (see the
  [`MsgHash`](#signature-message-construction) definition).
- `features` is a bit vector with bits set according to [BOLT #9](09-features.md#assigned-features-flags)
- `block_height` allows for ordering or messages in the case of multiple
  announcements and also allows for natural rate limiting of
  `node_announcement_2` messages.
- `node_id` is the public key associated with this node. It must match a node ID
  that has previously been announced in the `node_id_1` or `node_id_2` fields of
  a `channel_announcement` or `channel_announcement_2` message for a channel
  that is still open.
- `rgb_color` is an optional field that a node may use to assign itself a color.
- `alias` is an optional field that a node may use to assign itself an alias
  that can then be used for a nicer UX on intelligence services. If this field
  is set, then it MUST be 32 utf8 characters or less.
- `ipv4_addr` is an ipv4 address and port.
- `ipv6_addr` is an ipv6 address and port.
- `tor_v3_addr` is a Tor version 3 ([prop224]) onion service address;
  Its `onion_addr` encodes:
  `[32:32_byte_ed25519_pubkey] || [2:checksum] || [1:version]`, where
  `checksum = sha3(".onion checksum" | pubkey || version)[:2]`.
- `dns_hostname` is a DNS hostname. The `hostname` MUST be ASCII characters.
  Non-ASCII characters MUST be encoded using [Punycode][punycode]. The length of
  the `hostname` cannot exceed 255 bytes.

#### Requirements

TODO: flesh out when it is ok to send new vs old node announcement. Is it ever
ok to send both? if so - what if the info inside them differs?

The sender:

- MUST set TLV fields 0, 2 and 4.
- MUST set `signature` to a valid [BIP340][bip-340] signature for the
  `node_id` key. The message to be signed is
  `MsgHash("node_announcement_2", "signature", m)` where `m` is the
  serialisation of the `node_announcement_2` message excluding the
  `signature` field (see the
  [`MsgHash`](#signature-message-construction) definition).
- MAY set `color` and `alias` to customise appearance in maps and graphs.
- If the node sets the `alias`:
    - MUST use 32 utf8 characters or less.
- MUST set `block_height` to be greater than that of any previous
  `node_announcement_2` it has previously created.
- TODO: how to determine a lower bound for the block_height of the node_ann?
  cant say "must be greater than or = oldest advertised channel" since a node
  could open a new channel and close the previous which would then invalidate
  the node_announcement.
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

The receiver:

- If type 0, 2 or 4 is missing:
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
- if `signature` is NOT a valid [BIP340][bip-340] signature (using
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

### Rationale

New node features are possible in the future: backwards compatible (or
optional) ones will have _odd_ `feature` _bits_, incompatible ones will have
_even_ `feature` _bits_. These will be propagated normally; incompatible feature
bits here refer to the nodes, not the `node_announcement_2` message itself.

### Security Considerations for Node Aliases

The security considerations for node aliases mentioned in
[BOLT #7][bolt-7-alias-security] apply here too.

### The `channel_update_2` Message

- TODO: should updates for legacy channels also sometimes be broadcast using the
  new format for easier set reconciliation?

After a channel has been initially announced via `channel_announcement_2`, each
side independently announces the fees and minimum expiry delta it requires to
relay HTLCs through this channel. Each uses the 8-byte short channel id that
matches the `channel_announcement_2` and the `direction` field to
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
1. type: 271 (`channel_update_2`)
2. data:
    * [`bip340sig`:`signature`]
    * [`channel_update_2_tlvs`:`tlvs`]

1. `tlv_stream`: `channel_update_2_tlvs`
2. types:
    1. type: 0 (`chain_hash`)
    2. data:
        * [`chain_hash`:`chain_hash`]
    1. type: 2 (`short_channel_id`)
    2. data:
        * [`short_channel_id`:`short_channel_id`]
    1. type: 4 (`block_height`)
    2. data:
        * [`u32`:`block_height`]
    1. type: 6 (`disable_flags`)
    2. data:
        * [`byte`:`disable_flags`]
    1. type: 8 (`second_peer`)
    1. type: 10 (`cltv_expiry_delta`)
    2. data:
        * [`u16`:`cltv_expiry_delta`]
    1. type: 12 (`htlc_minimum_msat`)
    2. data:
        * [`u64`:`htlc_minimum_msat`]
    1. type: 14 (`htlc_maximum_msat`)
    2. data:
        * [`u64`:`htlc_maximum_msat`]
    1. type: 16 (`fee_base_msat`)
    2. data:
        * [`u32`:`fee_base_msat`]
    1. type: 18 (`fee_proportional_millionths`)
    2. data:
        * [`u32`:`fee_proportional_millionths`]


The `disable_flags` bitfield is used to indicate that the channel is either
temporarily or permanently disabled. The following table specifies the meaning 
of the individual bits:

| Bit Position | Name        | Meaning                                               |
|--------------|-------------|-------------------------------------------------------|
| 0            | `permanant` | The disable update is permanent (otherwise temporary) |
| 1            | `incoming`  | The node can't receive via this channel               |
| 2            | `outgoing`  | The node can't forward or send via this channel       |

Both the `incoming` and `outgoing` bit can be set to indicate that the channel
peer is offline.

If the `permanant` bit is set, then the channel can be considered closed. 

#### Message Field Descriptions

- The `chain_hash` is used to identify the blockchain containing the channel
  being referred to.
- `short_channel_id` is the unique identifier of the channel. If the channel is
  unannounced, then this may be set to an agreed upon alias.
- `block_height` is the timestamp associated with the message. A node may not
  send two `channel_update` messages with the same `block_height`. The
  `block_height` must also be greater than or equal to the block height
  indicated by the `short_channel_id` used in the `channel_announcement` and
  must not be less than current best block height minus 2016 (~2 weeks of
  blocks).
- The `disable` bit field can be used to advertise to the network that a channel
  is disabled and that it should not be used for routing. The individual
  `disable_flags` bits can be used to communicate more fine-grained information.
- The `second_peer` is used to indicate which node in the channel node pair has 
  created and signed this message. If present, the node was `node_id_2` in the
  `channel_announcment`, otherwise the node is `node_id_1` in the 
  `channel_announcement` message.
- `cltv_expiry_delta` is the number of blocks that the node will subtract from
  an incoming HTLC's `cltv_expiry`.
- `htlc_minimum_msat` is the minimum HTLC value (in millisatoshi) that the
  channel peer will accept.
- `htlc_maximum_msat` is the maximum value the node will send through this
  channel for a single HTLC.
    - MUST be less than or equal to the channel capacity
    - MUST be less than or equal to the `max_htlc_value_in_flight_msat` it
      received from the peer in the `open_channel` message.
- `fee_base_msat` is the base fee (in millisatoshis) that the node will charge
  for an HTLC.
- `fee_proportional_millionths` is the amount (in millionths of a satoshi) that
  node will charge per transferred satoshi.

#### TLV Defaults

For types 0, 6, 10, 12, 14, 16 and 18, the following defaults apply if the
TLV is not present in the message:

| `channel_update_2` TLV Type        | Default Value                                                      | Comment                                                                                     |
|------------------------------------|--------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| 0  (`chain_hash`)                  | `6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000` | The hash of the genesis block of the mainnet Bitcoin blockchain.                            | 
| 6  (`disable`)                     | empty                                                              |                                                                                             | 
| 10 (`cltv_expiry_delta`)           | 80                                                                 |                                                                                             | 
| 12 (`htlc_minimum_msat`)           | 1                                                                  |                                                                                             | 
| 14 (`htlc_maximum_msat`)           | floor(channel capacity / 2)                                        | // TODO: remove this since makes encoding/decoding dependent on things outside the message? | 
| 16 (`fee_base_msat`)               | 1000                                                               |                                                                                             | 
| 18 (`fee_proportional_millionths`) | 1                                                                  |                                                                                             |

#### Requirements

The origin node:

- For all fields with defined defaults:
    - SHOULD not include the field in the TLV stream if the default value is
      desired.
- MUST use the `channel_update_2` message to communicate channel parameters of a
  Taproot channel.
- MAY use the `channel_update_2` message to communicate channel parameters of a
  legacy (P2SH) channel.
- MUST NOT send a created `channel_update_2` before `channel_ready` has been
  received.
- For an unannounced channel (i.e. one where the `announce_channel` bit was not
  set in `open_channel`):
    - MAY create a `channel_update_2` to communicate the channel parameters to the
      channel peer.
    - MUST set the `short_channel_id` to either an `alias` it has received from
      the peer, or the real channel `short_channel_id`.
    - MUST NOT forward such a `channel_update_2` to other peers, for privacy
      reasons.
- For announced channels:
    - MUST set `chain_hash` AND `short_channel_id` to match the 32-byte hash AND
      8-byte channel ID that uniquely identifies the channel specified in the
      `channel_announcement_2` message.
- MUST set `signature` to a valid [BIP340][bip-340] signature for its own
  `node_id` key. The message to be signed is
  `MsgHash("channel_update_2", "signature", m)` where `m` is the serialised
  TLV stream of the `channel_update` (see the
  [`MsgHash`](#signature-message-construction) definition).
- SHOULD NOT create redundant `channel_update_2`s.
- If it creates a new `channel_update_2` with updated channel parameters:
    - SHOULD keep accepting the previous channel parameters for 2 blocks.

The receiving node:

- If the `short_channel_id` does NOT match a previous `channel_announcement_2`
  or `channel_announcement`, OR if the channel has been closed in the meantime:
    - MUST ignore `channel_update_2`s that do NOT correspond to one of its own
      channels.
- SHOULD accept `channel_update_2`s for its own channels (even if non-public),
  in order to learn the associated origin nodes' forwarding parameters.
- if `signature` is NOT a valid [BIP340][bip-340] signature (using `node_id`
  over the message):
    - SHOULD send a `warning` and close the connection.
    - MUST NOT process the message further.

#### Rationale

- An even type is used so that best-effort propagation can be used.

### Query Messages

TODO: 
    1. new first block height & block range fields in gossip_timestamp_range
    2. add block-height query option (like timestamps query option)

# Appendix A: Algorithms

## Partial Signature Calculation

When both nodes have exchanged a `channel_ready` message containing the
`announcement_node_pubnonce` and `announcement_bitcoin` fields then they will
each have the following information:

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
`channel_announcement_2` _without_ the `signature` field (i.e. without
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

## Partial Signature Verification

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

## Verifying the `channel_announcement_2` signature

For all the following cases, it should be verified that the output at the
provided `short_channel_id` is an unspent Taproot output.

### The 3-of-3 MuSig2 Scenario

In the case where a received `channel_announcement_2` message is received which
does not have the optional `bitcoin_key_*` fields, the signature of the message
should be verified as a 3-of-3 MuSig2 signature. The keys involved are:
`node_id_1`, `node_id_2` and the taproot output key (`tr_output_key`) found in
the channel's funding output specified by the provided `short_channel_id`.

The full list of inputs required:
- `node_id_1`
- `node_id_2`
- `tr_output_key`
- `msg`: the serialised `channel_announcement_2` tlv stream.
- `sig`: the 64-byte BIP340 signature found in the `signature` field of the 
  `channel_announcement_2` message. This signature must be parsed into `R` and 
  `s` values as defined in BIP327.

The aggregate key can be calculated as follows:

```
P_agg = MuSig2.KeyAgg(MuSig2.KeySort(`node_id_1`, `node_id_2`, `tr_output_key`))
```

The signature can then be verified as follows:
- Let `pk` = `bytes(P_agg)` where the `bytes` function is defined in BIP340.
- Let `m` = `MsgHash("channel_announcement_2", "signature", msg)`
- Use the BIP340 `Verify` function to determine if the signature is valid by
  passing in `pk`, `m` and `sig`.

### The 4-of-4 MuSig2 Scenario

In the case where a received `channel_announcement_2` message is received which
does have both the optional `bitcoin_key_*` fields, the signature of the message
should be verified as a 4-of-4 MuSig2 signature. The keys involved are:
`node_id_1`, `node_id_2`, `bitcoin_key_1` and `bitcoin_key_2`. The message may
also optionally contain the `merkle_root_hash` field in this case.

Before the actual signature verification is done, it should first be asserted
that the taproot output key found in the funding output is in-fact made up of
the provided bitcoin keys. This can be done as follows:

First, calculate the aggregate key used as the internal key for the taproot
output, `P_internal`:

```
P_internal = KeyAgg(MuSig2.KeySort(`bitcoin_key_1`, `bitcoin_key_2`))
```

- Let `P_o` be the taproot output key found on-chain in the funding output
  referred to by the SCID.
- if the `merkle_root_hash` field is _not_ provided:
    - Fail the check if `P_internal != P_o`
- otherwise, if the `merkle_root_hash` is provided:
    - let `p` = `bytes(P_internal)`
    - let `t = hash_TapTweak(p || merkle_root_hash)` where `hash_TapTweak` uses
      the `hash_name(x)` method defined in BIP340.
    - Fail if `P_o != P_internal + t*G`

If the above check is successful, then it has been shown that the output key
is constructed from the two provided bitcoin keys. So now the signature
verification can be done.

The full list of inputs required:
- `node_id_1`
- `node_id_2`
- `bitcoin_key_1`
- `bitcoin_key_2`
- `msg`: the serialised `channel_announcement_2` tlv stream.
- `sig`: the 64-byte BIP340 signature found in the `signature` field of the 
  `channel_announcement_2` message. This signature must be parsed into `R` and 
  `s` values as defined in BIP327.

The aggregate key can be calculated as follows:

```
P_agg = MuSig2.KeyAgg(MuSig2.KeySort(`node_id_1`, `node_id_2`, `bitcoin_key_1`, `bitcoin_key_2`))
```

The signature can then be verified as follows:
- Let `pk` = `bytes(P_agg)` where the `bytes` function is defined in BIP340.
- Let `m` = `MsgHash("channel_announcement_2", "signature", msg)`
- Use the BIP340 `Verify` function to determine if the signature is valid by
  passing in `pk`, `m` and `sig`.

## Signature Message Construction

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

TODO

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
