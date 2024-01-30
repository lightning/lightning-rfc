# BOLT #4: Onion Routing Protocol

## Overview

This document describes the construction of an onion routed packet that is
used to route a payment from an _origin node_ to a _final node_. The packet
is routed through a number of intermediate nodes, called _hops_.

The routing schema is based on the [Sphinx][sphinx] construction and is
extended with a per-hop payload.

Intermediate nodes forwarding the message can verify the integrity of
the packet and can learn which node they should forward the
packet to. They cannot learn which other nodes, besides their
predecessor or successor, are part of the packet's route; nor can they learn
the length of the route or their position within it. The packet is
obfuscated at each hop, to ensure that a network-level attacker cannot
associate packets belonging to the same route (i.e. packets belonging
to the same route do not share any correlating information). Notice that this
does not preclude the possibility of packet association by an attacker
via traffic analysis.

The route is constructed by the origin node, which knows the public
keys of each intermediate node and of the final node. Knowing each node's public key
allows the origin node to create a shared secret (using ECDH) for each
intermediate node and for the final node. The shared secret is then
used to generate a _pseudo-random stream_ of bytes (which is used to obfuscate
the packet) and a number of _keys_ (which are used to encrypt the payload and
compute the HMACs). The HMACs are then in turn used to ensure the integrity of
the packet at each hop.

Each hop along the route only sees an ephemeral key for the origin node, in
order to hide the sender's identity. The ephemeral key is blinded by each
intermediate hop before forwarding to the next, making the onions unlinkable
along the route.

This specification describes _version 0_ of the packet format and routing
mechanism.

A node:
  - upon receiving a higher version packet than it implements:
    - MUST report a route failure to the origin node.
    - MUST discard the packet.

# Table of Contents

  * [Conventions](#conventions)
  * [Key Generation](#key-generation)
  * [Pseudo Random Byte Stream](#pseudo-random-byte-stream)
  * [Packet Structure](#packet-structure)
    * [Payload Format](#payload-format)
    * [Basic Multi-Part Payments](#basic-multi-part-payments)
    * [Route Blinding](#route-blinding)
  * [Accepting and Forwarding a Payment](#accepting-and-forwarding-a-payment)
    * [Payload for the Last Node](#payload-for-the-last-node)
    * [Non-strict Forwarding](#non-strict-forwarding)
  * [Shared Secret](#shared-secret)
  * [Blinding Ephemeral Keys](#blinding-ephemeral-keys)
  * [Packet Construction](#packet-construction)
  * [Packet Forwarding](#packet-forwarding)
  * [Filler Generation](#filler-generation)
  * [Returning Errors](#returning-errors)
    * [Failure Messages](#failure-messages)
    * [Receiving Failure Codes](#receiving-failure-codes)
  * [`max_htlc_cltv` Selection](#max-htlc-cltv-selection)
  * [Onion Messages](#onion-messages)
  * [Test Vector](#test-vector)
    * [Returning Errors](#returning-errors)
  * [References](#references)
  * [Authors](#authors)

# Conventions

There are a number of conventions adhered to throughout this document:

 - HMAC: the integrity verification of the packet is based on Keyed-Hash
   Message Authentication Code, as defined by the [FIPS 198
   Standard][fips198]/[RFC 2104][RFC2104], and using a `SHA256` hashing
   algorithm.
 - Elliptic curve: for all computations involving elliptic curves, the Bitcoin
   curve is used, as specified in [`secp256k1`][sec2]
 - Pseudo-random stream: [`ChaCha20`][rfc8439] is used to generate a
   pseudo-random byte stream. For its generation, a fixed 96-bit null-nonce
   (`0x000000000000000000000000`) is used, along with a key derived from a shared
   secret and with a `0x00`-byte stream of the desired output size as the
   message.
 - The terms _origin node_ and _final node_ refer to the initial packet sender
   and the final packet recipient, respectively.
 - The terms _hop_ and _node_ are sometimes used interchangeably, but a _hop_
   usually refers to an intermediate node in the route rather than an end node.
        _origin node_ --> _hop_ --> ... --> _hop_ --> _final node_
 - The term _processing node_ refers to the specific node along the route that is
   currently processing the forwarded packet.
 - The term _peers_ refers only to hops that are direct neighbors (in the
   overlay network): more specifically, _sending peers_ forward packets
   to _receiving peers_.
 - Each hop in the route has a variable length `hop_payload`.
    - The variable length `hop_payload` is prefixed with a `bigsize` encoding
      the length in bytes, excluding the prefix and the trailing HMAC.

# Key Generation

A number of encryption and verification keys are derived from the shared secret:

 - _rho_: used as key when generating the pseudo-random byte stream that is used
   to obfuscate the per-hop information
 - _mu_: used during the HMAC generation
 - _um_: used during error reporting
 - _pad_: use to generate random filler bytes for the starting mix-header
   packet

The key generation function takes a key-type (_rho_=`0x72686F`, _mu_=`0x6d75`, 
_um_=`0x756d`, or _pad_=`0x706164`) and a 32-byte secret as inputs and returns
a 32-byte key.

Keys are generated by computing an HMAC (with `SHA256` as hashing algorithm)
using the appropriate key-type (i.e. _rho_, _mu_, _um_, or _pad_) as HMAC-key
and the 32-byte shared secret as the message. The resulting HMAC is then
returned as the key.

Notice that the key-type does not include a C-style `0x00`-termination-byte,
e.g. the length of the _rho_ key-type is 3 bytes, not 4.

# Pseudo Random Byte Stream

The pseudo-random byte stream is used to obfuscate the packet at each hop of the
path, so that each hop may only recover the address and HMAC of the next hop.
The pseudo-random byte stream is generated by encrypting (using `ChaCha20`) a
`0x00`-byte stream, of the required length, which is initialized with a key
derived from the shared secret and a 96-bit zero-nonce (`0x000000000000000000000000`).

The use of a fixed nonce is safe, since the keys are never reused.

# Packet Structure

The packet consists of four sections:

 - a `version` byte
 - a 33-byte compressed `secp256k1` `public_key`, used during the shared secret
   generation
 - a 1300-byte `hop_payloads` consisting of multiple, variable length,
   `hop_payload` payloads
 - a 32-byte `hmac`, used to verify the packet's integrity

The network format of the packet consists of the individual sections
serialized into one contiguous byte-stream and then transferred to the packet
recipient. Due to the fixed size of the packet, it need not be prefixed by its
length when transferred over a connection.

The overall structure of the packet is as follows:

1. type: `onion_packet`
2. data:
   * [`byte`:`version`]
   * [`point`:`public_key`]
   * [`1300*byte`:`hop_payloads`]
   * [`32*byte`:`hmac`]

For this specification (_version 0_), `version` has a constant value of `0x00`.

The `hop_payloads` field is a structure that holds obfuscated routing information, and associated HMAC.
It is 1300 bytes long and has the following structure:

1. type: `hop_payloads`
2. data:
   * [`bigsize`:`length`]
   * [`length*byte`:`payload`]
   * [`32*byte`:`hmac`]
   * ...
   * `filler`

Where, the `length`, `payload`, and `hmac` are repeated for each hop;
and where, `filler` consists of obfuscated, deterministically-generated padding, as detailed in [Filler Generation](#filler-generation).
Additionally, `hop_payloads` is incrementally obfuscated at each hop.

Using the `payload` field, the origin node is able to specify the path and structure of the HTLCs forwarded at each hop.
As the `payload` is protected under the packet-wide HMAC, the information it contains is fully authenticated with each pair-wise relationship between the HTLC sender (origin node) and each hop in the path.

Using this end-to-end authentication, each hop is able to cross-check the HTLC
parameters with the `payload`'s specified values and to ensure that the
sending peer hasn't forwarded an ill-crafted HTLC.

Since no `payload` TLV value can ever be shorter than 2 bytes, `length` values of 0 and 1 are reserved.  (`0` indicated a legacy format no longer supported, and `1` is reserved for future use).

### `payload` format

This is formatted according to the Type-Length-Value format defined in [BOLT #1](01-messaging.md#type-length-value-format).

1. `tlv_stream`: `payload`
2. types:
    1. type: 2 (`amt_to_forward`)
    2. data:
        * [`tu64`:`amt_to_forward`]
    1. type: 4 (`outgoing_cltv_value`)
    2. data:
        * [`tu32`:`outgoing_cltv_value`]
    1. type: 6 (`short_channel_id`)
    2. data:
        * [`short_channel_id`:`short_channel_id`]
    1. type: 8 (`payment_data`)
    2. data:
        * [`32*byte`:`payment_secret`]
        * [`tu64`:`total_msat`]
    1. type: 10 (`encrypted_recipient_data`)
    2. data:
        * [`...*byte`:`encrypted_data`]
    1. type: 12 (`current_blinding_point`)
    2. data:
        * [`point`:`blinding`]
    1. type: 16 (`payment_metadata`)
    2. data:
        * [`...*byte`:`payment_metadata`]
    1. type: 18 (`total_amount_msat`)
    2. data:
        * [`tu64`:`total_msat`]
    1. type: 20 (`attributable_error`)
    2. data: <no data>

`short_channel_id` is the ID of the outgoing channel used to route the
message; the receiving peer should operate the other end of this channel.

`amt_to_forward` is the amount, in millisatoshis, to forward to the
next receiving peer specified within the routing information, or for
the final destination.

For non-final nodes, this includes the origin node's computed _fee_ for the
receiving peer, calculated according to the receiving peer's advertised fee
schema (as described in [BOLT #7](07-routing-gossip.md#htlc-fees)).

`outgoing_cltv_value` is the CLTV value that the _outgoing_ HTLC
carrying the packet should have.  Inclusion of this field allows a hop
to both authenticate the information specified by the origin node, and
the parameters of the HTLC forwarded, and ensure the origin node is
using the current `cltv_expiry_delta` value.

If the values don't correspond, this indicates that either a
forwarding node has tampered with the intended HTLC values or that the
origin node has an obsolete `cltv_expiry_delta` value.

The requirements ensure consistency in responding to an unexpected
`outgoing_cltv_value`, whether it is the final node or not, to avoid
leaking its position in the route.

`attributable_error` is a marker record that specifies that the failure message
in the `update_fail_htlc` response should be structured as an attributable
error. For the legacy format, this record should not be set.

### Requirements

The creator of `encrypted_recipient_data` (usually, the recipient of payment):

  - MUST create `encrypted_data_tlv` for each node in the blinded route (including itself).
  - MUST include `encrypted_data_tlv.short_channel_id` and `encrypted_data_tlv.payment_relay` for each non-final node.
  - MUST set `encrypted_data_tlv.payment_constraints` for each non-final node:
    - `max_cltv_expiry` to the largest block height at which the route is allowed to be used, starting
    from the final node and adding `encrypted_data_tlv.payment_relay.cltv_expiry_delta` at each hop.
    - `htlc_minimum_msat` to the largest minimum HTLC value the nodes will allow.
  - If it sets `encrypted_data_tlv.allowed_features`:
    - MUST set it to an empty array.
  - MUST compute the total fees and cltv delta of the route as follows and communicate them to the sender:
    - `total_fee_base_msat(n+1) = (fee_base_msat(n+1) * 1000000 + total_fee_base_msat(n) * (1000000 + fee_proportional_millionths(n+1)) + 1000000 - 1) / 1000000`
    - `total_fee_proportional_millionths(n+1) = ((total_fee_proportional_millionths(n) + fee_proportional_millionths(n+1)) * 1000000 + total_fee_proportional_millionths(n) * fee_proportional_millionths(n+1) + 1000000 - 1) / 1000000`
  - MUST create the `encrypted_recipient_data` from the `encrypted_data_tlv` as required in [Route Blinding](#route-blinding).

The writer of the TLV `payload`:

  - For every node inside a blinded route:
    - MUST include the `encrypted_recipient_data` provided by the recipient
    - For the first node in the blinded route:
      - MUST include the `blinding_point` provided by the recipient in `current_blinding_point`
    - If it is the final node:
      - MUST include `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
      - The value set for `outgoing_cltv_value`: 
        - MUST use the current block height as a baseline value. 
        - if a [random offset](07-routing-gossip.md#recommendations-for-routing) was added to improve privacy:
          - SHOULD add the offset to the baseline value.
    - MUST NOT include any other tlv field.
  - For every node outside of a blinded route:
    - MUST include `amt_to_forward` and `outgoing_cltv_value`.
    - If every node in the route advertises `option_attributable_error`:
      - SHOULD include `attributable_error` for every node
    otherwise:
      - MUST NOT include `attributable_error`
    - For every non-final node:
      - MUST include `short_channel_id`
      - MUST NOT include `payment_data`
    - For the final node:
      - MUST NOT include `short_channel_id`
      - if the recipient provided `payment_secret`:
        - MUST include `payment_data`
        - MUST set `payment_secret` to the one provided
        - MUST set `total_msat` to the total amount it will send
      - if the recipient provided `payment_metadata`:
        - MUST include `payment_metadata` with every HTLC
        - MUST not apply any limits to the size of `payment_metadata` except the limits implied by the fixed onion size

The reader:

  - If `encrypted_recipient_data` is present:
    - If `blinding_point` is set in the incoming `update_add_htlc`:
      - MUST return an error if `current_blinding_point` is present.
      - MUST use that `blinding_point` as the blinding point for decryption.
    - Otherwise:
      - MUST return an error if `current_blinding_point` is not present.
      - MUST use that `current_blinding_point` as the blinding point for decryption.
      - SHOULD add a random delay before returning errors.
    - MUST return an error if `encrypted_recipient_data` does not decrypt using the
      blinding point as described in [Route Blinding](#route-blinding).
    - If `payment_constraints` is present:
      - MUST return an error if:
        - the expiry is greater than `encrypted_recipient_data.payment_constraints.max_cltv_expiry`.
        - the amount is below `encrypted_recipient_data.payment_constraints.htlc_minimum_msat`.
    - If `allowed_features` is missing:
      - MUST process the message as if it were present and contained an empty array.
    - MUST return an error if:
      - `encrypted_recipient_data.allowed_features.features` contains an unknown feature bit (even if it is odd).
      - the payment uses a feature not included in `encrypted_recipient_data.allowed_features.features`.
    - If it is not the final node:
      - MUST return an error if the payload contains other tlv fields than `encrypted_recipient_data` and `current_blinding_point`.
      - MUST return an error if `encrypted_recipient_data` does not contain either `short_channel_id` or `next_node_id`.
      - MUST return an error if `encrypted_recipient_data` does not contain `payment_relay`.
      - MUST use values from `encrypted_recipient_data.payment_relay` to calculate `amt_to_forward` and `outgoing_cltv_value` as follows:
        - `amt_to_forward = ((amount_msat - fee_base_msat) * 1000000 + 1000000 + fee_proportional_millionths - 1) / (1000000 + fee_proportional_millionths)`
        - `outgoing_cltv_value = cltv_expiry - payment_relay.cltv_expiry_delta`
    - If it is the final node:
      - MUST return an error if the payload contains other tlv fields than `encrypted_recipient_data`, `current_blinding_point`, `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
      - MUST return an error if `amt_to_forward`, `outgoing_cltv_value` or `total_amount_msat` are not present.
      - MUST return an error if `amt_to_forward` is below what it expects for the payment.
      - MUST return an error if incoming `cltv_expiry` < `outgoing_cltv_value`.
      - MUST return an error if incoming `cltv_expiry` < `current_block_height` + `min_final_cltv_expiry_delta`.
  - Otherwise (it is not part of a blinded route):
    - MUST return an error if `blinding_point` is set in the incoming `update_add_htlc` or `current_blinding_point` is present.
    - MUST return an error if `amt_to_forward` or `outgoing_cltv_value` are not present.
    - MUST return an attributable error if `attributable_error` is present.
    - if it is not the final node:
      - MUST return an error if:
        - `short_channel_id` is not present,
        - it cannot forward the HTLC to the peer indicated by the channel `short_channel_id`.
        - incoming `amount_msat` - `fee` < `amt_to_forward` (where `fee` is the advertised fee as described in [BOLT #7](07-routing-gossip.md#htlc-fees))
        - `cltv_expiry` - `cltv_expiry_delta` < `outgoing_cltv_value`
  - If it is the final node:
    - MUST treat `total_msat` as if it were equal to `amt_to_forward` if it is not present.
    - MUST return an error if:
      - incoming `amount_msat` < `amt_to_forward`.
      - incoming `cltv_expiry` < `outgoing_cltv_value`.
      - incoming `cltv_expiry` < `current_block_height` + `min_final_cltv_expiry_delta`.

Additional requirements are specified [here](#basic-multi-part-payments) for
multi-part payments, and [here](#route-blinding) for blinded payments.

### Basic Multi-Part Payments

An HTLC may be part of a larger "multi-part" payment: such
"base" atomic multipath payments will use the same `payment_hash` for
all paths.

Note that `amt_to_forward` is the amount for this HTLC only: a
`total_msat` field containing a greater value is a promise by the
ultimate sender that the rest of the payment will follow in succeeding
HTLCs; we call these outstanding HTLCs which have the same preimage,
an "HTLC set".

Note that there are two distinct tlv fields that can be used to transmit
`total_msat`. The last one, `total_amount_msat`, was introduced with
blinded paths for which the `payment_secret` doesn't make sense.

`payment_metadata` is to be included in every payment part, so that
invalid payment details can be detected as early as possible.

#### Requirements

The writer:
  - if the invoice offers the `basic_mpp` feature:
    - MAY send more than one HTLC to pay the invoice.
    - MUST use the same `payment_hash` on all HTLCs in the set.
    - SHOULD send all payments at approximately the same time.
    - SHOULD try to use diverse paths to the recipient for each HTLC.
    - SHOULD retry and/or re-divide HTLCs which fail.
    - if the invoice specifies an `amount`:
       - MUST set `total_msat` to at least that `amount`, and less
         than or equal to twice `amount`.
    - otherwise:
      - MUST set `total_msat` to the amount it wishes to pay.
    - MUST ensure that the total `amt_to_forward` of the HTLC set which arrives
      at the payee is equal to or greater than `total_msat`.
    - MUST NOT send another HTLC if the total `amt_to_forward` of the HTLC set
      is already greater or equal to `total_msat`.
    - MUST include `payment_secret`.
  - otherwise:
    - MUST set `total_msat` equal to `amt_to_forward`.

The final node:
  - MUST fail the HTLC if dictated by Requirements under [Failure Messages](#failure-messages)
    - Note: "amount paid" specified there is the `total_msat` field.
  - if it does not support `basic_mpp`:
    - MUST fail the HTLC if `total_msat` is not exactly equal to `amt_to_forward`.
  - otherwise, if it supports `basic_mpp`:
    - MUST add it to the HTLC set corresponding to that `payment_hash`.
    - SHOULD fail the entire HTLC set if `total_msat` is not the same for
      all HTLCs in the set.
    - if the total `amt_to_forward` of this HTLC set is equal to or greater
      than `total_msat`:
      - SHOULD fulfill all HTLCs in the HTLC set
    - otherwise, if the total `amt_to_forward` of this HTLC set is less than
      `total_msat`:
      - MUST NOT fulfill any HTLCs in the HTLC set
      - MUST fail all HTLCs in the HTLC set after some reasonable timeout.
        - SHOULD wait for at least 60 seconds after the initial HTLC.
        - SHOULD use `mpp_timeout` for the failure message.
      - MUST require `payment_secret` for all HTLCs in the set.
    - if it fulfills any HTLCs in the HTLC set:
       - MUST fulfill the entire HTLC set.

#### Rationale

If `basic_mpp` is present it causes a delay to allow other partial
payments to combine.  The total amount must be sufficient for the
desired payment, just as it must be for single payments.  But this must
be reasonably bounded to avoid a denial-of-service.

Because invoices do not necessarily specify an amount, and because
payers can add noise to the final amount, the total amount must be
sent explicitly.  The requirements allow exceeding this slightly, as
it simplifies adding noise to the amount when splitting, as well as
scenarios in which the senders are genuinely independent (friends
splitting a bill, for example).

Because a node may need to pay more than its desired amount (due to the
`htlc_minimum_msat` value of channels in the desired path), nodes are allowed
to pay more than the `total_msat` they specified. Otherwise, nodes would be
constrained in which paths they can take when retrying payments along specific
paths. However, no individual HTLC may be for less than the difference between
the total paid and `total_msat`.

The restriction on sending an HTLC once the set is over the agreed total prevents the preimage being released before all
the partial payments have arrived: that would allow any intermediate
node to immediately claim any outstanding partial payments.

An implementation may choose not to fulfill an HTLC set which
otherwise meets the amount criterion (eg. some other failure, or
invoice timeout), however if it were to fulfill only some of them,
intermediary nodes could simply claim the remaining ones.

### Route Blinding

Nodes receiving onion packets may hide their identity from senders by
"blinding" an arbitrary amount of hops at the end of an onion path.

When using route blinding, nodes find a route to themselves from a given
"introduction node" and initial "blinding point". They then use ECDH with
each node in that route to create a "blinded" node ID and an encrypted blob
(`encrypted_data`) for each one of the blinded nodes.

They communicate this blinded route and the encrypted blobs to the sender.
The sender finds a route to the introduction node and extends it with the
blinded route provided by the recipient. The sender includes the encrypted
blobs in the corresponding onion payloads: they allow nodes in the blinded
part of the route to "unblind" the next node and correctly forward the packet.

Note that there are two ways for the sender to reach the introduction
point: one is to create a normal (unblinded) payment, and place the
initial blinding point in `current_blinding_point` along with the
`encrypted_data` in the onion payload for the introduction point to
start the blinded path. The second way is to create a blinded path to
the introduction point, set `next_blinding_override` inside the
`encrypted_data_tlv` on the hop prior to the introduction point to the
initial blinding point, and have it sent to the introduction node.

The `encrypted_data` is a TLV stream, encrypted for a given blinded node, that
may contain the following TLV fields:

1. `tlv_stream`: `encrypted_data_tlv`
2. types:
    1. type: 1 (`padding`)
    2. data:
        * [`...*byte`:`padding`]
    1. type: 2 (`short_channel_id`)
    2. data:
        * [`short_channel_id`:`short_channel_id`]
    1. type: 4 (`next_node_id`)
    2. data:
        * [`point`:`node_id`]
    1. type: 6 (`path_id`)
    2. data:
        * [`...*byte`:`data`]
    1. type: 8 (`next_blinding_override`)
    2. data:
        * [`point`:`blinding`]
    1. type: 10 (`payment_relay`)
    2. data:
        * [`u16`:`cltv_expiry_delta`]
        * [`u32`:`fee_proportional_millionths`]
        * [`tu32`:`fee_base_msat`]
    1. type: 12 (`payment_constraints`)
    2. data:
        * [`u32`:`max_cltv_expiry`]
        * [`tu64`:`htlc_minimum_msat`]
    1. type: 14 (`allowed_features`)
    2. data:
        * [`...*byte`:`features`]

#### Requirements

A recipient N(r) creating a blinded route `N(0) -> N(1) -> ... -> N(r)` to itself:

- MUST create a blinded node ID `B(i)` for each node using the following algorithm:
  - `e(0) <- {0;1}^256`
  - `E(0) = e(0) * G`
  - For every node in the route:
    - let `N(i) = k(i) * G` be the `node_id` (`k(i)` is `N(i)`'s private key)
    - `ss(i) = SHA256(e(i) * N(i)) = SHA256(k(i) * E(i))` (ECDH shared secret known only by `N(r)` and `N(i)`)
    - `B(i) = HMAC256("blinded_node_id", ss(i)) * N(i)` (blinded `node_id` for `N(i)`, private key known only by `N(i)`)
    - `rho(i) = HMAC256("rho", ss(i))` (key used to encrypt the payload for `N(i)` by `N(r)`)
    - `e(i+1) = SHA256(E(i) || ss(i)) * e(i)` (blinding ephemeral private key, only known by `N(r)`)
    - `E(i+1) = SHA256(E(i) || ss(i)) * E(i)` (NB: `N(i)` MUST NOT learn `e(i)`)
- MAY replace `E(i+1)` with a different value, but if it does:
  - MUST set `encrypted_data_tlv(i).next_blinding_override` to `E(i+1)`
- MAY store private data in `encrypted_data_tlv(r).path_id` to verify that the route is used in the right context and was created by them
- SHOULD add padding data to ensure all `encrypted_data_tlv(i)` have the same length
- MUST encrypt each `encrypted_data_tlv(i)` with ChaCha20-Poly1305 using the corresponding `rho(i)` key and an all-zero nonce to produce `encrypted_recipient_data(i)`
- MUST communicate the blinded node IDs `B(i)` and `encrypted_recipient_data(i)` to the sender
- MUST communicate the real node ID of the introduction point `N(0)` to the sender
- MUST communicate the first blinding ephemeral key `E(0)` to the sender

A reader:

- If it receives `blinding_point` (`E(i)`) from the prior peer:
  - MUST use `b(i)` instead of its private key `k(i)` to decrypt the onion.
    Note that the node may instead tweak the onion ephemeral key with
    `HMAC256("blinded_node_id", ss(i))` which achieves the same result.
- Otherwise:
  - MUST use `k(i)` to decrypt the onion, to extract `current_blinding_point` (`E(i)`).
- MUST compute:
  - `ss(i) = SHA256(k(i) * E(i))` (standard ECDH)
  - `b(i) = HMAC256("blinded_node_id", ss(i)) * k(i)`
  - `rho(i) = HMAC256("rho", ss(i))`
  - `E(i+1) = SHA256(E(i) || ss(i)) * E(i)`
- MUST decrypt the `encrypted_data` field using `rho(i)` and use the
  decrypted fields to locate the next node
- If the `encrypted_data` field is missing or cannot be decrypted:
  - MUST return an error
- If `encrypted_data` contains a `next_blinding_override`:
  - MUST use it as the next blinding point instead of `E(i+1)`
- Otherwise:
  - MUST use `E(i+1)` as the next blinding point
- MUST forward the onion and include the next blinding point in the lightning
  message for the next node

The final recipient:

- MUST compute:
  - `ss(r) = SHA256(k(r) * E(r))` (standard ECDH)
  - `b(r) = HMAC256("blinded_node_id", ss(r)) * k(r)`
  - `rho(r) = HMAC256("rho", ss(r))`
- MUST decrypt the `encrypted_data` field using `rho(r)`
- If the `encrypted_data` field is missing or cannot be decrypted:
  - MUST return an error
- MUST ignore the message if the `path_id` does not match the blinded route it
  created

#### Rationale

Route blinding is a lightweight technique to provide recipient anonymity.
It's more flexible than rendezvous routing because it simply replaces the public
keys of the nodes in the route with random public keys while letting senders
choose what data they put in the onion for each hop. Blinded routes are also
reusable in some cases (e.g. onion messages).

Each node in the blinded route needs to receive `E(i)` to be able to decrypt
the onion and the `encrypted_data` payload. Protocols that use route blinding
must specify how this value is propagated between nodes.

When concatenating two blinded routes generated by different nodes, the
last node of the first route needs to know the first `blinding_point` of the
second route: the `next_blinding_override` field must be used to transmit this
information.

The final recipient must verify that the blinded route is used in the right
context (e.g. for a specific payment) and was created by them. Otherwise a
malicious sender could create different blinded routes to all the nodes that
they suspect could be the real recipient and try them until one accepts the
message. The recipient can protect against that by storing `E(r)` and the
context (e.g. a `payment_hash`), and verifying that they match when receiving
the onion. Otherwise, to avoid additional storage cost, it can put some private
context information in the `path_id` field (e.g. the `payment_preimage`) and
verify that when receiving the onion. Note that it's important to use private
information in that case, that senders cannot have access to.

Whenever the introduction point receives a failure from the blinded route, it
should add a random delay before forwarding the error. Failures are likely to
be probing attempts and message timing may help the attacker infer its distance
to the final recipient.

The `padding` field can be used to ensure that all `encrypted_data` have the
same length. It's particularly useful when adding dummy hops at the end of a
blinded route, to prevent the sender from figuring out which node is the final
recipient.

When route blinding is used for payments, the recipient specifies the fees and
expiry that blinded nodes should apply to the payment instead of letting the
sender configure them. The recipient also adds additional constraints to the
payments that can go through that route to protect against probing attacks that
would let malicious nodes unblind the identity of the blinded nodes. It should
set `payment_constraints.max_cltv_expiry` to restrict the lifetime of a blinded
route and reduce the risk that an intermediate node updates its fees and rejects
payments (which could be used to unblind nodes inside the route).

# Accepting and Forwarding a Payment

Once a node has decoded the payload it either accepts the payment locally, or forwards it to the peer indicated as the next hop in the payload.

## Non-strict Forwarding

A node MAY forward an HTLC along an outgoing channel other than the one
specified by `short_channel_id`, so long as the receiver has the same node
public key intended by `short_channel_id`. Thus, if `short_channel_id` connects
nodes A and B, the HTLC can be forwarded across any channel connecting A and B.
Failure to adhere will result in the receiver being unable to decrypt the next
hop in the onion packet.

### Rationale

In the event that two peers have multiple channels, the downstream node will be
able to decrypt the next hop payload regardless of which channel the packet is
sent across.

Nodes implementing non-strict forwarding are able to make real-time assessments
of channel bandwidths with a particular peer, and use the channel that is
locally-optimal. 

For example, if the channel specified by `short_channel_id` connecting A and B
does not have enough bandwidth at forwarding time, then A is able use a
different channel that does. This can reduce payment latency by preventing the
HTLC from failing due to bandwidth constraints across `short_channel_id`, only
to have the sender attempt the same route differing only in the channel between
A and B.

Non-strict forwarding allows nodes to make use of private channels connecting
them to the receiving node, even if the channel is not known in the public
channel graph.

### Recommendation

Implementations using non-strict forwarding should consider applying the same
fee schedule to all channels with the same peer, as senders are likely to select
the channel which results in the lowest overall cost. Having distinct policies
may result in the forwarding node accepting fees based on the most optimal fee
schedule for the sender, even though they are providing aggregate bandwidth
across all channels with the same peer.

Alternatively, implementations may choose to apply non-strict forwarding only to
like-policy channels to ensure their expected fee revenue does not deviate by
using an alternate channel.

## Payload for the Last Node

When building the route, the origin node MUST use a payload for
the final node with the following values:

* `payment_secret`: set to the payment secret specified by the recipient (e.g.
  `payment_secret` from a [BOLT #11](11-payment-encoding.md) payment invoice)
* `outgoing_cltv_value`: set to the final expiry specified by the recipient (e.g.
  `min_final_cltv_expiry_delta` from a [BOLT #11](11-payment-encoding.md) payment invoice)
* `amt_to_forward`: set to the final amount specified by the recipient (e.g. `amount`
  from a [BOLT #11](11-payment-encoding.md) payment invoice)

This allows the final node to check these values and return errors if needed,
but it also eliminates the possibility of probing attacks by the second-to-last
node. Such attacks could, otherwise, attempt to discover if the receiving peer is the
last one by re-sending HTLCs with different amounts/expiries.
The final node will extract its onion payload from the HTLC it has received and
compare its values against those of the HTLC. See the
[Returning Errors](#returning-errors) section below for more details.

If not for the above, since it need not forward payments, the final node could
simply discard its payload.

# Shared Secret

The origin node establishes a shared secret with each hop along the route using
Elliptic-curve Diffie-Hellman between the sender's ephemeral key at that hop and
the hop's node ID key. The resulting curve point is serialized to the
compressed format and hashed using `SHA256`. The hash output is used
as the 32-byte shared secret.

Elliptic-curve Diffie-Hellman (ECDH) is an operation on an EC private key and
an EC public key that outputs a curve point. For this protocol, the ECDH
variant implemented in `libsecp256k1` is used, which is defined over the
`secp256k1` elliptic curve. During packet construction, the sender uses the
ephemeral private key and the hop's public key as inputs to ECDH, whereas
during packet forwarding, the hop uses the ephemeral public key and its own
node ID private key. Because of the properties of ECDH, they will both derive
the same value.

# Blinding Ephemeral Keys

In order to ensure multiple hops along the route cannot be linked by the
ephemeral public keys they see, the key is blinded at each hop. The blinding is
done in a deterministic way that allows the sender to compute the
corresponding blinded private keys during packet construction.

The blinding of an EC public key is a single scalar multiplication of
the EC point representing the public key with a 32-byte blinding factor. Due to
the commutative property of scalar multiplication, the blinded private key is
the multiplicative product of the input's corresponding private key with the
same blinding factor.

The blinding factor itself is computed as a function of the ephemeral public key
and the 32-byte shared secret. Concretely, it is the `SHA256` hash value of the
concatenation of the public key serialized in its compressed format and the
shared secret.

# Packet Construction

In the following example, it's assumed that a _sending node_ (origin node),
`n_0`, wants to route a packet to a _receiving node_ (final node), `n_r`.
First, the sender computes a route `{n_0, n_1, ..., n_{r-1}, n_r}`, where `n_0`
is the sender itself and `n_r` is the final recipient. All nodes `n_i` and
`n_{i+1}` MUST be peers in the overlay network route. The sender then gathers the
public keys for `n_1` to `n_r` and generates a random 32-byte `sessionkey`.
Optionally, the sender may pass in _associated data_, i.e. data that the
packet commits to but that is not included in the packet itself. Associated
data will be included in the HMACs and must match the associated data provided
during integrity verification at each hop.

To construct the onion, the sender initializes the ephemeral private key for the
first hop `ek_1` to the `sessionkey` and derives from it the corresponding
ephemeral public key `epk_1` by multiplying with the `secp256k1` base point. For
each of the `k` hops along the route, the sender then iteratively computes the
shared secret `ss_k` and ephemeral key for the next hop `ek_{k+1}` as follows:

 - The sender executes ECDH with the hop's public key and the ephemeral private
 key to obtain a curve point, which is hashed using `SHA256` to produce the
 shared secret `ss_k`.
 - The blinding factor is the `SHA256` hash of the concatenation between the
 ephemeral public key `epk_k` and the shared secret `ss_k`.
 - The ephemeral private key for the next hop `ek_{k+1}` is computed by
 multiplying the current ephemeral private key `ek_k` by the blinding factor.
 - The ephemeral public key for the next hop `epk_{k+1}` is derived from the
 ephemeral private key `ek_{k+1}` by multiplying with the base point.

Once the sender has all the required information above, it can construct the
packet. Constructing a packet routed over `r` hops requires `r` 32-byte
ephemeral public keys, `r` 32-byte shared secrets, `r` 32-byte blinding factors,
and `r` variable length `hop_payload` payloads.
The construction returns a single 1366-byte packet along with the first receiving peer's address.

The packet construction is performed in the reverse order of the route, i.e.
the last hop's operations are applied first.

The packet is initialized with 1300 _random_ bytes derived from a CSPRNG
(ChaCha20). The _pad_ key referenced above is used to extract additional random
bytes from a ChaCha20 stream, using it as a CSPRNG for this purpose.  Once the
`paddingKey` has been obtained, ChaCha20 is used with an all zero nonce, to
generate 1300 random bytes. Those random bytes are then used as the starting
state of the mix-header to be created.

A filler is generated (see [Filler Generation](#filler-generation)) using the
shared secret.

For each hop in the route, in reverse order, the sender applies the
following operations:

 - The _rho_-key and _mu_-key are generated using the hop's shared secret.
 - `shift_size` is defined as the length of the `hop_payload` plus the bigsize encoding of the length and the length of that HMAC. Thus if the payload length is `l` then the `shift_size` is `1 + l + 32` for `l < 253`, otherwise `3 + l + 32` due to the bigsize encoding of `l`.
 - The `hop_payload` field is right-shifted by `shift_size` bytes, discarding the last `shift_size`
 bytes that exceed its 1300-byte size.
 - The bigsize-serialized length, serialized `hop_payload` and `hmac` are copied into the following `shift_size` bytes.
 - The _rho_-key is used to generate 1300 bytes of pseudo-random byte stream
 which is then applied, with `XOR`, to the `hop_payloads` field.
 - If this is the last hop, i.e. the first iteration, then the tail of the
 `hop_payloads` field is overwritten with the routing information `filler`.
 - The next HMAC is computed (with the _mu_-key as HMAC-key) over the
 concatenated `hop_payloads` and associated data.

The resulting final HMAC value is the HMAC that will be used by the first
receiving peer in the route.

The packet generation returns a serialized packet that contains the `version`
byte, the ephemeral pubkey for the first hop, the HMAC for the first hop, and
the obfuscated `hop_payloads`.

The following Go code is an example implementation of the packet construction:

```Go
func NewOnionPacket(paymentPath []*btcec.PublicKey, sessionKey *btcec.PrivateKey,
	hopsData []HopData, assocData []byte) (*OnionPacket, error) {

	numHops := len(paymentPath)
	hopSharedSecrets := make([][sha256.Size]byte, numHops)

	// Initialize ephemeral key for the first hop to the session key.
	var ephemeralKey big.Int
	ephemeralKey.Set(sessionKey.D)

	for i := 0; i < numHops; i++ {
		// Perform ECDH and hash the result.
		ecdhResult := scalarMult(paymentPath[i], ephemeralKey)
		hopSharedSecrets[i] = sha256.Sum256(ecdhResult.SerializeCompressed())

		// Derive ephemeral public key from private key.
		ephemeralPrivKey := btcec.PrivKeyFromBytes(btcec.S256(), ephemeralKey.Bytes())
		ephemeralPubKey := ephemeralPrivKey.PubKey()

		// Compute blinding factor.
		sha := sha256.New()
		sha.Write(ephemeralPubKey.SerializeCompressed())
		sha.Write(hopSharedSecrets[i])

		var blindingFactor big.Int
		blindingFactor.SetBytes(sha.Sum(nil))

		// Blind ephemeral key for next hop.
		ephemeralKey.Mul(&ephemeralKey, &blindingFactor)
		ephemeralKey.Mod(&ephemeralKey, btcec.S256().Params().N)
	}

	// Generate the padding, called "filler strings" in the paper.
	filler := generateHeaderPadding("rho", numHops, hopDataSize, hopSharedSecrets)

	// Allocate and initialize fields to zero-filled slices
	var mixHeader [routingInfoSize]byte
	var nextHmac [hmacSize]byte
        
        // Our starting packet needs to be filled out with random bytes, we
        // generate some deterministically using the session private key.
        paddingKey := generateKey("pad", sessionKey.Serialize()
        paddingBytes := generateCipherStream(paddingKey, routingInfoSize)
        copy(mixHeader[:], paddingBytes)

	// Compute the routing information for each hop along with a
	// MAC of the routing information using the shared key for that hop.
	for i := numHops - 1; i >= 0; i-- {
		rhoKey := generateKey("rho", hopSharedSecrets[i])
		muKey := generateKey("mu", hopSharedSecrets[i])

		hopsData[i].HMAC = nextHmac

		// Shift and obfuscate routing information
		streamBytes := generateCipherStream(rhoKey, numStreamBytes)

		rightShift(mixHeader[:], hopDataSize)
		buf := &bytes.Buffer{}
		hopsData[i].Encode(buf)
		copy(mixHeader[:], buf.Bytes())
		xor(mixHeader[:], mixHeader[:], streamBytes[:routingInfoSize])

		// These need to be overwritten, so every node generates a correct padding
		if i == numHops-1 {
			copy(mixHeader[len(mixHeader)-len(filler):], filler)
		}

		packet := append(mixHeader[:], assocData...)
		nextHmac = calcMac(muKey, packet)
	}

	packet := &OnionPacket{
		Version:      0x00,
		EphemeralKey: sessionKey.PubKey(),
		RoutingInfo:  mixHeader,
		HeaderMAC:    nextHmac,
	}
	return packet, nil
}
```

# Packet Forwarding

This specification is limited to `version` `0` packets; the structure
of future versions may change.

Upon receiving a packet, a processing node compares the version byte of the
packet with its own supported versions and aborts the connection if the packet
specifies a version number that it doesn't support.
For packets with supported version numbers, the processing node first parses the
packet into its individual fields.

Next, the processing node computes the shared secret using the private key
corresponding to its own public key and the ephemeral key from the packet, as
described in [Shared Secret](#shared-secret).

The above requirements prevent any hop along the route from retrying a payment
multiple times, in an attempt to track a payment's progress via traffic
analysis. Note that disabling such probing could be accomplished using a log of
previous shared secrets or HMACs, which could be forgotten once the HTLC would
not be accepted anyway (i.e. after `outgoing_cltv_value` has passed). Such a log
may use a probabilistic data structure, but it MUST rate-limit commitments as
necessary, in order to constrain the worst-case storage requirements or false
positives of this log.

Next, the processing node uses the shared secret to compute a _mu_-key, which it
in turn uses to compute the HMAC of the `hop_payloads`. The resulting HMAC is then
compared against the packet's HMAC.

Comparison of the computed HMAC and the packet's HMAC MUST be
time-constant to avoid information leaks.

At this point, the processing node can generate a _rho_-key.

The routing information is then deobfuscated, and the information about the
next hop is extracted.
To do so, the processing node copies the `hop_payloads` field, appends 1300 `0x00`-bytes,
generates `2*1300` pseudo-random bytes (using the _rho_-key), and applies the result, using `XOR`, to the copy of the `hop_payloads`.
The first few bytes correspond to the bigsize-encoded length `l` of the `hop_payload`, followed by `l` bytes of the resulting routing information become the `hop_payload`, and the 32 byte HMAC.
The next 1300 bytes are the `hop_payloads` for the outgoing packet.

A special `hmac` value of 32 `0x00`-bytes indicates that the currently processing hop is the intended recipient and that the packet should not be forwarded.

If the HMAC does not indicate route termination, and if the next hop is a peer of the
processing node; then the new packet is assembled. Packet assembly is accomplished
by blinding the ephemeral key with the processing node's public key, along with the
shared secret, and by serializing the `hop_payloads`.
The resulting packet is then forwarded to the addressed peer.

## Requirements

The processing node:
  - if the ephemeral public key is NOT on the `secp256k1` curve:
    - MUST abort processing the packet.
    - MUST report a route failure to the origin node.
  - if the packet has previously been forwarded or locally redeemed, i.e. the
  packet contains duplicate routing information to a previously received packet:
    - if preimage is known:
      - MAY immediately redeem the HTLC using the preimage.
    - otherwise:
      - MUST abort processing and report a route failure.
  - if the computed HMAC and the packet's HMAC differ:
    - MUST abort processing.
    - MUST report a route failure.
  - if the `realm` is unknown:
    - MUST drop the packet.
    - MUST signal a route failure.
  - MUST address the packet to another peer that is its direct neighbor.
  - if the processing node does not have a peer with the matching address:
    - MUST drop the packet.
    - MUST signal a route failure.


# Filler Generation

Upon receiving a packet, the processing node extracts the information destined
for it from the route information and the per-hop payload.
The extraction is done by deobfuscating and left-shifting the field.
This would make the field shorter at each hop, allowing an attacker to deduce the
route length. For this reason, the field is pre-padded before forwarding.
Since the padding is part of the HMAC, the origin node will have to pre-generate an
identical padding (to that which each hop will generate) in order to compute the
HMACs correctly for each hop.
The filler is also used to pad the field-length, in the case that the selected
route is shorter than 1300 bytes.

Before deobfuscating the `hop_payloads`, the processing node pads it with 1300
`0x00`-bytes, such that the total length is `2*1300`.
It then generates the pseudo-random byte stream, of matching length, and applies
it with `XOR` to the `hop_payloads`.
This deobfuscates the information destined for it, while simultaneously
obfuscating the added `0x00`-bytes at the end.

In order to compute the correct HMAC, the origin node has to pre-generate the
`hop_payloads` for each hop, including the incrementally obfuscated padding added
by each hop. This incrementally obfuscated padding is referred to as the
`filler`.

The following example code shows how the filler is generated in Go:

```Go
func generateFiller(key string, numHops int, hopSize int, sharedSecrets [][sharedSecretSize]byte) []byte {
	fillerSize := uint((numMaxHops + 1) * hopSize)
	filler := make([]byte, fillerSize)

	// The last hop does not obfuscate, it's not forwarding anymore.
	for i := 0; i < numHops-1; i++ {

		// Left-shift the field
		copy(filler[:], filler[hopSize:])

		// Zero-fill the last hop
		copy(filler[len(filler)-hopSize:], bytes.Repeat([]byte{0x00}, hopSize))

		// Generate pseudo-random byte stream
		streamKey := generateKey(key, sharedSecrets[i])
		streamBytes := generateCipherStream(streamKey, fillerSize)

		// Obfuscate
		xor(filler, filler, streamBytes)
	}

	// Cut filler down to the correct length (numHops+1)*hopSize
	// bytes will be prepended by the packet generation.
	return filler[(numMaxHops-numHops+2)*hopSize:]
}
```

Note that this example implementation is for demonstration purposes only; the
`filler` can be generated much more efficiently.
The last hop need not obfuscate the `filler`, since it won't forward the packet
any further and thus need not extract an HMAC either.

# Returning Errors

The onion routing protocol includes a mechanism for returning encrypted
error messages to the origin node.
The returned error messages may be failures reported by any hop, including the
final node.
The format of the forward packet is not usable for the return path, since no hop
besides the origin has access to the information required for its generation.
Note that these error messages are not reliable, as they are not placed on-chain
due to the possibility of hop failure.

Intermediate hops store the shared secret from the forward path and reuse it to
authenticate and obfuscate any corresponding return packet during each hop.
In addition, each node locally stores data regarding its own sending peer in the
route, so it knows where to return-forward any eventual return packets.

The origin node signals to each node on the path that it supports attributable
errors by setting the `attributable_error` tlv record in the forward packet. It
must make sure that each node supports this format by observing the node feature
`option_attributable_error`.

## Erring node

The node generating the error message builds a return packet
consisting of the following fields:

1. data:
   * [`u16`:`failure_len`]
   * [`failure_len*byte`:`failuremsg`]
   * [`u16`:`pad_len`]
   * [`pad_len*byte`:`pad`]
   * [`20*5*byte`:`payloads`]
   * [`210*4*byte`:`hmacs`]



Where `failuremsg` is defined below, and `pad` are the extra bytes used to
conceal length.

The field `payloads` contains a per-hop payload. The erring node puts its
payload at the start of this array and zeroes out the rest. The size of the
field is based on the maximum supported number of hops in a route (20) and the
payload size (5 bytes).

The per-hop payload consists of the following fields:
   * [`byte`:`payload_source`]
   * [`uint32`:`hold_time_ms`]

`payload_source` indicates whether this hop is an intermediate hop (value
0) or the source of the error (value 1). The erring node sets this to 1. Via
`hold_time_ms` each hops reports the time that it held on to the htlc. The
sender can use this information to identify slow nodes and avoid them for future
payment attempts.

The field `hmacs` contains truncated authentication codes for each hop, with a
`um` type key generated using the above process. Regular 32 byte hmacs are
truncated to the first 4 bytes to save space.

In theory this truncation makes it possible for malicious nodes to guess the
right hmac. However, game theory is against them because a wrong guess will get
them penalized.

The size of the field is based on the maximum number of hops in a route (20) and
the truncated hmac size (4 bytes). Each hop adds 20 hmacs, one for each possible
position that the hop could be at in the path. This is necessary because only
the sender knows the position of each hop in the path.

At each step backwards, one hmac for every hop can be pruned. Rather than
holding on to 20 * 20 = 400 hmacs, pruning reduces the total space requirement
to 210 hmacs. More on pruning below.

The layout of the `hmacs` field shown below. The actual format is much longer,
but for readability the format is described as if the maximum route length would
be just three hops.

`hmac_0_2` | `hmac_0_1`| `hmac_0_0`| `hmac_1_1`| `hmac_1_0`| `hmac_2_0`

`hmac_x_y` is the hmac added by node `x` (counted from the node that is
currently handling the failure message) assuming that this node is `y` hops
away from the erring node. Each hmac covers the following data:

* `failure_len`, `failuremsg`, `pad_len` and `pad`.

* The first `y+1` payloads in `payloads`. For example, `hmac_0_2` would cover
  all three payloads.

* `y` downstream hmacs that correspond to downstream node positions relative to
  `x`. For example, `hmac_0_2` would cover `hmac_1_1` and `hmac_2_0`.

The erring node stores its 20 hmacs at the start of the array and zeroes
out the rest. Strictly speaking the erring node would only need to add the
single `hmac_0_0` here, because there is no downstream data to cover. However,
for verification efficiency at the origin node, we still require all hmacs to be
calculated. The redundant hmacs will cover portions of the zero-initialized
data.

Finally a new key is generated, using the key type `ammag`. This key is then
used to generate a pseudo-random stream, which is in turn applied to the packet
using `XOR`.

Error handling for HTLCs with `blinding_point` is particularly fraught,
since differences in implementations (or versions) may be leveraged to
de-anonymize elements of the blinded path. Thus the decision turn every
error into `invalid_onion_blinding` which will be converted to a normal
onion error by the introduction point.

### Requirements

The _erring node_:
  - MUST set `pad` such that the `failure_len` plus `pad_len` is at least 256.
  - SHOULD set `pad` such that the `failure_len` plus `pad_len` is equal to
    256. Deviating from this may cause older nodes to be unable to parse the
    return message.

## Intermediate nodes

Every hop along the return path that receives a packet will in turn:

* Shift all existing payloads to the right and put its own payload at the
start. Intermediate nodes will use payload source 0.

* Shift and prune all existing hmacs.

  For the simplified three-hop layout above, the shift/prune operation would
apply a transformation that results in:

  `-` | `-` | `-` | `hmac_0'_1` | `hmac_0'_0` | `hmac_1'_0`

  The former `hmac_x'_y` now becomes `hmac_x+1_y`. The left-most hmac for
  each hop is discarded.

* Calculate its own 20 hmacs and put them at the start of `hmacs` in the
  newly created space.

* Generate its `ammag`, generate the pseudo-random byte stream, and apply the
result to obfuscate the return packet before return-forwarding it. This is
identical to the obfuscation step that the erring node carries out.

## Origin node

The origin node is able to detect that it's the intended final recipient of the
return message, because of course, it was the originator of the corresponding
forward packet.
When an origin node receives an error message matching a transfer it initiated
(i.e. it cannot return-forward the error any further) it generates the `ammag`
and `um` keys for each hop in the route.

It then iteratively decrypts the error message, using each hop's `ammag` key,
and verifies the HMAC that corresponds to the hop's position in the path, using
each hop's `um` key.

When the origin node encounters a payload that signals that it is a final
payload, the sender of the error message has been reached and the decryption
process can stop.

The association between the forward and return packets is handled outside of
this onion routing protocol, e.g. via association with an HTLC in a payment
channel.

### Requirements

The _origin node_:
  - once the return message has been decrypted:
    - SHOULD store a copy of the message.
    - SHOULD continue decrypting, until the loop has been repeated 20 times.
    - SHOULD use constant `ammag` and `um` keys to obfuscate the route length.

## Failure Messages

The failure message encapsulated in `failuremsg` has an identical format as
a normal message: a 2-byte type `failure_code` followed by data applicable
to that type. The message data is followed by an optional
[TLV stream](01-messaging.md#type-length-value-format).

Below is a list of the currently supported `failure_code`
values, followed by their use case requirements.

Notice that the `failure_code`s are not of the same type as other message types,
defined in other BOLTs, as they are not sent directly on the transport layer
but are instead wrapped inside return packets.
The numeric values for the `failure_code` may therefore reuse values, that are
also assigned to other message types, without any danger of causing collisions.

The top byte of `failure_code` can be read as a set of flags:
* 0x8000 (BADONION): unparsable onion encrypted by sending peer
* 0x4000 (PERM): permanent failure (otherwise transient)
* 0x2000 (NODE): node failure (otherwise channel)
* 0x1000 (UPDATE): new channel update enclosed

Please note that the `channel_update` field is mandatory in messages whose
`failure_code` includes the `UPDATE` flag. It is encoded *with* the message
type prefix, i.e. it should always start with `0x0102`. Note that historical
lightning implementations serialized this without the `0x0102` message type.

The following `failure_code`s are defined:

1. type: PERM|1 (`invalid_realm`)

The `realm` byte was not understood by the processing node.

1. type: NODE|2 (`temporary_node_failure`)

General temporary failure of the processing node.

1. type: PERM|NODE|2 (`permanent_node_failure`)

General permanent failure of the processing node.

1. type: PERM|NODE|3 (`required_node_feature_missing`)

The processing node has a required feature which was not in this onion.

1. type: BADONION|PERM|4 (`invalid_onion_version`)
2. data:
   * [`sha256`:`sha256_of_onion`]

The `version` byte was not understood by the processing node.

1. type: BADONION|PERM|5 (`invalid_onion_hmac`)
2. data:
   * [`sha256`:`sha256_of_onion`]

The HMAC of the onion was incorrect when it reached the processing node.

1. type: BADONION|PERM|6 (`invalid_onion_key`)
2. data:
   * [`sha256`:`sha256_of_onion`]

The ephemeral key was unparsable by the processing node.

1. type: UPDATE|7 (`temporary_channel_failure`)
2. data:
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The channel from the processing node was unable to handle this HTLC,
but may be able to handle it, or others, later.

1. type: PERM|8 (`permanent_channel_failure`)

The channel from the processing node is unable to handle any HTLCs.

1. type: PERM|9 (`required_channel_feature_missing`)

The channel from the processing node requires features not present in
the onion.

1. type: PERM|10 (`unknown_next_peer`)

The onion specified a `short_channel_id` which doesn't match any
leading from the processing node.

1. type: UPDATE|11 (`amount_below_minimum`)
2. data:
   * [`u64`:`htlc_msat`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The HTLC amount was below the `htlc_minimum_msat` of the channel from
the processing node.

1. type: UPDATE|12 (`fee_insufficient`)
2. data:
   * [`u64`:`htlc_msat`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The fee amount was below that required by the channel from the
processing node.

1. type: UPDATE|13 (`incorrect_cltv_expiry`)
2. data:
   * [`u32`:`cltv_expiry`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The `cltv_expiry` does not comply with the `cltv_expiry_delta` required by
the channel from the processing node: it does not satisfy the following
requirement:

        cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value

1. type: UPDATE|14 (`expiry_too_soon`)
2. data:
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The CLTV expiry is too close to the current block height for safe
handling by the processing node.

1. type: PERM|15 (`incorrect_or_unknown_payment_details`)
2. data:
   * [`u64`:`htlc_msat`]
   * [`u32`:`height`]

The `payment_hash` is unknown to the final node, the `payment_secret` doesn't
match the `payment_hash`, the amount for that `payment_hash` is too low,
the CLTV expiry of the htlc is too close to the current block height for safe
handling or `payment_metadata` isn't present while it should be.

The `htlc_msat` parameter is superfluous, but left in for backwards
compatibility. The value of `htlc_msat` is required to be at least the value
specified in the final hop onion payload. It therefore does not have any
substantial informative value to the sender (though may indicate the
penultimate node took a lower fee than expected). A penultimate hop sending an
amount or an expiry that is too low for the htlc is handled through
`final_incorrect_cltv_expiry` and `final_incorrect_htlc_amount`.

The `height` parameter is set by the final node to the best known block height
at the time of receiving the htlc. This can be used by the sender to distinguish
between sending a payment with the wrong final CLTV expiry and an intermediate
hop delaying the payment so that the receiver's invoice CLTV delta requirement
is no longer met.

Note: Originally PERM|16 (`incorrect_payment_amount`) and 17
(`final_expiry_too_soon`) were used to differentiate incorrect htlc parameters
from unknown payment hash. Sadly, sending this response allows for probing
attacks whereby a node which receives an HTLC for forwarding can check guesses
as to its final destination by sending payments with the same hash but much
lower values or expiry heights to potential destinations and check the response.
Care must be taken by implementations to differentiate the previously
non-permanent case for `final_expiry_too_soon` (17) from the other, permanent
failures now represented by `incorrect_or_unknown_payment_details` (PERM|15).

1. type: 18 (`final_incorrect_cltv_expiry`)
2. data:
   * [`u32`:`cltv_expiry`]

The CLTV expiry in the HTLC is less than the value in the onion.

1. type: 19 (`final_incorrect_htlc_amount`)
2. data:
   * [`u64`:`incoming_htlc_amt`]

The amount in the HTLC is less than the value in the onion.

1. type: UPDATE|20 (`channel_disabled`)
2. data:
   * [`u16`:`disabled_flags`]
   * [`u16`:`len`]
   * [`len*byte`:`channel_update`]

The channel from the processing node has been disabled.
No flags for `disabled_flags` are currently defined, thus it is currently
always two zero bytes.

1. type: 21 (`expiry_too_far`)

The CLTV expiry in the HTLC is too far in the future.

1. type: PERM|22 (`invalid_onion_payload`)
2. data:
   * [`bigsize`:`type`]
   * [`u16`:`offset`]

The decrypted onion per-hop payload was not understood by the processing node
or is incomplete. If the failure can be narrowed down to a specific tlv type in
the payload, the erring node may include that `type` and its byte `offset` in
the decrypted byte stream.

1. type: 23 (`mpp_timeout`)

The complete amount of the multi-part payment was not received within a
reasonable time.

1. type: BADONION|PERM|24 (`invalid_onion_blinding`)
2. data:
   * [`sha256`:`sha256_of_onion`]

An error occurred within the blinded path.

### Requirements

An _erring node_:
  - if `blinding_point` is set in the incoming `update_add_htlc`:
    - MUST return an `invalid_onion_blinding` error.
  - if `current_blinding_point` is set in the onion payload and it is not the
    final node:
    - MUST return an `invalid_onion_blinding` error.
  - otherwise:
    - MUST select one of the above error codes when creating an error message.
    - MUST include the appropriate data for that particular error type.
    - if there is more than one error:
      - SHOULD select the first error it encounters from the list above.

An _erring node_ MAY:
  - if the `realm` byte is unknown:
    - return an `invalid_realm` error.
  - if the per-hop payload in the onion is invalid (e.g. it is not a valid tlv stream)
  or is missing required information (e.g. the amount was not specified):
    - return an `invalid_onion_payload` error.
  - if an otherwise unspecified transient error occurs for the entire node:
    - return a `temporary_node_failure` error.
  - if an otherwise unspecified permanent error occurs for the entire node:
    - return a `permanent_node_failure` error.
  - if a node has requirements advertised in its `node_announcement` `features`,
  which were NOT included in the onion:
    - return a `required_node_feature_missing` error.

A _forwarding node_ MUST:
  - if `blinding_point` is set in the incoming `update_add_htlc`:
    - return an `invalid_onion_blinding` error.
  - if `current_blinding_point` is set in the onion payload and it is not the
    final node:
    - return an `invalid_onion_blinding` error.
  - otherwise:
    - select one of the above error codes when creating an error message.

A _forwarding node_ MAY, but a _final node_ MUST NOT:
  - if the onion `version` byte is unknown:
    - return an `invalid_onion_version` error.
  - if the onion HMAC is incorrect:
    - return an `invalid_onion_hmac` error.
  - if the ephemeral key in the onion is unparsable:
    - return an `invalid_onion_key` error.
  - if during forwarding to its receiving peer, an otherwise unspecified,
  transient error occurs in the outgoing channel (e.g. channel capacity reached,
  too many in-flight HTLCs, etc.):
    - return a `temporary_channel_failure` error.
  - if an otherwise unspecified, permanent error occurs during forwarding to its
  receiving peer (e.g. channel recently closed):
    - return a `permanent_channel_failure` error.
  - if the outgoing channel has requirements advertised in its
  `channel_announcement`'s `features`, which were NOT included in the onion:
    - return a `required_channel_feature_missing` error.
  - if the receiving peer specified by the onion is NOT known:
    - return an `unknown_next_peer` error.
  - if the HTLC amount is less than the currently specified minimum amount:
    - report the amount of the outgoing HTLC and the current channel setting for
    the outgoing channel.
    - return an `amount_below_minimum` error.
  - if the HTLC does NOT pay a sufficient fee:
    - report the amount of the incoming HTLC and the current channel setting for
    the outgoing channel.
    - return a `fee_insufficient` error.
 -  if the incoming `cltv_expiry` minus the `outgoing_cltv_value` is below the
    `cltv_expiry_delta` for the outgoing channel:
    - report the `cltv_expiry` of the outgoing HTLC and the current channel setting for the outgoing
    channel.
    - return an `incorrect_cltv_expiry` error.
  - if the `cltv_expiry` is unreasonably near the present:
    - report the current channel setting for the outgoing channel.
    - return an `expiry_too_soon` error.
  - if the `cltv_expiry` is more than `max_htlc_cltv` in the future:
    - return an `expiry_too_far` error.
  - if the channel is disabled:
    - report the current channel setting for the outgoing channel.
    - return a `channel_disabled` error.

An _intermediate hop_ MUST NOT, but the _final node_:
  - if the payment hash has already been paid:
    - MAY treat the payment hash as unknown.
    - MAY succeed in accepting the HTLC.
  - if the `payment_secret` doesn't match the expected value for that `payment_hash`,
    or the `payment_secret` is required and is not present:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the amount paid is less than the amount expected:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the payment hash is unknown:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the amount paid is more than twice the amount expected:
    - SHOULD fail the HTLC.
    - SHOULD return an `incorrect_or_unknown_payment_details` error.
      - Note: this allows the origin node to reduce information leakage by
      altering the amount while not allowing for accidental gross overpayment.
  - if the `cltv_expiry` value is unreasonably near the present:
    - MUST fail the HTLC.
    - MUST return an `incorrect_or_unknown_payment_details` error.
  - if the `cltv_expiry` from the final node's HTLC is below `outgoing_cltv_value`:
    - MUST return `final_incorrect_cltv_expiry` error.
  - if `amount_msat` from the final node's HTLC is below `amt_to_forward`:
    - MUST return a `final_incorrect_htlc_amount` error.
  - if it returns a `channel_update`:
    - MUST set `short_channel_id` to the `short_channel_id` used by the incoming onion.

### Rationale

In the case of multiple short_channel_id aliases, the `channel_update`
`short_channel_id` should refer to the one the original sender is
expecting, to both avoid confusion and to avoid leaking information
about other aliases (or the real location of the channel UTXO).

## Receiving Failure Codes

### Requirements

The _origin node_:
  - MUST ignore any extra bytes in `failuremsg`.
  - if the _final node_ is returning the error:
    - if the PERM bit is set:
      - SHOULD fail the payment.
    - otherwise:
      - if the error code is understood and valid:
        - MAY retry the payment. In particular, `final_expiry_too_soon` can
        occur if the block height has changed since sending, and in this case
        `temporary_node_failure` could resolve within a few seconds.
  - otherwise, an _intermediate hop_ is returning the error:
    - if the NODE bit is set:
      - SHOULD remove all channels connected with the erring node from
      consideration.
    - if the PERM bit is NOT set:
      - SHOULD restore the channels as it receives new `channel_update`s.
    - otherwise:
      - if UPDATE is set, AND the `channel_update` is valid and more recent
      than the `channel_update` used to send the payment:
        - if `channel_update` should NOT have caused the failure:
          - MAY treat the `channel_update` as invalid.
        - otherwise:
          - SHOULD apply the `channel_update`.
        - MAY queue the `channel_update` for broadcast.
      - otherwise:
        - SHOULD eliminate the channel outgoing from the erring node from
        consideration.
        - if the PERM bit is NOT set:
          - SHOULD restore the channel as it receives new `channel_update`s.
    - SHOULD then retry routing and sending the payment.
  - MAY use the data specified in the various failure types for debugging
  purposes.

# Onion Messages

Onion messages allow peers to use existing connections to query for
invoices (see [BOLT 12](12-offer-encoding.md)).  Like gossip messages,
they are not associated with a particular local channel.  Like HTLCs,
they use [onion messages](#onion-messages) protocol for
end-to-end encryption.

Onion messages use the same form as HTLC `onion_packet`, with a
slightly more flexible format: instead of 1300 byte payloads, the
payload length is implied by the total length (minus 66 bytes for the
header and trailing bytes).  The `onionmsg_payloads` themselves are the same
as the `hop_payloads` format, except there is no "legacy" length: a 0
`length` would mean an empty `onionmsg_payload`.

Onion messages are unreliable: in particular, they are designed to
be cheap to process and require no storage to forward.  As a result,
there is no error returned from intermediary nodes.

For consistency, all onion messages use [Route Blinding](#route-blinding).

## The `onion_message` Message

1. type: 513 (`onion_message`) (`option_onion_messages`)
2. data:
    * [`point`:`blinding`]
    * [`u16`:`len`]
    * [`len*byte`:`onion_message_packet`]

1. type: `onion_message_packet`
2. data:
   * [`byte`:`version`]
   * [`point`:`public_key`]
   * [`...*byte`:`onionmsg_payloads`]
   * [`32*byte`:`hmac`]

1. type: `onionmsg_payloads`
2. data:
   * [`bigsize`:`length`]
   * [`length*u8`:`onionmsg_tlv`]
   * [`32*byte`:`hmac`]
   * ...
   * `filler`

The `onionmsg_tlv` itself is a TLV: an intermediate node expects an
`encrypted_data` which it can decrypt into an `encrypted_data_tlv`
using the `blinding` which it is handed along with the onion message.

Field numbers 64 and above are reserved for payloads for the final
hop, though these are not explicitly refused by non-final hops (unless
even, of course!).

1. `tlv_stream`: `onionmsg_tlv`
2. types:
    1. type: 2 (`reply_path`)
    2. data:
        * [`blinded_path`:`path`]
    1. type: 4 (`encrypted_recipient_data`)
    2. data:
        * [`...*byte`:`encrypted_recipient_data`]

1. subtype: `blinded_path`
2. data:
   * [`point`:`first_node_id`]
   * [`point`:`blinding`]
   * [`byte`:`num_hops`]
   * [`num_hops*onionmsg_hop`:`path`]

1. subtype: `onionmsg_hop`
2. data:
    * [`point`:`blinded_node_id`]
    * [`u16`:`enclen`]
    * [`enclen*byte`:`encrypted_recipient_data`]

#### Requirements

The creator of `encrypted_recipient_data` (usually, the recipient of the onion):

  - MUST create the `encrypted_recipient_data` from the `encrypted_data_tlv` as required in [Route Blinding](#route-blinding).
  - MUST NOT include `short_channel_id`, `payment_relay` or `payment_constraints` in any `encrypted_data_tlv`
  - MUST include `encrypted_data_tlv.next_node_id` for each non-final node.
  - MUST create the `encrypted_recipient_data` from the `encrypted_data_tlv` as required in [Route Blinding](#route-blinding).

The writer:

- MUST set the `onion_message_packet` `version` to 0.
- MUST construct the `onion_message_packet` `onionmsg_payloads` as detailed above using Sphinx.
- MUST NOT use any `associated_data` in the Sphinx construction.
- SHOULD set `onion_message_packet` `len` to 1366 or 32834.
- SHOULD retry via a different path if it expects a response and doesn't receive one after a reasonable period.
- For the non-final nodes' `onionmsg_tlv`:
  - MUST NOT set fields other than `encrypted_recipient_data`.
- For the final node's `onionmsg_tlv`:
  - if the final node is permitted to reply:
    - MUST set `reply_path` `blinding` to the initial blinding factor for the `first_node_id`
    - MUST set `reply_path` `first_node_id` to the unblinded node id of the first node in the reply path.
    - For every `reply_path` `path`:
      - MUST set `blinded_node_id` to the blinded node id to encrypt the onion hop for.
      - MUST set `encrypted_recipient_data` to a valid encrypted `encrypted_data_tlv` stream which meets the requirements of the `onionmsg_tlv` when used by the recipient.
      - MAY use `path_id` to contain a secret so it can recognize use of this `reply_path`.
  - otherwise:
    - MUST NOT set `reply_path`.


The reader:

- SHOULD accept onion messages from peers without an established channel.
- MAY rate-limit messages by dropping them.
- MUST read the `encrypted_recipient_data` using `blinding` as required in [Route Blinding](#route-blinding).
  - MUST ignore the message if that considers the message invalid.
- if `encrypted_data_tlv` contains `allowed_features`:
  - MUST ignore the message if:
    - `encrypted_data_tlv.allowed_features.features` contains an unknown feature bit (even if it is odd).
    - the message uses a feature not included in `encrypted_data_tlv.allowed_features.features`.
- if it is not the final node according to the onion encryption:
  - if the `onionmsg_tlv` contains other tlv fields than `encrypted_recipient_data`:
    - MUST ignore the message.
  - if the `encrypted_data_tlv` contains `path_id`:
    - MUST ignore the message.
  - otherwise:
    - SHOULD forward the message using `onion_message` to the next peer indicated by `next_node_id`.
    - if it forwards the message:
      - MUST set `blinding` in the forwarded `onion_message` to the next blinding as calculated in [Route Blinding](#route-blinding).
- otherwise (it is the final node):
  - if `path_id` is set and corresponds to a path the reader has previously published in a `reply_path`:
    - if the onion message is not a reply to that previous onion:
      - MUST ignore the onion message
  - otherwise (unknown or unset `path_id`):
    - if the onion message is a reply to an onion message which contained a `path_id`:
      - MUST respond (or not respond) exactly as if it did not send the initial onion message.
  - if the `onionmsg_tlv` contains more than one payload field:
    - MUST ignore the message.
  - if it wants to send a reply:
    - MUST create an onion message using `reply_path`.
    - MUST send the reply via `onion_message` to the node indicated by
      the `first_node_id`, using `reply_path` `blinding` to send
      along `reply_path` `path`.


#### Rationale

Care must be taken that replies are only accepted using the exact
reply_path given, otherwise probing is possible.  That means checking
both ways: non-replies don't use the reply path, and replies always
use the reply path.

The requirement to discard messages with `onionmsg_tlv` fields which
are not strictly required ensures consistency between current and
future implementations.  Even odd fields can be a problem since they
are parsed (and thus may be rejected!) by nodes which understand them,
and ignored by those which don't.

All onion messages are blinded, even though this overhead is not
always necessary (33 bytes here, the 16-byte MAC for each encrypted_data_tlv in
the onion).  This blinding allows nodes to use a path provided by
others without knowing its contents.  Using it universally simplifies
implementations a little, and makes it more difficult to distinguish
onion messages.

`len` allows larger messages to be sent than the standard 1300 bytes
allowed for an HTLC onion, but this should be used sparingly as it
reduces the anonymity set, hence the recommendation that it either looks
like an HTLC onion, or if larger, be a fixed size.

Onion messages don't explicitly require a channel, but for
spam-reduction a node may choose to ratelimit such peers, especially
messages it is asked to forward.

## `max_htlc_cltv` Selection

This `max_htlc_ctlv` value is defined as 2016 blocks, based on historical value
deployed by Lightning implementations.

# Test Vector

## Returning Errors

The test vectors use the following parameters:

	pubkey[0] = 0x02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
	pubkey[1] = 0x0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
	pubkey[2] = 0x027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007
	pubkey[3] = 0x032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991
	pubkey[4] = 0x02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145

	nhops = 5
	sessionkey = 0x4141414141414141414141414141414141414141414141414141414141414141

	failure_source  = node 4
	failure_message = `incorrect_or_unknown_payment_details`
      htlc_msat = 100
      height    = 800000
      tlv data
        type  = 34001
        value = [128, 128, ..., 128] (300 bytes)

The expected encrypted failure message produced at each hop can be found in this [json](attributable_error.json) file.

# References

[sphinx]: http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf
[RFC2104]: https://tools.ietf.org/html/rfc2104
[fips198]: http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
[sec2]: http://www.secg.org/sec2-v2.pdf
[rfc8439]: https://tools.ietf.org/html/rfc8439

# Authors

[ FIXME: ]

![Creative Commons License](https://i.creativecommons.org/l/by/4.0/88x31.png "License CC-BY")
<br>
This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
