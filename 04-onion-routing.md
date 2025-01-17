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
    * [Inside encrypted_recipient_data: encrypted_data_tlv](Inside-encrypted_recipient_data-encrypted_data_tlv)
  * [Accepting and Forwarding a Payment](#accepting-and-forwarding-a-payment)
    * [Payload for the Last Node](#payload-for-the-last-node)
    * [Non-strict Forwarding](#non-strict-forwarding)
  * [Shared Secret](#shared-secret)
  * [Blinding Ephemeral Onion Keys](#blinding-ephemeral-onion-keys)
  * [Packet Construction](#packet-construction)
  * [Onion Decryption](#onion-decryption)
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
    1. type: 1 (`invoice_request`)
    2. data:
        * [`...*byte`:`invoice_request_tlv_stream`]
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
        * [`...*byte`:`encrypted_recipient_data`]
    1. type: 12 (`current_path_key`)
    2. data:
        * [`point`:`path_key`]
    1. type: 16 (`payment_metadata`)
    2. data:
        * [`...*byte`:`payment_metadata`]
    1. type: 18 (`total_amount_msat`)
    2. data:
        * [`tu64`:`total_msat`]
    1. type: 5482373484 (`sender_provided_payment_preimage`)
    2. data:
        * [`32*byte`:`payment_preimage`]

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

`sender_provided_payment_preimage` and `invoice_request` are set in the case 
that the recipient is often-offline and another node provided a static BOLT 12 
invoice on their behalf, where `invoice_request` is the sender's originl 
invoice request corresponding to this HTLC.

### Requirements

The creator of `encrypted_recipient_data` (usually, the recipient of payment):

  - MUST create `encrypted_data_tlv` for each node in the blinded route (including itself).
  - MUST include `encrypted_data_tlv.payment_relay` for each non-final node.
  - MUST include exactly one of `encrypted_data_tlv.short_channel_id` or `encrypted_data_tlv.next_node_id` for each non-final node.
  - MUST set `encrypted_data_tlv.payment_constraints` for each non-final node and MAY set it for the final node:
    - `max_cltv_expiry` to the largest block height at which the route is allowed to be used, starting
       from the final node's chosen `max_cltv_expiry` height at which the route should expire, adding 
       the final node's `min_final_cltv_expiry_delta` and then adding 
       `encrypted_data_tlv.payment_relay.cltv_expiry_delta` at each hop.
    - `htlc_minimum_msat` to the largest minimum HTLC value the nodes will allow.
  - If it sets `encrypted_data_tlv.allowed_features`:
    - MUST set it to an empty array.
  - MUST compute the total fees and CLTV delta of the route as follows and communicate them to the sender:
    - `total_fee_base_msat(n+1) = (fee_base_msat(n+1) * 1000000 + total_fee_base_msat(n) * (1000000 + fee_proportional_millionths(n+1)) + 1000000 - 1) / 1000000`
    - `total_fee_proportional_millionths(n+1) = ((total_fee_proportional_millionths(n) + fee_proportional_millionths(n+1)) * 1000000 + total_fee_proportional_millionths(n) * fee_proportional_millionths(n+1) + 1000000 - 1) / 1000000`
    - `total_cltv_delta = cltv_delta(0) + cltv_delta(1) + ... + cltv_delta(n) + min_final_cltv_expiry_delta`
  - MUST create the `encrypted_recipient_data` from the `encrypted_data_tlv` as required in [Route Blinding](#route-blinding).

The writer of the TLV `payload`:

  - For every node inside a blinded route:
    - MUST include the `encrypted_recipient_data` provided by the recipient
    - For the first node in the blinded route:
      - MUST include the `path_key` provided by the recipient in `current_path_key`
    - If it is the final node:
      - MUST include `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
      - The value set for `outgoing_cltv_value`: 
        - MUST use the current block height as a baseline value. 
        - if a [random offset](07-routing-gossip.md#recommendations-for-routing) was added to improve privacy:
          - SHOULD add the offset to the baseline value.
      - if paying to a static BOLT 12 invoice:
        - MUST set `sender_provided_payment_preimage` to randomly generated unique bytes.
        - MUST set `update_add_htlc.payment_hash` to match the SHA256 hash of
          `sender_provided_payment_preimage`.
        - MUST set `invoice_request` to the BOLT 12 invoice request
          corresponding to this HTLC.
      - otherwise:
        - MUST NOT set `sender_provided_payment_preimage`.
    - MUST NOT include any other tlv field.
  - For every node outside of a blinded route:
    - MUST include `amt_to_forward` and `outgoing_cltv_value`.
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
    - If `path_key` is set in the incoming `update_add_htlc`:
      - MUST return an error if `current_path_key` is present.
      - MUST use that `path_key` as `path_key` for decryption.
    - Otherwise:
      - MUST return an error if `current_path_key` is not present.
      - MUST use that `current_path_key` as the `path_key` for decryption.
      - SHOULD add a random delay before returning errors.
    - MUST return an error if `encrypted_recipient_data` does not decrypt using the
      `path_key` as described in [Route Blinding](#route-blinding).
    - If `payment_constraints` is present:
      - MUST return an error if:
        - the expiry is greater than `encrypted_recipient_data.payment_constraints.max_cltv_expiry`.
        - the amount is below `encrypted_recipient_data.payment_constraints.htlc_minimum_msat`.
    - If `allowed_features` is missing:
      - MUST process the message as if it were present and contained an empty array.
    - MUST return an error if:
      - `encrypted_recipient_data.allowed_features.features` contains an unknown feature bit (even if it is odd).
      - `encrypted_recipient_data` contains both `short_channel_id` and `next_node_id`.
      - the payment uses a feature not included in `encrypted_recipient_data.allowed_features.features`.
    - If it is not the final node:
      - MUST return an error if the payload contains other tlv fields than `encrypted_recipient_data` and `current_path_key`.
      - MUST return an error if `encrypted_recipient_data` does not contain either `short_channel_id` or `next_node_id`.
      - MUST return an error if `encrypted_recipient_data` does not contain `payment_relay`.
      - MUST use values from `encrypted_recipient_data.payment_relay` to calculate `amt_to_forward` and `outgoing_cltv_value` as follows:
        - `amt_to_forward = ((amount_msat - fee_base_msat) * 1000000 + 1000000 + fee_proportional_millionths - 1) / (1000000 + fee_proportional_millionths)`
        - `outgoing_cltv_value = cltv_expiry - payment_relay.cltv_expiry_delta`
    - If it is the final node:
      - MUST return an error if the payload contains other tlv fields than `encrypted_recipient_data`, `current_path_key`, `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
      - MUST return an error if `amt_to_forward`, `outgoing_cltv_value` or `total_amount_msat` are not present.
      - MUST return an error if `amt_to_forward` is below what it expects for the payment.
      - MUST return an error if incoming `cltv_expiry` < `outgoing_cltv_value`.
      - MUST return an error if incoming `cltv_expiry` < `current_block_height` + `min_final_cltv_expiry_delta`.
      - MUST use `sender_provided_payment_preimage` when claiming the HTLC, if present
  - Otherwise (it is not part of a blinded route):
    - MUST return an error if `path_key` is set in the incoming `update_add_htlc` or `current_path_key` is present.
    - MUST return an error if `amt_to_forward` or `outgoing_cltv_value` are not present.
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

## Route Blinding

1. subtype: `blinded_path`
2. data:
   * [`sciddir_or_pubkey`:`first_node_id`]
   * [`point`:`first_path_key`]
   * [`byte`:`num_hops`]
   * [`num_hops*blinded_path_hop`:`path`]

1. subtype: `blinded_path_hop`
2. data:
    * [`point`:`blinded_node_id`]
    * [`u16`:`enclen`]
    * [`enclen*byte`:`encrypted_recipient_data`]

A blinded path consists of:
1. an initial introduction point (`first_node_id`)
2. an initial key to share a secret with the first node_id (`first_path_key`)
3. a series of tweaked node ids (`path.blinded_node_id`)
4. a series of binary blobs encrypted to the nodes (`path.encrypted_recipient_data`)
   to tell them the next hop.

For example, Dave wants Alice to reach him via public node Bob then
Carol.  He creates a chain of public keys ("path_keys") for Bob, Carol
and finally himself, so he can share a secret with each of them.  These
keys are a simple chain, so each node can derive the next `path_key` without
having to be told explicitly.

From these shared secrets, Dave creates and encrypts three `encrypted_data_tlv`s:
1. encrypted_data_bob: For Bob to tell him to forward to Carol
2. encrypted_data_carol: For Carol to tell her to forward to him
3. encrypted_data_dave: For himself to indicate the path was used, and any metadata he wants.

To mask the node ids, he also derives three blinding factors from the
shared secrets, which turn Bob into Bob', Carol into Carol' and Dave
into Dave'.

So this is the `blinded_path` he hands to Alice.

1. `first_node_id`: Bob
2. `first_path_key`: the first path key for Bob 
3. `path`: [Bob', encrypted_data_bob], [Carol', encrypted_data_carol], [Dave', encrypted_data_dave]

There are two different ways for Alice to construct an onion which gets to Bob (since he's probably not a direct peer of hers) which are described in the requirements below.

But after Bob the path is always the same: he will send Carol the `path_key` he derived, along with the onion.  She will use the `path_key` to derive the tweak for the onion (which Alice encrypted for Carol' not Carol) so she can decrypt it, and also to derive the key to decrypt `encrypted_data_tlv` which will tell her to forward to Dave (and possibly additional restrictions Dave specified).

### Requirements

Note that the creator of the blinded path (i.e. the recipient) is creating it for the sender to use to create an onion, and for the intermediate nodes to read the instructions, hence there are two reader sections here.

The writer of a `blinded_path`:

- MUST create a viable path to itself ($`N_r`$) i.e. $`N_0 \rightarrow N_1 \rightarrow ... \rightarrow N_r`$.
- MUST set `first_node_id` to $`N_0`$
- MUST create a series of ECDH shared secrets for each node in the route using the following algorithm:
  - $`e_0 \leftarrow \{0;1\}^{256}`$ ($`e_0`$ SHOULD be obtained via CSPRNG)
  - $`E_0 = e_0 \cdot G`$
  - For every node in the route:
    - let $`N_i = k_i * G`$ be the `node_id` ($`k_i`$ is $`N_i`$'s private key)
    - $`ss_i = SHA256(e_i * N_i) = SHA256(k_i * E_i)`$ (ECDH shared secret known only by $`N_r`$ and $`N_i`$)
    - $`rho_i = HMAC256(\text{"rho"}, ss_i)`$ (key used to encrypt `encrypted_recipient_data` for $`N_i`$ by $`N_r`$)
    - $`e_{i+1} = SHA256(E_i || ss_i) * e_i`$ (ephemeral private path key, only known by $`N_r`$)
    - $`E_{i+1} = SHA256(E_i || ss_i) * E_i`$ (`path_key`. NB: $`N_i`$ MUST NOT learn $`e_i`$)
- MUST set `first_path_key` to $`E_0`$
- MUST create a series of blinded node IDs $`B_i`$ for each node using the following algorithm:
  - $`B_i = HMAC256(\text{"blinded\_node\_id"}, ss_i) * N_i`$ (blinded `node_id` for $`N_i`$, private key known only by $`N_i`$)
  - MUST set `blinded_node_id` for each `blinded_path_hop` in `path` to $`B_i`$
- MAY replace $`E_{i+1}`$ with a different value, but if it does:
  - MUST set `encrypted_data_tlv[i].next_path_key_override` to $`E_{i+1}`$
- MAY store private data in `encrypted_data_tlv[r].path_id` to verify that the route is used in the right context and was created by them
- SHOULD add padding data to ensure all `encrypted_data_tlv[i]` have the same length
- MUST encrypt each `encrypted_data_tlv[i]` with ChaCha20-Poly1305 using the corresponding $`rho_i`$ key and an all-zero nonce to produce `encrypted_recipient_data[i]`
- MAY add additional "dummy" hops at the end of the path (which it will ignore on receipt) to obscure the path length.

The reader of the `blinded_path`:
- MUST prepend its own onion payloads to reach the `first_node_id`
- MUST include the corresponding `encrypted_recipient_data` in each onion payload within `path`
- For the first entry in `path`:
  - if it is sending a payment:
    - SHOULD create an unblinded onion payment to `first_node_id`, and include `first_path_key` as `current_path_key`.
  - otherwise:
    - MUST encrypt the first blinded path onion to the first `blinded_node_id`.
    - MUST set `next_path_key_override` in the prior onion payload to `first_path_key`.
- For each successive entry in `path`:
  - MUST encrypt the onion to the corresponding `blinded_node_id`.

The reader of the `encrypted_recipient_data`:

- MUST compute:
  - $`ss_i = SHA256(k_i * E_i)`$ (standard ECDH)
  - $`b_i = HMAC256(\text{"blinded\_node\_id"}, ss_i) * k_i`$
  - $`rho_i = HMAC256(\text{"rho"}, ss_i)`$
- MUST decrypt the `encrypted_recipient_data` field using $`rho_i`$ as a key using ChaCha20-Poly1305 and an all-zero nonce key.
- If the `encrypted_recipient_data` field is missing, cannot be decrypted into an `encrypted_data_tlv` or contains unknown even fields:
  - MUST return an error
- If the `encrypted_data_tlv` contains a `next_path_key_override`:
  - MUST use it as the next `path_key`.
- Otherwise:
  - MUST use $`E_{i+1} = SHA256(E_i || ss_i) * E_i`$ as the next `path_key`
- MUST forward the onion and include the next `path_key` in the lightning
  message for the next node
- If it is the final recipient:
  - MUST ignore the message if the `path_id` does not match the blinded route it
    created for this purpose

### Rationale

Route blinding is a lightweight technique to provide recipient anonymity.
It's more flexible than rendezvous routing because it simply replaces the public
keys of the nodes in the route with random public keys while letting senders
choose what data they put in the onion for each hop. Blinded routes are also
reusable in some cases (e.g. onion messages).

Each node in the blinded route needs to receive $`E_i`$ to be able to decrypt
the onion and the `encrypted_recipient_data` payload.

When concatenating two blinded routes generated by different nodes, the
last node of the first route needs to know the first `path_key` of the
second route: the `next_path_key_override` field must be used to transmit this
information.  In theory this method could be used for payments (not just
onion messages), but we recommend using an unblinded path to reach the 
`first_node_id` and using `current_path_key` there: this means that the
node can tell it is being used as an introductory point, but also does
not require blinded path support on the nodes to reach that point, and
gives meaningful errors on the unblinded part of the payment.

The final recipient must verify that the blinded route is used in the right
context (e.g. for a specific payment) and was created by them. Otherwise a
malicious sender could create different blinded routes to all the nodes that
they suspect could be the real recipient and try them until one accepts the
message. The recipient can protect against that by storing $`E_r`$ and the
context (e.g. a `payment_hash`), and verifying that they match when receiving
the onion. Otherwise, to avoid additional storage cost, it can put some private
context information in the `path_id` field (e.g. the `payment_preimage`) and
verify that when receiving the onion. Note that it's important to use private
information in that case, that senders cannot have access to.

Whenever the introduction point receives a failure from the blinded route, it
should add a random delay before forwarding the error. Failures are likely to
be probing attempts and message timing may help the attacker infer its distance
to the final recipient.

The `padding` field can be used to ensure that all `encrypted_recipient_data` have the
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

### Inside `encrypted_recipient_data`: `encrypted_data_tlv`

The `encrypted_recipient_data` is a TLV stream, encrypted for a given blinded node, that
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
    1. type: 8 (`next_path_key_override`)
    2. data:
        * [`point`:`path_key`]
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

#### Rationale

Encrypted recipient data is created by the final recipient to give to the
sender, containing instructions for the node on how to handle the message (it can also be created by the sender themselves: the node forwarding cannot tell).  It's used
in both payment onions and onion messages onions.  See [Route Blinding](#route-blinding).


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

# Blinding Ephemeral Onion Keys

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

# Onion Decryption

There are two kinds of `onion_packet` we use:

1. `onion_routing_packet` in `update_add_htlc` for payments, which contains a `payload` TLV (see [Adding an HTLC](02-peer-protocol.md#adding-an-htlc-update_add_htlc))
2. `onion_message_packet` in `onion_message` for messages, which contains an `onionmsg_tlv` TLV (see [Onion Messages](#onion-messages))

Those sections specify the `associated_data` to use, the `path_key` (if any), the extracted payload format and handling (including how to determine the next peer, if any), and how to handle errors.  The processing itself is identical.

## Requirements

A reader:
  - if `version` is not 0:
    - MUST abort processing the packet and fail.
  - if `public_key` is not a valid pubkey:
    - MUST abort processing the packet and fail.
  - if the onion is for a payment:
    - if `hmac` has previously been received:
      - if the preimage is known:
        - MAY immediately redeem the HTLC using the preimage.
      - otherwise:
        - MUST abort processing the packet and fail.
  - if `path_key` is specified:
    - Calculate the `blinding_ss` as ECDH(`path_key`, `node_privkey`).
    - Either:
      - Tweak `public_key` by multiplying by $`HMAC256(\text{"blinded\_node\_id"}, blinding\_ss)`$.
    - or (equivalently):
      - Tweak its own `node_privkey` below by multiplying by $`HMAC256(\text{"blinded\_node\_id"}, blinding\_ss)`$.
  - Derive the shared secret `ss` as ECDH(`public_key`, `node_privkey`) (see [Shared Secret](#shared-secret)).
  - Derive `mu` as $`HMAC256(\text{"mu"}, ss)`$ (see [Key Generation](#key-generation)).
  - Derive the HMAC as $`HMAC256(mu, hop\_payloads || associated\_data)`$.
  - MUST use a constant time comparison of the computed HMAC and `hmac`.
  - If the computed HMAC and `hmac` differ:
    - MUST abort processing the packet and fail.
  - Derive `rho` as $`HMAC256(\text{"rho"}, ss)`$ (see [Key Generation](#key-generation)).
  - Derive `bytestream` of twice the length of `hop_payloads` using `rho` (see [Pseudo Random Byte Stream](pseudo-random-byte-stream)).
  - Set `unwrapped_payloads` to the XOR of `hop_payloads` and `bytestream`.
  - Remove a `bigsize` from the front of `unwrapped_payloads` as `payload_length`.  If that is malformed:
    - MUST abort processing the packet and fail.
  - If the `payload_length` is less than two:
    - MUST abort processing the packet and fail.
  - If there are fewer than `payload_length` bytes remaining in `unwrapped_payloads`:
    - MUST abort processing the packet and fail.
  - Remove `payload_length` bytes from the front of `unwrapped_payloads`, as the current `payload`.
  - If there are fewer than 32 bytes remaining in `unwrapped_payloads`:
    - MUST abort processing the packet and fail.
  - Remove 32 bytes as `next_hmac` from the front of `unwrapped_payloads`.
  - If `unwrapped_payloads` is smaller than `hop_payloads`:
    - MUST abort processing the packet and fail.
  - If `next_hmac` is not all-zero (not the final node):
    - Derive `blinding_tweak` as $`SHA256(public\_key || ss)`$ (see [Blinding Ephemeral Onion Keys](#blinding-ephemeral-onion-keys)).
    - SHOULD forward an onion to the next peer with:
      - `version` set to 0.
      - `public_key` set to the incoming `public_key` multiplied by `blinding_tweak`.
      - `hop_payloads` set to the `unwrapped_payloads`, truncated to the incoming `hop_payloads` size.
      - `hmac` set to `next_hmac`.
    - If it cannot forward:
      - MUST fail.
  - Otherwise (all-zero `next_hmac`):
    - This is the final destination of the onion.

## Rationale

In the case where blinded paths are used, the sender did not actually encrypt this onion for our `node_id`, but for a tweaked version: we can derive the tweak used from `path_key` which is given alongside the onion.  Then we either tweak our node private key the same way to decrypt the onion, or tweak to the onion ephemeral key which is mathematically equivalent.

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

The onion routing protocol includes a simple mechanism for returning encrypted
error messages to the origin node.
The returned error messages may be failures reported by any hop, including the
final node.
The format of the forward packet is not usable for the return path, since no hop
besides the origin has access to the information required for its generation.
Note that these error messages are not reliable, as they are not placed on-chain
due to the possibility of hop failure.

Intermediate hops store the shared secret from the forward path and reuse it to
obfuscate any corresponding return packet during each hop.
In addition, each node locally stores data regarding its own sending peer in the
route, so it knows where to return-forward any eventual return packets.
The node generating the error message (_erring node_) builds a return packet
consisting of the following fields:

1. data:
   * [`32*byte`:`hmac`]
   * [`u16`:`failure_len`]
   * [`failure_len*byte`:`failuremsg`]
   * [`u16`:`pad_len`]
   * [`pad_len*byte`:`pad`]

Where `hmac` is an HMAC authenticating the remainder of the packet, with a key
generated using the above process, with key type `um`, `failuremsg` as defined
below, and `pad` as the extra bytes used to conceal length.

The erring node then generates a new key, using the key type `ammag`.
This key is then used to generate a pseudo-random stream, which is in turn
applied to the packet using `XOR`.

The obfuscation step is repeated by every hop along the return path.
Upon receiving a return packet, each hop generates its `ammag`, generates the
pseudo-random byte stream, and applies the result to the return packet before
return-forwarding it.

The origin node is able to detect that it's the intended final recipient of the
return message, because of course, it was the originator of the corresponding
forward packet.
When an origin node receives an error message matching a transfer it initiated
(i.e. it cannot return-forward the error any further) it generates the `ammag`
and `um` keys for each hop in the route.
It then iteratively decrypts the error message, using each hop's `ammag`
key, and computes the HMAC, using each hop's `um` key.
The origin node can detect the sender of the error message by matching the
`hmac` field with the computed HMAC.

The association between the forward and return packets is handled outside of
this onion routing protocol, e.g. via association with an HTLC in a payment
channel.

Error handling for HTLCs with `path_key` is particularly fraught,
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

The _origin node_:
  - once the return message has been decrypted:
    - SHOULD store a copy of the message.
    - SHOULD continue decrypting, until the loop has been repeated 27 times
    (maximum route length of tlv payload type).
    - SHOULD use constant `ammag` and `um` keys to obfuscate the route length.

### Rationale

The requirements for the _origin node_ should help hide the payment sender.
By continuing decrypting 27 times (dummy decryption cycles after the error is found)
the erroring node cannot learn its relative position in the route by performing
a timing analysis if the sender were to retry the same route multiple times.

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
* 0x1000 (UPDATE): channel forwarding parameter was violated

The following `failure_code`s are defined:

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
  - if `path_key` is set in the incoming `update_add_htlc`:
    - MUST return an `invalid_onion_blinding` error.
  - if `current_path_key` is set in the onion payload and it is not the
    final node:
    - MUST return an `invalid_onion_blinding` error.
  - otherwise:
    - MUST select one of the above error codes when creating an error message.
    - MUST include the appropriate data for that particular error type.
    - if there is more than one error:
      - SHOULD select the first error it encounters from the list above.

An _erring node_ MAY:
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
  - if `path_key` is set in the incoming `update_add_htlc`:
    - return an `invalid_onion_blinding` error.
  - if `current_path_key` is set in the onion payload and it is not the
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

The `channel_update` field used to be mandatory in messages whose `failure_code`
includes the `UPDATE` flag. However, because nodes applying an update contained
in the onion to their gossip data is a massive fingerprinting vulnerability,
the `channel_update` field is no longer mandatory and nodes are expected to
transition away from including it. Nodes which do not provide a
`channel_update` are expected to set the `channel_update` `len` field to zero.

Some nodes may still use the `channel_update` for retries of the same payment,
however.

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
      - SHOULD restore the channels as it receives new `channel_update`s from
        its peers.
    - otherwise:
      - if UPDATE is set, AND the `channel_update` is valid and more recent
        than the `channel_update` used to send the payment:
        - MAY consider the `channel_update` when calculating routes to retry
          the payment which failed
      - MUST NOT expose the `channel_update` to third-parties in any other
        context, including applying the `channel_update` to the local network
        graph, send the `channel_update` to peers as gossip, etc.
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
    * [`point`:`path_key`]
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
`encrypted_recipient_data` which it can decrypt into an `encrypted_data_tlv`
using the `path_key` which it is handed along with the onion message.

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
    1. type: 64 (`invoice_request`)
    2. data:
        * [`tlv_invoice_request`:`invreq`]
    1. type: 66 (`invoice`)
    2. data:
        * [`tlv_invoice`:`inv`]
    1. type: 68 (`invoice_error`)
    2. data:
        * [`tlv_invoice_error`:`inverr`]

#### Requirements

The creator of `encrypted_recipient_data` (usually, the recipient of the onion):

  - MUST create the `encrypted_recipient_data` from the `encrypted_data_tlv` as required in [Route Blinding](#route-blinding).
  - MUST NOT include `payment_relay` or `payment_constraints` in any `encrypted_data_tlv`
  - MUST include either `next_node_id` or `short_channel_id` in the `encrypted_data_tlv` for each non-final node.
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
    - MUST set `reply_path` `path_key` to the initial path key for the `first_node_id`
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
- MUST decrypt `onion_message_packet` using an empty `associated_data`, and `path_key`, as described in [Onion Decryption](04-onion-routing.md#onion-decryption) to extract an `onionmsg_tlv`.
- If decryption fails, the result is not a valid `onionmsg_tlv`, or it contains unknown even types:
  - MUST ignore the message.
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
    - if `next_node_id` is present:
      - the *next peer* is the peer with that node id.
    - otherwise, if `short_channel_id` is present and corresponds to an announced short_channel_id or a local alias for a channel:
      - the *next peer* is the peer at the other end of that channel.
    - otherwise:
      - MUST ignore the message.
    - SHOULD forward the message using `onion_message` to the *next peer*.
    - if it forwards the message:
      - MUST set `path_key` in the forwarded `onion_message` to the next `path_key` as calculated in [Route Blinding](#route-blinding).
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
      the `first_node_id`, using `reply_path` `path_key` to send
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

This `max_htlc_cltv` value is defined as 2016 blocks, based on historical value
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

The following is an in-depth trace of an example of error message creation:

	# creating error message
	encoded_failure_message = 400f0000000000000064000c3500fd84d1fd012c80808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808002c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	shared_secret = b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328
	payload = 0140400f0000000000000064000c3500fd84d1fd012c80808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808002c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	um_key = 4da7f2923edce6c2d85987d1d9fa6d88023e6c3a9c3d20f07d3b10b61a78d646
	raw_error_packet = fda7e11974f78ca6cc456f2d17ae54463664696e93842548245dd2a2c513a6260140400f0000000000000064000c3500fd84d1fd012c80808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808080808002c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	# forwarding error packet
	shared_secret = b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328
	ammag_key = 2f36bb8822e1f0d04c27b7d8bb7d7dd586e032a3218b8d414afbba6f169a4d68
	stream = e9c975b07c9a374ba64fd9be3aae955e917d34d1fa33f2e90f53bbf4394713c6a8c9b16ab5f12fd45edd73c1b0c8b33002df376801ff58aaa94000bf8a86f92620f343baef38a580102395ae3abf9128d1047a0736ff9b83d456740ebbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f42968888550a3bded8c05247e045b866baef0499f079fdaeef6538f31d44deafffdfd3afa2fb4ca9082b8f1c465371a9894dd8c243fb4847e004f5256b3e90e2edde4c9fb3082ddfe4d1e734cacd96ef0706bf63c9984e22dc98851bcccd1c3494351feb458c9c6af41c0044bea3c47552b1d992ae542b17a2d0bba1a096c78d169034ecb55b6e3a7263c26017f033031228833c1daefc0dedb8cf7c3e37c9c37ebfe42f3225c326e8bcfd338804c145b16e34e4f5984bc119af09d471a61f39e9e389c4120cadabc5d9b7b1355a8ccef050ca8ad72f642fc26919927b347808bade4b1c321b08bc363f20745ba2f97f0ced2996a232f55ba28fe7dfa70a9ab0433a085388f25cce8d53de6a2fbd7546377d6ede9027ad173ba1f95767461a3689ef405ab608a21086165c64b02c1782b04a6dba2361a7784603069124e12f2f6dcb1ec7612a4fbf94c0e14631a2bef6190c3d5f35e0c4b32aa85201f449d830fd8f782ec758b0910428e3ec3ca1dba3b6c7d89f69e1ee1b9df3dfbbf6d361e1463886b38d52e8f43b73a3bd48c6f36f5897f514b93364a31d49d1d506340b1315883d425cb36f4ea553430d538fd6f3596d4afc518db2f317dd051abc0d4bfb0a7870c3db70f19fe78d6604bbf088fcb4613f54e67b038277fedcd9680eb97bdffc3be1ab2cbcbafd625b8a7ac34d8c190f98d3064ecd3b95b8895157c6a37f31ef4de094b2cb9dbf8ff1f419ba0ecacb1bb13df0253b826bec2ccca1e745dd3b3e7cc6277ce284d649e7b8285727735ff4ef6cca6c18e2714f4e2a1ac67b25213d3bb49763b3b94e7ebf72507b71fb2fe0329666477ee7cb7ebd6b88ad5add8b217188b1ca0fa13de1ec09cc674346875105be6e0e0d6c8928eb0df23c39a639e04e4aedf535c4e093f08b2c905a14f25c0c0fe47a5a1535ab9eae0d9d67bdd79de13a08d59ee05385c7ea4af1ad3248e61dd22f8990e9e99897d653dd7b1b1433a6d464ea9f74e377f2d8ce99ba7dbc753297644234d25ecb5bd528e2e2082824681299ac30c05354baaa9c3967d86d7c07736f87fc0f63e5036d47235d7ae12178ced3ae36ee5919c093a02579e4fc9edad2c446c656c790704bfc8e2c491a42500aa1d75c8d4921ce29b753f883e17c79b09ea324f1f32ddf1f3284cd70e847b09d90f6718c42e5c94484cc9cbb0df659d255630a3f5a27e7d5dd14fa6b974d1719aa98f01a20fb4b7b1c77b42d57fab3c724339d459ee4a1c6b5d3bd4e08624c786a257872acc9ad3ff62222f2265a658d9f2a007229a5293b67ec91c84c4b4407c228434bad8a815ca9b256c776bd2c9f
	error packet for node 4: 146e94a9086dbbed6a0ab6932d00c118a7195dbf69b7d7a12b0e6956fc54b5e0a989f165b5f12fd45edd73a5b0c48630ff5be69500d3d82a29c0803f0a0679a6a073c33a6fb8250090a3152eba3f11a85184fa87b67f1b0354d6f48e3b342e332a17b7710f342f342a87cf32eccdf0afc2160808d58abb5e5840d2c760c538e63a6f841970f97d2e6fe5b8739dc45e2f7f5f532f227bcc2988ab0f9cc6d3f12909cd5842c37bc8c7608475a5ebbe10626d5ecc1f3388ad5f645167b44a4d166f87863fe34918cea25c18059b4c4d9cb414b59f6bc50c1cea749c80c43e2344f5d23159122ed4ab9722503b212016470d9610b46c35dbeebaf2e342e09770b38392a803bc9d2e7c8d6d384ffcbeb74943fe3f64afb2a543a6683c7db3088441c531eeb4647518cb41992f8954f1269fb969630944928c2d2b45593731b5da0c4e70d04a0a57afe4af42e99912fbb4f8883a5ecb9cb29b883cb6bfa0f4db2279ff8c6d2b56a232f55ba28fe7dfa70a9ab0433a085388f25cce8d53de6a2fbd7546377d6ede9027ad173ba1f95767461a3689ef405ab608a21086165c64b02c1782b04a6dba2361a7784603069124e12f2f6dcb1ec7612a4fbf94c0e14631a2bef6190c3d5f35e0c4b32aa85201f449d830fd8f782ec758b0910428e3ec3ca1dba3b6c7d89f69e1ee1b9df3dfbbf6d361e1463886b38d52e8f43b73a3bd48c6f36f5897f514b93364a31d49d1d506340b1315883d425cb36f4ea553430d538fd6f3596d4afc518db2f317dd051abc0d4bfb0a7870c3db70f19fe78d6604bbf088fcb4613f54e67b038277fedcd9680eb97bdffc3be1ab2cbcbafd625b8a7ac34d8c190f98d3064ecd3b95b8895157c6a37f31ef4de094b2cb9dbf8ff1f419ba0ecacb1bb13df0253b826bec2ccca1e745dd3b3e7cc6277ce284d649e7b8285727735ff4ef6cca6c18e2714f4e2a1ac67b25213d3bb49763b3b94e7ebf72507b71fb2fe0329666477ee7cb7ebd6b88ad5add8b217188b1ca0fa13de1ec09cc674346875105be6e0e0d6c8928eb0df23c39a639e04e4aedf535c4e093f08b2c905a14f25c0c0fe47a5a1535ab9eae0d9d67bdd79de13a08d59ee05385c7ea4af1ad3248e61dd22f8990e9e99897d653dd7b1b1433a6d464ea9f74e377f2d8ce99ba7dbc753297644234d25ecb5bd528e2e2082824681299ac30c05354baaa9c3967d86d7c07736f87fc0f63e5036d47235d7ae12178ced3ae36ee5919c093a02579e4fc9edad2c446c656c790704bfc8e2c491a42500aa1d75c8d4921ce29b753f883e17c79b09ea324f1f32ddf1f3284cd70e847b09d90f6718c42e5c94484cc9cbb0df659d255630a3f5a27e7d5dd14fa6b974d1719aa98f01a20fb4b7b1c77b42d57fab3c724339d459ee4a1c6b5d3bd4e08624c786a257872acc9ad3ff62222f2265a658d9f2a007229a5293b67ec91c84c4b4407c228434bad8a815ca9b256c776bd2c9f
	# forwarding error packet
	shared_secret = 21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d
	ammag_key = cd9ac0e09064f039fa43a31dea05f5fe5f6443d40a98be4071af4a9d704be5ad
	stream = 617ca1e4624bc3f04fece3aa5a2b615110f421ec62408d16c48ea6c1b7c33fe7084a2bd9d4652fc5068e5052bf6d0acae2176018a3d8c75f37842712913900263cff92f39f3c18aa1f4b20a93e70fc429af7b2b1967ca81a761d40582daf0eb49cef66e3d6fbca0218d3022d32e994b41c884a27c28685ef1eb14603ea80a204b2f2f474b6ad5e71c6389843e3611ebeafc62390b717ca53b3670a33c517ef28a659c251d648bf4c966a4ef187113ec9848bf110816061ca4f2f68e76ceb88bd6208376460b916fb2ddeb77a65e8f88b2e71a2cbf4ea4958041d71c17d05680c051c3676fb0dc8108e5d78fb1e2c44d79a202e9d14071d536371ad47c39a05159e8d6c41d17a1e858faaaf572623aa23a38ffc73a4114cb1ab1cd7f906c6bd4e21b29694f9830d12e8ad4b1ac320b3d5bfb4e534f02cefe9a983d66939581412acb1927eb93e8ed73145cddf24266bdcc95923ecb38c8c9c5f4465335b0f18bf9f2d03fa02d57f258db27983d94378bc796cbe7737180dd7e39a36e461ebcb7ec82b6dcdf9d3f209381f7b3a23e798c4f92e13b4bb972ee977e24f4b83bb59b577c210e1a612c2b035c8271d9bc1fb915776ac6560315b124465866830473aa238c35089cf2adb9c6e9f05ab113c1d0a4a18ba0cb9951b928c0358186532c36d4c3daa65657be141cc22e326f88e445e898893fd5f0a7dd231ee5bc972077b1e12a8e382b75d4b557e895a2adc757f2e451e33e0ae3fb54566ee09155da6ada818aa4a4a2546832a8ba22f0ef9ec6a1c78e03a7c29cb126bcaf81aea61cd8b07ab9f4e5e0ad0d9a3a0c66d2d0a00cc05884d183a68e816e76b75842d55895f5b91c5c1b9f7052763aae8a647aa0799214275b6e781f0816fc9ffb802a0101eb5a2de6b3375d3e3478f892b2de7f1900d8ca9bf188fcba89fc49d03c38fa2587a8ae119abfb295b15fa11cb188796bedc4fdfceef296e44fbfa7e84569cc6346389a421782e40a298e1e2b6f9cae3103c3f39d24541e4ab7b61dafe1a5f2fe936a59d87cccdaf7c226acc451ceec3e81bc4828b4925feeae3526d5e2bf93bd5f4fdc0e069010aea1ae7e0d480d438918598896b776bf08fea124f91b3a13414b56934857707902612fc97b0e5d02cbe6e5901ad304c7e8656390efccf3a1b22e18a2935181b78d5d2c89540ede8b0e6194d0d3945780bf577f622cb12deedbf8210eb1450c298b9ee19f3c7082aabc2bdbd3384f3539dc3766978567135549df0d48287735854a6098fa40a9e48eaa27e0d159beb65dd871e4c0b3fffa65f0375f0d3253f582193135ece60d5b9d8ba6739d87964e992cbec674b728d9eaaed595462c41d15fb497d4baa062368005d13fc99e1402563117a6c140c10363b05196a4cbb6b84ae807d62c748485c15e3316841e4a98c3aac81e3bc996b4baca77eac8cdbe99cc7c5ebeb85c907cefb4abe15cbe87fdc5dc2326019196235ac205934fcf8e3
	error packet for node 3: 7512354d6a26781d25e65539772ba049b7ed7c530bf75ab7ef80cf974b978a07a1c3dabc61940011585323f70fa98cfa1d4c868da30b1f751e44a72d9b3f79809c8c51c9f0843daa8fe83587844fedeacb7348362003b31922cbb4d6169b2087b6f8d192d9cfe5363254cd1fde24641bde9e422f170c3eb146f194c48a459ae2889d706dc654235fa9dd20307ea54091d09970bf956c067a3bcc05af03c41e01af949a131533778bf6ee3b546caf2eabe9d53d0fb2e8cc952b7e0f5326a69ed2e58e088729a1d85971c6b2e129a5643f3ac43da031e655b27081f10543262cf9d72d6f64d5d96387ac0d43da3e3a03da0c309af121dcf3e99192efa754eab6960c256ffd4c546208e292e0ab9894e3605db098dc16b40f17c320aa4a0e42fc8b105c22f08c9bc6537182c24e32062c6cd6d7ec7062a0c2c2ecdae1588c82185cdc61d874ee916a7873ac54cddf929354f307e870011704a0e9fbc5c7802d6140134028aca0e78a7e2f3d9e5c7e49e20c3a56b624bfea51196ec9e88e4e56be38ff56031369f45f1e03be826d44a182f270c153ee0d9f8cf9f1f4132f33974e37c7887d5b857365c873cb218cbf20d4be3abdb2a2011b14add0a5672e01e5845421cf6dd6faca1f2f443757aae575c53ab797c2227ecdab03882bbbf4599318cefafa72fa0c9a0f5a51d13c9d0e5d25bfcfb0154ed25895260a9df8743ac188714a3f16960e6e2ff663c08bffda41743d50960ea2f28cda0bc3bd4a180e297b5b41c700b674cb31d99c7f2a1445e121e772984abff2bbe3f42d757ceeda3d03fb1ffe710aecabda21d738b1f4620e757e57b123dbc3c4aa5d9617dfa72f4a12d788ca596af14bea583f502f16fdc13a5e739afb0715424af2767049f6b9aa107f69c5da0e85f6d8c5e46507e14616d5d0b797c3dea8b74a1b12d4e47ba7f57f09d515f6c7314543f78b5e85329d50c5f96ee2f55bbe0df742b4003b24ccbd4598a64413ee4807dc7f2a9c0b92424e4ae1b418a3cdf02ea4da5c3b12139348aa7022cc8272a3a1714ee3e4ae111cffd1bdfd62c503c80bdf27b2feaea0d5ab8fe00f9cec66e570b00fd24b4a2ed9a5f6384f148a4d6325110a41ca5659ebc5b98721d298a52819b6fb150f273383f1c5754d320be428941922da790e17f482989c365c078f7f3ae100965e1b38c052041165295157e1a7c5b7a57671b842d4d85a7d971323ad1f45e17a16c4656d889fc75c12fc3d8033f598306196e29571e414281c5da19c12605f48347ad5b4648e371757cbe1c40adb93052af1d6110cfbf611af5c8fc682b7e2ade3bfca8b5c7717d19fc9f97964ba6025aebbc91a6671e259949dcf40984342118de1f6b514a7786bd4f6598ffbe1604cef476b2a4cb1343db608aca09d1d38fc23e98ee9c65e7f6023a8d1e61fd4f34f753454bd8e858c8ad6be6403edc599c220e03ca917db765980ac781e758179cd93983e9c1e769e4241d47c
	# forwarding error packet
	shared_secret = 3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc
	ammag_key = 1bf08df8628d452141d56adfd1b25c1530d7921c23cecfc749ac03a9b694b0d3
	stream = 6149f48b5a7e8f3d6f5d870b7a698e204cf64452aab4484ff1dee671fe63fd4b5f1b78ee2047dfa61e3d576b149bedaf83058f85f06a3172a3223ad6c4732d96b32955da7d2feb4140e58d86fc0f2eb5d9d1878e6f8a7f65ab9212030e8e915573ebbd7f35e1a430890be7e67c3fb4bbf2def662fa625421e7b411c29ebe81ec67b77355596b05cc155755664e59c16e21410aabe53e80404a615f44ebb31b365ca77a6e91241667b26c6cad24fb2324cf64e8b9dd6e2ce65f1f098cfd1ef41ba2d4c7def0ff165a0e7c84e7597c40e3dffe97d417c144545a0e38ee33ebaae12cc0c14650e453d46bfc48c0514f354773435ee89b7b2810606eb73262c77a1d67f3633705178d79a1078c3a01b5fadc9651feb63603d19decd3a00c1f69af2dab2595931ca50d8280758b1cc91ba2dc43dbbc3d91bf25c08b46c2ecef7a32cec64d4b61ee3a629ef563afe058b71e71bcb69033948bc8728c5ebe65ec596e4f305b9fc159d53f723dfc95b57f3d51717f1c89af97a6d587e89e62efcc92198a1b2bd66e2d875505ea4046c04389f8cb0ee98f0af03af2652e2f3d9a9c48430f2891a4d9b16e7d18099e4a3dd334c24aba1e2450792c2f22092c170da549d43a440021e699bd6c20d8bbf1961100a01ebcce06a4609f5ad93066287acf68294cfa9ea7cea03a508983b134a9f0118b16409a61c06aaa95897d2067cb7cd59123f3e2ccf0e16091571d616c44818f118bb7835a679f5c0eea8cf1bd5479882b2c2a341ec26dbe5da87b3d37d66b1fbd176f71ab203a3b6eaf7f214d579e7d0e4a3e59089ebd26ba04a62403ae7a793516ec16d971d51c5c0107a917d1a70221e6de16edca7cb057c7d06902b5191f298aa4d478a0c3a6260c257eae504ebbf2b591688e6f3f77af770b6f566ae9868d2f26c12574d3bf9323af59f0fe0072ff94ae597c2aa6fbcbf0831989e02f9d3d1b9fd6dd97f509185d9ecbf272e38bd621ee94b97af8e1cd43853a8f6aa6e8372585c71bf88246d064ade524e1e0bd8496b620c4c2d3ae06b6b064c97536aaf8d515046229f72bee8aa398cd0cc21afd5449595016bef4c77cb1e2e9d31fe1ca3ffde06515e6a4331ccc84edf702e5777b10fc844faf17601a4be3235931f6feca4582a8d247c1d6e4773f8fb6de320cf902bbb1767192782dc550d8e266e727a2aa2a414b816d1826ea46af71701537193c22bbcc0123d7ff5a23b0aa8d7967f36fef27b14fe1866ff3ab215eb29e07af49e19174887d71da7e7fe1b7aa1b3c805c063e0fafedf125fa6c57e38cce33a3f7bb35fd8a9f0950de3c22e49743c05f40bc55f960b8a8b5e2fde4bb229f125538438de418cb318d13968532499118cb7dcaaf8b6d635ac4001273bdafd12c8ea0702fb2f0dac81dbaaf68c1c32266382b293fa3951cb952ed5c1bdc41750cdbc0bd62c51bb685616874e251f031a929c06faef5bfcb0857f815ae20620b823f0abecfb5
	error packet for node 2: 145bc1c63058f7204abbd2320d422e69fb1b3801a14312f81e5e29e6b5f4774cfed8a25241d3dfb7466e749c1b3261559e49090853612e07bd669dfb5f4c54162fa504138dabd6ebcf0db8017840c35f12a2cfb84f89cc7c8959a6d51815b1d2c5136cedec2e4106bb5f2af9a21bd0a02c40b44ded6e6a90a145850614fb1b0eef2a03389f3f2693bc8a755630fc81fff1d87a147052863a71ad5aebe8770537f333e07d841761ec448257f948540d8f26b1d5b66f86e073746106dfdbb86ac9475acf59d95ece037fba360670d924dce53aaa74262711e62a8fc9eb70cd8618fbedae22853d3053c7f10b1a6f75369d7f73c419baa7dbf9f1fc5895362dcc8b6bd60cca4943ef7143956c91992119bccbe1666a20b7de8a2ff30a46112b53a6bb79b763903ecbd1f1f74952fb1d8eb0950c504df31fe702679c23b463f82a921a2c931500ab08e686cffb2d87258d254fb17843959cccd265a57ba26c740f0f231bb76df932b50c12c10be90174b37d454a3f8b284c849e86578a6182c4a7b2e47dd57d44730a1be9fec4ad07287a397e28dce4fda57e9cdfdb2eb5afdf0d38ef19d982341d18d07a556bb16c1416f480a396f278373b8fd9897023a4ac506e65cf4c306377730f9c8ca63cf47565240b59c4861e52f1dab84d938e96fb31820064d534aca05fd3d2600834fe4caea98f2a748eb8f200af77bd9fbf46141952b9ddda66ef0ebea17ea1e7bb5bce65b6e71554c56dd0d4e14f4cf74c77a150776bf31e7419756c71e7421dc22efe9cf01de9e19fc8808d5b525431b944400db121a77994518d6025711cb25a18774068bba7faaa16d8f65c91bec8768848333156dcb4a08dfbbd9fef392da3e4de13d4d74e83a7d6e46cfe530ee7a6f711e2caf8ad5461ba8177b2ef0a518baf9058ff9156e6aa7b08d938bd8d1485a787809d7b4c8aed97be880708470cd2b2cdf8e2f13428cc4b04ef1f2acbc9562f3693b948d0aa94b0e6113cafa684f8e4a67dc431dfb835726874bef1de36f273f52ee694ec46b0700f77f8538067642a552968e866a72a3f2031ad116663ac17b172b446c5bc705b84777363a9a3fdc6443c07b2f4ef58858122168d4ebbaee920cefc312e1cea870ed6e15eec046ab2073bbf08b0a3366f55cfc6ad4681a12ab0946534e7b6f90ea8992d530ec3daa6b523b3cf03101c60cadd914f30dec932c1ef4341b5a8efac3c921e203574cfe0f1f83433fddb8ccfd273f7c3cab7bc27efe3bb61fdccd5146f1185364b9b621e7fb2b74b51f5ee6be72ab6ff46a6359dc2c855e61469724c1dbeb273df9d2e1c1fb74891239c0019dc12d5c7535f7238f963b761d7102b585372cf021b64c4fc85bfb3161e59d2e298bba44cfd34d6859d9dba9dc6271e5047d525468c814f2ae438474b0a977273036da1a2292f88fcfb89574a6bdca1185b40f8aa54026d5926725f99ef028da1be892e3586361efe15f4a148ff1bc9
	# forwarding error packet
	shared_secret = a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae
	ammag_key = 59ee5867c5c151daa31e36ee42530f429c433836286e63744f2020b980302564
	stream = 0f10c86f05968dd91188b998ee45dcddfbf89fe9a99aa6375c42ed5520a257e048456fe417c15219ce39d921555956ae2ff795177c63c819233f3bcb9b8b28e5ac6e33a3f9b87ca62dff43f4cc4a2755830a3b7e98c326b278e2bd31f4a9973ee99121c62873f5bfb2d159d3d48c5851e3b341f9f6634f51939188c3b9ff45feeb11160bb39ce3332168b8e744a92107db575ace7866e4b8f390f1edc4acd726ed106555900a0832575c3a7ad11bb1fe388ff32b99bcf2a0d0767a83cf293a220a983ad014d404bfa20022d8b369fe06f7ecc9c74751dcda0ff39d8bca74bf9956745ba4e5d299e0da8f68a9f660040beac03e795a046640cf8271307a8b64780b0588422f5a60ed7e36d60417562938b400802dac5f87f267204b6d5bcfd8a05b221ec294d883271b06ca709042ed5dbb64a7328d2796195eab4512994fb88919c73b3e5dd7bf68b2136d34cff39b3be266b71e004509bf975a240800bb8ae5eed248423a991ae80ef751b2d03b67fb93ffdd7969d5b500fe446a4ffb4cd04d0767a5d367ebd3f8f260f38ae1e9d9f9a7bd1a99ca1e10ee36bd241f06fc2b481c9b7450d9c9704204666807783264a0e93468e22db4dc4a7a4db2963ddf4366d08e225cf94848aac794bcecb7e850113e38cc3647a03a5dfaa3442b1bb58b1de7fa7f436feb4d7c23cbd2de6d55d4025fcd383cc9d49c0b130e2fd5a9097c216683c842f898a8a2159761cca9aa1c818194e3b7bea6da6652d5189f3b6b0ca1d5398b6d14e311d9c7f00399c29e94deb98496f4cd97c5d7d6a65cabc3791f60d728d6422a422c0cff5f7dfd4ce2d7e8d38dd71ae18763acc832c57275497f61b2620cca13cc64c0c48353f3817016f91448d6fc1cc451ee1f4a429e43292bbcd54fcd807e2c47675bac1781d9d81e9e6dc69028d428f5ee261750f626bcaf416a0e7badadf73fe1922207ae6c5209d16849e4a108f4a6f38694075f55177105ac4c2b97f6a474b94c03257d8d12b0196e2905d914b8c2213a1b9dc9608e1a2a1e03fe0820a813275de83be5e9734875787a9e006eb8574c23ddd49e2347d1ecfcedf3caa0a5dd45666368525b48ac14225d6422f82dbf59860ee4dc78e845d3c57668ce9b9e7a8d012491cef242078b458a956ad67c360fb6d8b86ab201d6217e49b55fa02a1dea2dbe88d0b08d30670d1b93c35cc5e41e088fccb267e41d6151cf8560496e1beeefe680744d9dabb383a4957466b4dc3e2bce7b135211da483d998a22fa687cc609641126c5dee3ed87291067916b5b065f40582163291d48e81ecd975d0d6fd52a31754f8ef15e43a560bd30ea5bf21915bd2e7007e607abbc6261edc8430cc7f789675b1fe83e807c5c475bd5178eba2fc40674706b0a68c6a428e5dec36e413e653c6db1178923ff87e2389a78bf9e93b713de4f4753f9f9d6a361369b609e1970c91ff9bd191c472e0bf2e8681412260ad0ef5855dc39f2084d45
	error packet for node 1: 1b4b09a935ce7af95b336baae307f2b400e3a7e808d9b4cf421cc4b3955620acb69dcdb656128dae8857adbd4e6b37fbb1be9c1f2f02e61e9e59a630c4c77cf383cb37b07413aa4de2f2fbf5b40ae40a91a8f4c6d74aeacef1bb1be4ecbc26ec2c824d2bc45db4b9098e732a769788f1cff3f5b41b0d25c132d40dc5ad045ef0043b15332ca3c5a09de2cdb17455a0f82a8f20da08346282823dab062cdbd2111e238528141d69de13de6d83994fbc711e3e269df63a12d3a4177c5c149150eb4dc2f589cd8acabcddba14dec3b0dada12d663b36176cd3c257c5460bab93981ad99f58660efa9b31d7e63b39915329695b3fa60e0a3bdb93e7e29a54ca6a8f360d3848866198f9c3da3ba958e7730847fe1e6478ce8597848d3412b4ae48b06e05ba9a104e648f6eaf183226b5f63ed2e68f77f7e38711b393766a6fab7921b03eba82b5d7cb78e34dc961948d6161eadd7cf5d95d9c56df2ff5faa6ccf85eacdc9ff2fc3abafe41c365a5bd14fd486d6b5e2f24199319e7813e02e798877ffe31a70ae2398d9e31b9e3727e6c1a3c0d995c67d37bb6e72e9660aaaa9232670f382add2edd468927e3303b6142672546997fe105583e7c5a3c4c2b599731308b5416e6c9a3f3ba55b181ad0439d3535356108b059f2cb8742eed7a58d4eba9fe79eaa77c34b12aff1abdaea93197aabd0e74cb271269ca464b3b06aef1d6573df5e1224179616036b368677f26479376681b772d3760e871d99efd34cca5cd6beca95190d967da820b21e5bec60082ea46d776b0517488c84f26d12873912d1f68fafd67bcf4c298e43cfa754959780682a2db0f75f95f0598c0d04fd014c50e4beb86a9e37d95f2bba7e5065ae052dc306555bca203d104c44a538b438c9762de299e1c4ad30d5b4a6460a76484661fc907682af202cd69b9a4473813b2fdc1142f1403a49b7e69a650b7cde9ff133997dcc6d43f049ecac5fce097a21e2bce49c810346426585e3a5a18569b4cddd5ff6bdec66d0b69fcbc5ab3b137b34cc8aefb8b850a764df0e685c81c326611d901c392a519866e132bbb73234f6a358ba284fbafb21aa3605cacbaf9d0c901390a98b7a7dac9d4f0b405f7291c88b2ff45874241c90ac6c5fc895a440453c344d3a365cb929f9c91b9e39cb98b142444aae03a6ae8284c77eb04b0a163813d4c21883df3c0f398f47bf127b5525f222107a2d8fe55289f0cfd3f4bbad6c5387b0594ef8a966afc9e804ccaf75fe39f35c6446f7ee076d433f2f8a44dba1515acc78e589fa8c71b0a006fe14feebd51d0e0aa4e51110d16759eee86192eee90b34432130f387e0ccd2ee71023f1f641cddb571c690107e08f592039fe36d81336a421e89378f351e633932a2f5f697d25b620ffb8e84bb6478e9bd229bf3b164b48d754ae97bd23f319e3c56b3bcdaaeb3bd7fc02ec02066b324cb72a09b6b43dec1097f49d69d3c138ce6f1a6402898baf7568c
	# forwarding error packet
	shared_secret = 53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66
	ammag_key = 3761ba4d3e726d8abb16cba5950ee976b84937b61b7ad09e741724d7dee12eb5
	stream = 3699fd352a948a05f604763c0bca2968d5eaca2b0118602e52e59121f050936c8dd90c24df7dc8cf8f1665e39a6c75e9e2c0900ea245c9ed3b0008148e0ae18bbfaea0c711d67eade980c6f5452e91a06b070bbde68b5494a92575c114660fb53cf04bf686e67ffa4a0f5ae41a59a39a8515cb686db553d25e71e7a97cc2febcac55df2711b6209c502b2f8827b13d3ad2f491c45a0cafe7b4d8d8810e805dee25d676ce92e0619b9c206f922132d806138713a8f69589c18c3fdc5acee41c1234b17ecab96b8c56a46787bba2c062468a13919afc18513835b472a79b2c35f9a91f38eb3b9e998b1000cc4a0dbd62ac1a5cc8102e373526d7e8f3c3a1b4bfb2f8a3947fe350cb89f73aa1bb054edfa9895c0fc971c2b5056dc8665902b51fced6dff80c4d247db977c15a710ce280fbd0ae3ca2a245b1c967aeb5a1a4a441c50bc9ceb33ca64b5ca93bd8b50060520f35a54a148a4112e8762f9d0b0f78a7f46a5f06c7a4b0845d020eb505c9e527aabab71009289a6919520d32af1f9f51ce4b3655c6f1aae1e26a16dc9aae55e9d4a6f91d4ba76e96fcb851161da3fc39d0d97ce30a5855c75ac2f613ff36a24801bcbd33f0ce4a3572b9a2fca21efb3b07897fc07ee71e8b1c0c6f8dbb7d2c4ed13f11249414fc94047d1a4a0be94d45db56af4c1a3bf39c9c5aa18209eaebb9e025f670d4c8cc1ee598c912db154eaa3d0c93cb3957e126c50486bf98c852ad326b5f80a19df6b2791f3d65b8586474f4c5dcb2aca0911d2257d1bb6a1e9fc1435be879e75d23290f9feb93ed40baaeca1c399fc91fb1da3e5f0f5d63e543a8d12fe6f7e654026d3a118ab58cb14bef9328d4af254215eb1f639828cc6405a3ab02d90bb70a798787a52c29b3a28fc67b0908563a65f08112abd4e9115cb01db09460c602aba3ddc375569dc3abe42c61c5ea7feb39ad8b05d8e2718e68806c0e1c34b0bc85492f985f8b3e76197a50d63982b780187078f5c59ebd814afaeffc7b2c6ee39d4f9c8c45fb5f685756c563f4b9d028fe7981b70752f5a31e44ba051ab40f3604c8596f1e95dc9b0911e7ede63d69b5eecd245fbecbcf233cf6eba842c0fec795a5adeab2100b1a1bc62c15046d48ec5709da4af64f59a2e552ddbbdcda1f543bb4b687e79f2253ff0cd9ba4e6bfae8e510e5147273d288fd4336dbd0b6617bf0ef71c0b4f1f9c1dc999c17ad32fe196b1e2b27baf4d59bba8e5193a9595bd786be00c32bae89c5dbed1e994fddffbec49d0e2d270bcc1068850e5d7e7652e274909b3cf5e3bc6bf64def0bbeac974a76d835e9a10bdd7896f27833232d907b7405260e3c986569bb8fdd65a55b020b91149f27bda9e63b4c2cc5370bcc81ef044a68c40c1b178e4265440334cc40f59ab5f82a022532805bfa659257c8d8ab9b4aef6abbd05de284c2eb165ef35737e3d387988c566f7b1ca0b1fc3e7b4ed991b77f23775e1c36a09a991384a33b78
	error packet for node 0: 2dd2f49c1f5af0fcad371d96e8cddbdcd5096dc309c1d4e110f955926506b3c03b44c192896f45610741c85ed4074212537e0c118d472ff3a559ae244acd9d783c65977765c5d4e00b723d00f12475aafaafff7b31c1be5a589e6e25f8da2959107206dd42bbcb43438129ce6cce2b6b4ae63edc76b876136ca5ea6cd1c6a04ca86eca143d15e53ccdc9e23953e49dc2f87bb11e5238cd6536e57387225b8fff3bf5f3e686fd08458ffe0211b87d64770db9353500af9b122828a006da754cf979738b4374e146ea79dd93656170b89c98c5f2299d6e9c0410c826c721950c780486cd6d5b7130380d7eaff994a8503a8fef3270ce94889fe996da66ed121741987010f785494415ca991b2e8b39ef2df6bde98efd2aec7d251b2772485194c8368451ad49c2354f9d30d95367bde316fec6cbdddc7dc0d25e99d3075e13d3de0822669861dafcd29de74eac48b64411987285491f98d78584d0c2a163b7221ea796f9e8671b2bb91e38ef5e18aaf32c6c02f2fb690358872a1ed28166172631a82c2568d23238017188ebbd48944a147f6cdb3690d5f88e51371cb70adf1fa02afe4ed8b581afc8bcc5104922843a55d52acde09bc9d2b71a663e178788280f3c3eae127d21b0b95777976b3eb17be40a702c244d0e5f833ff49dae6403ff44b131e66df8b88e33ab0a58e379f2c34bf5113c66b9ea8241fc7aa2b1fa53cf4ed3cdd91d407730c66fb039ef3a36d4050dde37d34e80bcfe02a48a6b14ae28227b1627b5ad07608a7763a531f2ffc96dff850e8c583461831b19feffc783bc1beab6301f647e9617d14c92c4b1d63f5147ccda56a35df8ca4806b8884c4aa3c3cc6a174fdc2232404822569c01aba686c1df5eecc059ba97e9688c8b16b70f0d24eacfdba15db1c71f72af1b2af85bd168f0b0800483f115eeccd9b02adf03bdd4a88eab03e43ce342877af2b61f9d3d85497cd1c6b96674f3d4f07f635bb26add1e36835e321d70263b1c04234e222124dad30ffb9f2a138e3ef453442df1af7e566890aedee568093aa922dd62db188aa8361c55503f8e2c2e6ba93de744b55c15260f15ec8e69bb01048ca1fa7bbbd26975bde80930a5b95054688a0ea73af0353cc84b997626a987cc06a517e18f91e02908829d4f4efc011b9867bd9bfe04c5f94e4b9261d30cc39982eb7b250f12aee2a4cce0484ff34eebba89bc6e35bd48d3968e4ca2d77527212017e202141900152f2fd8af0ac3aa456aae13276a13b9b9492a9a636e18244654b3245f07b20eb76b8e1cea8c55e5427f08a63a16b0a633af67c8e48ef8e53519041c9138176eb14b8782c6c2ee76146b8490b97978ee73cd0104e12f483be5a4af414404618e9f6633c55dda6f22252cb793d3d16fae4f0e1431434e7acc8fa2c009d4f6e345ade172313d558a4e61b4377e31b8ed4e28f7cd13a7fe3f72a409bc3bdabfe0ba47a6d861e21f64d2fac706dab18b3e546df4

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
