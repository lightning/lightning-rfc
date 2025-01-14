# BOLT #11: Invoice Protocol for Lightning Payments

A simple, extendable, QR-code-ready protocol for requesting payments
over Lightning.

## Table of Contents

  * [Encoding Overview](#encoding-overview)
  * [Human-Readable Part](#human-readable-part)
  * [Data Part](#data-part)
    * [Tagged Fields](#tagged-fields)
    * [Feature Bits](#feature-bits)
  * [Payer / Payee Interactions](#payer--payee-interactions)
    * [Payer / Payee Requirements](#payer--payee-requirements)
  * [Implementation](#implementation)
  * [Examples](#examples)
  * [Authors](#authors)

## Encoding Overview

The format for a Lightning invoice uses
[bech32 encoding](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki),
which is already used for Bitcoin Segregated Witness. It can be
simply reused for Lightning invoices even though its 6-character checksum is optimized
for manual entry, which is unlikely to happen often given the length
of Lightning invoices.

If a URI scheme is desired, the current recommendation is to either
use 'lightning:' as a prefix before the BOLT-11 encoding (note: not
'lightning://'), or for fallback to Bitcoin payments, to use 'bitcoin:',
as per BIP-21, with the key 'lightning' and the value equal to the BOLT-11
encoding.

### Requirements

A writer:
   - MUST encode the payment request in Bech32 (see BIP-0173)
   - SHOULD use upper case for QR codes (see BIP-0173)
   - MAY exceed the 90-character limit specified in BIP-0173.

A reader:
  - MUST parse the address as Bech32, as specified in BIP-0173 (also without the character limit).
	- Note: this includes handling uppercase as specified by BIP-0173
  - if the checksum is incorrect:
    - MUST fail the payment.

## Human-Readable Part

The human-readable part of a Lightning invoice consists of two sections:
1. `prefix`: `ln` + BIP-0173 currency prefix (e.g. `lnbc` for Bitcoin mainnet,
   `lntb` for Bitcoin testnet, `lntbs` for Bitcoin signet, and `lnbcrt` for
   Bitcoin regtest)
1. `amount`: optional number in that currency, followed by an optional
   `multiplier` letter. The unit encoded here is the 'social' convention of a payment unit -- in the case of Bitcoin the unit is 'bitcoin' NOT satoshis.

The following `multiplier` letters are defined:

* `m` (milli): multiply by 0.001
* `u` (micro): multiply by 0.000001
* `n` (nano): multiply by 0.000000001
* `p` (pico): multiply by 0.000000000001

### Requirements

A writer:
  - MUST encode `prefix` using the currency required for successful payment.
  - if a specific minimum `amount` is required for successful payment:
	  - MUST include that `amount`.
	- MUST encode `amount` as a positive decimal integer with no leading 0s.
	- If the `p` multiplier is used the last decimal of `amount` MUST be `0`.
	- SHOULD use the shortest representation possible, by using the largest
	  multiplier or omitting the multiplier.

A reader:
  - if it does NOT understand the `prefix`:
    - MUST fail the payment.
  - if the `amount` is empty:
	  - SHOULD indicate to the payer that amount is unspecified.
  - otherwise:
    - if `amount` contains a non-digit OR is followed by anything except
    a `multiplier` (see table above):
  	  - MUST fail the payment.
    - if the `multiplier` is present:
	  - MUST multiply `amount` by the `multiplier` value to derive the
      amount required for payment.
      - if multiplier is `p` and the last decimal of `amount` is not 0:
	    - MUST fail the payment.

### Rationale

The `amount` is encoded into the human readable part, as it's fairly
readable and a useful indicator of how much is being requested.

Donation addresses often don't have an associated amount, so `amount`
is optional in that case. Usually a minimum payment is required for
whatever is being offered in return.

The `p` multiplier would allow to specify sub-millisatoshi amounts, which cannot be transferred on the network, since HTLCs are denominated in millisatoshis.
Requiring a trailing `0` decimal ensures that the `amount` represents an integer number of millisatoshis.

## Data Part

The data part of a Lightning invoice consists of multiple sections:

1. `timestamp`: seconds-since-1970 (35 bits, big-endian)
1. zero or more tagged parts
1. `signature`: Bitcoin-style signature of above (520 bits)

### Requirements

A writer:
  - MUST set `timestamp` to the number of seconds since Midnight 1 January 1970, UTC in
  big-endian.
  - MUST set `signature` to a valid 512-bit secp256k1 signature of the SHA2 256-bit hash of the
  human-readable part, represented as UTF-8 bytes, concatenated with the
  data part (excluding the signature) with 0 bits appended to pad the
  data to the next byte boundary, with a trailing byte containing
  the recovery ID (0, 1, 2, or 3).

A reader:
  - MUST check that the `signature` is valid (see the `n` tagged field specified below).

### Rationale

`signature` covers an exact number of bytes even though the SHA2
standard actually supports hashing in bit boundaries, because it's not widely
implemented. The recovery ID allows public-key recovery, so the
identity of the payee node can be implied.

### Tagged Fields

Each Tagged Field is of the form:

1. `type` (5 bits)
1. `data_length` (10 bits, big-endian)
1. `data` (`data_length` x 5 bits)

Note that the maximum length of a Tagged Field's `data` is constricted by the maximum value of `data_length`. This is 1023 x 5 bits, or 639 bytes.

Currently defined tagged fields are:

* `p` (1): `data_length` 52. 256-bit SHA256 payment_hash. Preimage of this provides proof of payment.
* `s` (16): `data_length` 52. This 256-bit secret prevents forwarding nodes from probing the payment recipient.
* `d` (13): `data_length` variable. Short description of purpose of payment (UTF-8), e.g. '1 cup of coffee' or 'ナンセンス 1杯'
* `m` (27): `data_length` variable. Additional metadata to attach to the
  payment. Note that the size of this field is limited by the maximum hop payload size. Long metadata fields reduce the maximum route length.
* `n` (19): `data_length` 53. 33-byte public key of the payee node
* `h` (23): `data_length` 52. 256-bit description of purpose of payment (SHA256). This is used to commit to an associated description that is over 639 bytes, but the transport mechanism for the description in that case is transport specific and not defined here.
* `x` (6): `data_length` variable. `expiry` time in seconds (big-endian). Default is 3600 (1 hour) if not specified.
* `c` (24): `data_length` variable. `min_final_cltv_expiry_delta` to use for the last HTLC in the route. Default is 18 if not specified.
* `f` (9): `data_length` variable, depending on version. Fallback on-chain address: for Bitcoin, this starts with a 5-bit `version` and contains a witness program or P2PKH or P2SH address.
* `r` (3): `data_length` variable. One or more entries containing extra routing information for a private route; there may be more than one `r` field
   * `pubkey` (264 bits)
   * `short_channel_id` (64 bits)
   * `fee_base_msat` (32 bits, big-endian)
   * `fee_proportional_millionths` (32 bits, big-endian)
   * `cltv_expiry_delta` (16 bits, big-endian)
* `9` (5): `data_length` variable. One or more 5-bit values containing features
  supported or required for receiving this payment.
  See [Feature Bits](#feature-bits).

#### Requirements

A writer:
  - MUST include exactly one `p` field.
  - MUST include exactly one `s` field.
  - MUST set `payment_hash` to the SHA2 256-bit hash of the `payment_preimage`
  that will be given in return for payment.
  - MUST include either exactly one `d` or exactly one `h` field.
    - if `d` is included:
      - MUST set `d` to a valid UTF-8 string.
      - SHOULD use a complete description of the purpose of the payment.
    - if `h` is included:
      - MUST make the preimage of the hashed description in `h` available
      through some unspecified means.
        - SHOULD use a complete description of the purpose of the payment.
  - MAY include one `x` field.
    - if `x` is included:
      - SHOULD use the minimum `data_length` possible.
  - SHOULD include one `c` field (`min_final_cltv_expiry_delta`).
    - MUST set `c` to the minimum `cltv_expiry` it will accept for the last
    HTLC in the route.
    - SHOULD use the minimum `data_length` possible.
  - MAY include one `n` field. (Otherwise performing signature recovery is required)
    - MUST set `n` to the public key used to create the `signature`.
  - MAY include one or more `f` fields.
    - for Bitcoin payments:
      - MUST set an `f` field to a valid witness version and program, OR to `17`
      followed by a public key hash, OR to `18` followed by a script hash.
  - if there is NOT a public channel associated with its public key:
    - MUST include at least one `r` field.
      - `r` field MUST contain one or more ordered entries, indicating the forward route from
      a public node to the final destination.
        - Note: for each entry, the `pubkey` is the node ID of the start of the channel;
        `short_channel_id` is the short channel ID field to identify the channel; and
        `fee_base_msat`, `fee_proportional_millionths`, and `cltv_expiry_delta` are as
        specified in [BOLT #7](07-routing-gossip.md#the-channel_update-message).
    - MAY include more than one `r` field to provide multiple routing options.
  - if `9` contains non-zero bits:
    - SHOULD use the minimum `data_length` possible.
  - otherwise:
    - MUST omit the `9` field altogether.
  - MUST pad field data to a multiple of 5 bits, using 0s.
  - if a writer offers more than one of any field type, it:
    - MUST specify the most-preferred field first, followed by less-preferred fields, in order.

A reader:
  - MUST skip over unknown fields, OR an `f` field with unknown `version`, OR  `p`, `h`, `s` or
  `n` fields that do NOT have `data_length`s of 52, 52, 52 or 53, respectively.
  - if the `9` field contains unknown _odd_ bits that are non-zero:
    - MUST ignore the bit.
  - if the `9` field contains unknown _even_ bits that are non-zero:
    - MUST fail the payment.
	- SHOULD indicate the unknown bit to the user.
  - MUST check that the SHA2 256-bit hash in the `h` field exactly matches the hashed
  description.
  - if a valid `n` field is provided:
    - MUST use the `n` field to validate the signature instead of performing signature recovery.
  - if there is a valid `s` field:
    - MUST use that as [`payment_secret`](04-onion-routing.md#tlv_payload-payload-format)
  - if the `c` field (`min_final_cltv_expiry_delta`) is not provided:
    - MUST use an expiry delta of at least 18 when making the payment
  - if an `m` field is provided:
    - MUST use that as [`payment_metadata`](04-onion-routing.md#tlv_payload-payload-format)

#### Rationale

The type-and-length format allows future extensions to be backward
compatible. `data_length` is always a multiple of 5 bits, for easy
encoding and decoding. Readers also ignore fields of different length,
for fields that are expected may change.

The `p` field supports the current 256-bit payment hash, but future
specs could add a new variant of different length: in which case,
writers could support both old and new variants, and old readers would
ignore the variant not the correct length.

The `d` field allows inline descriptions, but may be insufficient for
complex orders. Thus, the `h` field allows a summary: though the method
by which the description is served is as-yet unspecified and will
probably be transport dependent. The `h` format could change in the future,
by changing the length, so readers ignore it if it's not 256 bits.

The `m` field allows metadata to be attached to the payment. This supports
applications where the recipient doesn't keep any context for the payment.

The `n` field can be used to explicitly specify the destination node ID,
instead of requiring signature recovery.

The `x` field gives warning as to when a payment will be
refused: mainly to avoid confusion. The default was chosen
to be reasonable for most payments and to allow sufficient time for
on-chain payment, if necessary.

The `c` field allows a way for the destination node to require a specific
minimum CLTV expiry for its incoming HTLC. Destination nodes may use this
to require a higher, more conservative value than the default one (depending
on their fee estimation policy and their sensitivity to time locks). Note
that remote nodes in the route specify their required `cltv_expiry_delta`
in the `channel_update` message, which they can update at all times.

The `f` field allows on-chain fallback; however, this may not make sense for
tiny or time-sensitive payments. It's possible that new
address forms will appear; thus, multiple `f` fields (in an implied
preferred order) help with transition, and `f` fields with versions 19-31
will be ignored by readers.

The `r` field allows limited routing assistance: as specified, it only
allows minimum information to use private channels, however, it could also
assist in future partial-knowledge routing.

#### Security Considerations for Payment Descriptions

Payment descriptions are user-defined and provide a potential avenue for
injection attacks: during the processes of both rendering and persistence.

Payment descriptions should always be sanitized before being displayed in
HTML/Javascript contexts (or any other dynamically interpreted rendering
frameworks). Implementers should be extra perceptive to the possibility of
reflected XSS attacks, when decoding and displaying payment descriptions. Avoid
optimistically rendering the contents of the payment request until all
validation, verification, and sanitization processes have been successfully
completed.

Furthermore, consider using prepared statements, input validation, and/or
escaping, to protect against injection vulnerabilities in persistence
engines that support SQL or other dynamically interpreted querying languages.

* [Stored and Reflected XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [DOM-based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)

Don't be like the school of [Little Bobby Tables](https://xkcd.com/327/).

### Feature Bits

Feature bits allow forward and backward compatibility, and follow the
_it's ok to be odd_ rule.  Features appropriate for use in the `9` field
are marked in [BOLT 9](09-features.md).

The field is big-endian.  The least-significant bit is numbered 0,
which is _even_, and the next most significant bit is numbered 1,
which is _odd_.

#### Requirements

A writer:
  - MUST set the `9` field to a feature vector compliant with the
    [BOLT 9 origin node requirements](09-features.md#requirements).

A reader:
  - if the feature vector does not set all known, transitive feature dependencies:
    - MUST NOT attempt the payment.
  - if the `basic_mpp` feature is offered in the invoice:
    - MAY pay using [Basic multi-part payments](04-onion-routing.md#basic-multi-part-payments).
  - otherwise:
    - MUST NOT use [Basic multi-part payments](04-onion-routing.md#basic-multi-part-payments).


## Payer / Payee Interactions

These are generally defined by the rest of the Lightning BOLT series,
but it's worth noting that [BOLT #4](04-onion-routing.md#requirements-2) specifies that the payee SHOULD
accept up to twice the expected `amount`, so the payer can make
payments harder to track by adding small variations.

The intent is that the payer recovers the payee's node ID from the
signature, and after checking that conditions such as fees,
expiry, and block timeout are acceptable, attempts a payment. It can use `r` fields to
augment its routing information, if necessary to reach the final node.

If the payment succeeds but there is a later dispute, the payer can
prove both the signed offer from the payee and the successful
payment.

### Payer / Payee Requirements

A payer:
  - after the `timestamp` plus `expiry` has passed:
    - SHOULD NOT attempt a payment.
  - otherwise:
    - if a Lightning payment fails:
      - MAY attempt to use the address given in the first `f` field that it
      understands for payment.
  - MAY use the sequence of channels, specified by the `r` field, to route to the payee.
  - SHOULD consider the fee amount and payment timeout before initiating payment.
  - SHOULD use the first `p` field that it did NOT skip as the payment hash.

A payee:
  - after the `timestamp` plus `expiry` has passed:
    - SHOULD NOT accept a payment.

## Implementation

https://github.com/rustyrussell/lightning-payencode

## Examples

NB: all the following examples are signed with `priv_key`=`e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734`.
All invoices contain a `payment_secret`=`1111111111111111111111111111111111111111111111111111111111111111` unless otherwise noted.

> ### Please make a donation of any amount using payment_hash 0001020304050607080900010203040506070809000102030405060708090102 to me @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad
> lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs`: payment secret 1111111111111111111111111111111111111111111111111111111111111111
* `p`: payment hash
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq`: payment hash 0001020304050607080900010203040506070809000102030405060708090102
* `d`: short description
  * `pl`: `data_length` (`p` = 1, `l` = 31; 1 * 32 + 31 == 63)
  * `2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq`: 'Please consider supporting this project'
* `9`: features
  * `qr`: `data_length` (`q` = 0, `r` = 3; 0 * 32 + 3 == 3)
  * `sgq`: b100000100000000
* `357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp`: signature
* `9lfyql`: Bech32 checksum
* Signature breakdown:
  * `8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d81127425e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1` hex of signature data (32-byte r, 32-byte s)
  * `1` (int) recovery flag contained in `signature`
  * `6c6e62630b25fe64500d04444444444444444444444444444444444444444444444444444444444444444021a00008101820283038404800081018202830384048000810182028303840480810343f506c6561736520636f6e736964657220737570706f7274696e6720746869732070726f6a6563740500e08000` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `6daf4d488be41ce7cbb487cab1ef2975e5efcea879b20d421f0ef86b07cbb987` hex of SHA256 of the preimage

> ### Please send $3 for a cup of coffee to the same peer, within one minute
> lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `2500u`: amount (2500 micro-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret...
* `p`: payment hash...
* `d`: short description
  * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
  * `xysxxatsyp3k7enxv4js`: '1 cup coffee'
* `x`: expiry time
  * `qz`: `data_length` (`q` = 0, `z` = 2; 0 * 32 + 2 == 2)
  * `pu`: 60 seconds (`p` = 1, `u` = 28; 1 * 32 + 28 == 60)
* `9`: features
  * `qr`: `data_length` (`q` = 0, `r` = 3; 0 * 32 + 3 == 3)
  * `sgq`: b100000100000000
* `uk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgp`: signature
* `fna3rh`: Bech32 checksum
* Signature breakdown:
  * `e59e3ffbd3945e4334879158d31e89b076dff54f3fa7979ae79df2db9dcaf5896cbfe1a478b8d2307e92c88139464cb7e6ef26e414c4abe33337961ddc5e8ab1` hex of signature data (32-byte r, 32-byte s)
  * `1` (int) recovery flag contained in `signature`
  * `6c6e626332353030750b25fe64500d04444444444444444444444444444444444444444444444444444444444444444021a000081018202830384048000810182028303840480008101820283038404808103414312063757020636f66666565030041e140382000` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `047e24bf270b25d42a56d57b2578faa3a10684641bab817c2851a871cb41dbc0` hex of SHA256 of the preimage

> ### Please send 0.0025 BTC for a cup of nonsense (ナンセンス 1杯) to the same peer, within one minute
> lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `2500u`: amount (2500 micro-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret...
* `p`: payment hash...
* `d`: short description
  * `pq`: `data_length` (`p` = 1, `q` = 0; 1 * 32 + 0 == 32)
  * `uwpc4curk03c9wlrswe78q4eyqc7d8d0`: 'ナンセンス 1杯'
* `x`: expiry time
  * `qz`: `data_length` (`q` = 0, `z` = 2; 0 * 32 + 2 == 2)
  * `pu`: 60 seconds (`p` = 1, `u` = 28; 1 * 32 + 28 == 60)
* `9`: features
  * `qr`: `data_length` (`q` = 0, `r` = 3; 0 * 32 + 3 == 3)
  * `sgq`: b100000100000000
* `htjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp`: signature
* `573dxr`: Bech32 checksum
* Signature breakdown:
  * `bae41ef385e0fc972977c7ea42b12cbd76577d2412919da8a8a22f9577b6507710c0e96dd78c821dea16453037f717f44aa7e3d196ebb18fbb97307dcb7336c3` hex of signature data (32-byte r, 32-byte s)
  * `1` (int) recovery flag contained in `signature`
  * `6c6e626332353030750b25fe64500d04444444444444444444444444444444444444444444444444444444444444444021a000081018202830384048000810182028303840480008101820283038404808103420e3838ae383b3e382bbe383b3e382b92031e69daf30041e14038200` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `f140d992ba419578ba9cfe1af85f92df90a76f442fb5e6e09b1f0582534ba87d` hex of SHA256 of the preimage

> ### Now send $24 for an entire list of things (hashed)
> lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `20m`: amount (20 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret...
* `p`: payment hash...
* `h`: tagged field: hash of description
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `8yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs`: SHA256 of 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon'  (SHA256 hex: `3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1`)
* `9`: features
  * `qr`: `data_length` (`q` = 0, `r` = 3; 0 * 32 + 3 == 3)
  * `sgq`: b100000100000000
* `7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp`: signature
* `7ynn44`: Bech32 checksum
* Signature breakdown:
  * `f67a5f696648fa4fb102e1a07b230e54722f8e024cee71e80b4847ac191da3fb2d2cdb28cc32344d7e9a9cf5c9b6a0ee0582ae46e9938b9c81e344a4dbb5289d` hex of signature data (32-byte r, 32-byte s)
  * `1` (int) recovery flag contained in `signature`
  * `6c6e626332306d0b25fe64500d04444444444444444444444444444444444444444444444444444444444444444021a000081018202830384048000810182028303840480008101820283038404808105c343925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c10280704000` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `e2ffa444e2979edb639fbdaa384638683ba1a5240b14dd7a150e45a04eea261d` hex of SHA256 of the preimage

> ### The same, on testnet, with a fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP
> lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8

Breakdown:

* `lntb`: prefix, Lightning on Bitcoin testnet
* `20m`: amount (20 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `h`: tagged field: hash of description...
* `s`: payment secret...
* `p`: payment hash...
* `f`: tagged field: fallback address
  * `pp`: `data_length` (`p` = 1; 1 * 32 + 1 == 33)
  * `3` = 17, so P2PKH address
  * `x9et2e20v6pu37c5d9vax37wxq72un98`: 160-bit P2PKH address
* `9`: features...
* `dj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgp`: signature
* `ghe9k8`: Bech32 checksum
* Signature breakdown:
  * `6ca95a74dc32e69ced6175b15a5cc56a92bf19f5dace0f134b7d94d464b9f5cf6090a18d48b243f289394d17bdf89466d8e6b37df5981f696bc3dd5986e1bee1` hex of signature data (32-byte r, 32-byte s)
  * `1` (int) recovery flag contained in `signature`
  * `6c6e746232306d0b25fe64500d044444444444444444444444444444444444444444444444444444444444444442e1a1c92db7b3f161a001b7689049eea2701b46f8db7513629edf2408fac7eaedc608043400010203040506070809000102030405060708090001020304050607080901020484313172b5654f6683c8fb146959d347ce303cae4ca728070400` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `33bc6642a336097c74299cadfdfdd2e4884a555cf1b4fda72b095382d473d795` hex of SHA256 of the preimage

> ### On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with extra routing info to go via nodes 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255 then 039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255
> lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `20m`: amount (20 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret...
* `p`: payment hash...
* `h`: tagged field: hash of description...
* `f`: tagged field: fallback address
  * `pp`: `data_length` (`p` = 1; 1 * 32 + 1 == 33)
  * `3` = 17, so P2PKH address
  * `qjmp7lwpagxun9pygexvgpjdc4jdj85f`: 160-bit P2PKH address
* `r`: tagged field: route information
  * `9y`: `data_length` (`9` = 5, `y` = 4; 5 * 32 + 4 == 164)
    * `q20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq`:
      * pubkey: `029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255`
      * `short_channel_id`: 66051x263430x1800
      * `fee_base_msat`: 1 millisatoshi
      * `fee_proportional_millionths`: 20
      * `cltv_expiry_delta`: 3
      * pubkey: `039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255`
      * `short_channel_id`: 197637x395016x2314
      * `fee_base_msat`: 2 millisatoshi
      * `fee_proportional_millionths`: 30
      * `cltv_expiry_delta`: 4
* `9`: features...
* `dfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq`: signature
* `76cqw0`: Bech32 checksum
* Signature breakdown:
  * `6a6586db4e8f6d40e3a5bb92e4df5110c627e9ce493af237e20a046b4e86ea200178c59564ecf892f33a9558bf041b6ad2cb8292d7a6c351fbb7f2ae2d16b54e` hex of signature data (32-byte r, 32-byte s)
  * `0` (int) recovery flag contained in `signature`
  * `6c6e626332306d0b25fe64500d04444444444444444444444444444444444444444444444444444444444444444021a000081018202830384048000810182028303840480008101820283038404808105c343925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c104843104b61f7dc1ea0dc99424464cc4064dc564d91e891948053c07520370aa69fe3d258878e8863ef9ce408c0c1f9ef52b86fc291ef18ee4aa020406080a0c0e1000000002000000280006073c07520370aa69fe3d258878e8863ef9ce408c0c1f9ef52b86fc291ef18ee4aa06080a0c0e101214000000040000003c00080500e08000` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `b342d4655b984e53f405fe4d872fb9b7cf54ba538fcd170ed4a5906a9f535064` hex of SHA256 of the preimage

> ### On mainnet, with fallback (P2SH) address 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
> lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z99qrsgqz6qsgww34xlatfj6e3sngrwfy3ytkt29d2qttr8qz2mnedfqysuqypgqex4haa2h8fx3wnypranf3pdwyluftwe680jjcfp438u82xqphf75ym

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `20m`: amount (20 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret...
* `h`: tagged field: hash of description...
* `p`: payment hash...
* `f`: tagged field: fallback address
  * `pp`: `data_length` (`p` = 1; 1 * 32 + 1 == 33)
  * `j` = 18, so P2SH address
  * `3a24vwu6r8ejrss3axul8rxldph2q7z9`:  160-bit P2SH address
* `9`: features...
* `z6qsgww34xlatfj6e3sngrwfy3ytkt29d2qttr8qz2mnedfqysuqypgqex4haa2h8fx3wnypranf3pdwyluftwe680jjcfp438u82xqp`: signature
* `hf75ym`: Bech32 checksum
* Signature breakdown:
  * `16810439d1a9bfd5a65acc61340dc92448bb2d456a80b58ce012b73cb5202438020500c9ab7ef5573a4d174c811f669885ae27f895bb3a3be52c243589f87518` hex of signature data (32-byte r, 32-byte s)
  * `1` (int) recovery flag contained in `signature`
  * `6c6e626332306d0b25fe64500d044444444444444444444444444444444444444444444444444444444444444442e1a1c92db7b3f161a001b7689049eea2701b46f8db7513629edf2408fac7eaedc608043400010203040506070809000102030405060708090001020304050607080901020484328f55563b9a19f321c211e9b9f38cdf686ea0784528070400` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `9e93321a775f7dffdca03e61d1ac6e0e356cc63cecd3835271200c1e5b499d29` hex of SHA256 of the preimage

> ### On mainnet, with fallback (P2WPKH) address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
> lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7k9qrsgqt29a0wturnys2hhxpner2e3plp6jyj8qx7548zr2z7ptgjjc7hljm98xhjym0dg52sdrvqamxdezkmqg4gdrvwwnf0kv2jdfnl4xatsqmrnsse

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `20m`: amount (20 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret...
* `h`: tagged field: hash of description...
* `p`: payment hash...
* `f`: tagged field: fallback address
  * `pp`: `data_length` (`p` = 1; 1 * 32 + 1 == 33)
  * `q`: 0, so witness version 0
  * `w508d6qejxtdg4y5r3zarvary0c5xw7k`: 160 bits = P2WPKH.
* `9`: features...
* `t29a0wturnys2hhxpner2e3plp6jyj8qx7548zr2z7ptgjjc7hljm98xhjym0dg52sdrvqamxdezkmqg4gdrvwwnf0kv2jdfnl4xatsq`: signature
* `mrnsse`: Bech32 checksum
* Signature breakdown:
  * `5a8bd7b97c1cc9055ee60cf2356621f8752248e037a953886a1782b44a58f5ff2d94e6bc89b7b514541a3603bb33722b6c08aa1a3639d34becc549a99fea6eae` hex of signature data (32-byte r, 32-byte s)
  * `0` (int) recovery flag contained in `signature`
  * `6c6e626332306d0b25fe64500d044444444444444444444444444444444444444444444444444444444444444442e1a1c92db7b3f161a001b7689049eea2701b46f8db7513629edf2408fac7eaedc60804340001020304050607080900010203040506070809000102030405060708090102048420751e76e8199196d454941c45d1b3a323f1433bd628070400` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `44fbec32cdac99a1a3cd638ec507dad633a1e5bba514832fd3471e663a157f7b` hex of SHA256 of the preimage

> ### On mainnet, with fallback (P2WSH) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
> lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `20m`: amount (20 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `s`: payment secret...
* `h`: tagged field: hash of description...
* `p`: payment hash...
* `f`: tagged field: fallback address
  * `p4`: `data_length` (`p` = 1, `4` = 21; 1 * 32 + 21 == 53)
  * `q`: 0, so witness version 0
  * `rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q`: 260 bits = P2WSH.
* `9`: features...
* `9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp`: signature
* `9yrrwc`: Bech32 checksum
* Signature breakdown:
  * `2b3ec248f80301a421817369194f012cdd8af8df1c279981420f9e901e20fa3309d791e11355e609b59ce4a220852a0cd55ab862b1785a83b206c90fa74d01c8` hex of signature data (32-byte r, 32-byte s)
  * `1` (int) recovery flag contained in `signature`
  * `6c6e626332306d0b25fe64500d044444444444444444444444444444444444444444444444444444444444444442e1a1c92db7b3f161a001b7689049eea2701b46f8db7513629edf2408fac7eaedc608043400010203040506070809000102030405060708090001020304050607080901020486a01863143c14c5166804bd19203356da136c985678cd4d27a1b8c63296049032620280704000` hex of data for signing (prefix + data after separator up to the start of the signature)
  * `865a2cc6730e1eeeacd30e6da8e9ab0e9115828d27953ec0c0f985db05da5027` hex of SHA256 of the preimage

> ### Please send 0.00967878534 BTC for a list of items within one week, amount in pico-BTC
> lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz

Breakdown:

* `lnbc`: prefix, Lightning on bitcoin mainnet
* `9678785340p`: amount (9678785340 pico-bitcoin = 967878534 milli satoshi)
* `1`: Bech32 separator
* `pwmna7l`: timestamp (1572468703)
* `s`: payment secret...
* `p`: payment hash
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0s`: payment hash 462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f
* `d`: short description
  * `8d`: `data_length` (`8` = 7, `d` = 13; 7 * 32 + 13 == 237)
  * `gfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khx`: 'Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, \"Back In My Day\" Sticker x 2, \"I Got Lightning Working\" Sticker x 2 and 1 more items'
* `x`: expiry time
  * `qy`: `data_length` (`q` = 0, `y` = 2; 0 * 32 + 4 == 4)
  * `jw5q`: 604800 seconds (`j` = 18, `w` = 14, `5` = 20, `q` = 0; 18 * 32^3 + 14 * 32^2 + 20 * 32 + 0 == 604800)
* `c`: `min_final_cltv_expiry_delta`
  * `qp`: `data_length` (`q` = 0, `p` = 1; 0 * 32 + 1 == 1)
  * `2`: min_final_cltv_expiry_delta = 10
* `r`: tagged field: route information
  * `zj`: `data_length` (`z` = 2, `j` = 18; 2 * 32 + 18 == 82)
  * `q0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q`:
    * pubkey: 03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7
    * short_channel_id: 589390x3312x1
    * fee_base_msat = 1000
    * fee_proportional_millionths = 2500
    * cltv_expiry_delta = 40
* `9`: features...
* `rvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqp`: signature
* `u2v9wz`: Bech32 checksum

> ### Please send $30 for coffee beans to the same peer, which supports features 8, 14 and 99, using secret 0x1111111111111111111111111111111111111111111111111111111111111111
> lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgpz3uapa

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `25m`: amount (25 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `p`: payment hash...
* `d`: short description
  * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
  * `vdhkven9v5sxyetpdees`: 'coffee beans'
* `s`: payment secret
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs`: 0x1111111111111111111111111111111111111111111111111111111111111111
* `9`: features
  * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
  * `sqqqqqqqqqqqqqqqqsgq`: b1000....00000100000100000000
* `2a25dxl5hrntdtn6zvydt7d66hyzsyhqs4wdynavys42xgl6sgx9c4g7me86a27t07mdtfry458rtjr0v92cnmswpsjscgt2vcse3sgp`: signature
* `z3uapa`: Bech32 checksum

> ### Same, but all upper case.
> LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQQSGQ2A25DXL5HRNTDTN6ZVYDT7D66HYZSYHQS4WDYNAVYS42XGL6SGX9C4G7ME86A27T07MDTFRY458RTJR0V92CNMSWPSJSCGT2VCSE3SGPZ3UAPA

> ### Same, but including fields which must be ignored.
> lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcqzn8z9x

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `25m`: amount (25 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `p`: payment hash...
* `d`: short description
  * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
  * `vdhkven9v5sxyetpdees`: 'coffee beans'
* `s`: payment secret
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs`: 0x1111111111111111111111111111111111111111111111111111111111111111
* `9`: features
  * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
  * `sqqqqqqqqqqqqqqqqsgq`: b1000....00000100000100000000
* `2`: unknown field
  * `qr`: `data_length` (`q` = 0, `r` = 3; 0 * 32 + 3 == 3)
  * `qqq`: zeroes
* `f`: tagged field: fallback address
  * `pp`: `data_length` (`p` = 1, `p` = 1; 1 * 32 + 1 == 33)
  * `nqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`: fallback address type 19 (ignored)
* `p`: payment hash
  * `pn`: `data_length` (`p` = 1, `n` = 19; 1 * 32 + 19 == 51) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `p`: payment hash
  * `p4`: `data_length` (`p` = 1, `4` = 21; 1 * 32 + 21 == 53) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `h`: hash of description
  * `pn`: `data_length` (`p` = 1, `n` = 19; 1 * 32 + 19 == 51) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `h`: hash of description
  * `p4`: `data_length` (`p` = 1, `4` = 21; 1 * 32 + 21 == 53) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `s`: payment secret
  * `pn`: `data_length` (`p` = 1, `n` = 19; 1 * 32 + 19 == 51) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `s`: payment secret
  * `p4`: `data_length` (`p` = 1, `4` = 21; 1 * 32 + 21 == 53) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `n`: node id
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `n`: node id
  * `pk`: `data_length` (`p` = 1, `k` = 22; 1 * 32 + 22 == 54) (ignored)
  * `qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq`
* `z599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcq`: signature
* `zn8z9x`: Bech32 checksum

> ### Please send 0.01 BTC with payment metadata 0x01fafaf0
> lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `10m`: amount (10 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `p`: payment hash
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq`: payment hash 0001020304050607080900010203040506070809000102030405060708090102
* `d`: short description
  * `p9`: `data_length` (`p` = 1, `9` = 5; 1 * 32 + 5 == 37)
  * `wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2`: 'payment metadata inside'
* `m`: metadata
  * `q8`: `data_length` (`q` = 0, `8` = 7; 0 * 32 + 7 == 7)
  * `q8a04uq`: 0x01fafaf0
* `s`: payment secret
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs`: 0x1111111111111111111111111111111111111111111111111111111111111111
* `9`: features
  * `q2`: `data_length` (`q` = 0, `2` = 10; 0 * 32 + 10 == 10)
  * `gqqqqqqsgq`: [b01000000000000000000000000000000000100000100000000] = 8 + 14 + 48
* `7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqp`: signature
* `d05wjc`: Bech32 checksum

## Examples of Invalid Invoices

> ### Same, but adding invalid unknown feature 100
> lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q4psqqqqqqqqqqqqqqqqsgqtqyx5vggfcsll4wu246hz02kp85x4katwsk9639we5n5yngc3yhqkm35jnjw4len8vrnqnf5ejh0mzj9n3vz2px97evektfm2l6wqccp3y7372

Breakdown:

* `lnbc`: prefix, Lightning on Bitcoin mainnet
* `25m`: amount (25 milli-bitcoin)
* `1`: Bech32 separator
* `pvjluez`: timestamp (1496314658)
* `p`: payment hash...
* `d`: short description
  * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
  * `vdhkven9v5sxyetpdees`: 'coffee beans'
* `s`: payment secret
  * `p5`: `data_length` (`p` = 1, `5` = 20; 1 * 32 + 20 == 52)
  * `zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs`: 0x1111111111111111111111111111111111111111111111111111111111111111
* `9`: features
  * `q4`: `data_length` (`q` = 0, `4` = 21; 0 * 32 + 21 == 21)
  * `psqqqqqqqqqqqqqqqqsgq`: b000011000....00000100000100000000
* `tqyx5vggfcsll4wu246hz02kp85x4katwsk9639we5n5yngc3yhqkm35jnjw4len8vrnqnf5ejh0mzj9n3vz2px97evektfm2l6wqccp`: signature
* `3y7372`: Bech32 checksum

> ### Bech32 checksum is invalid.
> lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt

> ### Malformed bech32 string (no 1)
> pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny

> ### Malformed bech32 string (mixed case)
> LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny

> ### Signature is not recoverable.
> lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqwgt7mcn5yqw3yx0w94pswkpq6j9uh6xfqqqtsk4tnarugeektd4hg5975x9am52rz4qskukxdmjemg92vvqz8nvmsye63r5ykel43pgz7zq0g2

> ### String is too short.
> lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh

> ### Invalid multiplier
> lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j

> ### Invalid sub-millisatoshi precision.
> lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x

## Authors

[ FIXME: ]

![Creative Commons License](https://i.creativecommons.org/l/by/4.0/88x31.png "License CC-BY")
<br>
This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
