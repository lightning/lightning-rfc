# BOLT #12: Flexible Protocol for Lightning Payments

## Table of Contents

  * [Limitations of BOLT 11](#limitations-of-bolt-11)
  * [Payment Flow Scenarios](#payment-flow-scenarios)
  * [Encoding](#encoding)
  * [Signature calculation](#signature-calculation)
  * [Offers](#offers)
  * [Invoice Requests](#invoice-requests)
  * [Invoices](#invoices)
  * [Invoice Errors](#invoice-errors)

## Limitations of BOLT 11

The BOLT 11 invoice format has proven popular but has several
limitations:

1. The entangling of bech32 encoding makes it awkward to send
   in other forms (e.g. inside the lightning network itself).
2. The signature applying to the entire invoice makes it impossible
   to prove an invoice without revealing its entirety.
3. Fields cannot generally be extracted for external use: the `h`
   field was a boutique extraction of the `d` field only.
4. The lack of the 'it's OK to be odd' rule makes backward compatibility
   harder.
5. The 'human-readable' idea of separating amounts proved fraught:
   `p` was often mishandled, and amounts in pico-bitcoin are harder
   than the modern satoshi-based counting.
6. Developers found the bech32 encoding to have an issue with extensions,
   which means we want to replace or discard it anyway.
7. The `payment_secret` designed to prevent probing by other nodes in
   the path was only useful if the invoice remained private between the
   payer and payee.
8. Invoices must be given per user and are actively dangerous if two
   payment attempts are made for the same user.


## Payment Flow Scenarios

Here we use "user" as shorthand for the individual user's lightning
node and "merchant" as the shorthand for the node of someone who is
selling or has sold something.

There are two basic payment flows supported by BOLT 12:

The general user-pays-merchant flow is:
1. A merchant publishes an *offer*, such as on a web page or a QR code.
2. Every user requests a unique *invoice* over the lightning network
   using an *invoice_request* message, which contains the offer fields.
3. The merchant replies with the *invoice*.
4. The user makes a payment to the merchant as indicated by the invoice.

The merchant-pays-user flow (e.g. ATM or refund):
1. The merchant publishes an *invoice_request* which includes an amount it wishes to send to the user.
2. The user sends an *invoice* over the lightning network for the amount in the
   *invoice_request*, using a (possibly temporary) *invoice_node_id*.
3. The merchant confirms the *invoice_node_id* to ensure it's about to pay the correct
   person, and makes a payment to the invoice.

### Payment Proofs and Payer Proofs

Note that the normal lightning "proof of payment" can only demonstrate that an
invoice was paid (by showing the preimage of the `payment_hash`), not who paid
it.  The merchant can claim an invoice was paid, and once revealed, anyone can
claim they paid the invoice, too.[1]

Providing a key in *invoice_request* allows the payer to prove that they were the one
to request the invoice.  In addition, the Merkle construction of the BOLT 12
invoice signature allows the user to reveal invoice fields in case
of a dispute selectively.

## Encoding

Each of the forms documented here are in
[TLV](01-messaging.md#type-length-value-format) format.

The supported ASCII encoding is the human-readable prefix, followed by a
`1`, followed by a bech32-style data string of the TLVs in order,
optionally interspersed with `+` (for indicating additional data is to
come).  There is no checksum, unlike bech32m.

### Requirements

Writers of a bolt12 string:
- MUST either use all lowercase or all UPPERCASE.
- SHOULD use uppercase for QR codes.
- SHOULD use lower case otherwise.
- MAY use `+`, optionally followed by whitespace, to separate large bolt12 strings.

Readers of a bolt12 string:
- MUST handle strings which are all lowercase, or all uppercase.
- if it encounters a `+` followed by zero or more whitespace characters between 
  two bech32 characters:
  - MUST remove the `+` and whitespace.

### Rationale

The use of bech32 is arbitrary but already exists in the bitcoin
world.  We currently omit the six-character trailing checksum: QR
codes have their own checksums anyway, and errors don't result in loss
of funds, simply an invalid offer (or inability to parse).

The use of `+` (which is ignored) allows use over limited
text fields like Twitter:

```
lno1xxxxxxxx+

yyyyyyyyyyyy+

zzzzz
```

See [format-string-test.json](bolt12/format-string-test.json).

## Signature Calculation

All signatures are created as per
[BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
and tagged as recommended there.  Thus we define H(`tag`,`msg`) as
SHA256(SHA256(`tag`) || SHA256(`tag`) || `msg`), and SIG(`tag`,`msg`,`key`)
as the signature of H(`tag`,`msg`) using `key`.

Each form is signed using one or more *signature TLV elements*: TLV
types 240 through 1000 (inclusive).  For these,
the tag is "lightning" || `messagename` || `fieldname`, and `msg` is the
Merkle-root; "lightning" is the literal 9-byte ASCII string,
`messagename` is the name of the TLV stream being signed (i.e. "invoice_request" or "invoice") and the `fieldname` is the TLV field containing the
signature (e.g. "signature").

The formulation of the Merkle tree is similar to that proposed in
[BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki),
with each TLV leaf paired with a nonce leaf to avoid
revealing adjacent nodes in proofs.

The Merkle tree's leaves are, in TLV-ascending order for each tlv:
1. The H("LnLeaf",tlv).
2. The H("LnNonce"||first-tlv,tlv-type) where first-tlv is the numerically-first TLV entry in the stream, and tlv-type is the "type" field (1-9 bytes) of the current tlv.

The Merkle tree inner nodes are H("LnBranch", lesser-SHA256||greater-SHA256);
this ordering means proofs are more compact since left/right is
inherently determined.

If there is not exactly a power of 2 leaves, then the tree depth will
be uneven, with the deepest tree on the lowest-order leaves.

e.g. consider the encoding of an `invoice` `signature` with TLVs TLV0, TLV1, and TLV2 (of types 0, 1, and 2 respectively):

```
L1=H("LnLeaf",TLV0)
L1nonce=H("LnNonce"||TLV0,0)
L2=H("LnLeaf",TLV1)
L2nonce=H("LnNonce"||TLV0,1)
L3=H("LnLeaf",TLV2)
L3nonce=H("LnNonce"||TLV0,2)

Assume L1 < L1nonce, L2 > L2nonce and L3 > L3nonce.

   L1    L1nonce                      L2   L2nonce                L3   L3nonce
     \   /                             \   /                       \   /
      v v                               v v                         v v
L1A=H("LnBranch",L1||L1nonce) L2A=H("LnBranch",L2nonce||L2)  L3A=H("LnBranch",L3nonce||L3)
                 
Assume L1A < L2A:

       L1A   L2A                                 L3A=H("LnBranch",L3nonce||L3)
         \   /                                    |
          v v                                     v
  L1A2A=H("LnBranch",L1A||L2A)                   L3A=H("LnBranch",L3nonce||L3)
  
Assume L1A2A > L3A:

  L1A2A=H("LnBranch",L1A||L2A)          L3A
                          \            /
                           v          v
                Root=H("LnBranch",L3A||L1A2A)

Signature = SIG("lightninginvoicesignature", Root, nodekey)
```

## Offers

Offers are a precursor to an invoice_request: readers will request an invoice
(or multiple) based on the offer.  An offer can be much longer-lived than a
particular invoice, so it has some different characteristics; in particular the amount can be in a non-lightning currency.  It's
also designed for compactness to fit inside a QR code easily.

Note that the non-signature TLV elements get mirrored into
invoice_request and invoice messages, so they each have specific and
distinct TLV ranges.

The human-readable prefix for offers is `lno`.

### TLV Fields for Offers

1. `tlv_stream`: `offer`
2. types:
    1. type: 2 (`offer_chains`)
    2. data:
        * [`...*chain_hash`:`chains`]
    1. type: 4 (`offer_metadata`)
    2. data:
        * [`...*byte`:`data`]
    1. type: 6 (`offer_currency`)
    2. data:
        * [`...*utf8`:`iso4217`]
    1. type: 8 (`offer_amount`)
    2. data:
        * [`tu64`:`amount`]
    1. type: 10 (`offer_description`)
    2. data:
        * [`...*utf8`:`description`]
    1. type: 12 (`offer_features`)
    2. data:
        * [`...*byte`:`features`]
    1. type: 14 (`offer_absolute_expiry`)
    2. data:
        * [`tu64`:`seconds_from_epoch`]
    1. type: 16 (`offer_paths`)
    2. data:
        * [`...*blinded_path`:`paths`]
    1. type: 18 (`offer_issuer`)
    2. data:
        * [`...*utf8`:`issuer`]
    1. type: 20 (`offer_quantity_max`)
    2. data:
        * [`tu64`:`max`]
    1. type: 22 (`offer_issuer_id`)
    2. data:
        * [`point`:`id`]

### Requirements For Offers

A writer of an offer:
  - MUST NOT set any TLV fields outside the inclusive ranges: 1 to 79 and 1000000000 to 1999999999.
  - if the chain for the invoice is not solely bitcoin:
    - MUST specify `offer_chains` the offer is valid for.
  - otherwise:
    - SHOULD omit `offer_chains`, implying that bitcoin is only chain.
  - if a specific minimum `offer_amount` is required for successful payment:
    - MUST set `offer_amount` to the amount expected (per item).
    - if the currency for `offer_amount` is that of all entries in `chains`:
      - MUST specify `offer_amount` in multiples of the minimum lightning-payable unit
        (e.g. milli-satoshis for bitcoin).
    - otherwise:
      - MUST specify `offer_currency` `iso4217` as an ISO 4217 three-letter code.
      - MUST specify `offer_amount` in the currency unit adjusted by the ISO 4217
        exponent (e.g. USD cents).
    - MUST set `offer_description` to a complete description of the purpose
      of the payment.
  - otherwise:
    - MUST NOT set `offer_amount`
    - MUST NOT set `offer_currency`
    - MAY set `offer_description`
  - MAY set `offer_metadata` for its own use.
  - if it supports bolt12 offer features:
    - MUST set `offer_features`.`features` to the bitmap of bolt12 features.
  - if the offer expires:
    - MUST set `offer_absolute_expiry` `seconds_from_epoch` to the number of seconds
      after midnight 1 January 1970, UTC that invoice_request should not be
      attempted.
  - if it is connected only by private channels:
    - MUST include `offer_paths` containing one or more paths to the node from
      publicly reachable nodes.
  - otherwise:
    - MAY include `offer_paths`.
  - if it includes `offer_paths`:
    - MAY set `offer_issuer_id`.
  - otherwise:
     - MUST set `offer_issuer_id` to the node's public key to request the invoice from.
  - if it sets `offer_issuer`:
    - SHOULD set it to identify the issuer of the invoice clearly.
    - if it includes a domain name:
      - SHOULD begin it with either user@domain or domain
      - MAY follow with a space and more text
  - if it can supply more than one item for a single invoice:
    - if the maximum quantity is known:
      - MUST set that maximum in `offer_quantity_max`.
      - MUST NOT set `offer_quantity_max` to 0.
    - otherwise:
      - MUST set `offer_quantity_max` to 0.
  - otherwise:
    - MUST NOT set `offer_quantity_max`.

A reader of an offer:
  - if the offer contains any TLV fields outside the inclusive ranges: 1 to 79 and 1000000000 to 1999999999:
    - MUST NOT respond to the offer.
  - if `offer_features` contains unknown _odd_ bits that are non-zero:
    - MUST ignore the bit.
  - if `offer_features` contains unknown _even_ bits that are non-zero:
    - MUST NOT respond to the offer.
    - SHOULD indicate the unknown bit to the user.
  - if `offer_chains` is not set:
    - if the node does not accept bitcoin invoices:
      - MUST NOT respond to the offer
  - otherwise: (`offer_chains` is set):
    - if the node does not accept invoices for any of the `chains`:
      - MUST NOT respond to the offer
  - if `offer_amount` is set and `offer_description` is not set:
    - MUST NOT respond to the offer.
  - if `offer_currency` is set and `offer_amount` is not set:
    - MUST NOT respond to the offer.
  - if neither `offer_issuer_id` nor `offer_paths` are set:
    - MUST NOT respond to the offer.
  - if `num_hops` is 0 in any `blinded_path` in `offer_paths`:
    - MUST NOT respond to the offer.
  - if it uses `offer_amount` to provide the user with a cost estimate:
    - MUST take into account the currency units for `offer_amount`:
      - `offer_currency` field if set
      - otherwise, the minimum lightning-payable unit (e.g. milli-satoshis for
        bitcoin).
    - MUST warn the user if the received `invoice_amount` differs significantly
        from that estimate.
  - if the current time is after `offer_absolute_expiry`:
    - MUST NOT respond to the offer.
  - if it chooses to send an invoice request, it sends an onion message:
    - if `offer_paths` is set:
      - MUST send the onion message via any path in `offer_paths` to the final `onion_msg_hop`.`blinded_node_id` in that path
    - otherwise:
      - MUST send the onion message to `offer_issuer_id`
    - MAY send more than one invoice request onion message at once.

### Rationale

The entire offer is reflected in the invoice_request, both for
completeness (so all information will be returned in the invoice), and
so that the offer node can be stateless.  This makes `offer_metadata`
particularly useful, since it can contain an authentication cookie to
validate the other fields.

Because offer fields are copied into the invoice request (and then the invoice),
they require distinct ranges.  The range 1-79 is the normal range, with another
billion for self-assigning experimental ranges.

A signature is unnecessary, and makes for a longer string (potentially
limiting QR code use on low-end cameras); if the offer has an error, no
invoice will be given since the request includes all the non-signature 
fields.

The `offer_issuer_id` can be omitted for brevity, if `offer_paths` is set, as each of the final `blinded_node_id` in the paths can serve as a valid public key for the destination.

Because `offer_amount` can be in a different currency (using the `offer_currency` field) it is merely a guide: the issuer will convert it into a number of millisatoshis for `invoice_amount` at the time they generate an invoice, or the invoice request can specify the exact amount in `invreq_amount`, but the issuer may then reject it if it disagrees.

`offer_quantity_max` is allowed to be 1, which seems useless, but
useful in a system which bases it on available stock.  It would be
painful to have to special-case the "only one left" offer generation.

Offers can be used to simply send money without expecting anything in return (tips, kudos, donations, etc), which means the description field is optional (the `offer_issuer` field is very useful for this case!); if you are charging for something specific, the description is vital for the user to know what it was they paid for.

## Invoice Requests

Invoice Requests are a request for an invoice; the human-readable prefix for
invoice requests is `lnr`.

There are two similar-looking uses for invoice requests, which are
almost identical from a workflow perspective, but are quite different
from a user's point of view.

One is a response to an offer; this contains the `offer_issuer_id` or `offer_paths` and
all other offer details, and is generally received over an onion
message: if it's valid and refers to a known offer, the response is
generally to reply with an `invoice` using the `reply_path` field of
the onion message.

The second case is publishing an invoice request without an offer,
such as via QR code.  It contains neither `offer_issuer_id` nor `offer_paths`, setting the
`invreq_payer_id` (and possibly `invreq_paths`) instead, as it in the one paying: the
other offer fields are filled by the creator of the `invoice_request`,
forming a kind of offer-to-send-money.

Note: the `invreq_metadata` is numbered 0 (not in the
80-159 range for other invreq fields) making it the "numerically-first TLV entry"
for [Signature Calculation](#signature-calculation).  This ensures that merkle
leaves are unguessable, allowing a future compact representation to hide fields
while still allowing signature validation.


### TLV Fields for `invoice_request`

1. `tlv_stream`: `invoice_request`
2. types:
    1. type: 0 (`invreq_metadata`)
    2. data:
        * [`...*byte`:`blob`]
    1. type: 2 (`offer_chains`)
    2. data:
        * [`...*chain_hash`:`chains`]
    1. type: 4 (`offer_metadata`)
    2. data:
        * [`...*byte`:`data`]
    1. type: 6 (`offer_currency`)
    2. data:
        * [`...*utf8`:`iso4217`]
    1. type: 8 (`offer_amount`)
    2. data:
        * [`tu64`:`amount`]
    1. type: 10 (`offer_description`)
    2. data:
        * [`...*utf8`:`description`]
    1. type: 12 (`offer_features`)
    2. data:
        * [`...*byte`:`features`]
    1. type: 14 (`offer_absolute_expiry`)
    2. data:
        * [`tu64`:`seconds_from_epoch`]
    1. type: 16 (`offer_paths`)
    2. data:
        * [`...*blinded_path`:`paths`]
    1. type: 18 (`offer_issuer`)
    2. data:
        * [`...*utf8`:`issuer`]
    1. type: 20 (`offer_quantity_max`)
    2. data:
        * [`tu64`:`max`]
    1. type: 22 (`offer_issuer_id`)
    2. data:
        * [`point`:`id`]
    1. type: 80 (`invreq_chain`)
    2. data:
        * [`chain_hash`:`chain`]
    1. type: 82 (`invreq_amount`)
    2. data:
        * [`tu64`:`msat`]
    1. type: 84 (`invreq_features`)
    2. data:
        * [`...*byte`:`features`]
    1. type: 86 (`invreq_quantity`)
    2. data:
        * [`tu64`:`quantity`]
    1. type: 88 (`invreq_payer_id`)
    2. data:
        * [`point`:`key`]
    1. type: 89 (`invreq_payer_note`)
    2. data:
        * [`...*utf8`:`note`]
    1. type: 90 (`invreq_paths`)
    2. data:
        * [`...*blinded_path`:`paths`]
    1. type: 91 (`invreq_bip_353_name`)
    2. data:
        * [`u8`:`name_len`]
        * [`name_len*byte`:`name`]
        * [`u8`:`domain_len`]
        * [`domain_len*byte`:`domain`]
    1. type: 240 (`signature`)
    2. data:
        * [`bip340sig`:`sig`]

### Requirements for Invoice Requests

The writer:
  - if it is responding to an offer:
    - MUST copy all fields from the offer (including unknown fields).
    - if `offer_chains` is set:
      - MUST set `invreq_chain` to one of `offer_chains` unless that chain is bitcoin, in which case it SHOULD omit `invreq_chain`.
    - otherwise:
      - if it sets `invreq_chain` it MUST set it to bitcoin.
    - MUST set `signature`.`sig` as detailed in [Signature Calculation](#signature-calculation) using the `invreq_payer_id`.
    - if `offer_amount` is not present:
      - MUST specify `invreq_amount`.
    - otherwise:
      - MAY omit `invreq_amount`.
      - if it sets `invreq_amount`:
        - MUST specify `invreq_amount`.`msat` as greater or equal to amount expected by `offer_amount` (and, if present, `offer_currency` and `invreq_quantity`).
    - MUST set `invreq_payer_id` to a transient public key.
    - MUST remember the secret key corresponding to `invreq_payer_id`.
    - if `offer_quantity_max` is present:
      - MUST set `invreq_quantity` to greater than zero.
      - if `offer_quantity_max` is non-zero:
        - MUST set `invreq_quantity` less than or equal to `offer_quantity_max`.
    - otherwise:
      - MUST NOT set `invreq_quantity`
  - otherwise (not responding to an offer):
    - MUST set `offer_description` to a complete description of the purpose of the payment.
    - MUST set (or not set) `offer_absolute_expiry` and `offer_issuer` as it would for an offer.
    - MUST set `invreq_payer_id` (as it would set `offer_issuer_id` for an offer).
    - MUST set `invreq_paths` as it would set (or not set) `offer_paths` for an offer.
    - MUST NOT include `signature`, `offer_metadata`, `offer_chains`, `offer_amount`, `offer_currency`, `offer_features`, `offer_quantity_max`, `offer_paths` or `offer_issuer_id`
    - if the chain for the invoice is not solely bitcoin:
      - MUST specify `invreq_chain` the offer is valid for.
    - MUST set `invreq_amount`.
  - MUST NOT set any non-signature TLV fields outside the inclusive ranges: 0 to 159 and 1000000000 to 2999999999
  - MUST set `invreq_metadata` to an unpredictable series of bytes.
  - if it sets `invreq_amount`:
    - MUST set `msat` in multiples of the minimum lightning-payable unit
        (e.g. milli-satoshis for bitcoin) for `invreq_chain` (or for bitcoin, if there is no `invreq_chain`).
  - if it supports bolt12 invoice request features:
    - MUST set `invreq_features`.`features` to the bitmap of features.
  - if it received the offer from which it constructed this `invoice_request` using BIP 353 resolution:
    - MUST include `invreq_bip_353_name` with,
      - `name` set to the post-₿, pre-@ part of the BIP 353 HRN,
      - `domain` set to the post-@ part of the BIP 353 HRN.

The reader:
  - MUST reject the invoice request if `invreq_payer_id` or `invreq_metadata` are not present.
  - MUST reject the invoice request if any non-signature TLV fields are outside the inclusive ranges: 0 to 159 and 1000000000 to 2999999999
  - if `invreq_features` contains unknown _odd_ bits that are non-zero:
    - MUST ignore the bit.
  - if `invreq_features` contains unknown _even_ bits that are non-zero:
    - MUST reject the invoice request.
  - MUST reject the invoice request if `signature` is not correct as detailed in [Signature Calculation](#signature-calculation) using the `invreq_payer_id`.
  - if `num_hops` is 0 in any `blinded_path` in `invreq_paths`:
    - MUST reject the invoice request.
  - if `offer_issuer_id` is present, and `invreq_metadata` is identical to a previous `invoice_request`:
    - MAY simply reply with the previous invoice.
  - otherwise:
    - MUST NOT reply with a previous invoice.
  - if `offer_issuer_id` or `offer_paths` are present (response to an offer):
    - MUST reject the invoice request if the offer fields do not exactly match a valid, unexpired offer.
    - if `offer_paths` is present:
      - MUST ignore the invoice_request if it did not arrive via one of those paths.
    - otherwise:
      - MUST ignore any invoice_request if it arrived via a blinded path.
    - if `offer_quantity_max` is present:
      - MUST reject the invoice request if there is no `invreq_quantity` field.
      - if `offer_quantity_max` is non-zero:
        - MUST reject the invoice request if `invreq_quantity` is zero, OR greater than `offer_quantity_max`.
    - otherwise:
      - MUST reject the invoice request if there is an `invreq_quantity` field.
    - if `offer_amount` is present:
      - MUST calculate the *expected amount* using the `offer_amount`:
        - if `offer_currency` is not the `invreq_chain` currency, convert to the
          `invreq_chain` currency.
        - if `invreq_quantity` is present, multiply by `invreq_quantity`.`quantity`.
      - if `invreq_amount` is present:
        - MUST reject the invoice request if `invreq_amount`.`msat` is less than the *expected amount*.
        - MAY reject the invoice request if `invreq_amount`.`msat` greatly exceeds the *expected amount*.
    - otherwise (no `offer_amount`):
      - MUST reject the invoice request if it does not contain `invreq_amount`.
    - SHOULD send an invoice in response using the `onionmsg_tlv` `reply_path`.
  - otherwise (no `offer_issuer_id` or `offer_paths`, not a response to our offer):
    - MUST reject the invoice request if any of the following are present:
      - `offer_chains`, `offer_features` or `offer_quantity_max`.
    - MUST reject the invoice request if `invreq_amount` is not present.
    - MAY use `offer_amount` (or `offer_currency`) for informational display to user.
    - if it sends an invoice in response:
      - MUST use `invreq_paths` if present, otherwise MUST use `invreq_payer_id` as the node id to send to.
  - if `invreq_chain` is not present:
    - MUST reject the invoice request if bitcoin is not a supported chain.
  - if `invreq_bip_353_name` is present:
    - MUST reject the invoice request if `name` or `domain` contain any bytes which are not
      `0`-`9`, `a`-`z`, `A`-`Z`, `-`, `_` or `.`.
  - otherwise:
    - MUST reject the invoice request if `invreq_chain`.`chain` is not a supported chain.


### Rationale

`invreq_metadata` might typically contain information about the derivation of the
`invreq_payer_id`.  This should not leak any information (such as using a simple
BIP-32 derivation path); a valid system might be for a node to maintain a base
payer key and encode a 128-bit tweak here.  The payer_id would be derived by
tweaking the base key with SHA256(payer_base_pubkey || tweak).  It's also
the first entry (if present), ensuring an unpredictable nonce for hashing.

`invreq_payer_note` allows you to compliment, taunt, or otherwise engrave
graffiti into the invoice for all to see.

Users can give a tip (or obscure the amount sent) by specifying an
`invreq_amount` in their invoice request, even though the offer specifies an
`offer_amount`.  The recipient will only accept this if
the invoice request amount exceeds the amount it's expecting (i.e. its
`offer_amount` after any currency conversion, multiplied by `invreq_quantity`, if
any).

Non-offer-response invoice requests are currently required to
explicitly state the `invreq_amount` in the chain currency,
so `offer_amount` and `offer_currency` are redundant (but may be
informative for the payer to know how the sender claims
`invreq_amount` was derived).

The requirement to use `offer_paths` if present, ensures a node does not reveal it is the source of an offer if it is asked directly.  Similarly, the requirement that the correct path is used for the offer ensures that cannot be made to reveal that it is the same node that created some other offer.

## Invoices

Invoices are a payment request, and when the payment is made, 
the payment preimage can be combined with the invoice to form a cryptographic receipt.

The recipient sends an `invoice` in response to an `invoice_request` using
the `onion_message` `invoice` field.

1. `tlv_stream`: `invoice`
2. types:
    1. type: 0 (`invreq_metadata`)
    2. data:
        * [`...*byte`:`blob`]
    1. type: 2 (`offer_chains`)
    2. data:
        * [`...*chain_hash`:`chains`]
    1. type: 4 (`offer_metadata`)
    2. data:
        * [`...*byte`:`data`]
    1. type: 6 (`offer_currency`)
    2. data:
        * [`...*utf8`:`iso4217`]
    1. type: 8 (`offer_amount`)
    2. data:
        * [`tu64`:`amount`]
    1. type: 10 (`offer_description`)
    2. data:
        * [`...*utf8`:`description`]
    1. type: 12 (`offer_features`)
    2. data:
        * [`...*byte`:`features`]
    1. type: 14 (`offer_absolute_expiry`)
    2. data:
        * [`tu64`:`seconds_from_epoch`]
    1. type: 16 (`offer_paths`)
    2. data:
        * [`...*blinded_path`:`paths`]
    1. type: 18 (`offer_issuer`)
    2. data:
        * [`...*utf8`:`issuer`]
    1. type: 20 (`offer_quantity_max`)
    2. data:
        * [`tu64`:`max`]
    1. type: 22 (`offer_issuer_id`)
    2. data:
        * [`point`:`id`]
    1. type: 80 (`invreq_chain`)
    2. data:
        * [`chain_hash`:`chain`]
    1. type: 82 (`invreq_amount`)
    2. data:
        * [`tu64`:`msat`]
    1. type: 84 (`invreq_features`)
    2. data:
        * [`...*byte`:`features`]
    1. type: 86 (`invreq_quantity`)
    2. data:
        * [`tu64`:`quantity`]
    1. type: 88 (`invreq_payer_id`)
    2. data:
        * [`point`:`key`]
    1. type: 89 (`invreq_payer_note`)
    2. data:
        * [`...*utf8`:`note`]
    1. type: 90 (`invreq_paths`)
    2. data:
        * [`...*blinded_path`:`paths`]
    1. type: 160 (`invoice_paths`)
    2. data:
        * [`...*blinded_path`:`paths`]
    1. type: 162 (`invoice_blindedpay`)
    2. data:
        * [`...*blinded_payinfo`:`payinfo`]
    1. type: 164 (`invoice_created_at`)
    2. data:
        * [`tu64`:`timestamp`]
    1. type: 166 (`invoice_relative_expiry`)
    2. data:
        * [`tu32`:`seconds_from_creation`]
    1. type: 168 (`invoice_payment_hash`)
    2. data:
        * [`sha256`:`payment_hash`]
    1. type: 170 (`invoice_amount`)
    2. data:
        * [`tu64`:`msat`]
    1. type: 172 (`invoice_fallbacks`)
    2. data:
        * [`...*fallback_address`:`fallbacks`]
    1. type: 174 (`invoice_features`)
    2. data:
        * [`...*byte`:`features`]
    1. type: 176 (`invoice_node_id`)
    2. data:
        * [`point`:`node_id`]
    1. type: 240 (`signature`)
    2. data:
        * [`bip340sig`:`sig`]

1. subtype: `blinded_payinfo`
2. data:
   * [`u32`:`fee_base_msat`]
   * [`u32`:`fee_proportional_millionths`]
   * [`u16`:`cltv_expiry_delta`]
   * [`u64`:`htlc_minimum_msat`]
   * [`u64`:`htlc_maximum_msat`]
   * [`u16`:`flen`]
   * [`flen*byte`:`features`]

1. subtype: `fallback_address`
2. data:
   * [`byte`:`version`]
   * [`u16`:`len`]
   * [`len*byte`:`address`]

### Invoice Features

| Bits | Description                      | Name           |
|------|----------------------------------|----------------|
| 16   | Multi-part-payment support       | MPP/compulsory |
| 17   | Multi-part-payment support       | MPP/optional   |

The 'MPP support' invoice feature indicates that the payer MUST (16) or
MAY (17) use multiple part payments to pay the invoice.

Some implementations may not support MPP (e.g. for small payments), or
may (due to capacity limits on a single channel) require it.

### Requirements

A writer of an invoice:
  - MUST set `invoice_created_at` to the number of seconds since Midnight 1
    January 1970, UTC when the invoice was created.
  - MUST set `invoice_amount` to the minimum amount it will accept, in units of 
    the minimal lightning-payable unit (e.g. milli-satoshis for bitcoin) for
    `invreq_chain`.
  - if the invoice is in response to an `invoice_request`:
    - MUST copy all non-signature fields from the invoice request (including unknown fields).
    - if `invreq_amount` is present:
      - MUST set `invoice_amount` to `invreq_amount`
    - otherwise:
      - MUST set `invoice_amount` to the *expected amount*.
  - MUST set `invoice_payment_hash` to the SHA256 hash of the
    `payment_preimage` that will be given in return for payment.
  - if `offer_issuer_id` is present:
    - MUST set `invoice_node_id` to the `offer_issuer_id`
  - otherwise, if `offer_paths` is present:
    - MUST set `invoice_node_id` to the final `blinded_node_id` on the path it received the invoice request
  - MUST specify exactly one signature TLV element: `signature`.
    - MUST set `sig` to the signature using `invoice_node_id` as described in [Signature Calculation](#signature-calculation).
  - if it requires multiple parts to pay the invoice:
    - MUST set `invoice_features`.`features` bit `MPP/compulsory`
  - or if it allows multiple parts to pay the invoice:
    - MUST set `invoice_features`.`features` bit `MPP/optional`
  - if the expiry for accepting payment is not 7200 seconds after `invoice_created_at`:
    - MUST set `invoice_relative_expiry`.`seconds_from_creation` to the number of
      seconds after `invoice_created_at` that payment of this invoice should not be attempted.
  - if it accepts onchain payments:
    - MAY specify `invoice_fallbacks`
    - SHOULD specify `invoice_fallbacks` in order of most-preferred to least-preferred
      if it has a preference.
    - for the bitcoin chain, it MUST set each `fallback_address` with
      `version` as a valid witness version and `address` as a valid witness
      program
  - MUST include `invoice_paths` containing one or more paths to the node.
    - MUST specify `invoice_paths` in order of most-preferred to least-preferred if it has a preference.
    - MUST include `invoice_blindedpay` with exactly one `blinded_payinfo` for each `blinded_path` in `paths`, in order.
    - MUST set `features` in each `blinded_payinfo` to match `encrypted_data_tlv`.`allowed_features` (or empty, if no `allowed_features`).
    - SHOULD ignore any payment which does not use one of the paths.

A reader of an invoice:
  - MUST reject the invoice if `invoice_amount` is not present.
  - MUST reject the invoice if `invoice_created_at` is not present.
  - MUST reject the invoice if `invoice_payment_hash` is not present.
  - MUST reject the invoice if `invoice_node_id` is not present.
  - if `invreq_chain` is not present:
    - MUST reject the invoice if bitcoin is not a supported chain.
  - otherwise:
    - MUST reject the invoice if `invreq_chain`.`chain` is not a supported chain.
  - if `invoice_features` contains unknown _odd_ bits that are non-zero:
    - MUST ignore the bit.
  - if `invoice_features` contains unknown _even_ bits that are non-zero:
    - MUST reject the invoice.
  - if `invoice_relative_expiry` is present:
    - MUST reject the invoice if the current time since 1970-01-01 UTC is greater than `invoice_created_at` plus `seconds_from_creation`.
  - otherwise:
    - MUST reject the invoice if the current time since 1970-01-01 UTC is greater than `invoice_created_at` plus 7200.
  - MUST reject the invoice if `invoice_paths` is not present or is empty.
  - MUST reject the invoice if `num_hops` is 0 in any `blinded_path` in `invoice_paths`.
  - MUST reject the invoice if `invoice_blindedpay` is not present.
  - MUST reject the invoice if `invoice_blindedpay` does not contain exactly one `blinded_payinfo` per `invoice_paths`.`blinded_path`.
  - For each `invoice_blindedpay`.`payinfo`:
    - MUST NOT use the corresponding `invoice_paths`.`path` if `payinfo`.`features` has any unknown even bits set.
    - MUST reject the invoice if this leaves no usable paths.
  - if the invoice is a response to an `invoice_request`:
    - MUST reject the invoice if all fields in ranges 0 to 159 and 1000000000 to 2999999999 (inclusive) do not exactly match the invoice request.
    - if `offer_issuer_id` is present (invoice_request for an offer):
      - MUST reject the invoice if `invoice_node_id` is not equal to `offer_issuer_id`
    - otherwise, if `offer_paths` is present (invoice_request for an offer without id):
      - MUST reject the invoice if `invoice_node_id` is not equal to the final `blinded_node_id` it sent the invoice request to.
    - otherwise (invoice_request without an offer):
      - MAY reject the invoice if it cannot confirm that `invoice_node_id` is correct, out-of-band.
  - MUST reject the invoice if `signature` is not a valid signature using `invoice_node_id` as described in [Signature Calculation](#signature-calculation).
  - SHOULD prefer to use earlier `invoice_paths` over later ones if it has no other reason for preference.
  - if `invoice_features` contains the MPP/compulsory bit:
    - MUST pay the invoice via multiple separate blinded paths.
  - otherwise, if `invoice_features` contains the MPP/optional bit:
    - MAY pay the invoice via multiple separate payments.
  - otherwise:
    - MUST NOT use multiple parts to pay the invoice.
  - if `invreq_amount` is present:
    - MUST reject the invoice if `invoice_amount` is not equal to `invreq_amount`
  - otherwise:
    - SHOULD confirm authorization if `invoice_amount`.`msat` is not within the amount range authorized.
  - for the bitcoin chain, if the invoice specifies `invoice_fallbacks`:
    - MUST ignore any `fallback_address` for which `version` is greater than 16.
    - MUST ignore any `fallback_address` for which `address` is less than 2 or greater than 40 bytes.
    - MUST ignore any `fallback_address` for which `address` does not meet known requirements for the given `version`
  - if `invreq_paths` is present:
    - MUST reject the invoice if it did not arrive via one of those paths.
  - otherwise, neither `offer_issuer_id` nor `offer_paths` are present (not derived from an offer):
    - MUST reject the invoice if it arrived via a blinded path.
  - otherwise (derived from an offer):
    - MUST reject the invoice if it did not arrive via invoice request `onionmsg_tlv` `reply_path`.

### Rationale

Because the messaging layer is unreliable, it's quite possible to
receive multiple requests for the same offer.  As it's the caller's
responsibility to make `invreq_metadata` both unpredictable and unique,
the writer doesn't have to check all the fields are duplicates before
simply returning a previous invoice.  Note that such caching is optional,
and should be carefully limited when e.g. currency conversion is involved,
or if the invoice has expired.

The invoice duplicates fields rather than committing to the previous
invreq.  This flattened format simplifies storage at some space cost, as
the payer need only remember the invoice for any refunds or proof.

The reader of the invoice cannot trust the invoice correctly reflects
the invreq fields, hence the requirements to check that they
are correct, although allowance is made for simply sending an unrequested
invoice directly.

Note that the recipient of the invoice can determine the expected
amount from either the offer it received, or the invreq it
sent, so often already has authorization for the expected amount.

The default `invoice_relative_expiry` of 7200 seconds, which is generally a
sufficient time for payment, even if new channels need to be opened.

Blinded paths provide an equivalent to `payment_secret` and `payment_metadata` used in BOLT 11.
Even if `invoice_node_id` or `invreq_payer_id` is public, we force the use of blinding paths to keep these features.
If the recipient does not care about the added privacy offered by blinded paths, they can create a path of length 1 with only themselves.

Rather than provide detailed per-hop-payinfo for each hop in a blinded path, we aggregate the fees and CLTV deltas.
This avoids trivially revealing any distinguishing non-uniformity which may distinguish the path.

In the case of an invoice where there was no offer (just an invoice
request), the payer needs to ensure that the invoice is from the
intended payment recipient.  This is the basis for the suggestion to
confirm the invoice_node_id for this case.

Raw invoices (not based on an invoice_request) are generally not
supported, though an implementation is allowed to support them, and we
may define the behavior in future.  The redundant requirement to check
`invreq_chain` explicitly is a nod to this: if the invoice is
a response to an invoice request, that field must have existed due
to the invoice request requirements, and we also require it to be mirrored
here.


## Invoice Errors

Informative errors can be returned in an onion message `invoice_error`
field (via the onion `reply_path`) for either `invoice_request` or
`invoice`.

### TLV Fields for `invoice_error`

1. `tlv_stream`: `invoice_error`
2. types:
    1. type: 1 (`erroneous_field`)
    2. data:
        * [`tu64`:`tlv_fieldnum`]
    1. type: 3 (`suggested_value`)
    2. data:
        * [`...*byte`:`value`]
    1. type: 5 (`error`)
    2. data:
        * [`...*utf8`:`msg`]

### Requirements

A writer of an invoice_error:
  - MUST set `error` to an explanatory string.
  - MAY set `erroneous_field` to a specific field number in the
    `invoice` or `invoice_request` which had a problem.
  - if it sets `erroneous_field`:
    - MAY set `suggested_value`.
    - if it sets `suggested_value`:
      - MUST set `suggested_value` to a valid field for that `tlv_fieldnum`.
  - otherwise:
    - MUST NOT set `suggested_value`.

A reader of an invoice_error:
   FIXME!

### Rationale

Usually an error message is sufficient for diagnostics, however future
enhancements may make automated handling useful.

In particular, we could allow non-offer-response `invoice_request`s to
omit `invreq_amount` in future and use offer fields to
indicate alternate currencies.  ("I will send you 10c!").  Then the
sender of the invoice would have to guess how many msat that was,
and could use the `invoice_error` to indicate if the recipient disagreed
with the conversion so the sender can send a new invoice.

## FIXME: Possible future extensions:

1. The offer can require delivery info in the `invoice_request`.
2. An offer can be updated: the response to an `invoice_request` is another offer,
   perhaps with a signature from the original `offer_issuer_id`
3. Any empty TLV fields can mean the value is supposed to be known by
   other means (i.e. transport-specific), but is still hashed for sig.
4. We could upgrade to allow multiple offers in one invreq and
   invoice, to make a shopping list.
7. All-zero offer_id == gratuitous payment.
8. Streaming invoices?
9. Re-add recurrence.
10. Re-add `invreq_refund_for` to support proofs.
11. Re-add `invoice_replace` for requesting replacement of a (stuck-payment) 
    invoice with a new one.
12. Allow non-offer `invoice_request` with alternate currencies?
13. Add `offer_quantity_unit` to indicate stepping for quantity
    (e.g. 100 grams).

[1] https://www.youtube.com/watch?v=4SYc_flMnMQ
