# BOLT #0: Introduction and Index

Welcome, friend! These Basis of Lightning Technology (BOLT) documents
describe a layer-2 protocol for off-chain bitcoin transfer by mutual
cooperation, relying on on-chain transactions for enforcement if
necessary.

Some requirements are subtle; we have tried to highlight motivations
and reasoning behind the results you see here. I'm sure we've fallen
short; if you find any part confusing or wrong, please contact us and
help us improve.

This is version 0.

1. [BOLT #1](01-messaging.md): Base Protocol
2. [BOLT #2](02-peer-protocol.md): Peer Protocol for Channel Management
3. [BOLT #3](03-transactions.md): Bitcoin Transaction and Script Formats
4. [BOLT #4](04-onion-routing.md): Onion Routing Protocol
5. [BOLT #5](05-onchain.md): Recommendations for On-chain Transaction Handling
7. [BOLT #7](07-routing-gossip.md): P2P Node and Channel Discovery
8. [BOLT #8](08-transport.md): Encrypted and Authenticated Transport
9. [BOLT #9](09-features.md): Assigned Feature Flags
10. [BOLT #10](10-dns-bootstrap.md): DNS Bootstrap and Assisted Node Location
11. [BOLT #11](11-payment-encoding.md): Invoice Protocol for Lightning Payments
12. [BOLT #12](12-offer-encoding.md): Flexible Protocol for Lightning Payments

## The Spark: A Short Introduction to Lightning

Lightning is a protocol for making fast payments with Bitcoin using a
network of channels.

### Channels

Lightning works by establishing *channels*: two participants create a
Lightning payment channel that contains some amount of bitcoin (e.g.,
0.1 bitcoin) that they've locked up on the Bitcoin network. It is
spendable only with both their signatures.

Initially they each hold a bitcoin transaction that sends all the
bitcoin (e.g. 0.1 bitcoin) back to one party.  They can later sign a new bitcoin
transaction that splits these funds differently, e.g. 0.09 bitcoin to one
party, 0.01 bitcoin to the other, and invalidate the previous bitcoin
transaction so it won't be spent.

See [BOLT #2: Channel Establishment](02-peer-protocol.md#channel-establishment) for more on
channel establishment and [BOLT #3: Funding Transaction Output](03-transactions.md#funding-transaction-output) for the format of the bitcoin transaction that creates the channel.  See [BOLT #5: Recommendations for On-chain Transaction Handling](05-onchain.md) for the requirements when participants disagree or fail, and the cross-signed bitcoin transaction must be spent.

### Conditional Payments

A Lightning channel only allows payment between two participants, but channels can be connected together to form a network that allows payments between all members of the network. This requires the technology of a conditional payment, which can be added to a channel,
e.g. "you get 0.01 bitcoin if you reveal the secret within 6 hours".
Once the recipient presents the secret, that bitcoin transaction is
replaced with one lacking the conditional payment and adding the funds
to that recipient's output.

See [BOLT #2: Adding an HTLC](02-peer-protocol.md#adding-an-htlc-update_add_htlc) for the commands a participant uses to add a conditional payment, and [BOLT #3: Commitment Transaction](03-transactions.md#commitment-transaction) for the
complete format of the bitcoin transaction.

### Forwarding

Such a conditional payment can be safely forwarded to another
participant with a lower time limit, e.g. "you get 0.01 bitcoin if you reveal the secret
within 5 hours".  This allows channels to be chained into a network
without trusting the intermediaries.

See [BOLT #2: Forwarding HTLCs](02-peer-protocol.md#forwarding-htlcs) for details on forwarding payments, [BOLT #4: Packet Structure](04-onion-routing.md#packet-structure) for how payment instructions are transported.

### Network Topology

To make a payment, a participant needs to know what channels it can
send through.  Participants tell each other about channel and node
creation, and updates.

See [BOLT #7: P2P Node and Channel Discovery](07-routing-gossip.md)
for details on the communication protocol, and [BOLT #10: DNS
Bootstrap and Assisted Node Location](10-dns-bootstrap.md) for initial
network bootstrap.

### Payment Invoicing

A participant receives invoices that tell them what payments to make.

See [BOLT #11: Invoice Protocol for Lightning Payments](11-payment-encoding.md) for the protocol describing the destination and purpose of a payment such that the payer can later prove successful payment.


## Glossary and Terminology Guide

* #### *Announcement*:
   * A gossip message sent between *[peers](#peers)* intended to aid the discovery of a *[channel](#channel)* or a *[node](#node)*.

* #### `chain_hash`:
   * The uniquely identifying hash of the target blockchain (usually the genesis hash).
     This allows *[nodes](#node)* to create and reference *channels* on
     several blockchains. Nodes are to ignore any messages that reference a
     `chain_hash` that are unknown to them. Unlike `bitcoin-cli`, the hash is
     not reversed but is used directly.

     For the main chain Bitcoin blockchain, the `chain_hash` value MUST be
     (encoded in hex):
     `6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000`.

* #### *Channel*:
   * A fast, off-chain method of mutual exchange between two *[peers](#peers)*.
   To transact funds, peers exchange signatures to create an updated *[commitment transaction](#commitment-transaction)*.
   * _See closure methods: [mutual close](#mutual-close), [revoked transaction close](#revoked-transaction-close), [unilateral close](#unilateral-close)_
   * _See related: [route](#route)_

* #### *Closing transaction*:
   * A transaction generated as part of a *[mutual close](#mutual-close)*. A closing transaction is similar to a _commitment transaction_, but with no pending payments.
   * _See related: [commitment transaction](#commitment-transaction), [funding transaction](#funding-transaction), [penalty transaction](#penalty-transaction)_

* #### *Commitment number*:
   * A 48-bit incrementing counter for each *[commitment transaction](#commitment-transaction)*; counters
    are independent for each *peer* in the *channel* and start at 0.
   * _See container: [commitment transaction](#commitment-transaction)_
   * _See related: [closing transaction](#closing-transaction), [funding transaction](#funding-transaction), [penalty transaction](#penalty-transaction)_

* #### *Commitment revocation private key*:
   * Every *[commitment transaction](#commitment-transaction)* has a unique commitment revocation private-key
    value that allows the other *peer* to spend all outputs
    immediately: revealing this key is how old commitment
    transactions are revoked. To support revocation, each output of the
    commitment transaction refers to the commitment revocation public key.
   * _See container: [commitment transaction](#commitment-transaction)_
   * _See originator: [per-commitment secret](#per-commitment-secret)_

* #### *Commitment transaction*:
   * A transaction that spends the *[funding transaction](#funding-transaction)*.
   Each *peer* holds the other peer's signature for this transaction, so that each
   always has a commitment transaction that it can spend. After a new
   commitment transaction is negotiated, the old one is *revoked*.
   * _See parts: [commitment number](#commitment-number), [commitment revocation private key](#commitment-revocation-private-key), [HTLC](#HTLC-Hashed-Time-Locked-Contract), [per-commitment secret](#per-commitment-secret), [outpoint](#outpoint)_
   * _See related: [closing transaction](#closing-transaction), [funding transaction](#funding-transaction), [penalty transaction](#penalty-transaction)_
   * _See types: [revoked commitment transaction](#revoked-commitment-transaction)_

* #### *Fail the channel*:
  * This is a forced close of the channel. Very early on (before
  opening), this may not require any action but forgetting the
  existence of the channel.  Usually it requires signing and
  broadcasting the latest commitment transaction, although during
  mutual close it can also be performed by signing and broadcasting a
  mutual close transaction.  See [BOLT #5](05-onchain.md#failing-a-channel).

* #### *Close the connection*:
  * This means closing communication with the peer (such as closing
  the TCP socket).  It does not imply closing any channels with the
  peer, but does cause the discarding of uncommitted state for
  connections with channels: see [BOLT #2](02-peer-protocol.md#message-retransmission).

* #### *Final node*:
   * The final recipient of a packet that is routing a payment from an *[origin node](#origin-node)* through some number of *[hops](#hop)*. It is also the final *[receiving peer](#receiving-peer)* in a chain.
   * _See category: [node](#node)_
   * _See related: [origin node](#origin-node), [processing node](#processing-node)_

* #### *Funding transaction*:
   * An irreversible on-chain transaction that pays to both *[peers](#peers)* on a *[channel](#channel)*.
   It can only be spent by mutual consent.
   * _See related: [closing transaction](#closing-transaction), [commitment transaction](#commitment-transaction), [penalty transaction](#penalty-transaction)_

* #### *Hop*:
   * A *[node](#node)*. Generally, an intermediate node lying between an *[origin node](#origin-node)* and a *[final node](#final-node)*.
   * _See category: [node](#node)_

* #### *HTLC*: Hashed Time Locked Contract.
   * A conditional payment between two *[peers](#peers)*: the recipient can spend
    the payment by presenting its signature and a *payment preimage*,
    otherwise the payer can cancel the contract by spending it after
    a given time. These are implemented as outputs from the
    *[commitment transaction](#commitment-transaction)*.
   * _See container: [commitment transaction](#commitment-transaction)_
   * _See parts: [Payment hash](#Payment-hash), [Payment preimage](#Payment-preimage)_

* #### *Invoice*: A request for funds on the Lightning Network, possibly
    including payment type, payment amount, expiry, and other
    information. This is how payments are made on the Lightning
    Network, rather than using Bitcoin-style addresses.

* #### *It's ok to be odd*:
   * A rule applied to some numeric fields that indicates either optional or
     compulsory support for features. Even numbers indicate that both endpoints
     MUST support the feature in question, while odd numbers indicate
     that the feature MAY be disregarded by the other endpoint.

* #### *MSAT*:
   * A millisatoshi, often used as a field name.

* #### *Mutual close*:
   * A cooperative close of a *[channel](#channel)*, accomplished by broadcasting an unconditional
    spend of the *[funding transaction](#funding-transaction)* with an output to each *peer*
    (unless one output is too small, and thus is not included).
   * _See related: [revoked transaction close](#revoked-transaction-close), [unilateral close](#unilateral-close)_

* #### *Node*:
   * A computer or other device that is part of the Lightning network.
   * _See related: [peers](#peers)_
   * _See types: [final node](#final-node), [hop](#hop), [origin node](#origin-node), [processing node](#processing-node), [receiving node](#receiving-node), [sending node](#sending-node)_

* #### *Origin node*:
   * The *[node](#node)* that originates a packet that will route a payment through some number of [hops](#hop) to a *[final node](#final-node)*. It is also the first [sending peer](#sending-peer) in a chain.
   * _See category: [node](#node)_
   * _See related: [final node](#final-node), [processing node](#processing-node)_

* #### *Outpoint*:
  * A transaction hash and output index that uniquely identify an unspent transaction output. Needed to compose a new transaction, as an input.
  * _See related: [funding transaction](#funding-transaction), [commitment transaction](#commitment-transaction)_

* #### *Payment hash*:
   * The *[HTLC](#HTLC-Hashed-Time-Locked-Contract)* contains the payment hash, which is the hash of the
    *[payment preimage](#Payment-preimage)*.
   * _See container: [HTLC](#HTLC-Hashed-Time-Locked-Contract)_
   * _See originator: [Payment preimage](#Payment-preimage)_

* #### *Payment preimage*:
   * Proof that payment has been received, held by
    the final recipient, who is the only person who knows this
    secret. The final recipient releases the preimage in order to
    release funds. The payment preimage is hashed as the *[payment hash](#Payment-hash)*
    in the *[HTLC](#HTLC-Hashed-Time-Locked-Contract)*.
   * _See container: [HTLC](#HTLC-Hashed-Time-Locked-Contract)_
   * _See derivation: [payment hash](#Payment-hash)_

* #### *Peers*:
   * Two *[nodes](#node)* that are in communication with each other.
      * Two peers may gossip with each other prior to setting up a channel.
      * Two peers may establish a *[channel](#channel)* through which they transact.
   * _See related: [node](#node)_

* #### *Penalty transaction*:
   * A transaction that spends all outputs of a *[revoked commitment
    transaction](#revoked-commitment-transaction)*, using the *commitment revocation private key*. A *[peer](#peers)* uses this
    if the other peer tries to "cheat" by broadcasting a *[revoked commitment
    transaction](#revoked-commitment-transaction)*.
   * _See related: [closing transaction](#closing-transaction), [commitment transaction](#commitment-transaction), [funding transaction](#funding-transaction)_

* #### *Per-commitment secret*:
   * Every *[commitment transaction](#commitment-transaction)* derives its keys from a per-commitment secret,
     which is generated such that the series of per-commitment secrets
     for all previous commitments can be stored compactly.
   * _See container: [commitment transaction](#commitment-transaction)_
   * _See derivation: [commitment revocation private key](#commitment-revocation-private-key)_

* #### *Processing node*:
   * A *[node](#node)* that is processing a packet that originated with an *[origin node](#origin-node)* and that is being sent toward a *[final node](#final-node)* in order to route a payment. It acts as a *[receiving peer](#receiving-peer)* to receive the message, then a [sending peer](#sending-peer) to send on the packet.
   * _See category: [node](#node)_
   * _See related: [final node](#final-node), [origin node](#origin-node)_

* #### *Receiving node*:
   * A *[node](#node)* that is receiving a message.
   * _See category: [node](#node)_
   * _See related: [sending node](#sending-node)_

* #### *Receiving peer*:
   * A *[node](#node)* that is receiving a message from a directly connected *peer*.
   * _See category: [peer](#Peers)_
   * _See related: [sending peer](#sending-peer)_

* #### *Revoked commitment transaction*:
   * An old *[commitment transaction](#commitment-transaction)* that has been revoked because a new commitment transaction has been negotiated.
   * _See category: [commitment transaction](#commitment-transaction)_

* #### *Revoked transaction close*:
   * An invalid close of a *[channel](#channel)*, accomplished by broadcasting a *revoked
    commitment transaction*. Since the other *peer* knows the
    *commitment revocation secret key*, it can create a *[penalty transaction](#penalty-transaction)*.
   * _See related: [mutual close](#mutual-close), [unilateral close](#unilateral-close)_

* #### *Route*: 
  * A path across the Lightning Network that enables a payment
    from an *origin node* to a *[final node](#final-node)* across one or more
    *[hops](#hop)*.
  * _See related: [channel](#channel)_

* #### *Sending node*:
   * A *[node](#node)* that is sending a message.
   * _See category: [node](#node)_
   * _See related: [receiving node](#receiving-node)_

* #### *Sending peer*:
   * A *[node](#node)* that is sending a message to a directly connected *peer*.
   * _See category: [peer](#Peers)_
   * _See related: [receiving peer](#receiving-peer)_.

* #### *Unilateral close*:
   * An uncooperative close of a *[channel](#channel)*, accomplished by broadcasting a
    *[commitment transaction](#commitment-transaction)*. This transaction is larger (i.e. less
    efficient) than a *[closing transaction](#closing-transaction)*, and the *[peer](#peers)* whose
    commitment is broadcast cannot access its own outputs for some
    previously-negotiated duration.
   * _See related: [mutual close](#mutual-close), [revoked transaction close](#revoked-transaction-close)_

## Theme Song

      Why this network could be democratic...
      Numismatic...
      Cryptographic!
      Why it could be released Lightning!
      (Release Lightning!)


      We'll have some timelocked contracts with hashed pubkeys, oh yeah.
      (Keep talking, whoa keep talkin')
      We'll segregate the witness for trustless starts, oh yeah.
      (I'll get the money, I've got to get the money)
      With dynamic onion routes, they'll be shakin' in their boots;
      You know that's just the truth, we'll be scaling through the roof.
      Release Lightning!
      (Go, go, go, go; go, go, go, go, go, go)


      [Chorus:]
      Oh released Lightning, it's better than a debit card..
      (Release Lightning, go release Lightning!)
      With released Lightning, micropayments just ain't hard...
      (Release Lightning, go release Lightning!)
      Then kaboom: we'll hit the moon -- release Lightning!
      (Go, go, go, go; go, go, go, go, go, go)

 
      We'll have QR codes, and smartphone apps, oh yeah.
      (Ooo ooo ooo ooo ooo ooo ooo)
      P2P messaging, and passive incomes, oh yeah.
      (Ooo ooo ooo ooo ooo ooo ooo)
      Outsourced closure watch, gives me feelings in my crotch.
      You'll know it's not a brag when the repo gets a tag:
      Released Lightning.


      [Chorus]
      [Instrumental, ~1m10s]
      [Chorus]
      (Lightning! Lightning! Lightning! Lightning!
       Lightning! Lightning! Lightning! Lightning!)


      C'mon guys, let's get to work!


   -- Anthony Towns <aj@erisian.com.au>

## Authors

[ FIXME: Insert Author List ]

![Creative Commons License](https://i.creativecommons.org/l/by/4.0/88x31.png "License CC-BY")
<br>
This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
