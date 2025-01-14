# Trampoline Onion Routing

## Table of Contents

* [Introduction](#introduction)
* [Overview](#overview)
* [Trampoline onion](#trampoline-onion)
* [Returning errors](#returning-errors)
* [Invoice flow](#invoice-flow)
  * [With Bolt 11 invoices](#with-bolt-11-invoices)
  * [With Bolt 12 invoices](#with-bolt-12-invoices)
* [Privacy](#privacy)
* [Trampoline MPP](#trampoline-mpp)
* [Trampoline fees](#trampoline-fees)
* [Future gossip extensions](#future-gossip-extensions)
* [Why not rendezvous routing](#why-not-rendezvous-routing)

## Introduction

As the network grows, more bandwidth and storage will be required to keep an
up-to-date view of the whole network. Finding a payment path will also require
more computing power, making it unsustainable for constrained devices.

Constrained devices should only keep a view of a small part of the network and
leverage trampoline nodes to route payments.

While a thorough analysis has not been made, the current state of the proposal
should not result in a loss of privacy; on the contrary, it gives more routing
flexibility and is likely to improve the anonymity set.

## Overview

Nodes that are able to calculate (partial) routes on behalf of other nodes will
advertise support for the `trampoline_routing` feature. This is an opportunity
for them to earn more fees than with the default onion routing (payers choose
to pay a fee premium in exchange for reliable path-finding-as-a-service from
trampoline nodes).

A payer selects trampoline nodes and builds a corresponding trampoline onion,
very similar to the normal onion; the only difference is that the next nodes
are identified by `node_id` instead of `short_channel_id` and may not be
direct peers.

The payer then embeds that trampoline onion in the last `hop_payload` of an
`onion_packet` destined to the first trampoline node. Computing routes between
trampoline nodes is then deferred to the trampoline nodes themselves.

A trampoline payment will thus look like this:

```text
Trampoline route:

Alice ---> Bob ---> Carol ---> Dave

Complete route:

        +--> Irvin --> Iris --+          +--> ... --+            +--> ... --+
        |                     |          |          |            |          |
        |                     |          |          |            |          |
Alice --+                     +--> Bob --+          +--> Carol --+          +--> Dave

<----------------------------------><----------------------><--------------------->
            (normal payment)            (normal payment)        (normal payment)
```

Note that this construction still uses onions created by the payer so it doesn't
sacrifice privacy (in most cases it may even provide a bigger anonymity set).

## Trampoline onion

A trampoline onion uses the same construction as normal payment onions but with
a smaller size, to allow embedding it inside a normal payment onion.

For example, Alice may want to pay Carol using trampoline. Alice inserts
trampoline nodes between her and Carol. For this example we use a single
trampoline (Bob) but Alice may use more than one trampoline.

Alice then finds a route to the first trampoline Bob. The complete route is:

```text
        +--> Irvin --> Iris --+          +--> ... --+
        |                     |          |          |
        |                     |          |          |
Alice --+                     +--> Bob --+          +--> Carol
```

Note again that Alice only needs to find a route to Bob (instead of having to
find a complete route to Carol). She doesn't know what route will be used
between Bob and Carol: it will be Bob's responsibility to find one that works.

If Alice wants to send 50 000 msat to Carol, the corresponding `update_add_htlc`
message sent by Alice to Irvin will look like:

```text
                        update_add_htlc
+---------------------------------------------------------------------------+
| channel_id: 1x2x3                                                         |
| htlc_id: 42                                                               |
| amount_msat: 55000                                                        |
| cltv_expiry: 1500                                                         |
| payment_hash: 0xabcd                                                      |
| onion_routing_packet:                                                     |
| +-----------------------------------------------------------------------+ |
| | +--------------------------------------------+----------------------+ | |
| | | amt_to_forward: 54000                      | normal onion payload | | |
| | | outgoing_cltv_value: 1450                  | for Irvin            | | |
| | | short_channel_id: 5x3x7                    |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +--------------------------------------------+----------------------+ | |
| | | amt_to_forward: 53000                      | normal onion payload | | |
| | | outgoing_cltv_value: 1400                  | for Iris             | | |
| | | short_channel_id: 6x3x0                    |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +--------------------------------------------+----------------------+ | |
| | | amt_to_forward: 53000                      |                      | | |
| | | outgoing_cltv_value: 1400                  | normal onion payload | | |
| | | payment_secret: 0x1111...                  | for Bob              | | |
| | | total_amount: 53000                        |                      | | |
| | | trampoline_onion:                          |                      | | |
| | | +---------------------------+------------+ |                      | | |
| | | | amt_to_forward: 50000     | trampoline | |                      | | |
| | | | outgoing_cltv_value: 1000 | payload    | |                      | | |
| | | | outgoing_node_id: carol   | for Bob    | |                      | | |
| | | +---------------------------+------------+ |                      | | |
| | | +---------------------------+------------+ |                      | | |
| | | | amt_to_forward: 50000     | trampoline | |                      | | |
| | | | outgoing_cltv_value: 1000 | payload    | |                      | | |
| | | | payment_secret: 0x6666    | for Carol  | |                      | | |
| | | | total_amount: 50000       | (final)    | |                      | | |
| | | +---------------------------+------------+ |                      | | |
| | +--------------------------------------------+----------------------+ | |
| +-----------------------------------------------------------------------+ |
+---------------------------------------------------------------------------+
```

When Bob receives the trampoline onion, he discovers that the next node is Carol.
Bob finds a route to Carol, builds a new payment onion and includes the peeled
trampoline onion in the final payload. This process may repeat with multiple
trampoline hops until we reach the final recipient.

Here is an example flow of `update_add_htlc` messages received at each hop:

```text
Alice ------------------> Irvin -------------------------------------> Iris -----------------------------------> Bob -----------------------------------------> John ------------------------------------> Jack ------------------------------------> Carol

                      update_add_htlc                            update_add_htlc                            update_add_htlc                                update_add_htlc                            update_add_htlc                            update_add_htlc               
               +-------------------------------+          +-------------------------------+          +-----------------------------------+          +-------------------------------+          +-------------------------------+          +-----------------------------------+
               | channel_id: 1x2x3             |          | channel_id: 5x3x7             |          | channel_id: 6x3x0                 |          | channel_id: 2x8x3             |          | channel_id: 1x3x5             |          | channel_id: 6x5x4                 |
               | htlc_id: 42                   |          | htlc_id: 21                   |          | htlc_id: 17                       |          | htlc_id: 7                    |          | htlc_id: 15                   |          | htlc_id: 3                        |
               | amount_msat: 55000            |          | amount_msat: 54000            |          | amount_msat: 53000                |          | amount_msat: 51000            |          | amount_msat: 50500            |          | amount_msat: 50000                |
               | cltv_expiry: 1500             |          | cltv_expiry: 1450             |          | cltv_expiry: 1400                 |          | cltv_expiry: 1200             |          | cltv_expiry: 1100             |          | cltv_expiry: 1000                 |
               | payment_hash: 0xabcd...       |          | payment_hash: 0xabcd...       |          | payment_hash: 0xabcd...           |          | payment_hash: 0xabcd...       |          | payment_hash: 0xabcd...       |          | payment_hash: 0xabcd...           |
               | onion_routing_packet:         |          | onion_routing_packet:         |          | onion_routing_packet:             |          | onion_routing_packet:         |          | onion_routing_packet:         |          | onion_routing_packet:             |
               | +---------------------------+ |          | +---------------------------+ |          | +-------------------------------+ |          | +---------------------------+ |          | +---------------------------+ |          | +-------------------------------+ |
               | | amt_to_forward: 54000     | |          | | amt_to_forward: 53000     | |          | | amt_to_forward: 53000         | |          | | amt_to_forward: 50500     | |          | | amt_to_forward: 50000     | |          | | amt_to_forward: 50000         | |
               | | outgoing_cltv_value: 1450 | |          | | outgoing_cltv_value: 1400 | |          | | outgoing_cltv_value: 1400     | |          | | outgoing_cltv_value: 1100 | |          | | outgoing_cltv_value: 1000 | |          | | outgoing_cltv_value: 1000     | |
               | | short_channel_id: 5x3x7   | |          | | short_channel_id: 6x3x0   | |          | | payment_secret: 0x1111...     | |          | | short_channel_id: 1x3x5   | |          | | short_channel_id: 6x5x4   | |          | | payment_secret: 0x2222...     | |
               | +---------------------------+ |          | +---------------------------+ |          | | total_amount: 53000           | |          | +---------------------------+ |          | +---------------------------+ |          | | total_amount: 50000           | |
               | |       (encrypted)         | |          | |       (encrypted)         | |          | | trampoline_onion:             | |          | |       (encrypted)         | |          | |       (encrypted)         | |          | | trampoline_onion:             | |
               | +---------------------------+ |          | +---------------------------+ |          | | +---------------------------+ | |          | +---------------------------+ |          | +---------------------------+ |          | | +---------------------------+ | |
               +-------------------------------+          +-------------------------------+          | | | amt_to_forward: 50000     | | |          +-------------------------------+          +-------------------------------+          | | | amt_to_forward: 50000     | | |
                                                                                                     | | | outgoing_cltv_value: 1000 | | |                                                                                                | | | outgoing_cltv_value: 1000 | | |
                                                                                                     | | | outgoing_node_id: carol   | | |                                                                                                | | | payment_secret: 0x6666... | | |
                                                                                                     | | +---------------------------+ | |                                                                                                | | | total_amount: 50000       | | |
                                                                                                     | | |       (encrypted)         | | |                                                                                                | | +---------------------------+ | |
                                                                                                     | | +---------------------------+ | |                                                                                                | | |           EOF             | | |
                                                                                                     | +-------------------------------+ |                                                                                                | | +---------------------------+ | |
                                                                                                     | |             EOF               | |                                                                                                | +-------------------------------+ |
                                                                                                     | +-------------------------------+ |                                                                                                | |             EOF               | |
                                                                                                     +-----------------------------------+                                                                                                | +-------------------------------+ |
                                                                                                                                                                                                                                          +-----------------------------------+
```

## Returning errors

Trampoline nodes apply the same error-wrapping mechanism used for normal onions
at the trampoline onion level. This results in two layers of error wrapping
that let the origin node get actionable data for potential retries.

### Notations

We note `ss(Alice, Bob)` the shared secret between Alice and Bob for the outer
onion encryption, and `tss(Alice, Bob)` the shared secret between Alice and Bob
for the trampoline onion encryption.

### Error before the first trampoline

```text
    +---> N1 ---> N2 (error)
    |
    |
+-------+                          +----+
| Alice |                          | T1 |
+-------+                          +----+
```

* Alice receives `wrap(ss(Alice,N1), wrap(ss(Alice,N2), error))`
* She discovers N2 is the failing node by unwrapping with outer onion shared secrets

### Error between trampoline nodes

```text
    +---> N1 ---> N2 ---+  +---> M1 ---+  +---> E1 ---> E2 (error)
    |                   |  |           |  |
    |                   v  |           v  |
+-------+              +----+         +----+
| Alice |              | T1 |         | T2 |
+-------+              +----+         +----+
```

* T2 receives `wrap(ss(T2,E1),wrap(ss(T2,E2), error))`
* T2 discovers E2 is the failing node by unwrapping with outer onion shared
  secrets, and can transform this error to the error that makes the most sense
  to return to the payer, and wraps it with the trampoline shared secret and
  then the outer onion shared secret: `wrap(ss(T1,T2), wrap(tss(Alice,T2), error))`
* T1 receives `wrap(ss(T1, M1), wrap(ss(T1,T2), wrap(tss(Alice,T2), error)))`
* After unwrapping with the outer onion shared secrets T1 obtains: `wrap(tss(Alice,T2), error)`
  T1 cannot decrypt further, so it adds its own two layers of wrapping and
  forwards upstream `wrap(ss(Alice,T1), wrap(tss(Alice,T1), wrap(tss(Alice,T2), error)))`
* Alice receives `wrap(ss(Alice,N1), wrap(ss(Alice,N2), wrap(ss(Alice,T1), wrap(tss(Alice,T1), wrap(tss(Alice,T2), error)))))`
* She unwraps with the outer onion secrets and obtains: `wrap(tss(Alice,T1), wrap(tss(Alice,T2), error))`
* Since this is still not a plaintext error, she unwraps with the trampoline
  onion secrets, recovers `error` and knows that T2 sent it.

### Error at a trampoline node

```text
    +---> N1 ---> N2 ---+  +---> M1 ----+
    |                   |  |            |
    |                   v  |            v
+-------+              +----+         +----+
| Alice |              | T1 |         | T2 | (error)
+-------+              +----+         +----+
```

* T2 creates a local error and wraps it: `wrap(ss(T1,T2), wrap(tss(Alice,T2), error))`
* T1 receives `wrap(ss(T1, M1), wrap(ss(T1,T2), wrap(tss(Alice,T2), error)))`
* After unwrapping with the outer onion shared secrets T1 obtains: `wrap(tss(Alice,T2), error)`
  It cannot decrypt further, so it adds its own two layers of wrapping and
  forwards upstream `wrap(ss(Alice,T1), wrap(tss(Alice,T1), wrap(tss(Alice,T2), error)))`
* Alice receives `wrap(ss(Alice,N1), wrap(ss(Alice,N2), wrap(ss(Alice,T1), wrap(tss(Alice,T1), wrap(tss(Alice,T2), error)))))`
* She unwraps with the outer onion secrets and obtains: `wrap(tss(Alice,T1), wrap(tss(Alice,T2), error))`
* Since this is still not a plaintext error, she unwraps with the trampoline
  onion secrets, recovers `error` and knowns that T2 sent it.

### Unparsable error somewhere in the route

This works the same, each trampoline unwraps as much as it can then re-wraps.
It will result in an unparsable error at Alice (as expected).

## Invoice flow

Now the question is: how does Alice choose the trampoline nodes to reach Carol?

### With Bolt 11 invoices

When creating a Bolt 11 invoice with the trampoline feature bit activated, the
recipient may include routing hints that support trampoline. This is useful in
particular when the recipient is directly connected to trampoline nodes with
private channels: those trampoline nodes can be used by the sender to reach the
recipient.

If the recipient is a public node, they don't need to include any routing hint
in their invoice.

```json
{
  "routing_hints": [
    {
      "trampoline_node_id": "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2",
      "short_channel_id": "823786x17x3",
      "cltv_expiry_delta": 288,
      "fee_base_msat": 5,
      "fee_proportional_millionths": 300
    }
  ]
}
```

When Alice wants to pay the invoice, she selects a trampoline node close to her
(let's call it T1) and a trampoline node from Carol's invoice (let's call it
T2). If Carol doesn't include any routing hint in the invoice, T2 = Carol.

Alice then simply uses the trampoline route `Alice -> T1 -> T2 -> Carol` and
creates the corresponding trampoline onion. Alice then finds a route to T1, and
sends the payment through that route.

```text
     Alice's neighborhood                                                     Carol's neighborhood
+----------------------------------+                                        +----------------------+
|                                  |                                        |                      |
|      +-----> T4                  |                                        |    T3 <--------+     |
|      |                           |                                        |                |     |
|      |                           |                                        |                |     |
|    Alice -----> N1 -----> T1     |-------> (public network graph) ------->|    T2 <----- Carol   |
|      |                           |                                        |                      |
|      |                           |                                        +----------------------+
|      +-----> N2 -----> T5        |
|                                  |
+----------------------------------+
```

Alice and Carol both assume connectivity between their respective neighborhoods.
Note that this assumption is also necessary with the default source-routing
scheme, so trampoline is not adding any new restrictions.

### With Bolt 12 invoices

Bolt 12 introduces blinded paths in order to protect the receiver's privacy.
This feature combines very nicely with trampoline payments, by providing two
options for the payer. If the receiver supports trampoline, the blinded nodes
are used as trampoline nodes, which provides great anonymity and flexibility.
Otherwise, if the receiver does not support trampoline, the payer can still
pay them privately by asking a trampoline node to relay to the blinded paths
provided in the invoice, which doesn't reveal the receiver's identity (unless
the blinded paths are empty, in which case the payment shouldn't be made with
trampoline if privacy is important).

Carol provides a standard Bolt 12 invoice containing blinded paths to herself:

```text
     Carol's neighborhood
+--------------------------------+
|                                |
|       I1 -----> I2 ------+     |
|                          |     |
|                          v     |
|    I3 -----> I4 -----> Carol   |
|                                |
+--------------------------------+
```

#### Invoice using trampoline

If Carol supports trampoline, Alice uses every node of the blinded path as
trampoline node, and adds a trampoline node in her own neighborhood at the
beginning of the trampoline route. She includes the invoice's encrypted data
for each node in their respective trampoline payload: this is very similarly
to paying a blinded path without trampoline.

Alice includes the `current_path_key` of the blinded path in the trampoline
onion payload for the introduction node: this means that her trampoline node
T1 doesn't even learn that a blinded path is being used.

This also lets her include any additional fields she'd like in the trampoline
onion payload for Carol.

```text
        +---> N1 ---+                             +-----+         +-----+
        |           |                             |     |         |     |
Alice --+           +--> T1 -----> Bob ----> I3 --+     +--> I4 --+     +--> Carol

<------------------------><------------------><---------------------------------->
     (normal payment)       (normal payment)       (blinded trampoline payment)
```

The `update_add_htlc` messages received at each hop look like:

```text
Alice -----------> N1 --------------------------------------> T1 --------------------------------------------> Bob ------------------------------------------> I3 ---------------------------------------------> I4 ------------------------------------------> Carol

            update_add_htlc                                update_add_htlc                                update_add_htlc                                 update_add_htlc                                  update_add_htlc                                  update_add_htlc                
     +-------------------------------+          +-----------------------------------+          +-----------------------------------+          +-------------------------------------+          +-------------------------------------+          +-------------------------------------+
     | channel_id: 1x2x3             |          | channel_id: 5x3x7                 |          | channel_id: 9x3x6                 |          | channel_id: 2x8x0                   |          | channel_id: 7x2x3                   |          | channel_id: 8x3x0                   |
     | htlc_id: 42                   |          | htlc_id: 17                       |          | htlc_id: 23                       |          | htlc_id: 31                         |          | htlc_id: 17                         |          | htlc_id: 33                         |
     | amount_msat: 55000            |          | amount_msat: 54000                |          | amount_msat: 52000                |          | amount_msat: 51000                  |          | amount_msat: 50500                  |          | amount_msat: 50000                  |
     | cltv_expiry: 1500             |          | cltv_expiry: 1450                 |          | cltv_expiry: 1300                 |          | cltv_expiry: 1200                   |          | cltv_expiry: 1150                   |          | cltv_expiry: 1000                   |
     | payment_hash: 0xabcd...       |          | payment_hash: 0xabcd...           |          | payment_hash: 0xabcd...           |          | payment_hash: 0xabcd...             |          | payment_hash: 0xabcd...             |          | payment_hash: 0xabcd...             |
     | onion_routing_packet:         |          | onion_routing_packet:             |          | onion_routing_packet:             |          | onion_routing_packet:               |          | onion_routing_packet:               |          | onion_routing_packet:               |
     | +---------------------------+ |          | +-------------------------------+ |          | +-------------------------------+ |          | +---------------------------------+ |          | +---------------------------------+ |          | +---------------------------------+ |
     | | amt_to_forward: 54000     | |          | | amt_to_forward: 54000         | |          | | amt_to_forward: 51000         | |          | | amt_to_forward: 51000           | |          | | amt_to_forward: 50500           | |          | | amt_to_forward: 50000           | |
     | | outgoing_cltv_value: 1450 | |          | | outgoing_cltv_value: 1450     | |          | | outgoing_cltv_value: 1200     | |          | | outgoing_cltv_value: 1200       | |          | | outgoing_cltv_value: 1150       | |          | | outgoing_cltv_value: 1000       | |
     | | short_channel_id: 5x3x7   | |          | | payment_secret: 0x1111...     | |          | | short_channel_id: 2x8x0       | |          | | payment_secret: 0x2222...       | |          | | payment_secret: 0x3333...       | |          | | payment_secret: 0x4444...       | |
     | +---------------------------+ |          | | total_amount: 54000           | |          | +-------------------------------+ |          | | total_amount: 51000             | |          | | total_amount: 50500             | |          | | total_amount: 50000             | |
     | |       (encrypted)         | |          | | trampoline_onion:             | |          | |         (encrypted)           | |          | | trampoline_onion:               | |          | | current_path_key: 0xd5b1...     | |          | | current_path_key: 0x73a5...     | |
     | +---------------------------+ |          | | +---------------------------+ | |          | +-------------------------------+ |          | | +-----------------------------+ | |          | | trampoline_onion:               | |          | | trampoline_onion:               | |
     +-------------------------------+          | | | outgoing_node_id: I3      | | |          +-----------------------------------+          | | | current_path_key: 0x7a3c... | | |          | | +-----------------------------+ | |          | | +-----------------------------+ | |
                                                | | | amt_to_forward: 51000     | | |                                                         | | | encrypted_recipient_data:   | | |          | | | encrypted_recipient_data:   | | |          | | | amt_to_forward: 50000       | | |
                                                | | | outgoing_cltv_value: 1200 | | |                                                         | | | +-------------------------+ | | |          | | | +-------------------------+ | | |          | | | outgoing_cltv_value: 1000   | | |
                                                | | +---------------------------+ | |                                                         | | | | cltv_expiry_delta: 50   | | | |          | | | | cltv_expiry_delta: 150  | | | |          | | | encrypted_recipient_data:   | | |
                                                | | |        (encrypted)        | | |                                                         | | | | fee_proportional: 0     | | | |          | | | | fee_proportional: 0     | | | |          | | | +-------------------------+ | | |
                                                | | +---------------------------+ | |                                                         | | | | fee_base_msat: 500      | | | |          | | | | fee_base_msat: 500      | | | |          | | | | path_id: 0xdeadbeef...  | | | |
                                                | +-------------------------------+ |                                                         | | | | short_channel_id: 7x2x3 | | | |          | | | | short_channel_id: 8x3x0 | | | |          | | | +-------------------------+ | | |
                                                | |              EOF              | |                                                         | | | +-------------------------+ | | |          | | | +-------------------------+ | | |          | | +-----------------------------+ | |
                                                | +-------------------------------+ |                                                         | | +-----------------------------+ | |          | | +-----------------------------+ | |          | | |             EOF             | | |
                                                +-----------------------------------+                                                         | | |         (encrypted)         | | |          | | |         (encrypted)         | | |          | | +-----------------------------+ | |
                                                                                                                                              | | +-----------------------------+ | |          | | +-----------------------------+ | |          | +---------------------------------+ |
                                                                                                                                              | +---------------------------------+ |          | +---------------------------------+ |          | |               EOF               | |
                                                                                                                                              | |               EOF               | |          | |               EOF               | |          | +---------------------------------+ |
                                                                                                                                              | +---------------------------------+ |          | +---------------------------------+ |          +-------------------------------------+
                                                                                                                                              +-------------------------------------+          +-------------------------------------+
```

Note that this also lets nodes inside the blinded path split the outgoing
payment in multiple parts if they have more than one channel with the next
node, which improves reliability.

#### Invoice without trampoline

If Carol doesn't support trampoline, Alice can still pay her invoice with
trampoline, but in that case she won't be able to include additional fields
in the payment for Carol (e.g. async payment fields).

Alice chooses a trampoline node in her own neighborhood and simply provides
the blinded paths in the trampoline onion. The trampoline node then forwards
the payment using those blinded paths, which ensures that it doesn't learn
the receiver's identity (only the blinded paths introduction nodes).

```text
        +---> N1 ---+                             +---> I4 ---+
        |           |                             |           |
Alice --+           +--> T1 -----> Bob ----> I3 --+           +--> Carol

<------------------------><------------------><------------------------>
     (normal payment)       (normal payment)       (blinded payment)
```

The `update_add_htlc` message sent by Alice to N1 looks like:

```text
                        update_add_htlc
+---------------------------------------------------------------------------+
| channel_id: 1x2x3                                                         |
| htlc_id: 42                                                               |
| amount_msat: 55000                                                        |
| cltv_expiry: 1500                                                         |
| payment_hash: 0xabcd...                                                   |
| onion_routing_packet:                                                     |
| +-----------------------------------------------------------------------+ |
| | +--------------------------------------------+----------------------+ | |
| | | amt_to_forward: 54000                      | normal onion payload | | |
| | | outgoing_cltv_value: 1450                  | for N1               | | |
| | | short_channel_id: 5x3x7                    |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +--------------------------------------------+----------------------+ | |
| | | amt_to_forward: 53000                      |                      | | |
| | | outgoing_cltv_value: 1400                  | normal onion payload | | |
| | | payment_secret: 0x1111...                  | for T1               | | |
| | | total_amount: 53000                        |                      | | |
| | | trampoline_onion:                          |                      | | |
| | | +---------------------------+------------+ |                      | | |
| | | | amt_to_forward: 50000     |            | |                      | | |
| | | | outgoing_cltv_value: 1000 | trampoline | |                      | | |
| | | | blinded_paths:            | payload    | |                      | | |
| | | |   <blinded_path_from_I1>  | for N1     | |                      | | |
| | | |   <blinded_path_from_I3>  |            | |                      | | |
| | | +---------------------------+------------+ |                      | | |
| | | |            EOF                         | |                      | | |
| | | +----------------------------------------+ |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +-------------------------------------------------------------------+ | |
| | |                                EOF                                | | |
| | +-------------------------------------------------------------------+ | |
| +-----------------------------------------------------------------------+ |
+---------------------------------------------------------------------------+
```

The `update_add_htlc` message sent by T1 to Bob looks like:

```text
                        update_add_htlc
+---------------------------------------------------------------------------+
| channel_id: 4x5x6                                                         |
| htlc_id: 13                                                               |
| amount_msat: 52000                                                        |
| cltv_expiry: 1300                                                         |
| payment_hash: 0xabcd...                                                   |
| onion_routing_packet:                                                     |
| +-----------------------------------------------------------------------+ |
| | +--------------------------------------------+----------------------+ | |
| | | amt_to_forward: 51000                      | normal onion payload | | |
| | | outgoing_cltv_value: 1200                  | for Bob              | | |
| | | short_channel_id: 5x3x7                    |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +--------------------------------------------+----------------------+ | |
| | | current_path_key: 0x7a3c...                |                      | | |
| | | encrypted_recipient_data:                  | blinded path         | | |
| | | +----------------------------------------+ | introduction onion   | | |
| | | | cltv_expiry_delta: 100                 | | payload for I3       | | |
| | | | fee_proportional_millionths: 0         | |                      | | |
| | | | fee_base_msat: 500                     | |                      | | |
| | | | short_channel_id: 8x1x9                | |                      | | |
| | | +----------------------------------------+ |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +--------------------------------------------+----------------------+ | |
| | | encrypted_recipient_data:                  |                      | | |
| | | +----------------------------------------+ | blinded path onion   | | |
| | | | cltv_expiry_delta: 100                 | | payload for I4       | | |
| | | | fee_proportional_millionths: 0         | |                      | | |
| | | | fee_base_msat: 500                     | |                      | | |
| | | | short_channel_id: 4x3x7                | |                      | | |
| | | +----------------------------------------+ |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +--------------------------------------------+----------------------+ | |
| | | amt_to_forward: 50000                      |                      | | |
| | | total_amount_msat: 50000                   | blinded path onion   | | |
| | | outgoing_cltv_value: 1000                  | payload for Carol    | | |
| | | encrypted_recipient_data:                  |                      | | |
| | | +----------------------------------------+ |                      | | |
| | | | path_id: 0xdeadbeef...                 | |                      | | |
| | | +----------------------------------------+ |                      | | |
| | +--------------------------------------------+----------------------+ | |
| | +-------------------------------------------------------------------+ | |
| | |                                EOF                                | | |
| | +-------------------------------------------------------------------+ | |
| +-----------------------------------------------------------------------+ |
+---------------------------------------------------------------------------+
```

## Privacy

Trampoline routing allows constrained devices to send and receive payments
without sacrificing privacy.

Such nodes are advised to sync only a small portion of the graph (their local
neighborhood) and to ensure connectivity to a few distinct trampoline nodes.

This allows them to insert normal hops before the first trampoline node, thus
protecting their privacy with the same guarantees as normal payments. In the
example graph from the previous section, T1 cannot know that the payment comes
from Alice because it only sees an HTLC coming from N1 (especially if Alice is
using an unannounced channel to N1). When T1 receives the HTLC, it cannot know
if the next node in the route (T2) is the final destination or not. Similarly,
T2 cannot know that Carol is the recipient nor that the payment comes from
Alice (T2 cannot even know that the previous trampoline node was T1).

When used with blinded paths, there is no need for multiple trampoline hops.
Even with a single trampoline node, the destination stays private.

## Trampoline MPP

Trampoline routing combines nicely with multi-part payments. When multi-part
payment is used, we can let trampoline nodes combine all the incoming partial
payments before forwarding. Once the totality of the payment is received, the
trampoline node can choose the most efficient way to re-split it to reach the
next trampoline node.

For example, Alice could split a payment in 3 parts to reach a trampoline node,
which would then split it in only 2 parts to reach the destination (we use a
single hop between trampoline nodes for simplicity here, but any number of
intermediate nodes may be used):

```text
                                                     HTLC(1500 msat, 600112 cltv)
                                                    +---------------------------+
                                                    | amount_fwd: 1500 msat     |
                                                    | expiry: 600112            |
            HTLC(1560 msat, 600124 cltv)            | payment_secret: aaaaa     |
             +-----------------------+              | total_amount: 2800 msat   |
             | amount_fwd: 1500 msat |              | trampoline_onion:         |                                                                  HTLC(1100 msat, 600000 cltv)
             | expiry: 600112        |              | +-----------------------+ |                                                                 +-----------------------------+
        +--> | channel_id: 3         | ---> I1 ---> | | amount_fwd: 2500 msat | | --+                                                             | amount_fwd: 1100 msat       |
        |    |-----------------------|              | | expiry: 600000        | |   |                                                             | expiry: 600000              |
        |    |     (encrypted)       |              | | node_id: Bob          | |   |                                                             | payment_secret: xxxxx       |
        |    +-----------------------+              | +-----------------------+ |   |                     HTLC(1150 msat, 600080 cltv)            | total_amount: 2500 msat     |
        |                                           | |      (encrypted)      | |   |                      +-----------------------+              | trampoline_onion:           |
        |                                           | +-----------------------+ |   |                      | amount_fwd: 1100 msat |              | +-------------------------+ |
        |                                           +---------------------------+   |                      | expiry: 600000        |              | | amount_fwd: 2500 msat   | |
        |                                           |             EOF           |   |                 +--> | channel_id: 561       | ---> I4 ---> | | expiry: 600000          | | --+
        |                                           +---------------------------+   |                 |    |-----------------------|              | | total_amount: 2500 msat | |   |
        |                                            HTLC(800 msat, 600112 cltv)    |                 |    |     (encrypted)       |              | | payment_secret: yyyyy   | |   |
        |                                           +---------------------------+   |                 |    +-----------------------+              | +-------------------------+ |   |
        |                                           | amount_fwd: 800 msat      |   |                 |                                           | |         EOF             | |   |
        |                                           | expiry: 600112            |   |                 |                                           | +-------------------------+ |   |
        |   HTLC(820 msat, 600130 cltv)             | payment_secret: aaaaa     |   |                 |                                           +-----------------------------+   |
        |    +-----------------------+              | total_amount: 2800 msat   |   |                 |                                           |             EOF             |   |
        |    | amount_fwd: 800 msat  |              | trampoline_onion:         |   |                 |                                           +-----------------------------+   |
        |    | expiry: 600112        |              | +-----------------------+ |   |                 |                                                                             |
Alice --+--> | channel_id: 5         | ---> I2 ---> | | amount_fwd: 2500 msat | | --+--> Trampoline --+                                                                             +--> Bob
        |    |-----------------------|              | | expiry: 600000        | |   |  (fee 170 msat) |                                            HTLC(1400 msat, 600000 cltv)     |
        |    |     (encrypted)       |              | | node_id: Bob          | |   |    (delta 32)   |                                           +-----------------------------+   |
        |    +-----------------------+              | +-----------------------+ |   |                 |                                           | amount_fwd: 1400 msat       |   |
        |                                           | |      (encrypted)      | |   |                 |                                           | expiry: 600000              |   |
        |                                           | +-----------------------+ |   |                 |                                           | payment_secret: xxxxx       |   |
        |                                           +---------------------------+   |                 |   HTLC(1480 msat, 600065 cltv)            | total_amount: 2500 msat     |   |
        |                                           |             EOF           |   |                 |    +-----------------------+              | trampoline_onion:           |   |
        |                                           +---------------------------+   |                 |    | amount_fwd: 1400 msat |              | +-------------------------+ |   |
        |                                            HTLC(500 msat, 600112 cltv)    |                 |    | expiry: 600000        |              | | amount_fwd: 2500 msat   | |   |
        |                                           +---------------------------+   |                 +--> | channel_id: 1105      | ---> I5 ---> | | expiry: 600000          | | --+
        |                                           | amount_fwd: 500 msat      |   |                      |-----------------------|              | | total_amount: 2500 msat | |
        |                                           | expiry: 600112            |   |                      |     (encrypted)       |              | | payment_secret: yyyyy   | |
        |   HTLC(510 msat, 600120 cltv)             | payment_secret: aaaaa     |   |                      +-----------------------+              | +-------------------------+ |
        |    +-----------------------+              | total_amount: 2800 msat   |   |                                                             | |         EOF             | |
        |    | amount_fwd: 500 msat  |              | trampoline_onion:         |   |                                                             | +-------------------------+ |
        |    | expiry: 600112        |              | +-----------------------+ |   |                                                             +-----------------------------+
        +--> | channel_id: 7         | ---> I3 ---> | | amount_fwd: 2500 msat | | --+                                                             |             EOF             |
             |-----------------------|              | | expiry: 600000        | |                                                                 +-----------------------------+
             |     (encrypted)       |              | | node_id: Bob          | |
             +-----------------------+              | +-----------------------+ |
                                                    | |      (encrypted)      | |
                                                    | +-----------------------+ |
                                                    +---------------------------+
                                                    |             EOF           |
                                                    +---------------------------+
```

## Trampoline fees

An important question that comes to mind if how senders choose the fee budget
that they allocate to each trampoline node. A previous version of this proposal
had extensions to the `node_announcement` message that contained trampoline fees.
However, this is different from channel relay fees, because since trampoline
nodes aren't necessarily directly connected to each other, fees may vary based
on the destination and the liquidity available along those paths.

This mechanism was dropped in favor of a trial-and-error approach: whenever
trampoline nodes are unable to relay a payment because the fee budget is not
sufficient to reach the next trampoline node, they return an error to the
sender that contains the fees that would likely work for that payment, and
the sender may retry the payment with those values.

This mechanism is inefficient when many trampoline nodes are used. However,
the most common scenario will be to use a single trampoline node (when using
blinded paths) or two trampoline nodes (mobile-to-mobile payments). In those
cases, the trial-and-error approach works well.

We may want to add a gossip mechanism later to communicate fees if we feel
that the trial-and-error approach is too limiting for some use-cases.

## Future gossip extensions

With the current gossip mechanisms, some bandwidth will be unnecessarily wasted
when constrained nodes sync their local neighborhood, because they have no way
of asking for `channel_update`s within a given distance boundary nor telling
their peers to *not* relay some updates to them.

That can be easily addressed in the future with new Bolt 7 gossip queries, but
is not mandatory to the deployment of trampoline routing.

Two mechanisms in particular would be useful:

* `channel_update` filters: constrained nodes can ask their peers to discard
  updates coming from nodes that are further than N hops instead of relaying
  them.
* distance-based gossip queries: constrained nodes can ask their peers for all
  updates from nodes that are at most N hops far, and combine that with the
  current gossip query tricks to avoid replaying updates they already have.

## Why not rendezvous routing

While rendezvous routing shares some properties with trampoline routing and may
be more private, it's also less flexible: payers cannot add data to the partial
onion for the recipient nor change existing data. The amount and expiry must be
fixed ahead of time in the partial onion, which means MPP cannot be used, and
holding payments at trampoline nodes for often-offline mobile wallets (e.g. for
https://github.com/lightning/bolts/pull/1149) is not possible either (whereas
the expiry can be simply omitted from the trampoline onion to make this
possible).
