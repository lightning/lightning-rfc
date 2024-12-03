# BOLT #14: Friend of a friend Balance Sharing

WIP: in particular it is not clear if this will be its own BOLT together with fee free rebalancing and JIT routing or an extension of BOLT 07 or BOLT 02

## Overview
This document describes a collection of techniques that will help nodes to improve their (and consequently the networks) ability to find paths with enough liquidity to route a payment from a sender to the recipient. 

It contains recommendations for nodes to enable them to have better liquidity and channel management. Topics contain: 
 sharing balance information within the friend of a friend network which is done with the `query_foaf_balances` and the `reply_foaf_balances` message. 
A Recommendation of how nodes should allocate their funds to their channels to increase their (and consequently the networks) ability to find payment paths.
A protocol for fee free rebalancing operations to move liquidity between payment channels along a circular path. 
The specification of the proactive channel rebalancing algorithm and the JIT Routing (Just in Time Routing) scheme which are very similar with the respect to the used Lightning Messages and used algorithms.

Most of the ideas and techniques in this BOLT are inspired by recent research: https://arxiv.org/abs/1912.09555 

It might in future also include techniques like:
* techniques for cancable stuck payments (requires Schnorr signatures)
* Redundant multipath payments with the Boomerang construction (requires Adaptor Signatures)

### The `query_foaf_balances` and `reply_foaf_balances` Messages

A node can ask its peers to share balance information via `query_foaf_balances` message. Nodes SHOULD respond with a `reply_foaf_balances` message. However they MAY also proactively share on which channels they would like to have rebalancing by sending out a `reply_foaf_balances` message.
The information spread in these messages is MUST NOT be gossiped and forwarded to other peers. Thus the name foaf ( = friend of a friend ). A node will only be able to gain information about the friends of its friends. 

No exact balance information is being sent and shared in these two messages. They rather indicate the desire to initiate a rebalance operation with a certain amount. 

`query_foaf_balances` 
1. type: 347  (`query_foaf_balances`) (`peer_queries`)
2. data:
    * [`chain_hash: chain_hash`]
    * [`byte: flow_value`] 
    * [`u64: amt_to_rebalance`]

`reply_foaf_balances` 
1. type:  (`reply_foaf_balances`) (`peer_queries`)
2. data:
    * [`chain_hash: chain_hash`]
    * [`byte: flow_value`] 
    * [`u64: timestamp`]
    * [`u64: amt_to_rebalance`]  
    * [`u16:len`]
    * [`len*u64: short_channel_id`] 

TODO: we have to fix feature bits 20/21 would be the next feature bits, informations for BOLT9: 20/21, option_balance_sharing, Balance sharing in the context of JIT-Routing, IN, dependencies?, link to BOLT #14

#### Requirements:
The sender of `query_foaf_balances` and `reply_foaf_balances` messages must set the chain hash to the hash of the genesis block of the underlying blockchain of the payment channels they want to share information about.

* A node MUST have an active channel with the peer before sending a `query_foaf_balances` or `reply_foaf_balances` message 
* If a node receives a `query_foaf_balances` or `reply_foaf_balances` message without having an active payment channel with that peer it SHOULD fail the connection. 

* The sender of a `query_foaf_rebalance` message SHOULD set `flow_value` to 1 if he intends to forward funds along his channels with the recipient
* The sender of a `reply_foaf_rebalance` message SHOULD set `flow_value` to 1 if he offers to forward `amt_to_rebalance` along the channels in the `reply_foaf_balances` message.
* The sender of a `query_foaf_rebalance` message  SHOULD set `flow_value` to 0 if he wants to receive funds for rebalancing along his channels with the recipient. 
* The sender  of a `reply_foaf_rebalance` message SHOULD set `flow_value` to 0 if he is willing to receive `amt_to_rebalance` along the channels in the `reply_foaf_balances` message

* The sender of a `query_foaf_balances` message SHOULD set `amt_to_rebalance` at least to the value he intends to rebalance. 
* The sender  of a `query_foaf_balances` message  MAY set a higher `amt_to_rebalance` in order to obfuscate the leak of information about the current outstanding routing request.
* The recipient  of a `query_foaf_balances` message  SHOULD only reply with channels that he is willing to rebalance the `amount_to_rebalance` in the direction of `flow_value`.
* The recipient  of a `query_foaf_balances` message  SHOULD use at least the same `amt_to_rebalance` value in the `reply_foaf_balances`. 
* The recipient  of a `query_foaf_balances` message MAY use a lower `amt_to_rebalance` value in the `reply_foaf_balances` message.

* The recipient SHOULD set an actual wall clock `timestamp` in the `reply_foaf_balances` message. 
* When receiving an `reply_foaf_balances` message a node SHOULD check if it already has a message with a more recent `timestamp` for these `short_channel_ids` with this `flow_value`. If yes it MAY discard those `short_channel_ids`
* If the recipient of a `reply_foaf_balances` message observes a `timestamp` that is too far in future he MAY fail the connection.

* The sender of a `reply_foaf_balances` message SHOULD only include channels which are operational (meaning established, not in the closing process and with a live peer connection)
* The sender of a `reply_foaf_balances` MAY obfuscate its reply by omitting channels which fulfil the requirement or it MAY add channels which do not fulfill the requirements. 

* A node SHOULD not send more than 4 `query_foaf_balance` or 4 `reply_foaf_balances` messages to the same peer within 10 seconds. 
* A node MUST not include more than 1000 `short_channel_ids` in a `reply_foaf_balances` query.
* If a node has more than 1000 eligible channels for a `reply_foaf_balances` message it SHOULD sample up to 1000 channels following a uniform distribution. 
* A node MUST NOT include unannounced channels in the `reply_foaf_balances` message
* If a node receives unknown `short_channel_ids` in the `reply_foaf_balances` message it MUST discard those. 
* If a node receives a `reply_foaf_balances` message with more than 1000 `short_channel_ids` it should fail the connection. 

#### Rationale: 

Of course nodes can send out the queries frequently to gather balance information about the channels of their neighbours. However three things limit privacy problems arising from this
Nodes are not required to respond to the `query_foaf_balance` message
Nodes MAY obfuscate the information in the `reply_foaf_balance` message
Probing channel balances is already a possible (and for the network expensive) attack vector. In particular probing the FOAF network is easily achievable so nodes might as well already share this information
It has been shown (https://arxiv.org/abs/2004.00333) that when these messages are used to implement JIT routing probing of channel balances becomes impossible. 

Also it has been shown that it is beneficial for routing success if nodes try to minimize the imbalance of their channels. For this nodes should aim to have the same relative balance in each channel. 

TODO: What about multiple channels between two nodes? I would consider them in the calculation as one large channel

### Channel Management

### Fee free rebalancing protocol

### JIT Routing


## References

1. tba

![Creative Commons License](https://i.creativecommons.org/l/by/4.0/88x31.png "License CC-BY")
<br>
This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).
