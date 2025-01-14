# Local Resource Conservation

## Table of Contents
* [Introduction](#introduction)
* [Overview](#overview)
* [Local Reputation](#local-reputation)
  * [Recommendations for Reputation Scoring](#recommendations-for-reputation-scoring)
    * [Effective HTLC Fees](#effective-htlc-fees)
    * [Outgoing Channel Revenue](#outgoing-channel-revenue)
    * [Incoming Channel Revenue](#incoming-channel-revenue)
    * [In Flight HTLC Risk](#in-flight-htlc-risk)
* [Resource Bucketing](#resource-bucketing)
* [Implementation Notes](#implementation-notes)
  * [Decaying Average](#decaying-average)
  * [Multiple Channels](#multiple-channels)

## Introduction
Channel jamming is a known denial-of-service attack against the Lightning 
Network. An attacker that controls both ends of a payment route can disrupt 
usage of a channel by sending payments that are destined to fail through a 
target route. Fees are currently only paid to routing nodes on successful 
completion of a payment, so this attack is virtually free - the attacker pays 
only for the costs of running a node, funding channels on-chain and the 
opportunity cost of capital committed to the attack.

A channel can be fully jammed by depleting its available HTLC slots by holding 
`max_accepted_htlcs` or its available liquidity by holding the 
`max_htlc_value_in_flight`. An economically rational attacker will pursue the 
attack method with the lowest cost and highest utility. An attack can exhaust 
the resources along the target route in two ways, though the difference 
between the two behaviors is not rigorously defined:
* Quick Jamming: sending a continuous stream of payments through a route that 
  are quickly resolved, but block all of the liquidity or HTLC slots along the 
  route.
* Slow Jamming: sending a slow stream of payments through a route and only 
  failing them at the latest possible timeout, blocking all of the liquidity 
  or HTLC slots along the route for the duration.

This document outlines recommendations for implementing local resource 
conservation to mitigate slow jamming attacks. It is part of a hybrid solution 
to mitigating channel jamming, intended to be followed by the introduction of 
unconditional fees to mitigate fast jamming.

## Overview
Local resource conservation combines the following elements to provide nodes 
with a mechanism to protect themselves against slow-jamming attacks:

* [HTLC Endorsement](#../02-peer-protocol.md#adding-an-htlc-update_add_htlc): 
  propagation of a signal along the payment route that indicates whether the 
  node sending `update_add_htlc` recommends that the HTLC should be granted 
  access to downstream resources (and that it will stake its reputation on the 
  fast resolution of the HTLC).
* [Local Reputation](#local-reputation): local tracking of the historical 
  forwarding behavior of channel peers, used to decide whether to grant 
  incoming HTLCs full access to local resources and whether to propagate 
  endorsement downstream.
* [Resource Bucketing](#resource-bucketing): reservation of a portion of 
  "protected" liquidity and slots for endorsed HTLCs that have been forwarded 
  by high reputation nodes. 

Sequence: 
* The `update_add_htlc` is sent by an upstream peer.
* If the sending peer has sufficient local reputation (per the receiving 
  peer's view) AND the incoming HTLC was sent with a non-zero `endorsed` TLV: 
  * The HTLC will be allowed access to the "protected" bucket, so will have 
    full access to the channel's liquidity and slots, 
  * The corresponding outgoing HTLC (if present) will be forwarded with 
    `endorsed` set to `1`.
* Otherwise: 
  * The HTLC will be limited to the remaining "general" slots and liquidity, 
    and will be failed if there are no resources remaining in this bucket.
  * The corresponding outgoing HTLC (if present) will be forwarded with 
    `endorsed` set to `0`.

In the steady state when Lightning is being used as expected, there should be 
no need for use of protected resources as channels are not saturated during 
regular operation. Should the network come under attack, honest nodes that 
have built up reputation over time will still be able to utilize protected 
resources to process payments in the network.

## Local Reputation

### Recommendations for Reputation Scoring
Local reputation can be used by forwarding nodes to decide whether to allocate 
resources to and signal endorsement of a HTLC on the outgoing channel. Nodes MAY 
use any metric of their choosing to classify a peer as having sufficient 
reputation, though a poor choice of reputation scoring metric may affect their 
reputation with their downstream peers. 

The goal of this reputation metric is to ensure that the cost to obtain 
sufficient reputation for a HTLC to be endorsed on the outgoing channel is 
greater than the damage that a node can inflict by abusing the access that it 
is granted. This algorithm uses forwarding fees to measure damage, as this value 
is observable within the protocol. It is reasonable to expect an adversary to 
"about turn" - to behave perfectly to build up reputation, then alter their 
behavior to abuse it. For this reason, in-flight HTLCs have a temporary 
negative impact on reputation until they are resolved.

If granted full access to a node's liquidity and slots, the maximum amount of 
damage that can be inflicted on the targeted node is bounded by the largest 
cltv delta from the current block height that it will allow a HTLC to set 
before failing it with [expiry_too_far](../04-onion-routing.md#failure-messages).
This value is typically 2016 blocks (~2 weeks) at the time of writing.

Upon receipt of `update_add_htlc`, the local node considers the following to 
determine whether the sender is classified as having sufficient reputation: 
* Outgoing channel revenue: the total routing fees over the maximum allowed HTLC 
  hold period (~2 weeks) that the outgoing channel has earned the local node, 
  considering both incoming and outgoing HTLCs that have used the channel.
* Incoming channel revenue: the total routing fees that the incoming channel has 
  earned the local node, considering only incoming HTLCs on the channel.
* In-flight HTLCs risk: any endorsed HTLC that the incoming channel has 
  in-flight on the requested outgoing channel negatively affect reputation, 
  based on the assumption that they will be held until just before their 
  expiry height.

On a per-HTLC basis, the local node will classify the sending node's 
reputation for the offered HTLC as follows: 
* if `incoming_channel_revenue - in_flight_risk >= outgoing_channel_revenue`: 
  * the sending node is considered to have *sufficient* reputation for the 
    offered HTLC.  
* otherwise, the sending node is considered to have *insufficient* reputation 
  for the offered HTLC.

The sections that follow provide details of how to calculate the components of 
the inequality.

#### Effective HTLC Fees
The contribution that the fees paid by a HTLC make to reputation standings is 
adjusted by the amount of time that a HTLC took to resolve. By accounting for 
the "opportunity cost" of HTLCs that are held for longer periods of time, the 
reputation score rewards fast resolving, successful payments and penalizes 
slow resolving payments (regardless of successful resolution).

We define the following parameters: 
* `resolution_period`: the amount of time a HTLC is allowed to resolve in that 
  classifies as "good" behavior, expressed in seconds. The recommended default 
  is 90 seconds (given that the protocol allows for a 60 second MPP timeout). 
* `resolution_time`: the amount of time elapsed in seconds between a HTLC being 
  added to and removed from the local node's commitment transaction. 
* `fees`: the fees that are offered to the local node to forward the HTLC, 
  expressed in milli-satoshis.

We define the `opportunity_cost` of the time a HTLC takes to resolve:
`opportunity_cost`: `ceil ( (resolution_time - resolution_period) / resolution_period) * fees`

Given that `resolution_time` will be > 0 in practice, `opportunity_cost` is 0 
for HTLCs that resolve within `resolution_period`, and charges the `fees` that 
the HTLC would have earned per period it is held thereafter. This cost accounts 
for the slot and liquidity that could have otherwise been paid for by 
successful, fast resolving HTLCs during the `resolution_time` the HTLC was 
locked in the channel.

Each HTLC's contribution to reputation is expressed by its `effective_fee` 
which is determined by its endorsement, resolution time and outcome: 
* if `endorsed` is non-zero in `update_add_htlc`:
  * if successfully resolved with `update_fulfill_htlc`: 
    * `effective_fees` = `fees` - `opportunity_cost` 
  * otherwise: 
    * `effective_fees` = -`opportunity_cost` 
* otherwise: 
  * if successfully resolved AND `resolution_time` <= `resolution_period`
    * `effective_fees` = `fees`
  * otherwise: 
    * `effective_fees` = 0

##### Rationale
Reputation is negatively affected by slow-resolving HTLCs (regardless of whether
they are settled or failed) to ensure that reputation scoring reacts to bad 
behavior. HTLCs that resolve within a period of time that is considered 
reasonable do not decrease reputation, as some rate of failure is natural in 
the network.

The resolution of HTLCs with `endorsed` set to `0` do not have a negative 
impact on reputation because the forwarding node made no promises about their 
behavior. They are allowed to build reputation when they resolve successfully 
within the specified `resolution_period` to allow new nodes in the network to 
bootstrap reputation. 

#### Outgoing Channel Revenue
Outgoing channel revenue measures the damage to the local node (ie, the loss in 
forwarding fees) that a slow jamming attack can incur. For an individual 
channel, this is equal to the total revenue forwarded in both directions over 
the maximum allowed HTLC hold time.

We define the following parameters: 
* `outgoing_revenue_window`: the largest cltv delta from the current block 
  height that a node will allow a HTLC to set before failing it with 
  [expiry_too_far](../04-onion-routing.md#failure-messages), expressed in 
  seconds (assuming 10 minute blocks).

We define the `outgoing_channel_revenue`: 
* for each `update_add_htlc` processed on the outgoing channel over the rolling 
  window [`now` - `outgoing_revenue_window`; `now`]:
  * if the HTLC has been resolved: 
    * `outgoing_channel_revenue` += `fee`

##### Rationale
We consider bi-directional HTLC forwards on the outgoing channel to properly 
account for the potential loss of a jamming attack - even when fees don't 
accrue on the channel, it is pairwise valuable to the local node. In flight 
HTLCs have no impact on outgoing channel revenue, as their fee contribution is 
unknown.

#### Incoming Channel Revenue
Incoming channel revenue measures the unforgeable history that the incoming 
channel has built with the local node via payment of forwarding fees. As this 
value aims to capture the contribution of the channel (rather than its value 
to the local node), only incoming HTLCs are considered. 

We define the following parameters: 
* `incoming_revenue_multiplier`: a multiplier applied to 
  `outgoing_revenue_window` to determine the rolling window over which the 
  incoming channel's forwarding history is considered (default 10).

We define the `incoming_channel_revenue`: 
* for each incoming `update_add_htlc` processed on the incoming channel over 
  the rolling window [`now` - `outgoing_channel_window` * 
  `incoming_channel_multiplier`; `now`]: 
  * if the HTLC has been resolved: 
    * `incoming_channel_revenue` += `effective_fee(HTLC)`

##### Rationale
For the incoming channel, only HTLCs that they have forwarded to the local 
node count torwards their unforegable contribution to building reputation, as 
they push fees to the local node. While the incoming channel may be valuable 
as a sink (or predominantly outgoing) channel, the HTLCs that the local node 
has forwarded outwards do not represent fees paid by a potential attacker.

#### In Flight HTLC Risk
Whenever a HTLC is forwarded, we assume that it will resolve with the worst 
case off-chain resolution time and dock reputation accordingly. This decrease 
will be temporary in the case of fast resolution, and preemptively slash 
reputation in the case where the HTLC is used as part of a slow jamming attack.

We define the following parameters: 
* `height_added`: the block height at which the HTLC was irrevocably committed 
  to by the local node.

We define the `outstanding_risk` of in-flight HTLCs: 
* `outstanding_risk` = `fees` * ((`cltv_expiry` - `height_added`) * 10 * 60) / `resolution_period`

We define the `in_flight_htlc_risk` for an incoming channel sending 
`update_add_htlc`:
* `in_flight_htlc_risk` = `outstanding_risk(proposed update_add_htlc)`
* for each HTLC originating from the incoming channel:
  * if `endorsed` is non-zero: 
    * `in_flight_htlc_risk` += `outstanding_risk(HTLC)`

##### Rationale
In flight HTLC are included in reputation scoring to account for sudden changes
in a peer's behavior. Even when sufficient reputation is obtained, each HTLC 
choosing to take advantage of that reputation is treated as if it will be used 
to inflict maximum damage. The expiry height of each incoming in flight HTLC is 
considered so that risk is directly related to the amount of time the HTLC 
could be held in the channel. Ten minute blocks are assumed for simplicity.

## Resource Bucketing
When making the decision to forward a HTLC on its outgoing channel, a node 
MAY choose to limit its exposure to HTLCs that put it at risk of a denial of 
service attack.

We define the following parameters:
* `protected_slot_count`: defines the number of HTLC slots that are reserved 
  for endorsed HTLCs from peers with sufficient reputation (default: 0.5 * 
  remote peer's `max_accepted_htlcs`).
* `protected_liquidity_portion`: defines the portion of liquidity that is 
  reserved for endorsed HTLCs from peers with sufficient reputation (default: 
  0.5).

A node implementing resource bucketing limits exposure on its outgoing channel:
* MUST choose `protected_slot_count` <= the remote channel peer's 
  `max_accepted_htlcs`.
* MUST choose `protected_liquidity_portion` in [0;1].

For each `update_add_htlc` proposed by an incoming channel:
* If `endorsed` is non-zero AND the incoming channel has sufficient local 
  reputation for the HTLC (see [Recommendations for Reputation Scoring](#recommendations-for-reputation-scoring)):
  * SHOULD forward the HTLC as usual.
  * SHOULD set `endorsed` to 1 in the outgoing `update_add_htlc`.
* Otherwise: 
  * SHOULD reduce the remote peer's `max_accepted_htlcs` by 
    `protected_slot_count` for the purposes of the proposed HTLC.
  * SHOULD reduce the `max_htlc_value_in_flight` by 
    `protected_liquidity_portion` * `max_htlc_value_in_flight`.
  * SHOULD set `endorsed` to `0` in the outgoing `update_add_htlc`.

## Implementation Notes

### Decaying Average
Rolling windows specified in this write up may be implemented as a decaying 
average to minimize the amount of data that needs to be stored per-channel. In 
flight HTLCs can be accounted for separately to this calculation, as the node 
will already have data for these HTLCs available.

Track the following values for each rolling window: 
* `last_update`: stores the timestamp of the last update to the decaying 
    average, expressed in seconds.
* `decaying_average`: stores the value of the decaying average.
* `decay_rate`: a constant rate of decay based on the rolling window chosen, 
  calculated as: `((1/2)^(2/window_length_seconds))`.

To update the `decaying_average` at time `t`:
* `last_update_diff` = `now` - `last_update`.
* `decaying_average` = `decaying_average` * `decay_rate` ^ `last_update_diff`.
* `last_update` = `t`.

When assessing whether a peer has sufficient reputation for a HTLC: 
* MUST update `decaying_average` as described above.

When updating the `decaying_average` to add the `effective_fee` of a newly 
resolved HTLC at timestamp `t`: 
* MUST update `decaying_average` as described above.
* `decaying_average` = `decaying_average` + `effective_fee`

### Bootstrapping Outgoing Channel Revenue
New channels with no revenue history: 
* MAY choose not to endorse any HTLCs in their first two weeks of operation 
  to establish baseline revenue.
* MAY choose to use `outgoing_channel_revenue` for a similar channel as a 
  default starting point for scoring reputation.

### Multiple Channels
If the local node has multiple channels open with the incoming and outgoing 
peers:
* MAY consider `incoming_channel_revenue` across all channels with the peer 
  when assessing reputation.
* MAY consider `outgoing_channel_revenue` for all channels with the outgoing 
  peer, but SHOULD take care to [bootstrap](#bootstrapping-outgoing-channel-revenue)
  new channels so they do not lower the reputation threshold for existing ones.
* SHOULD calculate `outgoing_channel_revenue` for the channel that is selected 
  for [non-strict-forwarding](../04-onion-routing.md#non-strict-forwarding) 
  forwarding.

