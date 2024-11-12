# Staking Credentials

This document specifies the Staking Credentials architecture and requirements for its constituents
protocols used for constructing anonymous credentials mechanisms in the context of Bitcoin financial
contracts and Civkit functionary services.

This draft is version 0.0.1 of the Staking Credentials architecture.

## Introduction

Staking Credentials is an architecture for Bitcoin financial contracts based on anonymous credentials.
Those credentials are not only unlinking their issuance from their consumption, but also allows the
user staking of credentials to downgrade the costs of entering in future Bitcoin financial contracts
or accessing Civkit functionary services. The quality and thresholds of assets can be selected with
granularity by the contract provider to achieve a satisfying level of risks, combining monetary and
reputation strategies.

Staking Credentials approach is the following: the clients presents a basket of scarce assets
(Lightning preimage, stakes certificates) and blinded credentials to the issuance server, the credentials
are authenticated and yeilded back to the client. Once unblinded the credentials can be used to fulfill
a contract or service request towards a service provider server. The credentials are anonymous in
the sense that a given credential cannot be linked to the protocol instance in which that credential
was initially issued.

The Staking Credentials architecture consists of two protocols: credentials issuance and redemption.
The issuance protocol runs between two endpoints referred to as Requester and Issuer and one
function: Credential Authentication. The entity that implements the Credential Authentication,
referred to as the Issuer, is responsible for counter-signing the credentials in response to requests
from Requester. Issuer might accept different base assets in function of their risk strategy, and
the overhead cost they would like to transfer on the Committer for answering a contract or service
request. Requester and Issuer can agree on an Authentication method in function of the cryptographic
properties aimed for.

The redemption protocol runs between two endpoint reffered to as Client and Provider and
one function: Credential Consumption. The entity that implements the Credential Consumption, referred
to as the Client, is responsible to provide an authenticated Credential covering the contract risk
service request risk, as defined by the Provider. A Client can be a Provider, but those entities
can be also dissociated. An Issuer can be a Provider, but those entities can be also dissociated.
A Client can aggregate authenticated Credentials from multiple Requesters.

The credentials issuance and redemption protocols operate in concert as shown in the figure below:

```
		 ___________						        ____________
		|	    |      1. Scarce Asset + Blinded Credentials       |	    |
		|	    |------------------------------------------------->|  	    |
		|	    |						       |	    |
		| Requester |						       |   Issuer   |
          ------|	    |	   2. Authenticated Binded Credentials         |	    |
          |	|	    |<-------------------------------------------------|	    |
	  |	|___________|						       |____________|
	  |										 ^
	  |										 |
	  |  3. Authenticated Unblinded Credentials					 |
	  |										 |
	  |				       5. Credentials Authentication Validation	 |
	  |										 |
	  |										 |
	 _V__________								    _____|________
	|	     |  4. Authenticated Unblinded Credentials + Service Request   |		  |
	|	     |------------------------------------------------------------>|		  |
	|	     |								   |		  |
	|   Client   |								   |   Provider   |
	|	     |         6. Contract Acceptance OR Contract Reject	   |		  |
	|	     |<------------------------------------------------------------|		  |
	|____________|								   |______________|

```

This documents describes requirements for both issuance and redemption protocols. It also provides
recommendations on how the architecture should be deployed to ensure the economic effectiveness of
assets, the compatibility of incentives, the conservation of the client UX, the privacy and security
and the decentralization of the ecosystem.

## Terminology

The following terms are used throughout this document.

- Client: An entity that pledges a Credential as assets to redeem a Contract or Service Request.
- Requester: An entity that commit a set of scarce assets to redeem an authenticated Credential from an Issuer.
- Issuer: An entity that accept a scarce asset in exchange of authenticating a Credential.
- Provider: An entity that accept a set of Credentials as payment in case of Contract risk or Service providance to the client.

## Architecture

The Staking Credentials architecture consists of four logical entities -- Client, Issuer, Requester, Provider --
that work in concert for credentials issuance and redemption.

## Credentials Issuance

The credentials issuance is an authorization protocol wherein the Requester presents scarce asset and
blinded credentials to the Issuer for authorization. Usually, the rate of scarce assets to credentials
as placed by the Issuer should have been discovered by the Committer in non-defined protocol phase.

There are a number of scarce assets that can serve, including (non-limited):
- proof-of-payment (e.g Lightning preimage or on-chain txid)
- ecash token
- stakes certificates
- "faithful usage" reward

Issuer should consider which base assets to accept in function of the risk-management strategy they adopt. If
they aim for a 0-risk coverage, where all the contract or service execution risk is transferred on the counterparty,
they should pick up the default of on-chain/off-chain payment, where each contract cost unit should be covered by
a satoshi unit.

The credential issuance can be deployed as "native" or "reward".

In the "native" flow, a scarce asset for credential authentication should be exchanged a priori of a redemption phase:

```
		 ___________					    ____________
		|	    |	  1. Scarce asset + Credentials    |	        |
		|           |------------------------------------->|	        |
		|           |					   |	        |
		| Committer |					   |   Issuer   |
		|	    |	  2. Authenticated Credentials	   |		|
		|	    |<-------------------------------------|		|
		|___________|					   |____________|

```

In the "reward" context, one type of scarce asset, i.e contract fees are paid by the Client to the Provider,
a posteriori of a successful redemption phase. A quantity of authenticated credentials should be given
from the linked Issuer, back to the Committer:

```
	         ____________										
		|	     |						  ______________
		|	     |					         |		|
		|	     |						 |		|
		|   Client   |      1. Contract or Service fees		 |		|
		|	     |------------------------------------------>|   Provider   |
		|	     |						 |		|
		|____________|						 |		|
									 |______________|
										|
							 ____________		|
		 _____________				|	     |		|
		|	      |				|	     |		|
		|	      |				|	     |		|
		|	      |	   3. Authenticated	|   Issuer   |<----------
		|  Requester  |        Credentials	|	     |
		|	      |<------------------------|	     |  2. Unauthenticated Credential Callback
		|	      |				|____________|
		|_____________|

```

During issuance, the credentials should be blinded to ensure future unlinkability during the redemption phase.

Discovery of assets-to-credentials announced by the Issuer and consumed by the Client should be defined in
its own document.

A privacy-preserving communication protocol between Client and Issuer for credentials issuance should
be defined in its own document.

## Redemption

The redemption protocol is an identification protocol wherein the Client presents authenticated credentials
to the Provider to redeem the acceptance of a contract. The credentials should be unblinded before to be
presented to the Provider. The quantity of credentials attached to the contract request should
satisfy the contract liquidity units as enforced by the Contract Provider. Usually, the rate of credentials
to contract/service unit announced by the Provider should have been discovered by the Committer in a non-defined
protocol phase.

The protocol works as in the figure below:

```
					1. Authenticated Unblinded Credential
	 ____________			      		    +		      		      ______________
	|	     |				Contract/Service Request    		     |		    |
	|	     |---------------------------------------------------------------------->|		    |
	|	     |									     |		    |
	|   Client   |									     |   Provider   |
	|	     |        2. Contract/Service Acceptance OR Contract/Service Reject	     |		    |
	|	     |<----------------------------------------------------------------------|		    |
	|____________|									     |______________|
												    |
												    | 3. Contract/Service
												    | 	    Execution
												    |------------------------>
```

Depending on the contract execution outcome (success or failure), an additional fee can be paid by the Client
to the Provider. This fee should be determined in function of market forces constraining the type of contract/service
executed.

### Redemption Protocol Extensibility

The Staking Credentials and redemption protocol are both intended to be receptive to extensions that expand
the current set of functionalities through new types or modes of Bitcoin financial contracts covered. Among them,
long-term held contracts based on a timelock exceeding the usual requirements of Lightning payments.
Another type of flow is the correction of the opening asymmetries in multi-party Lightning channels funding transactions.

## Deployment Considerations

### Lightning HTLC routing

In this model, a HTLC forwarder (Committer) send an off-chain payment and a list of blinded credentials to a Routing hop (Issuer).
The Routing hop counter-sign the blinded credentials and send them back to the HTLC forwarder (Credentials Authentication phase).
The HTLC forwarder (Client) unblinds the credential, attach a HTLC and send the request for acceptance to the Routing hop (Contract
Provider). If the quantity of credentials attached satisfies the Routing hop, the HTLC is accepted and forward to the next hop
in the payment path.

This model is shown below:

```
		 _____________	   1. Off-chain payment + Blinded Credentials	      ____________
		|	      |----------------------------------------------------->|		  |
		|	      |							     |		  |
		|     HTLC    |	      2. Counter-signed Blinded Credentials 	     |  Routing   |  4. HTLC relay
		|  forwarder  |<-----------------------------------------------------|    hop     |--------------->
		|	      |							     |		  |
		|	      |	     3. Unblinded Credentials + HTLC forward 	     |		  |
		|_____________|----------------------------------------------------->|____________|

```


## Security Considerations

The major security risk from an Issuer perspective is the double-spend of the credentials by a Client. In
the context of the Staking Credential architecture, a double-spend is the replay of credential for multiple
Contract requests, therefore provoking a plain timevalue loss if contract fees are not paid by the Client for
each Contract request instance.

The Issuer should keep a private database to log every credential covering a Contract request. This private
database should be accessible by the Contract Provider to validate all the credentials presented for a Contract
request.

A major security risk from a Committer perspective is the tampering of the credentials during transport between
the Committer and Issuers hosts. Credentials could be hijacked based on credentials volume traffic monitoring. As
such credentials transport should be authenticated and the packets obfuscate against network-level inspection.

## References

- [Privacy Pass Architecture](https://www.ietf.org/archive/id/draft-ietf-privacypass-architecture-09.html)
- [Mitigating Channel Jamming with Stakes Certificates](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-November/002884.html)
- [Solving channel jamming issue of the lightning network](https://jamming-dev.github.io/book/about.html)
- [Discreet Log Contracts specification](https://github.com/discreetlogcontracts/dlcspecs/)
- [Lightning interactive transaction construction protocol](https://github.com/lightning/bolts/pull/851)

## Copyright

This document is placed in the public domain.
