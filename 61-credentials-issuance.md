# Credential Issuance

This document specifies the Credentials Issuance protocol inside the Staking Credentials framework.

The messages data format, validation algorithms and implementation considerations are laid out.

This draft is version 0.0.1 of the Credential Issuance protocol.

## Credentials Issuance

The Requester is sending a proof of scarce assets to the Issuer.

The Issuer is sending back an authentication of the scarce assets to the Requester.

	+-------+						  +-------+
	|	|						  |	  |
	|	|						  |	  |
	|	|--(1)--- request_credentials_authentication ---->|	  |
	|   A   |						  |   B	  |
	|	|						  |	  |
	|	|<-(2)--- reply_credentials_authentication -------|	  |
	|	|						  |	  |
	|	|						  |	  |
	+-------+						  +-------+


### The `request_credentials_authentication` message

This message contains a proof of scarce asset for the credentials and a set of unsigned blinded credentials.

1. type: 37560 (`request_credentials_authentication`)
2. data:
    * [`u32`: `session_id`]
    * [`point`: `issuance_pubkey`]
    * [`assetlen*byte`: `scarce_assets`]
    * [`credentiallen*byte`: `blinded_credentials`]

#### Requirements

The sender:
  - MUST set `session_id` to a pseudo-randomly generated 4-byte value.
  - MUST set `issuance_pubkey` to a public key discovered from a `credential_policy` issued by the receiver.
  - MUST NOT send `scarce_assets` if they have not been announced by a previous `credential_policy` issued by this node.
  - MUST NOT send `blinded_credentials` of a format which not been previously announced by a `credential_policy` issued by this node.
  - MUST set `blinded_credentials` to less than `max_onion_size`.

The receiver:
   - if `issuance_pubkey` has not been announced or has been rotated:
      MUST reject this authentication request.
  - if `scarce_asset` is not supported:
    - MUST reject this authentication request.
  - if `blinded_credentials` format is not supported:
    - MUST reject this authentication request.
  - if `blinded_credentials` size is equal or superior to `max_onion_size`:
    - MUST reject this authentication request.
  - if the `scarce_asset` amount is not covering the quantity of `blinded_credentials` requested for signature as announced by `credential_policy`:
    - MUST reject this authentication request.

#### Rationale

The session id purpose is to enable concurrent authentication sessions where multiple set of credentials can be requested for
authentication by the same Requester, and where the order of reception of concurrent request/reply is not guaranteed by the
transport mechanism.

The Issuer should be able to perform independent validation of a scarce asset to counter-sign the blinded credentials, and therefore
apply a risk management policy.

The Issuer should reject unknown blinded credentials as they cannot provide a valid authentication, if they do not support the
underlying cryptosystem.

The onions containing the blinded credentials must be upper bounded in size to be transported over the Lightning onion routing
infrastructure.

The Issuer should enforce the policy ratio between the scarce asset value and the quantity of credentials counter-signed, and
therefore the Issuer risk management policy is respected.

### The `reply_credentials_authentication` message

This message contains an issuance pubkey and a set of signatures for each credential from `request_credentials_authentication`.

1. type: 37561 (`reply_request_credentials_authentication`)
2. data:
    * [`u32`: `session_id`]
    * [`point`: `issuance_pubkey`]
    * [`credentiallen*signature`:`credentials_signature`]

#### Requirements

The sender:
  - MUST set `session_id` to the received value in the corresponding `request_credentials_authentication`
  - MUST set `credentials_signatures` to less than `max_onion_size`.
  - MUST sort the `credentials_signature` in the order of reception of `blinded_credentials` in the corresponding `request_credentials_authentication`

The receiver:
  - if `credentials_signature` size is equal or superior to `max_onion_size`:
    - MUST reject this authentication reply.
  - if the `issuance_pubkey` is not matching the announced key in `credentials_policy`:
    - MUST reject this authentication reply.
    - MAY add this Issuer identity on a banlist.
  - if the signatures are not valid for the `blinded_credentials` sent in the corresponding `request_credentials_authentication`:
    - MUST reject this authentication reply.
  
#### Rationale

The Requester should reject the reply if the issuance pubkey does not match the credential policy one. The issuance key might have
been honestly rotated by the Issuer or the Requester might be under a deanonymization attack.

### Implementations and Deployment Considerations

The credential signature request could constitute a CPU DoS vector, therefore the Issuer should either bound its incoming onions traffic or ensure the minimal proof
of assets scores for an amount high-enough to deter an adversary.

The scarce assets validation performed should be scale up to ensure there is an economic proportion between the forgery cost and the credentials value. E.g, if
on-chain transaction is a supported scarce asset, it should be confirmed with few blocks to avoid a 1-block reorg leading to a "free" dump of authenticated credentials.
