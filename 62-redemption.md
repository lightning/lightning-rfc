# Redemption Phase

This document specifies the Redemption protocol inside the Staking Credentials framework.

The messages data format, validation algorithms and implementation considerations are laid out.

This draft is version 0.0.1 of the Redemption phase protocol.

## Credentials Redemption

The Client is sending unblinded credenrtials and a service specific request.

```

	+-------+				  		+-------+
	|	|				  		|	|
	|	|				  		|	|
	|	|--(1)--- redeem_credentials ------------------>|	|
	|   A   |				  		|   B   |
	|	|						|	|
	|	|				  		|	|
	|	|-------- service_request (non-specified) ----->|	|
	|	|				  		|	|
	+-------+				  		+-------+

```

### The `redeem_credentials` message

This message contains a set of unblinded credentials, a set of corresponding credentials signatures, a set of unsigned blinded credentials for the reward mode and a service identifier.

1. type: 37562 (`redeem_credentials`)
2. data:
    * [`point`: `issuance_pubkey`]
    * [`credentiallen*byte`: `unblinded_credentials`]
    * [`credentiallen*signature`: `credentials_signature`]
    * [`credentiallen*byte`: `reward_blinded_credentials`]
    * [`32*byte`: `service_identifier`]
    * [`u32`: `request_identifier`]

#### Requirements

The sender:
   - MUST set the sum of `unblinded_credentials`, `credentials_signature` and `blinded_credentials` to less than `max_onion_size`
   - MUST sort the `credentials_signature` in the order of reception of `blinded_credentials` in the corresponding `request_credentials_authentication`
   - MUST set `service_identifier` to the service identifier requested for redemption
   - MUST set `request_identifier` to the service specific request identifier

The receiver:
   - if the signatures are not valid for the `unblinded_credentials``:
     - MUST reject this service request.
   - if the quantity of credentials does not satisfy the ratio announced by a `service_policy`:
     - MAY reject this service request.

#### Rationale

The issuance pubkey present avoids issues with propagation delays or key rotation, where the set of credentials are not valid anymore
for the providance of the service.

The 32-byte service identifier should pair with a random unique identifier provided in the `service_policy` gossip issued by this Provider.

The Provider is free to update its `service_policy` at anytime, therefore altering the economic value of the credentials.

### Implementations and Deployment Considerations

An authenticated and encrypted communication channel should be maintained between the Issuer and the Provider to avoid man-in-the-middle, if
the credential Issuance is delegated. Otherwise, credential validation can be forged and the service can be DoSed.
