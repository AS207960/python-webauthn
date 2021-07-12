# Python WebAuthN

Server side handlers for WebAuthN with support for Apple's FaceID, and the FIDO metadata service.

## Demo

A small Flask app showcasing this library is provided in the `demo` folder.

## Basic usage

### Register a credential

Part 1: generate request to be sent to browser

```python
# User the credential is to be registered to
user = webauthn.types.User(
    id=b"test",
    display_name="Test user",
    name="test@example.com",
    icon=None
)
# Who is requesting the credential
rp = webauthn.types.RelyingParty(
    id="as207960-webauthn.eu.ngrok.io",
    name="AS207960",
    icon="https://as207960.net/assets/img/logo.svg"
)

data, challenge = webauthn.create_webauthn_credentials(
    rp=rp, user=user, existing_keys=[],
    attachment=None, require_resident=False,
    user_verification=webauthn.types.UserVerification.Preferred,
    attestation_request=webauthn.types.Attestation.DirectAttestation,
)

# Store the challenge and user for part 3
```

Part 2: Create credential through the browser

```js
function b64decode(input) {
    return Uint8Array.from(window.atob(input), c => c.charCodeAt(0));
}

function b64encode(input) {
    return window.btoa(String.fromCharCode.apply(null, new Uint8Array(input)));
}

// Data having already been retrieved from the server
data.user.id = b64decode(data.user.id);
data.challenge = b64decode(data.challenge);
data.excludeCredentials = data.excludeCredentials.map(function (cred) {
    cred.id = b64decode(cred.id);
    return cred;
})
navigator.credentials.create({
    publicKey: data
}).then(function (response) {
    let data = {
        id: b64encode(response.rawId),
        response: {
            data: b64encode(response.response.clientDataJSON),
            attestation: b64encode(response.response.attestationObject),
        }
    }

    // Send response data back to the server
});
```

Part 3: Complete registration on the server

```python
# Response is the data from the browser as above

# This should be cached
fido_metadata = webauthn.metadata.get_metadata()

auth_data = webauthn.verify_create_webauthn_credentials(
    rp=rp, challenge_b64=challenge,
    client_data_b64=response["data"],
    attestation_b64=response["attestation"],
    fido_metadata=fido_metadata
)
```

The `auth_data` response can be inspected to decide if the authenticator is to be allowed by the server. Such rules are
outside the scope of this package.

### Perform a login

Part 1: generate request to be sent to browser

```python
options, challenge = webauthn.get_webauthn_credentials(
    rp=rp,
    existing_keys=[pkey_id],
    user_verification=webauthn.types.UserVerification.Preferred,
)

# Store the challenge and user for part 3
```

Part 2: Sign challenge

```js
// Data having already been retrieved from the server

data.challenge = b64decode(data.challenge);
data.allowCredentials = data.allowCredentials.map(function (cred) {
    cred.id = b64decode(cred.id);
    return cred;
})
return navigator.credentials.get({
    publicKey: data
}).then(function (response) {
    let data = {
        response: {
            data: b64encode(response.response.clientDataJSON),
            authenticator: b64encode(response.response.authenticatorData),
            signature: b64encode(response.response.signature),
            user: b64encode(response.response.userHandle),
        }
    }
    
    // Send response data back to the server
});
```

Part 3: Verify response on the server

```python
# Response is the data from the browser as above

# This should be cached
fido_metadata = webauthn.metadata.get_metadata()

auth_data = webauthn.verify_create_webauthn_credentials(
    rp=rp, challenge_b64=challenge,
    client_data_b64=response["data"],
    attestation_b64=response["attestation"],
    fido_metadata=fido_metadata
)
```
