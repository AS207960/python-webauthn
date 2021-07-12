import typing
import os
import base64
import dataclasses
import uuid
import json
import cbor2
import binascii
import hashlib
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.exceptions

from . import data, types, errors, utils, metadata, attestation


def create_webauthn_credentials(
        rp: types.RelyingParty, user: types.User, existing_keys: typing.List[bytes] = None,
        attachment: typing.Optional[types.AuthenticatorAttachment] = None, require_resident: bool = False,
        user_verification: typing.Optional[types.UserVerification] = None,
        attestation_request: typing.Optional[types.Attestation] = None
) -> typing.Tuple[dict, str]:
    if existing_keys is None:
        existing_keys = []

    if len(user.id) > 64:
        raise errors.WebAuthnError("User ID length is larger than limit of 64 bytes")

    challenge = os.urandom(64)
    challenge_base64 = base64.b64encode(challenge).decode()

    selection = {}
    if attachment:
        selection["authenticatorAttachment"] = attachment.value
    if require_resident:
        selection["requireResidentKey"] = bool(require_resident)
    if user_verification:
        selection["userVerification"] = user_verification.value

    options = {
        "rp": rp.to_options(),
        "user": user.to_options(),
        "challenge": challenge_base64,
        "pubKeyCredParams": [{
            "type": "public-key",
            "alg": alg
        } for alg in data.SUPPORTED_ALGORITHMS],
        "excludeCredentials": [{
            "type": "public-key",
            "id": base64.b64encode(k).decode()
        } for k in existing_keys],
        "authenticatorSelection": selection
    }
    if attestation:
        options["attestation"] = attestation_request.value

    return options, challenge_base64


def get_webauthn_credentials(
        rp: types.RelyingParty, existing_keys: typing.List[bytes] = None,
        user_verification: typing.Optional[types.UserVerification] = None,
) -> typing.Tuple[dict, str]:
    if existing_keys is None:
        existing_keys = []

    challenge = os.urandom(64)
    challenge_base64 = base64.b64encode(challenge).decode()

    options = {
        "rpId": rp.id,
        "challenge": challenge_base64,
        "allowCredentials": [{
            "type": "public-key",
            "id": base64.b64encode(k).decode()
        } for k in existing_keys],
    }
    if user_verification:
        options["userVerification"] = user_verification.value

    return options, challenge_base64


@dataclasses.dataclass
class CreateResult:
    aaguid: uuid.UUID
    sign_count: int
    public_key_alg: int
    public_key: typing.Union[
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey,
    ]
    attestation: types.AttestationResult


def verify_create_webauthn_credentials(
        rp: types.RelyingParty, challenge_b64: str, client_data_b64: str, attestation_b64: str,
        fido_metadata: metadata.FIDOMetadata, user_verification_required: bool = False
) -> CreateResult:
    try:
        challenge = base64.b64decode(challenge_b64)
        client_data_bytes = base64.b64decode(client_data_b64)
        client_data = json.loads(client_data_bytes.decode())
        attestation_data = cbor2.loads(base64.b64decode(attestation_b64))
    except (binascii.Error, ValueError, json.JSONDecodeError, cbor2.CBORDecodeError):
        raise errors.WebAuthnError("Invalid data")

    try:
        client_challenge = base64.urlsafe_b64decode(client_data["challenge"] + "==")
    except (binascii.Error, KeyError):
        raise errors.WebAuthnError("Invalid data")

    if client_challenge != challenge:
        raise errors.WebAuthnError("Verification failed")
    if client_data.get("type") != "webauthn.create":
        raise errors.WebAuthnError("Verification failed")
    if not client_data.get("origin", "").endswith(rp.id):
        raise errors.WebAuthnError("Verification failed")

    client_data_hash = hashlib.sha256(client_data_bytes).digest()
    rp_hash = hashlib.sha256(rp.id.encode()).digest()

    if "authData" not in attestation_data or type(attestation_data["authData"]) != bytes:
        raise errors.WebAuthnError("Invalid data")

    authenticator_data = attestation.AuthenticatorData.from_bytes(attestation_data["authData"])

    if rp_hash != authenticator_data.rp_hash:
        raise errors.WebAuthnError("Verification failed")

    if not authenticator_data.user_presence:
        raise errors.WebAuthnError("User not present")
    if not authenticator_data.user_verification and user_verification_required:
        raise errors.WebAuthnError("User not verified")

    verified_attestation = attestation.verify_attestation(
        attestation_statement=attestation_data, authenticator_data=authenticator_data,
        client_data_hash=client_data_hash, fido_metadata=fido_metadata
    )

    return CreateResult(
        aaguid=authenticator_data.attested_data.aaguid,
        sign_count=authenticator_data.sign_count,
        attestation=verified_attestation,
        public_key_alg=authenticator_data.attested_data.public_key_alg,
        public_key=authenticator_data.attested_data.public_key
    )


@dataclasses.dataclass
class GetResult:
    sign_count: int


def verify_get_webauthn_credentials(
        rp: types.RelyingParty, challenge_b64: str, client_data_b64: str, authenticator_b64: str, signature_b64: str,
        sign_count: int, pubkey_alg: int, pubkey, user_verification_required: bool = False,
) -> GetResult:
    try:
        challenge = base64.b64decode(challenge_b64)
        client_data_bytes = base64.b64decode(client_data_b64)
        client_data = json.loads(client_data_bytes.decode())
        authenticator = base64.b64decode(authenticator_b64)
        signature = base64.b64decode(signature_b64)
    except (binascii.Error, ValueError, json.JSONDecodeError):
        raise errors.WebAuthnError("Invalid data")

    authenticator_data = attestation.AuthenticatorData.from_bytes(authenticator)

    try:
        client_challenge = base64.urlsafe_b64decode(client_data["challenge"] + "==")
    except (binascii.Error, KeyError):
        raise errors.WebAuthnError("Invalid data")

    if client_challenge != challenge:
        raise errors.WebAuthnError("Verification failed")
    if client_data.get("type") != "webauthn.get":
        raise errors.WebAuthnError("Verification failed")
    if not client_data.get("origin", "").endswith(rp.id):
        raise errors.WebAuthnError("Verification failed")

    client_data_hash = hashlib.sha256(client_data_bytes).digest()
    rp_hash = hashlib.sha256(rp.id.encode()).digest()

    if rp_hash != authenticator_data.rp_hash:
        raise errors.WebAuthnError("Verification failed")

    if not authenticator_data.user_verification and user_verification_required:
        raise errors.WebAuthnError("User not verified")

    signed_data = authenticator + client_data_hash

    try:
        utils.verify_signature(pubkey, signed_data, signature, pubkey_alg)
    except cryptography.exceptions.InvalidSignature:
        raise errors.WebAuthnError("Verification failed")

    if sign_count != 0 and authenticator_data.sign_count != 0:
        if authenticator_data.sign_count > sign_count:
            sign_count = authenticator_data.sign_count
        else:
            raise errors.WebAuthnError("Verification failed")

    return GetResult(
        sign_count=sign_count
    )
