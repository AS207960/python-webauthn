import base64
import json
import cryptography.x509
import cryptography.exceptions
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.x25519
import cryptography.hazmat.primitives.asymmetric.x448
import os

import webauthn

from flask import Flask, render_template, session, request

app = Flask(__name__)
app.secret_key = os.urandom(40)

MDS_LOCATION = "./fido-mds.json"

RP_ICON = "https://as207960.net/assets/img/logo.svg"
RP_ID = "as207960-webauthn.eu.ngrok.io"
RP_NAME = "AS207960"


@app.route('/')
def hello_world():
    return render_template("index.html")


@app.route("/register")
def register():
    ukey = b"test"

    user = webauthn.types.User(id=ukey, display_name="Test user", name="test@example.com", icon=None)
    rp = webauthn.types.RelyingParty(id=RP_ID, name=RP_NAME, icon=RP_ICON)

    try:
        options, challenge = webauthn.create_webauthn_credentials(
            rp=rp, user=user, existing_keys=[], attachment=None, require_resident=False,
            user_verification=webauthn.types.UserVerification.Preferred,
            attestation_request=webauthn.types.Attestation.DirectAttestation
        )
    except webauthn.errors.WebAuthnError as e:
        return {
            "result": "error",
            "message": e.message
        }

    session["challenge"] = challenge

    return {
        "result": "ok",
        "data": options
    }


@app.route("/complete_registration", methods=["POST"])
def complete_registration():
    data = request.json
    challenge = session.pop("challenge")

    rp = webauthn.types.RelyingParty(id=RP_ID, name=RP_NAME, icon=RP_ICON)

    if not challenge:
        return {
            "result": "error",
            "message": "Invalid session"
        }

    if "id" not in data or "response" not in data or type(data["id"]) != str or type(data["response"]) != dict:
        return {
            "result": "error",
            "message": "Invalid data"
        }

    pkey_id = data["id"]
    response = data["response"]
    if "data" not in response or "attestation" not in response or type(response["data"]) != str \
            or type(response["attestation"]) != str:
        return {
            "result": "error",
            "message": "Invalid data"
        }

    try:
        auth_data = webauthn.verify_create_webauthn_credentials(
            rp=rp, challenge_b64=challenge, client_data_b64=response["data"], attestation_b64=response["attestation"],
            fido_metadata=fido_metadata
        )
    except webauthn.errors.WebAuthnError as e:
        return {
            "result": "error",
            "message": e.message
        }

    session["pkey_id"] = pkey_id
    session["pkey_alg"] = str(auth_data.public_key_alg)
    session["pkey"] = auth_data.public_key.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.PEM,
        cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    session["sign_counter"] = auth_data.sign_count

    print(auth_data)

    return {
        "result": "ok",
        "data": None
    }


@app.route("/login")
def login():
    rp = webauthn.types.RelyingParty(id=RP_ID, name=RP_NAME, icon=RP_ICON)

    if "pkey_id" not in session:
        return {
            "result": "error",
            "message": "Invalid session"
        }

    pkey = base64.b64decode(session["pkey_id"])

    try:
        options, challenge = webauthn.get_webauthn_credentials(
            rp=rp, existing_keys=[pkey], user_verification=webauthn.types.UserVerification.Preferred,
        )
    except webauthn.errors.WebAuthnError as e:
        return {
            "result": "error",
            "message": e.message
        }

    session["login-challenge"] = challenge

    return {
        "result": "ok",
        "data": options
    }


@app.route("/complete_login", methods=["POST"])
def complete_login():
    data = request.json
    challenge = session.pop("login-challenge")

    if not challenge or "pkey" not in session or "pkey_alg" not in session or "sign_counter" not in session:
        return {
            "result": "error",
            "message": "Invalid session"
        }

    rp = webauthn.types.RelyingParty(id=RP_ID, name=RP_NAME, icon=RP_ICON)
    pkey = cryptography.hazmat.primitives.serialization.load_pem_public_key(session["pkey"].encode())
    pkey_alg = int(session["pkey_alg"])
    sign_counter = int(session["sign_counter"])

    if "response" not in data or type(data["response"]) != dict:
        return {
            "result": "error",
            "message": "Invalid data"
        }

    response = data["response"]
    if "data" not in response or "authenticator" not in response or "signature" not in response \
            or "user" not in response or type(response["data"]) != str or type(response["authenticator"]) != str \
            or type(response["signature"]) != str or type(response["user"]) != str:
        return {
            "result": "error",
            "message": "Invalid data"
        }

    print(f'User: {base64.b64decode(response["user"])}')

    try:
        auth_data = webauthn.verify_get_webauthn_credentials(
            challenge_b64=challenge, client_data_b64=response["data"], authenticator_b64=response["authenticator"],
            signature_b64=response["signature"], pubkey=pkey, pubkey_alg=pkey_alg, rp=rp, sign_count=sign_counter
        )
    except webauthn.errors.WebAuthnError as e:
        return {
            "result": "error",
            "message": e.message
        }

    print(auth_data)

    return {
        "result": "ok",
        "data": None
    }


if __name__ == '__main__':
    with open(MDS_LOCATION, "rb") as r:
        metadata_json = json.load(r)

    fido_metadata = webauthn.metadata.FIDOMetadata.from_metadata(metadata_json)

    app.run()
