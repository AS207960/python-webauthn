import dataclasses
import uuid
import typing
import io
import struct
import cbor2
import json
import base64
import binascii
import hashlib
import certvalidator
import datetime
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.serialization
import cryptography.x509
import cryptography.exceptions

from .errors import WebAuthnError
from . import utils, types, data, metadata


@dataclasses.dataclass
class AttestedCredentialData:
    aaguid: uuid.UUID
    credential_id: bytes
    public_key_alg: int
    public_key: typing.Union[
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey,
    ]


@dataclasses.dataclass
class AuthenticatorData:
    rp_hash: bytes
    user_presence: bool
    user_verification: bool
    sign_count: int
    attested_data: typing.Optional[AttestedCredentialData]
    extensions: typing.Optional[dict]
    data_bytes: bytes

    @classmethod
    def from_bytes(cls, data_bytes: bytes):
        data = io.BytesIO(data_bytes)

        try:
            rp_hash, flags, sign_count = struct.unpack("!32sBI", data.read(37))
        except struct.error:
            raise WebAuthnError("Invalid data")
        up = bool(flags & 0b00000001)
        uv = bool(flags & 0b00000100)
        at = bool(flags & 0b01000000)
        ed = bool(flags & 0b10000000)

        if at:
            try:
                aaguid, cred_id_len = struct.unpack("!16sH", data.read(18))
            except struct.error:
                raise WebAuthnError("Invalid data")
            aaguid = uuid.UUID(bytes=aaguid)
            cred_id = data.read(cred_id_len)
            try:
                pubkey = cbor2.CBORDecoder(data).decode()
            except (IndexError, cbor2.CBORDecodeError):
                raise WebAuthnError("Invalid data")
            pubkey, alg = utils.load_cose_key(pubkey)

            attested_data = AttestedCredentialData(
                aaguid=aaguid,
                credential_id=cred_id,
                public_key_alg=alg,
                public_key=pubkey
            )
        else:
            attested_data = None

        if ed:
            try:
                extensions = cbor2.CBORDecoder(data).decode()
            except (IndexError, cbor2.CBORDecodeError):
                raise WebAuthnError("Invalid data")
        else:
            extensions = None

        return cls(
            rp_hash=rp_hash,
            user_presence=up,
            user_verification=uv,
            sign_count=sign_count,
            attested_data=attested_data,
            extensions=extensions,
            data_bytes=data_bytes
        )


def verify_attestation(
        attestation_statement: dict, authenticator_data: AuthenticatorData, client_data_hash: bytes,
        fido_metadata: metadata.FIDOMetadata
):
    fmt = attestation_statement.get("fmt", None)
    if not fmt:
        raise WebAuthnError("Invalid data")
    attestation_statement = attestation_statement.get("attStmt", None)
    if attestation_statement is None:
        raise WebAuthnError("Invalid data")

    if not authenticator_data.attested_data:
        raise WebAuthnError("Invalid data")

    signed_data = authenticator_data.data_bytes + client_data_hash

    if fmt == types.AttestationMode.Packed.value:
        alg = attestation_statement.get("alg", None)
        if alg not in data.SUPPORTED_ALGORITHMS:
            raise WebAuthnError("Invalid data")

        sig = attestation_statement.get("sig", None)
        if not sig:
            raise WebAuthnError("Invalid data")

        x5c = attestation_statement.get("x5c", None)

        if x5c:
            if len(x5c) < 1:
                raise WebAuthnError("Invalid data")

            try:
                certs = [cryptography.x509.load_der_x509_certificate(c) for c in x5c]
            except ValueError:
                raise WebAuthnError("Invalid data")
            except cryptography.exceptions.UnsupportedAlgorithm:
                raise WebAuthnError("Unsupported authenticator")

            out_certs = list(certs)

            attestation_cert: cryptography.x509.Certificate = certs.pop(0)

            try:
                utils.verify_signature(attestation_cert.public_key(), signed_data, sig, alg)
            except cryptography.exceptions.InvalidSignature:
                raise WebAuthnError("Verification failed")

            try:
                if attestation_cert.version != cryptography.x509.Version.v3:
                    raise WebAuthnError("Invalid data")
            except cryptography.x509.InvalidVersion:
                raise WebAuthnError("Invalid data")

            subject: cryptography.x509.Name = attestation_cert.subject
            subject_cc = subject.get_attributes_for_oid(cryptography.x509.NameOID.COUNTRY_NAME)
            subject_o = subject.get_attributes_for_oid(cryptography.x509.NameOID.ORGANIZATION_NAME)
            subject_ou = subject.get_attributes_for_oid(cryptography.x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
            subject_cn = subject.get_attributes_for_oid(cryptography.x509.NameOID.COMMON_NAME)
            if len(subject_cc) != 1 or len(subject_cc[0].value) != 2:
                raise WebAuthnError("Verification failed")
            if len(subject_o) != 1:
                raise WebAuthnError("Verification failed")
            if len(subject_ou) != 1 or subject_ou[0].value != "Authenticator Attestation":
                raise WebAuthnError("Verification failed")
            if len(subject_cn) != 1:
                raise WebAuthnError("Verification failed")

            try:
                extensions = attestation_cert.extensions
            except (cryptography.x509.DuplicateExtension, cryptography.x509.UnsupportedGeneralNameType):
                raise WebAuthnError("Invalid data")

            try:
                basic_constraints = extensions.get_extension_for_oid(
                    cryptography.x509.ExtensionOID.BASIC_CONSTRAINTS
                )
                if basic_constraints.value.ca:
                    raise WebAuthnError("Verification failed")
            except cryptography.x509.ExtensionNotFound:
                raise WebAuthnError("Verification failed")

            try:
                aaguid_ext = extensions.get_extension_for_oid(
                    cryptography.x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
                )

                if aaguid_ext.critical:
                    raise WebAuthnError("Verification failed")

                aaguid = aaguid_ext.value.value
                if not aaguid.startswith(b"\x04\x10"):
                    raise WebAuthnError("Invalid data")
                aaguid = aaguid[2:]
                if len(aaguid) != 16:
                    raise WebAuthnError("Invalid data")
                aaguid = uuid.UUID(bytes=aaguid)

                if aaguid != authenticator_data.attested_data.aaguid:
                    raise WebAuthnError("Verification failed")
            except cryptography.x509.ExtensionNotFound:
                pass

            metadata_index = fido_metadata.aaguid_map.get(authenticator_data.attested_data.aaguid)
            if metadata_index is not None:
                metadata = fido_metadata.entries[metadata_index]

                if metadata.protocol != "fido2":
                    raise WebAuthnError("Verification failed")

                if metadata.is_revoked:
                    raise WebAuthnError("Verification failed")

                validator_context = certvalidator.ValidationContext(
                    trust_roots=[c.public_bytes(
                        cryptography.hazmat.primitives.serialization.Encoding.DER
                    ) for c in metadata.root_cas], allow_fetching=True
                )
                cert_validator = certvalidator.CertificateValidator(
                    end_entity_cert=x5c[0],
                    intermediate_certs=x5c[1:] if len(x5c) > 1 else None,
                    validation_context=validator_context
                )

                try:
                    path = cert_validator.validate_usage(key_usage=set())
                except certvalidator.errors.ValidationError as e:
                    raise WebAuthnError("Verification failed")

                path = [cryptography.x509.load_der_x509_certificate(c.dump()) for c in list(path)]

                return types.AttestationResult(
                    type=types.AttestationType.AttestationCA,
                    mode=types.AttestationMode.Packed,
                    root_ca=path[0],
                    cert_chain=path[1:],
                    safety_net_cts=None,
                    fido_metadata=metadata,
                )
            else:
                return types.AttestationResult(
                    type=types.AttestationType.Basic,
                    mode=types.AttestationMode.Packed,
                    root_ca=None,
                    cert_chain=out_certs,
                    safety_net_cts=None,
                    fido_metadata=None,
                )

        else:
            if alg != authenticator_data.attested_data.public_key_alg:
                raise WebAuthnError("Verification failed")

            try:
                utils.verify_signature(authenticator_data.attested_data.public_key, signed_data, sig, alg)
            except cryptography.exceptions.InvalidSignature:
                raise WebAuthnError("Verification failed")

            return types.AttestationResult(
                type=types.AttestationType.Self,
                mode=types.AttestationMode.Packed,
                root_ca=None,
                cert_chain=[],
                safety_net_cts=None,
                fido_metadata=None,
            )

    elif fmt == types.AttestationMode.AndroidSafetynet.value:
        try:
            response: bytes = attestation_statement.get("response", b"\xFF")
        except UnicodeDecodeError:
            raise WebAuthnError("Invalid data")

        if response.count(b".") != 2:
            raise WebAuthnError("Invalid data")

        jwt_sig_data, signature_str = response.rsplit(b".", 1)
        header_str, body_str = jwt_sig_data.split(b".", 1)
        try:
            header = json.loads(base64.urlsafe_b64decode(header_str + b"==").decode())
            body = json.loads(base64.urlsafe_b64decode(body_str + b"==").decode())
            signature = base64.urlsafe_b64decode(signature_str + b"==")
            certificates_bytes = [base64.b64decode(c) for c in header.get("x5c", [])]
            certificates = [cryptography.x509.load_der_x509_certificate(c) for c in certificates_bytes]
        except (ValueError, binascii.Error, json.JSONDecodeError):
            raise WebAuthnError("Invalid data")
        except cryptography.exceptions.UnsupportedAlgorithm:
            raise WebAuthnError("Unsupported authenticator")

        if len(certificates) < 1:
            raise WebAuthnError("Invalid data")

        cert_validator = certvalidator.CertificateValidator(
            end_entity_cert=certificates_bytes[0],
            intermediate_certs=certificates_bytes[1:] if len(certificates_bytes) > 1 else None
        )
        try:
            path = list(cert_validator.validate_tls("attest.android.com"))
        except certvalidator.errors.ValidationError:
            raise WebAuthnError("Verification failed")

        root_ca = cryptography.x509.load_der_x509_certificate(path.pop(0).dump())
        cert_chain = [cryptography.x509.load_der_x509_certificate(c.dump()) for c in path]

        alg_id = utils.jwt_alg_id_to_cose(header.get("alg"))

        if alg_id is None:
            raise WebAuthnError("Unsupported authenticator")

        try:
            utils.verify_signature(certificates[0].public_key(), jwt_sig_data, signature, alg_id)
        except cryptography.exceptions.InvalidSignature:
            raise WebAuthnError("Verification failed")

        signed_data_b64 = base64.b64encode(hashlib.sha256(signed_data).digest()).decode()
        if body.get("nonce") != signed_data_b64:
            raise WebAuthnError("Verification failed")

        now = datetime.datetime.utcnow()
        timestamp = datetime.datetime.fromtimestamp(body.get("timestampMs", 0) / 1000.0)
        if now - timestamp > datetime.timedelta(minutes=5):
            raise WebAuthnError("Verification failed")

        if not body.get("basicIntegrity", False):
            raise WebAuthnError("Unsupported authenticator")

        return types.AttestationResult(
            type=types.AttestationType.Basic,
            mode=types.AttestationMode.AndroidSafetynet,
            root_ca=root_ca,
            cert_chain=cert_chain,
            safety_net_cts=body.get("ctsProfileMatch", False),
            fido_metadata=None
        )

    elif fmt == types.AttestationMode.FIDOU2F.value:
        x5c = attestation_statement.get("x5c", [])
        if len(x5c) != 1:
            raise WebAuthnError("Verification failed")

        sig = attestation_statement.get("sig", None)
        if not sig:
            raise WebAuthnError("Verification failed")

        try:
            cert = cryptography.x509.load_der_x509_certificate(x5c[0])
        except ValueError:
            raise WebAuthnError("Invalid data")
        except cryptography.exceptions.UnsupportedAlgorithm:
            raise WebAuthnError("Unsupported authenticator")

        public_key = cert.public_key()
        if not isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
            raise WebAuthnError("Verification failed")
        if public_key.curve.name != "secp256r1":
            raise WebAuthnError("Verification failed")

        cred_key_bytes = authenticator_data.attested_data.public_key.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.X962,
            cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint
        )

        verification_data = bytearray([0x00])
        verification_data.extend(authenticator_data.rp_hash)
        verification_data.extend(client_data_hash)
        verification_data.extend(authenticator_data.attested_data.credential_id)
        verification_data.extend(cred_key_bytes)

        try:
            public_key.verify(sig, verification_data, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA256()
            ))
        except cryptography.exceptions.InvalidSignature:
            raise WebAuthnError("Verification failed")

        fingerprint = binascii.hexlify(
            cryptography.x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
        ).decode()
        metadata_index = fido_metadata.cki_map.get(fingerprint)

        if metadata_index is not None:
            metadata = fido_metadata.entries[metadata_index]

            if metadata.protocol != "u2f":
                raise WebAuthnError("Verification failed")

            if metadata.is_revoked:
                raise WebAuthnError("Verification failed")

            validator_context = certvalidator.ValidationContext(
                trust_roots=[c.public_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.DER
                ) for c in metadata.root_cas], allow_fetching=True
            )
            cert_validator = certvalidator.CertificateValidator(
                end_entity_cert=x5c[0],
                validation_context=validator_context,
            )

            try:
                path = cert_validator.validate_usage(key_usage=set())
            except certvalidator.errors.ValidationError:
                raise WebAuthnError("Verification failed")

            return types.AttestationResult(
                type=types.AttestationType.AttestationCA,
                mode=types.AttestationMode.FIDOU2F,
                root_ca=cryptography.x509.load_der_x509_certificate(path[0].dump()),
                cert_chain=[cert],
                safety_net_cts=None,
                fido_metadata=metadata,
            )

        return types.AttestationResult(
            type=types.AttestationType.Basic,
            mode=types.AttestationMode.FIDOU2F,
            root_ca=None,
            cert_chain=[cert],
            safety_net_cts=None,
            fido_metadata=None
        )

    elif fmt == types.AttestationMode.Apple.value:
        x5c = attestation_statement.get("x5c", [])
        if len(x5c) < 1:
            raise WebAuthnError("Invalid data")

        validator_context = certvalidator.ValidationContext(
            trust_roots=[data.APPLE_WEBAUTHN_ROOT]
        )
        cert_validator = certvalidator.CertificateValidator(
            end_entity_cert=x5c[0],
            intermediate_certs=x5c[1:] if len(x5c) > 1 else None,
            validation_context=validator_context
        )

        try:
            certs = [cryptography.x509.load_der_x509_certificate(c) for c in x5c]
        except ValueError:
            raise WebAuthnError("Invalid data")
        except cryptography.exceptions.UnsupportedAlgorithm:
            raise WebAuthnError("Unsupported authenticator")

        attestation_cert: cryptography.x509.Certificate = certs.pop(0)
        nonce = hashlib.sha256(signed_data).digest()

        try:
            if attestation_cert.version != cryptography.x509.Version.v3:
                raise WebAuthnError("Invalid data")
        except cryptography.x509.InvalidVersion:
            raise WebAuthnError("Invalid data")

        try:
            extensions = attestation_cert.extensions
        except (cryptography.x509.DuplicateExtension, cryptography.x509.UnsupportedGeneralNameType):
            raise WebAuthnError("Invalid data")

        try:
            nonce_ext = extensions.get_extension_for_oid(
                cryptography.x509.ObjectIdentifier("1.2.840.113635.100.8.2")
            )
        except cryptography.x509.ExtensionNotFound:
            raise WebAuthnError("Invalid data")

        cert_nonce = nonce_ext.value.value
        asn1_prefix = b"\x30\x24\xa1\x22\x04\x20"
        if not cert_nonce.startswith(asn1_prefix):
            raise WebAuthnError("Invalid data")

        if cert_nonce[len(asn1_prefix):] != nonce:
            raise WebAuthnError("Verification failed")

        if not utils.key_equal(authenticator_data.attested_data.public_key, attestation_cert.public_key()):
            raise WebAuthnError("Verification failed")

        try:
            path = cert_validator.validate_usage(
                key_usage={"digital_signature"}
            )
        except certvalidator.errors.ValidationError:
            raise WebAuthnError("Verification failed")

        path = [cryptography.x509.load_der_x509_certificate(c.dump()) for c in list(path)]

        return types.AttestationResult(
            type=types.AttestationType.AnonymizationCA,
            mode=types.AttestationMode.Apple,
            root_ca=path[0],
            cert_chain=path[1:],
            safety_net_cts=None,
            fido_metadata=None
        )

    elif fmt == types.AttestationMode.NoneAttestation.value:
        return types.AttestationResult(
            type=types.AttestationType.NoneAttestation,
            mode=types.AttestationMode.NoneAttestation,
            root_ca=None,
            cert_chain=[],
            safety_net_cts=None,
            fido_metadata=None
        )

    else:
        raise WebAuthnError("Unsupported authenticator")
