import logging
import enum
import dataclasses
import typing
import cryptography.x509
import uuid
import datetime
import base64
import urllib.parse
import certvalidator
import requests
import json
import binascii
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.exceptions

from . import data, errors

logger = logging.getLogger(__name__)


class FIDOCertification(enum.Enum):
    NotCertified = "NOT_FIDO_CERTIFIED"
    Certified = "FIDO_CERTIFIED"
    CertifiedL1 = "FIDO_CERTIFIED_L1"
    CertifiedL1Plus = "FIDO_CERTIFIED_L1plus"
    CertifiedL2 = "FIDO_CERTIFIED_L2"
    CertifiedL2Plus = "FIDO_CERTIFIED_L2plus"
    CertifiedL3 = "FIDO_CERTIFIED_L3"
    CertifiedL3Plus = "FIDO_CERTIFIED_L3plus"


@dataclasses.dataclass
class FIDOMetadataEntry:
    description: str
    protocol: str
    icon: typing.Optional[str]
    root_cas: typing.List[cryptography.x509.Certificate]
    fido_certification_level: FIDOCertification
    is_revoked: bool
    is_compromised: bool


@dataclasses.dataclass
class FIDOMetadata:
    entries: typing.List[FIDOMetadataEntry]
    aaguid_map: typing.Dict[uuid.UUID, int]
    cki_map: typing.Dict[str, int]

    @classmethod
    def from_metadata(cls, metadata):
        next_update = datetime.datetime.strptime(metadata["nextUpdate"], "%Y-%m-%d").date()
        today = datetime.datetime.utcnow().date()

        if next_update < today:
            logger.warning("Metadata out of date, please update")

        entries = []
        aaguid_map = {}
        cki_map = {}

        for entry in metadata["entries"]:
            root_cas = []
            statement = entry["metadataStatement"]

            fido_certification_level = FIDOCertification.NotCertified
            is_revoked = False
            is_compromised = False

            status_reports = sorted(filter(
                lambda d: d[0] <= today,
                map(
                    lambda d: (datetime.datetime.strptime(d["effectiveDate"], "%Y-%m-%d").date(), d),
                    entry["statusReports"]
                )
            ), key=lambda d: d[0])

            for _, report in status_reports:
                if report["status"] == FIDOCertification.NotCertified.value:
                    fido_certification_level = FIDOCertification.NotCertified
                elif report["status"] == FIDOCertification.Certified.value:
                    fido_certification_level = FIDOCertification.Certified
                elif report["status"] == FIDOCertification.CertifiedL1.value:
                    fido_certification_level = FIDOCertification.CertifiedL1
                elif report["status"] == FIDOCertification.CertifiedL1Plus.value:
                    fido_certification_level = FIDOCertification.CertifiedL1Plus
                elif report["status"] == FIDOCertification.CertifiedL2.value:
                    fido_certification_level = FIDOCertification.CertifiedL2
                elif report["status"] == FIDOCertification.CertifiedL2Plus.value:
                    fido_certification_level = FIDOCertification.CertifiedL2Plus
                elif report["status"] == FIDOCertification.CertifiedL3.value:
                    fido_certification_level = FIDOCertification.CertifiedL3
                elif report["status"] == FIDOCertification.CertifiedL3Plus.value:
                    fido_certification_level = FIDOCertification.CertifiedL3Plus
                elif report["status"] == "REVOKED":
                    is_revoked = True
                elif report["status"] == "USER_VERIFICATION_BYPASS":
                    is_compromised = True
                elif report["status"] == "ATTESTATION_KEY_COMPROMISE":
                    is_compromised = True
                elif report["status"] == "USER_KEY_REMOTE_COMPROMISE":
                    is_compromised = True
                elif report["status"] == "USER_KEY_PHYSICAL_COMPROMISE":
                    is_compromised = True

            if statement["schema"] != 3:
                continue

            for cert in statement["attestationRootCertificates"]:
                cert_bytes = base64.b64decode(cert)
                root_cas.append(
                    cryptography.x509.load_der_x509_certificate(cert_bytes)
                )

            md_entry = FIDOMetadataEntry(
                description=statement["description"],
                protocol=statement["protocolFamily"],
                icon=statement.get("icon"),
                root_cas=root_cas,
                fido_certification_level=fido_certification_level,
                is_revoked=is_revoked,
                is_compromised=is_compromised,
            )
            index = len(entries)
            entries.append(md_entry)

            for cki in entry.get("attestationCertificateKeyIdentifiers", []):
                cki_map[cki] = index

            if "aaguid" in entry:
                aaguid_map[uuid.UUID(entry["aaguid"])] = index

        return cls(
            entries=entries,
            aaguid_map=aaguid_map,
            cki_map=cki_map
        )


CERT_START_LINE = b"-----BEGIN CERTIFICATE-----\n"
CERT_END_LINE = b"\n-----BEGIN CERTIFICATE-----"


def _get_signing_cert(root, h):
    validation_context = certvalidator.ValidationContext(
        trust_roots=[root], allow_fetching=True, revocation_mode="require"
    )

    if "x5u" in h:
        x5u = h["x5u"]
        if not isinstance(x5u, str):
            return None

        mds_parts = urllib.parse.urlsplit(data.FIDO_MDS_URL, scheme='https')
        x5u_parts = urllib.parse.urlsplit(x5u, scheme='https')
        if mds_parts.scheme != x5u_parts.scheme or mds_parts.netloc != x5u_parts.netloc:
            return None

        chain_r = requests.get(x5u, stream=True)
        chain_certs = list(map(
            lambda c: base64.b64decode(c.rstrip(CERT_END_LINE)),
            chain_r.iter_lines(delimiter=CERT_START_LINE)
        ))[1:]
    elif "x5c" in h:
        x5c = h["x5c"]
        if not isinstance(x5c, list):
            return None

        chain_certs = list(map(lambda c: base64.b64decode(c), x5c))
    else:
        return root

    validator = certvalidator.CertificateValidator(
        end_entity_cert=chain_certs[0],
        intermediate_certs=chain_certs[1:],
        validation_context=validation_context,
    )

    try:
        validator.validate_usage(
            key_usage={"digital_signature"},
            extended_optional=True
        )
    except certvalidator.errors.ValidationError:
        return None

    return cryptography.x509.load_der_x509_certificate(chain_certs[0])


def verify(cert, h, msg, sig):
    alg = h.get("alg")

    pubkey = cert.public_key()

    if alg in ("RS256", "RS384", "RS512"):
        if not isinstance(pubkey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
            logger.warning("Invalid key for RSA algorithm")
            return False

        if alg == "RS256":
            hasher = cryptography.hazmat.primitives.hashes.SHA256()
        elif alg == "RS384":
            hasher = cryptography.hazmat.primitives.hashes.SHA384()
        else:
            hasher = cryptography.hazmat.primitives.hashes.SHA512()

        try:
            pubkey.verify(
                sig,
                msg,
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                hasher
            )
        except cryptography.exceptions.InvalidSignature:
            return False

        return True
    else:
        logger.warning("Unsupported signature algorithm")
        return False


def get_metadata():
    try:
        mds_r = requests.get(data.FIDO_MDS_URL)
    except requests.exceptions.RequestException:
        raise errors.WebAuthnError("Failed to fetch metadata")

    if mds_r.status_code != 200:
        raise errors.WebAuthnError("Failed to fetch metadata")

    try:
        mds_data = iter(mds_r.text.split("."))
        header_str = next(mds_data)
        header_bytes = base64.urlsafe_b64decode(header_str + '==')
        header = json.loads(header_bytes)
    except (json.JSONDecodeError, StopIteration, binascii.Error):
        raise errors.WebAuthnError("Invalid metadata")

    if header.get("typ") != "JWT":
        print("Metadata not a JWT")
        return

    cert = _get_signing_cert(data.FIDO_MDS_ROOT, header)

    if not cert:
        raise errors.WebAuthnError("Failed to get signing certificate")

    try:
        msg_str = next(mds_data)
        msg_bytes = base64.urlsafe_b64decode(msg_str + '==')
        sig_bytes = base64.urlsafe_b64decode(next(mds_data) + '==')
    except (StopIteration, binascii.Error):
        raise errors.WebAuthnError("Invalid metadata")

    if not verify(cert, header, (header_str + "." + msg_str).encode(), sig_bytes):
        raise errors.WebAuthnError("Metadata signature verification failed")

    try:
        msg = json.loads(msg_bytes)
    except json.JSONDecodeError:
        raise errors.WebAuthnError("Invalid metadata")

    return msg
