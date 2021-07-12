import enum
import dataclasses
import typing
import base64
import cryptography.x509

from . import metadata


class AttestationType(enum.Enum):
    Self = enum.auto()
    Basic = enum.auto()
    AttestationCA = enum.auto()
    AnonymizationCA = enum.auto()
    NoneAttestation = enum.auto()


class AttestationMode(enum.Enum):
    Packed = "packed"
    TPM = "tpm"
    AndroidKey = "android-key"
    AndroidSafetynet = "android-safetynet"
    FIDOU2F = "fido-u2f"
    Apple = "apple"
    NoneAttestation = "none"


@dataclasses.dataclass
class AttestationResult:
    type: AttestationType
    mode: AttestationMode
    root_ca: typing.Optional[cryptography.x509.Certificate]
    cert_chain: typing.List[cryptography.x509.Certificate]
    safety_net_cts: typing.Optional[bool]
    fido_metadata: typing.Optional[metadata.FIDOMetadataEntry]


class AuthenticatorAttachment(enum.Enum):
    Platform = "platform"
    CrossPlatform = "cross-platform"


class UserVerification(enum.Enum):
    Required = "required"
    Preferred = "preferred"
    Discouraged = "discouraged"


class Attestation(enum.Enum):
    NoneAttestation = "none"
    IndirectAttestation = "indirect"
    DirectAttestation = "direct"


@dataclasses.dataclass
class RelyingParty:
    id: str
    name: str
    icon: typing.Optional[str]

    def to_options(self):
        out = {
            "id": self.id,
            "name": self.name
        }
        if self.icon:
            out["icon"] = self.icon
        return out


@dataclasses.dataclass
class User:
    id: bytes
    display_name: str
    name: str
    icon: typing.Optional[str]

    def to_options(self):
        out = {
            "id": base64.b64encode(self.id).decode(),
            "name": self.name,
            "displayName": self.display_name,
        }
        if self.icon:
            out["icon"] = self.icon
        return out
