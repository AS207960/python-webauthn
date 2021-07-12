import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes

from .errors import WebAuthnError
from . import data


def load_cose_key(cose_key: dict):
    kty = cose_key.pop(1, None)
    if not kty:
        raise WebAuthnError("Invalid data")

    if kty == 3:
        alg = cose_key.pop(3, None)
        if alg and alg not in data.RSA_ALGORITHMS:
            raise WebAuthnError("Invalid data")

        n = cose_key.pop(-1, None)
        e = cose_key.pop(-2, None)
        if bool(cose_key):
            raise WebAuthnError("Invalid data")
        if not n or not e:
            raise WebAuthnError("Invalid data")

        try:
            n = int.from_bytes(n, byteorder='big')
            e = int.from_bytes(e, byteorder='big')
        except ValueError:
            raise WebAuthnError("Invalid data")

        pub_nums = cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers(n=n, e=e)
    elif kty == 2:
        crv = cose_key.pop(-1, None)
        alg = cose_key.pop(3, None)
        if not crv:
            raise WebAuthnError("Invalid data")

        if alg and alg not in data.ES_ALGORITHMS:
            raise WebAuthnError("Invalid data")

        x = cose_key.pop(-2, None)
        y = cose_key.pop(-3, None)
        if bool(cose_key):
            raise WebAuthnError("Invalid data")
        if not x or not y:
            raise WebAuthnError("Invalid data")

        if crv == 1:
            crv = cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
        elif crv == 2:
            crv = cryptography.hazmat.primitives.asymmetric.ec.SECP384R1()
        elif crv == 3:
            crv = cryptography.hazmat.primitives.asymmetric.ec.SECP521R1()
        elif crv == 8:
            crv = cryptography.hazmat.primitives.asymmetric.ec.SECP256K1()
        else:
            raise WebAuthnError("Invalid data")

        try:
            x = int.from_bytes(x, byteorder='big')
            y = int.from_bytes(y, byteorder='big')
        except ValueError:
            raise WebAuthnError("Invalid data")

        pub_nums = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
            x=x, y=y, curve=crv
        )
    else:
        raise WebAuthnError("Invalid data")

    try:
        pub_key = pub_nums.public_key()
    except ValueError:
        raise WebAuthnError("Invalid data")

    return pub_key, alg


def jwt_alg_id_to_cose(jwt_alg_id: str) -> int:
    if jwt_alg_id == "ES256":
        return data.ES256
    elif jwt_alg_id == "ES384":
        return data.ES384
    elif jwt_alg_id == "ES512":
        return data.ES512
    elif jwt_alg_id == "RS256":
        return data.RS256
    elif jwt_alg_id == "RS384":
        return data.RS384
    elif jwt_alg_id == "RS512":
        return data.RS512
    elif jwt_alg_id == "PS256":
        return data.PS256
    elif jwt_alg_id == "PS384":
        return data.PS384
    elif jwt_alg_id == "PS512":
        return data.PS512


def verify_signature(pubkey, msg_data: bytes, signature: bytes, cose_alg_id: int):
    if isinstance(pubkey, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
        if cose_alg_id == data.ES256:
            alg = cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA256()
            )
        elif cose_alg_id == data.ES384:
            alg = cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA384()
            )
        elif cose_alg_id == data.ES512:
            alg = cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA512()
            )
        else:
            raise WebAuthnError("Invalid data")

        pubkey.verify(signature, msg_data, alg)
    elif isinstance(pubkey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        if cose_alg_id == data.RS256:
            padding, alg = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(), \
                           cryptography.hazmat.primitives.hashes.SHA256()
        elif cose_alg_id == data.RS384:
            padding, alg = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(), \
                           cryptography.hazmat.primitives.hashes.SHA384()
        elif cose_alg_id == data.RS512:
            padding, alg = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(), \
                           cryptography.hazmat.primitives.hashes.SHA512()
        elif cose_alg_id == data.PS256:
            padding, alg = cryptography.hazmat.primitives.asymmetric.padding.PSS(
                cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    cryptography.hazmat.primitives.hashes.SHA256()
                ), cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH
            ), cryptography.hazmat.primitives.hashes.SHA256()
        elif cose_alg_id == data.PS384:
            padding, alg = cryptography.hazmat.primitives.asymmetric.padding.PSS(
                cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    cryptography.hazmat.primitives.hashes.SHA384()
                ), cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH
            ), cryptography.hazmat.primitives.hashes.SHA384()
        elif cose_alg_id == data.PS512:
            padding, alg = cryptography.hazmat.primitives.asymmetric.padding.PSS(
                cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    cryptography.hazmat.primitives.hashes.SHA512()
                ), cryptography.hazmat.primitives.asymmetric.padding.PSS.MAX_LENGTH
            ), cryptography.hazmat.primitives.hashes.SHA512()
        else:
            raise WebAuthnError("Invalid data")

        pubkey.verify(signature, msg_data, padding, alg)


def key_equal(left, right):
    if isinstance(left, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey) and \
            isinstance(right, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
        left = left.public_numbers()
        right = right.public_numbers()
        return left == right
    elif isinstance(left, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey) and \
            isinstance(right, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        left = left.public_numbers()
        right = right.public_numbers()
        return left == right
    else:
        return False
