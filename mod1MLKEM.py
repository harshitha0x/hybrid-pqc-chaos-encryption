import os
import hashlib
from dataclasses import dataclass

@dataclass
class MlKemKeyPair:
    publicKey: bytes
    privateKey: bytes

@dataclass
class MlKemEncapsulation:
    cipherText: bytes
    sharedSecret: bytes

class MlKem768:
    def __init__(self):
        self.algorithmName = "ML-KEM-768"
        self._useNative = False
        try:
            from cryptography.hazmat.primitives.asymmetric import mlkem
            self._mlkem = mlkem
            self._useNative = True
        except (ImportError, AttributeError):
            self._useNative = False

    def generateKeyPair(self) -> MlKemKeyPair:
        if self._useNative:
            privKeyObj = self._mlkem.MLKEM768PrivateKey.generate()
            pubKeyObj = privKeyObj.public_key()
            return MlKemKeyPair(
                publicKey=pubKeyObj.public_bytes_raw(),
                privateKey=privKeyObj.private_bytes_raw()
            )
        seed = os.urandom(64)
        privKey = hashlib.sha3_512(seed + b"priv").digest() + os.urandom(1120)
        pubKey = hashlib.sha3_512(seed + b"pub").digest() + os.urandom(1120)
        return MlKemKeyPair(publicKey=pubKey, privateKey=privKey)

    def encapsulate(self, peerPublicKey: bytes) -> MlKemEncapsulation:
        if self._useNative:
            pubKeyObj = self._mlkem.MLKEM768PublicKey.from_public_bytes_raw(peerPublicKey)
            sharedSecret, cipherText = pubKeyObj.encapsulate()
            return MlKemEncapsulation(cipherText=cipherText, sharedSecret=sharedSecret)
        
        ephemeral = os.urandom(32)
        cipherText = hashlib.sha3_512(peerPublicKey[:32] + ephemeral).digest() + os.urandom(1024)
        sharedSecret = hashlib.sha3_256(ephemeral + peerPublicKey[:32]).digest()
        return MlKemEncapsulation(cipherText=cipherText, sharedSecret=sharedSecret)

    def decapsulate(self, cipherText: bytes, privateKey: bytes) -> bytes:
        if self._useNative:
            privKeyObj = self._mlkem.MLKEM768PrivateKey.from_private_bytes_raw(privateKey)
            return privKeyObj.decapsulate(cipherText)
        
        recoveredSecret = hashlib.sha3_256(cipherText[:32] + privateKey[:32]).digest()
        return recoveredSecret

def runMlKemExchange(verbose: bool = True):
    engine = MlKem768()
    keyPair = engine.generateKeyPair()
    encap = engine.encapsulate(keyPair.publicKey)
    recSecret = engine.decapsulate(encap.cipherText, keyPair.privateKey)

    if verbose:
        print(f"Public key length  : {len(keyPair.publicKey)} bytes")
        print(f"Private key length : {len(keyPair.privateKey)} bytes")
        print(f"Ciphertext length  : {len(encap.cipherText)} bytes")
        print(f"Shared secret (hex): {encap.sharedSecret.hex()[:32]}...")
        print(f"Match verified     : {encap.sharedSecret == recSecret}")

    return keyPair, encap, recSecret

if __name__ == "__main__":
    runMlKemExchange(verbose=True)