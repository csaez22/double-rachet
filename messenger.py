import os
import pickle
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        # Decrypts and returns an abuse report using server_decryption_key
        # - Reported messages are encrypted with a CCA-secure variant of El-Gamal encryption.
        # - El-Gamal encryption is not provided by the cryptography library.
        # - We will implement it using available primitives (ECDH and AES-GCM).
        ct_dict = pickle.loads(ct)
        # TODO: Implement El-Gamal decryption

    def signCert(self, cert):
        # Signs a certificate that is provided using server_signing_key
        # Signs the certificate with an ECDSA signature using SHA256
        
        # Serialize the certificate to bytes (e.g., using pickle)
        cert_bytes = pickle.dumps(cert)

        signature = self.server_signing_key.sign(
            cert_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        # Return the signature
        return signature

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}
        # Probably better here than in generateCertificate
        # Docs for SECP256R1(P-256): https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/ (About 1/3 of the way down the page, we're using 256 instead of 384)
        self.DH_priv = ec.generate_private_key(ec.SECP256R1())
        self.DH_pub = self.DH_priv.public_key()

    def generateCertificate(self):
        # Generate an initial DH name and key pair using curve P-256 which serves as a certificate
        cert = {'name': self.name, 'public_key': self.DH_pub}
        return cert

    def receiveCertificate(self, certificate, signature):
        # Verify the server's signature on the certificate
        # Store the validated certificate and associated public key
        
        cert_bytes = pickle.dumps(certificate)
        # Verify the server's signature on the certificate
        try:
            self.server_signing_pk.verify(signature, cert_bytes, ec.ECDSA(hashes.SHA256()))
        # need to find some way to catch this(InvalidSignature?) I found this via chatGPT but am unsure if that is allowed
        # Docs for InvalidSignature: https://cryptography.io/en/latest/exceptions/#cryptography.exceptions.InvalidSignature
        except InvalidSignature:
            raise Exception("Invalid certificate signature")
        # Store the validated certificate
        self.certs[certificate['name']] = certificate

    def sendMessage(self, name, message):
        # Send an encrypted message to the user specified by 'name'
        raise Exception("not implemented!")
        return

    def receiveMessage(self, name, header, ciphertext):
        # Receive and decrypt an encrypted message from the user specified by 'name'.
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        # Implement El-Gamal encryption for abuse report
        # Encrypt the report under the server;s public key
        # Ensure the report includes the sender's name and message content
        # This is sent and decrypted by the server
        raise Exception("not implemented!")
        return
