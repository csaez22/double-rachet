import os
import pickle
import string
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

    def generateCertificate(self):
        # Generate an initial DH pair using curve P-256
        # Gen certificate with name and public key
        # Serialize the certificate
        raise Exception("not implemented!")
        return

    def receiveCertificate(self, certificate, signature):
        # Verify the server's signature on the certificate
        # Store the validated certificate and associated public key
        raise Exception("not implemented!")
        return

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
        # Ensure the report includes the sender's name and message content 
        # This is sent and decrypted by the server(I believe)
        raise Exception("not implemented!")
        return
