import os
import pickle
import string

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        raise Exception("not implemented!")
        return

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
        # 
        raise Exception("not implemented!")
        return

    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        # Implement El-Gamal encryption for abuse report
        # Encrypt the report under the server;s public key
        # Ensure the report includes the sender's name and message content 
        raise Exception("not implemented!")
        return

# AHHHHH