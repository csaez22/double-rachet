import os
import pickle
import string
from cryptography.hazmat.primitives import hashes, hmac, serialization
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
        public_key_pem = self.DH_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        cert = {'name': self.name, 'public_key': public_key_pem}
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
        # Deserialize the public key from PEM bytes
        public_key_pem = certificate['public_key']
        peer_public_key = serialization.load_pem_public_key(public_key_pem)
        
        # Store the validated certificate with the deserialized public key
        self.certs[certificate['name']] = {
            'name': certificate['name'],
            'public_key': peer_public_key
        }

    def sendMessage(self, name, message):
        # Send an encrypted message to the user specified by 'name'
        if name not in self.conns:
            # TODO session_init
            self.session_init(name)
        
        session = self.conns[name]

        # Prepare header: DH public key, Pn(length in prev sending chain), Ns(message number in sending chain)
        header = {
            'dh_pub': session['DHs'].public_key(),
            'pn': session['Pn'],
            'ns': session['Ns'],
        }

        # If CK isn't initialized, raise an error
        if session['CKs'] is None:
            raise ValueError("Sending chain key is not initialized.")
        
        serialized_header = pickle.dumps(header)

        # The current chain key is passed to te KDF method to derive a new MK and the next CKs
        CKs, MK = self.KDF_CK(session['CKs'])

        #Encrypt the message using MK
        aesgcm = AESGCM(MK)
        # Unique random value for cryptographic use; Might not be allowed
        nonce = os.urandom(12)
        plaintext = message.encode('utf-8')
        # aesgcm handles both confidentiality and integrity; no need for HMAC(See if Saez agrees)
        ct = aesgcm.encrypt(nonce, plaintext, serialized_header)

        #  Message number incremented
        session['Ns'] += 1

        # Prepare ciphertext components as hex strings for JSON serialization
        ciphertext_dict = {
            'nonce': nonce,
            'ciphertext': ct
        }

        return header, ciphertext_dict

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
    
    def session_init(self, name):
        peer_cert = self.certs[name]
        # Other person's publick key
        DHr = peer_cert['public_key']
        DHs = self.DH_priv

        # Compute shared secret
        shared_secret = self.DH_priv.exchange(ec.ECDH(), DHr)

        # Root key
        initial_RK = b'\x00' * 32

        session_RK, CKs = self.KDF_RK(initial_RK, shared_secret)

        # Initialize session state
        session = {
            'RK': session_RK,
            'CKs': CKs,
            'CKr': None,
            'DHs': DHs,
            'DHr': DHr,
            'Ns': 0,
            'Nr': 0,
            'Pn': 0,
        }

        self.conns[name] = session

    def KDF_CK(self,CK):
        # From Docs 5.2
        # KDF_CK(ck): HMAC [2] with SHA-256 or SHA-512 [8] is recommended,
        # using ck as the HMAC key and using separate constants as input 
        # (e.g. a single byte 0x01 as input to produce the message key, and a single byte 0x02 as input to produce the next chain key).


        # Derive MK using HMAC with input 0x02
        h_mk = hmac.HMAC(CK, hashes.SHA256())
        h_mk.update(b'\x01')
        MK = h_mk.finalize()

        # Derive new_CK using HMAC with input 0x01
        h_new_ck = hmac.HMAC(CK, hashes.SHA256())
        h_new_ck.update(b'\x02')
        new_CK = h_new_ck.finalize()

        return new_CK, MK
    
    # Done in session init
    def KDF_RK(self, RK, DH_out):
        # From Docs 5.2:
        # KDF_RK(rk, dh_out): HKDF [3] with SHA-256 or SHA-512 [8] is recommended,
        # using rk as the salt, dh_out as the input keying material (IKM), and an application-specific byte sequences as HKDF info.
        # Info value should be distinct from other uses of HKDF

        # Is info distinct?
        # I believe so because all the calls to the function are for the same purpose of
        # deriving new Root Key and Chain Key
        info = b'DoubleRatchetKDF_RK'

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for RK and 32 bytes for CK
            salt=RK,
            info=info,
        )

        derived_keys = hkdf.derive(DH_out)
        next_RK = derived_keys[:32]
        CKs = derived_keys[32:]
    
        return next_RK, CKs