from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter

class NetDRTCipher:
    def __init__(self, salt=None) -> None:
        self.rsa_key = None
        self.salt = "%netdrt#2025%" if salt is None else salt

    def keygen(self, passkey, salt=None):
        # The same passkey and salt generate the same dk, which seeds the AES-CTR cipher. 
        # This guarantees reproducible random bytes.

        if salt is None:
            salt = self.salt
        # Convert passkey to bytes if it's a string
        if isinstance(passkey, str):
            passkey_bytes = passkey.encode('utf-8')
        else:
            passkey_bytes = passkey
        
        # Derive a 32-byte key using PBKDF2 with 100,000 iterations
        dk = PBKDF2(passkey_bytes, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        
        # Initialize AES-CTR as a deterministic PRNG
        ctr = Counter.new(128, initial_value=0)  # 128-bit counter starting at 0
        aes_cipher = AES.new(dk, AES.MODE_CTR, counter=ctr)
        
        # Deterministic random bytes generator
        def rand_func(n):
            return aes_cipher.encrypt(b'\x00' * n)  # Encrypt zeros to get keystream
        
        # Generate RSA key pair
        key = RSA.generate(2048, randfunc=rand_func)

        self.rsa_key = key
        return key
    
    def encrypt(self, plaintext):
        if self.rsa_key is None:
            raise ValueError("Must generate RSA key first")
        cipher = PKCS1_OAEP.new(self.rsa_key.publickey(), hashAlgo=SHA256)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
        return ciphertext
    
    def decrypt(self, ciphertext):
        if self.rsa_key is None:
            raise ValueError("Must generate RSA key first")
        cipher = PKCS1_OAEP.new(self.rsa_key, hashAlgo=SHA256)
        plaintext = cipher.decrypt(ciphertext).decode('utf-8')
        return plaintext