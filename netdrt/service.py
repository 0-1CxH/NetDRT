from .cipher import NetDRTCipher
from .protocol import NetDRTProtocol
from .log import setup_logger
from typing import Dict

class NetDRTClient:
    def __init__(self, client_configs: Dict) -> None:
        self.logger = setup_logger(
            name="client_main",
            level=client_configs.get('log_level', 'DEBUG'), 
            to_console=True, 
            to_file=client_configs.get('log_to_file', False)
        )
        self.cipher = NetDRTCipher(salt=client_configs.get('salt', None))
        passkey = client_configs.get('passkey', None)
        if passkey is None:
            passkey = input("ENTER YOUR PASSKEY:")
        self.cipher.keygen(passkey=passkey)
        assert self.cipher.rsa_key is not None
        
        self.logger.debug(f"NDRT Cipher Init Finish. Please Check Your Public Key: \n{self.cipher.rsa_key.publickey().export_key().decode()}")

        self.protocol = NetDRTProtocol(client_configs)
        self.logger.debug(
            f"NDRT Protocol Init Finish. Chunk size: {self.protocol.chunk_size/1024/1024}M+/-{self.protocol.chunk_size_variance_percentage*100}%, Appendix: 0-{self.protocol.append_random_bytes} "
        )

        self.server_ip = client_configs.get('server_ip', '127.0.0.1')
        self.server_port = client_configs.get('server_port', '9651')
        self._connect()
        self.logger.info(f"NDRT Client Init Finish. Server: {self.server_ip}:{self.server_port}")
    
    def _connect(self):
        pass
    
    def send(self, content):
        pass

    
    



        