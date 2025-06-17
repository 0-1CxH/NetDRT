from .cipher import NetDRTCipher
from .protocol import NetDRTProtocol
from .log import setup_logger
import os
import hashlib
import time
from typing import Dict
import requests
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed


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
        self.thread_num = client_configs.get('thread_num', 5)

        self.logger.info(f"NDRT Client Init Finish. Server: {self.server_ip}:{self.server_port}")
    

    def _send(self, session_id, packet):
        url = f"http://{self.server_ip}:{self.server_port}"
        response = requests.post(url, json={
            'c': packet,
            's': session_id,
        })
        if response.status_code == 200:
            return True
        else:
            raise RuntimeError(f"Failed to send packet. Status code: {response.status_code}. Message: {response.content.decode()}")
    
    def _sign_current_timestamp(self):
        enc_ts = self.cipher.encrypt(time.time().__str__())
        return base64.b64encode(enc_ts).decode('ascii')
    
    
    def _get_session_id(self, packed_chunks_count):
        url = f"http://{self.server_ip}:{self.server_port}"
        
        response = requests.get(url, data={
            'g': self._sign_current_timestamp(),
            'n': packed_chunks_count,
        })
        if response.status_code == 200:
            session_id = response.json().get('session_id')
            if session_id:
                self.logger.info(f"Session ID obtained: {session_id}")
            else:
                self.logger.error("Session ID not found in response.")
            return session_id
        else:
            self.logger.error(f"Failed to get session ID. Status code: {response.status_code}. Message: {response.content.decode()}")
    


    def send_file(self, file_path: str):
        with open(file_path, "rb") as f:            
            # Get the file name, size
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)

            content = f.read()
            # Calculate the file hash (SHA-256)
            file_hash = hashlib.sha256(content).hexdigest()

            self.logger.info(f"File Name: {file_name}, File Size: {file_size} bytes, File Hash: {file_hash}")

            packed_chunks = self.protocol.pack(
                content, 
                {
                "file_path_on_sender": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "file_hash": file_hash
                }
            )

            packed_chunks = [
                base64.b64encode(self.cipher.encrypt(_)).decode('ascii') for _ in packed_chunks
            ]

            packed_chunks_count = len(packed_chunks)

            session_id = self._get_session_id(packed_chunks_count)
            
            def send_chunk(chunk):
                retrying = 3
                while retrying > 0:
                    try:
                        if self._send(session_id, chunk) is True:
                            break
                    except Exception as e:
                        self.logger.error(f"Error sending chunk: {e}, Remaining Retries: {retrying}")
                        retrying -= 1 

            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                futures = {}
                for idx, chunk in enumerate(packed_chunks):
                    self.logger.debug(f"Start submitting thread of chunk {idx}")
                    fut = executor.submit(send_chunk, chunk)
                    futures[fut] = idx

                for fut in as_completed(futures):
                    idx = futures[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        self.logger.error(f"Chunk {idx} sending failed: {e}")






        