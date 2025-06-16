from .cipher import NetDRTCipher
from .protocol import NetDRTProtocol
from .log import setup_logger
import os
import hashlib
import time
import random
from typing import Dict
import requests
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import uuid

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
    

    def _send_to_processing_port(self, session_id, processing_port, packet):
        url = f"http://{self.server_ip}:{processing_port}/s={session_id}"
        response = requests.post(url, data=packet)
        self.logger.debug(response)
        if response.status_code == 200:
            self.logger.info("Packet sent successfully.")
        else:
            self.logger.error(f"Failed to send packet. Status code: {response.status_code}")
    
    
    def _get_session_id_and_processing_port(self):
        url = f"http://{self.server_ip}:{self.server_port}"
        
        response = requests.get(url)
        if response.status_code == 200:
            session_id = response.json().get('session_id')
            processing_port = response.json().get('processing_port')
            if session_id:
                self.logger.info(f"Session ID obtained: {session_id}, Processing Port Obtained: {processing_port}")
            else:
                self.logger.error("Session ID/Processing Port not found in response.")
            return session_id, processing_port
        else:
            self.logger.error(f"Failed to get session ID/Processing Port. Status code: {response.status_code}")
    


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

            session_id, processing_port = self._get_session_id_and_processing_port()
            
            def send_chunk(chunk):
                try:
                    self._send_to_processing_port(session_id, processing_port, chunk)
                except Exception as e:
                    self.logger.error(f"Error sending chunk: {e}")

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






        