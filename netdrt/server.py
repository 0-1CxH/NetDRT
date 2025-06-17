from flask import Flask, request, jsonify
import time
import uuid
import os
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib

from .cipher import NetDRTCipher
from .protocol import NetDRTProtocol
from .log import setup_logger

class NetDRTServer:
    def __init__(self, server_configs: dict):
        # Logger setup
        self.logger = setup_logger(
            name="server_main",
            level=server_configs.get('log_level', 'DEBUG'), 
            to_console=True, 
            to_file=server_configs.get('log_to_file', False)
        )

        # Cipher initialization 
        self.cipher = NetDRTCipher(salt=server_configs.get('salt', None))
        passkey = server_configs.get('passkey', None)
        if passkey is None:
            passkey = input("ENTER YOUR SERVER PASSKEY:")
        self.cipher.keygen(passkey=passkey)
        assert self.cipher.rsa_key is not None

        self.logger.debug(f"NDRT Cipher Init Finish. Please Check Your Public Key: \n{self.cipher.rsa_key.publickey().export_key().decode()}")

        # Protocol setup
        self.protocol = NetDRTProtocol(server_configs)
        self.logger.debug(
            f"NDRT Protocol Init Finish."
        )

        # Session management
        self.active_sessions = {}
        
        # Server configuration
        self.max_sessions = server_configs.get('max_sessions', 10)
        
        # File reception storage
        self.file_reception_dir = server_configs.get('file_reception_dir', './received_files')
        os.makedirs(self.file_reception_dir, exist_ok=True)

    def authenticate_sign(self, sign):
        try:
            # Decrypt the sign
            decrypted_timestamp = float(self.cipher.decrypt(
                base64.b64decode(sign.encode())
            ))
            # Check if timestamp is within +/- 10 seconds
            current_time = time.time()
            self.logger.info(f"Client Timestamp {decrypted_timestamp}, Server Timestamp {current_time}")
            return abs(current_time - decrypted_timestamp) <= 10
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            return False

    def create_session(self):
        # Create a new session with a unique ID and processing port
        session_id = str(uuid.uuid4())
        if len(self.active_sessions) >= self.max_sessions:
            return None
        else:
            self.active_sessions[session_id] = {'chunks': [], 'file_info': None}
            return session_id

    def handle_chunk(self, session_id, encrypted_chunk):
        try:
            # Decrypt the chunk
            chunk = self.cipher.decrypt(base64.b64decode(encrypted_chunk))
            # Store the chunk
            session = self.active_sessions.get(session_id)
            if session:
                session['chunks'].append(chunk)
                self.logger.info(f"Chunk received for session {session_id}")
                return True
            else:
                self.logger.error(f"Invalid session {session_id}")
                return False
        except Exception as e:
            self.logger.error(f"Chunk processing error: {e}")
            return False

    def finalize_file(self, session_id):
        session = self.active_sessions.get(session_id)
        if not session:
            return False

        try:
             # #DO NOT Unpack the chunk HERE, do after all are collected
            # unpacked_chunk = self.protocol.unpack(chunk)
            # self.logger.debug(f"{unpacked_chunk=}")
            # print(unpacked_chunk)
            # Update file info on first chunk
                # if not session['file_info']:
                #     session['file_info'] = unpacked_chunk['metadata']
                

            # Reconstruct file
            file_info = session['file_info']
            reconstructed_content = self.protocol.reconstruct(session['chunks'])

            # Verify hash
            file_hash = hashlib.sha256(reconstructed_content).hexdigest()
            if file_hash != file_info['file_hash']:
                self.logger.error("File hash mismatch")
                return False

            # Save file
            file_path = os.path.join(
                self.file_reception_dir, 
                file_info['file_name']
            )
            with open(file_path, 'wb') as f:
                f.write(reconstructed_content)

            self.logger.info(f"File {file_info['file_name']} received successfully")
            
            # Clean up session
            del self.active_sessions[session_id]
            del self.processing_ports[session_id]

            return True
        except Exception as e:
            self.logger.error(f"File finalization error: {e}")
            return False

def create_flask_server(server_instance):
    app = Flask(__name__)

    @app.route('/', methods=['GET'])
    def get_session():
        sign = request.form.get('sign')
        if not sign or not server_instance.authenticate_sign(sign):
            return jsonify({"error": "Authentication failed"}), 403
        
        try:
            session_id = server_instance.create_session()
            if session_id is not None:
                return jsonify({
                    "session_id": session_id, 
                })
            else:
                return jsonify({"error": "Max session number reached"}), 507
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/', methods=['POST'])
    def receive_chunk():
        session_id = request.form.get('session_id')
        encrypted_chunk = request.form.get('packet')

        print(f"{session_id=}, {len(encrypted_chunk)=}")

        if not session_id or not encrypted_chunk:
            return jsonify({"error": "Missing session_id or packet"}), 400

        success = server_instance.handle_chunk(session_id, encrypted_chunk)
        
        # Optional: Implement logic to finalize file when all chunks received
        if success:
            return jsonify({"status": "chunk_received"})
        else:
            return jsonify({"error": "Chunk processing failed"}), 500

    return app

