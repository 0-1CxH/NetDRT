from flask import Flask, request, jsonify
import time
import uuid
import os
import base64
import hashlib
import datetime

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

    def create_session(self, chunks_count):
        # Create a new session with a unique ID and processing port
        session_id = str(uuid.uuid4())
        if len(self.active_sessions) >= self.max_sessions:
            return None
        else:
            self.active_sessions[session_id] = {
                'updated_time': time.time(),
                'chunks': [],
                'chunks_count': int(chunks_count),
                'file_info': None
            }
            return session_id

    def handle_chunk(self, session_id, encrypted_chunk):
        try:
            # Decrypt the chunk
            chunk = self.cipher.decrypt(base64.b64decode(encrypted_chunk))
            # Store the chunk
            session = self.active_sessions.get(session_id)
            
            if session:
                session['chunks'].append(chunk)
                session['updated_time'] = time.time()
                received_chunk_count = len(session['chunks'])
                self.logger.info(f"Session {session_id} received {received_chunk_count}/{session['chunks_count']} chunks.")
                if received_chunk_count == session['chunks_count']:
                    return self.finalize_file(session_id)
                else:
                    return True
            else:
                self.logger.error(f"Invalid session {session_id}")
                return False
        except Exception as e:
            self.logger.error(f"Chunk processing error: {e}")
            return False

    def finalize_file(self, session_id):
        self.logger.info(f"Session {session_id} received all chunks, now reconstructing the file.")
        session = self.active_sessions.get(session_id)
        if not session:
            return False

        try:

            unpacked = self.protocol.unpack(session['chunks'])
            # self.logger.debug(f"{unpacked_chunk=}")
            # Update file info on first chunk
            if not session['file_info']:
                session['file_info'] = unpacked['metadata']
            
            reconstructed_content = unpacked['data']

            # Verify hash
            file_hash = hashlib.sha256(reconstructed_content).hexdigest()
            if file_hash != session['file_info']['file_hash']:
                self.logger.error("File hash mismatch")
                return False

            # Save file
            file_path = os.path.join(
                self.file_reception_dir, 
                session['file_info']['file_name']
            )

            # Check if the file already exists
            if os.path.exists(file_path):
                # Generate a new file name with a UUID to ensure uniqueness
                base_name, extension = os.path.splitext(session['file_info']['file_name'])
                new_file_name = f"{base_name}_{datetime.datetime.now().__str__().replace(" ", "-")}{extension}"
                file_path = os.path.join(self.file_reception_dir, new_file_name)
                self.logger.info(f"File already exists. Renaming to {new_file_name}.")

            with open(file_path, 'wb') as f:
                f.write(reconstructed_content)
            
            # also verify file size too
            file_size = os.path.getsize(file_path)
            if file_size != session['file_info']['file_size']:
                self.logger.warning(f"File size mismatch.")

            self.logger.info(f"File {session['file_info']['file_name']} (size: {file_size/1024/1024}M, hash: {file_hash}) "
                             f"saved to {file_path} (path on sender: {session['file_info']['file_path_on_sender']}) successfully.")
            
            # Clean up session
            del self.active_sessions[session_id]

            return True
        except Exception as e:
            self.logger.error(f"File finalization error: {e}")
            return False

def create_flask_server(server_instance):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024

    @app.route('/', methods=['GET'])
    def get_session():
        sign = request.form.get('g')
        chunks_count = request.form.get('n')
        if not sign or not server_instance.authenticate_sign(sign):
            return jsonify({"error": "Authentication failed"}), 403
        
        try:
            session_id = server_instance.create_session(chunks_count)
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
        session_id = request.json.get('s')
        encrypted_chunk = request.json.get('c')

        if not session_id or not encrypted_chunk:
            return jsonify({"error": "Missing session_id or packet"}), 400

        success = server_instance.handle_chunk(session_id, encrypted_chunk)
        
        # Optional: Implement logic to finalize file when all chunks received
        if success:
            return jsonify({"status": "chunk_received"})
        else:
            return jsonify({"error": "Chunk processing failed"}), 500

    return app

