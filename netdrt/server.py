from flask import Flask, request, jsonify
import time
import uuid
import os
import base64
import hashlib
import datetime
import asyncio
import random
import aiofiles  # For async file operations
import concurrent.futures
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
        self.overwrite_if_exists = server_configs.get('overwrite_if_exists', False)
        self.session_expiration = server_configs.get('session_expiration', 30 * 60) # 30min 
        
        # File reception storage
        self.file_reception_dir = server_configs.get('file_reception_dir', './ndrt_received_files')
        os.makedirs(self.file_reception_dir, exist_ok=True)
        
        # Thread pool for CPU-bound tasks
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=server_configs.get('server_async_thread_num', 32))
        
        # Create event loop for async operations
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def authenticate_sign(self, sign):
        try:
            # Decrypt the sign
            decrypted_timestamp = float(self.cipher.decrypt(
                base64.b64decode(sign.encode())
            ))
            # Check if timestamp is within +/- 10 seconds
            current_time = time.time()
            self.logger.debug(f"Client Timestamp {decrypted_timestamp}, Server Timestamp {current_time}")
            return abs(current_time - decrypted_timestamp) <= 10
        except Exception as e:
            self.logger.error(f"Authentication failed: {e}")
            return False

    def _purge_sessions(self):
        expired_sessions = []
        for sid, session in self.active_sessions.items():
            if time.time() - session['updated_time'] > self.session_expiration:
                expired_sessions.append(sid)
        
        for sid in expired_sessions:
            del self.active_sessions[sid]
            self.logger.info(f"Session {sid} has been purged due to expiration.")
    
    def create_session(self, chunks_count):
        self._purge_sessions()
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
            self.logger.info(f"Session {session_id} Created, Preserved {int(chunks_count)} Chunks.")
            return session_id

    def handle_chunk(self, session_id, encrypted_chunk):
        """Wrapper for async handle_chunk to maintain API compatibility"""
        return asyncio.run(self.handle_chunk_async(session_id, encrypted_chunk))
    
    async def handle_chunk_async(self, session_id, encrypted_chunk):
        """Async version of handle_chunk that processes chunks asynchronously"""
        try:
            # Decrypt the chunk in a separate thread to not block the event loop
            loop = asyncio.get_event_loop()
            chunk = await loop.run_in_executor(
                self.executor,
                lambda: self.cipher.decrypt(base64.b64decode(encrypted_chunk))
            )
            
            # Store the chunk
            session = self.active_sessions.get(session_id)
            
            if session:
                session['chunks'].append(chunk)
                session['updated_time'] = time.time()
                received_chunk_count = len(session['chunks'])
                self.logger.info(f"Session {session_id} Received {received_chunk_count}/{session['chunks_count']} Chunks.")
                
                if received_chunk_count == session['chunks_count']:
                    return await self.finalize_file_async(session_id)
                else:
                    return True
            else:
                self.logger.error(f"Invalid session {session_id}")
                return False
        except Exception as e:
            self.logger.error(f"Chunk processing error: {e}")
            return False

    def finalize_file(self, session_id):
        """Wrapper for async finalize_file to maintain API compatibility"""
        return asyncio.run(self.finalize_file_async(session_id))
    
    async def finalize_file_async(self, session_id):
        """Async version of finalize_file that processes file reconstruction asynchronously"""
        self.logger.info(f"Session {session_id} received all chunks, now reconstructing the file.")
        session = self.active_sessions.get(session_id)
        if not session:
            return False
        try:
            # Process unpacking in a separate thread
            loop = asyncio.get_event_loop()
            unpacked = await loop.run_in_executor(
                self.executor,
                lambda: self.protocol.unpack(session['chunks'])
            )
            
            # Update file info on first chunk
            if not session['file_info']:
                session['file_info'] = unpacked['metadata']
            
            reconstructed_content = unpacked['data']
            
            # Verify hash in a separate thread
            file_hash = await loop.run_in_executor(
                self.executor,
                lambda: hashlib.sha256(reconstructed_content).hexdigest()
            )
            
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
                if self.overwrite_if_exists:
                    self.logger.warning(f"File already exists, will **OVERWRITE** existing one.")
                else:
                    base_name, extension = os.path.splitext(session['file_info']['file_name'])
                    new_file_name = f"{base_name}_{datetime.datetime.now().__str__().replace(' ', '-')}{extension}"
                    file_path = os.path.join(self.file_reception_dir, new_file_name)
                    self.logger.info(f"File already exists. Renaming to {new_file_name}.")
                
                
            # Write file asynchronously
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(reconstructed_content)
            
            # Verify file size
            file_stats = await loop.run_in_executor(
                self.executor,
                os.path.getsize,
                file_path
            )
            
            file_size = file_stats
            if file_size != session['file_info']['file_size']:
                self.logger.warning(f"File size mismatch.")
                
            self.logger.info(f"File {session['file_info']['file_name']} (size: {file_size/1024/1024:.4f}M, hash: {file_hash}) "
                             f"Saved to {file_path} (file path on sender: {session['file_info']['file_path_on_sender']}) Successfully.")
            
            # Clean up session
            del self.active_sessions[session_id]
            return True
        except Exception as e:
            self.logger.error(f"File finalization error: {e}")
            return False

    @staticmethod
    def serve(server_configs):
        server_instance = NetDRTServer(server_configs)

        chunk_size = server_configs.get('chunk_size', 4 * 1024 * 1024)
        chunk_size_variance_percentage = server_configs.get('chunk_size_variance_percentage', 0.1)
        assert 0.0 <= chunk_size_variance_percentage <= 1.0
        max_chunk_size = chunk_size * (1 + chunk_size_variance_percentage)

        respond_random_bytes = server_configs.get('respond_random_bytes', 256)
        

        app = Flask(__name__)
        app.config['MAX_CONTENT_LENGTH'] = max(256 * 1024 * 1024, max_chunk_size * 1.2)
        
        @app.route('/', methods=['GET'])
        def get_session():
            sign = request.form.get('g')
            chunks_count = int(request.form.get('n'))
            if not sign or not server_instance.authenticate_sign(sign):
                return jsonify({"error": "Authentication failed"}), 403
            
            assert chunks_count > 0
            
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
            
            if success:
                return jsonify({
                    "content": base64.b64encode(server_instance.protocol._get_random_bytes(
                            int(random.randint(0, respond_random_bytes)))).decode()
                })
            else:
                return jsonify({"error": "Chunk processing failed"}), 500
        
        app.run(
            host=server_configs.get('server_ip', '127.0.0.1'),
            port=int(server_configs.get('server_port', '9651'))
        )