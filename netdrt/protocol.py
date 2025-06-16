from typing import Dict, Optional, ByteString
import random
import hashlib
import struct
import json

class NetDRTProtocol:
    def __init__(self, config: Optional[Dict] = None) -> None:
        self.chunk_size = config.get('chunk_size', 8 * 1024 * 1024) # 8MB
        self.chunk_size_variance_percentage = config.get('chunk_size_variance_percentage', 0.1) # sample in +/- 10% range
        assert 0.0 <= self.chunk_size_variance_percentage < 1.0
        self.append_random_bytes = config.get('append_random_bytes', 128) # append 0-128 bytes after real data
    
    def _chunking(self, data: ByteString):
        chunks = []
        data_length = len(data)
        index = 0
        
        while index < data_length:
            # Calculate the chunk size with variance
            variance = self.chunk_size * self.chunk_size_variance_percentage
            chunk_size = int(random.uniform(self.chunk_size - variance, self.chunk_size + variance))
            chunk_size = max(1, chunk_size)  # Ensure chunk size is at least 1 byte
            
            # Extract the chunk from the data
            chunk = data[index:index + chunk_size]
            chunks.append(chunk)
            
            # Move the index forward by the chunk size
            index += chunk_size
        
        return chunks

    @staticmethod
    def _get_random_bytes(n):
        return bytes(random.getrandbits(8) for _ in range(n))
    
    
    def _assemble_chunk_entry(self, chunk_entry):
        input_data_metadata = chunk_entry['metadata']
        input_data_metadata = json.dumps(input_data_metadata, ensure_ascii=True)
        metadata_part = input_data_metadata.encode('ascii')
        metadata_part_length = len(metadata_part)
        assert 0 <= metadata_part_length <= 0xFFFFFFFFFFFFFFFF
        metadata_part_length_part = struct.pack('>Q', metadata_part_length)

        chunk_id = chunk_entry['chunk_id']
        assert 0 <= chunk_id <= 0xFFFFFFFFFFFFFFFF, f"chunk_id out of range: {chunk_id}"
        chunk_id_bytes = struct.pack('>Q', chunk_id)
        chunk_id_part = b'\xff\xff' + chunk_id_bytes + b'\xff\xff'

        chunks_count = chunk_entry['chunks_count']
        assert 0 <= chunks_count <= 0xFFFFFFFFFFFFFFFF
        chunks_count_bytes = struct.pack('>Q', chunks_count)
        chunks_count_part = b'\xff\xff' + chunks_count_bytes + b'\xff\xff'


        chunk_digest_bytes = chunk_entry['chunk_digest'].encode('ascii')

        chunk_size = chunk_entry['chunk_size']
        chunk_size_bytes = chunk_size.to_bytes(64, byteorder='big', signed=False)
        chunk_size_part = b'\xff' * 4 + chunk_size_bytes + b'\xff' * 4
        assert 0 <= chunk_size <= (1 << (64 * 8)) - 1, f"chunk_size out of range: {chunk_size}"

        chunk_data = chunk_entry['chunk_data']
        assert isinstance(chunk_data, bytes)

        

        byte_stream = (
            metadata_part_length_part +
            metadata_part +
            chunk_id_part +
            chunks_count_part +
            chunk_digest_bytes +
            chunk_size_part +
            chunk_data
        )

        if self.append_random_bytes > 0:
            random_part = self._get_random_bytes(int(random.randint(0, self.append_random_bytes)))
            byte_stream += random_part

        return byte_stream
    
    def _disassemble_chunk_entry(self, byte_stream):
        """
        Parse a packed chunk byte stream into its components.
        """
        # Extract metadata part length (first 8 bytes)
        metadata_part_length = struct.unpack('>Q', byte_stream[:8])[0]
        
        # Extract metadata part
        metadata_part = byte_stream[8:8+metadata_part_length]
        metadata = json.loads(metadata_part.decode('ascii'))
        
        # Current position after metadata
        pos = 8 + metadata_part_length
        
        # Extract chunk_id (surrounded by \xff\xff markers)
        assert byte_stream[pos:pos+2] == b'\xff\xff'
        chunk_id = struct.unpack('>Q', byte_stream[pos+2:pos+10])[0]
        assert byte_stream[pos+10:pos+12] == b'\xff\xff'
        pos += 12
        
        # Extract chunks_count (surrounded by \xff\xff markers)
        assert byte_stream[pos:pos+2] == b'\xff\xff'
        chunks_count = struct.unpack('>Q', byte_stream[pos+2:pos+10])[0]
        assert byte_stream[pos+10:pos+12] == b'\xff\xff'
        pos += 12
        
        # Extract chunk digest (64 ASCII hex characters)
        chunk_digest = byte_stream[pos:pos+64].decode('ascii')
        pos += 64
        
        # Extract chunk size (surrounded by 4 \xff markers on each side)
        assert byte_stream[pos:pos+4] == b'\xff' * 4
        chunk_size_bytes = byte_stream[pos+4:pos+68]
        chunk_size = int.from_bytes(chunk_size_bytes, byteorder='big', signed=False)
        assert byte_stream[pos+68:pos+72] == b'\xff' * 4
        pos += 72
        
        # Extract chunk data
        chunk_data = byte_stream[pos:pos+chunk_size]

        if self.append_random_bytes == 0:
            assert pos + chunk_size == len(byte_stream)
        
        return {
            'metadata': metadata,
            'chunk_id': chunk_id,
            'chunks_count': chunks_count,
            'chunk_digest': chunk_digest,
            'chunk_size': chunk_size,
            'chunk_data': chunk_data
        }

    
    def pack(self, input_data: ByteString, input_data_metadata: Optional[Dict] = None):
        if input_data_metadata is None:
            input_data_metadata = {}
        chunked_data = self._chunking(input_data)
        chunks_count = len(chunked_data)
        packed_chunks = []

        for chunk_id, chunk in enumerate(chunked_data):
            # Compute the chunk's digest
            chunk_digest = hashlib.sha256(chunk).digest()
            
            # Prepare the chunk entry
            chunk_entry = {
                'metadata': input_data_metadata,
                'chunk_id': chunk_id,
                'chunks_count': chunks_count,
                'chunk_digest': chunk_digest.hex(),
                'chunk_size': len(chunk),
                'chunk_data': chunk
            }
            chunk_byte_stream = self._assemble_chunk_entry(chunk_entry)
            packed_chunks.append(chunk_byte_stream)
        
        return packed_chunks
    
    def unpack(self, packed_chunks):
        """
        Unpack the data from a list of packed chunks and validate their integrity.
        
        Args:
            packed_chunks: List of byte streams produced by the pack method
            
        Returns:
            tuple: (original_data, metadata)
        """
        if not packed_chunks:
            return {
                "data": None,
                "metadata": None
            }
        
        # Parse all chunks
        chunks = []
        metadata = None
        expected_chunks_count = None
        
        for packed_chunk in packed_chunks:
            # Extract chunk entry
            chunk_entry = self._disassemble_chunk_entry(packed_chunk)
            
            # Set expected chunks count if not already set
            if expected_chunks_count is None:
                expected_chunks_count = chunk_entry['chunks_count']
            elif expected_chunks_count != chunk_entry['chunks_count']:
                raise ValueError(f"Inconsistent chunks count: expected {expected_chunks_count}, got {chunk_entry['chunks_count']}")
            
            # Validate chunk digest
            computed_digest = hashlib.sha256(chunk_entry['chunk_data']).digest()
            if computed_digest.hex() != chunk_entry['chunk_digest']:
                raise ValueError(f"Chunk digest mismatch for chunk {chunk_entry['chunk_id']}")
            
            chunks.append((chunk_entry['chunk_id'], chunk_entry['chunk_data']))
            
            # Use metadata from first chunk
            if metadata is None:
                metadata = chunk_entry['metadata']
            else:
                assert metadata == chunk_entry['metadata']
        
        # Validate that we have all chunks
        if len(chunks) != expected_chunks_count:
            raise ValueError(f"Missing chunks: expected {expected_chunks_count}, got {len(chunks)}")
        
        # Sort chunks by chunk_id to ensure correct order
        chunks.sort(key=lambda x: x[0])
        
        # Concatenate chunk data
        data = b''.join(chunk_data for _, chunk_data in chunks)
        
        if not metadata:
            metadata = None
        
        return {
            "data": data, 
            "metadata": metadata
        }
    

        
        
        
        


