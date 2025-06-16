from netdrt.protocol import NetDRTProtocol



def test_pack():
    proto = NetDRTProtocol(
        {"chunk_size": 8, "chunk_size_variance_percentage": 0.75, "append_random_bytes": 1024}
    )

    # proto = NetDRTProtocol(
    #     {"chunk_size": 8, "chunk_size_variance_percentage": 0.75, "append_random_bytes": 0}
    # )

    data = bytes([_ for _ in range(32)])

    packed = proto.pack(data, input_data_metadata={"a": 1})
    print(packed)

    for _ in range(len(packed)):
        print(proto._disassemble_chunk_entry(packed[_]))

    unpacked = proto.unpack(packed_chunks=packed)
    print(unpacked)


if __name__ == "__main__":
    test_pack()