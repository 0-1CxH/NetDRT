from netdrt.service import NetDRTClient

def test_client():
    client = NetDRTClient({})
    client.send_file("tests/sample.txt")


if __name__ == "__main__":
    test_client()