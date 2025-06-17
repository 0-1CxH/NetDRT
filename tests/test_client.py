from netdrt.client import NetDRTClient

def test_client():
    client = NetDRTClient({'passkey': '1',})
    # client.send_file("tests/15m.zip")
    while True:
        client.send_file(input())


if __name__ == "__main__":
    test_client()