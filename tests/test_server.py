from netdrt.server import NetDRTServer

if __name__ == "__main__":
    server_configs = {
        'log_level': 'DEBUG',
        'overwrite_if_exists': True,
        'passkey': '1',
        'port': 9651,
        'file_reception_dir': './received_files'
    }
    
    NetDRTServer.serve(server_configs)