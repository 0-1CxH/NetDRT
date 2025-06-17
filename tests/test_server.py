from netdrt.server import NetDRTServer, create_flask_server

if __name__ == "__main__":
    server_configs = {
        'log_level': 'DEBUG',
        'passkey': '1',
        'base_port': 9651,
        'file_reception_dir': './received_files'
    }
    
    server = NetDRTServer(server_configs)
    flask_app = create_flask_server(server)
    flask_app.run(host='0.0.0.0', port=server_configs['base_port'])