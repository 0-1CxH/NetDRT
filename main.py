import argparse
import yaml
import time
from netdrt import NetDRTClient, NetDRTServer


def read_config_file(yaml_path):
    """Read and parse the YAML configuration file."""
    with open(yaml_path, 'r') as f:
        return yaml.safe_load(f)
    

def prepare_client(configs):
    """Initialize and return a NetDRT client."""
    return NetDRTClient(configs)

def prepare_server(configs):
    """Initialize and start the NetDRT server."""
    NetDRTServer.serve(configs)


def timed_sending_file(client_instance, file_path):
    start_time = time.time()
    client_instance.send_file(file_path)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"File {file_path} sent in {elapsed_time:.2f} seconds.")


def main():
    parser = argparse.ArgumentParser(description='NetDRT - Network Data Reception Tool')
    parser.add_argument('mode', choices=['client', 'server'], help='Operation mode: client or server')
    parser.add_argument('-c', '--config', type=str, required=True, help='Path to configuration YAML file')
    parser.add_argument('-f', '--file', nargs='+', help='File(s) to send (client mode only)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Use CLI manual input to get file to send (client mode only)')
    args = parser.parse_args()
    print(args)

    # read configs
    cfg = read_config_file(args.config)
    if args.mode == 'server':
        prepare_server(cfg)
    else: # client
        client = prepare_client(cfg)
        # Handle interactive mode
        if args.interactive:
            while True:
                file_path = input("Enter file path (or 'quit' to exit): ")
                if file_path.lower() == 'quit':
                    break
                timed_sending_file(client, file_path)
               
        
        # Handle file arguments
        elif args.file:
            for file_path in args.file:
                timed_sending_file(client, file_path)
        else:
            print("No files specified. Use -f to specify files or -i for interactive mode.")
        

if __name__ == "__main__":
    main()