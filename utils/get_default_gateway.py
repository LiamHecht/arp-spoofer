def get_default_gateway():
    try:
        with open('/proc/net/route', 'r') as route_file:
            for line in route_file.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= 3:
                    interface, destination, gateway = fields[:3]
                    if destination == '00000000' and gateway != '00000000':
                        # Convert the gateway hexadecimal address to an IP address
                        gateway_segments = [str(int(gateway[i:i+2], 16)) for i in range(0, len(gateway), 2)]
                        gateway_ip = '.'.join(reversed(gateway_segments))
                        return gateway_ip
    except Exception as e:
        print("Error:", e)
    return None

# Get and print the default gateway
if __name__ == "__main__":
    default_gateway = get_default_gateway()
    if default_gateway:
        print("Default Gateway:", default_gateway)
    else:
        print("Default gateway not found.")
