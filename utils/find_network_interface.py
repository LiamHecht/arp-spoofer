def get_network_interface():
    try:
        with open('/proc/net/route', 'r') as route_file:
            lines = route_file.readlines()[1:]  # Skip the header line
            if len(lines) >= 2:
                second_line = lines[1]
                fields = second_line.strip().split()
                if len(fields) >= 1:
                    return fields[0]
    except Exception as e:
        print("Error:", e)
    return None

# Get and print the second interface
if __name__ == "__main__":
    interface = get_network_interface()
    if interface:
        print("Second Interface:", interface)
    else:
        print("Second interface not found.")
