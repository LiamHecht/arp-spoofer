import subprocess


def find_mac(ip):

    command = ["ping", "-c", "2", ip]  # Linux/Unix

    # Run the ping command
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
        print(output)
    except subprocess.CalledProcessError as e:
        print(f"Ping failed with error: {e.returncode}")
# if __name__ == "__main__":
#     find_mac("10.0.0.1")
#     find_mac("10.0.0.27")