import pyshark

def get_network_interfaces():
    """Get a list of available network interfaces."""
    try:
        interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
        if not interfaces:
            print("No network interfaces found.")
            return []
        print("Available network interfaces:")
        for i, interface in enumerate(interfaces):
            print(f"{i+1}. {interface}")
        return interfaces
    except Exception as e:
        print("Error retrieving network interfaces:", e)
        return []

# Call the function to display interfaces
get_network_interfaces()
