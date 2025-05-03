import socket
import psutil
import socket


def get_subnet_mask(interface_name='Wi-Fi'):
    # Get all network interfaces
    interfaces = psutil.net_if_addrs()

    # Check for the specific interface
    if interface_name in interfaces:
        for addr in interfaces[interface_name]:
            if addr.family == socket.AF_INET:
                return addr.netmask
    return None


def getLocalIp():
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock1.connect(("8.8.8.8", 80))
    LOCALIP = sock1.getsockname()[0]
    sock1.close()
    return LOCALIP