from scapy.all import ARP, Ether, srp
import socket
import nmap
import ping3

def measure_ping(target):
    response_time = ping3.ping(target)
    if response_time is not None:
        return (f"{response_time}")

def get_ip_range():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    ip_parts = ip_address.split('.')
    ip_parts[-1] = '0/24'  # Assuming a subnet mask of 255.255.255.0
    ip_range = '.'.join(ip_parts)
    return ip_range


def get_connected_devices(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')

    connected_devices = []
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            mac_address = nm[host]['addresses']['mac']
            ip_address = nm[host]['addresses']['ipv4']

            connected_devices.append({'ip': ip_address, 'mac': mac_address})

    return connected_devices

network_range = get_ip_range()

connected_devices = get_connected_devices(network_range)
for device in connected_devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}, ping: {measure_ping(device['ip'])} ms")

