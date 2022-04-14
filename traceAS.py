from argparse import ArgumentParser
import requests
import socket
import json

echo_icmp, private = b'\x08\x00\x0b\x27\xeb\xd8\x01\x00', {
    ('127.0.0.0', '127.255.255.255'), ('10.0.0.0', '10.255.255.255'),
    ('192.168.0.0', '192.168.255.255'), ('172.16.0.0', '172.31.255.255')
}

def tracer(dest, hops, timeout):
    dest, curr_addr, ttl = socket.gethostbyname(dest), None, 1
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.settimeout(timeout)
        while dest != curr_addr and ttl != hops:
            s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            s.sendto(echo_icmp, (dest, 1))
            try:
                p, addr = s.recvfrom(1024)
                curr_addr = addr[0]
                message = "{0} {1}".format(ttl, curr_addr)
                if check_private_network(curr_addr):
                    message += load_api_ip_info(curr_addr)
                yield message
            except socket.timeout:
                yield '*****'
            ttl += 1


def check_private_network(ip):
    for network in private:
        if network[1] >= ip >= network[0]:
            return False
    return True


def load_api_ip_info(ip):
    apicontent = json.loads(requests.get("http://ipinfo.io/{0}/json".format(ip)).content)
    message = "{}".format(apicontent["ip"])
    if "org" in apicontent and apicontent["org"] != "":
        message += " org: {}".format(apicontent["org"])
    if "loc" in apicontent and apicontent["loc"] != "":
        message += " loc: {}".format(apicontent["loc"])
    return message


if __name__ == '__main__':
    parser = ArgumentParser(description="Trace AS")
    parser.add_argument("-hops", default=32, type=int, help="Max hops amount")
    parser.add_argument("-timeout", default=10, type=int, help="Timeout in seconds")
    parser.add_argument("dest", type=str, help="Destination host")
    args = parser.parse_args()
    for message in tracer(args.dest, args.hops, args.timeout):
        print(message)