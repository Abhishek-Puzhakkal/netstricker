from scapy.all import*

class LanScanning():
    def __init__(self, network):

        self.network = network
    
    def arp_scanning(self):
        target_network = self.network

        replied, un_replied = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst= target_network), timeout=2)

        hosts_under_lan = {}

        for sent, recevied in replied:
            ip = recevied.psrc
            mac = recevied.hwsrc

            hosts_under_lan[ip] = mac

        return hosts_under_lan
    
    


class OuiMap:

    @staticmethod
    def load_oui_database(file_path="oui.txt"):
        oui_database = {}

        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if "(hex)" in line:
                    parts = line.split()
                    oui = parts[0]
                    vendor = " ".join(parts[2:])
                    oui_database[oui] = vendor

        return oui_database


