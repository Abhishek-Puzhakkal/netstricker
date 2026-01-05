from scapy.all import*
import socket

class LanScanning():
    def __init__(self, network):

        self.network = network
    
    def arp_scanning(self):
        target_network = self.network

        replied, un_replied = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst= target_network), timeout=2, verbose=0)

        hosts_under_lan = {}

        for sent, recevied in replied:
            ip = recevied.psrc
            mac = recevied.hwsrc

            hosts_under_lan[ip] = mac

        return hosts_under_lan
    
    
class IcmpPingLanScanning():
    def __init__(self, network):
        self.network = network 

    def icmp_ping(self):
        target_network = self.network
        hosts_ip = list()
        hosts_with_ip_mac = {}
        replied, unreplied = sr(IP(dst=target_network)/ICMP(), timeout=2, verbose=0)

        for sent, received in replied:
            ip = received.src
            hosts_ip.append(ip)
        for ip in hosts_ip:
            arp_replied, arp_un_replied = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst= ip), timeout=2)
            for sent, received in arp_replied:
                mac = received.hwsrc
                hosts_with_ip_mac[ip] = mac

        return hosts_with_ip_mac


class TcpSynScan:
    def __init__(self, value, ports):
        self.ports = ports
        self.value = value
        self.open_ports = []
        self.ip_addr = None
    def tcp_syc_scan(self):
        res, unans = sr( IP(dst=self.value)
                /TCP(flags="S", dport=(self.ports)), timeout = 2, verbose = 0)
        
        

        self.ip_addr = socket.gethostbyname(self.value)

        for sent, received in res:
            if received.haslayer(TCP):
                flags = received[TCP].flags

                
                if flags & 0x12 == 0x12:
                   self.open_ports.append(sent[TCP].dport)

        
        return self.open_ports, self.ip_addr

class BannerGrabing(TcpSynScan):
    def __init__(self, value, ports):
        super().__init__(value, ports)
        
    def banner_grabing(self):
        banner = []
        for port in self.open_ports:
            try:
                s = socket.socket()
                s.settimeout(3)
                s.connect((self.ip_addr, port))
                banner.append((port, s.recv(1024).decode(errors="ignore").strip()))
            except Exception:
                pass
            finally:
                s.close()

        return banner


        



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


