from scapy.all import*
import socket

class LanScanning():
    def __init__(self, network):

        self.network = network
    
    def arp_scanning(self) -> dict:
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

    def icmp_ping(self) -> dict :
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
    def tcp_syc_scan(self) -> tuple[list[int], str]:
        res, unans = sr( IP(dst=self.value)/TCP(flags="S", dport=(self.ports)), timeout = 2, verbose = 0)
        
        

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
        
    def banner_grabing(self) -> list:
        banner = []
        for port in self.open_ports:
            try:
                s = socket.socket()
                s.settimeout(3)
                s.connect((self.ip_addr, port))
                banner.append((port, s.recv(1024).decode(errors="ignore").strip()))
            except Exception as e:
                print(e)
            finally:
                s.close()

        return banner

class OuiMap:

    @staticmethod
    def load_oui_database(file_path="oui.txt") -> dict:
        oui_database = {}

        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if "(hex)" in line:
                    parts = line.split()
                    oui = parts[0]
                    vendor = " ".join(parts[2:])
                    oui_database[oui] = vendor

        return oui_database
    

class TcpConnectScan:
    def __init__(self, ip, ports):
        self.ip = ip
        self.starting_point = ports[0]
        self.ending_point = ports[1]
    
    def tcp_connect_scan(self) -> list[int, int] :
        open_ports = list()
        for port in range(self.starting_point, self.ending_point+1):
            try:
                s = socket.socket()
                s.settimeout(2)
                result = s.connect_ex((self.ip, port))
                if result == 0:
                    open_ports.append(port)
            except Exception as e:
                print(e)
            finally:
                s.close()
        
        return open_ports

class CommonPorts:
    def __init__(self):
        self.common_ports = {
            7:"Echo", 20:"FTP data", 21:"FTP", 22:"SSH", 23:"Telnet",
            25:"SMTP", 53:"DNS", 69:"TFTP", 80:"HTTP", 88:"Kerberos", 
            102:"lso-tsap", 110:"POP3", 135:"Microsoft-EPMAP", 137:"NetBIOS-ns", 
            139:"NetBIOS-ssn", 143:"IMAP4", 381:"HP Openview", 383:"HP Openview", 
            443:"HTTPS", 464:"kerberos", 465:"SMTPS", 587:"SMTP", 593:"Microsoft DCOM", 
            636:"LDAP over SSL", 691:"MS Exchange", 902:"VMware Server", 989:"FTP over ssl", 
            990:"FTP over ssl", 993:"IMAP4 over SSL" , 995:"POP3 over SSL", 1025:"Microsoft RPC", 
            1194:"OpenVPN", 1337:"WASTE", 1589:"Cisco VQP",1725:"Stem", 2082:"cPANEL", 
            2083:"radsec, cPanel",2483:"Oracle DB", 2484:"Oracle DB", 2967:"Symantec AV", 
            3074:"XBOX Live", 3306:"MySQL", 3724:"World of Warcraft", 4664:"Google Desktop", 
            5432:"PostgreSQL", 5900:"RFB/VNC Server", 6665:'IRC', 6669:"IRC", 6666:"IRC", 
            6667:'IRC', 6668:'IRC', 6881:"BitTorrent", 6999:"BitTorrent", 6970:"Quicktime", 
            8086:"Kaspersky AV", 8087:"Kaspersky AV", 8222:'VMware Server', 9100:'PDL', 
            10000:'BackupExec', 12345:'NetBus', 27374:"Sub7", 31337:'Back Orifice',
            3389:'RDP', 445:'SMB', 2049:'NFS', 6379:'Redis', 27017:'MongoDB', 8443:'HTTPS alt',
            9200:'Elasticserach', 11211:'Memcached'
        }
    def get_port_service(self, port_number) -> dict:
        return self.common_ports.get(port_number, 'unknown')