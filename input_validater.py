import ipaddress
import socket

class IpRangeChecker:
    def __init__(self, ip  ):
        self.ip = ip
    def checker(self):
        try :
            network = ipaddress.ip_network(self.ip, strict=False)
            return True
        except ValueError:
            return False

class ValueChecker:
    def __init__(self, value):
        self.value = value
    
    def value_checking_function(self):
        try:
            ipaddress.ip_address(self.value)
            return "ip"
        except ValueError:
            pass

        try:
            socket.gethostbyname(self.value)
            return "domain name"
        except socket.gaierror:
            pass

        return False
       
        

    

        
        

        
