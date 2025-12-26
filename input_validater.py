import ipaddress

class IpRangeChecker:
    def __init__(self, ip  ):
        self.ip = ip
    def checker(self):
        try :
            network = ipaddress.ip_network(self.ip, strict=False)
            return True
        except ValueError:
            return False
        
        

        
