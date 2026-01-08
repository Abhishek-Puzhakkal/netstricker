import argparse
from input_validater import IpRangeChecker , ValueChecker
import platform
from scanning_result import LanScanning, OuiMap, IcmpPingLanScanning, TcpSynScan, BannerGrabing, CommonPorts, TcpConnectScan

base_os = platform.system()

commands = argparse.ArgumentParser()

commands.add_argument("--discover")
commands.add_argument("--scan")
commands.add_argument("--port", "-p", "-p-", nargs=2, type=int)
user_input = commands.parse_args()

if user_input.discover:
    checker = IpRangeChecker(user_input.discover)
    if checker.checker() and base_os != "Windows":
        print(f'scanning started on {user_input.discover}')

        arp_scanning = LanScanning(user_input.discover)
        arp_scanning_result = arp_scanning.arp_scanning()
        oui_lookup = OuiMap()
        local_oui_db = oui_lookup.load_oui_database()

        for ip, mac in arp_scanning_result.items():
            oui_arp_scanning_result = mac.upper().replace(":", "-")[0:8]
            mac_vendor = local_oui_db.get(oui_arp_scanning_result)
            print(f" {ip} : {mac} : {mac_vendor}")

    elif checker.checker() and base_os == "Windows":
        icmp_scanning = IcmpPingLanScanning(user_input.discover)
        icmp_result = icmp_scanning.icmp_ping()
        oui_lookup = OuiMap()
        local_oui_db = oui_lookup.load_oui_database()

        for ip, mac in icmp_result:
            oui_icmp_scanning = mac.upper().replace(":", "-")[0:8]
            mac_vendor = local_oui_db.get(oui_icmp_scanning)

            print(f"{ip} : {mac} : {mac_vendor}")


    else:
        print(f'invalid user input {user_input.discover} is not valid ')
elif user_input.scan:
    if base_os != 'Windows':
        print('non windows code is running')
        value_checker = ValueChecker(user_input.scan)
        result_value_checker = value_checker.value_checking_function()
        if result_value_checker == 'ip':
            print(f"your given ip is a valid one {user_input.scan}")
            print(f"port scanning started on {user_input.scan}")
            port_scaning_result = BannerGrabing(user_input.scan, user_input.port)
            scanning_result, ip_addrr = port_scaning_result.tcp_syc_scan()
            banners = port_scaning_result.banner_grabing()
            common_ports_and_serviceses = CommonPorts()
            
            
            if banners:
                banner_lookuped = list()
                for i in banners:
                    print(f'{ip_addrr} : {i}')
                    banner_lookuped.append(i[0])
                unmapped = list(set(banner_lookuped) - set(scanning_result))

                for i in unmapped:
                    if i in scanning_result:
                        print(f'{ip_addrr} : {i} : {common_ports_and_serviceses.common_ports(i)}')
            else:
                for port in scanning_result:
                    print(f'{ip_addrr} : {port} : {common_ports_and_serviceses.common_ports(port)}')
                
                
        elif result_value_checker == "domain name":
            
            print(f"the {user_input.scan} is a valid domain name")
            print(f"port scanning started on {user_input.scan}")
            port_scaning_result = BannerGrabing(user_input.scan, user_input.port)
            scanning_result, ip_addrr = port_scaning_result.tcp_syc_scan()
            banners = port_scaning_result.banner_grabing()
            
            common_ports_and_serviceses = CommonPorts()
            
            
            if banners:
                banner_lookuped = list()
                for i in banners:
                    print(f'{ip_addrr} : {i}')
                    banner_lookuped.append(i[0])
                unmapped = list(set(banner_lookuped) - set(scanning_result))

                for i in unmapped:
                    if i in scanning_result:
                        print(f'{ip_addrr} : {i} : {common_ports_and_serviceses.common_ports(i)}')
            else:
                for port in scanning_result:
                    print(f'{ip_addrr} : {port} : {common_ports_and_serviceses.common_ports(port)}')
                
        else:
            print(f"invalid user input {user_input.scan} is not a valid ip or doamin name ")
    else:
        print('windows else block runnign')
        value_checker = ValueChecker(user_input.scan)
        result_value_checker = value_checker.value_checking_function()
        if result_value_checker == 'ip':
            print(f"your given ip is a valid one {user_input.scan}")
            print(f"port scanning started on {user_input.scan}")
            port_scaning_result_windows = TcpConnectScan(user_input.scan, user_input.port)
            open_ports = port_scaning_result_windows.tcp_connect_scan()
            common_ports_and_serviceses = CommonPorts()

            if open_ports:
                for ports in open_ports:
                    print(f'{user_input.scan} : {ports} : {common_ports_and_serviceses.common_ports(ports)}')
            else:
                print("i didn't got any open ports , my be my fault ")
        elif result_value_checker == "domain name":
            
            print(f"the {user_input.scan} is a valid domain name")
            print(f"port scanning started on {user_input.scan}")
            port_scaning_result_windows = TcpConnectScan(user_input.scan, user_input.port)
            open_ports = port_scaning_result_windows.tcp_connect_scan()
            common_ports_and_serviceses = CommonPorts()

            if open_ports:
                for ports in open_ports:
                    print(f'{user_input.scan} : {ports} : {common_ports_and_serviceses.common_ports(ports)}')
            else:
                print("i didn't got any open ports , my be my fault ")
        else:
            print(f"invalid user input {user_input.scan} is not a valid ip or doamin name ")
            



