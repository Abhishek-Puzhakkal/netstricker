import argparse
from rich.console import Console
from rich.spinner import Spinner
from input_validater import IpRangeChecker , ValueChecker
import platform


from scanning_result import LanScanning, OuiMap, IcmpPingLanScanning, TcpSynScan, BannerGrabing, CommonPorts, TcpConnectScan

base_os = platform.system()

rich_console = Console()

commands = argparse.ArgumentParser(description="NetStricker is simple Lan discoviering and ports scanning tool ",
                                   epilog= """
        Usage :

            netstricker.py --discover <network range>  -> This is the commad for finding live hosts under Lan
            netstricker.py --scan <target Ip or Domain name> --port <starting-port> <ending-port> -> This is the command for port scanning , and it will check all the ip's in between user provided starting and ending port
        
        Example usage:

            netstricker.py --discover 192.168.1.0/24
            netstricker.py --scan 192.168.1.4 --port 1 500

        Note :- Anything else other than above mentioned example will show a error message 

        Author: Abhishek Puzhakkal
                                        """ 
                                        ,formatter_class=argparse.RawDescriptionHelpFormatter)

command_modes = commands.add_mutually_exclusive_group(required=True)

command_modes.add_argument('--discover', metavar='Current Lan Range', help='To discover live hosts on your Lan ')
command_modes.add_argument('--scan', metavar="Target", help='The target ip or domain name for portscanning ')

commands.add_argument("--port", nargs=2, type=int, metavar='port-number', 
                      help='The staring and Ending ports for port scainng ,' \
                      ' the scanner will scan all the ports in between the provided starting and ending ports ')

user_input = commands.parse_args()
if user_input.discover and user_input.port:
    rich_console.print(f"[red] Invalid commands , Please check --help documentaion ")
elif user_input.discover :
    checker = IpRangeChecker(user_input.discover)
    checker_result = checker.checker()
    if checker_result == True and base_os != "Windows":
        
        with rich_console.status('Started Discovring Hosts on Lan......', spinner='dots12'):
            arp_scanning = LanScanning(user_input.discover)
            arp_scanning_result = arp_scanning.arp_scanning()
            oui_lookup = OuiMap()
            local_oui_db = oui_lookup.load_oui_database()

        for ip, mac in arp_scanning_result.items():
            oui_arp_scanning_result = mac.upper().replace(":", "-")[0:8]
            mac_vendor = local_oui_db.get(oui_arp_scanning_result)
            rich_console.print(f" [cyan]{ip} : {mac} : {mac_vendor} [/cyan]")

    elif checker_result == True and base_os == "Windows":
        
        with rich_console.status('Started Discovring Hosts on Lan......', spinner='dots12'):
            icmp_scanning = IcmpPingLanScanning(user_input.discover)
            icmp_result = icmp_scanning.icmp_ping()
            oui_lookup = OuiMap()
            local_oui_db = oui_lookup.load_oui_database()

        for ip, mac in icmp_result.items():
            oui_icmp_scanning = mac.upper().replace(":", "-")[0:8]
            mac_vendor = local_oui_db.get(oui_icmp_scanning)

            rich_console.print(f"[cyan]{ip} : {mac} : {mac_vendor}[/cyan]")
    elif checker_result == False:
        rich_console.print(f'[red]invalid user input :- [bold yellow]{user_input.discover}[/bold yellow] is not valid 1111 [/red]')

if user_input.scan and user_input.port:
    if base_os != 'Windows':
        value_checker = ValueChecker(user_input.scan)
        result_value_checker = value_checker.value_checking_function()
        if result_value_checker == 'ip':
            
            rich_console.print(f"Your given ip is a valid one [yellow]{user_input.scan}[/yellow]")
            

            with rich_console.status('Started Port Scanning On Target......', spinner='dots12'):
                port_scaning_result = BannerGrabing(user_input.scan, user_input.port)
                scanning_result, ip_addrr = port_scaning_result.tcp_syc_scan()
                banners = port_scaning_result.banner_grabing()
                common_ports_and_serviceses = CommonPorts()
            
            
            if scanning_result:
                for port in scanning_result:
                    rich_console.print(f"[cyan]{ip_addrr} : {port} : {common_ports_and_serviceses.get_port_service(port)}[/cyan]")
            else:
                rich_console.print(f"[red]Sorry, netstricker can't find any open ports on [cyan]{user_input.scan}[/cyan][/red]")

                
                
        elif result_value_checker == "domain name":
            
            rich_console.print(f"The [bold yellow]{user_input.scan}[/bold yellow] is a valid domain name")
            
            with rich_console.status('Started Port Scanning On Target......', spinner='dots12'):
                port_scaning_result = BannerGrabing(user_input.scan, user_input.port)
                scanning_result, ip_addrr = port_scaning_result.tcp_syc_scan()
                common_ports_and_serviceses = CommonPorts()
            
            
            if scanning_result:
                for port in scanning_result:
                    rich_console.print(f"[cyan]{ip_addrr} : {port} : {common_ports_and_serviceses.get_port_service(port)}[/cyan]")
            else:
                rich_console.print(f"[red]Sorry, netstricker can't find any open ports on [cyan]{user_input.scan}[/cyan][/red]")
                
        else:
            rich_console.print(f"[red]invalid user input [yellow{user_input.scan} [/yellow]is not a valid ip or doamin name [/red]")
    else:
        
        value_checker = ValueChecker(user_input.scan)
        result_value_checker = value_checker.value_checking_function()
        if result_value_checker == 'ip':
            rich_console.print(f"Your given ip is a valid one [bold yellow]{user_input.scan}[/bold yellow]")
           
            with rich_console.status('[yellow] Port scanning started...[/yellow]', spinner='dots12'):
                port_scaning_result_windows = TcpConnectScan(user_input.scan, user_input.port)
                open_ports = port_scaning_result_windows.tcp_connect_scan()
                common_ports_and_serviceses = CommonPorts()
            
            

            if open_ports:
                for ports in open_ports:
                    rich_console.print(f'[cyan]{user_input.scan} : {ports} : {common_ports_and_serviceses.get_port_service(ports)}[/cyan]')
                
            else:
                rich_console.print(f"[red]Sorry, netstricker can't find any open ports on [yellow]{user_input.scan}[/yellow][/red]")
        elif result_value_checker == "domain name":
            
            rich_console.print(f"The [bold yellow]{user_input.scan}[/bold yellow] is a valid domain name")
            with rich_console.status('Started Port Scanning On Target......', spinner='dots12'):
                port_scaning_result_windows = TcpConnectScan(user_input.scan, user_input.port)
                open_ports = port_scaning_result_windows.tcp_connect_scan()
                common_ports_and_serviceses = CommonPorts()

            if open_ports:
                for ports in open_ports:
                    rich_console.print(f'[cyan]{user_input.scan} : {ports} : {common_ports_and_serviceses.get_port_service(ports)}[/cyan]')
            else:
                Console.print(f"[red]Sorry, netstricker can't find any open ports on [cyan]{user_input.scan}[/cyan][/red]")
        else:
            rich_console.print(f"[red]invalid user input:- [bold yellow]{user_input.scan}[/bold yellow] is not a valid ip or doamin name [/red]")
elif user_input.scan:
    rich_console.print('[red] Invalid commands --scan option need --port with it ')
            



