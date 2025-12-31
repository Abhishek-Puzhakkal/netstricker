import argparse
from input_validater import IpRangeChecker
import platform
from scanning_result import LanScanning, OuiMap, IcmpPingLanScanning

os = list()

os.append(platform.system())

commands = argparse.ArgumentParser()

commands.add_argument("--discover")
user_input = commands.parse_args()

if user_input.discover:
    checker = IpRangeChecker(user_input.discover)
    if checker.checker() and os != "Windows":
        print(f'scanning started on {user_input.discover}')

        arp_scanning = LanScanning(user_input.discover)
        arp_scanning_result = arp_scanning.arp_scanning()
        oui_lookup = OuiMap()
        local_oui_db = oui_lookup.load_oui_database()

        for ip, mac in arp_scanning_result.items():
            oui_arp_scanning_result = mac.upper().replace(":", "-")[0:8]
            mac_vendor = local_oui_db.get(oui_arp_scanning_result)
            print(f" {ip} : {mac} : {mac_vendor}")

    elif checker.checker() and os == "Windows":
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



