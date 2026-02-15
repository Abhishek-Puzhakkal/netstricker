# **NetStricker**





### **Introduction**



**NetStricker is a simple python based Lan discovery and port scanning tool .**

**It perform discovering hosts under Lan , OUI lookup of hosts under Lan ,  port scanning and printing open-ports and it's default service running on each open ports (no banner grabbing)**



**Also it work well in Linux environment , On windows it Definitely stuck or may take longer time or give incorrect answers , So I recommend to use on Linux environment , Once again it is a basic tool not like nmap or something like that , just a simple tool , I created it as a warm up project to get confidence for my future projects** 



## 

### **Features**



* **ICMP and ARP based LAN host discovery**



* **ARP-based MAC address resolution**



* **MAC vendor (OUI) identification**



* **TCP port scanning**



* **Common port service detection**



* **Clean CLI interface with progress spinners**



* **Works on Linux (fully) and Windows (limited)**





### **Installation** 





    git clone https://github.com/Abhishek-Puzhakkal/netstricker.git



	cd netstricker



	python -m venv venv



	source venv/bin/activate      # Linux**

	venv\\Scripts\\activate         # Windows**



	pip install -r requirements.txt**

## 

## **Usage** 



1. **LAN DISCOVERY**



		python netstricker.py --discover 192.168.1.0/24  #This command to discover hosts under the Lan** 



**2. PORT SCANNING**



	**python netstricker.py --scan 192.168.1.4 --port 1 150 #On this command the --port starting-port ending-port then it will check entire port range inside that range**









**Author**

**Abhishek Puzhakkal**









