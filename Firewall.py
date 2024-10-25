import subprocess
import os
from netfilterqueue import NetfilterQueue
from scapy.all import *
import time
import json
import ipaddress  # For CIDR handling
import logging  # For logging

# Setup logging
logging.basicConfig(
    filename='history.log',  # Log file
    level=logging.INFO,  # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
)

# Function to run a system command with elevated privileges (sudo)
def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}\nError: {e}")
        logging.error(f"Error executing command: {command} - {e}")

# Set up iptables rules for the firewall
def setup_iptables():
    print("Setting up iptables rules...")
    logging.info("Setting up iptables rules.")
    run_command("sudo iptables -I INPUT -j NFQUEUE --queue-num 1")
    run_command("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1")

# Teardown iptables rules to restore the system to default state
def teardown_iptables():
    print("Flushing iptables rules...")
    logging.info("Flushing iptables rules.")
    run_command("sudo iptables -F")
    run_command("sudo iptables -t nat -F")
    run_command("sudo iptables -t mangle -F")
    run_command("sudo iptables -X")

# Load rules from JSON
try:
    f = open("firewallrules.json", "r")
    y = json.load(f)
    f.close()

    # Validate and load the rule sets
    ListOfBannedIpAddr = y.get("ListOfBannedIpAddr", [])
    ListOfBannedPorts = y.get("ListOfBannedPorts", [])
    ListOfBannedPrefixes = [ipaddress.ip_network(prefix) for prefix in y.get("ListOfBannedPrefixes", [])]
    TimeThreshold = y.get("TimeThreshold", 10)
    PacketThreshold = y.get("PacketThreshold", 100)
    BlockPingAttacks = y.get("BlockPingAttacks", "True").lower() == "true"

    logging.info("Firewall rules loaded from firewallrules.json.")

except FileNotFoundError:
    print("Rule file (firewallrules.json) not found, setting default values")
    logging.warning("Rule file (firewallrules.json) not found, using default values.")
    ListOfBannedIpAddr = []
    ListOfBannedPorts = []
    ListOfBannedPrefixes = []
    TimeThreshold = 10
    PacketThreshold = 100
    BlockPingAttacks = True

DictOfPackets = {}

def firewall(pkt):
    sca = IP(pkt.get_payload())

    # Check if the source IP is banned
    if sca.src in ListOfBannedIpAddr:
        print(f"{sca.src} is banned by the firewall.")
        logging.info(f"Blocked IP: {sca.src}")
        pkt.drop()
        return

    # Check if the packet matches any banned IP prefixes (CIDR)
    src_ip = ipaddress.ip_address(sca.src)
    if any(src_ip in prefix for prefix in ListOfBannedPrefixes):
        print(f"Prefix of {sca.src} is banned by the firewall.")
        logging.info(f"Blocked by prefix: {sca.src}")
        pkt.drop()
        return

    # Check for TCP/UDP and if destination port is banned
    if sca.haslayer(TCP):
        t = sca.getlayer(TCP)
        if t.dport in ListOfBannedPorts:
            print(f"TCP port {t.dport} is blocked by the firewall.")
            logging.info(f"Blocked TCP port: {t.dport} from {sca.src}")
            pkt.drop()
            return

    if sca.haslayer(UDP):
        u = sca.getlayer(UDP)
        if u.dport in ListOfBannedPorts:
            print(f"UDP port {u.dport} is blocked by the firewall.")
            logging.info(f"Blocked UDP port: {u.dport} from {sca.src}")
            pkt.drop()
            return

    # Block Ping Attacks
    if BlockPingAttacks and sca.haslayer(ICMP):
        icmp_layer = sca.getlayer(ICMP)
        if icmp_layer.code == 0:  # Echo request
            if sca.src in DictOfPackets:
                if len(DictOfPackets[sca.src]) >= PacketThreshold:
                    if time.time() - DictOfPackets[sca.src][0] <= TimeThreshold:
                        print(f"Ping by {sca.src} blocked by the firewall (too many requests).")
                        logging.info(f"Ping flood blocked from {sca.src}")
                        pkt.drop()
                        return
                    else:
                        DictOfPackets[sca.src].pop(0)
                DictOfPackets[sca.src].append(time.time())
            else:
                DictOfPackets[sca.src] = [time.time()]

    pkt.accept()  # Accept the packet if it doesn't match any rules

# Bind the firewall to NetfilterQueue
nfqueue = NetfilterQueue()

try:
    # Setup iptables rules
    setup_iptables()

    print("Firewall running...")
    logging.info("Firewall started.")
    nfqueue.bind(1, firewall)
    nfqueue.run()

except KeyboardInterrupt:
    print("Stopping the firewall...")
    logging.info("Firewall stopped by user.")

finally:
    # Ensure that iptables rules are flushed on exit
    teardown_iptables()
    nfqueue.unbind()
    logging.info("Firewall stopped and iptables rules flushed.")
