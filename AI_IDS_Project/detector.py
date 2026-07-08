import ollama
from scapy.all import rdpcap, IP, TCP, UDP

# 1. Point to your exact file name from the sidebar
PCAP_FILE = "traffic.pcapng.pcapng"
MODEL_NAME = "deepseek-r1:1.5b" # Or change to "qwen2.5-coder:7b"

print(f"[*] Reading packets from {PCAP_FILE}...")
try:
    packets = rdpcap(PCAP_FILE)
except Exception as e:
    print(f"[-] Error opening file: {e}. Make sure the file name is exact!")
    exit()

# Extract a small text summary of the first 15 packets to give the AI context
packet_summary_text = ""
for i, pkt in enumerate(packets[:15]):
    if pkt.haslayer(IP):
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
        packet_summary_text += f"Index: {i} | Src: {pkt[IP].src} -> Dst: {pkt[IP].dst} | Proto: {proto} | Size: {len(pkt)}\n"

# The Prompt that forces the AI to look for anomalies
prompt = f"""
You are an expert AI Threat Hunter. Analyze these packet logs extracted from a Wireshark capture. 
Look for security anomalies like data exfiltration, port scanning, C2 beaconing, or unusual local traffic.

[PACKET DATA LOGS]:
{packet_summary_text}

Provide a summary specifying if there is an ANOMALY or if the traffic looks CLEAR.
"""

print(f"[*] Sending packet text to local AI ({MODEL_NAME})...")
try:
    response = ollama.generate(model=MODEL_NAME, prompt=prompt)
    print("\n=== AI ANOMALY DETECTION REPORT ===")
    print(response['response'])
except Exception as e:
    print(f"[-] Ollama error: {e}. Is Ollama running in the background?")