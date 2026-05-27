import streamlit as st
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether
import pandas as pd
from io import BytesIO
import datetime

def load_pcap(uploaded_file):
    """Load and process PCAP file"""
    try:
        with st.spinner("Reading PCAP file..."):
            bytes_data = uploaded_file.read()
            packets = rdpcap(BytesIO(bytes_data))
        
        st.success(f"✅ Loaded {len(packets)} packets")
        
        data = []
        for pkt in packets:
            try:
                packet_info = {
                    'timestamp': datetime.datetime.fromtimestamp(float(pkt.time)),
                    'packet_size': len(pkt),
                    'protocol': 'Unknown',
                    'src_ip': None,
                    'dst_ip': None,
                    'src_port': None,
                    'dst_port': None,
                    'flags': None,
                }

                if Ether in pkt:
                    packet_info['src_mac'] = pkt[Ether].src
                    packet_info['dst_mac'] = pkt[Ether].dst

                if IP in pkt:
                    packet_info['src_ip'] = pkt[IP].src
                    packet_info['dst_ip'] = pkt[IP].dst
                    packet_info['ttl'] = pkt[IP].ttl

                if TCP in pkt:
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = pkt[TCP].sport
                    packet_info['dst_port'] = pkt[TCP].dport
                    packet_info['flags'] = str(pkt[TCP].flags)
                elif UDP in pkt:
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = pkt[UDP].sport
                    packet_info['dst_port'] = pkt[UDP].dport
                elif ICMP in pkt:
                    packet_info['protocol'] = 'ICMP'

                data.append(packet_info)
            except:
                continue

        df = pd.DataFrame(data)
        
        if not df.empty:
            df['hour'] = df['timestamp'].dt.hour
            df['flow'] = df.apply(
                lambda row: f"{row.get('src_ip')}:{row.get('src_port')} → {row.get('dst_ip')}:{row.get('dst_port')}", 
                axis=1
            )

        return packets, df

    except Exception as e:
        st.error(f"Error loading PCAP: {str(e)}")
        return [], pd.DataFrame()