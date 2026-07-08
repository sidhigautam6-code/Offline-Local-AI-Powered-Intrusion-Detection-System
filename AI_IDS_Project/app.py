import streamlit as st
import pandas as pd
import time
import os
import datetime
import json
import re
import ollama
from scapy.all import rdpcap, IP, TCP, UDP, sniff
from fpdf import FPDF
import plotly.express as px
import plotly.graph_objects as go
from db_config import db_manager
import hashlib

# =========================================================
# INITIAL CONFIGURATION
# =========================================================
st.set_page_config(page_title="☠️ Enterprise AI-IDS Platform", layout="wide")

# Initialize session state for authentication
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_info' not in st.session_state:
    st.session_state.user_info = None
if 'session_token' not in st.session_state:
    st.session_state.session_token = None
if 'show_register' not in st.session_state:
    st.session_state.show_register = False
if 'active_tab' not in st.session_state:
    st.session_state.active_tab = 0
if 'alert_logs' not in st.session_state:
    st.session_state.alert_logs = []
if 'alert_active' not in st.session_state:
    st.session_state.alert_active = False
if 'last_alert_time' not in st.session_state:
    st.session_state.last_alert_time = 0
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'captured_df' not in st.session_state:
    st.session_state.captured_df = pd.DataFrame()
if 'all_packets' not in st.session_state:
    st.session_state.all_packets = []
if 'last_capture_type' not in st.session_state:
    st.session_state.last_capture_type = None
if 'capture_history' not in st.session_state:
    st.session_state.capture_history = []
if 'loaded_capture_index' not in st.session_state:
    st.session_state.loaded_capture_index = None

# Check for existing session on app load
def check_existing_session():
    if 'session_token' in st.session_state and st.session_state.session_token:
        user_info = db_manager.validate_session(st.session_state.session_token)
        if user_info:
            st.session_state.authenticated = True
            st.session_state.user_info = user_info
            return True
    return False

# =========================================================
# LOGIN/REGISTRATION UI
# =========================================================
def login_page():
    # Custom CSS for dark red and black background
    st.markdown("""
    <style>
        /* Dark red and black gradient background */
        .stApp {
            background: linear-gradient(135deg, #1a0000 0%, #2d0000 25%, #000000 50%, #1a0000 75%, #2d0000 100%);
            background-size: 200% 200%;
            animation: gradientShift 10s ease infinite;
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        
        /* Dark overlay with red glow */
        .stApp::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at 50% 50%, rgba(139, 0, 0, 0.15) 0%, rgba(0, 0, 0, 0.8) 100%);
            pointer-events: none;
            z-index: 0;
        }
        
        /* Ensure all form elements are visible */
        .stTextInput > div > div > input {
            background-color: rgba(0, 0, 0, 0.9) !important;
            color: white !important;
            border: 1px solid #8b0000 !important;
            border-radius: 8px !important;
        }
        
        .stTextInput > div > div > input:focus {
            border-color: #ff0000 !important;
            box-shadow: 0 0 10px rgba(255, 0, 0, 0.3) !important;
        }
        
        .stTextInput > label {
            color: #ff6b6b !important;
        }
        
        /* Make buttons visible with red theme */
        .stButton > button {
            background: linear-gradient(135deg, #8b0000, #cc0000) !important;
            color: white !important;
            border: none !important;
            border-radius: 8px !important;
            font-weight: bold !important;
        }
        
        .stButton > button:hover {
            background: linear-gradient(135deg, #cc0000, #ff0000) !important;
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(255, 0, 0, 0.4);
        }
        
        /* Secondary button style */
        .stButton > button:nth-child(2) {
            background: transparent !important;
            border: 1px solid #cc0000 !important;
            color: #ff6b6b !important;
        }
        
        .stButton > button:nth-child(2):hover {
            background: rgba(204, 0, 0, 0.2) !important;
            border-color: #ff0000 !important;
            color: #ff0000 !important;
        }
        
        /* Alert messages visibility */
        .stAlert {
            background-color: rgba(0, 0, 0, 0.9) !important;
            color: white !important;
            border-left: 4px solid #cc0000 !important;
        }
        
        /* Title styling */
        h1, .stTitle {
            color: #ff6b6b !important;
            text-shadow: 0 0 20px rgba(255, 0, 0, 0.5) !important;
        }
        
        /* Subheader styling */
        .stSubheader {
            color: #ff6b6b !important;
        }
        
        /* Info and warning messages */
        .stAlert-success {
            border-left-color: #00ff00 !important;
        }
        
        /* Footer styling */
        .footer-text {
            color: #8b8b8b !important;
        }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🔐 AI-IDS Platform Login")
    
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        if not st.session_state.show_register:
            # Login Form - using unique key
            with st.form(key="login_form_main"):
                username = st.text_input("Username or Email", key="login_username_input")
                password = st.text_input("Password", type="password", key="login_password_input")
                
                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    submitted = st.form_submit_button("🔓 Login", use_container_width=True)
                with col_btn2:
                    if st.form_submit_button("📝 Register", use_container_width=True):
                        st.session_state.show_register = True
                        st.rerun()
                
                if submitted:
                    if username and password:
                        client_ip = 'Local'
                        success, user_info, message = db_manager.login_user(username, password, client_ip)
                        if success:
                            st.session_state.authenticated = True
                            st.session_state.user_info = user_info
                            st.session_state.session_token = user_info['session_token']
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
                    else:
                        st.warning("Please enter both username and password")
        else:
            # Registration Form - using unique key
            with st.form(key="register_form_main"):
                st.subheader("📝 Create New Account")
                full_name = st.text_input("Full Name", key="reg_fullname_input")
                username = st.text_input("Username*", key="reg_username_input")
                email = st.text_input("Email*", key="reg_email_input")
                password = st.text_input("Password*", type="password", key="reg_password_input")
                confirm_password = st.text_input("Confirm Password*", type="password", key="reg_confirm_input")
                
                col_btn1, col_btn2 = st.columns(2)
                with col_btn1:
                    submitted = st.form_submit_button("✅ Register", use_container_width=True)
                with col_btn2:
                    if st.form_submit_button("← Back to Login", use_container_width=True):
                        st.session_state.show_register = False
                        st.rerun()
                
                if submitted:
                    if not all([username, email, password]):
                        st.error("Please fill all required fields (*)")
                    elif password != confirm_password:
                        st.error("Passwords do not match")
                    elif len(password) < 8:
                        st.error("Password must be at least 8 characters long")
                    elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                        st.error("Please enter a valid email address")
                    else:
                        success, message = db_manager.register_user(username, email, password, full_name)
                        if success:
                            st.success(message)
                            st.balloons()
                            st.session_state.show_register = False
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(message)
    
    # Footer
    st.markdown("""
    <div style="position: fixed; bottom: 20px; left: 0; right: 0; text-align: center; color: #8b8b8b; font-size: 12px; z-index: 1;">
        Advanced AI IDS v2.2 • Enterprise SOC Platform
    </div>
    """, unsafe_allow_html=True)

def logout():
    if st.session_state.session_token:
        db_manager.logout_user(st.session_state.session_token)
    for key in ['authenticated', 'user_info', 'session_token', 'show_register']:
        if key in st.session_state:
            del st.session_state[key]
    st.success("Logged out successfully!")
    st.rerun()

def sidebar_logout_button():
    with st.sidebar:
        st.divider()
        if st.button("🚪 Logout", type="secondary", use_container_width=True):
            logout()

# =========================================================
# STYLING
# =========================================================
st.markdown("""
<style>
    .stApp { background-color: #05070f !important; color: #f1f5f9 !important; }
    h1, h2, h3 { color: #ef4444 !important; text-shadow: 0 0 15px rgba(239, 68, 68, 0.5) !important; }
    .warning-banner { background: linear-gradient(90deg, #450a0a 0%, #0f172a 100%); padding: 18px; border: 2px solid #ef4444; border-radius: 8px; text-align: center; margin-bottom: 25px; }
    .packet-entry-card { padding: 12px 16px; margin-bottom: 10px; border-radius: 6px; font-family: 'Consolas', monospace; font-size: 13px; display: flex; align-items: center; gap: 12px; }
    .state-normal { background: rgba(56, 189, 248, 0.05); color: #bae6fd; border: 1px solid rgba(56, 189, 248, 0.15); border-left: 5px solid #38bdf8; }
    .state-critical { background: rgba(239, 68, 68, 0.08); color: #fee2e2; border: 1px solid rgba(239, 68, 68, 0.3); border-left: 5px solid #ef4444; }
    .inner-pill { background: rgba(0,0,0,0.5); padding: 3px 8px; border-radius: 4px; font-size: 10.5px; font-weight: bold; }
    .feed-viewport { max-height: 480px; overflow-y: auto; }
    .user-info { background: rgba(239, 68, 68, 0.1); padding: 10px; border-radius: 5px; margin-bottom: 10px; }
</style>
""", unsafe_allow_html=True)

# =========================================================
# HELPER FUNCTIONS
# =========================================================
def send_device_notification(title, message, severity):
    if time.time() - st.session_state.last_alert_time < 1:
        return
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    st.session_state.alert_logs.insert(0, {"time": ts, "title": title, "severity": severity})
    if len(st.session_state.alert_logs) > 50: 
        st.session_state.alert_logs = st.session_state.alert_logs[:50]
    st.toast(f"{title}", icon="🚨" if severity == "critical" else "⚠️")
    if severity == "critical":
        st.session_state.alert_active = True
    st.session_state.last_alert_time = time.time()

def load_pcap_local(uploaded_file):
    temp_path = f"temp_{uploaded_file.name}"
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    packets = rdpcap(temp_path)
    data = []
    for i, pkt in enumerate(packets):
        dt = datetime.datetime.fromtimestamp(float(pkt.time))
        size = len(pkt)
        src_ip = pkt[IP].src if IP in pkt else "N/A"
        dst_ip = pkt[IP].dst if IP in pkt else "N/A"
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
        data.append({"index": i, "timestamp": dt, "src_ip": src_ip, "dst_ip": dst_ip, 
                     "protocol": proto, "size": size})
    df = pd.DataFrame(data)
    return packets, df, temp_path

def extract_ip_distribution(df):
    """Extract IP distribution for SOC analysis"""
    if df.empty:
        return "No data available"
    top_ips = df['src_ip'].value_counts().head(5).to_dict()
    return json.dumps(top_ips)

def clean_json_string(raw_str):
    """Clean JSON string from AI response"""
    raw_str = raw_str.strip()
    if raw_str.startswith('```json'):
        raw_str = raw_str[7:]
    if raw_str.startswith('```'):
        raw_str = raw_str[3:]
    if raw_str.endswith('```'):
        raw_str = raw_str[:-3]
    return raw_str.strip()

# =========================================================
# PERSISTENT HISTORY FUNCTIONS
# =========================================================
HISTORY_FILE = "capture_history.json"

def load_history():
    """Load history from JSON file on app startup"""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for entry in data:
                    if 'df' in entry and isinstance(entry['df'], list):
                        entry['df'] = pd.DataFrame(entry['df'])
                st.session_state.capture_history = data
        except:
            st.session_state.capture_history = []
    else:
        st.session_state.capture_history = []

def save_history():
    """Save history to JSON file"""
    try:
        history_to_save = []
        for entry in st.session_state.capture_history:
            entry_copy = entry.copy()
            if isinstance(entry_copy.get('df'), pd.DataFrame):
                entry_copy['df'] = entry_copy['df'].to_dict('records')
            entry_copy.pop('packets_list', None)
            history_to_save.append(entry_copy)
        
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history_to_save, f, indent=4, default=str)
    except Exception as e:
        st.warning(f"Could not save history: {e}")

# =========================================================
# MAIN APP (Protected by Authentication)
# =========================================================
def main_app():
    # Load history when app starts
    load_history()
    
    # Sidebar with User Info
    with st.sidebar:
        # Display user information
        st.markdown(f"""
        <div class="user-info">
            <p>👤 <strong>{st.session_state.user_info['username']}</strong></p>
            <p>📧 {st.session_state.user_info['email']}</p>
            <p>🔑 Role: {st.session_state.user_info['role'].upper()}</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.header("🚨 THREAT MONITOR")
        if st.session_state.alert_logs:
            if st.button("Clear Logs"):
                st.session_state.alert_logs = []
                st.session_state.alert_active = False
                st.rerun()
        if not st.session_state.alert_logs:
            st.info("System Normal: No threats detected.")
        else:
            for alert in st.session_state.alert_logs[:10]:
                color = "#ef4444" if alert['severity'] == 'critical' else "#f59e0b"
                st.markdown(f"<span style='color:{color}'>●</span> **{alert['time']}**: {alert['title']}", unsafe_allow_html=True)

        st.header("📁 Upload Capture")
        capture_mode = st.radio("Capture Mode", ["Upload PCAP", "Live Sniffing"])

        uploaded_file = None
        if capture_mode == "Upload PCAP":
            uploaded_file = st.file_uploader("Upload PCAP / PCAPNG file", type=["pcap", "pcapng"])
        else:
            interface = st.text_input("Network Interface", "Wi-Fi")
            duration = st.slider("Capture Duration (seconds)", 10, 120, 30)

        st.divider()
        model_choice = st.selectbox("Select Ollama Model", ["deepseek-coder", "deepseek-r1:1.5b", "qwen", "llama3"])
        packet_count = st.slider("Packets to Analyze:", min_value=5, max_value=200, value=50)

        # Persistent Network Capture History
        st.divider()
        st.header("📜 Capture History")
        st.caption("Previous scans (Auto-Saved)")

        if not st.session_state.capture_history:
            st.info("No captures yet. Start scanning!", icon="📭")
        else:
            for i, entry in enumerate(st.session_state.capture_history[:8]):
                with st.expander(f"🔍 {entry['type']}", expanded=False):
                    st.caption(f"🕒 {entry['datetime']}")
                    st.write(f"**File:** {entry['filename']}")
                    st.write(f"**Packets:** {entry['packets']}")
                    st.write(f"**Anomalies:** {entry['anomalies']}")

                if st.button("🔄 Load & Analyze", key=f"load_{i}"):
                    if isinstance(entry.get('df'), pd.DataFrame):
                        loaded_df = entry['df'].copy()
                    else:
                        loaded_df = pd.DataFrame(entry.get('df', []))
                    
                    if 'timestamp' in loaded_df.columns:
                        loaded_df['timestamp'] = pd.to_datetime(loaded_df['timestamp'], errors='coerce')
                    
                    if 'anomaly' not in loaded_df.columns and not loaded_df.empty:
                        mean_size = loaded_df['size'].mean()
                        std_size = loaded_df['size'].std() if loaded_df['size'].std() != 0 else 1.0
                        loaded_df['z_score'] = (loaded_df['size'] - mean_size) / std_size
                        loaded_df['anomaly'] = loaded_df['z_score'].abs() > 2.0
                    
                    st.session_state.captured_df = loaded_df
                    st.session_state.all_packets = []
                    
                    st.success(f"✅ Loaded: {entry['filename']} ({len(loaded_df)} packets)")
                    st.rerun()

        if st.session_state.capture_history:
            if st.button("🗑️ Clear All History", type="secondary"):
                st.session_state.capture_history = []
                save_history()
                st.success("History cleared permanently")
                st.rerun()
        
        # Logout button
        st.divider()
        if st.button("🚪 Logout", type="secondary", use_container_width=True):
            logout()

    # Main content area
    st.markdown("""
    <div class="warning-banner">
        <h2>⚠️ SYSTEM COMPROMISE: NETWORK BREACH INTRUSION DETECTED ⚠️</h2>
        <p style='margin: 5px 0 0 0; color: #fca5a5;'>Active Threat Breach Mitigation Pipeline Operating Environment</p>
    </div>
    """, unsafe_allow_html=True)

    st.title("🛡️ AI-POWERED INTRUSION DETECTION SYSTEM")
    st.caption("Enterprise SOC Platform • Real-Time Analysis • AI Forensics")

    # Initialize local variables
    packets = st.session_state.all_packets if st.session_state.all_packets else []
    df = st.session_state.captured_df if not st.session_state.captured_df.empty else pd.DataFrame()

    # Handle Upload PCAP
    if capture_mode == "Upload PCAP" and uploaded_file:
        with st.spinner("🔄 Decoding target network capture layers..."):
            packets, df, saved_file_path = load_pcap_local(uploaded_file)
            if not df.empty:
                mean_size = df['size'].mean()
                std_size = df['size'].std() if df['size'].std() != 0 else 1.0
                df['z_score'] = (df['size'] - mean_size) / std_size
                df['anomaly'] = df['z_score'].abs() > 2.0
                
                st.session_state.captured_df = df.copy()
                st.session_state.all_packets = packets
                st.session_state.last_capture_type = "Uploaded PCAP"
            
            st.success(f"✅ Successfully Loaded {len(packets)} Packets")
            
            # Save to persistent history
            timestamp = datetime.datetime.now().strftime("%d %b %Y • %I:%M %p")
            st.session_state.capture_history.insert(0, {
                "type": "Uploaded PCAP",
                "filename": uploaded_file.name,
                "packets": len(packets),
                "anomalies": int(df['anomaly'].sum()) if 'anomaly' in df.columns else 0,
                "df": df.copy(),
                "packets_list": packets,
                "datetime": timestamp
            })
            if len(st.session_state.capture_history) > 20:
                st.session_state.capture_history = st.session_state.capture_history[:20]
            save_history()

            # Alerts
            if not df.empty:
                if df['anomaly'].sum() > 0:
                    send_device_notification(f"🔴 Anomaly Detected: {df['anomaly'].sum()} threats in PCAP", 
                                        (f"Uploaded PCAP file contains {df['anomaly'].sum()} anomalous packets...", "critical"))
                else:
                    send_device_notification("✅ PCAP Loaded - No Threats", f"Uploaded file contains {len(packets)} packets...", "normal")

    # Handle Live Sniffing
    elif capture_mode == "Live Sniffing":
        if st.button("🚀 Start Live Sniffing & Threat Hunting", key="live_sniff_btn"):
            with st.spinner(f"Sniffing on {interface} for {duration} seconds..."):
                try:
                    packets = sniff(iface=interface, timeout=duration, count=500)
                    data = []
                    threat_count = 0
                    for pkt in packets:
                        if IP in pkt:
                            size = len(pkt)
                            is_threat = size > 1000
                            if is_threat:
                                threat_count += 1
                            data.append({
                                "index": len(data),
                                "timestamp": datetime.datetime.now(),
                                "src_ip": pkt[IP].src,
                                "dst_ip": pkt[IP].dst,
                                "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other",
                                "size": size,
                                "is_threat": is_threat
                            })
                    df = pd.DataFrame(data)
                    
                    if not df.empty:
                        mean_size = df['size'].mean()
                        std_size = df['size'].std() if df['size'].std() != 0 else 1.0
                        df['z_score'] = (df['size'] - mean_size) / std_size
                        df['anomaly'] = df['z_score'].abs() > 2.0
                    
                    st.session_state.captured_df = df.copy()
                    st.session_state.all_packets = packets
                    st.session_state.last_capture_type = "Live Sniffing"
                    
                    st.success(f"✅ Live Captured {len(packets)} packets, {threat_count} threats!")
                    
                    # Save to History
                    timestamp = datetime.datetime.now().strftime("%d %b %Y • %I:%M %p")
                    st.session_state.capture_history.insert(0, {
                        "type": "Live Sniffing",
                        "filename": f"Live_{interface}_{duration}s",
                        "packets": len(packets),
                        "anomalies": int(df['anomaly'].sum()) if 'anomaly' in df.columns else 0,
                        "df": df.copy(),
                        "packets_list": packets,
                        "datetime": timestamp
                    })
                    if len(st.session_state.capture_history) > 20:
                        st.session_state.capture_history = st.session_state.capture_history[:20]
                    save_history()
                    
                    # Alerts
                    if threat_count > 0:
                        send_device_notification(f"🔴 Live Threat Detected: {threat_count} suspicious packets", "...", "critical")
                    elif not df.empty and df['anomaly'].sum() > 0:
                        send_device_notification(f"⚠️ Anomaly Detected: {df['anomaly'].sum()} statistical outliers", "...", "warning")
                    else:
                        send_device_notification("✅ Live Capture Complete - No Threats", "...", "normal")
                        
                except Exception as e:
                    st.error(f"Sniffing Error: {e}")

    # Define labels for tabs
    tab_names = [
        "📥 Live Packet Feed", 
        "📊 Overview", 
        "📈 Visualizations", 
        "⚠️ Anomaly Detection", 
        "🤖 AI Chat Assistant", 
        "🛡️ SOC Analyst", 
        "👁️ PCAP Intelligence"
    ]

    # Create the tabs
    tabs = st.tabs(tab_names)
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = tabs

    # TAB 1: Live Packet Feed
    with tab1:
        st.header("📥 Live Packet Feed")
        st.caption("Packet Interception View")
        
        packet_placeholder = st.empty()
        
        # Use DataFrame as main source when full packets not available
        display_df = st.session_state.captured_df if not st.session_state.captured_df.empty else df
        display_packets = st.session_state.all_packets if st.session_state.all_packets else packets
        
        if st.button("🔄 Refresh Packet Feed", type="primary", use_container_width=True, key="refresh_feed"):
            st.rerun()

        if not display_df.empty:
            packet_cards_list = []
            to_display = display_df.head(packet_count)   # Use DataFrame for history
            
            for i, row in to_display.iterrows():
                size = int(row.get('size', 0))
                proto = row.get('protocol', 'N/A')
                src_ip = row.get('src_ip', 'N/A')
                dst_ip = row.get('dst_ip', 'N/A')
                is_anomaly = bool(row.get('anomaly', size > 1000))
                
                state_class = "state-critical" if is_anomaly else "state-normal"
                badge = f"☠️ THREAT: {i}" if is_anomaly else f"♦ WIRE: {i}"
                log_line = f"Src: {src_ip} ➔ Dst: {dst_ip} | Proto: {proto} | Size: {size} bytes"
                
                card_html = f"<div class='packet-entry-card {state_class}'><div class='inner-pill'>{badge}</div><div style='flex-grow:1; font-weight:500;'>{log_line}</div></div>"
                packet_cards_list.append(card_html)
            
            with packet_placeholder.container():
                st.html(f"<div class='feed-viewport'>{''.join(packet_cards_list)}</div>")
            
            st.success(f"✅ Showing {len(to_display)} / {len(display_df)} packets")
        else:
            st.warning("No capture loaded yet. Run Live Sniffing or Upload PCAP.")

    # TAB 2: Overview
    with tab2:
        st.header("📊 Network Overview")
        
        # Use DataFrame as primary source of truth
        display_df = st.session_state.captured_df if not st.session_state.captured_df.empty else df
        
        if not display_df.empty:
            total_packets = len(display_df)   # ← This is the most reliable count
            
            col1, col2, col3, col4 = st.columns(4)
            with col1: 
                st.metric("Total Packets", total_packets)
            with col2: 
                st.metric("Unique Host IPs", display_df['src_ip'].nunique())
            with col3: 
                st.metric("Protocols", display_df['protocol'].nunique())
            with col4: 
                st.metric("Total Network Volume", f"{display_df['size'].sum() / 1000:.2f} KB")
            
            st.dataframe(display_df, use_container_width=True)
            st.caption(f"📊 Total Records: {total_packets} packets")
        else:
            st.info("No capture data available.")

    # TAB 3: Visualizations
    with tab3:
        st.header("📈 Visualizations")
        # Use session state df
        display_df = st.session_state.captured_df if not st.session_state.captured_df.empty else df
        
        if not display_df.empty:
            # Fix timestamp type for loaded history data
            if 'timestamp' in display_df.columns:
                display_df['timestamp'] = pd.to_datetime(display_df['timestamp'], errors='coerce')
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("#### IP Interaction Matrix")
                links = display_df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='Volume')
                fig_graph = px.scatter(
                    links, x='src_ip', y='dst_ip', size='Volume', color='Volume',
                    title="Communication Volume Scatter Matrix Map",
                    color_continuous_scale=px.colors.sequential.Reds
                )
                fig_graph.update_layout(template="plotly_dark", plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig_graph, use_container_width=True)
            
            with col2:
                st.markdown("#### Time series transmission rates")
                if pd.api.types.is_datetime64_any_dtype(display_df['timestamp']):
                    df_time = (display_df.set_index('timestamp')
                              .resample('10s')
                              .size()
                              .reset_index(name='Packets'))
                    fig_timeline = px.area(
                        df_time, x='timestamp', y='Packets',
                        title="Volume Rate Over Time (10-Second Windows)",
                        color_discrete_sequence=['#ef4444']
                    )
                    fig_timeline.update_layout(template="plotly_dark", plot_bgcolor='rgba(0,0,0,0)')
                    st.plotly_chart(fig_timeline, use_container_width=True)
                else:
                    st.warning("⚠️ Timestamp data not available for time series chart.")
        else:
            st.warning("No data available for visualizations.")

    # TAB 4: Anomaly Detection
    with tab4:
        st.header("⚠️ ML Anomaly Detection")
        # Use session state df
        display_df = st.session_state.captured_df if not st.session_state.captured_df.empty else df
        if not display_df.empty:
            st.markdown("#### Statistical Behavioral Anomaly Scanner (Z-Score Modeling)")
            
            anomalies = display_df[display_df['anomaly']] if 'anomaly' in display_df.columns else pd.DataFrame()
            
            col1, col2 = st.columns([1, 2])
            with col1:
                st.metric("Discovered Anomalies", len(anomalies))
                st.info("💡 Anomaly trigger threshold calibrated at Z-Score deviation absolute value > 2.0.")
            with col2:
                if not anomalies.empty:
                    st.error("🚨 Outlier Signature Patterns Flagged:")
                    st.dataframe(anomalies[['index', 'src_ip', 'dst_ip', 'protocol', 'size', 'z_score']], use_container_width=True)
                else:
                    st.success("✅ No statistical network behavior anomalies recorded.")
        else:
            st.warning("Upload network capture or start live sniffing to run behavioral models.")

    # TAB 5: AI Chat Assistant
    with tab5:
        st.header("🤖 AI Threat Hunter")
        st.caption("Elite Cybersecurity Analyst • DeepSeek Powered")

        for message in st.session_state.chat_history:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("Ask anything about this network capture..."):
            st.session_state.chat_history.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                with st.spinner("Thinking as Senior Cybersecurity Expert..."):
                    try:
                        display_df = st.session_state.captured_df if not st.session_state.captured_df.empty else df
                        display_packets = st.session_state.all_packets if st.session_state.all_packets else packets
                        context = f"Total Packets: {len(display_packets)} | Unique IPs: {display_df['src_ip'].nunique() if not display_df.empty else 0}"
                        response = ollama.chat(
                            model=model_choice,
                            messages=[{"role": "system", "content": "You are an elite cybersecurity expert."},
                                      {"role": "user", "content": f"{context}\nQuestion: {prompt}"}]
                        )
                        reply = response['message']['content']
                        st.markdown(reply)
                    except Exception as e:
                        st.error(f"AI Error: {e}")
                        reply = "Sorry, I couldn't process that request."
            st.session_state.chat_history.append({"role": "assistant", "content": reply})

    # TAB 6: SOC Analyst
    with tab6:
        st.header("🛡️ SOC Analyst Command Deck")
        st.caption("DeepSeek Triage Agent: Evaluates structural context maps to output verified report schemas.")
        
        if st.button("🚨 Run Full SOC Triage Analysis", type="primary", use_container_width=True):
            
            with st.spinner("Structuring incident evaluation context blocks..."):
                
                # --- STEP A: Initialize variables ---
                report_data = {}
                display_df = st.session_state.captured_df if not st.session_state.captured_df.empty else df
                display_packets = st.session_state.all_packets if st.session_state.all_packets else packets
                
                # --- STEP B: Data Analysis / AI Attempt ---
                try:
                    summary_data = (
                        f"Total Ingested Packets: {len(display_packets)}\n"
                        f"Unique IP Distribution Profile: {extract_ip_distribution(display_df)}\n"
                        f"Protocols Volume Mapping: {display_df['protocol'].value_counts().to_dict() if not display_df.empty else 'N/A'}\n"
                        f"Max Isolated Packet Size: {display_df['size'].max() if not display_df.empty else 0} bytes\n"
                        f"Outlier Anomalies flagged statically: {display_df['anomaly'].sum() if 'anomaly' in display_df.columns else 0}"
                    )
                    
                    system_instruction = (
                        "You are a Tier-3 SOC Incident Commander. Evaluate the provided network log summary and "
                        "output a STRICT, VALID JSON object. Do not output conversational filler. Do not wrap the JSON inside "
                        "backticks. Ensure the JSON follows this exact schema:\n"
                        "{\n"
                        '  "incident_classification": "Attack Classification Name (e.g., C2 Beaconing, Port Scan)",\n'
                        '  "threat_severity_score": Integer between 0 and 100,\n'
                        '  "executive_summary": "High-level summary of the incident and business impact",\n'
                        '  "root_cause_analysis": ["Bullet point 1 detailing why", "Bullet point 2"],\n'
                        '  "mitigation_steps": ["Containment action 1", "Action 2"]\n'
                        "}"
                    )
                    
                    response = ollama.generate(
                        model=model_choice,
                        prompt=f"{system_instruction}\n\nTelemetry Summary Data:\n{summary_data}",
                        format="json",
                        options={"temperature": 0.1}
                    )
                    
                    raw_text = clean_json_string(response.get('response', '{}'))
                    report_data = json.loads(raw_text)
                    
                except Exception as err:
                    # --- STEP C: Fallback ---
                    anomaly_count = display_df['anomaly'].sum() if 'anomaly' in display_df.columns else 0
                    report_data = {
                        "incident_classification": "Undetermined Automated Profile",
                        "threat_severity_score": 85 if anomaly_count > 0 else 30,
                        "executive_summary": "Auto-compiled summary detailing outlier traces in network captures.",
                        "root_cause_analysis": [f"Captured anomalous packet events: {anomaly_count}", "Varying packet lengths detected."],
                        "mitigation_steps": ["Block anomalous external IPs.", "Isolate nodes with highest transmission volumes."]
                    }
                
                # --- STEP D: Render UI ---
                score = report_data.get("threat_severity_score", 0)
                
                if score >= 75:
                    badge_color = "#ef4444"
                    bg_banner = "rgba(239, 68, 68, 0.1)"
                    status_txt = "CRITICAL BREACH ACTIVATED"
                elif score >= 40:
                    badge_color = "#f59e0b"
                    bg_banner = "rgba(245, 158, 11, 0.1)"
                    status_txt = "HIGH RISK SUSPICIOUS ANOMALY"
                else:
                    badge_color = "#10b981"
                    bg_banner = "rgba(16, 185, 129, 0.1)"
                    status_txt = "LOW RISK STANDARD TRAFFIC PROFILE"

                # Threat Assessment Score KPIs
                st.markdown(f"""
                    <div style='background: {bg_banner}; border-left: 6px solid {badge_color}; padding: 18px; border-radius: 6px; margin-bottom: 20px;'>
                        <h4 style='margin: 0; color: #ffffff;'>Incident Classification Focus:</h4>
                        <span style='font-family: monospace; font-size: 20px; color: {badge_color}; font-weight: bold;'>{report_data.get("incident_classification", "Unclassified Threat")} ({status_txt})</span>
                    </div>
                """, unsafe_allow_html=True)

                col_score, col_meta = st.columns([1, 2])
                with col_score:
                    st.metric("Threat Vector Risk Index", f"{score} / 100")
                with col_meta:
                    st.markdown("**Verdict Meter Status Alignment:**")
                    st.markdown(f"""
                    <div style='display:flex; gap: 4px; margin-top: 8px;'>
                        <div style='height:14px; flex:1; border-radius:2px; background:#10b981; opacity:{"1" if score > 0 else "0.2"};'></div>
                        <div style='height:14px; flex:1; border-radius:2px; background:#f59e0b; opacity:{"1" if score >= 40 else "0.2"};'></div>
                        <div style='height:14px; flex:1; border-radius:2px; background:#ef4444; opacity:{"1" if score >= 75 else "0.2"}; box-shadow: { "0 0 10px #ef4444" if score >= 75 else "none" };'></div>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("<hr style='border-color: rgba(255,255,255,0.1); margin: 20px 0;'>", unsafe_allow_html=True)

                # Render White Presentation Report Card
                html_document_payload = f"""
                <div class='diagnosis-paper-card'>
                    <div style='display:flex; align-items:center; gap:15px; margin-bottom:20px;'>
                        <svg width="55" height="55" viewBox="0 0 100 100" style="background:#7f1d1d; border-radius:8px; padding:6px;">
                            <circle cx="50" cy="42" r="22" fill="white"/>
                            <rect x="38" cy="58" width="24" height="14" rx="4" fill="white"/>
                            <circle cx="44" cy="42" r="4" fill="#7f1d1d"/>
                            <circle cx="56" cy="42" r="4" fill="#7f1d1d"/>
                            <rect x="25" y="76" width="50" height="14" rx="3" fill="white"/>
                            <circle cx="35" cy="83" r="2" fill="#7f1d1d"/>
                            <circle cx="42" cy="83" r="2" fill="#7f1d1d"/>
                        </svg>
                        <div>
                            <h2 style='margin:0; font-size:22px; color:#b91c1c; font-family:sans-serif !important;'>Infiltration Incident Triage</h2>
                            <p style='margin:2px 0 0 0; color:#475569; font-size:13px;'>AI FORENSIC HUNTER: Layer analysis and containment recommendations.</p>
                        </div>
                    </div>
                    
                    <p style='color:#334155; font-size:14px; margin-bottom:20px;'>
                        <b>Executive Triage Summary:</b><br>{report_data.get("executive_summary", "No summary calculated.")}
                    </p>

                    <div class='report-grid'>
                        <div class='report-col'>
                            <span class='verdict-badge' style='background-color:#991b1b;'>1. Technical Observations</span>
                            <ul style='margin-top:10px; padding-left:18px; font-size:13px; color:#334155;'>
                                {"".join([f"<li>{obs}</li>" for obs in report_data.get("root_cause_analysis", [])])}
                            </ul>
                        </div>
                        
                        <div class='report-col'>
                            <span class='verdict-badge' style='background-color:#0f5132;'>2. Mitigation & Containment</span>
                            <ul style='margin-top:10px; padding-left:18px; font-size:13px; color:#334155;'>
                                {"".join([f"<li>{step}</li>" for step in report_data.get("mitigation_steps", [])])}
                            </ul>
                        </div>
                    </div>
                </div>
                """
                st.html(html_document_payload)

                # Export Button
                st.markdown("<br>", unsafe_allow_html=True)
                export_payload = json.dumps(report_data, indent=4)
                st.download_button(
                    label="📥 Export Forensic Incident Audit (.json)",
                    data=export_payload,
                    file_name=f"ids_audit_record_{int(time.time())}.json",
                    mime="application/json",
                    use_container_width=True
                )

    # TAB 7: PCAP Intelligence
    with tab7:
        st.header("👁️ PCAP Intelligence")
        st.caption("Deep System Forensic Investigation and Intelligence Analysis Dashboard")
        
        analysis_mode = st.selectbox("Intelligence Mode Profile", [
            "Deep Packet Analysis",
            "Suspicious Behavior Detection",
            "Full Forensic Summary"
        ])
        
        if st.button("🚀 Run Advanced Intelligent Forensic Inspection", type="primary", use_container_width=True):
            with st.spinner("AI performing deep forensic sweep..."):
                # Use session state data
                display_df = st.session_state.captured_df if not st.session_state.captured_df.empty else df
                display_packets = st.session_state.all_packets if st.session_state.all_packets else packets
                
                intel_prompt = f"""
                You are an elite Incident Response Commander. Generate an advanced, professional forensic intelligence report for the {analysis_mode} stage.
                
                Network Metadata Ingest:
                - Captured Packet Count: {len(display_packets)}
                - Distinguishable Host IPs: {display_df['src_ip'].nunique() if not display_df.empty else 0}
                - Protocol Distribution: {display_df['protocol'].value_counts().to_dict() if not display_df.empty else 'N/A'}
                - Statistical Outlier Count: {display_df['anomaly'].sum() if 'anomaly' in display_df.columns else 0}
                
                Ensure the analysis maps vulnerabilities, threat classification types, and recommended countermeasures. Format with highly readable headers.
                """
                
                try:
                    response = ollama.generate(model=model_choice, prompt=intel_prompt)
                    intel_verdict = response.get('response', 'Inference pipeline failure.')
                except Exception as err:
                    intel_verdict = f"Ollama engine connectivity lost: {err}"
                
                # Render Report
                st.markdown("### 🔬 Security Intelligence Advisory")
                st.markdown(intel_verdict)
                
                # Save & Export Report Actions
                timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                os.makedirs("IDS_Reports", exist_ok=True)
                report_file_path = f"IDS_Reports/forensic_report_{timestamp_str}.md"
                
                with open(report_file_path, "w", encoding="utf-8") as f:
                    f.write(intel_verdict)
                
                st.success("✅ Assessment logged permanently to workspace.")
                
                st.download_button(
                    label="📥 Download Markdown Advisory Report (.md)",
                    data=intel_verdict,
                    file_name=f"ids_advisory_log_{timestamp_str}.md",
                    mime="text/markdown",
                    use_container_width=True
                )

    st.sidebar.caption("Advanced AI IDS v2.2 • Enterprise SOC Platform")

# =========================================================
# APP ENTRY POINT
# =========================================================
# Check if user is authenticated
if not st.session_state.authenticated:
    # Try to restore session
    if not check_existing_session():
        login_page()
    else:
        main_app()
else:
    main_app()