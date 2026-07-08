import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
from utils.ollama_helper import query_ollama

def extract_features(df):
    """Extract features suitable for anomaly detection"""
    features = pd.DataFrame()
    
    if df.empty:
        return features
    
    # Basic numerical features
    if 'packet_size' in df.columns:
        features['packet_size'] = df['packet_size']
        features['packet_size_zscore'] = (df['packet_size'] - df['packet_size'].mean()) / df['packet_size'].std()
    
    if 'src_ip' in df.columns:
        # Frequency of each source IP
        features['src_ip_freq'] = df['src_ip'].map(df['src_ip'].value_counts())
    
    if 'dst_ip' in df.columns:
        features['dst_ip_freq'] = df['dst_ip'].map(df['dst_ip'].value_counts())
    
    if 'src_port' in df.columns:
        features['src_port_freq'] = df['src_port'].map(df['src_port'].value_counts())
    
    if 'protocol' in df.columns:
        # Protocol encoding
        protocol_dummies = pd.get_dummies(df['protocol'], prefix='proto')
        features = pd.concat([features, protocol_dummies], axis=1)
    
    # Fill NaN values
    features = features.fillna(0)
    
    return features


def detect_anomalies(df, model_name="deepseek-coder"):
    """Main anomaly detection function"""
    st.header("⚠️ ML-Based Anomaly Detection")
    
    if df.empty:
        st.warning("No data available for analysis.")
        return
    
    with st.spinner("Training Isolation Forest model..."):
        features = extract_features(df)
        
        if len(features) < 20 or features.shape[1] == 0:
            st.warning("Not enough data or features for reliable anomaly detection.")
            return
        
        # Train Isolation Forest
        model = IsolationForest(
            contamination=0.08,      # Expect 8% anomalies
            random_state=42,
            n_estimators=100
        )
        
        # Fit and predict
        df['anomaly_score'] = model.fit_predict(features)
        df['anomaly'] = df['anomaly_score'].map({-1: "🔴 Anomaly", 1: "🟢 Normal"})
        
        # Results
        anomaly_count = (df['anomaly_score'] == -1).sum()
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Anomalies Detected", anomaly_count, 
                     delta=f"{(anomaly_count/len(df)*100):.1f}% of traffic")
        with col2:
            st.metric("Total Packets Analyzed", len(df))
        
        # Show anomalies
        st.subheader("Top Anomalous Packets")
        anomalies = df[df['anomaly_score'] == -1].sort_values(by='packet_size', ascending=False)
        st.dataframe(anomalies.head(15), use_container_width=True)
        
        # AI Explanation Button
        if st.button("🤖 Get AI Explanation of Anomalies", type="primary"):
            with st.spinner("Asking AI to analyze anomalies..."):
                anomaly_sample = anomalies.head(12).to_string(index=False)
                
                prompt = f"""
                You are a cybersecurity expert. Analyze the following network anomalies:

                {anomaly_sample}

                Provide:
                1. Possible attack types or suspicious behaviors
                2. Why these packets were flagged as anomalous
                3. Recommended actions
                Keep it concise but insightful.
                """
                
                response = query_ollama(prompt, model=model_name)
                st.markdown("### AI Analysis")
                st.markdown(response)