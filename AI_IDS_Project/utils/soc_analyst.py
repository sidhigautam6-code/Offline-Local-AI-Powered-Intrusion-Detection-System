import streamlit as st
from sentence_transformers import SentenceTransformer
import chromadb
import uuid
import json
from datetime import datetime

class SOCAnalyst:
    def __init__(self):
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.client = chromadb.PersistentClient(path="security_knowledge")
        self.collection = self.client.get_or_create_collection("threat_intel")
        
        # Pre-load some threat intelligence
        self._seed_knowledge()

    def _seed_knowledge(self):
        threats = [
            ("Port scanning detected", "Reconnaissance phase - Nmap style scan"),
            ("C2 beaconing", "Command and Control communication"),
            ("Data exfiltration", "Sensitive data leaving network"),
            ("Ransomware behavior", "High entropy file encryption"),
        ]
        for text, desc in threats:
            embedding = self.embedding_model.encode(text).tolist()
            self.collection.add(
                documents=[text],
                metadatas=[{"description": desc}],
                ids=[str(uuid.uuid4())]
            )

    def analyze_incident(self, df, packets, anomalies):
        """Main SOC Analysis"""
        summary = f"""
        Incident Summary:
        - Total Packets: {len(packets)}
        - Anomalies Detected: {len(anomalies) if 'anomalies' in locals() else 0}
        - Unique IPs: {df['src_ip'].nunique() if 'src_ip' in df.columns else 0}
        """
        
        # Retrieve similar past incidents
        query_embedding = self.embedding_model.encode(summary).tolist()
        results = self.collection.query(query_embeddings=[query_embedding], n_results=3)
        
        return {
            "risk_score": self._calculate_risk_score(df),
            "attack_stage": self._determine_attack_stage(df),
            "recommendations": self._generate_playbook(results),
            "summary": summary
        }

    def _calculate_risk_score(self, df):
        score = 50
        if 'src_ip' in df.columns and df['src_ip'].nunique() > 20:
            score += 30
        return min(95, score)

    def _determine_attack_stage(self, df):
        return "Exfiltration / C2 Communication" if len(df) > 100 else "Reconnaissance"

    def _generate_playbook(self, results):
        return [
            "1. Isolate affected hosts",
            "2. Block suspicious IPs",
            "3. Collect full packet capture",
            "4. Run memory forensics"
        ]