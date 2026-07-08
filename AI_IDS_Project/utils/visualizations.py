import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx

def create_network_graph(df):
    st.subheader("🌐 Network Communication Graph")
    
    if df.empty or 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
        st.warning("No network data available to generate graph.")
        return

    # Create graph
    G = nx.Graph()
    edges = df.groupby(['src_ip', 'dst_ip']).size().reset_index(name='weight')
    
    for _, row in edges.iterrows():
        G.add_edge(row['src_ip'], row['dst_ip'], weight=row['weight'])

    # Use Plotly for better compatibility with Streamlit
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = edge[0], edge[1]  # Simplified positions
        edge_x.extend([x0, y0, None])
        edge_y.extend([y0, x0, None])  # Note: simplified

    # Better approach using Plotly
    try:
        fig = go.Figure()

        # Add edges
        for edge in G.edges(data=True):
            fig.add_trace(go.Scatter(
                x=[edge[0], edge[1]],
                y=[edge[0], edge[1]],
                mode='lines',
                line=dict(width=1, color='#ff4444'),
                opacity=0.6
            ))

        # Add nodes
        node_x = list(G.nodes())
        node_y = list(G.nodes())
        fig.add_trace(go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            marker=dict(size=15, color='#00ff88', line=dict(width=2)),
            text=list(G.nodes()),
            textposition="top center",
            hoverinfo='text'
        ))

        fig.update_layout(
            title="Network Communication Graph",
            showlegend=False,
            height=600,
            plot_bgcolor="#1a1a1a",
            paper_bgcolor="#0a0a0a",
            xaxis=dict(showgrid=False, zeroline=False),
            yaxis=dict(showgrid=False, zeroline=False)
        )

        st.plotly_chart(fig, use_container_width=True)

    except:
        st.warning("Using fallback simple chart...")
        top_comms = edges.nlargest(10, 'weight')
        st.bar_chart(top_comms.set_index(['src_ip', 'dst_ip'])['weight'])


def create_timeline(df):
    st.subheader("⏱️ Packet Timeline")
    
    if df.empty or 'timestamp' not in df.columns:
        st.info("Timestamp data not available.")
        return

    df_t = df.copy()
    if 'timestamp' in df_t.columns:
        df_t['hour'] = df_t['timestamp'].dt.hour
        
        fig = px.histogram(df_t, x='timestamp', color='protocol', 
                          title="Packet Activity Over Time")
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
