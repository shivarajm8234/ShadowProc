import streamlit as st
import pandas as pd
import time
import psutil
from monitor import collect_process_data, build_process_dataframe
from analyzer import ProcessAnalyzer

st.set_page_config(
    page_title="PPID-X Threat Monitor",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for "Terminal" aesthetic
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .stMetric {
        background-color: #262730;
        padding: 10px;
        border-radius: 5px;
    }
    div[data-testid="stMetricValue"] {
        color: #00ff41; 
    }
    .risk-high {
        color: #ff4b4b;
        font-weight: bold;
    }
    .risk-medium {
        color: #ffa421;
        font-weight: bold;
    }
    .risk-low {
        color: #00ff41;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def render_ascii_tree(pid, process_map, depth=0, visited=None):
    """
    Recursive function to build an ASCII tree of the process lineage.
    Searching DOWN from the given PID (children).
    """
    if visited is None:
        visited = set()
    
    if pid in visited:
        return ""
    visited.add(pid)
    
    proc = process_map.get(pid)
    if not proc:
        return ""
    
    # Simple ASCII Tree format
    prefix = "    " * depth
    tree_str = f"{prefix}|-- [{proc['pid']}] {proc['name']} (User: {proc['username']})\n"
    
    # Find children
    children = [p for p in process_map.values() if p['ppid'] == pid]
    for child in children:
        tree_str += render_ascii_tree(child['pid'], process_map, depth + 1, visited)
        
    return tree_str

import plotly.graph_objects as go
from visualizer import create_process_tree_figure

def main():
    st.title("PPID-X: Process Threat Intelligence")
    st.markdown("### Real-Time Parent-Child Process Analysis")

    # Sidebar Configuration
    st.sidebar.header("Configuration")
    refresh_rate = st.sidebar.slider("Refresh Rate (seconds)", 1, 60, 5)
    cpu_threshold = st.sidebar.slider("CPU Alert Threshold (%)", 10, 100, 80)
    mem_threshold = st.sidebar.slider("Memory Alert Threshold (%)", 10, 100, 80)
    
    # Analyzer Init
    analyzer = ProcessAnalyzer(high_cpu_threshold=cpu_threshold, high_mem_threshold=mem_threshold)

    # Placeholder for live updates
    placeholder = st.empty()

    if 'auto_refresh' not in st.session_state:
        st.session_state.auto_refresh = True

    if st.sidebar.button("Stop/Start Live Monitoring"):
        st.session_state.auto_refresh = not st.session_state.auto_refresh

    if st.session_state.auto_refresh:
        with placeholder.container():
            # 1. Collect Data
            raw_data = collect_process_data()
            df = build_process_dataframe(raw_data)
            
            # Create a simplified map for tree building
            process_map = {p['pid']: p for p in raw_data}

            # 2. Analyze Threats
            risky_df = analyzer.analyze(df)

            # 3. Validation Metrics
            total_procs = len(df)
            risky_count = len(risky_df)
            
            # Top Metrics Row
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Processes", total_procs)
            m2.metric("Risky Processes Detected", risky_count, delta_color="inverse")
            m3.metric("System CPU", f"{psutil.cpu_percent()}%")
            m4.metric("System Memory", f"{psutil.virtual_memory().percent}%")

            st.divider()

            # 4. Main Tab Layout
            tab_all, tab_risk = st.tabs(["All Processes", "Threat Intelligence"])

            with tab_all:
                st.subheader("Live System Processes")
                # Show full table with search
                st.dataframe(
                    df[['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'create_time_str']],
                    use_container_width=True,
                    hide_index=True
                )

            with tab_risk:
                st.subheader("Detected Anomalies")
                if not risky_df.empty:
                    st.dataframe(
                        risky_df[['pid', 'name', 'username', 'risk_score', 'risk_level', 'flags']],
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "risk_score": st.column_config.ProgressColumn(
                                "Risk Score",
                                help="0-100 Threat Score",
                                format="%d",
                                min_value=0,
                                max_value=100,
                            ),
                            "risk_level": st.column_config.TextColumn("Risk", help="Severity Level"),
                            "flags": st.column_config.TextColumn("Detections", width="large")
                        }
                    )
                else:
                    st.success("No active threats detected. System appears normal.")

            # 5. Interactive Detail & Explanation Area
            st.divider()
            st.markdown("### Process Inspector")
            
            # Unified Selector: Combine Risky and All for selection
            # We prioritize Risky PIDs in the list
            all_pids = sorted(df['pid'].unique())
            risky_pids = sorted(risky_df['pid'].unique()) if not risky_df.empty else []
            other_pids = [p for p in all_pids if p not in risky_pids]
            
            c_sel1, c_sel2 = st.columns([1, 3])
            with c_sel1:
                selected_pid = st.selectbox("Select PID to Analyze", risky_pids + other_pids)

            if selected_pid:
                # Get Process Info
                proc_info = df[df['pid'] == selected_pid].iloc[0]
                
                # Check if it was flagged as risky
                is_risky = False
                risk_details = None
                if not risky_df.empty and selected_pid in risky_df['pid'].values:
                    is_risky = True
                    risk_details = risky_df[risky_df['pid'] == selected_pid].iloc[0]

                # --- Detail Cards ---
                
                # Risk Analysis Panel (Only if Risky)
                if is_risky:
                    score = risk_details.get('risk_score', 0)
                    st.error(f"THREAT DETECTED: {risk_details['risk_level'].upper()} RISK (Score: {score}/100)")
                    
                    with st.expander("Threat Analysis Report", expanded=True):
                        st.markdown(f"**Reason for Detection:**")
                        for flag in risk_details['flags'].split('; '):
                            st.markdown(f"- {flag}")
                        
                        st.markdown("---")
                        st.markdown(f"**Recommended Mitigation:**")
                        for rec in risk_details['recommendations'].split('; '):
                            st.markdown(f"- {rec}")
                else:
                    st.info("Process appears benign (No active flags).")

                # Basic Details & Tree - STACKED LAYOUT (Not Beside)
                
                st.markdown("#### Process Metadata")
                st.text(f"PID:      {proc_info['pid']}")
                st.text(f"PPID:     {proc_info['ppid']}")
                st.text(f"Name:     {proc_info['name']}")
                st.text(f"User:     {proc_info['username']}")
                st.text(f"Status:   {proc_info['status']}")
                st.text(f"Command:  {proc_info['cmdline']}")
                st.text(f"Path:     {proc_info['exe']}")
            
                st.markdown("#### Resource Usage")
                st.progress(proc_info['cpu_percent'] / 100, text=f"CPU: {proc_info['cpu_percent']}%")
                st.progress(proc_info['memory_percent'] / 100, text=f"Memory: {proc_info['memory_percent']:.2f}%")
                st.text(f"Uptime:   {proc_info['uptime_seconds']:.0f} sec")

                # --- Path Verification Section ---
                st.markdown("#### Path Security Verification")
                exe_path = str(proc_info['exe']).lower()
                path_status = " Verified / Safe"
                path_note = "Standard system path"
                
                # Re-using simple heuristics for display (visual feedback)
                if '/tmp' in exe_path or '/var/tmp' in exe_path or '/dev/shm' in exe_path:
                    path_status = " Suspicious (Temp Path)"
                    path_note = "Process running from volatile temporary storage"
                elif '/.' in exe_path:
                    path_status = " Suspicious (Hidden Path)"
                    path_note = "Process hidden in dot-prefixed directory"
                elif proc_info['username'] == 'root' and '/home' in exe_path:
                    path_status = " Anomaly (Root in Home)"
                    path_note = "Root process running from user space"
                
                c_path1, c_path2 = st.columns([1, 2])
                c_path1.markdown(f"**Analysis:** {path_status}")
                c_path2.markdown(f"**Details:** {path_note}")
                
                st.markdown("#### Process Lineage Tree (Interactive)")
                
                # Visualizer Integration
                current_risky_pids = set(risky_df['pid'].values) if not risky_df.empty else set()
                
                # We use a persistent key based on PID to allow updates without resetting state (thanks to uirevision)
                # But to ensure it changes when PID changes (state reset), the key itself handles that (unique PID).
                fig = create_process_tree_figure(selected_pid, process_map, risky_pids=current_risky_pids)
                st.plotly_chart(fig, use_container_width=True, key=f"tree_viz_{selected_pid}")

            time.sleep(refresh_rate)
            st.rerun()

if __name__ == "__main__":
    main()