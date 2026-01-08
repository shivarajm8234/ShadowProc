import psutil
import pandas as pd
import time
from datetime import datetime

def collect_process_data():
    """
    Collects real-time process data from the OS.
    Returns a list of dictionaries containing process information.
    """
    processes = []
    
    # Iterate over all running processes
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'status', 'username', 'cpu_percent', 'memory_percent', 'exe', 'create_time', 'cmdline']):
        try:
            # Fetch process info (some attributes might need explicit retrieval if not in the list)
            pinfo = proc.info
            
            # Handle potential None values
            pinfo['pid'] = pinfo.get('pid')
            pinfo['ppid'] = pinfo.get('ppid')
            pinfo['name'] = pinfo.get('name', 'Unknown')
            pinfo['status'] = pinfo.get('status', 'Unknown')
            pinfo['username'] = pinfo.get('username', 'Unknown')
            pinfo['cpu_percent'] = pinfo.get('cpu_percent', 0.0)
            pinfo['memory_percent'] = pinfo.get('memory_percent', 0.0)
            pinfo['exe'] = pinfo.get('exe', '')
            pinfo['cmdline'] = " ".join(pinfo.get('cmdline', [])) if pinfo.get('cmdline') else ""
            
            # Calculate execution time
            create_time = pinfo.get('create_time')
            if create_time:
                pinfo['create_time_str'] = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S')
                pinfo['uptime_seconds'] = time.time() - create_time
            else:
                pinfo['create_time_str'] = "Unknown"
                pinfo['uptime_seconds'] = 0
            
            # Count children (expensive operation if done individually, but psutil optimizes iteration)
            # For efficiency in a loop, we might skip explicit child counting here and derive it from PPID relationships later
            # But specific child count is requested.
            try:
                children = proc.children()
                pinfo['num_children'] = len(children)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pinfo['num_children'] = 0

            processes.append(pinfo)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes

def build_process_dataframe(processes):
    """
    Converts the list of process dictionaries into a Pandas DataFrame.
    """
    if not processes:
        return pd.DataFrame()
    
    df = pd.DataFrame(processes)
    
    # Ensure types
    df['pid'] = df['pid'].astype(int)
    df['ppid'] = df['ppid'].fillna(0).astype(int)
    
    return df

if __name__ == "__main__":
    # Simple test
    data = collect_process_data()
    df = build_process_dataframe(data)
    print(df.head())
