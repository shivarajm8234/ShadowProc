import pandas as pd

class ProcessAnalyzer:
    def __init__(self, high_cpu_threshold=80.0, high_mem_threshold=80.0, max_children=50):
        self.high_cpu_threshold = high_cpu_threshold
        self.high_mem_threshold = high_mem_threshold
        self.max_children = max_children

    def analyze(self, process_df):
        """
        Analyzes the process DataFrame and returns a DataFrame of risky processes.
        """
        if process_df.empty:
            return pd.DataFrame()

        risky_processes = []
        
        # Create a fast lookup for process owners to detect privilege escalation
        # Map: PID -> Username
        proc_owners = process_df.set_index('pid')['username'].to_dict()

        for index, row in process_df.iterrows():
            flags = []
            risk_score = 0.0
            recommendations = []
            
            # --- MANDATORY SECURITY CHECKS ---
            
            # 1. Privilege Escalation (User Parent -> Root Child)
            ppid = row['ppid']
            parent_user = proc_owners.get(ppid)
            current_user = row['username']
            
            if parent_user and parent_user != 'root' and current_user == 'root':
                flags.append("Privilege Escalation Detected (User Parent -> Root Child)")
                risk_score += 30
                recommendations.append(
                    f"The process is running as 'root' but was spawned by a non-privileged user '{parent_user}'.\n"
                    "This is a critical indicator of potential privilege escalation malware or an exploit (e.g., setuid abuse).\n"
                    "Verify the parent process lineage immediately to determine how this elevation occurred."
                )

            # 2. Suspicious Executable Paths
            exe_path = str(row['exe']).lower()
            if not exe_path or exe_path == 'nan' or exe_path == '':
                pass 
            else:
                # Hidden Directory Check
                if '/.' in exe_path:
                    flags.append("Execution from Hidden Directory")
                    risk_score += 25
                    recommendations.append(
                        f"The process executable lies within a hidden directory ({row['exe']}).\n"
                        "Malware often hides in dot-prefixed folders (e.g., ~/.local/...) to evade casual detection.\n"
                        "Inspect the contents of this directory and the legitimacy of the executable."
                    )
                
                # Temp or Dev SHM Check
                if '/tmp' in exe_path or '/var/tmp' in exe_path or '/dev/shm' in exe_path:
                    flags.append("Execution from Temporary Directory")
                    risk_score += 25
                    recommendations.append(
                        f"The process is running from a temporary storage area ({row['exe']}).\n"
                        "Legitimate long-running applications rarely execute from volatile paths like /tmp or /dev/shm.\n"
                        "Terminate this process and capture the file for forensic analysis."
                    )
                
                # Execution from Home Directory (Contextual - Suspicious for background root processes)
                if row['username'] == 'root' and '/home' in exe_path:
                    flags.append("Root Process Executing from User Home")
                    risk_score += 20
                    recommendations.append(
                        "A root-privileged process should typically run from system directories (/bin, /usr, /sbin), not a user's home folder.\n"
                        "This anomaly often suggests a compromised user account attempting to run a backdoor as root.\n"
                        "Investigate the executable's origin."
                    )

            # 3. Zombie Processes
            if row['status'] == 'zombie':
                flags.append("Zombie Process Detected")
                risk_score += 10
                recommendations.append(
                    "This process is a 'zombie' entry in the process table, waiting for its parent to read its exit code.\n"
                    "Accumulation of zombies can lead to resource exhaustion (PID starvation).\n"
                    "Restart or terminate the parent process to clean up these entries."
                )

            # 4. Resource abuse
            # CPU
            if row['cpu_percent'] > self.high_cpu_threshold:
                flags.append(f"Critical CPU Consumption ({row['cpu_percent']}%)")
                risk_score += 15
                recommendations.append(
                    "The process is consuming an abnormally high amount of CPU resources.\n"
                    "Possible Denial of Service (DoS) or crypto-mining activity.\n"
                    "Thittle or kill the process if this behavior is unintended."
                )
            
            # Memory
            if row['memory_percent'] > self.high_mem_threshold:
                flags.append(f"Critical Memory Allocation ({row['memory_percent']}%)")
                risk_score += 15
                recommendations.append(
                    "The process is consuming excessive system RAM, risking system instability (OOM kill).\n"
                    "Check for memory leaks or malicious buffer filling.\n"
                    "Restart the service or process."
                )

            # 5. Fork Spam / Child Count
            if row['num_children'] > self.max_children:
                flags.append(f"Excessive Child Processes ({row['num_children']})")
                risk_score += 20
                recommendations.append(
                    f"The process has spawned {row['num_children']} children, indicating a potential fork bomb or spamer.\n"
                    "This can rapidly crash the system by exhausting process limits.\n"
                    "Kill the parent PID immediately."
                )

            # Risk Categorization (0-100 Scale)
            if risk_score > 100:
                risk_score = 100

            if risk_score > 0:
                risk_level = "Low"
                if risk_score >= 30 and risk_score < 60:
                    risk_level = "Medium"
                elif risk_score >= 60:
                    risk_level = "High"
                
                risky_processes.append({
                    'pid': row['pid'],
                    'name': row['name'],
                    'ppid': row['ppid'],
                    'username': row['username'],
                    'risk_level': risk_level,
                    'risk_score': int(risk_score),
                    'flags': "; ".join(flags),
                    'recommendations': "; ".join(recommendations),
                    'exe': row['exe']
                })
        
        # Sort by Risk Score descending
        risky_df = pd.DataFrame(risky_processes)
        if not risky_df.empty:
            risky_df = risky_df.sort_values(by='risk_score', ascending=False)
            
        return risky_df
