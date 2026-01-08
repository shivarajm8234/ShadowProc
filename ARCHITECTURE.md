# PPID-X: System Architecture & Workflow

## Overview
PPID-X is a real-time OS Process Threat Intelligence system. It monitors system processes, constructs a parent-child lineage tree, and applies heuristic analysis to detect security risks like privilege escalation, malware masquerading, and resource abuse.

## 1. System Components
The project is modularized into four key components:

### A. Data Collector (`monitor.py`)
*   **Role**: The "Eyes" of the system.
*   **Function**: `collect_process_data()`
*   **Logic**:
    1.  Iterates through all running PIDs using `psutil.process_iter()`.
    2.  Extracts raw OS data: PID, PPID, Name, User, Status, CPU%, Mem%, Creation Time, CommandLine, and Executable Path.
    3.  Converts this data into a standardized Pandas DataFrame for easy manipulation.

### B. Threat Analyzer (`analyzer.py`)
*   **Role**: The "Brain" of the system.
*   **Function**: `analyze(process_df)`
*   **Logic**:
    1.  **Privilege Escalation Detection**:
        *   Checks if a parent process is a normal user but the child process is `root`.
        *   **Risk**: Critical (+30 Score).
    2.  **Suspicious Path Detection**:
        *   **Hidden Dirs**: Checks for `/.` in the path (e.g., `~/.local/bin/malware`).
        *   **Temp Dirs**: Checks for execution from `/tmp`, `/var/tmp`, `/dev/shm`.
        *   **Root in Home**: Checks if `root` is running a binary from `/home/user`.
    3.  **Heuristic Scoring (0-100)**:
        *   Calculates a weighted risk score based on the above flags plus CPU/Memory usage, Zombie status, and Fork abuse (excessive children).
    4.  **Classification**:
        *   **Low**: 0-29
        *   **Medium**: 30-59
        *   **High**: 60-100

### C. Visualizer (`visualizer.py`)
*   **Role**: The "Renderer" of the system.
*   **Function**: `create_process_tree_figure(root_pid, process_map)`
*   **Logic**:
    1.  **Graph Construction**: Uses `networkx` to build a directed graph of the process lineage (Ancestors -> Root -> Descendants).
    2.  **Layout Algorithm**: Custom recursive algorithm to assign X/Y coordinates, ensuring nodes don't overlap designated by `X_SCALE`.
    3.  **Rendering**: Uses `plotly.graph_objects` to draw:
        *   **Red Nodes**: Risky processes.
        *   **Cyan Node**: The selected Root process.
        *   **Green Nodes**: Safe child/parent processes.
    4.  **Interactivity**: Enables Zoom/Pan and detailed Hover tooltips.

### D. User Interface (`app.py`)
*   **Role**: The "Face" of the system.
*   **Framework**: Streamlit.
*   **Workflow**:
    1.  **Auto-Refresh Loop**: Every N seconds (default 5), it re-runs the data collection pipeline.
    2.  **Dashboard**: Displays global metrics (Total PIDs, Risky Count, System Load).
    3.  **Tabs**:
        *   **"All Processes"**: Searchable table of every running task.
        *   **"Threat Intelligence"**: Filtered view of only Risky processes with their 0-100 Score and Flag details.
    4.  **Process Inspector**:
        *   Allows selecting any PID.
        *   Displays detailed metadata cards.
        *   **Path Verification**: Explicitly verifies if the path is Safe or Suspicious.
        *   **Interactive Tree**: Embeds the Plotly chart for lineage analysis.

## 2. Data Flow
1.  **OS Kernel** -> `psutil` (Raw Data)
2.  `monitor.py` -> **Pandas DataFrame** (Structured Data)
3.  `analyzer.py` -> **Risk DataFrame** (Scored & Flagged Data)
4.  `app.py` -> Use Risk Data to filter UI & Color Graph
5.  **User Screen** (Interactive Dashboard)

## 3. Technology Stack
*   **Python 3.9+**: Core language.
*   **Streamlit**: Web UI framework.
*   **Psutil**: Cross-platform system monitoring.
*   **Pandas**: Data structuring and querying.
*   **Plotly**: Interactive graphing.
*   **NetworkX**: Graph theory and structure.
