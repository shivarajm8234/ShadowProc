import plotly.graph_objects as go
import networkx as nx

def build_lineage_graph(root_pid, process_map):
    """
    Builds a networkx DiGraph for the lineage starting from root_pid (descendants).
    """
    G = nx.DiGraph()
    queue = [root_pid]
    visited = set()
    
    # Check if root exists
    if root_pid not in process_map:
        return G

    # Add root
    root_proc = process_map[root_pid]
    label = f"PID: {root_proc['pid']}<br>{root_proc['name']}"
    G.add_node(root_pid, label=label, info=root_proc)
    visited.add(root_pid)

    while queue:
        current_pid = queue.pop(0)
        
        # Find children
        children = [p['pid'] for p in process_map.values() if p['ppid'] == current_pid]
        
        for child_pid in children:
            if child_pid not in visited:
                child_proc = process_map[child_pid]
                label = f"PID: {child_proc['pid']}<br>{child_proc['name']}"
                G.add_node(child_pid, label=label, info=child_proc)
                G.add_edge(current_pid, child_pid)
                visited.add(child_pid)
                queue.append(child_pid)
    
    return G

def get_tree_layout(G, root_pid):
    """
    Computes a tree layout properly.
    """
    pos = {}
    
    # Simple width-based recursive layout
    widths = {}
    def calc_width(u):
        children = list(G.successors(u))
        if not children:
            widths[u] = 1
            return 1
        w = sum(calc_width(v) for v in children)
        widths[u] = w
        return w
        
    calc_width(root_pid)
    
    def assign_pos(u, x_start, y):
        pos[u] = (x_start + widths[u] / 2, y)
        current_x = x_start
        for v in G.successors(u):
            assign_pos(v, current_x, y - 1)
            current_x += widths[v]
            
    assign_pos(root_pid, 0, 0)
    
    return pos

def create_process_tree_figure(root_pid, process_map, risky_pids=None):
    """
    Creates a Plotly Figure for the process tree.
    """
    if risky_pids is None:
        risky_pids = set()

    G = build_lineage_graph(root_pid, process_map)
    if len(G.nodes) == 0:
        return go.Figure()

    pos = get_tree_layout(G, root_pid)
    
    # Scale X to prevent overlap
    X_SCALE = 2.0
    for node in pos:
        x, y = pos[node]
        pos[node] = (x * X_SCALE, y)

    edge_x = []
    edge_y = []
    
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#666'), 
        hoverinfo='none',
        mode='lines')

    node_x = []
    node_y = []
    node_text = []
    node_colors = []
    node_sizes = []
    border_colors = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        proc = G.nodes[node]['info']
        
        # Risk Coloring Logic
        is_risky = node in risky_pids
        is_root = (node == root_pid)
        
        if is_risky:
            node_colors.append('#ff4b4b') # Red for Risk
            node_sizes.append(25)
            border_colors.append('#ffffff')
        elif is_root:
            node_colors.append('#00bcd4') # Cyan for Root/Selected
            node_sizes.append(30)
            border_colors.append('#ffffff')
        else:
            node_colors.append('#00ff41') # Matrix Green for normal
            node_sizes.append(20)
            border_colors.append('#1e1e1e')

        # Detailed Hover Info
        hover_info = (
            f"<b>{proc['name']}</b><br>"
            f"PID: {proc['pid']}<br>"
            f"User: {proc['username']}<br>"
            f"CPU: {proc['cpu_percent']}% | Mem: {proc['memory_percent']}%"
        )
        node_text.append(hover_info)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        hovertext=node_text,
        text=[G.nodes[n]['label'] for n in G.nodes()],
        textposition="bottom center",
        marker=dict(
            showscale=False,
            color=node_colors,
            size=node_sizes,
            line=dict(width=2, color=border_colors)
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace],
                 layout=go.Layout(
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=0,l=0,r=0,t=20),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    height=500,
                    uirevision='constant' # Preserve zoom/pan state on updates
                    ))
    
    # Add annotation for context if empty/small
    if len(G.nodes) < 2:
        fig.add_annotation(text="Single Process (No Children)", xref="paper", yref="paper", showarrow=False)
        
    return fig
