import json
import networkx as nx
import matplotlib.pyplot as plt

# -----------------------------
# 1. Initialize Directed Graph
# -----------------------------
G = nx.DiGraph()

# -----------------------------
# 2. Read Auditbeat Log File
# -----------------------------
LOG_FILE = "auditbeat-report.log"

with open(LOG_FILE, "r") as f:
    for line in f:
        try:
            event = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        # Extract key fields
        proc = event.get("process", {}).get("name")           # Process name (e.g., dirty_cow)
        pid = event.get("process", {}).get("pid")             # Process ID
        file_path = event.get("file", {}).get("path")         # File path (e.g., /etc/passwd)
        action = event.get("event", {}).get("action")         # Action (e.g., open, write, madvise)
        timestamp = event.get("@timestamp")                   # Timestamp

        if not proc or not action:
            continue

        proc_node = f"{proc}({pid})"

        # -----------------------------
        # 3. Add Process Node
        # -----------------------------
        G.add_node(proc_node,
                   type="process",
                   label=proc,
                   timestamp=timestamp)

        # -----------------------------
        # 4. Add File Node
        # -----------------------------
        if file_path:
            G.add_node(file_path,
                       type="file",
                       label=file_path,
                       timestamp=timestamp)
            G.add_edge(proc_node, file_path, label=action, time=timestamp)

        # -----------------------------
        # 5. Capture Process Execution Relationships
        # -----------------------------
        if action in ["execve", "execveat"]:
            parent = proc_node
            child_exe = event.get("process", {}).get("executable")
            if child_exe:
                G.add_node(child_exe, type="process", label=child_exe)
                G.add_edge(parent, child_exe, label="exec", time=timestamp)

        # -----------------------------
        # 6. Capture Parent Process Relationships (bash → dirty_cow)
        # -----------------------------
        parent_info = event.get("process", {}).get("parent", {})
        parent_name = parent_info.get("name")
        parent_pid = parent_info.get("pid")

        # If a parent process exists, connect it with a "spawned" edge
        if parent_name and parent_pid:
            parent_node = f"{parent_name}({parent_pid})"
            G.add_node(parent_node, type="process", label=parent_name)
            # Add directed edge: parent → current process
            G.add_edge(parent_node, proc_node, label="spawned", time=timestamp)

# -----------------------------
# 7. Filter Dirty COW Related Nodes
# -----------------------------
dirtycow_nodes = [n for n in G.nodes if "dirty" in n or "cow" in n or "passwd" in n or "bash" in n]
sub_nodes = set()

for n in dirtycow_nodes:
    sub_nodes |= nx.descendants(G, n)
    sub_nodes.add(n)

H = G.subgraph(sub_nodes).copy()

# -----------------------------
# 8. Drawing
# -----------------------------
def wrap_label(text, max_len=15):
    """Wrap long file paths for better visualization."""
    if len(text) <= max_len:
        return text
    if '/' in text:
        parts = text.split('/')
        wrapped = ""
        line = ""
        for p in parts:
            if len(line) + len(p) < max_len:
                line += p + '/'
            else:
                wrapped += line + '\n'
                line = p + '/'
        wrapped += line
        return wrapped.rstrip('/')
    else:
        return '\n'.join([text[i:i+max_len] for i in range(0, len(text), max_len)])

labels = {n: wrap_label(n) for n in H.nodes()}

process_nodes = [n for n, attr in H.nodes(data=True) if attr["type"] == "process"]
file_nodes = [n for n, attr in H.nodes(data=True) if attr["type"] == "file"]
other_nodes = [n for n, attr in H.nodes(data=True) if attr["type"] not in ["process", "file"]]

plt.figure(figsize=(11, 8))
pos = nx.spring_layout(H, k=0.6, seed=42)
ax = plt.gca()

node_size_process = 800
node_size_file = 800
node_size_other = 700
max_node_size = 800

# Draw edges first
nx.draw_networkx_edges(H, pos,
                       ax=ax,
                       arrows=True,
                       arrowsize=18,
                       arrowstyle='->',
                       edge_color="#555555",
                       width=1.8,
                       alpha=0.85,
                       node_size=int(max_node_size * 1.5))

# Draw process nodes
nx.draw_networkx_nodes(H, pos,
                       ax=ax,
                       nodelist=process_nodes,
                       node_color="#E1AFBE",
                       node_shape='o',
                       node_size=node_size_process,
                       alpha=0.85,
                       label="Process")

# Draw file nodes
nx.draw_networkx_nodes(H, pos,
                       ax=ax,
                       nodelist=file_nodes,
                       node_color="#D2EBBE",
                       node_shape='s',
                       node_size=node_size_file,
                       alpha=0.85,
                       label="File")

# Draw other nodes
nx.draw_networkx_nodes(H, pos,
                       ax=ax,
                       nodelist=other_nodes,
                       node_color="#AAAAAA",
                       node_shape='D',
                       node_size=node_size_other,
                       alpha=0.75,
                       label="Other")


nx.draw_networkx_labels(H, pos, labels=labels, font_size=7, verticalalignment='center')
edge_labels = nx.get_edge_attributes(H, "label")
nx.draw_networkx_edge_labels(H, pos, edge_labels=edge_labels, font_size=7, font_color="gray")


plt.title("Provenance Graph of Dirty COW Attack", fontsize=12)
plt.legend(scatterpoints=1,
           loc="upper left",
           bbox_to_anchor=(0.0, 1.05),
           fontsize=9,
           frameon=True)

plt.axis("off")
plt.tight_layout()
plt.subplots_adjust(top=0.9)
plt.savefig("provenance_graph_shapes.png", dpi=300)
plt.show()

# -----------------------------
# 9. Log Summary
# -----------------------------
print(f"[INFO] Graph built successfully with {len(H.nodes())} nodes and {len(H.edges())} edges.")
print("[INFO] Parent-child process relationships (bash → dirty_cow) are now included.")
