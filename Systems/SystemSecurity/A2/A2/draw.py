"""
build_dirtycow_provenance_graph_race_clean.py

Features:
---------
1) Vertical timeline: nodes are layered by second (top = early, bottom = late).
2) Race detection: flags processes that issue madvise + write/pwrite within the same second.
3) Aggregated edge labels: shows per-(proc, file, action) counts (e.g., write×4061).
4) Security-relevant highlighting: /proc/self/mem and /etc/passwd (root_file) edges and nodes.
5) Clearer drawing: curved edges, spaced layers, readable labels/legend, hide idle bash nodes.

Env:
- Python 3.10+
- pip install networkx matplotlib
"""

import json
import random
from collections import defaultdict, Counter
from datetime import datetime
import networkx as nx
import matplotlib.pyplot as plt

LOG_FILE = "auditbeat-report.log"

# -----------------------------
# Helpers
# -----------------------------
def parse_time(ts: str):
    """Parse ISO8601 -> naive datetime (strip tz to avoid mixed aware/naive)."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None)
    except Exception:
        return None

def time_bucket(dt: datetime):
    """Bucket to second precision (for layering)."""
    if not dt:
        return None
    return dt.replace(microsecond=0)

def format_time_ms(dt: datetime):
    """Format datetime to HH:MM:SS.mmm (millisecond precision).
    
    Examples:
        - 11:11:35.471000 -> 11:11:35.471
        - 11:11:35.000000 -> 11:11:35.000
    """
    if not dt:
        return ""
    # Convert microseconds to milliseconds (1 ms = 1000 μs)
    ms = dt.microsecond // 1000
    return dt.strftime(f'%H:%M:%S.{ms:03d}')

def wrap_label(text, max_len=16):
    """Word-wrap long paths for compact node labels."""
    if not text or len(text) <= max_len:
        return text
    if "/" in text:
        parts = text.split("/")
        out, line = [], ""
        for p in parts:
            if len(line) + len(p) + (1 if line else 0) <= max_len:
                line = (line + "/" + p) if line else p
            else:
                out.append(line)
                line = p
        if line:
            out.append(line)
        return "\n".join(out)
    return "\n".join(text[i:i+max_len] for i in range(0, len(text), max_len))

# -----------------------------
# 1) Ingest & pre-aggregate
# -----------------------------
events = []
with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for ln in f:
        ln = ln.strip()
        if not ln:
            continue
        try:
            events.append(json.loads(ln))
        except json.JSONDecodeError:
            continue

# Sort chronologically
events.sort(key=lambda e: parse_time(e.get("@timestamp") or ""))

# Containers
G = nx.DiGraph()
proc_syscalls_by_sec = defaultdict(lambda: defaultdict(set))   # proc -> sec -> {actions}
edge_counters = Counter()                                      # (proc_node, file_path, action) -> count
parent_links = set()                                           # (parent_node, child_node, timestamp)
node_time = {}                                                 # node -> earliest timestamp seen
proc_last_ts = {}                                              # proc_node -> last timestamp

# Security targets
TARGET_FILES = {"/etc/passwd", "/etc/shadow"}
PROC_SELF_MEM = "/proc/self/mem"

for ev in events:
    ts = ev.get("@timestamp")
    dt = parse_time(ts)
    bucket = time_bucket(dt)

    proc_name = ev.get("process", {}).get("name")
    pid = ev.get("process", {}).get("pid")
    
    # Try multiple sources for action/syscall information
    action = ev.get("event", {}).get("action")
    # If event.action is empty, check auditd.data.syscall
    if not action or action == "":
        action = ev.get("auditd", {}).get("data", {}).get("syscall")
    # Also check event.type
    if not action:
        action = ev.get("event", {}).get("type")
    
    file_path = ev.get("file", {}).get("path")

    if not proc_name or not action:
        continue

    proc_node = f"{proc_name}({pid})"

    # Track process node & time
    if proc_node not in G:
        G.add_node(proc_node, type="process", label=proc_name)
    if proc_node not in node_time or (dt and node_time.get(proc_node) and dt < node_time[proc_node]) or node_time.get(proc_node) is None:
        node_time[proc_node] = dt
    proc_last_ts[proc_node] = dt or proc_last_ts.get(proc_node)

    # Race-detection bookkeeping
    if bucket:
        proc_syscalls_by_sec[proc_node][bucket].add(action)

    # Parent → child (spawned)
    parent = ev.get("process", {}).get("parent", {}) or {}
    if parent.get("name") and parent.get("pid"):
        parent_node = f"{parent['name']}({parent['pid']})"
        if parent_node not in G:
            G.add_node(parent_node, type="process", label=parent["name"])
        parent_links.add((parent_node, proc_node, dt))
        if parent_node not in node_time or (dt and node_time.get(parent_node) and dt < node_time[parent_node]) or node_time.get(parent_node) is None:
            node_time[parent_node] = dt

    # File access aggregation
    if file_path:
        if file_path not in G:
            G.add_node(file_path, type="file", label=file_path)
        edge_counters[(proc_node, file_path, action)] += 1
    else:
        # For syscalls without file (e.g., madvise, mmap on memory)
        # Try to extract memory address or create a virtual node
        if action in ("madvise", "mmap", "munmap", "mprotect"):
            # Extract memory address from auditd.data
            mem_addr = ev.get("auditd", {}).get("data", {}).get("a0", "")
            if mem_addr:
                # Create a virtual memory node
                mem_node = f"[memory:{mem_addr[:10]}...]"
                if mem_node not in G:
                    G.add_node(mem_node, type="memory", label=mem_node)
                edge_counters[(proc_node, mem_node, action)] += 1

# -----------------------------
# 2) Race detection (madvise + write/pwrite within same second)
# -----------------------------
race_procs = set()
for proc_node, by_sec in proc_syscalls_by_sec.items():
    for sec, acts in by_sec.items():
        if "madvise" in acts and (("write" in acts) or ("pwrite" in acts)):
            race_procs.add(proc_node)
            break

# -----------------------------
# 3) Build graph from aggregates
# -----------------------------
for (pnode, fpath, act), cnt in edge_counters.items():
    lbl = f"{act}×{cnt}"
    tlabel = proc_last_ts.get(pnode)
    if tlabel:
        lbl = f"{lbl}\n{format_time_ms(tlabel)}"
    G.add_edge(pnode, fpath, label=lbl, action=act)

for parent, child, dt in parent_links:
    lbl = "spawned"
    if dt:
        lbl += f"\n{format_time_ms(dt)}"
    G.add_edge(parent, child, label=lbl, action="spawned")

# -----------------------------
# 4) Extract Dirty COW–related subgraph
# -----------------------------
# First, check what actions we have in the full graph
all_actions = set()
for u, v, d in G.edges(data=True):
    act = d.get("action", "")
    if act:
        all_actions.add(act)
print(f"[DEBUG] All actions in graph: {sorted(all_actions)}")

# Check madvise edges
madvise_edges = [(u, v, d) for u, v, d in G.edges(data=True) if d.get("action") == "madvise"]
print(f"[DEBUG] Found {len(madvise_edges)} madvise edges in full graph")
if madvise_edges:
    print("[DEBUG] Sample madvise edges:")
    for u, v, d in madvise_edges[:5]:  # Show first 5
        print(f"  {u} -> {v}: {d}")

# Node-based filtering
KEYS = ("dirty", "cow", "passwd", "shadow", "bash", "mem")
seed_nodes = [n for n in G.nodes if any(k in str(n).lower() for k in KEYS)]

# Also add nodes involved in critical actions (madvise, mmap, etc.)
# Support both exact match and substring match (in case action is "syscall-madvise" etc.)
CRITICAL_ACTIONS = ["madvise", "mmap", "write", "pwrite"]
for u, v, d in G.edges(data=True):
    act = d.get("action", "")
    # Check if action contains any critical action keyword
    if any(critical in act.lower() for critical in CRITICAL_ACTIONS):
        seed_nodes.append(u)  # Add source node (process)
        seed_nodes.append(v)  # Add target node (file)

seed_nodes = list(set(seed_nodes))  # Remove duplicates
print(f"[DEBUG] Seed nodes after adding critical actions: {len(seed_nodes)}")

keep = set()
for n in seed_nodes:
    keep.add(n)
    keep |= nx.descendants(G, n)
    keep |= nx.ancestors(G, n)
H = G.subgraph(keep).copy()

# Check madvise edges in subgraph
madvise_edges_h = [(u, v) for u, v, d in H.edges(data=True) if d.get("action") == "madvise"]
print(f"[DEBUG] Found {len(madvise_edges_h)} madvise edges in subgraph H")

# 4.1) Remove isolated bash nodes (visual noise)
isolated_bash = [n for n in H.nodes() if H.degree(n) == 0 and "bash" in str(n)]
H.remove_nodes_from(isolated_bash)

# -----------------------------
# 5) Assign vertical time layers (top = earliest)
# -----------------------------
# Ensure each node has a timestamp
for n in H.nodes:
    node_time.setdefault(n, None)

pairs = [(n, time_bucket(node_time[n]) if node_time[n] else None) for n in H.nodes]
pairs.sort(key=lambda t: (t[1] or datetime.min))

layers, current, last_bucket = [], [], None
for n, b in pairs:
    if b is None:
        continue
    if last_bucket is None or b != last_bucket:
        if current:
            layers.append(current)
        current = [n]
        last_bucket = b
    else:
        current.append(n)
if current:
    layers.append(current)

unknown = [n for n, b in pairs if b is None]
if unknown:
    if layers:
        layers[0].extend(unknown)
    else:
        layers = [unknown]

for i, layer in enumerate(layers):
    for n in layer:
        H.nodes[n]["layer"] = i

# Layout: vertical timeline, extra spacing
# Increase scale for more vertical separation
pos = nx.multipartite_layout(H, subset_key="layer", align="vertical", scale=7.5)

# Type-based horizontal offset + slight jitter to reduce overlaps
random.seed(42)
for n, (x, y) in pos.items():
    t = H.nodes[n].get("type")
    jitter = random.uniform(-0.2, 0.2)  # Reduced jitter for cleaner layout
    if t == "process":
        pos[n] = (x - 0.6 + jitter, y)  # Increased offset for more separation
    elif t == "file":
        pos[n] = (x + 0.6 + jitter, y)  # Increased offset for more separation
    elif t == "memory":
        pos[n] = (x + jitter, y)  # Center position for memory
    else:
        pos[n] = (x + jitter, y)

# -----------------------------
# 6) Styling & drawing
# -----------------------------
plt.figure(figsize=(14, 12))  # Larger figure for more space
ax = plt.gca()

process_nodes = [n for n, a in H.nodes(data=True) if a.get("type") == "process"]
file_nodes    = [n for n, a in H.nodes(data=True) if a.get("type") == "file"]
memory_nodes  = [n for n, a in H.nodes(data=True) if a.get("type") == "memory"]
other_nodes   = [n for n, a in H.nodes(data=True) if a.get("type") not in ("process", "file", "memory")]

# File colors
file_colors = {}
for n in file_nodes:
    lbl = str(n)
    if lbl in TARGET_FILES:
        file_colors[n] = "#FFD166"  # highlight passwd/shadow
    elif lbl == PROC_SELF_MEM:
        file_colors[n] = "#B7E4C7"  # highlight /proc/self/mem
    else:
        file_colors[n] = "#D2EBBE"

# Memory node colors
memory_colors = {n: "#FFB6C1" for n in memory_nodes}  # Light pink for memory

# Process colors (race candidates red)
proc_colors = {n: ("#FF9999" if n in race_procs else "#E1AFBE") for n in process_nodes}

# Define node sizes (reduced for less overlap)
node_size_process = 900
node_size_file = 900
node_size_memory = 850
node_size_other = 750

# Edges - Color-coded by action type for better visibility
edge_color_map = {
    "write": "#FF4444",    # Bright red
    "pwrite": "#FF4444",   # Bright red
    "madvise": "#FF8800",  # Orange
    "read": "#3366FF",     # Blue
    "pread": "#3366FF",    # Blue
    "mmap": "#00AA00",     # Green
    "open": "#9900CC",     # Purple
    "spawned": "#666666",  # Gray
}

# Draw edges first with node_size parameter to ensure arrows stop at node edges
for u, v, d in H.edges(data=True):
    act = d.get("action", "")
    # Use action-specific color, default to gray
    color = edge_color_map.get(act, "#888888")
    # Make security-critical operations more prominent
    is_hot = act in ("write", "pwrite", "madvise", "mmap")
    width  = 2.4 if is_hot else 1.8 if act in ("read", "open") else 1.3
    rad    = 0.28 if is_hot else -0.18 if act in ("read", "open") else -0.12
    
    # Use larger node_size to ensure arrows stop before reaching actual nodes
    nx.draw_networkx_edges(
        H, pos,
        edgelist=[(u, v)],
        arrows=True,
        arrowsize=15,
        arrowstyle="-|>",
        width=width,
        edge_color=color,
        alpha=0.88 if is_hot else 0.80 if act in ("read", "open") else 0.70,
        connectionstyle=f"arc3,rad={rad}",
        node_size=node_size_process * 1.4,  # Use larger value to create gap
    )

# Nodes (draw after edges, so they appear on top)
nx.draw_networkx_nodes(H, pos, nodelist=process_nodes,
                       node_color=[proc_colors[n] for n in process_nodes],
                       node_shape="o", node_size=node_size_process, 
                       alpha=0.95, label="Process")

nx.draw_networkx_nodes(H, pos, nodelist=file_nodes,
                       node_color=[file_colors[n] for n in file_nodes],
                       node_shape="s", node_size=node_size_file, 
                       alpha=0.92, label="File")

if memory_nodes:
    nx.draw_networkx_nodes(H, pos, nodelist=memory_nodes,
                           node_color=[memory_colors[n] for n in memory_nodes],
                           node_shape="^", node_size=node_size_memory, 
                           alpha=0.90, label="Memory")

if other_nodes:
    nx.draw_networkx_nodes(H, pos, nodelist=other_nodes,
                           node_color="#AAAAAA", node_shape="D",
                           node_size=node_size_other, alpha=0.85, label="Other")

# Labels
labels = {n: wrap_label(n) for n in H.nodes()}
nx.draw_networkx_labels(H, pos, labels=labels, font_size=8,
                        verticalalignment="center", horizontalalignment="center")

# Edge labels (counts + time snippet) - Enhanced visibility
# Use same color map as edges for consistency
action_colors = edge_color_map.copy()  # Reuse edge color map
default_edge_color = "#333333"  # Dark gray for other actions

# Create edge labels with enhanced formatting
edge_labels_formatted = {}
for (u, v), label in nx.get_edge_attributes(H, "label").items():
    edge_labels_formatted[(u, v)] = label

# Draw edge labels with action-specific colors
# Use transparent background without border for cleaner look
for (u, v), label in edge_labels_formatted.items():
    # Extract action from edge data to determine color
    act = H.edges[(u, v)].get("action", "")
    label_color = action_colors.get(act, default_edge_color)
    
    # Draw each edge label separately with appropriate color
    # Remove border and use minimal semi-transparent background
    nx.draw_networkx_edge_labels(
        H, pos,
        edge_labels={(u, v): label},
        font_size=8.5,  # Slightly smaller for cleaner look
        font_color=label_color,
        font_weight='bold',  # Make text more prominent
        bbox=dict(boxstyle="round,pad=0.15", 
                 facecolor="white", 
                 edgecolor="none",  # Remove border
                 alpha=0.70)  # More transparent background for minimal interference
    )

# Legend - Enhanced with edge label colors
legend_text = [
    "Process (red = possible race: madvise + write/pwrite in same second)",
    "File: yellow = /etc/passwd or /etc/shadow, green = /proc/self/mem",
    "Memory: pink triangles = memory regions (for madvise, mmap operations)",
    "Edge Labels: RED=write/pwrite, ORANGE=madvise, BLUE=read, GREEN=mmap, PURPLE=open"
]
for i, txt in enumerate(legend_text):
    plt.text(0.02, 0.985 - i*0.03, txt, transform=plt.gcf().transFigure,
             fontsize=9, va="top", ha="left",
             bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="#CCCCCC", alpha=0.9))

# plt.title("Dirty COW Provenance Graph (Vertical Timeline, Aggregated & Highlighted)", fontsize=13)
plt.axis("off")
plt.tight_layout()
plt.savefig("provenance_graph_timestamp_race_vertical.png", dpi=300)
plt.show()

# -----------------------------
# 7) Console summary
# -----------------------------
print(f"\n[INFO] Graph Statistics:")
print(f"  - Total nodes: {len(H.nodes())}")
print(f"  - Process nodes: {len(process_nodes)}")
print(f"  - File nodes: {len(file_nodes)}")
print(f"  - Memory nodes: {len(memory_nodes)}")
print(f"  - Other nodes: {len(other_nodes)}")
print(f"  - Total edges: {len(H.edges())}")
print(f"  - Removed isolated bash nodes: {len(isolated_bash)}")

# Count edges by action type
edge_action_counts = {}
for u, v, d in H.edges(data=True):
    act = d.get("action", "unknown")
    edge_action_counts[act] = edge_action_counts.get(act, 0) + 1
print(f"\n[INFO] Edge counts by action:")
for act, cnt in sorted(edge_action_counts.items(), key=lambda x: -x[1]):
    print(f"  - {act}: {cnt}")

print(f"\n[INFO] Race-candidate processes: {len(race_procs)}")
if race_procs:
    for p in sorted(race_procs):
        print("  -", p)
print("\n[INFO] Output: provenance_graph_timestamp_race_vertical.png")
