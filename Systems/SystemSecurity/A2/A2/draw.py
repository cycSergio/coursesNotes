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
    """Bucket to second precision."""
    if not dt:
        return None
    return dt.replace(microsecond=0)

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
    action = ev.get("event", {}).get("action")
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
        lbl = f"{lbl}\n{tlabel.strftime('%H:%M:%S')}"
    G.add_edge(pnode, fpath, label=lbl, action=act)

for parent, child, dt in parent_links:
    lbl = "spawned"
    if dt:
        lbl += f"\n{dt.strftime('%H:%M:%S')}"
    G.add_edge(parent, child, label=lbl, action="spawned")

# -----------------------------
# 4) Extract Dirty COW–related subgraph
# -----------------------------
KEYS = ("dirty", "cow", "passwd", "shadow", "bash", "mem")
seed_nodes = [n for n in G.nodes if any(k in str(n) for k in KEYS)]
keep = set()
for n in seed_nodes:
    keep.add(n)
    keep |= nx.descendants(G, n)
    keep |= nx.ancestors(G, n)
H = G.subgraph(keep).copy()

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
pos = nx.multipartite_layout(H, subset_key="layer", align="vertical", scale=6.0)

# Type-based horizontal offset + slight jitter to reduce overlaps
random.seed(42)
for n, (x, y) in pos.items():
    t = H.nodes[n].get("type")
    jitter = random.uniform(-0.25, 0.25)
    if t == "process":
        pos[n] = (x - 0.4 + jitter, y)
    elif t == "file":
        pos[n] = (x + 0.4 + jitter, y)
    else:
        pos[n] = (x + jitter, y)

# -----------------------------
# 6) Styling & drawing
# -----------------------------
plt.figure(figsize=(12, 11))
ax = plt.gca()

process_nodes = [n for n, a in H.nodes(data=True) if a.get("type") == "process"]
file_nodes    = [n for n, a in H.nodes(data=True) if a.get("type") == "file"]
other_nodes   = [n for n, a in H.nodes(data=True) if a.get("type") not in ("process", "file")]

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

# Process colors (race candidates red)
proc_colors = {n: ("#FF9999" if n in race_procs else "#E1AFBE") for n in process_nodes}

# Edges
for u, v, d in H.edges(data=True):
    act = d.get("action", "")
    is_hot = act in ("write", "pwrite", "madvise")
    color  = "#FF5733" if is_hot else "#6E6E6E"
    width  = 2.6 if is_hot else 1.5
    rad    = 0.28 if is_hot else -0.18
    nx.draw_networkx_edges(
        H, pos,
        edgelist=[(u, v)],
        arrows=True,
        arrowsize=16,
        arrowstyle="-|>",
        width=width,
        edge_color=color,
        alpha=0.92 if is_hot else 0.78,
        connectionstyle=f"arc3,rad={rad}",
    )

# Nodes
nx.draw_networkx_nodes(H, pos, nodelist=process_nodes,
                       node_color=[proc_colors[n] for n in process_nodes],
                       node_shape="o", node_size=1150, alpha=0.95, label="Process")

nx.draw_networkx_nodes(H, pos, nodelist=file_nodes,
                       node_color=[file_colors[n] for n in file_nodes],
                       node_shape="s", node_size=1150, alpha=0.9, label="File")

if other_nodes:
    nx.draw_networkx_nodes(H, pos, nodelist=other_nodes,
                           node_color="#AAAAAA", node_shape="D",
                           node_size=950, alpha=0.8, label="Other")

# Labels
labels = {n: wrap_label(n) for n in H.nodes()}
nx.draw_networkx_labels(H, pos, labels=labels, font_size=8,
                        verticalalignment="center", horizontalalignment="center")

# Edge labels (counts + time snippet)
nx.draw_networkx_edge_labels(
    H, pos,
    edge_labels=nx.get_edge_attributes(H, "label"),
    font_size=7, font_color="gray"
)

# Legend
legend_text = [
    "Process (red = possible race: madvise + write/pwrite in same second)",
    "File: yellow = /etc/passwd or /etc/shadow, green = /proc/self/mem",
    "Red edges = write / pwrite / madvise (aggregated)"
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
print(f"[INFO] Nodes: {len(H.nodes())}, Edges: {len(H.edges())}")
print(f"[INFO] Removed isolated bash nodes: {len(isolated_bash)}")
print(f"[INFO] Race-candidate processes: {len(race_procs)}")
if race_procs:
    for p in sorted(race_procs):
        print("  -", p)
print("[INFO] Output: provenance_graph_timestamp_race_vertical.png")
