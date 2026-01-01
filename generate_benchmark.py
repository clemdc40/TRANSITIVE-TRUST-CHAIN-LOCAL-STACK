import json
import time
from collections import deque

INPUT_FILE = "big_graph_100k.json"

ATTACK_CONTEXT = {
    "mfa": False 
}

# -----------------------------
# Chargement du graphe
# -----------------------------
def load_graph(file_path):
    print(f"[+] Loading {file_path}...")
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    adj = {}
    principals = {}

    for p in data["principals"]:
        principals[p["id"]] = p
        adj[p["id"]] = []

    for e in data["edges"]:
        adj[e["from"]].append(e)

    return adj, principals


# -----------------------------
# Predicate Φ
# -----------------------------
def phi(edge, context):
    if edge.get("requires_mfa", False) and not context["mfa"]:
        return False
    return True


# -----------------------------
# BFS Φ-aware
# -----------------------------
def bfs_shortest_path(adj, principals, use_phi=True):
    start_nodes = [pid for pid, p in principals.items() if p.get("controlled")]
    critical_nodes = {pid for pid, p in principals.items() if p.get("critical")}

    queue = deque()
    visited = set()

    for s in start_nodes:
        queue.append((s, [s]))
        visited.add(s)

    found_paths = []

    start_time = time.time()

    while queue:
        current, path = queue.popleft()

        if current in critical_nodes and len(path) > 2:
            found_paths.append(path)
            break  

        for edge in adj.get(current, []):
            if use_phi and not phi(edge, ATTACK_CONTEXT):
                continue

            neighbor = edge["to"]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    duration = time.time() - start_time
    return found_paths, duration


# -----------------------------
# Benchmark
# -----------------------------
if __name__ == "__main__":
    adj, principals = load_graph(INPUT_FILE)

    print("[+] Running STRUCTURE-ONLY BFS")
    paths_struct, t_struct = bfs_shortest_path(adj, principals, use_phi=False)

    print("[+] Running Φ-AWARE BFS")
    paths_phi, t_phi = bfs_shortest_path(adj, principals, use_phi=True)

    print("-" * 60)
    print(f"STRUCTURE-ONLY : {len(paths_struct)} path(s) found in {t_struct:.4f}s")
    print(f"Φ-AWARE        : {len(paths_phi)} path(s) found in {t_phi:.4f}s")
    print("-" * 60)
