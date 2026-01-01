import json
import random
import time

# --- CONFIGURATION ---
NODES = 100000
EDGES = 500000
FILENAME = "big_graph_100k.json"

def generate_json():
    print(f"[*] Génération de {NODES} nœuds...")
    data = {"principals": [], "edges": []}
    ids = []

    # 1. Création des identités
    for i in range(NODES):
        pid = f"User_{i}"
        ptype = "User" if i % 2 == 0 else "Role"
        data["principals"].append({
            "id": pid, 
            "type": ptype, 
            "controlled": False, 
            "critical": False
        })
        ids.append(pid)

    # 2. Injection de la cible et de l'attaquant
    attack_chain = ["Bob", "Role_A", "Role_B", "Role_C", "Role_D", "Alice_Admin"]
    for name in attack_chain:
        if name not in ids:
            data["principals"].append({
                "id": name, "type": "Role", 
                "controlled": (name == "Bob"), 
                "critical": (name == "Alice_Admin")
            })
            ids.append(name)

    print(f"[*] Création de {EDGES} relations (bruit)...")
    # 3. Arêtes aléatoires
    for _ in range(EDGES):
        u, v = random.choice(ids), random.choice(ids)
        if u != v:
            data["edges"].append({"from": u, "to": v, "type": "CAN_ACT_AS"})

    # 4. Arêtes de l'attaque
    for i in range(len(attack_chain)-1):
        data["edges"].append({
            "from": attack_chain[i], 
            "to": attack_chain[i+1],
            "type": "CAN_ACT_AS"
        })

    print(f"[*] Sauvegarde dans {FILENAME}...")
    with open(FILENAME, "w") as f:
        json.dump(data, f)
    
    print(f"[SUCCESS] Fichier généré : {FILENAME}")

if __name__ == "__main__":
    generate_json()