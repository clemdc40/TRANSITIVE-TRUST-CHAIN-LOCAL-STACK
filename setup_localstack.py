import json
import random
import string
import time
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional, Any

import boto3
from botocore.exceptions import ClientError

# ============================================================
# CONFIG
# ============================================================

LOCALSTACK_ENDPOINT = "http://localhost:4566"
REGION = "us-east-1"

OUTPUT_FILE = "iam_dataset_localstack.json"
OUTPUT_META = "iam_dataset_localstack.meta.json"

SEED = 1337

# Dataset size
NUM_NOISE_USERS = 80          # bruit users
NUM_NOISE_ROLES = 60          # bruit roles
AVG_OUT_DEGREE = 2            # relations moyennes par rôle (trust+perm alignées)
MISSING_PERMISSION_RATE = 0.18  # % de trust sans permission (pour simuler faux positifs si on n’intersecte pas)

# TTCA injection
CONTROLLED_USER = "Bob"
NUM_TTCA_CHAINS = 8
TTCA_MIN_HOPS = 2             # >=2 edges => 3+ nodes
TTCA_MAX_HOPS = 8
NUM_CRITICAL_ROLES = 8

# Safety: limit recursion / exploration
MAX_POLICY_DOC_BYTES = 250_000


# ============================================================
# HELPERS
# ============================================================

def rnd_suffix(n=6) -> str:
    return "".join(random.choices(string.hexdigits.lower(), k=n))

def safe_json_dumps(obj: Any) -> str:
    s = json.dumps(obj)
    if len(s.encode("utf-8")) > MAX_POLICY_DOC_BYTES:
        raise ValueError("Policy doc too large")
    return s

def extract_name_from_arn(arn: str) -> str:
    # arn:aws:iam::000000000000:user/NAME  OR role/NAME
    return arn.split("/")[-1].strip()

def now_ms() -> int:
    return int(time.time() * 1000)


# ============================================================
# IAM CLIENT
# ============================================================

def iam_client():
    return boto3.client(
        "iam",
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=REGION,
    )


# ============================================================
# POLICY BUILDERS
# ============================================================

def trust_policy_allow_assume(principal_arns: List[str]) -> str:
    # Allow sts:AssumeRole from principals
    # Principal can be string or list; AWS accepts both but we normalize to list.
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "TrustAllowAssume",
            "Effect": "Allow",
            "Principal": {"AWS": principal_arns if len(principal_arns) > 1 else principal_arns[0]},
            "Action": "sts:AssumeRole",
        }]
    }
    return safe_json_dumps(policy)

def permission_policy_allow_assume(target_role_arn: str) -> str:
    # Inline policy for a user/role permitting sts:AssumeRole to target role
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAssumeTarget",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": target_role_arn
        }]
    }
    return safe_json_dumps(policy)


# ============================================================
# CREATE / ENSURE RESOURCES
# ============================================================

def ensure_user(iam, username: str) -> str:
    try:
        resp = iam.create_user(UserName=username)
        return resp["User"]["Arn"]
    except ClientError:
        # already exists
        return f"arn:aws:iam::000000000000:user/{username}"

def ensure_role(iam, role_name: str, assume_policy_doc: str) -> str:
    try:
        resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=assume_policy_doc)
        return resp["Role"]["Arn"]
    except ClientError:
        # might exist, update trust policy to match desired
        try:
            iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=assume_policy_doc)
        except ClientError:
            pass
        return f"arn:aws:iam::000000000000:role/{role_name}"

def put_inline_user_policy(iam, username: str, policy_name: str, policy_doc: str):
    try:
        iam.put_user_policy(UserName=username, PolicyName=policy_name, PolicyDocument=policy_doc)
    except ClientError:
        pass

def put_inline_role_policy(iam, role_name: str, policy_name: str, policy_doc: str):
    try:
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    except ClientError:
        pass


# ============================================================
# POLICY PARSING (INLINE ONLY)
# ============================================================

def doc_allows_assume_to(doc: Dict[str, Any], target_role_arn: str) -> bool:
    # Minimal evaluator for our generated inline policies.
    # Returns True if any statement allows sts:AssumeRole to the target role ARN.
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        action = st.get("Action")
        actions = [action] if isinstance(action, str) else (action or [])
        if "sts:AssumeRole" not in actions and "*" not in actions:
            continue
        res = st.get("Resource")
        resources = [res] if isinstance(res, str) else (res or [])
        if target_role_arn in resources or "*" in resources:
            return True
    return False


def principal_has_assume_permission(iam, principal_type: str, principal_name: str, target_role_arn: str) -> bool:
    # Inline policies only (since we create inline)
    try:
        if principal_type == "User":
            pols = iam.list_user_policies(UserName=principal_name).get("PolicyNames", [])
            for pn in pols:
                pd = iam.get_user_policy(UserName=principal_name, PolicyName=pn).get("PolicyDocument", {})
                if doc_allows_assume_to(pd, target_role_arn):
                    return True
        elif principal_type == "Role":
            pols = iam.list_role_policies(RoleName=principal_name).get("PolicyNames", [])
            for pn in pols:
                pd = iam.get_role_policy(RoleName=principal_name, PolicyName=pn).get("PolicyDocument", {})
                if doc_allows_assume_to(pd, target_role_arn):
                    return True
    except ClientError:
        return False
    return False


def trust_allows_principal(trust_doc: Dict[str, Any], principal_arn: str) -> bool:
    stmts = trust_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        action = st.get("Action")
        actions = [action] if isinstance(action, str) else (action or [])
        if "sts:AssumeRole" not in actions and "*" not in actions:
            continue
        pr = st.get("Principal", {}).get("AWS")
        if pr is None:
            continue
        principals = [pr] if isinstance(pr, str) else pr
        if principal_arn in principals or "*" in principals:
            return True
    return False


# ============================================================
# DATASET GENERATION
# ============================================================

@dataclass
class PrincipalRef:
    name: str
    ptype: str  # "User" or "Role"
    arn: str


def setup_infrastructure():
    random.seed(SEED)
    iam = iam_client()

    created_users: List[PrincipalRef] = []
    created_roles: List[PrincipalRef] = []

    # Controlled principal
    bob_arn = ensure_user(iam, CONTROLLED_USER)
    created_users.append(PrincipalRef(CONTROLLED_USER, "User", bob_arn))

    # Noise users
    for _ in range(NUM_NOISE_USERS):
        uname = f"User_{rnd_suffix(6)}"
        uarn = ensure_user(iam, uname)
        created_users.append(PrincipalRef(uname, "User", uarn))

    # Pre-create roles with temporary trust (will be overwritten)
    for _ in range(NUM_NOISE_ROLES):
        rname = f"Role_{rnd_suffix(6)}"
        # Temporary trust: Bob (harmless, overwritten later anyway)
        assume_doc = trust_policy_allow_assume([bob_arn])
        rarn = ensure_role(iam, rname, assume_doc)
        created_roles.append(PrincipalRef(rname, "Role", rarn))

    # Pick critical roles among roles + create extra critical roles if needed
    random.shuffle(created_roles)
    critical_roles = created_roles[:max(0, min(NUM_CRITICAL_ROLES, len(created_roles)))]
    critical_role_names = {r.name for r in critical_roles}

    # Make some roles explicitly "Critical_*" (more readable)
    # We'll rename by creating additional roles (rename isn't supported).
    extra_needed = max(0, NUM_CRITICAL_ROLES - len(critical_roles))
    for i in range(extra_needed):
        rname = f"Critical_{i}_{rnd_suffix(4)}"
        assume_doc = trust_policy_allow_assume([bob_arn])
        rarn = ensure_role(iam, rname, assume_doc)
        pr = PrincipalRef(rname, "Role", rarn)
        created_roles.append(pr)
        critical_roles.append(pr)
        critical_role_names.add(pr.name)

    # Pool for choosing trustors (users+roles, excluding target role itself later)
    principals_pool: List[PrincipalRef] = created_users + created_roles

    # ------------------------------------------------------------
    # 1) Random noise relations
    # For each role, pick a few trustors and set trust policy to include them.
    # Then add matching permission policies for most, but sometimes omit permission
    # to create “would-be” edges that get filtered by intersection.
    # ------------------------------------------------------------
    for role in created_roles:
        # choose k trustors
        k = max(1, int(random.expovariate(1.0 / max(1, AVG_OUT_DEGREE))))
        trustors = []
        while len(trustors) < k:
            cand = random.choice(principals_pool)
            if cand.arn == role.arn:
                continue
            trustors.append(cand)
        # update trust policy
        trust_doc = trust_policy_allow_assume([t.arn for t in trustors])
        ensure_role(iam, role.name, trust_doc)

        # permissions: for each trustor, often create permission policy to allow sts:AssumeRole to this role
        for t in trustors:
            if random.random() < MISSING_PERMISSION_RATE:
                continue  # omit permission on purpose
            pol_doc = permission_policy_allow_assume(role.arn)
            pol_name = f"Assume_{extract_name_from_arn(role.arn)}_{rnd_suffix(4)}"
            if t.ptype == "User":
                put_inline_user_policy(iam, t.name, pol_name, pol_doc)
            else:
                put_inline_role_policy(iam, t.name, pol_name, pol_doc)

    # ------------------------------------------------------------
    # 2) Inject TTCA chains:
    # Bob -> R1 -> R2 -> ... -> CriticalRole
    # Each hop requires:
    #   - next role trust allows current principal ARN
    #   - current principal has permission sts:AssumeRole on next role ARN
    # ------------------------------------------------------------
    injected_chains: List[List[str]] = []
    for _ in range(NUM_TTCA_CHAINS):
        hops = random.randint(TTCA_MIN_HOPS, TTCA_MAX_HOPS)  # edges
        # need hops roles in chain: hops edges means hops roles? Actually nodes: start + hops roles => edges = hops
        # Example: start=Bob, hops=3 => Bob->A->B->C (C can be critical)
        chain_roles = random.sample(created_roles, k=min(hops, len(created_roles)))
        # ensure last is critical (swap last with a critical role)
        if critical_roles:
            chain_roles[-1] = random.choice(critical_roles)

        path_nodes = [CONTROLLED_USER] + [r.name for r in chain_roles]
        injected_chains.append(path_nodes)

        current = PrincipalRef(CONTROLLED_USER, "User", bob_arn)
        for next_role in chain_roles:
            # Update trust policy of next_role to allow current principal (in addition to existing ones)
            try:
                gr = iam.get_role(RoleName=next_role.name)
                trust_doc = gr["Role"].get("AssumeRolePolicyDocument", {})
            except ClientError:
                trust_doc = {}

            # Merge principal into trust_doc by rebuilding a safe policy with union set
            allowed: Set[str] = set()
            # Extract existing allowed AWS principals (best-effort)
            stmts = trust_doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for st in stmts:
                pr = st.get("Principal", {}).get("AWS")
                if pr is None:
                    continue
                if isinstance(pr, str):
                    allowed.add(pr)
                else:
                    for x in pr:
                        allowed.add(x)

            allowed.add(current.arn)
            merged_trust = trust_policy_allow_assume(sorted(list(allowed)))
            ensure_role(iam, next_role.name, merged_trust)

            # Add permission to current principal to assume next_role
            pol_doc = permission_policy_allow_assume(next_role.arn)
            pol_name = f"TTCA_Assume_{next_role.name}_{rnd_suffix(4)}"
            if current.ptype == "User":
                put_inline_user_policy(iam, current.name, pol_name, pol_doc)
            else:
                put_inline_role_policy(iam, current.name, pol_name, pol_doc)

            # Now current becomes the assumed role (role principal)
            current = PrincipalRef(next_role.name, "Role", next_role.arn)

    meta = {
        "seed": SEED,
        "generated_at_ms": now_ms(),
        "controlled_user": CONTROLLED_USER,
        "num_noise_users": NUM_NOISE_USERS,
        "num_noise_roles": NUM_NOISE_ROLES,
        "avg_out_degree": AVG_OUT_DEGREE,
        "missing_permission_rate": MISSING_PERMISSION_RATE,
        "num_ttca_chains": NUM_TTCA_CHAINS,
        "ttca_hops_range": [TTCA_MIN_HOPS, TTCA_MAX_HOPS],
        "critical_role_names": sorted(list(critical_role_names)),
        "injected_chains": injected_chains,
    }

    with open(OUTPUT_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print("[SUCCESS] Infrastructure + dataset seeds created in LocalStack.")
    print(f"         Meta written to: {OUTPUT_META}")
    print(f"         Example injected chain: {injected_chains[0] if injected_chains else None}")


# ============================================================
# EXTRACTION: BUILD EFFECTIVE GRAPH (trust ∩ permission)
# ============================================================

def extract_graph_from_localstack():
    random.seed(SEED)
    iam = iam_client()

    # --- collect principals
    principals: List[Dict[str, Any]] = []
    name_to_ref: Dict[str, PrincipalRef] = {}

    # users
    users_resp = iam.list_users()
    for u in users_resp.get("Users", []):
        name = u["UserName"]
        arn = u["Arn"]
        ref = PrincipalRef(name, "User", arn)
        name_to_ref[name] = ref
        principals.append({
            "id": name,
            "type": "User",
            "controlled": (name == CONTROLLED_USER),
        })

    # roles
    roles_resp = iam.list_roles()
    role_names: List[str] = []
    for r in roles_resp.get("Roles", []):
        role_names.append(r["RoleName"])

    # Read meta for "critical" marking (because “AdministratorAccess” isn't reliable in LocalStack)
    critical_names: Set[str] = set()
    try:
        with open(OUTPUT_META, "r", encoding="utf-8") as f:
            meta = json.load(f)
            critical_names = set(meta.get("critical_role_names", []))
    except Exception:
        pass

    for rn in role_names:
        try:
            gr = iam.get_role(RoleName=rn)
            arn = gr["Role"]["Arn"]
        except ClientError:
            arn = f"arn:aws:iam::000000000000:role/{rn}"

        ref = PrincipalRef(rn, "Role", arn)
        name_to_ref[rn] = ref
        principals.append({
            "id": rn,
            "type": "Role",
            "controlled": False,
            "critical": (rn in critical_names),
        })

    # --- build effective edges
    edges: List[Dict[str, Any]] = []

    # For each target role: find allowed principals in trust policy,
    # then keep only those with permission sts:AssumeRole to that role.
    for rn in role_names:
        try:
            role = iam.get_role(RoleName=rn)["Role"]
            trust_doc = role.get("AssumeRolePolicyDocument", {})
            target_arn = role.get("Arn", f"arn:aws:iam::000000000000:role/{rn}")
        except ClientError:
            continue

        # Extract list of trustors ARNs from trust policy
        trustors_arns: Set[str] = set()
        stmts = trust_doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            if st.get("Effect") != "Allow":
                continue
            action = st.get("Action")
            actions = [action] if isinstance(action, str) else (action or [])
            if "sts:AssumeRole" not in actions and "*" not in actions:
                continue

            pr = st.get("Principal", {}).get("AWS")
            if pr is None:
                continue
            if isinstance(pr, str):
                trustors_arns.add(pr)
            else:
                for x in pr:
                    trustors_arns.add(x)

        for trustor_arn in trustors_arns:
            if trustor_arn == "*" or trustor_arn.strip() == "":
                continue
            trustor_name = extract_name_from_arn(trustor_arn)
            if trustor_name not in name_to_ref:
                # Unknown principal (maybe external). Skip.
                continue
            trustor_ref = name_to_ref[trustor_name]

            # Check permission side
            if not principal_has_assume_permission(iam, trustor_ref.ptype, trustor_ref.name, target_arn):
                continue

            edges.append({
                "from": trustor_ref.name,
                "to": rn,
                "type": "CAN_ACT_AS"
            })

    data = {"principals": principals, "edges": edges}

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"[SUCCESS] Graph extracted to: {OUTPUT_FILE}")
    print(f"          Nodes: {len(principals)}")
    print(f"          Edges (effective): {len(edges)}")


# ============================================================
# OPTIONAL: QUICK TTCA DETECTION ON EXTRACTED GRAPH
# ============================================================

def detect_ttca_from_json(input_file: str, max_depth: int = 8) -> List[List[str]]:
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    principals = {p["id"]: p for p in data.get("principals", [])}
    edges = {}
    for e in data.get("edges", []):
        edges.setdefault(e["from"], []).append(e["to"])

    controlled = [pid for pid, p in principals.items() if p.get("controlled") is True]
    critical = {pid for pid, p in principals.items() if p.get("critical") is True}

    alerts: List[List[str]] = []

    def dfs(start: str, cur: str, path: List[str], depth: int):
        if depth > max_depth:
            return
        path.append(cur)

        # TTCA condition: path length edges >=2 AND reaches critical
        if (len(path) - 1) >= 2 and cur in critical:
            alerts.append(path.copy())

        for nxt in edges.get(cur, []):
            if nxt in path:
                continue
            dfs(start, nxt, path.copy(), depth + 1)

    for s in controlled:
        dfs(s, s, [], 0)

    # Deduplicate
    uniq = []
    seen = set()
    for p in alerts:
        t = tuple(p)
        if t not in seen:
            seen.add(t)
            uniq.append(p)
    return uniq


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print(f"[+] LocalStack endpoint: {LOCALSTACK_ENDPOINT}")
    print("[+] Step 1: setup_infrastructure()")
    setup_infrastructure()

    print("\n[+] Step 2: extract_graph_from_localstack()")
    extract_graph_from_localstack()

    print("\n[+] Step 3 (optional): TTCA detection on extracted JSON")
    paths = detect_ttca_from_json(OUTPUT_FILE, max_depth=10)
    print(f"[INFO] TTCA paths found: {len(paths)}")
    for p in paths[:10]:
        print("   - " + " -> ".join(p))
