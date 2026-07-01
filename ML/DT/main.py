"""
Decision Tree trainer for BPF XDP IDS.
Reads a CSV with columns: SOURCE_PORT, DEST_PORT, PROTOCOL, MEAN_SIZE, LABEL
Outputs a C header (dt_params.h) ready to be included in the BPF project.

Usage:
    max_depth: limits tree depth. The CSV pathes are directly written into the python script. Don't hesitate to modify it.
    
"""

import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

#pathes & columns to retrieve from CSV
PATHES = ["/home/sacha/Desktop/ebpf_progs/ML/data/self/curr.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_DNS.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_LDAP.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_NetBIOS.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_NTP.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_UDP.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_MSSQL.csv"] #easier to store pathes directly in this script, since we will modify the features according to each CSV source.
#For estimating features, MUST HAVE _mean and _std, OPTIONAL _skew, _max and _min.
FEATURE_COLS = [["src_port", "dst_port", "protocol" ,"fwd_packets_IAT_mean","fwd_packets_IAT_std","fwd_packets_IAT_skew","fwd_bytes_mean","fwd_bytes_std","fwd_bytes_skew"],
                ["Source Port", "Destination Port", "Protocol","Fwd Packet Length_mean", "Fwd Packet Length_std", "Flow IAT_mean", "Flow IAT_std"],
                ["Source Port", "Destination Port", "Protocol","Fwd Packet Length_mean", "Fwd Packet Length_std", "Flow IAT_mean", "Flow IAT_std"],
                ["Source Port", "Destination Port", "Protocol","Fwd Packet Length_mean", "Fwd Packet Length_std", "Flow IAT_mean", "Flow IAT_std"],
                ["Source Port", "Destination Port", "Protocol","Fwd Packet Length_mean", "Fwd Packet Length_std", "Flow IAT_mean", "Flow IAT_std"],
                ["Source Port", "Destination Port", "Protocol","Fwd Packet Length_mean", "Fwd Packet Length_std", "Flow IAT_mean", "Flow IAT_std"],
                ["Source Port", "Destination Port", "Protocol","Fwd Packet Length_mean", "Fwd Packet Length_std", "Flow IAT_mean", "Flow IAT_std"]] #features columns in the CSV. Remember that it uses f_mean and f_std to randomly reconstruct the OG feature value.

#Now, features informations to transmit to the bpf program
FEATURE_IDX  = {"src_port":0, "dst_port":1, "protocol":2,"fwd_bytes":3,"fwd_packets_IAT_mean":4,"fwd_packets_IAT":5,
                "Source Port":0,"Destination Port":1,"Protocol":2,"Fwd Packet Length":3, "Flow IAT_mean":4, "Flow IAT":5} #Theses number SHALL BE in the range 0->(FEATURES_NB-1). Every index should also be in the croissant order, according to features int definitions in /include/project_features.h (such as they can be reconstructed by fvifupdate in dt_xdp.bpf.c)
FEATURE_NAMES = ["F_S_PORT","F_D_PORT","F_PROTOCOL","F_PKT_SIZE","F_IAT_MEAN", "F_IAT"] #Feature names, in the same order as above. Strings should correspond exactly to project_features.h definitions
LABEL_COL    = "Label" #label col has to be the same in each csv (it can be easily modified by hand)
BENIGN_LABEL = "BENIGN" #same for benign keyword 

# Load every datasets into a tuple of (X, y) where:
#   X is a 2D numpy array of shape [n_samples, n_features]. CAN BE REALLY BIG
#   y is a 1D numpy array of binary labels (0=BENIGN, 1 = malicious)
def load_datasets(pathes, outpath=None) -> tuple:
    X_list, y_list = [], []
    for (i_p,path) in enumerate(pathes):
        #retrieve required columns
        #read CSV and ensure there is all the columns
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        missing = [c for c in FEATURE_COLS[i_p] + [LABEL_COL] if c not in df.columns]
        if missing:
            raise ValueError(f"Missing columns in {path}: {missing}")
        #drop empty lines
        df = df.dropna(subset=FEATURE_COLS[i_p] + [LABEL_COL])
        #create new Xi dataframe; will be filled later.
        # Xi has shape (FEATURES_NB, n_samples) where each row is a feature, each col is a sample
        Xi = np.zeros((len(FEATURE_NAMES), len(df)))
        
        for feat_name_csv in FEATURE_COLS[i_p]:
            #for the columns that directly corresponds to features (are keys in the dict) : simply copy them to the dataframe (at right index : dict)
            if feat_name_csv in FEATURE_IDX.keys():
                feature_idx = FEATURE_IDX[feat_name_csv]
                Xi[feature_idx, :] = df[feat_name_csv].astype(np.int32).values
                
            #for the columns that contains mean, std, ... (& are not keys of the dict) -> use them to reconstruct the corresponding feature
            else:
                # Try to find base feature by removing suffixes
                base_feat_name = feat_name_csv
                for suffix in ["_mean", "_std", "_skew"]:
                    if suffix in base_feat_name:
                        base_feat_name = base_feat_name.replace(suffix, "").strip()
                        break
                
                if base_feat_name in FEATURE_IDX.keys():
                    feature_idx = FEATURE_IDX[base_feat_name]

                    #if feature is not already reconstructed (because we encounter twice a parameter of the feature : mean & std)
                    if Xi[feature_idx, 0] == 0:
                        # At this step, we found the OG feature & it has not been already filled.
                        # Now, generate a new value for the sample using mean and std (and skew ?) from the CSV.

                        std_col = base_feat_name + "_std"
                        mean_col = base_feat_name + "_mean"
                        skew_col = base_feat_name + "_skew" if (base_feat_name + "_skew") in df.columns else None

                        mean_vals = df[mean_col].astype(np.float64).to_numpy()
                        std_vals = df[std_col].astype(np.float64).to_numpy()

                        if skew_col is not None:
                            # try to use scipy's skewnorm if available; otherwise fall back to an approximation
                            try:
                                from scipy.stats import skewnorm
                                # build sample array using per-sample skew parameter
                                a_vals = df[skew_col].astype(np.float64).to_numpy()
                                samples = np.array([
                                    skewnorm.rvs(a=float(a), loc=float(m), scale=float(s))
                                    for m, s, a in zip(mean_vals, std_vals, a_vals)
                                ])
                            except Exception:
                                # fallback: approximate skew by mixing a normal and an exponential term scaled by skew
                                a_vals = df[skew_col].astype(np.float64).to_numpy()
                                normal_part = np.random.normal(loc=0.0, scale=1.0, size=len(mean_vals)) * std_vals
                                exp_part = (np.random.exponential(scale=1.0, size=len(mean_vals)) - 1.0) * (a_vals * std_vals)
                                samples = mean_vals + normal_part + exp_part
                        else:
                            samples = np.random.normal(loc=mean_vals, scale=std_vals)

                        Xi[feature_idx, :] = np.maximum(samples.astype(np.float64), 0)

        
        yi = (df[LABEL_COL].str.strip() != BENIGN_LABEL).astype(int).to_numpy() #0 benign, 1 malicious
        labels = df[LABEL_COL].str.strip().unique().tolist()
        print(f"[dataset]  {path} : {len(df)} rows, {len(labels)} classes: {labels}")
        nben, nmal = (yi==0).sum(), (yi==1).sum()
        print(f"[dataset]  BENIGN: {nben}  MALICIOUS: {nmal}")

        #Now, remove some malicious flows if unbalanced : max malicious flows = 10 times benign flows.
        max_malicious = nben*10
        if nmal > max_malicious:
            print(f"[dataset]   Removing {nmal-max_malicious} randomly chosen Malicious samples")
            mal_indices = np.where(yi == 1)[0]
            to_remove = np.random.choice(mal_indices, nmal - max_malicious, replace=False)
            all_indices = np.arange(len(yi))
            keep_mask = ~np.isin(all_indices, to_remove)
            Xi = Xi[:, keep_mask]
            yi = yi[keep_mask]
            print(f"[dataset]   removed ! we have now {(yi==0).sum()} Benign and {(yi==1).sum()} Malicious samples.")

        
        # Append Xi and yi to the growing lists
        X_list.append(Xi)
        y_list.append(yi)
    
    # hstack and cocatenate once at the end, to reduce memory usage spikes
    print(f"[dataset]  Concatenating {len(y_list)} datasets together")
    X = np.hstack(X_list)
    y = np.concatenate(y_list)
    
    print(f"\n[dataset]  Total: {len(y)} rows — BENIGN: {(y==0).sum()}  MALICIOUS: {(y==1).sum()}")
    return X.T, y  # Transpose X to shape [n_samples, n_features]

# Train a DT.
def DT_train(X, y, max_depth: int) -> DecisionTreeClassifier:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y
    )
    print(f"[train] training DT with {len(y_train)} train samples, {len(y_test)} test samples ...")
    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        class_weight={0: 10, 1: 1},    # handles imbalanced BENIGN/MALICIOUS ratio
        min_samples_split=500,
        min_samples_leaf=100,
        criterion="entropy", #better for imbalanced data
        
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[evaluation]")
    rep = classification_report(y_test, y_pred, target_names=["BENIGN", "MALICIOUS"])
    print(rep)
    print(f"[tree]  depth={clf.get_depth()}  leaves={clf.get_n_leaves()}  nodes={clf.tree_.node_count}")
    return clf, rep


def DT_export_c_header_and_update_sh(clf: DecisionTreeClassifier, max_depth: int, out_path: str, report=None):
    """
    Converts sklearn tree to the raw __u32 node format used in dt_xdp.bpf.c.

    Node encoding in a single 32-bit value:
        bits 31..8 : threshold value (24-bit integer, lower byte is reserved)
        bits 7..2  : feature index << 2
        bit 1      : pass_left  (1 = pass if feature <= threshold)
        bit 0      : pass_right (1 = pass if feature > threshold)

    The tree is stored as a complete binary tree in BFS order:
        node 0 = root
        node i → left child  = 2*i + 1
        node i → right child = 2*i + 2
    """
    tree = clf.tree_
    # https://scikit-learn.org/stable/auto_examples/tree/plot_unveil_tree_structure.html#sphx-glr-auto-examples-tree-plot-unveil-tree-structure-py
    max_nodes = 2 ** (max_depth + 1) - 1  # size of the complete binary tree array
    print(f"[export]  Writing nodes to {out_path} ({max_nodes} max nodes)")

    # sklearn tree arrays (indexed by sklearn node id, NOT BFS position)
    sk_left     = tree.children_left    # sklearn left child id  (-1 = leaf)
    sk_right    = tree.children_right
    sk_feature  = tree.feature          # feature index (-2 = leaf)
    sk_threshold= tree.threshold        # float threshold
    sk_value    = tree.value            # shape [n_nodes, n_outputs, n_classes]

    # We'll walk the sklearn tree in BFS order and map to our array positions.
    # bfs_queue holds (bfs_position, sklearn_node_id)
    nodes = [None] * max_nodes          # our output array

    bfs_queue = [(0, 0)]
    #explore nodes in bfs order
    while bfs_queue:
        bfs_i, sk_i = bfs_queue.pop(0)
        #if index out of range
        if bfs_i >= max_nodes:
            continue
        
        #leaf nodes : undefined value 0
        if sk_left[sk_i] == -1:
            nodes[bfs_i] = 0
            continue

        # Map sklearn feature index & threshold to our BPF node encoding
        bpf_feat_i = int(sk_feature[sk_i])  # same order since we control FEATURE_IDX
        threshold_raw = float(sk_threshold[sk_i])
        threshold = int(np.floor(threshold_raw))
        threshold = max(threshold, 0)

        #find pass_left and pass_right decisions
        values_childs = [
            [sk_value[sk_left[sk_i]][0][0], sk_value[sk_left[sk_i]][0][1]],
            [sk_value[sk_right[sk_i]][0][0], sk_value[sk_right[sk_i]][0][1]],
        ]
        pass_left = int(values_childs[0][0] > values_childs[0][1])
        pass_right = int(values_childs[1][0] > values_childs[1][1])

        node_value = (
            (threshold & 0x00FFFFFF) << 8
            | ((bpf_feat_i & 0x3F) << 2)
            | (pass_left << 1)
            | pass_right
        )
        nodes[bfs_i] = node_value

        #next DT nodes : left, then right childs.
        bfs_queue.append((2 * bfs_i + 1, sk_left[sk_i]))
        bfs_queue.append((2 * bfs_i + 2, sk_right[sk_i]))

    # Fill unused slots with zero
    for i in range(max_nodes):
        if nodes[i] is None:
            nodes[i] = 0

    # ── Write dt_parameters.h ───────────────────────────────────────────────────────
    with open(out_path+"dt_params.h", "w") as f:
        f.write("// Auto-generated by main.py.\n")
        f.write("// Include this file in dt_xdp.usr.c to load the decision tree.\n\n")
        f.write("#ifndef DT_PARAMS_H\n")
        f.write("#define DT_PARAMS_H\n\n")
        f.write(f"#define DT_NODE_NB {max_nodes+1}\n\n")
        f.write("static __u32 trained_dt_nodes[] = {\n")
        for i, node_value in enumerate(nodes):
            if node_value == 0:
                comment = "leaf / undef"
            else:
                pass_left = (node_value >> 1) & 1
                pass_right = node_value & 1
                feat_idx = (node_value >> 2) & 0x3F
                threshold = (node_value >> 8) & 0x00FFFFFF
                comment = f"feat_id={feat_idx} thresh={threshold} pass_left={pass_left} pass_right={pass_right}"
            f.write(f"    0x{node_value:08X},  // [{i}] {comment}\n")
        f.write("};\n\n")

        #writing report of this trained DT :
        if report:
            f.write("/*\n")
            f.write(report)
            f.write("*/\n")

        f.write("#endif /* DT_PARAMS_H */\n")

    print(f"\n[export]  Written to {out_path}dt_params.h  ({max_nodes} nodes)")

    # ── Write dt_features.h ───────────────────────────────────────────────────────
    with open(out_path+"dt_features.h", "w") as f:
        f.write("// Auto-generated by main.py.\n")
        f.write("// Include this file in dt_xdp.xdp.c to load the feature vector descriptor.\n\n")
        f.write(f"#define DT_NODE_NB {max_nodes+1}\n\n")
        f.write(f"#define FEATURE_NB {len(FEATURE_NAMES)}\n")
        f.write("#define FEATURES (")
        for i in range(len(FEATURE_NAMES)):
            f.write(f"{FEATURE_NAMES[i]}")
            if i<(len(FEATURE_NAMES)-1):
                f.write("|")
        f.write(")\n")
    
    print(f"\n[export]  Written to {out_path}dt_features.h  ({len(FEATURE_NAMES)} features)")

    # ── Write update_params.sh ───────────────────────────────────────────────────────
    write_update_params_sh(nodes, out_path)


def write_update_params_sh(nodes: list, out_path: str):
    """
    Generates a bash script that uses bpftool to load the decision-tree nodes
    into a running BPF map.
 
    Map value layout (4 bytes, little-endian):
        bytes 0-3 : node value (__u32 LE)

    Usage of the generated script:
        ./update_params.sh <map_id>
 
    The key for node i is simply the 4-byte LE representation of i.
    """
 
    def u32_to_hex_le(value: int) -> str:
        """Return a 4-byte little-endian hex string, e.g. '01 00 00 00'."""
        v = value & 0xFFFFFFFF
        return " ".join(f"{(v >> (8 * b)) & 0xFF:02X}" for b in range(4))
 
    sh_path = out_path + "update_params.sh"
    with open(sh_path, "w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("# Auto-generated by main.py.\n")
        f.write("# Loads decision-tree nodes into a BPF map via bpftool.\n")
        f.write("#\n")
        f.write("# Usage: sudo ./update_params.sh <map_id>\n")
        f.write("#\n")
        f.write("# Map value layout (4 bytes, little-endian):\n")
        f.write("#   bytes 0-3 : node value (__u32 LE)\n\n")
 
        f.write('if [ -z "$1" ]; then\n')
        f.write('    echo "Usage: sudo $0 <map_id>"\n')
        f.write('    exit 1\n')
        f.write('fi\n\n')
 
        f.write('MAP_ID="$1"\n\n')
 
        for i, node_value in enumerate(nodes):
            key_hex = u32_to_hex_le(i)
            value_hex = u32_to_hex_le(node_value)

            if node_value == 0:
                comment = f"node {i}: leaf / undefined"
            else:
                pass_left = (node_value >> 1) & 1
                pass_right = node_value & 1
                feat_idx = (node_value >> 2) & 0x3F
                threshold = (node_value >> 8) & 0x00FFFFFF
                comment = f"node {i}: feat_id={feat_idx} thresh={threshold} pass_left={pass_left} pass_right={pass_right}"

            f.write(f"# {comment}\n")
            f.write(
                f'bpftool map update id "$MAP_ID" '
                f'key hex {key_hex} '
                f'value hex {value_hex}\n\n'
            )
 
        f.write('echo "Done loading $MAP_ID nodes."\n')
 
    import os
    os.chmod(sh_path, 0o755)
    print(f"\n[export]  Written to {sh_path}  ({len(nodes)} node updates)")


def main():
    if len(sys.argv) < 1:
        print(__doc__)
        sys.exit(1)

    csv_pathes  = PATHES
    max_depth = int(sys.argv[1])

    # Warn if DT_NODE_NB would exceed BPF map limits
    max_nodes = 2 ** (max_depth + 1) - 1
    print(f"[config]  max_depth={max_depth}  →  DT_NODE_NB={max_nodes}")
    if max_nodes > 255:
        print(f"[warning] DT_NODE_NB={max_nodes} may be too large for ebpf — consider max_depth <= 8")

    X, y = load_datasets(csv_pathes)
    clf, rep  = DT_train(X, y, max_depth)
    #print decision tree into standard output (in order to compare with outputed dt_params.h)
    plot_tree(clf, feature_names=(FEATURE_NAMES), class_names=[BENIGN_LABEL, "Malicious"])
    plt.savefig("/home/sacha/Desktop/ebpf_progs/ML/DT/dt_params.png",dpi= 600)
    DT_export_c_header_and_update_sh(clf, max_depth=clf.get_depth()-1, out_path="/home/sacha/Desktop/ebpf_progs/ML/DT/", report=rep) #removing 1 from depth since we are not storing the leaf nodes (nodes without threshold are not sent to bpf, decision to drop or pass is stored in the parent node.)

if __name__ == "__main__":
    main()