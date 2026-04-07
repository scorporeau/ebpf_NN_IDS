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

PATHES = ["/home/sacha/Desktop/ebpf_progs/ML/data/self/curr.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_DNS.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_LDAP.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_NetBIOS.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_NTP.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_UDP.csv",
          "/home/sacha/Desktop/ebpf_progs/ML/data/CICDDoS2019/CSV-01-12/01-12/DrDoS_MSSQL.csv"] #easier to store pathes directly in this script, since we will modify the features according to each CSV source.
#For estimating features, MUST HAVE _mean and _std, OPTIONAL _skew, _max and _min.
FEATURE_COLS = [["src_port", "dst_port", "protocol","fwd_payload_bytes_mean","fwd_payload_bytes_std","fwd_packets_IAT_mean","fwd_packets_IAT_std"],
                ["Source Port", "Destination Port", "Protocol", "Fwd IAT_mean", "Fwd IAT_std", "Fwd Packet Length_mean", "Fwd Packet Length_std"],
                ["Source Port", "Destination Port", "Protocol", "Fwd IAT_mean", "Fwd IAT_std", "Fwd Packet Length_mean", "Fwd Packet Length_std"],
                ["Source Port", "Destination Port", "Protocol", "Fwd IAT_mean", "Fwd IAT_std", "Fwd Packet Length_mean", "Fwd Packet Length_std"],
                ["Source Port", "Destination Port", "Protocol", "Fwd IAT_mean", "Fwd IAT_std", "Fwd Packet Length_mean", "Fwd Packet Length_std"],
                ["Source Port", "Destination Port", "Protocol", "Fwd IAT_mean", "Fwd IAT_std", "Fwd Packet Length_mean", "Fwd Packet Length_std"],
                ["Source Port", "Destination Port", "Protocol", "Fwd IAT_mean", "Fwd IAT_std", "Fwd Packet Length_mean", "Fwd Packet Length_std"]] #features columns in the CSV
FEATURE_IDX  = {"src_port":0, "dst_port":1, "protocol":2,"fwd_payload_bytes":3,"fwd_packets_IAT":4,"fwd_payload_bytes_mean":5,
                "Source Port":0,"Destination Port":1,"Protocol":2,"Fwd Packet Length":3, "Fwd IAT": 4, "Fwd Packet Length_mean":5} #features ID in the C program. Must match the switch(f_i) in dt_xdp.bpf.c exactly (which normaally fits the order of features in ml_dt.h)
FEATURE_NAMES = ["S port","D port","prot","packet len","IAT",'mean packet len'] #Feature names, in the same order as the C file (& above)
LABEL_COL    = "Label" #label col has to be the same in each csv
BENIGN_LABEL = "BENIGN" #same for benign keyword
FEATURES_NB = 6

# Load every datasets into a tuple of (X, y) where:
#   X is a 2D numpy array of shape [n_samples, n_features]. CAN BE REALLY BIG
#   y is a 1D numpy array of binary labels (0=BENIGN, 1 = malicious)
def load_datasets(pathes) -> tuple:
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
        Xi = np.zeros((FEATURES_NB, len(df)))
        
        for feat_name_csv in FEATURE_COLS[i_p]:
            #for the columns that directly corresponds to features (are keys in the dict) : simply copy them to the dataframe (at right index : dict)
            if feat_name_csv in FEATURE_IDX.keys():
                feature_idx = FEATURE_IDX[feat_name_csv]
                Xi[feature_idx, :] = df[feat_name_csv].astype(np.int32).values
                
            #for the columns that contains mean, std, ... (& are not keys of the dict) -> use them to reconstruct the corresponding feature
            else:
                # Try to find base feature by removing statistical suffixes
                base_feat_name = feat_name_csv
                # Remove common statistical suffixes to find base feature
                for suffix in ["_mean", "_std", "_skew"]:
                    if suffix in base_feat_name:
                        base_feat_name = base_feat_name.replace(suffix, "").strip()
                        break
                
                # Find matching base feature in FEATURE_IDX
                matching_feat = None
                for key in FEATURE_IDX.keys():
                    if key in base_feat_name or base_feat_name in key: # (Be careful about CSV features names. You can still change them easily)
                        matching_feat = key
                        break
                feature_idx = FEATURE_IDX[matching_feat]
                #if feature is not already reconstructed (because we encounter twice a parameter of the feature : mean & std)
                if Xi[feature_idx, 0] == 0:
                    #At this step, we found the OG feature.
                    # Now, generate a new value for the sample using mean and std from the CSV
                    
                    std_col = matching_feat + "_std"
                    mean_col = matching_feat + "_mean"
                    Xi[feature_idx, :] = np.maximum(np.random.normal(df[mean_col].astype(np.float64), df[std_col].astype(np.float64)), 0)

        
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


def DT_export_c_header(clf: DecisionTreeClassifier, max_depth: int, out_path: str, rep=None):
    """
    Converts sklearn tree to the dt_node array format used in dt_xdp.bpf.c.

    dt_node.feature byte layout:
        bit 7 (MSB)  : pass_left  — 1 = pass if feature <= threshold, 0 = pass if feature > threshold
        bit 6        : is_defined - 1 = defined node, 0 = unused
        bits 5..0    : feature index (0..5)

    dt_node.threshold: __u32, the split threshold value (rounded from float)

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
        
        #leaf nodes : empty
        is_leaf = (sk_left[sk_i] == -1)
        if is_leaf:
            #don't care about anything entered in this node, it only need a 0 in 3rd MSB.
            nodes[bfs_i] = (0, 0)
        
        #non leaf nodes :
        else:
            sk_feat_i = sk_feature[sk_i]

            # Map sklearn feature index to our BPF feature index
            bpf_feat_i = sk_feat_i  # same order since we control FEATURE_COLS
            threshold  = np.int32(round(sk_threshold[sk_i]-0.5)) #round DOWN (<=)

            #find pass_left and pass_right decisions
            values_childs = [[sk_value[sk_left[sk_i]][0][0], sk_value[sk_left[sk_i]][0][1]],[sk_value[sk_right[sk_i]][0][0], sk_value[sk_right[sk_i]][0][1]]]
            #comparing values to create pass_left boolean.
            # in cc : first index = left(0) or right (1), 2nd index = benign(0) or malicious (1), 3rd index = output (here we have )
            pass_left = (values_childs[0][0]) > (values_childs[0][1])
            pass_right = (values_childs[1][0]) > (values_childs[1][1])
            
            #exporting raw node values to the nodes array
            feature_byte = (pass_left << 7) | (pass_right << 6) | (1 << 5) | (bpf_feat_i & 0b00011111)
            nodes[bfs_i] = (feature_byte, threshold)

            #next DT nodes : left, then right childs.
            bfs_queue.append((2 * bfs_i + 1, sk_left[sk_i]))
            bfs_queue.append((2 * bfs_i + 2, sk_right[sk_i]))

    # Fill unused slots with zero
    for i in range(max_nodes):
        if nodes[i] is None:
            nodes[i] = (0, 0)

    # ── Write C header ────────────────────────────────────────────────────────
    with open(out_path, "w") as f:
        f.write("// Auto-generated by main.py.\n")
        f.write("// Include this file in dt_xdp.usr.c to load the decision tree.\n\n")
        f.write(f"//#define DT_NODE_NB {max_nodes}\n\n")
        f.write("static struct dt_node trained_dt_nodes[] = {\n")
        for i, (feat, thresh) in enumerate(nodes):
            is_leaf     = (feat & 0b00100000) == 0
            pass_left   =  feat & 0b10000000 >> 7
            pass_right  =  feat & 0b01000000 >> 6
            feat_idx    =  feat & 0b00011111
            comment = (
                f"leaf / undef"
                if is_leaf
                else f"feat={FEATURE_NAMES[feat_idx]} thresh={thresh} pass_left={pass_left} pass_right = {pass_right}"
            )
            f.write(f"    {{ .feature = 0x{feat:02X}, .threshold = {thresh} }},  // [{i}] {comment}\n")
        f.write("};\n")

        #writing report of this trained DT :
        if (rep):
            f.write("/*\n")
            f.write(rep)
            f.write("*/")

    print(f"\n[export]  Written to {out_path}  ({max_nodes} nodes)")
    print(f"[export]  Add to dt_xdp.usr.c:")
    print(f'          #include "dt_params.h"')
    print(f"          // replace retrieve_dt_parameters() with:")
    print(f"          memcpy(dt_nodes_array, trained_dt_nodes, sizeof(trained_dt_nodes));")


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
    DT_export_c_header(clf, max_depth=clf.get_depth()-1, out_path="/home/sacha/Desktop/ebpf_progs/ML/DT/dt_params.h", rep=rep) #removing 1 from depth since we are not storing the leaf nodes (nodes without threshold are not sent to bpf, decision to drop or pass is stored in the parent node.)

if __name__ == "__main__":
    main()