"""
Decision Tree trainer for BPF XDP IDS.
Reads a CSV with columns: SOURCE_PORT, DEST_PORT, PROTOCOL, MEAN_SIZE, LABEL
Outputs a C header (dt_params.h) ready to be included in the BPF project.

Usage:
    max_depth (optional, default=6): limits tree depth.
    With DT_NODE_NB = 2^(max_depth+1) - 1, a depth-6 tree needs 127 nodes.
    Keep max_depth <= 6 to stay within BPF stack limits.
"""

import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder


FEATURE_COLS = ["Source Port", "Destination Port", "Protocol", "Fwd Packet Length Mean"] #features columns in the CSV
FEATURE_IDX  = {"Source Port":0,"Destination Port":1,"Protocol":2,"Fwd Packet Length Mean":3} #features ID in the C program. Must match the switch(f_i) in dt_xdp.bpf.c exactly.
LABEL_COL    = "Label"
BENIGN_LABEL = "BENIGN"

# Load dataset into a tuple of (X, y) where:
#   X is a 2D numpy array of shape [n_samples, n_features]. CAN BE REALLY BIG
#   y is a 1D numpy array of binary labels (0=BENIGN,
def load_dataset(path: str) -> tuple:
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()

    #Check if all the columns are in the actual csv
    missing = [c for c in FEATURE_COLS + [LABEL_COL] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in CSV: {missing}")

    # Drop incomplete rows (= with missing values in features or label columns)
    df = df.dropna(subset=FEATURE_COLS + [LABEL_COL])

    X = df[FEATURE_COLS].astype(np.float64).values

    # Binary label: 0 = BENIGN, 1 = MALICIOUS
    y = (df[LABEL_COL].str.strip() != BENIGN_LABEL).astype(int).values

    labels = df[LABEL_COL].str.strip().unique().tolist()
    print(f"[dataset]  {len(df)} rows, {len(labels)} label classes: {labels}")
    print(f"[dataset]  BENIGN: {(y==0).sum()}  MALICIOUS: {(y==1).sum()}")
    return X, y

# Train a DT.
def train(X, y, max_depth: int) -> DecisionTreeClassifier:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, stratify=y
    )

    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        max_leaf_nodes=2**max_depth, #leave some room but force almost complete tree to be implemented. 
        class_weight="balanced",    # handles imbalanced BENIGN/MALICIOUS ratio
        min_samples_leaf=5,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[evaluation]")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "MALICIOUS"]))
    print(f"[tree]  depth={clf.get_depth()}  leaves={clf.get_n_leaves()}  nodes={clf.tree_.node_count}")
    return clf


def export_c_header(clf: DecisionTreeClassifier, max_depth: int, out_path: str):
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
            # Majority class at this leaf
            class_counts = sk_value[sk_i][0]  # shape [n_classes]
            majority_class = int(np.argmax(class_counts))
            # pass_left is the decision: 1 = PASS (benign), 0 = DROP (malicious)
            pass_decision = 1 if majority_class == 0 else 0

            # Leaf node: bit6=0, bit7=pass decision, bits5..0=0 (unused)
            feature_byte = (pass_decision << 7)  # bit6=0 → leaf
            nodes[bfs_i] = (feature_byte, 0)
        
        #non leaf nodes :
        else:
            sk_feat_i = sk_feature[sk_i]

            # Map sklearn feature index to our BPF feature index
            bpf_feat_i = sk_feat_i  # same order since we control FEATURE_COLS
            threshold  = int(round(sk_threshold[sk_i]))

            #find pass_left decision
            pass_left = 0
            #       left child == leaf        and    decision == pass   or right child = leaf and decision == drop
            class_counts = [sk_value[sk_left[sk_i]][0], sk_value[sk_right[sk_i]][0]]
            #comparing % of benign in left and right nodes to create pass_left boolean.
            pass_left = (class_counts[0][1]/np.sum(class_counts[0])) > (class_counts[1][1]/np.sum(class_counts[1]))
            
            #exporting raw node values to the nodes array
            feature_byte = (pass_left << 7) | (1 << 6) | (bpf_feat_i & 0x3F)
            nodes[bfs_i] = (feature_byte, threshold)

            #next DT nodes : left, then right.
            bfs_queue.append((2 * bfs_i + 1, sk_left[sk_i]))
            bfs_queue.append((2 * bfs_i + 2, sk_right[sk_i]))

    # Fill unused slots with zero
    for i in range(max_nodes):
        if nodes[i] is None:
            nodes[i] = (0, 0)

    # ── Write C header ────────────────────────────────────────────────────────
    with open(out_path, "w") as f:
        f.write("// Auto-generated by train_dt.py.\n")
        f.write("// Include this file in dt_xdp.usr.c to load the decision tree.\n\n")
        f.write(f"//#define DT_NODE_NB {max_nodes}\n\n")
        f.write("static struct dt_node trained_dt_nodes[] = {\n")
        for i, (feat, thresh) in enumerate(nodes):
            is_leaf     = (feat & 0b01000000) == 0
            pass_left   = (feat >> 7) & 1
            feat_idx    = feat & 0x3F
            comment = (
                f"leaf, {'PASS' if pass_left else 'DROP'}"
                if is_leaf
                else f"feat={feat_idx} thresh={thresh} pass_left={pass_left}"
            )
            f.write(f"    {{ .feature = 0x{feat:02X}, .threshold = {thresh} }},  // [{i}] {comment}\n")
        f.write("};\n")

    print(f"\n[export]  Written to {out_path}  ({max_nodes} nodes)")
    print(f"[export]  Add to dt_xdp.usr.c:")
    print(f'          #include "dt_params.h"')
    print(f"          // replace retrieve_dt_parameters() with:")
    print(f"          memcpy(dt_nodes_array, trained_dt_nodes, sizeof(trained_dt_nodes));")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    csv_path  = sys.argv[1]
    max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 6

    # Warn if DT_NODE_NB would exceed BPF map limits
    max_nodes = 2 ** (max_depth + 1) - 1
    print(f"[config]  max_depth={max_depth}  →  DT_NODE_NB={max_nodes}")
    if max_nodes > 127:
        print(f"[warning] DT_NODE_NB={max_nodes} is large — consider max_depth <= 6")

    X, y = load_dataset(csv_path)
    clf  = train(X, y, max_depth)
    export_c_header(clf, max_depth=clf.get_depth(), out_path="dt_params.h")

    #print decision tree into standard output (in order to compare with outputed dt_params.h)
    plot_tree(clf, fontsize= 15, feature_names=FEATURE_COLS, class_names=[BENIGN_LABEL, "Malicious"])
    plt.show()

if __name__ == "__main__":
    main()