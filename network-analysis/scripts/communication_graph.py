import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

#case 1
#INPUT_FILE = "output/week2/zeek_like/conn_summary.csv"
#OUTPUT_FILE = "output/week2/communication_graph.png"

#case 2
#INPUT_FILE = "output/case2/zeek_like/conn_summary.csv"
#OUTPUT_FILE = "output/case2/visualization/communication_graph.png"

#case 3
INPUT_FILE = "output/case3/zeek_like/conn_summary.csv"
OUTPUT_FILE = "output/case3/visualization/communication_graph.png"

df = pd.read_csv(INPUT_FILE)

G = nx.Graph()

for _, row in df.iterrows():

    src = row["src_ip"]
    dst = row["dst_ip"]

    G.add_edge(src, dst)

plt.figure(figsize=(12, 8))

pos = nx.spring_layout(G, seed=42)

nx.draw_networkx_nodes(
    G,
    pos,
    node_size=2500
)

nx.draw_networkx_edges(
    G,
    pos
)

nx.draw_networkx_labels(
    G,
    pos,
    font_size=9
)

plt.title("Network Communication Graph")

plt.axis("off")

plt.tight_layout()

plt.savefig(OUTPUT_FILE)

print(f"saved: {OUTPUT_FILE}")
