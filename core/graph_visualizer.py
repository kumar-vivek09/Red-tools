import networkx as nx
import matplotlib.pyplot as plt


class GraphVisualizer:

    def generate(self, target, attack_paths):

        G = nx.DiGraph()

        for path in attack_paths:
            steps = path.split(" → ")

            for i in range(len(steps) - 1):
                G.add_edge(steps[i], steps[i + 1])

        pos = nx.spring_layout(G)

        plt.figure(figsize=(12, 8))
        nx.draw(
            G,
            pos,
            with_labels=True,
            node_color="lightblue",
            node_size=3000,
            font_size=9,
            font_weight="bold",
            edge_color="gray"
        )

        filename = f"attack_graph_{target.replace('.', '_')}.png"

        plt.title("ARCHAI Attack Path Visualization")
        plt.savefig(filename)
        plt.close()

        return filename