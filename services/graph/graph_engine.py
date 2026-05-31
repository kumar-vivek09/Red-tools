"""Graph generation wrappers reusing existing attack graph and visualization logic."""

from core.attack_graph import AttackGraph
from core.graph_visualizer import GraphVisualizer


class GraphService:
    """Wrap existing graph generation capabilities."""

    def build_attack_graph(self, results):
        return AttackGraph().generate(results)

    def render_visualization(self, target, attack_paths):
        return GraphVisualizer().generate(target, attack_paths)
