# core/workflow_graph.py

class WorkflowGraph:

    def __init__(self):
        self.graph = {}

    def add_node(self, node_name, next_nodes=None):
        if next_nodes is None:
            next_nodes = []
        self.graph[node_name] = next_nodes

    def get_next_nodes(self, node_name):
        return self.graph.get(node_name, [])

    def build_default_workflow(self):
        """
        Define intelligent workflow structure.
        """

        self.add_node("port_scan", ["tech_detect"])
        self.add_node("tech_detect", ["header_analysis", "subdomain_enum"])
        self.add_node("subdomain_enum", ["deep_recon"])
        self.add_node("header_analysis", ["risk_evaluation"])
        self.add_node("deep_recon", ["risk_evaluation"])
        self.add_node("risk_evaluation", [])

        return self.graph