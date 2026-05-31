"""Graph event publishing bridge for distributed telemetry and live graph updates."""


class GraphStream:
    def __init__(self, queue_manager):
        self.queue_manager = queue_manager

    def publish(self, payload, channel="graph.events"):
        return self.queue_manager.publish(channel, payload)

    async def publish_async(self, payload, channel="graph.events"):
        return await self.queue_manager.publish_async(channel, payload)

    def publish_node(self, graph, node_id, label=None, metadata=None):
        return self.publish(
            {
                "type": "graph_update",
                "graph": graph,
                "kind": "node",
                "id": node_id,
                "label": label or node_id,
                "node_kind": metadata.get("kind") if isinstance(metadata, dict) else None,
                "metadata": metadata or {},
            }
        )

    def publish_edge(self, graph, edge_id, source, target, relation, metadata=None):
        return self.publish(
            {
                "type": "graph_update",
                "graph": graph,
                "kind": "edge",
                "id": edge_id,
                "source": source,
                "target": target,
                "label": relation,
                "relation": relation,
                "metadata": metadata or {},
            }
        )
