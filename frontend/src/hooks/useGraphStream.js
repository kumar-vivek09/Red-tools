import { useMemo } from 'react'

function upsertNode(graph, graphKey, nodeId, label, metadata = {}) {
  const target = graph[graphKey] || { nodes: [], edges: [] }
  const existing = target.nodes.find((node) => node.data.id === nodeId)

  if (existing) {
    existing.data.label = label || existing.data.label
    existing.data.metadata = { ...existing.data.metadata, ...metadata }
  } else {
    target.nodes.push({
      data: {
        id: nodeId,
        label: label || nodeId,
        kind: metadata.kind || 'node',
        metadata,
      },
    })
  }

  graph[graphKey] = target
}

function upsertEdge(graph, graphKey, edgeId, source, target, label, metadata = {}) {
  const targetGraph = graph[graphKey] || { nodes: [], edges: [] }
  const exists = targetGraph.edges.find((edge) => edge.data.id === edgeId)

  if (!exists) {
    targetGraph.edges.push({
      data: {
        id: edgeId,
        source,
        target,
        label,
        metadata,
      },
    })
  } else {
    exists.data.label = label || exists.data.label
    exists.data.metadata = { ...exists.data.metadata, ...metadata }
  }

  graph[graphKey] = targetGraph
}

export function useGraphStream(events) {
  return useMemo(() => {
    const graph = {
      attack: { nodes: [], edges: [] },
      malware: { nodes: [], edges: [] },
      ai: { nodes: [], edges: [] },
    }

    events.forEach((payload) => {
      if (payload?.type === 'graph_update') {
        const graphKey = payload.graph || 'attack'

        if (payload.kind === 'node') {
          upsertNode(graph, graphKey, payload.id, payload.label, payload.metadata || {})
        }

        if (payload.kind === 'edge') {
          upsertEdge(
            graph,
            graphKey,
            payload.id,
            payload.source,
            payload.target,
            payload.label || payload.relation || payload.kind,
            payload.metadata || {},
          )
        }

        return
      }

      if (payload?.type !== 'telemetry') {
        return
      }

      const eventType = payload.event_type
      const host = payload.host || payload.target || payload.url || payload.source

      if (eventType === 'host_discovered' && host) {
        upsertNode(graph, 'attack', host, host, { kind: 'host', event_type: eventType, ...payload })
      }

      if (eventType === 'port_discovered' && payload.host && payload.port) {
        const portNodeId = `${payload.host}:${payload.port}`
        upsertNode(graph, 'attack', portNodeId, portNodeId, {
          kind: 'port',
          host: payload.host,
          port: payload.port,
          service: payload.service,
          event_type: eventType,
          ...payload,
        })
        upsertEdge(graph, 'attack', `edge:${payload.host}:${payload.port}`, payload.host, portNodeId, 'listens_on', { event_type: eventType })
      }

      if (eventType === 'url_discovered' && payload.url) {
        const urlNodeId = `url:${payload.url}`
        upsertNode(graph, 'attack', urlNodeId, payload.url, { kind: 'url', event_type: eventType, ...payload })
        if (payload.host) {
          upsertEdge(graph, 'attack', `edge:${payload.host}:${payload.url}`, payload.host, urlNodeId, 'hosts', { event_type: eventType })
        }
      }

      if (eventType === 'service_detected' && payload.host && payload.service) {
        const serviceNodeId = `${payload.host}:${payload.service}`
        upsertNode(graph, 'attack', serviceNodeId, payload.service, {
          kind: 'service',
          host: payload.host,
          service: payload.service,
          event_type: eventType,
          ...payload,
        })
        upsertEdge(graph, 'attack', `edge:${serviceNodeId}`, payload.host, serviceNodeId, 'exposes', { event_type: eventType })
      }

      if (eventType === 'vulnerability_detected' && payload.target) {
        const vulnNodeId = `vuln:${payload.target}:${payload.port || 'generic'}`
        upsertNode(graph, 'attack', vulnNodeId, payload.vulnerability || 'vulnerability', {
          kind: 'vulnerability',
          target: payload.target,
          event_type: eventType,
          ...payload,
        })
        if (payload.host || payload.target) {
          upsertEdge(graph, 'attack', `edge:${vulnNodeId}`, payload.host || payload.target, vulnNodeId, 'affected_by', { event_type: eventType })
        }
      }
    })

    return graph
  }, [events])
}
