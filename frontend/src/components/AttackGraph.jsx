import CytoscapeComponent from 'react-cytoscapejs'

export default function AttackGraph({ graph }) {
  const elements = [...(graph?.attack?.nodes || []), ...(graph?.attack?.edges || [])]

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-cyan-200">Attack graph</p>
          <h3 className="mt-2 text-lg font-semibold text-white">Live graph stream</h3>
        </div>
      </div>

      <div className="mt-4 h-[360px] rounded-xl border border-slate-800 overflow-hidden">
        <CytoscapeComponent
          elements={elements}
          stylesheet={[
            {
              selector: 'node',
              style: {
                'background-color': '#22d3ee',
                label: 'data(label)',
                color: '#f8fafc',
                'font-size': '12px',
                'text-valign': 'center',
                'text-halign': 'center',
                width: 28,
                height: 28,
              },
            },
            {
              selector: 'edge',
              style: {
                width: 2,
                'line-color': '#94a3b8',
                'target-arrow-color': '#94a3b8',
                'target-arrow-shape': 'triangle',
                label: 'data(label)',
                color: '#e2e8f0',
                'font-size': '10px',
              },
            },
          ]}
          layout={{ name: 'cose', animate: true, padding: 24 }}
        />
      </div>
    </div>
  )
}
