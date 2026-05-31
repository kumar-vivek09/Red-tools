export default function ProcessTree({ events = [] }) {
  const processes = events
    .filter((event) => event.event_type === 'process_started' || event.event_type === 'process_spawned' || event.event_type === 'scan_completed')
    .map((event, index) => ({
      id: `${event.job_id || 'proc'}-${index}`,
      name: event.process || event.target || event.event_type,
      status: event.status || 'observed',
    }))

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
      <p className="text-xs uppercase tracking-[0.25em] text-rose-200">Process tree</p>
      <h3 className="mt-2 text-lg font-semibold text-white">Runtime telemetry</h3>
      <div className="mt-4 space-y-2">
        {processes.length === 0 ? (
          <p className="text-sm text-slate-300">No process telemetry has been published yet.</p>
        ) : (
          processes.map((process) => (
            <div key={process.id} className="rounded-xl border border-slate-800 px-3 py-2">
              <p className="text-sm font-semibold text-white">{process.name}</p>
              <p className="text-xs text-slate-300">{process.status}</p>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
