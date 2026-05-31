export default function TelemetryConsole({ events = [] }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-cyan-200">Telemetry stream</p>
          <h3 className="mt-2 text-lg font-semibold text-white">Live event feed</h3>
        </div>
      </div>

      <div className="mt-4 max-h-[320px] space-y-2 overflow-y-auto pr-1">
        {events.length === 0 ? (
          <p className="text-sm text-slate-300">Awaiting live events from the backend.</p>
        ) : (
          events.map((event, index) => (
            <div key={`${event.job_id || 'event'}-${index}`} className="rounded-xl border border-slate-800 bg-slate-900/80 px-3 py-2">
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm font-semibold text-cyan-100">{event.type || 'event'}</p>
                <span className="text-xs text-slate-400">{event.event_type || event.status || 'stream'}</span>
              </div>
              <pre className="mt-2 overflow-x-auto text-xs text-slate-200">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
