import AttackGraph from './components/AttackGraph'
import MalwareGraph from './components/MalwareGraph'
import ProcessTree from './components/ProcessTree'
import TelemetryConsole from './components/TelemetryConsole'
import { useTelemetry } from './hooks/useTelemetry'
import { useGraphStream } from './hooks/useGraphStream'

const webPanels = [
  'Masscan / Nmap orchestration',
  'Katana / WhatWeb / Assetfinder coverage',
  'Endpoint intel and JS analysis',
  'AI operator sidebar and attack graphing',
]

const malwarePanels = [
  'Quarantine ingestion and metadata extraction',
  'Static analysis with entropy and IOC heuristics',
  'Sandbox queueing and disposable VM workflow',
  'AI malware analyst and report generation',
]

function App() {
  const { events, jobs, connected, status } = useTelemetry()
  const graph = useGraphStream(events)

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col lg:grid lg:grid-cols-[280px_1fr]">
        <aside className="border-b border-slate-800 bg-slate-950/90 px-6 py-8 lg:border-b-0 lg:border-r">
          <div className="space-y-3">
            <p className="text-xs uppercase tracking-[0.35em] text-cyan-300">ARCHAI X</p>
            <h1 className="text-2xl font-semibold text-white">Cyber research workstation</h1>
            <p className="text-sm text-slate-300">
              Production-ready modular services for recon, malware analysis, reporting, and graph intelligence.
            </p>
          </div>

          <div className="mt-8 space-y-5">
            <div>
              <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Web analysis</p>
              <div className="mt-3 space-y-2 text-sm text-slate-200">
                <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-3 py-2">Dashboard</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Recon</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Web Intel</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Attack Graph</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Reports</div>
              </div>
            </div>

            <div>
              <p className="text-xs uppercase tracking-[0.2em] text-rose-300">Malware lab</p>
              <div className="mt-3 space-y-2 text-sm text-slate-200">
                <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2">Malware Lab</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Reverse Engineering</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Sandbox</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Dynamic Analysis</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">Samples</div>
                <div className="rounded-xl border border-slate-800 px-3 py-2">AI Malware Analyst</div>
              </div>
            </div>
          </div>
        </aside>

        <main className="px-6 py-8">
          <div className="rounded-[24px] border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 p-5 sm:p-8">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <p className="text-sm uppercase tracking-[0.3em] text-cyan-300">Operator overview</p>
                <h2 className="mt-2 text-2xl font-semibold text-white sm:text-3xl">Modular cyber operations workspace</h2>
              </div>
              <div className="flex flex-wrap gap-3">
                <div className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-200">
                  Backend API: {connected ? 'online' : 'offline'}
                </div>
                <div className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-sm text-cyan-100">
                  Jobs: {status.jobs_count}
                </div>
                <div className="rounded-full border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-sm text-rose-100">
                  Events: {status.events_count}
                </div>
              </div>
            </div>

            <div className="mt-8 grid gap-4 md:grid-cols-3">
              <div className="rounded-2xl border border-cyan-500/25 bg-cyan-950/30 p-4">
                <p className="text-sm text-cyan-200">Web workspace</p>
                <p className="mt-2 text-3xl font-bold text-white">Recon</p>
                <p className="mt-2 text-sm text-slate-300">Separated attack surface mapping and intelligence workflows.</p>
              </div>
              <div className="rounded-2xl border border-rose-500/25 bg-rose-950/20 p-4">
                <p className="text-sm text-rose-200">Malware workspace</p>
                <p className="mt-2 text-3xl font-bold text-white">Lab</p>
                <p className="mt-2 text-sm text-slate-300">Isolated analysis, sandbox queueing, and AI-assisted triage.</p>
              </div>
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
                <p className="text-sm text-slate-200">Services</p>
                <p className="mt-2 text-3xl font-bold text-white">FastAPI</p>
                <p className="mt-2 text-sm text-slate-300">Modular service wrappers preserve the existing recon engines.</p>
              </div>
            </div>

            <div className="mt-8 grid gap-4 xl:grid-cols-2">
              <section className="rounded-2xl border border-cyan-500/20 bg-slate-950/60 p-5">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-cyan-100">Web analysis workspace</h3>
                  <span className="rounded-full border border-cyan-400/40 px-3 py-1 text-xs text-cyan-100">attack surface mapper</span>
                </div>
                <ul className="mt-4 space-y-3 text-sm text-slate-200">
                  {webPanels.map((item) => (
                    <li key={item} className="rounded-xl border border-slate-800 px-3 py-2">{item}</li>
                  ))}
                </ul>
              </section>

              <section className="rounded-2xl border border-rose-500/20 bg-slate-950/60 p-5">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-rose-100">Malware analysis workspace</h3>
                  <span className="rounded-full border border-rose-400/40 px-3 py-1 text-xs text-rose-100">reverse engineering lab</span>
                </div>
                <ul className="mt-4 space-y-3 text-sm text-slate-200">
                  {malwarePanels.map((item) => (
                    <li key={item} className="rounded-xl border border-slate-800 px-3 py-2">{item}</li>
                  ))}
                </ul>
              </section>
            </div>

            <div className="mt-8 grid gap-4 xl:grid-cols-2">
              <AttackGraph graph={graph} />
              <MalwareGraph graph={graph} />
            </div>

            <div className="mt-8 grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
              <TelemetryConsole events={events} />
              <ProcessTree events={events} />
            </div>

            <div className="mt-8 rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
              <p className="text-xs uppercase tracking-[0.25em] text-cyan-200">Queued jobs</p>
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {Object.values(jobs).slice(0, 4).map((job) => (
                  <div key={job.job_id} className="rounded-xl border border-slate-800 px-3 py-2">
                    <p className="text-sm font-semibold text-white">{job.job_id}</p>
                    <p className="text-xs text-slate-300">Status: {job.status}</p>
                    <p className="text-xs text-slate-300">Queue: {job.queue}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}

export default App
