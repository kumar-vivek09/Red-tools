import { useEffect, useMemo, useState } from 'react'

const wsBase = () => {
  const base = import.meta.env.VITE_WS_BASE_URL || window.location.origin
  return base.replace(/^http/, 'ws')
}

export function useTelemetry() {
  const [events, setEvents] = useState([])
  const [jobs, setJobs] = useState({})
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    let socket
    let retries = 0

    const connect = () => {
      try {
        socket = new WebSocket(`${wsBase()}/ws/telemetry`)

        socket.onopen = () => {
          setConnected(true)
          retries = 0
        }

        socket.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data)
            setEvents((current) => [payload, ...current].slice(0, 100))

            if (payload.type === 'job_status' && payload.job_id) {
              setJobs((current) => ({ ...current, [payload.job_id]: payload }))
            }
          } catch (error) {
            console.error('Unable to parse telemetry payload', error)
          }
        }

        socket.onclose = () => {
          setConnected(false)
          retries += 1
          if (retries <= 5) {
            window.setTimeout(connect, 1500 * retries)
          }
        }

        socket.onerror = () => {
          socket.close()
        }
      } catch (error) {
        console.error('Unable to connect to telemetry websocket', error)
      }
    }

    connect()

    return () => {
      if (socket) {
        socket.close()
      }
    }
  }, [])

  const status = useMemo(() => ({
    connected,
    jobs_count: Object.keys(jobs).length,
    events_count: events.length,
  }), [connected, jobs, events.length])

  return { events, jobs, connected, status }
}
