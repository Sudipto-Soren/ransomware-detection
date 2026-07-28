import { useState, useEffect, useCallback } from 'react'
import { api } from './api'
import StatusBar    from './components/StatusBar'
import MetricCards  from './components/MetricCards'
import SessionFeed  from './components/SessionFeed'
import ThreatTable  from './components/ThreatTable'
import CloudPanel   from './components/CloudPanel'

const POLL_INTERVAL_MS = 5000   // refresh every 5 seconds

export default function App() {
  const [status,     setStatus]     = useState(null)
  const [stats,      setStats]      = useState(null)
  const [sessions,   setSessions]   = useState([])
  const [threats,    setThreats]    = useState([])
  const [quarantine, setQuarantine] = useState([])
  const [lastUpdate, setLastUpdate] = useState(null)
  const [error,      setError]      = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [s, st, sess, th, q] = await Promise.all([
        api.status(),
        api.stats(),
        api.sessions(30),
        api.threats(),
        api.quarantine(),
      ])
      setStatus(s)
      setStats(st)
      setSessions(sess)
      setThreats(th)
      setQuarantine(q)
      setLastUpdate(new Date())
      setError(null)
    } catch (e) {
      setError('Cannot reach backend — is uvicorn running on port 8000?')
    }
  }, [])

  // Initial load + polling
  useEffect(() => {
    refresh()
    const id = setInterval(refresh, POLL_INTERVAL_MS)
    return () => clearInterval(id)
  }, [refresh])

  const handleRestore = async (sessionId) => {
    try {
      await api.restoreSession(sessionId)
      refresh()   // reload data immediately after restore
    } catch (e) {
      alert(`Restore failed: ${e.message}`)
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-title">
          <span className="shield">🛡️</span>
          <div>
            <h1>Ransomware Detection Dashboard</h1>
            <p>AI-Assisted Cloud-Aware Kernel-Level Detection System — Batch B31, SIT Tumakuru</p>
          </div>
        </div>
        {lastUpdate && (
          <div className="last-update">
            Last refresh: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </header>

      {error && (
        <div className="error-banner">
          ⚠ {error}
        </div>
      )}

      <main className="app-main">
        <StatusBar status={status} />
        <MetricCards stats={stats} />

        <div className="grid-two">
          <SessionFeed sessions={sessions} onRestore={handleRestore} />
          <div className="right-col">
            <ThreatTable threats={threats} onRestore={handleRestore} />
            <CloudPanel quarantine={quarantine} />
          </div>
        </div>
      </main>
    </div>
  )
}
