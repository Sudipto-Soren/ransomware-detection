export default function StatusBar({ status }) {
  if (!status) return (
    <div className="status-bar">
      <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>Connecting to backend…</span>
    </div>
  )

  return (
    <div className="status-bar">
      <div className="status-item">
        <div className={`dot ${status.model_loaded ? 'green' : 'red'}`} />
        <span>
          {status.model_loaded
            ? `Model loaded (${status.model_name})`
            : 'Model not loaded — run train.py first'}
        </span>
      </div>

      <div className="status-item">
        <div className={`dot ${status.monitoring_active ? 'green' : 'gray'}`} />
        <span>{status.monitoring_active ? 'Monitoring active' : 'Monitoring inactive'}</span>
      </div>

      <div className="status-item">
        <div className={`dot ${status.active_threats > 0 ? 'red' : 'green'}`} />
        <span>
          {status.active_threats > 0
            ? `${status.active_threats} active threat${status.active_threats !== 1 ? 's' : ''}`
            : 'No active threats'}
        </span>
      </div>

      <div className="status-item">
        <div className="dot yellow" />
        <span>{status.sessions_last_hour} session{status.sessions_last_hour !== 1 ? 's' : ''} in last hour</span>
      </div>
    </div>
  )
}
