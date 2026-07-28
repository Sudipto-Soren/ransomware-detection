export default function CloudPanel({ quarantine }) {
  const total = quarantine.reduce((sum, q) => sum + (q.quarantined_count || 0), 0)

  return (
    <div className="card">
      <div className="card-header">
        <span>☁️ Cloud Protection</span>
        <span className={`badge ${total > 0 ? 'warn' : 'benign'}`}>
          {total} file{total !== 1 ? 's' : ''} blocked
        </span>
      </div>

      {quarantine.length === 0 ? (
        <div className="empty" style={{ padding: '16px' }}>
          No files quarantined. Cloud sync is clean.
        </div>
      ) : (
        <div className="card-body" style={{ padding: '8px 16px' }}>
          {quarantine.map((q, i) => (
            <div key={i} className="quarantine-item">
              <div className="q-session">
                {q.session_id} — {q.quarantined_count} file{q.quarantined_count !== 1 ? 's' : ''} blocked
              </div>
              <div className="q-meta">
                Process: {q.process_name || '—'} &nbsp;|&nbsp;
                Risk: {q.risk_score?.toFixed(0)}/100 &nbsp;|&nbsp;
                {new Date(q.quarantined_at).toLocaleTimeString()}
              </div>
            </div>
          ))}
          <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
            Files moved to backend/quarantine/ — prevented from uploading to cloud storage.
          </div>
        </div>
      )}
    </div>
  )
}
