function riskClass(score) {
  if (score >= 70) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

function fmt(dt) {
  if (!dt) return '—'
  return new Date(dt).toLocaleTimeString()
}

export default function SessionFeed({ sessions, onRestore }) {
  return (
    <div className="card">
      <div className="card-header">
        <span>📋 Recent Sessions</span>
        <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: 12 }}>
          auto-refreshes every 5 s
        </span>
      </div>

      {sessions.length === 0 ? (
        <div className="empty">No sessions yet — ingest some events to get started.</div>
      ) : (
        <div className="scroll-body table-wrap">
          <table>
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Process</th>
                <th>Files/sec</th>
                <th>Ext churn</th>
                <th>Risk</th>
                <th>Verdict</th>
                <th>Time</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {sessions.map(s => (
                <tr key={s.id}>
                  <td>
                    <span style={{ fontFamily: 'var(--font)', fontSize: 11, color: 'var(--text-muted)' }}>
                      {s.session_id}
                    </span>
                  </td>
                  <td>{s.process_name || '—'}</td>
                  <td style={{ fontFamily: 'var(--font)' }}>
                    {s.files_modified_per_sec?.toFixed(1) ?? '—'}
                  </td>
                  <td style={{ fontFamily: 'var(--font)' }}>
                    {s.extension_change_ratio != null
                      ? (s.extension_change_ratio * 100).toFixed(0) + '%'
                      : '—'}
                  </td>
                  <td>
                    <span className={`risk-score ${riskClass(s.risk_score)}`}>
                      {s.risk_score?.toFixed(0) ?? '—'}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${s.is_ransomware ? 'ransom' : 'benign'}`}>
                      {s.is_ransomware ? '🚨 Ransomware' : '✅ Benign'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                    {fmt(s.ingested_at)}
                  </td>
                  <td>
                    {s.is_ransomware && (
                      <button
                        className="btn btn-restore"
                        onClick={() => onRestore(s.session_id)}
                      >
                        Restore
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
