function fmt(dt) {
  if (!dt) return '—'
  return new Date(dt).toLocaleString()
}

export default function ThreatTable({ threats, onRestore }) {
  const active = threats.filter(t => t.status === 'active')

  return (
    <div className="card">
      <div className="card-header">
        <span>🚨 Active Threats</span>
        <span className={`badge ${active.length > 0 ? 'ransom' : 'benign'}`}>
          {active.length} active
        </span>
      </div>

      {threats.length === 0 ? (
        <div className="empty">No threats detected yet.</div>
      ) : (
        <div className="scroll-body">
          {threats.map(t => (
            <div
              key={t.id}
              style={{
                padding:      '10px 16px',
                borderBottom: '1px solid var(--border)',
                display:      'flex',
                flexDirection:'column',
                gap:          4,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--font)', fontSize: 12, color: 'var(--red)' }}>
                  {t.session_id}
                </span>
                <span
                  className={`badge ${
                    t.status === 'recovered' ? 'benign'
                    : t.status === 'active'   ? 'ransom'
                    : 'warn'
                  }`}
                >
                  {t.status}
                </span>
              </div>

              <div style={{ display: 'flex', gap: 12, fontSize: 12, color: 'var(--text-muted)' }}>
                <span>Process: {t.process_name || '—'}</span>
                <span>Files: {t.files_affected}</span>
                <span style={{ color: t.risk_score >= 70 ? 'var(--red)' : 'var(--yellow)', fontWeight: 700 }}>
                  Risk: {t.risk_score?.toFixed(0)}/100
                </span>
              </div>

              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {fmt(t.detected_at)}
              </div>

              {t.status === 'active' && (
                <button
                  className="btn btn-restore"
                  style={{ alignSelf: 'flex-start', marginTop: 4 }}
                  onClick={() => onRestore(t.session_id)}
                >
                  🔄 Restore Files
                </button>
              )}
              {t.status === 'recovered' && (
                <button className="btn btn-recovered" style={{ alignSelf: 'flex-start', marginTop: 4 }} disabled>
                  ✅ Recovered
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
