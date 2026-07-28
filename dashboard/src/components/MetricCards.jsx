function RiskBar({ score }) {
  const color = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--yellow)' : 'var(--green)'
  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar-track">
        <div className="risk-bar-fill" style={{ width: `${score}%`, background: color }} />
      </div>
    </div>
  )
}

export default function MetricCards({ stats }) {
  const s = stats || {}

  return (
    <div className="metric-cards">
      <div className="metric-card info">
        <div className="label">Total Sessions</div>
        <div className="value">{s.total_sessions ?? '—'}</div>
        <div className="sub">all time</div>
      </div>

      <div className="metric-card threat">
        <div className="label">Threats Detected</div>
        <div className="value">{s.total_threats ?? '—'}</div>
        <div className="sub">ransomware pattern</div>
      </div>

      <div className="metric-card safe">
        <div className="label">Benign Sessions</div>
        <div className="value">{s.benign_sessions ?? '—'}</div>
        <div className="sub">classified safe</div>
      </div>

      <div className="metric-card warn">
        <div className="label">Avg Risk Score</div>
        <div className="value">{s.avg_risk_score != null ? s.avg_risk_score.toFixed(1) : '—'}</div>
        <div className="sub">across all sessions</div>
        {s.avg_risk_score != null && <RiskBar score={s.avg_risk_score} />}
      </div>
    </div>
  )
}
