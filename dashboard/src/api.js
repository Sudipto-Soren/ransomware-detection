/**
 * api.js — all backend calls in one place.
 *
 * Because vite.config.js proxies /api → http://localhost:8000,
 * every function here just uses a relative path like '/api/status'.
 * No hardcoded ports anywhere in the component code.
 */

const BASE = '/api'

async function get(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`)
  return res.json()
}

async function post(path, body = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}`)
  return res.json()
}

// ── Endpoints ──────────────────────────────────────────────────────────────
export const api = {
  status:          ()         => get('/status'),
  stats:           ()         => get('/stats'),
  sessions:        (limit=50) => get(`/sessions?limit=${limit}`),
  threats:         ()         => get('/threats'),
  activeThreats:   ()         => get('/threats?status=active'),
  quarantine:      ()         => get('/cloud/quarantine'),
  stagingFiles:    ()         => get('/cloud/staging'),
  recoveryActions: ()         => get('/recovery/actions'),
  restoreSession:  (id)       => post(`/recovery/restore/${id}`),
}
