// Thin REST + WebSocket client for the manager API (same origin).
const base = ''

async function j(method, path, body) {
  const opt = { method, headers: {} }
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body) }
  const r = await fetch(base + path, opt)
  const text = await r.text()
  let data
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  if (!r.ok) throw Object.assign(new Error(data.detail || data.error || r.statusText), { status: r.status, data })
  return data
}

export const api = {
  readers: () => j('GET', '/api/readers'),
  detect: (i = 0) => j('GET', `/api/sim/detect?reader_index=${i}`),
  // `reader` (PC/SC reader NAME) lets the backend re-resolve the index at request time —
  // indices shift when another reader is unplugged, and a stale index could address the
  // wrong physical SIM.
  verifyPin: (pin, reader_index = 0, reader) => j('POST', '/api/sim/verify-pin', { pin, reader_index, reader }),
  changePin: (oldp, newp, reader_index = 0) => j('POST', '/api/sim/change-pin', { old: oldp, new: newp, reader_index }),
  setPinEnabled: (pin, enabled, reader_index = 0) => j('POST', '/api/sim/pin-enabled', { pin, enabled, reader_index }),

  settings: () => j('GET', '/api/settings'),
  saveSettings: (patch) => j('PUT', '/api/settings', patch),

  instances: () => j('GET', '/api/instances'),
  cards: () => j('GET', '/api/cards'),
  portsSuggest: () => j('GET', '/api/ports/suggest'),
  provision: (body) => j('POST', '/api/provision', body),
  saveInstance: (inst) => j('POST', '/api/instances', inst),
  deleteInstance: (id) => j('DELETE', `/api/instances/${id}`),
  start: (id, body) => j('POST', `/api/instances/${id}/start`, body || {}),
  stop: (id) => j('POST', `/api/instances/${id}/stop`),
  reprovision: (id, body) => j('POST', `/api/instances/${id}/reprovision`, body || {}),
  clearPin: (id) => j('POST', `/api/instances/${id}/pin/clear`),
  status: (id) => j('GET', `/api/instances/${id}/status`),
  logs: (id, tail = 300) => j('GET', `/api/instances/${id}/logs?tail=${tail}`),
  register: (id) => j('POST', `/api/instances/${id}/register`),

  threads: (id) => j('GET', `/api/instances/${id}/messages/threads`),
  messages: (id, peer) => j('GET', `/api/instances/${id}/messages/${encodeURIComponent(peer)}`),
  sendSms: (id, to, body) => j('POST', `/api/instances/${id}/sms/send`, { to, body }),
  // delete messages: { ids:[...] } | { peer } (whole conversation) | { all:true }
  deleteMessages: (id, sel) => j('POST', `/api/instances/${id}/messages/delete`, sel),

  calls: (id) => j('GET', `/api/instances/${id}/calls`),
  // delete call-log entries: { ids:[...] } | { all:true }
  deleteCalls: (id, sel) => j('POST', `/api/instances/${id}/calls/delete`, sel),
  call: (id, to, from_endpoint = 'webrtc') => j('POST', `/api/instances/${id}/call`, { to, from_endpoint }),
  hangup: (id) => j('POST', `/api/instances/${id}/hangup`),
  softphone: (id) => j('GET', `/api/instances/${id}/softphone`),
  sipinfo: (id) => j('GET', `/api/instances/${id}/sipinfo`),
}

export function connectWs(onMsg) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  let ws, alive = true
  const open = () => {
    ws = new WebSocket(`${proto}://${location.host}/ws`)
    ws.onmessage = (e) => { try { onMsg(JSON.parse(e.data)) } catch {} }
    ws.onclose = () => { if (alive) setTimeout(open, 2000) }
    ws.onerror = () => { try { ws.close() } catch {} }
  }
  open()
  return () => { alive = false; try { ws.close() } catch {} }
}
