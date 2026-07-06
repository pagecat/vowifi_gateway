import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Settings() {
  const [s, setS] = useState(null)
  const [msg, setMsg] = useState('')

  useEffect(() => { api.settings().then(setS).catch(() => {}) }, [])
  if (!s) return <div style={{ color: 'var(--text-dim)' }}>Loading…</div>

  const upd = (patch) => setS((x) => ({ ...x, ...patch }))
  const updTls = (patch) => setS((x) => ({ ...x, tls: { ...x.tls, ...patch } }))
  const updDebug = (patch) => setS((x) => ({ ...x, debug: { ...x.debug, ...patch } }))

  const save = async () => {
    try { await api.saveSettings(s); setMsg('Saved. Restart the control surface for TLS/port changes, and re-provision a line for ring-timeout changes, to take effect.') }
    catch (e) { setMsg('Error: ' + e.message) }
  }

  return (
    <div style={{ maxWidth: 640, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>Control surface (WebUI)</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div><label>Bind address</label><input value={s.bind || ''} onChange={(e) => upd({ bind: e.target.value })} /></div>
          <div><label>HTTPS port</label><input type="number" value={s.http_port || 8443} onChange={(e) => upd({ http_port: +e.target.value })} /></div>
        </div>
        <h4>TLS</h4>
        <label><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!s.tls.self_signed} onChange={(e) => updTls({ self_signed: e.target.checked })} />Use self-signed certificate</label>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 10, opacity: s.tls.self_signed ? .5 : 1 }}>
          <div><label>Domain</label><input value={s.tls.domain || ''} onChange={(e) => updTls({ domain: e.target.value })} placeholder="gw.example.com" /></div>
          <div />
          <div><label>Cert path</label><input className="mono" value={s.tls.cert_path || ''} onChange={(e) => updTls({ cert_path: e.target.value })} placeholder="/path/fullchain.pem" /></div>
          <div><label>Key path</label><input className="mono" value={s.tls.key_path || ''} onChange={(e) => updTls({ key_path: e.target.value })} placeholder="/path/privkey.pem" /></div>
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>Engine / debug defaults</h3>
        <label><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!s.debug?.asterisk} onChange={(e) => updDebug({ asterisk: e.target.checked })} />Asterisk verbose/debug logging</label>
        <label style={{ marginTop: 8 }}><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!s.debug?.charon} onChange={(e) => updDebug({ charon: e.target.checked })} />strongSwan (charon) high logging</label>
        <label style={{ marginTop: 8 }}><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!s.debug?.pcap} onChange={(e) => updDebug({ pcap: e.target.checked })} />Capture ESP/SIP pcap</label>
        <div style={{ marginTop: 14 }}><label>Manager URL (for engine event callbacks; auto if blank)</label>
          <input className="mono" value={s.manager_url || ''} onChange={(e) => upd({ manager_url: e.target.value })} placeholder="auto (e.g. https://gateway-host:8443)" /></div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>Auto-retry</h3>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 10 }}>
          If the VoWiFi tunnel or IMS registration drops while the SIM is still present, the line
          auto-retries. After the retry budget is exhausted it stops and shows the failure reason.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div><label>Max retries</label><input type="number" min="1" value={s.retry?.max ?? 3}
            onChange={(e) => upd({ retry: { ...(s.retry || {}), max: +e.target.value } })} /></div>
          <div><label>Seconds per attempt</label><input type="number" min="5" value={s.retry?.interval ?? 40}
            onChange={(e) => upd({ retry: { ...(s.retry || {}), interval: +e.target.value } })} /></div>
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>Calls</h3>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 10 }}>
          How long an outgoing call rings before the gateway gives up and cancels it. Most
          carriers roll an unanswered call to voicemail by ~30s. A shorter value also reduces
          how many times the callee is re-alerted when they don't answer. Applies to new calls
          after the line is re-provisioned/restarted.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div><label>Ring timeout (seconds)</label><input type="number" min="5" max="180" value={s.ring_timeout ?? 35}
            onChange={(e) => upd({ ring_timeout: +e.target.value })} /></div>
        </div>
      </div>

      <div>
        <button className="btn btn-primary" onClick={save}>Save settings</button>
        {msg && <span style={{ marginLeft: 12, color: '#22c55e', fontSize: 13 }}>{msg}</span>}
      </div>
    </div>
  )
}
