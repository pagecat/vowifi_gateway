import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import PushInfoModal from './PushInfoModal.jsx'

export default function Settings() {
  const [s, setS] = useState(null)
  const [msg, setMsg] = useState('')
  const [info, setInfo] = useState('')   // '' | 'webhook' | 'telegram' — which help modal is open

  useEffect(() => { api.settings().then(setS).catch(() => {}) }, [])
  if (!s) return <div style={{ color: 'var(--text-dim)' }}>Loading…</div>

  const upd = (patch) => setS((x) => ({ ...x, ...patch }))
  const updTls = (patch) => setS((x) => ({ ...x, tls: { ...x.tls, ...patch } }))
  const updDebug = (patch) => setS((x) => ({ ...x, debug: { ...x.debug, ...patch } }))
  // webhook / telegram helpers: patch the channel object and its nested `events` map.
  const wh = s.webhook || { enabled: false, url: '', events: {} }
  const tg = s.telegram || { enabled: false, bot_token: '', chat_id: '', events: {} }
  const updWh = (patch) => setS((x) => ({ ...x, webhook: { ...wh, ...patch } }))
  const updWhEv = (k, v) => setS((x) => ({ ...x, webhook: { ...wh, events: { ...(wh.events || {}), [k]: v } } }))
  const updTg = (patch) => setS((x) => ({ ...x, telegram: { ...tg, ...patch } }))
  const updTgEv = (k, v) => setS((x) => ({ ...x, telegram: { ...tg, events: { ...(tg.events || {}), [k]: v } } }))

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
        <label style={{ marginTop: 8 }}><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!s.debug?.charon} onChange={(e) => updDebug({ charon: e.target.checked })} />SWu tunnel (IKE) high logging</label>
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

      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>Tunnel</h3>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 10 }}>
          How often the gateway proactively rekeys the IPsec (ESP) security association with the
          carrier's ePDG. IKEv2 does not put a lifetime on the wire, so this is a local policy: the
          SA is refreshed (seamless make-before-break) before it silently ages out and the carrier
          stops accepting traffic. <b>0 disables</b> proactive rekey (the SA is only refreshed if
          the carrier initiates it). Applies after the line is re-provisioned/restarted.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div><label>SA rekey interval (minutes, 0 = off)</label>
            <input type="number" min="0" max="1440" value={s.rekey?.minutes ?? 30}
              onChange={(e) => upd({ rekey: { ...(s.rekey || {}), minutes: +e.target.value } })} /></div>
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h3 style={{ marginTop: 0, marginBottom: 0 }}>Webhook push</h3>
          <button className="btn btn-ghost" style={{ padding: '2px 9px', fontSize: 12, borderRadius: 20 }}
            title="Payload format & notes" onClick={() => setInfo('webhook')}>ⓘ Format</button>
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', margin: '8px 0 12px' }}>
          POST a JSON body to your URL when an incoming SMS or call arrives. Click <b>ⓘ Format</b> for
          the exact payload.
        </div>
        <label><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!wh.enabled}
          onChange={(e) => updWh({ enabled: e.target.checked })} />Enable webhook push</label>
        <div style={{ marginTop: 12, opacity: wh.enabled ? 1 : .5 }}>
          <label>Webhook URL</label>
          <input className="mono" value={wh.url || ''} disabled={!wh.enabled}
            onChange={(e) => updWh({ url: e.target.value })} placeholder="https://example.com/hook" />
          <div style={{ marginTop: 10, fontSize: 13, color: 'var(--text-mute)' }}>Events to push</div>
          <div style={{ display: 'flex', gap: 18, marginTop: 6 }}>
            <label><input type="checkbox" style={{ width: 'auto', marginRight: 7 }} disabled={!wh.enabled}
              checked={wh.events?.incoming_call !== false} onChange={(e) => updWhEv('incoming_call', e.target.checked)} />Incoming call</label>
            <label><input type="checkbox" style={{ width: 'auto', marginRight: 7 }} disabled={!wh.enabled}
              checked={wh.events?.incoming_sms !== false} onChange={(e) => updWhEv('incoming_sms', e.target.checked)} />Incoming SMS</label>
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h3 style={{ marginTop: 0, marginBottom: 0 }}>Telegram push</h3>
          <button className="btn btn-ghost" style={{ padding: '2px 9px', fontSize: 12, borderRadius: 20 }}
            title="Message format & setup" onClick={() => setInfo('telegram')}>ⓘ Format</button>
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', margin: '8px 0 12px' }}>
          Send incoming SMS/calls to a Telegram chat or channel via a bot. Click <b>ⓘ Format</b> for
          setup and the message layout.
        </div>
        <label><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!tg.enabled}
          onChange={(e) => updTg({ enabled: e.target.checked })} />Enable Telegram push</label>
        <div style={{ marginTop: 12, opacity: tg.enabled ? 1 : .5 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div><label>Bot token</label>
              <input className="mono" value={tg.bot_token || ''} disabled={!tg.enabled}
                onChange={(e) => updTg({ bot_token: e.target.value })} placeholder="123456:ABC-DEF..." /></div>
            <div><label>Chat / Channel ID</label>
              <input className="mono" value={tg.chat_id || ''} disabled={!tg.enabled}
                onChange={(e) => updTg({ chat_id: e.target.value })} placeholder="-1001234567890 or 12345678" /></div>
          </div>
          <div style={{ marginTop: 10, fontSize: 13, color: 'var(--text-mute)' }}>Events to push</div>
          <div style={{ display: 'flex', gap: 18, marginTop: 6 }}>
            <label><input type="checkbox" style={{ width: 'auto', marginRight: 7 }} disabled={!tg.enabled}
              checked={tg.events?.incoming_call !== false} onChange={(e) => updTgEv('incoming_call', e.target.checked)} />Incoming call</label>
            <label><input type="checkbox" style={{ width: 'auto', marginRight: 7 }} disabled={!tg.enabled}
              checked={tg.events?.incoming_sms !== false} onChange={(e) => updTgEv('incoming_sms', e.target.checked)} />Incoming SMS</label>
          </div>
        </div>
      </div>

      <div>
        <button className="btn btn-primary" onClick={save}>Save settings</button>
        {msg && <span style={{ marginLeft: 12, color: '#22c55e', fontSize: 13 }}>{msg}</span>}
      </div>
      {info && <PushInfoModal channel={info} onClose={() => setInfo('')} />}
    </div>
  )
}
