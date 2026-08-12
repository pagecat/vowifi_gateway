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
  const tgc = tg.commands || {}
  const updTgCmd = (patch) => setS((x) => ({ ...x, telegram: { ...tg, commands: { ...tgc, ...patch } } }))
  // Chat ids are edited as free text but stored as a list, so an empty box means "no extra
  // chats" rather than a list holding one empty string.
  const setAllowedChats = (text) => updTgCmd({
    allowed_chats: text.split(',').map((c) => c.trim()).filter(Boolean),
  })

  const save = async () => {
    try {
      const next = await api.saveSettings(s)
      setS(next)
      setMsg('Saved. Restart the control surface for TLS/port changes. Stop → Start (or re-provision) lines for advertise-address, ring-timeout, and other engine settings.')
    }
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
        <h3 style={{ marginTop: 0 }}>SIP / WebRTC advertise address</h3>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 10 }}>
          This address is written into local SIP Contact and SDP so Linphone, MicroSIP,
          and the browser softphone send RTP/RFC4733 DTMF back to this host. Leave it blank
          to auto-detect a LAN NIC; on a LAN + VPN host, pin the reachable LAN IP explicitly.
        </div>
        {s.advertise_address_managed_by_env ? (
          <div style={{
            padding: '10px 12px', borderRadius: 8, marginBottom: 10,
            background: 'var(--bg-elev, rgba(0,0,0,.08))', fontSize: 13,
          }}>
            <div>
              Managed by <code>VOWIFI_ADVERTISE_ADDR</code> — effective{' '}
              <span className="mono">{s.advertise_address_effective || '—'}</span>.
              This page cannot override the environment value.
            </div>
            <div style={{ marginTop: 8, color: 'var(--text-dim)' }}>
              To update the installer-managed value from the repository directory:
            </div>
            <pre className="mono" style={{
              margin: '8px 0 0', padding: '8px 10px', borderRadius: 6,
              overflowX: 'auto', background: 'rgba(0,0,0,.12)', fontSize: 12,
              whiteSpace: 'pre-wrap',
            }}>{`sudo VOWIFI_ADVERTISE_ADDR=${s.advertise_address_detected || s.advertise_address_effective || '192.168.x.x'} ./install.sh reload`}</pre>
          </div>
        ) : (
          <div>
            <label htmlFor="advertise_address">Advertise address (IP or hostname)</label>
            <input
              id="advertise_address"
              className="mono"
              value={s.advertise_address || ''}
              onChange={(e) => upd({ advertise_address: e.target.value })}
              placeholder={s.advertise_address_detected
                ? `auto → ${s.advertise_address_detected}`
                : 'auto (detect LAN IP)'}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-mute)' }}>
              The installer can pin the same value with:
              <pre className="mono" style={{
                margin: '6px 0 0', padding: '8px 10px', borderRadius: 6,
                overflowX: 'auto', background: 'rgba(0,0,0,.12)', fontSize: 12,
                whiteSpace: 'pre-wrap',
              }}>{`sudo VOWIFI_ADVERTISE_ADDR=${s.advertise_address_detected || '192.168.x.x'} ./install.sh reload`}</pre>
            </div>
          </div>
        )}
        <div className="mono" style={{ marginTop: 10, fontSize: 12, color: 'var(--text-mute)' }}>
          Effective: {s.advertise_address_effective || '—'}
          {s.advertise_address_detected
            ? ` · detected LAN: ${s.advertise_address_detected}`
            : ''}
        </div>
        <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-mute)' }}>
          After saving or reloading the installer, Stop → Start each running line so
          Asterisk reloads its Contact and SDP address.
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
          With network auto-recover enabled, a network/DNS freeze will re-provision the line once
          connectivity returns (SIM-auth and other permanent faults still stay stopped).
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div><label>Max retries</label><input type="number" min="1" value={s.retry?.max ?? 3}
            onChange={(e) => upd({ retry: { ...(s.retry || {}), max: +e.target.value } })} /></div>
          <div><label>Seconds per attempt</label><input type="number" min="5" value={s.retry?.interval ?? 40}
            onChange={(e) => upd({ retry: { ...(s.retry || {}), interval: +e.target.value } })} /></div>
        </div>
        <label style={{ marginTop: 12, display: 'block' }}>
          <input type="checkbox" style={{ width: 'auto', marginRight: 8 }}
            checked={s.retry?.auto_recover !== false}
            onChange={(e) => upd({ retry: { ...(s.retry || {}), auto_recover: e.target.checked } })} />
          Auto re-provision when network recovers
        </label>
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
            {/* Write-only: the server sends back a blank token and treats a blank one on save
                as "unchanged", so the credential never round-trips through the browser. */}
            <div><label>Bot token{tg.bot_token_set ? ' (saved)' : ''}</label>
              <input className="mono" type="password" value={tg.bot_token || ''} disabled={!tg.enabled}
                onChange={(e) => updTg({ bot_token: e.target.value })}
                placeholder={tg.bot_token_set ? 'leave blank to keep the saved token' : '123456:ABC-DEF...'} /></div>
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

          <h4 style={{ marginBottom: 4 }}>Commands (two-way)</h4>
          <div style={{ fontSize: 12.5, color: 'var(--text-mute)', marginBottom: 8, lineHeight: 1.5 }}>
            Lets the same bot take orders, not just send notices. Anyone who can post in an
            allowed chat can act on this gateway, so the riskier groups are separate switches.
          </div>
          <label><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} disabled={!tg.enabled}
            checked={!!tgc.enabled} onChange={(e) => updTgCmd({ enabled: e.target.checked })} />
            Accept commands (SMS, status)</label>
          <div style={{ marginTop: 10, opacity: tg.enabled && tgc.enabled ? 1 : .5 }}>
            <label>Chats allowed to command (comma separated)</label>
            <input className="mono" disabled={!tg.enabled || !tgc.enabled}
              value={(tgc.allowed_chats || []).join(', ')}
              onChange={(e) => setAllowedChats(e.target.value)}
              placeholder="empty = only the Chat / Channel ID above" />
            <label style={{ display: 'block', marginTop: 10 }}>
              <input type="checkbox" style={{ width: 'auto', marginRight: 8 }}
                disabled={!tg.enabled || !tgc.enabled} checked={!!tgc.allow_management}
                onChange={(e) => updTgCmd({ allow_management: e.target.checked })} />
              Also allow line control (start / stop / re-provision / PIN)
            </label>
            <div style={{ fontSize: 11.5, color: 'var(--text-mute)', marginTop: 6, lineHeight: 1.5 }}>
              A PIN sent in chat is deleted from the conversation as soon as it is read, but it
              still travels through Telegram — prefer entering it here in the WebUI.
            </div>
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
