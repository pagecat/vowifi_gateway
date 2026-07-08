import React, { useState, useEffect } from 'react'
import { api } from '../api.js'

const PIN_RE = /^\d{4,8}$/
const PORT_RE = /^\d{1,5}$/

// Final provisioning confirmation for a detected SIM. The PIN was already entered/verified
// on the dashboard card (passed in as `pin`); we collect IMEI + device identity + SIP options
// and confirm the SMSC. SMSC is auto (read from the SIM's EF_SMSP) or manual — no carrier preset.
export default function ProvisionModal({ card, pin: pinProp, onClose, onDone }) {
  const simSmsc = card.smsc || ''
  const [f, setF] = useState({
    name: '', imei: '', imeisv: '', webrtc: true, transport: 'udp', listen_addr: '0.0.0.0',
    user_agent: 'iOS/26.6 iPhone',
    apn: 'ims',                              // VoWiFi APN (default IMS APN)
    idrMode: 'apn',                          // ePDG IDr encoding: 'apn' (bare, default) | 'fqdn'
    cpMode: 'auto',                          // IMS PDN address family: 'auto' (default) | 'dual' | 'v6' | 'v4'
    smscMode: simSmsc ? 'auto' : 'manual',   // force manual if the SIM didn't yield one
    smscManual: '',
    portMode: 'auto',                        // 'auto' (conflict-checked) | 'manual'
    sipPort: '',                             // manual SIP UDP port
    pin: pinProp || '',
  })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [autoPort, setAutoPort] = useState(null)   // {auto_sip_udp, auto_sip_tls, min, max}
  const upd = (p) => setF((x) => ({ ...x, ...p }))

  // Fetch the port the automatic allocator would pick right now (also used as the manual
  // field's placeholder/default). Best-effort; the modal still works if it fails.
  useEffect(() => {
    let alive = true
    api.portsSuggest().then((p) => { if (alive) setAutoPort(p) }).catch(() => {})
    return () => { alive = false }
  }, [])

  const needPin = card.pin_enabled !== false     // PIN-enabled (or unknown) => provisioning needs it
  const pinOk = !needPin || PIN_RE.test(f.pin)
  const manualOk = f.smscMode !== 'manual' || f.smscManual.trim().length > 0
  const portMin = autoPort?.min ?? 1024, portMax = autoPort?.max ?? 65535
  const portNum = parseInt(f.sipPort, 10)
  const portOk = f.portMode !== 'manual' ||
    (PORT_RE.test(f.sipPort) && portNum >= portMin && portNum <= portMax)

  const submit = async () => {
    if (!f.imei) return setErr('IMEI is required.')
    if (needPin && !PIN_RE.test(f.pin)) return setErr('A valid SIM PIN (4–8 digits) is required.')
    if (f.smscMode === 'manual' && !f.smscManual.trim()) return setErr('Enter the SMS centre number (or switch to Auto).')
    if (f.portMode === 'manual' && !portOk) return setErr(`Enter a valid SIP port (${portMin}–${portMax}).`)
    setBusy(true); setErr('')
    try {
      const body = {
        reader_index: card.index, reader: card.name,   // name re-resolves the index server-side
        pin: f.pin, imei: f.imei, imeisv: f.imeisv.trim() || undefined, name: f.name,
        apn: f.apn.trim() || 'ims', idr_mode: f.idrMode, cp_mode: f.cpMode,
        smsc: f.smscMode === 'manual' ? f.smscManual.trim() : undefined,   // undefined => backend reads SIM
        webrtc: f.webrtc,
        port_mode: f.portMode,
        sip_port: f.portMode === 'manual' ? portNum : undefined,
        sip: { listen_addr: f.listen_addr, transport: f.transport, external: [],
               user_agent: f.user_agent, webrtc: { enable: f.webrtc } },
      }
      await api.provision(body)
      onDone && onDone()
      onClose()
    } catch (e) {
      // Backend signals an unreadable SIM SMSC with 422 — switch the user to manual entry.
      if (e.status === 422 && /smsc/i.test(e.message)) {
        upd({ smscMode: 'manual' })
        setErr('Could not read the SMS centre from the SIM — please enter it manually below.')
      } else if (e.status === 422 && /port/i.test(e.message)) {
        // Port conflict / invalid — surface the server's precise reason and stay on manual.
        setErr(e.message.replace(/^port_error:\s*/, 'Port error: '))
      } else setErr(e.message)
    }
    setBusy(false)
  }

  const radio = (mode, label) => (
    <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: simSmsc || mode === 'manual' ? 'pointer' : 'not-allowed', opacity: (!simSmsc && mode === 'auto') ? .5 : 1 }}>
      <input type="radio" name="smscMode" checked={f.smscMode === mode} disabled={!simSmsc && mode === 'auto'}
        onChange={() => upd({ smscMode: mode })} style={{ width: 'auto' }} />
      {label}
    </label>
  )

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000a', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50 }}
      onClick={onClose}>
      <div className="card" style={{ padding: 24, width: 460, maxWidth: '92vw', maxHeight: '92vh', overflow: 'auto' }} onClick={(e) => e.stopPropagation()}>
        <h2 style={{ marginTop: 0 }}>Provision SIM</h2>
        <div className="mono" style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 16, lineHeight: 1.6 }}>
          Reader {card.index}: {card.name}<br />
          ICCID: {card.iccid || '—'}<br />
          IMSI: {card.imsi || '—'}
        </div>
        <div style={{ display: 'grid', gap: 12 }}>
          <div><label>Name</label><input value={f.name} onChange={(e) => upd({ name: e.target.value })} placeholder="auto (MCC-MNC)" /></div>
          {needPin && (
            <div><label>SIM PIN (CHV1) — {pinProp ? 'verified ✓, re-confirm if needed' : 'required'}</label>
              <input type="password" inputMode="numeric" className="mono" value={f.pin} maxLength={8}
                onChange={(e) => upd({ pin: e.target.value.replace(/[^0-9]/g, '') })} placeholder="4–8 digits" /></div>
          )}
          <div><label>IMEI — required</label><input className="mono" value={f.imei} onChange={(e) => upd({ imei: e.target.value })} placeholder="35123456-789012-3" /></div>
          <div><label>IMEISV — optional</label><input className="mono" value={f.imeisv} onChange={(e) => upd({ imeisv: e.target.value.replace(/[^0-9]/g, '') })} maxLength={16} placeholder="auto from IMEI + random SVN" />
            <div style={{ fontSize: 11, opacity: 0.6, marginTop: 2 }}>16 digits, for the carrier's DEVICE_IDENTITY request. Leave blank to auto-generate (14-digit IMEI + 2-digit software version).</div>
          </div>

          <div>
            <label>SMS centre (SMSC)</label>
            <div style={{ display: 'flex', gap: 16, margin: '6px 0' }}>
              {radio('auto', 'Auto (from SIM)')}
              {radio('manual', 'Manual')}
            </div>
            {f.smscMode === 'auto'
              ? <div className="mono" style={{ fontSize: 12, color: simSmsc ? 'var(--text-soft)' : '#eab308' }}>
                  {simSmsc ? `${simSmsc} — read from SIM` : '⚠ SIM did not provide an SMSC; choose Manual'}
                </div>
              : <input className="mono" value={f.smscManual} onChange={(e) => upd({ smscManual: e.target.value })} placeholder="+1..." />}
          </div>

          <div><label>Device User-Agent (how the line identifies to the carrier)</label><input className="mono" value={f.user_agent} onChange={(e) => upd({ user_agent: e.target.value })} placeholder="iOS/26.6 iPhone" /></div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div><label>APN</label>
              <input className="mono" value={f.apn} onChange={(e) => upd({ apn: e.target.value })} placeholder="ims" />
              <div style={{ fontSize: 11, opacity: 0.6, marginTop: 2 }}>VoWiFi access point. Default <code>ims</code>.</div>
            </div>
            <div><label>ePDG identity (IDr)</label>
              <select value={f.idrMode} onChange={(e) => upd({ idrMode: e.target.value })}>
                <option value="apn">Bare APN (default)</option>
                <option value="fqdn">APN-FQDN</option>
              </select>
              <div style={{ fontSize: 11, opacity: 0.6, marginTop: 2 }}>How the APN is sent to the ePDG. Most carriers expect the bare APN; a few stricter ones require the full APN-FQDN.</div>
            </div>
            <div><label>IMS address family (CP)</label>
              <select value={f.cpMode} onChange={(e) => upd({ cpMode: e.target.value })}>
                <option value="auto">Auto-detect (recommended)</option>
                <option value="dual">Dual-stack (IPv4+IPv6)</option>
                <option value="v6">IPv6 only</option>
                <option value="v4">IPv4 only</option>
              </select>
              <div style={{ fontSize: 11, opacity: 0.6, marginTop: 2 }}>Address family of the IMS PDN. <b>Auto</b> discovers it for you (matches known carriers, else probes) — leave this unless you know the carrier needs a specific family. Telus/EE are IPv6; Vodafone UK is IPv4.</div>
            </div>
          </div>

          <div>
            <label>Local SIP port mapping</label>
            <div style={{ display: 'flex', gap: 16, margin: '6px 0' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <input type="radio" name="portMode" checked={f.portMode === 'auto'}
                  onChange={() => { upd({ portMode: 'auto' }); setErr('') }} style={{ width: 'auto' }} />
                Automatic
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <input type="radio" name="portMode" checked={f.portMode === 'manual'}
                  onChange={() => { upd({ portMode: 'manual', sipPort: f.sipPort || String(autoPort?.auto_sip_udp || '') }); setErr('') }} style={{ width: 'auto' }} />
                Manual
              </label>
            </div>
            {f.portMode === 'auto'
              ? <div className="mono" style={{ fontSize: 12, color: 'var(--text-soft)' }}>
                  {autoPort ? `Will use host port ${autoPort.auto_sip_udp} (UDP/TCP) · ${autoPort.auto_sip_tls} (TLS), auto-advanced past any in use.`
                            : 'Picks the next free host port automatically.'}
                </div>
              : <>
                  <input type="number" className="mono" value={f.sipPort} min={portMin} max={portMax}
                    onChange={(e) => { upd({ sipPort: e.target.value.replace(/[^0-9]/g, '') }); setErr('') }}
                    placeholder={String(autoPort?.auto_sip_udp || '5060')} />
                  <div style={{ fontSize: 11.5, color: f.sipPort && !portOk ? '#ef4444' : 'var(--text-mute)', marginTop: 4 }}>
                    {f.sipPort && !portOk
                      ? `Enter a valid port (${portMin}–${portMax}).`
                      : `SIP UDP port on the host (${portMin}–${portMax}). TLS uses this +1; WebRTC/RTP derive from it. Checked for conflicts on submit.`}
                  </div>
                </>}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div><label>SIP listen</label>
              <select value={f.listen_addr} onChange={(e) => upd({ listen_addr: e.target.value })}>
                <option value="0.0.0.0">0.0.0.0 (all)</option><option value="127.0.0.1">127.0.0.1</option>
              </select></div>
            <div><label>SIP transport</label>
              <select value={f.transport} onChange={(e) => upd({ transport: e.target.value })}>
                <option value="udp">UDP</option><option value="tcp">TCP</option><option value="tls">TLS</option>
              </select></div>
          </div>
          <label><input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={f.webrtc} onChange={(e) => upd({ webrtc: e.target.checked })} />Enable browser softphone (WebRTC)</label>
        </div>
        {err && <div style={{ color: '#ef4444', fontSize: 13, marginTop: 12 }}>{err}</div>}
        <div style={{ display: 'flex', gap: 8, marginTop: 20, justifyContent: 'flex-end' }}>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={busy || !f.imei || !pinOk || !manualOk || !portOk}>
            {busy ? 'Provisioning…' : 'Provision & start'}
          </button>
        </div>
      </div>
    </div>
  )
}
