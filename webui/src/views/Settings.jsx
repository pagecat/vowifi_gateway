import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import PushInfoModal from './PushInfoModal.jsx'

function applyUbStart(r, setUb, setUbInfo, setUbMsg, setUbCode, setUbPassword) {
  if (r.config) setUb(r.config)
  setUbInfo(r)
  const notes = (r.notes || []).filter(Boolean).join(' ')
  if (r.phase === 'building') {
    setUbMsg('Building the userbot image (first time compiles PJSIP — this can take a while).' + (notes ? '\n' + notes : ''))
    return
  }
  if (r.phase === 'login') {
    setUbCode('')
    setUbMsg('Telegram sent a login code to the account phone. Enter it below, then press Start.' + (notes ? '\n' + notes : ''))
    return
  }
  if (r.phase === 'password') {
    setUbPassword('')
    setUbMsg('This account has two-factor authentication. Enter the cloud password, then press Start.')
    return
  }
  if (r.ok || r.phase === 'running') {
    setUbCode('')
    setUbPassword('')
    setUbMsg('Started.' + (notes ? ' ' + notes : ''))
    return
  }
  setUbMsg(notes || 'Done.')
}

export default function Settings({ instances = [] }) {
  const [s, setS] = useState(null)
  const [msg, setMsg] = useState('')
  const [info, setInfo] = useState('')   // '' | 'webhook' | 'telegram' — which help modal is open
  // The call sidecar lives in its own container and its own config file, so it
  // loads and saves through a separate endpoint from everything else here.
  const [ub, setUb] = useState(null)        // the editable form
  const [ubInfo, setUbInfo] = useState({})  // status + container + signed_in + build + login
  const [ubMsg, setUbMsg] = useState('')
  const [ubBusy, setUbBusy] = useState(false)
  const [ubLogs, setUbLogs] = useState(null)
  const [ubCode, setUbCode] = useState('')
  const [ubPassword, setUbPassword] = useState('')
  const ubRef = React.useRef(null)
  const waitBuild = React.useRef(false)

  useEffect(() => { api.settings().then(setS).catch(() => {}) }, [])
  const building = !!ubInfo.build?.running
  useEffect(() => {
    let alive = true
    const pull = () => api.userbot().then((r) => {
      if (!alive) return
      setUb((cur) => cur || r.config)
      setUbInfo(r)
      if (waitBuild.current && r.build && !r.build.running) {
        waitBuild.current = false
        if (r.build.ok) {
          setUbMsg('Image ready. Continuing…')
          api.userbotStart(ubRef.current || r.config).then((next) => {
            if (!alive) return
            applyUbStart(next, setUb, setUbInfo, setUbMsg, setUbCode, setUbPassword)
          }).catch((e) => { if (alive) setUbMsg('Error: ' + e.message) })
        } else {
          setUbMsg('Error: image build failed — open the log below')
        }
      }
    }).catch(() => {})
    pull()
    const timer = setInterval(pull, building ? 2000 : 10000)
    return () => { alive = false; clearInterval(timer) }
  }, [building])
  useEffect(() => { ubRef.current = ub }, [ub])
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

  // Docker's view, which is not the same question as the sidecar's heartbeat: the
  // container can be up while the process inside it is failing to sign in.
  const ubBox = ubInfo.container || {}
  const ubRunning = ubBox.state === 'running'
  const ubLogin = ubInfo.login || {}
  const ubNeedLogin = !ubInfo.signed_in || ubLogin.pending || ubLogin.need_password
    || !!ubLogin.phone
  const updUb = (patch) => setUb((x) => {
    const next = { ...x, ...patch }
    ubRef.current = next
    return next
  })
  const ubCards = (ub && Array.isArray(ub.cards) ? ub.cards : [])
  const updCard = (index, patch) => updUb({
    cards: ubCards.map((c, i) => (i === index ? { ...c, ...patch } : c)),
  })
  // Every account that may drive the sidecar, primary first. Also the choices
  // for "who answers this card".
  const ubOwners = [Number(ub && ub.owner_id) || 0]
    .concat(String((ub && ub.owner_ids) || '').split(',').map((x) => Number(x.trim()) || 0))
    .filter((x, i, all) => x && all.indexOf(x) === i)
  const dupCardUser = ubCards.find((c, i) => c.sip_user
    && ubCards.findIndex((o) => o.sip_user === c.sip_user) !== i)
  const refreshUb = () => api.userbot().then(setUbInfo).catch(() => {})
  const saveUb = async () => {
    try {
      const r = await api.saveUserbot(ub)
      setUb(r.config)
      setUbMsg(r.restart_required
        ? 'Saved. It is read at startup, so hit Restart to apply it.'
        : 'Saved.')
      refreshUb()
    }
    catch (e) { setUbMsg('Error: ' + e.message) }
  }
  const ubAct = async (call, verb) => {
    setUbBusy(true)
    setUbMsg(`${verb}…`)
    try {
      const r = await call()
      if (r && r.phase === 'building') waitBuild.current = true
      applyUbStart(r, setUb, setUbInfo, setUbMsg, setUbCode, setUbPassword)
      if (r && r.config) ubRef.current = r.config
      setUbLogs(null)
    }
    catch (e) { setUbMsg('Error: ' + e.message) }
    finally {
      setUbBusy(false)
      refreshUb()
    }
  }
  const startUb = () => ubAct(
    () => api.userbotStart({
      ...(ub || {}),
      login_code: ubCode,
      login_password: ubPassword,
    }),
    ubRunning ? 'Restarting' : (ubNeedLogin ? 'Signing in' : 'Starting'),
  )
  const showUbLogs = async () => {
    if (ubLogs !== null) { setUbLogs(null); return }
    try { setUbLogs((await api.userbotLogs()).logs || '(the container has no log yet)') }
    catch (e) { setUbLogs('Could not read the log: ' + e.message) }
  }

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
            <label style={{ display: 'block', marginTop: 8 }}>
              <input type="checkbox" style={{ width: 'auto', marginRight: 8 }}
                disabled={!tg.enabled || !tgc.enabled} checked={!!tgc.allow_esim}
                onChange={(e) => updTgCmd({ allow_esim: e.target.checked })} />
              Also allow eSIM management (switch, download, delete profiles)
            </label>
            <div style={{ fontSize: 11.5, color: 'var(--text-mute)', marginTop: 6, lineHeight: 1.5 }}>
              Deleting a profile cannot be undone and a downloaded one usually cannot be
              fetched again, so that command asks you to type part of the ICCID back.
            </div>
            <div style={{ fontSize: 11.5, color: 'var(--text-mute)', marginTop: 6, lineHeight: 1.5 }}>
              A PIN sent in chat is deleted from the conversation as soon as it is read, but it
              still travels through Telegram — prefer entering it here in the WebUI.
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <h3 style={{ marginTop: 0, marginBottom: 0 }}>Telegram calls (userbot)</h3>
          <UserbotPill info={ubInfo} />
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-dim)', margin: '8px 0 12px', lineHeight: 1.55 }}>
          Bridges Telegram voice calls to this gateway's SIMs. It needs a <b>second Telegram
          account</b> (a bot token cannot place calls). Fill the fields and press Start — the
          image is built if missing, each card's SIP account is created if missing, and the
          login code Telegram sends is entered here.
        </div>
        {!ub ? <div style={{ color: 'var(--text-dim)', fontSize: 13 }}>Loading…</div> : <>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 10 }}>
            <div><label>API ID</label>
              <input className="mono" type="number" value={ub.api_id || ''}
                onChange={(e) => updUb({ api_id: e.target.value })} placeholder="from my.telegram.org" /></div>
            {/* Same write-only rule as the bot token: this credential owns a whole account. */}
            <div><label>API hash{ub.api_hash_set ? ' (saved)' : ''}</label>
              <input className="mono" type="password" value={ub.api_hash || ''}
                onChange={(e) => updUb({ api_hash: e.target.value })}
                placeholder={ub.api_hash_set ? 'leave blank to keep' : 'from my.telegram.org'} /></div>
            <div><label>Account phone number</label>
              <input className="mono" value={ub.phone || ''}
                onChange={(e) => updUb({ phone: e.target.value })} placeholder="+8613800138000" /></div>
            <div><label>Your Telegram user ID</label>
              <input className="mono" type="number" value={ub.owner_id || ''}
                onChange={(e) => updUb({ owner_id: e.target.value })} placeholder="ask @userinfobot" /></div>
          </div>
          <div style={{ marginTop: 10 }}>
            <label>Other Telegram user IDs allowed to use it (comma separated)</label>
            <input className="mono"
              value={Array.isArray(ub.owner_ids) ? ub.owner_ids.join(', ') : (ub.owner_ids || '')}
              onChange={(e) => updUb({ owner_ids: e.target.value })}
              placeholder="empty = only you" />
          </div>
          <div style={{ fontSize: 11.5, color: 'var(--text-mute)', marginTop: 6, lineHeight: 1.5 }}>
            Everyone listed may dial on any card, and a call from any of them is answered — the
            account would otherwise accept calls from strangers. Only one call runs at a time.
          </div>

          <h4 style={{ marginBottom: 4 }}>SIM cards</h4>
          <div style={{ fontSize: 11.5, color: 'var(--text-mute)', marginBottom: 8, lineHeight: 1.5 }}>
            One row per SIM. Start creates each SIP account on its line if it is missing, and the
            sidecar reads the password back from the gateway. Usernames must differ between lines:
            the sidecar registers them all from one SIP stack, where two identical names make an
            incoming call ambiguous.
          </div>
          {ubCards.map((card, i) => (
            // Wrapping flex, not a fixed grid: an inline grid template cannot be
            // undone by the narrow-screen media query, and these cells have to
            // stack on a phone. minWidth 0 is what lets them share the row
            // evenly — an <input> defaults to size=20, and a flex item may not
            // shrink below its intrinsic width without it, so the username box
            // would sit wider than the selects beside it.
            <div key={i} style={{
              display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 8, alignItems: 'end',
            }}>
              <div style={{ flex: '1 1 150px', minWidth: 0 }}><label>Line</label>
                <select className="mono" value={card.line || ''}
                  onChange={(e) => updCard(i, { line: e.target.value })}>
                  <option value="">first configured line</option>
                  {(instances || []).map((x) => (
                    <option key={x.id} value={String(x.id)}>
                      {`line ${x.id}`
                        + (x.msisdn ? ` · ${x.msisdn}` : '')
                        + (x.iccid ? ` · …${String(x.iccid).slice(-4)}` : '')}
                    </option>
                  ))}
                </select></div>
              <div style={{ flex: '1 1 150px', minWidth: 0 }}><label>SIP username</label>
                <input className="mono" value={card.sip_user || ''}
                  onChange={(e) => updCard(i, { sip_user: e.target.value })}
                  placeholder={`tgbridge${card.line || ''}`} /></div>
              <div style={{ flex: '1 1 150px', minWidth: 0 }}><label>Answered by</label>
                <select className="mono" value={String(card.answer_owner || 0)}
                  onChange={(e) => updCard(i, { answer_owner: Number(e.target.value) })}>
                  <option value="0">{`you (${ub.owner_id || 'primary'})`}</option>
                  {ubOwners.slice(1).map((o) => (
                    <option key={o} value={String(o)}>{o}</option>
                  ))}
                </select></div>
              <button className="btn btn-ghost" type="button" style={{ flex: '0 0 auto' }}
                onClick={() => updUb({ cards: ubCards.filter((_, j) => j !== i) })}>Remove</button>
            </div>
          ))}
          <button className="btn btn-ghost" type="button"
            onClick={() => updUb({
              cards: [...ubCards, { line: '', sip_user: '', answer_owner: 0 }],
            })}>Add card</button>
          {dupCardUser &&
            <div style={{ fontSize: 11.5, color: '#f59e0b', marginTop: 6 }}>
              Two cards both use <code>{dupCardUser.sip_user}</code>. Give each line its own name.
            </div>}
          {!instances.length &&
            <div style={{ fontSize: 11.5, color: '#f59e0b', marginTop: 6 }}>
              Add a SIM under SIM Config first — Start needs a line to attach the SIP account to.
            </div>}
          <div style={{ marginTop: 10 }}>
            <label>Numbers it may dial (comma separated)</label>
            <input className="mono"
              value={Array.isArray(ub.dial_allowlist) ? ub.dial_allowlist.join(', ') : (ub.dial_allowlist || '')}
              onChange={(e) => updUb({ dial_allowlist: e.target.value })}
              placeholder="empty = any number" />
          </div>

          {ubNeedLogin &&
            <div style={{ marginTop: 14, display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 10 }}>
              <div>
                <label>Telegram login code</label>
                <input className="mono" value={ubCode} autoComplete="one-time-code"
                  onChange={(e) => setUbCode(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') startUb() }}
                  placeholder={ubLogin.pending ? 'sent to the account phone' : 'press Start to send'} />
              </div>
              {ubLogin.need_password &&
                <div>
                  <label>Cloud password (2FA)</label>
                  <input className="mono" type="password" value={ubPassword}
                    onChange={(e) => setUbPassword(e.target.value)} placeholder="Telegram two-step password" />
                </div>}
            </div>}

          <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn" onClick={saveUb} disabled={ubBusy}>Save</button>
            <button className="btn" disabled={ubBusy || building} onClick={startUb}>
              {building ? 'Building…' : ubRunning ? 'Restart' : (ubNeedLogin ? 'Confirm & start' : 'Start')}
            </button>
            {ubBox.exists &&
              <button className="btn btn-ghost" disabled={ubBusy}
                onClick={() => ubAct(api.userbotStop, 'Stopping')}>Stop</button>}
            {ubLogin.pending &&
              <button className="btn btn-ghost" disabled={ubBusy}
                onClick={async () => {
                  setUbBusy(true)
                  try {
                    await api.userbotResendCode()
                    setUbMsg('A new login code was sent.')
                    refreshUb()
                  } catch (e) { setUbMsg('Error: ' + e.message) }
                  finally { setUbBusy(false) }
                }}>Resend code</button>}
            <button className="btn btn-ghost" onClick={showUbLogs}>
              {ubLogs === null ? 'Log' : 'Hide log'}
            </button>
          </div>
          {ubMsg && <div style={{
            marginTop: 8, fontSize: 12.5, whiteSpace: 'pre-wrap', lineHeight: 1.6,
            color: ubMsg.startsWith('Error') ? '#ef4444' : '#22c55e',
          }}>{ubMsg}</div>}
          {(building || (ubInfo.build && ubInfo.build.log && !ubInfo.image_present) || ubLogs !== null) &&
            <pre className="mono" style={{
              marginTop: 10, maxHeight: 260, overflow: 'auto', fontSize: 11.5, lineHeight: 1.5,
              background: 'var(--bg-deep, #0b0f16)', padding: 10, borderRadius: 6,
              whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            }}>{(building || (ubInfo.build && ubInfo.build.log && !ubInfo.image_present))
              ? (ubInfo.build?.log || 'starting build…')
              : ubLogs}</pre>}
          <div style={{ fontSize: 11.5, color: 'var(--text-mute)', marginTop: 10, lineHeight: 1.6 }}>
            Restart recreates the container, so it also applies whatever you just saved.
            First image build compiles PJSIP and can take a long time on a Pi.
          </div>
        </>}
      </div>

      <div>
        <button className="btn btn-primary" onClick={save}>Save settings</button>
        {msg && <span style={{ marginLeft: 12, color: '#22c55e', fontSize: 13 }}>{msg}</span>}
      </div>
      {info && <PushInfoModal channel={info} onClose={() => setInfo('')} />}
    </div>
  )
}

/** Two sources, deliberately kept apart. Docker says whether the container is up;
 *  the heartbeat says whether the process inside it is actually working. A container
 *  that is running while the heartbeat is stale is the interesting case — it is what
 *  a crash loop or a failed sign-in looks like — so it gets its own wording. */
function UserbotPill({ info }) {
  const st = info.status || {}
  const box = info.container || {}
  const pill = (text, colour) => (
    <span style={{
      fontSize: 11.5, padding: '2px 9px', borderRadius: 20, whiteSpace: 'nowrap',
      border: `1px solid ${colour}55`, color: colour, background: `${colour}18`,
    }}>{text}</span>
  )
  const note = (text, colour = 'var(--text-mute)') =>
    <span style={{ fontSize: 11.5, color: colour }}>{text}</span>
  const Row = ({ children }) =>
    <span style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>{children}</span>

  if (info.build?.running) return <Row>{pill('Building image', '#f59e0b')}</Row>
  if (!box.exists && info.image_present === false) {
    return <Row>{pill('Image not built', '#94a3b8')}{note('press Start')}</Row>
  }
  if (!box.exists) return <Row>{pill('Not created', '#94a3b8')}{note('press Start')}</Row>
  if (box.state !== 'running') return <Row>{pill(box.state || 'stopped', '#94a3b8')}</Row>
  if (!st.running) {
    return <Row>
      {pill('Container up, not responding', '#ef4444')}
      {note(st.last_error || 'it is probably failing at startup — check the log', '#ef4444')}
    </Row>
  }
  // With more than one card, "SIP down" alone hides which one is missing.
  const cards = Array.isArray(st.cards) ? st.cards : []
  const up = cards.filter((c) => c.registered).length
  const sipLabel = cards.length > 1
    ? `SIP ${up}/${cards.length} registered`
    : (st.sip_registered ? 'SIP registered' : 'SIP down')
  return <Row>
    {st.in_call ? pill('In a call', '#f59e0b') : pill('Running', '#22c55e')}
    {pill(st.telegram_connected ? 'Telegram up' : 'Telegram down',
      st.telegram_connected ? '#22c55e' : '#ef4444')}
    {pill(sipLabel, st.sip_registered ? '#22c55e' : '#ef4444')}
    {cards.filter((c) => !c.registered).map((c) =>
      note(`line ${c.line} (${c.sip_user}) is not registered`, '#ef4444'))}
    {st.last_error ? note(st.last_error, '#ef4444') : null}
  </Row>
}
