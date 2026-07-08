import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

// Connection parameters for a STANDARD SIP client (not the browser WebRTC softphone).
// Maps 1:1 to the fields a generic SIP softphone asks for:
//   Username / Login  -> the external account's username
//   Domain            -> gateway host:port (the port matters — see the Domain hint)
//   Password          -> the external account's password
//   Dial Plan         -> pass numbers straight through (E.164) or map +->00
// The gateway exposes one SIP endpoint per external account configured on the line
// (SIM Config → External SIP accounts). If none exist we tell the user to add one.
export default function SipInfoModal({ instance, onClose, setView, setSelected }) {
  const [info, setInfo] = useState(null)
  const [err, setErr] = useState('')
  const [copied, setCopied] = useState('')

  useEffect(() => {
    api.sipinfo(instance.id).then(setInfo).catch((e) => setErr(e.message))
  }, [instance.id])

  const copy = async (label, value) => {
    try { await navigator.clipboard.writeText(value); setCopied(label); setTimeout(() => setCopied(''), 1500) } catch {}
  }

  const Field = ({ label, value, hint, mono = true }) => (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 12, color: 'var(--text-mute)', marginBottom: 3 }}>{label}</div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <code style={{ flex: 1, background: 'var(--sidebar)', border: '1px solid var(--border)', borderRadius: 8,
          padding: '7px 10px', fontSize: 13, fontFamily: mono ? 'monospace' : 'inherit', overflowX: 'auto', whiteSpace: 'nowrap' }}>
          {value || <span style={{ color: 'var(--text-faint)' }}>—</span>}
        </code>
        {value != null && value !== '' &&
          <button className="btn btn-ghost" style={{ padding: '5px 10px', fontSize: 12 }} onClick={() => copy(label, String(value))}>
            {copied === label ? '✓' : 'Copy'}
          </button>}
      </div>
      {hint && <div style={{ fontSize: 11.5, color: 'var(--text-faint)', marginTop: 4, lineHeight: 1.5 }}>{hint}</div>}
    </div>
  )

  const acct = info?.accounts?.[0]

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000a', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50 }}
      onClick={onClose}>
      <div className="card" style={{ padding: 24, width: 520, maxWidth: '92vw', maxHeight: '92vh', overflow: 'auto' }} onClick={(e) => e.stopPropagation()}>
        <h2 style={{ marginTop: 0 }}>SIP client connection info</h2>
        <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginBottom: 16, lineHeight: 1.6 }}>
          Register a standard SIP softphone to this line ({instance.name || instance.imsi}). Incoming
          calls/SMS ring your SIP client, and numbers you dial go out over VoWiFi.
        </div>

        {err && <div style={{ color: '#ef4444', fontSize: 13 }}>{err}</div>}
        {!info && !err && <div style={{ color: 'var(--text-mute)' }}>Loading…</div>}

        {info && (
          <>
            {!info.running && (
              <div style={{ marginBottom: 14, padding: '8px 11px', borderRadius: 8, fontSize: 12.5,
                background: 'rgba(234,179,8,.12)', border: '1px solid rgba(234,179,8,.4)', color: 'var(--text-soft)' }}>
                This line isn't running — start it before registering a SIP client.
              </div>
            )}

            {!acct ? (
              <div style={{ padding: '14px 16px', borderRadius: 10, background: 'rgba(234,179,8,.12)',
                border: '1px solid rgba(234,179,8,.4)', fontSize: 13, lineHeight: 1.6 }}>
                <b>No SIP account configured for this line yet.</b><br />
                A SIP client needs a username + password. Add one under{' '}
                <a style={{ cursor: 'pointer', textDecoration: 'underline' }}
                  onClick={() => { setSelected && setSelected(instance.id); setView && setView('sims'); onClose() }}>
                  SIM Config → External SIP accounts
                </a>, save, then reopen this dialog.
              </div>
            ) : (
              <>
                <Field label="Domain" value={`${info.domain}:${info.port}`}
                  hint="Your account domain — this gateway's address. Include the port (:port) — each line uses a different port, and a client that omits it sends calls to the default 5060 and reaches the wrong line (registration may still work, but dialing fails)." />
                <Field label="Username" value={acct.username}
                  hint="Your account username." />
                <Field label="Login" value={acct.username}
                  hint="Username for authentication. If empty, Username is used — they're the same here." />
                <Field label="Password" value={acct.password}
                  hint="Your account password." />
                <div style={{ display: 'flex', gap: 12 }}>
                  <div style={{ flex: 1 }}><Field label="Port" value={info.port}
                    hint="This line's port. Already included in Domain above; set it here too if your client has a separate port field." /></div>
                  <div style={{ flex: 1 }}><Field label="Transport" value={String(info.transport).toUpperCase()} /></div>
                </div>
                <Field label="Server / Proxy (Domain:Port)" value={`${info.domain}:${info.port}`}
                  hint={`Some clients want host and port together (${String(info.transport).toUpperCase()} transport).`} />

                <div style={{ marginTop: 8, marginBottom: 6, fontWeight: 700, fontSize: 13 }}>Dial Plan</div>
                <Field label="Dial Plan (pass-through, recommended)" value={info.dial_plan}
                  hint="Sends the dialled number unchanged. Dial in full E.164 (e.g. +14155551212)." />
                <Field label="Dial Plan (map + to 00)" value={info.dial_plan_plus00}
                  hint="Use instead if your client can't send a leading +: it rewrites + as 00, and passes any other number through." />

                {info.msisdn &&
                  <div style={{ fontSize: 12, color: 'var(--text-mute)', marginTop: 6 }}>
                    This line's own number: <span className="mono">{info.msisdn}</span>
                  </div>}
              </>
            )}
          </>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 20 }}>
          <button className="btn btn-primary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}
