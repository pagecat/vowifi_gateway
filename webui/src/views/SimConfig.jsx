import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import SimSelector from './SimSelector.jsx'

const emptyInstance = () => ({
  id: '', name: '', imsi: '', mcc: '', mnc: '', imei: '', pin: '', reader: '',
  reader_index: 0, msisdn: '', smsc: '', enabled: true,
  sip: { listen_addr: '0.0.0.0', transport: 'udp', external: [], webrtc: { enable: true } },
  debug: { asterisk: true, charon: false },
})

function Field({ label, children }) {
  return <div><label>{label}</label>{children}</div>
}

export default function SimConfig({ instances, selected, refresh, cards, setSelected }) {
  const [readers, setReaders] = useState([])
  const [card, setCard] = useState(null)
  const [pin, setPin] = useState('')
  const [pinMsg, setPinMsg] = useState('')
  const [form, setForm] = useState(emptyInstance())
  const [saving, setSaving] = useState(false)
  const [smscMode, setSmscMode] = useState('auto')   // 'auto' = read from SIM, 'manual' = typed

  // Refresh the physical-reader list whenever the detected-card set changes (hotplug), so
  // the reader picker never lists a reader that has been unplugged.
  useEffect(() => { api.readers().then((r) => setReaders(r.readers)).catch(() => {}) }, [cards.map((c) => c.name).join(',')])
  useEffect(() => { if (selected) setForm({ ...emptyInstance(), ...selected }) }, [selected?.id])
  // Keep the reader selection valid for the CURRENT hardware. A stored reader_index can be
  // stale — saved when more readers were attached — and point past the live reader list; the
  // <select> then has no matching option and "Detect card" probes a phantom reader ("No SIM
  // card in reader N"). Clamp any out-of-range index back onto a reader that actually exists.
  useEffect(() => {
    if (!readers.length) return
    setForm((f) => (f.reader_index >= readers.length || f.reader_index < 0)
      ? { ...f, reader_index: 0 } : f)
  }, [readers.length])
  // Keep the "PIN saved?" indicator in sync when it changes server-side (delete-PIN,
  // start-with-PIN) without a full line switch — mirror the fresh value onto the form.
  useEffect(() => { if (selected) setForm((f) => ({ ...f, has_pin: selected.has_pin })) }, [selected?.has_pin])

  const upd = (patch) => setForm((f) => ({ ...f, ...patch }))
  const updSip = (patch) => setForm((f) => ({ ...f, sip: { ...f.sip, ...patch } }))
  // The reader index to act on, clamped to a reader that currently exists (never probe a
  // stale/out-of-range index that would report a phantom empty reader).
  const readerIdx = () => (form.reader_index >= 0 && form.reader_index < readers.length) ? form.reader_index : 0

  const detect = async () => {
    setPinMsg('Detecting…')
    try {
      const c = await api.detect(readerIdx())
      setCard(c)
      if (!c.present) {
        setPinMsg('No SIM card in this reader.')
        return
      }
      const patch = { imsi: c.imsi || form.imsi, mcc: c.mcc || form.mcc, mnc: c.mnc || form.mnc }
      if (c.smsc && smscMode === 'auto') patch.smsc = c.smsc   // SMSC from the SIM (EF_SMSP)
      if (c.imsi) patch.reader = `imsi:${c.imsi}`
      if (!form.id) patch.id = String(instances.length + 1)
      upd(patch)
      setPinMsg(c.imsi ? 'Card read.' : `Card present (enter PIN to read IMSI). ICCID ${c.iccid || '?'}, tries ${c.pin_tries ?? '?'}`)
    } catch (e) { setPinMsg('Error: ' + e.message) }
  }

  const verifyPin = async () => {
    setPinMsg('Verifying…')
    try {
      const r = await api.verifyPin(pin, readerIdx())
      setPinMsg(r.ok ? 'PIN OK ✓' : `Failed: ${r.error} (${r.tries} tries left)`)
      if (r.ok) {
        const p = { pin }
        if (r.card?.smsc && smscMode === 'auto') p.smsc = r.card.smsc   // now-readable SMSC from SIM
        upd(p)
        await detect()
      }
    } catch (e) { setPinMsg('Error: ' + e.message) }
  }

  const save = async () => {
    setSaving(true)
    try {
      const body = { ...form, mnc: String(form.mnc).padStart(3, '0') }
      // Strip runtime-only fields that ride along on the instance object from /api/instances
      // (they are computed per-request, not config — never persist them).
      delete body.status; delete body.has_pin
      // Never send an empty PIN — the stored PIN (tied to this IMSI) must survive edits to
      // unrelated fields. `pin` state is only set when the user re-enters/verifies a PIN
      // here; only then do we forward it to update the saved credential.
      delete body.pin
      if (pin) body.pin = pin
      const res = await api.saveInstance(body)
      await refresh()
      // A running line is restarted server-side to apply the new config (pjsip accounts,
      // IMEI, SMSC, User-Agent…); a stopped line just saves.
      setPinMsg(res?.applied ? 'Saved — restarting the line to apply changes…' : 'Saved.')
    } catch (e) { alert(e.message) }
    setSaving(false)
  }

  const del = async () => {
    if (!confirm('Delete this instance?')) return
    await api.deleteInstance(form.id); await refresh(); setForm(emptyInstance())
  }

  const deleteSavedPin = async () => {
    if (!form.id) return
    if (!confirm('Delete the saved SIM PIN for this line?\n\nThe line will be stopped and, '
      + 'the next time you start it, you\'ll be asked to enter the PIN again.')) return
    try {
      const r = await api.clearPin(form.id)
      upd({ has_pin: false })          // reflect immediately (form is local state)
      await refresh()
      setPinMsg(r.had_pin ? 'Saved PIN deleted — the line will ask for it on next start.'
                          : 'No saved PIN to delete.')
    } catch (e) { alert(e.message) }
  }

  const addAccount = () => updSip({ external: [...(form.sip.external || []), { username: '', password: '' }] })
  const setAccount = (i, k, v) => updSip({ external: form.sip.external.map((a, idx) => idx === i ? { ...a, [k]: v } : a) })

  return (
    <div style={{ maxWidth: 1000 }}>
      {instances.length > 1 &&
        <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} label="Configuring line" />}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      {/* Card / PIN panel */}
      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>SIM card</h3>
        <Field label="Reader">
          <select value={form.reader_index} onChange={(e) => upd({ reader_index: +e.target.value })}>
            {readers.map((r, i) => <option key={i} value={i}>{i}: {r}</option>)}
            {readers.length === 0 && <option>no readers</option>}
          </select>
        </Field>
        <button className="btn btn-ghost" style={{ marginTop: 10 }} onClick={detect}>Detect card</button>
        {card && (
          <div className="mono" style={{ fontSize: 12, color: card.present ? 'var(--text-dim)' : '#ef4444', marginTop: 12, lineHeight: 1.6 }}>
            {card.present ? (<>
              ICCID: {card.iccid || '—'}<br />IMSI: {card.imsi || '(locked)'}<br />
              PIN: {card.pin_enabled ? `enabled, ${card.pin_tries} tries` : 'disabled'}
            </>) : (<>No SIM card in reader {card.reader_index}.</>)}
          </div>
        )}
        <hr style={{ borderColor: 'var(--border)', margin: '16px 0' }} />
        <Field label="PIN (CHV1)">
          <input type="password" value={pin} onChange={(e) => setPin(e.target.value)} placeholder="e.g. 123456" />
        </Field>
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={verifyPin} disabled={!pin}>Verify PIN</button>
          {form.id && form.has_pin &&
            <button className="btn btn-ghost" style={{ color: '#ef4444' }} onClick={deleteSavedPin}>Delete saved PIN</button>}
        </div>
        {form.id && (
          <div style={{ fontSize: 12, color: 'var(--text-mute)', marginTop: 8 }}>
            {form.has_pin
              ? 'A PIN is saved for this line and used automatically on start.'
              : 'No PIN saved — you\'ll be asked for it when the line is started (if the SIM requires one).'}
          </div>
        )}
        {pinMsg && <div style={{ fontSize: 13, marginTop: 10, color: pinMsg.includes('OK') || pinMsg.includes('read') || pinMsg === 'Saved.' || pinMsg.includes('deleted') ? '#22c55e' : '#eab308' }}>{pinMsg}</div>}
      </div>

      {/* Instance form */}
      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>Line configuration</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <Field label="Instance ID"><input value={form.id} onChange={(e) => upd({ id: e.target.value })} placeholder="1" /></Field>
          <Field label="Name"><input value={form.name} onChange={(e) => upd({ name: e.target.value })} placeholder="Telus" /></Field>
          <Field label="IMSI"><input className="mono" value={form.imsi} onChange={(e) => upd({ imsi: e.target.value })} /></Field>
          <Field label="MCC"><input value={form.mcc} onChange={(e) => upd({ mcc: e.target.value })} /></Field>
          <Field label="MNC"><input value={form.mnc} onChange={(e) => upd({ mnc: e.target.value })} /></Field>
          <Field label="IMEI"><input className="mono" value={form.imei} onChange={(e) => upd({ imei: e.target.value })} placeholder="35123456-789012-3" /></Field>
          <Field label="Phone number (MSISDN)"><input className="mono" value={form.msisdn} onChange={(e) => upd({ msisdn: e.target.value })} placeholder="auto-learned" /></Field>
          <Field label="SMS centre (SMSC)">
            <div style={{ display: 'flex', gap: 12, marginBottom: 6, fontSize: 13 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }}>
                <input type="radio" name="scmode" checked={smscMode === 'auto'} style={{ width: 'auto' }}
                  onChange={() => { setSmscMode('auto'); if (card?.smsc) upd({ smsc: card.smsc }) }} />Auto (from SIM)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }}>
                <input type="radio" name="scmode" checked={smscMode === 'manual'} style={{ width: 'auto' }}
                  onChange={() => setSmscMode('manual')} />Manual
              </label>
            </div>
            <input className="mono" value={form.smsc} readOnly={smscMode === 'auto'}
              onChange={(e) => upd({ smsc: e.target.value })}
              placeholder={smscMode === 'auto' ? 'detect card / verify PIN to read from SIM' : '+1...'}
              style={smscMode === 'auto' ? { opacity: .7 } : undefined} />
          </Field>
          <Field label="Reader match"><input className="mono" value={form.reader} onChange={(e) => upd({ reader: e.target.value })} placeholder="imsi:302..." /></Field>
        </div>

        <h4 style={{ marginBottom: 6 }}>Local SIP access</h4>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <Field label="Listen address">
            <select value={form.sip.listen_addr} onChange={(e) => updSip({ listen_addr: e.target.value })}>
              <option value="0.0.0.0">0.0.0.0 (all)</option>
              <option value="127.0.0.1">127.0.0.1 (local)</option>
              {selected?.status && <option value="lan">LAN IP</option>}
            </select>
          </Field>
          <Field label="Transport">
            <select value={form.sip.transport} onChange={(e) => updSip({ transport: e.target.value })}>
              <option value="udp">UDP</option><option value="tcp">TCP</option><option value="tls">TLS</option>
            </select>
          </Field>
        </div>
        <label style={{ marginTop: 8 }}>
          <input type="checkbox" style={{ width: 'auto', marginRight: 8 }} checked={!!form.sip.webrtc?.enable}
            onChange={(e) => updSip({ webrtc: { ...form.sip.webrtc, enable: e.target.checked } })} />
          Enable browser softphone (WebRTC)
        </label>

        <div style={{ marginTop: 12 }}>
          <label>Device User-Agent (identify to the carrier as this device)</label>
          <input className="mono" value={form.sip.user_agent || ''} onChange={(e) => updSip({ user_agent: e.target.value })} placeholder="iOS/26.6 iPhone" />
        </div>

        <div style={{ marginTop: 12 }}>
          <label>External SIP accounts</label>
          {(form.sip.external || []).map((a, i) => (
            <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
              <input placeholder="username" value={a.username} onChange={(e) => setAccount(i, 'username', e.target.value)} />
              <input placeholder="password" value={a.password} onChange={(e) => setAccount(i, 'password', e.target.value)} />
            </div>
          ))}
          <button className="btn btn-ghost" onClick={addAccount}>+ Add account</button>
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 18 }}>
          <button className="btn btn-primary" onClick={save} disabled={saving || !form.id || !form.imsi}>Save</button>
          {form.id && <button className="btn btn-danger" onClick={del}>Delete</button>}
        </div>
      </div>
      </div>
    </div>
  )
}
