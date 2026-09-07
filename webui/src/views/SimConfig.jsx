import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import SimSelector from './SimSelector.jsx'

const PANI_ACCESS_TYPES = [
  'IEEE-802.11', 'IEEE-802.11a', 'IEEE-802.11b', 'IEEE-802.11g', 'IEEE-802.11n',
  'IEEE-802.11ac', 'IEEE-802.11ax', 'IEEE-802.11be', '3GPP-WLAN',
]

// Preview-only MCC→ISO hints (authoritative table lives in control/app/mcc_country.py).
const PREVIEW_MCC_ISO = {
  '202': 'GR', '204': 'NL', '206': 'BE', '208': 'FR', '214': 'ES', '216': 'HU',
  '219': 'HR', '222': 'IT', '226': 'RO', '228': 'CH', '230': 'CZ', '232': 'AT',
  '234': 'GB', '235': 'GB', '238': 'DK', '240': 'SE', '242': 'NO', '244': 'FI',
  '250': 'RU', '255': 'UA', '260': 'PL', '262': 'DE', '268': 'PT', '272': 'IE',
  '286': 'TR', '302': 'CA', '310': 'US', '311': 'US', '312': 'US', '313': 'US',
  '314': 'US', '315': 'US', '316': 'US', '334': 'MX', '404': 'IN', '405': 'IN',
  '440': 'JP', '441': 'JP', '450': 'KR', '454': 'HK', '455': 'MO', '460': 'CN',
  '461': 'CN', '466': 'TW', '502': 'MY', '505': 'AU', '510': 'ID', '515': 'PH',
  '520': 'TH', '525': 'SG', '530': 'NZ', '602': 'EG', '655': 'ZA', '724': 'BR',
}

const emptyInstance = () => ({
  // `iccid` is the line's identity; `reader`/`reader_index`/`reader_port` only record where
  // that card was last seen, so the manager can find it again without an APDU.
  id: '', name: '', imsi: '', iccid: '', mcc: '', mnc: '', imei: '', imeisv: '', pin: '', reader: '',
  reader_index: 0, reader_port: '', msisdn: '', smsc: '', enabled: true, apn: 'ims', idr_mode: 'apn', cp_mode: 'auto',
  use_reauth_id: true,
  sip: {
    listen_addr: '0.0.0.0', transport: 'udp', external: [], webrtc: { enable: true },
    pani_country_enable: true, pani_country: '',
    pani_node_id_enable: false, pani_node_id: '',
    pani_access_type: 'IEEE-802.11',
  },
  debug: { asterisk: true, charon: false },
})

function Field({ label, children }) {
  return <div><label>{label}</label>{children}</div>
}

function normalizePreviewCountry(c) {
  const s = String(c || '').trim().toUpperCase().replace(/[^A-Z]/g, '')
  return s.length === 2 ? s : ''
}

function normalizePreviewNodeId(m) {
  const s = String(m || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase()
  return /^[0-9a-f]{12}$/.test(s) ? s : ''
}

/** Client-side preview of the P-Access-Network-Info header that will be sent. */
function previewPani(sip, mcc) {
  const s = sip || {}
  if ((s.pani || '').trim()) return s.pani.trim()
  const parts = [s.pani_access_type || 'IEEE-802.11']
  if (s.pani_country_enable !== false) {
    let c = normalizePreviewCountry(s.pani_country)
    if (!c) {
      const key = String(mcc || '').replace(/\D/g, '').slice(0, 3).padStart(3, '0')
      c = PREVIEW_MCC_ISO[key] || ''
    }
    if (c) parts.push(`country=${c}`)
    else if (mcc) parts.push('country=<from SIM MCC>')
  }
  if (s.pani_node_id_enable) {
    const n = normalizePreviewNodeId(s.pani_node_id)
    if (n) parts.push(`i-wlan-node-id=${n}`)
  }
  return parts.join(';')
}

/** Next free line id. `instances.length + 1` collides after a deletion (lines 1 and 3 left ->
 *  "3"), and POST /api/instances is a blind upsert by id — the new line would overwrite line 3. */
function nextInstanceId(instances) {
  const top = (instances || []).reduce((m, i) => Math.max(m, parseInt(i.id, 10) || 0), 0)
  return String(top + 1)
}

/** Green (success) vs amber (attention) for the free-form status line. Failures are tested
 *  first, and success matches whole phrases: a bare 'read' also matches the word "reader", so
 *  anything mentioning a reader — a card-swap warning, or "reader '…' is no longer connected"
 *  — used to be painted as if everything were fine. */
function pinMsgOk(m) {
  if (m.startsWith('⚠') || m.startsWith('Error') || m.startsWith('Failed')) return false
  return m.includes('OK') || m.includes('Card read') || m.startsWith('Saved.') || m.includes('deleted')
}

function sipUsernameConflict(sip) {
  const accounts = sip?.external || []
  const webrtcUser = String(sip?.webrtc?.username || 'webrtc').trim()
  const reserved = new Set([
    'global', 'system', 'volte_ims', 'endpoint-local', 'auth-local', 'aor-local',
    'transport-local', 'transport-wss', webrtcUser,
  ].filter(Boolean))
  const seen = new Map()
  for (let i = 0; i < accounts.length; i++) {
    const username = String(accounts[i]?.username || '').trim()
    if (!username) continue
    if (reserved.has(username)) {
      return `SIP username '${username}' is reserved for the built-in softphone or Asterisk.`
    }
    if (seen.has(username)) {
      return `SIP username '${username}' is used more than once (accounts #${seen.get(username) + 1} and #${i + 1}).`
    }
    seen.set(username, i)
  }
  return ''
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
  useEffect(() => {
    if (!selected) return
    // Deep-merge sip so new PANI knobs keep their defaults when an older saved
    // instance has no pani_* keys yet (shallow spread would drop emptyInstance.sip).
    const base = emptyInstance()
    setForm({ ...base, ...selected, sip: { ...base.sip, ...(selected.sip || {}) } })
  }, [selected?.id])
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
  // Same for an ICCID the manager learned server-side (an older line without one gets it
  // backfilled on its next start). Only fills a blank — a just-detected card must win.
  useEffect(() => {
    if (selected?.iccid) setForm((f) => (f.iccid ? f : { ...f, iccid: selected.iccid }))
  }, [selected?.iccid])

  const upd = (patch) => setForm((f) => ({ ...f, ...patch }))
  const updSip = (patch) => setForm((f) => ({ ...f, sip: { ...f.sip, ...patch } }))
  // The reader index to act on, clamped to a reader that currently exists (never probe a
  // stale/out-of-range index that would report a phantom empty reader).
  const readerIdx = () => (form.reader_index >= 0 && form.reader_index < readers.length) ? form.reader_index : 0
  // PC/SC NAME of that reader. Sent alongside the index so the backend addresses the reader the
  // user is looking at even if the list shifted since it was fetched.
  const readerName = () => readers[readerIdx()] || ''
  // Stable USB port path of a reader index (from the live card monitor). A line binds to this
  // port, not the enumeration index, so it sticks to the physical reader socket even when pcscd
  // re-enumerates two identical readers in a different order.
  const portForIdx = (i) => (cards.find((c) => c.index === i) || {}).reader_port || ''
  // Picking a reader re-points the locator at it. A port that contradicts the chosen reader is
  // worse than none, so an unknown port clears the stored one — but only when the monitor has
  // actually reported: with no card data at all we don't know anything yet, and discarding a
  // good binding on transient ignorance would disable the port arm of every identity check.
  const pickReader = (i) => upd(cards.length
    ? { reader_index: i, reader_port: portForIdx(i) }
    : { reader_index: i })

  const detect = async () => {
    setPinMsg('Detecting…')
    try {
      const c = await api.detect(readerIdx(), readerName())
      setCard(c)
      if (!c.present) {
        setPinMsg('No SIM card in this reader.')
        return
      }
      const patch = { imsi: c.imsi || form.imsi, mcc: c.mcc || form.mcc, mnc: c.mnc || form.mnc }
      if (c.smsc && smscMode === 'auto') patch.smsc = c.smsc   // SMSC from the SIM (EF_SMSP)
      // Keep the `imsi:` form — the engine's reader matcher understands no other prefix.
      if (c.imsi) patch.reader = `imsi:${c.imsi}`
      // The ICCID is what identifies this line's SIM. Without it the manager can only trust the
      // socket, which is exactly what goes wrong when cards are swapped between readers.
      if (c.iccid) patch.iccid = c.iccid
      // Where that card currently sits (from the detected card, else the live monitor). A hint
      // for finding it again — start-time re-resolves the live index from this port.
      const port = c.reader_port || portForIdx(readerIdx())
      if (port) patch.reader_port = port
      if (!form.id) patch.id = nextInstanceId(instances)
      const known = (form.iccid || '').trim()
      const found = (c.iccid || '').trim()
      upd(patch)
      if (known && found && known !== found) {
        setPinMsg(`⚠ Different SIM: this line is ${known}, the card in this slot is ${found}. `
          + 'Saving now moves the line onto the new card (a swapped SIM or a switched eSIM '
          + 'profile); put the original card back if that is not what you want.')
      } else {
        setPinMsg(c.imsi ? 'Card read.' : `Card present (enter PIN to read IMSI). ICCID ${found || '?'}, tries ${c.pin_tries ?? '?'}`)
      }
    } catch (e) { setPinMsg('Error: ' + e.message) }
  }

  const verifyPin = async () => {
    setPinMsg('Verifying…')
    try {
      const r = await api.verifyPin(pin, readerIdx(), readerName())
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
      const sipError = sipUsernameConflict(form.sip)
      if (sipError) throw new Error(sipError)
      // Send a PATCH of what this form actually owns, not the whole object. /api/instances
      // merges, and GET /api/instances overlays the LIVE reader index/port onto every line —
      // so posting the form wholesale writes back a snapshot of wherever the SIM happened to be
      // when the page was seeded, undoing a binding the manager has since relearned. It also
      // keeps runtime-only fields (status, has_pin) out of the config by construction.
      const body = {
        id: form.id, name: form.name, imsi: form.imsi,
        mcc: form.mcc, mnc: String(form.mnc).padStart(3, '0'),
        imei: form.imei, imeisv: form.imeisv, msisdn: form.msisdn, smsc: form.smsc,
        apn: form.apn, idr_mode: form.idr_mode, cp_mode: form.cp_mode,
        use_reauth_id: form.use_reauth_id, enabled: form.enabled, sip: form.sip,
      }
      // The SIM binding is rewritten only on a deliberate change — a fresh Detect, a different
      // reader, or a line that doesn't exist yet. Editing an APN must not re-pin the line.
      // Compared against the loaded line only when it IS this line: after a delete the form is
      // blank while `selected` has moved on, and a new line must carry its own binding.
      const saved = selected && String(selected.id) === String(form.id) ? selected : null
      for (const k of ['iccid', 'reader', 'reader_index', 'reader_port']) {
        if (!saved || form[k] !== saved[k]) body[k] = form[k]
      }
      // A blank ICCID is never a deliberate edit: the field is read-only and only a card read
      // fills it, so sending one would erase an identity the manager learned on its own.
      if (!body.iccid) delete body.iccid
      // Never send an empty PIN — the stored PIN (tied to this IMSI) must survive edits to
      // unrelated fields. `pin` state is only set when the user re-enters/verifies a PIN
      // here; only then do we forward it to update the saved credential.
      if (pin) body.pin = pin
      // An empty password field means "keep the saved secret", not "replace it with
      // empty". A deliberate password change is sent normally.
      if (body.sip) {
        body.sip = {
          ...body.sip,
          external: (body.sip.external || []).map((account) => {
            const row = { username: account.username || '' }
            if (String(account.password || '').trim()) row.password = account.password
            return row
          }),
        }
      }
      const res = await api.saveInstance(body)
      await refresh()
      if (res?.restart_required) {
        const message = 'Saved. Restart this line (Stop → Start) for SIP, IMEI, and softphone changes to take effect.'
        setPinMsg(message)
        alert(message)
      } else {
        setPinMsg('Saved.')
      }
    } catch (e) { setPinMsg(e.message); alert(e.message) }
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
  const sipUserError = sipUsernameConflict(form.sip)

  return (
    <div style={{ maxWidth: 1000 }}>
      {instances.length > 1 &&
        <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} label="Configuring line" />}
      <div className="sim-config-grid">
      {/* Card / PIN panel */}
      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>SIM card</h3>
        <Field label="Reader">
          <select value={form.reader_index} onChange={(e) => pickReader(+e.target.value)}>
            {readers.map((r, i) => <option key={i} value={i}>{i}: {r}{portForIdx(i) ? ` — USB ${portForIdx(i)}` : ''}</option>)}
            {readers.length === 0 && <option>no readers</option>}
          </select>
        </Field>
        {form.reader_port &&
          <div className="mono" style={{ fontSize: 11, color: 'var(--text-mute)', marginTop: 4 }}>
            SIM last seen at USB port {form.reader_port} — where to look for it, not what identifies it
          </div>}
        <button className="btn btn-ghost" style={{ marginTop: 10 }} onClick={detect}>Detect card</button>
        {card && (
          <div className="mono" style={{ fontSize: 12, color: card.present ? 'var(--text-dim)' : '#ef4444', marginTop: 12, lineHeight: 1.6 }}>
            {card.present ? (<>
              ICCID: {card.iccid || '—'}<br />IMSI: {card.imsi || '(locked)'}<br />
              {card.reader_port && <>USB port: {card.reader_port}<br /></>}
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
        {pinMsg && <div style={{ fontSize: 13, marginTop: 10, color: pinMsgOk(pinMsg) ? '#22c55e' : '#eab308' }}>{pinMsg}</div>}
      </div>

      {/* Instance form */}
      <div className="card" style={{ padding: 20 }}>
        <h3 style={{ marginTop: 0 }}>Line configuration</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 10 }}>
          <Field label="Instance ID"><input value={form.id} onChange={(e) => upd({ id: e.target.value })} placeholder="1" /></Field>
          <Field label="Name"><input value={form.name} onChange={(e) => upd({ name: e.target.value })} placeholder="Telus" /></Field>
          <Field label="IMSI"><input className="mono" value={form.imsi} onChange={(e) => upd({ imsi: e.target.value })} /></Field>
          {/* Read-only: the ICCID is this line's identity and is only ever taken from the card
              itself. Typing one in would claim a SIM the manager has never seen. */}
          <Field label="ICCID (SIM identity)">
            <input className="mono" value={form.iccid || ''} readOnly style={{ opacity: .7 }}
              placeholder="detect the card to read it" />
          </Field>
          <Field label="MCC"><input value={form.mcc} onChange={(e) => upd({ mcc: e.target.value })} /></Field>
          <Field label="MNC"><input value={form.mnc} onChange={(e) => upd({ mnc: e.target.value })} /></Field>
          <Field label="IMEI"><input className="mono" value={form.imei} onChange={(e) => upd({ imei: e.target.value })} placeholder="35123456-789012-3" /></Field>
          <Field label="IMEISV"><input className="mono" value={form.imeisv || ''} onChange={(e) => upd({ imeisv: e.target.value.replace(/[^0-9]/g, '') })} maxLength={16} placeholder="auto from IMEI (DEVICE_IDENTITY)" /></Field>
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
          <Field label="APN"><input className="mono" value={form.apn ?? 'ims'} onChange={(e) => upd({ apn: e.target.value })} placeholder="ims" /></Field>
          <Field label="ePDG identity (IDr)">
            <select value={form.idr_mode ?? 'apn'} onChange={(e) => upd({ idr_mode: e.target.value })}>
              <option value="apn">Bare APN (default)</option>
              <option value="fqdn">APN-FQDN</option>
            </select>
          </Field>
          <Field label="IMS address family (CP)">
            <select value={form.cp_mode ?? 'auto'} onChange={(e) => upd({ cp_mode: e.target.value })}>
              <option value="auto">Auto-detect (recommended)</option>
              <option value="dual">Dual-stack (IPv4+IPv6)</option>
              <option value="v6">IPv6 only</option>
              <option value="v4">IPv4 only</option>
            </select>
            {form.cp_mode && form.cp_mode !== 'auto' && form.cp_mode_source === 'auto' && (
              <div style={{ fontSize: 11, color: 'var(--text-mute)', marginTop: 2 }}>
                Auto-detected: {form.cp_mode.toUpperCase()}. Switch back to Auto-detect to re-probe.
              </div>
            )}
          </Field>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-mute)', marginTop: 4 }}>
          IDr is how the APN is presented to the ePDG. <b>Bare APN</b> (just the APN string) is what most carriers' ePDGs expect and is the safe default; <b>APN-FQDN</b> (<code>&lt;apn&gt;.apn.epc.mnc…mcc….pub.3gppnetwork.org</code>) is required only by a few stricter carriers — some networks reject it.
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-mute)', marginTop: 4 }}>
          <b>IMS address family</b> must match the carrier's IMS PDN. <b>Auto-detect</b> figures it out for you (matches known carriers, else probes families after SIM auth) and pins the one that works — leave this unless you know the carrier needs a specific family. Telus/EE are IPv6; Vodafone UK is IPv4.
        </div>

        <label style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
          <input type="checkbox" style={{ width: 'auto' }}
            checked={form.use_reauth_id !== false}
            onChange={(e) => upd({ use_reauth_id: e.target.checked })} />
          Use EAP-AKA fast re-authentication
        </label>
        <div style={{ fontSize: 11, color: 'var(--text-mute)', marginTop: 4 }}>
          On by default. After a successful attach the carrier's AAA may hand out a short-lived re-authentication identity; presenting it on a reconnect lets the network skip a full SIM auth run. If it has expired the engine notices the rejection and retries with the permanent IMSI identity by itself, so this is safe to leave on. Turn it <b>off</b> for a carrier whose AAA rejects it on every reconnect (O2 UK) to skip that wasted attach attempt.
        </div>

        <h4 style={{ marginBottom: 6 }}>Local SIP access</h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: 10 }}>
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

        <h4 style={{ marginBottom: 6, marginTop: 16 }}>P-Access-Network-Info</h4>
        <div style={{ fontSize: 11, color: 'var(--text-mute)', marginBottom: 8 }}>
          Sent on IMS REGISTER / SIP to identify the Wi-Fi access. Default matches real phones:
          <code style={{ marginLeft: 4 }}>IEEE-802.11;country=&lt;SIM home country&gt;</code>
        </div>
        <Field label="Access type">
          <select value={form.sip.pani_access_type || 'IEEE-802.11'}
            onChange={(e) => updSip({ pani_access_type: e.target.value })}>
            {PANI_ACCESS_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </Field>
        <label style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
          <input type="checkbox" style={{ width: 'auto' }}
            checked={form.sip.pani_country_enable !== false}
            onChange={(e) => updSip({ pani_country_enable: e.target.checked })} />
          Report country code
        </label>
        {form.sip.pani_country_enable !== false && (
          <div style={{ marginTop: 6 }}>
            <input className="mono" maxLength={2}
              value={form.sip.pani_country || ''}
              onChange={(e) => updSip({ pani_country: e.target.value.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 2) })}
              placeholder="留空 = 按 SIM 的 MCC 自动推导（如 GB）" />
          </div>
        )}
        <label style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
          <input type="checkbox" style={{ width: 'auto' }}
            checked={!!form.sip.pani_node_id_enable}
            onChange={(e) => updSip({ pani_node_id_enable: e.target.checked })} />
          Report Wi-Fi AP BSSID (i-wlan-node-id)
        </label>
        {!!form.sip.pani_node_id_enable && (
          <div style={{ marginTop: 6 }}>
            <input className="mono"
              value={form.sip.pani_node_id || ''}
              onChange={(e) => updSip({ pani_node_id: e.target.value })}
              placeholder="000cf1126028" />
          </div>
        )}
        <div className="mono" style={{ marginTop: 10, fontSize: 12, padding: '8px 10px',
          background: 'var(--bg-elev, rgba(0,0,0,.25))', borderRadius: 6, color: 'var(--text-dim)' }}>
          Preview: P-Access-Network-Info: {previewPani(form.sip, form.mcc)}
        </div>

        <div style={{ marginTop: 12 }}>
          <label>External SIP accounts</label>
          <div style={{ fontSize: 12, color: 'var(--text-mute)', marginBottom: 6 }}>
            Each account needs a unique username and cannot reuse an Asterisk or WebRTC name.
          </div>
          {(form.sip.external || []).map((a, i) => (
            <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
              <input placeholder="username" value={a.username} onChange={(e) => setAccount(i, 'username', e.target.value)} />
              <input type="password" placeholder="password" value={a.password} onChange={(e) => setAccount(i, 'password', e.target.value)} />
            </div>
          ))}
          {sipUserError && (
            <div style={{ color: '#ef4444', fontSize: 12.5, marginTop: 6 }} role="alert">
              {sipUserError}
            </div>
          )}
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
