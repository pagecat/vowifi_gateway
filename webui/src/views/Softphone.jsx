import React, { useEffect, useRef, useState, useCallback } from 'react'
import { api } from '../api.js'
import { Softphone as Phone } from '../softphone.js'
import SimSelector from './SimSelector.jsx'

const GREEN = '#22c55e', RED = '#ef4444'
const KEYS = [['1', ''], ['2', 'ABC'], ['3', 'DEF'], ['4', 'GHI'], ['5', 'JKL'],
  ['6', 'MNO'], ['7', 'PQRS'], ['8', 'TUV'], ['9', 'WXYZ'], ['*', ''], ['0', '+'], ['#', '']]

const fmtDur = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

function Avatar({ label, color = 'var(--primary)', size = 96 }) {
  return (
    <div style={{ width: size, height: size, borderRadius: '50%', background: color + '22',
      border: `2px solid ${color}55`, display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: size * 0.42, color, margin: '0 auto' }}>☎</div>
  )
}

function RoundBtn({ icon, label, color, bg, onClick, active }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <button onClick={onClick} style={{
        width: 58, height: 58, borderRadius: '50%', cursor: 'pointer', fontSize: 22,
        border: '1px solid ' + (active ? color : 'var(--border-strong)'),
        background: bg || (active ? color + '22' : 'var(--hover)'),
        color: active ? color : 'var(--text-soft)', display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>{icon}</button>
      <span style={{ fontSize: 11, color: 'var(--text-mute)' }}>{label}</span>
    </div>
  )
}

export default function Softphone({ selected, subscribe, instances, cards, setSelected, showToast }) {
  const id = selected?.id
  const [prov, setProv] = useState(null)
  const [reg, setReg] = useState('idle')
  const [call, setCall] = useState(null)     // {dir, number, state, startedAt, endCause}
  const [num, setNum] = useState('')
  const [dur, setDur] = useState(0)
  const [muted, setMuted] = useState(false)
  const [keypad, setKeypad] = useState(false)
  const [dtmfSeq, setDtmfSeq] = useState('')   // digits/symbols entered since the keypad opened
  const [recording, setRecording] = useState(false)
  const [calls, setCalls] = useState([])
  const [callSelMode, setCallSelMode] = useState(false)
  const [callSel, setCallSel] = useState(() => new Set())
  const phone = useRef(null)
  // Persistent, DOM-rendered <audio> sink. One stable element (primed on the first click via
  // unlockAudio) is what makes remote WebRTC audio play under Chrome/Edge autoplay policy.
  const audioRef = useRef(null)

  const loadCalls = useCallback(() => { if (id) api.calls(id).then((r) => setCalls(r.calls || [])).catch(() => {}) }, [id])
  useEffect(() => { loadCalls() }, [loadCalls])
  useEffect(() => { setCallSelMode(false); setCallSel(new Set()) }, [id])
  // if the list empties (own delete, or another client's clear-all over WS), leave select
  // mode so the toolbar/checkbox UI can't get stranded on an empty list.
  useEffect(() => { if (!calls.length) { setCallSelMode(false); setCallSel(new Set()) } }, [calls.length])
  useEffect(() => subscribe && subscribe((m) => { if (m.type === 'call' && m.instance === id) loadCalls() }), [subscribe, id, loadCalls])

  const toast = (m) => (showToast ? showToast(m) : null)
  const toggleCallSel = (cid) => setCallSel((s) => { const n = new Set(s); n.has(cid) ? n.delete(cid) : n.add(cid); return n })
  // Reload only if still on the same line (a delete may resolve after the user switched SIMs).
  const reloadIfSame = (forId) => { if (forId === id) loadCalls() }

  const deleteSelectedCalls = async () => {
    if (!callSel.size) return
    if (!confirm(`Delete ${callSel.size} selected call${callSel.size > 1 ? 's' : ''}?`)) return
    const forId = id
    try {
      await api.deleteCalls(forId, { ids: [...callSel] })
      setCallSelMode(false); setCallSel(new Set()); reloadIfSame(forId); toast('Calls deleted')
    } catch (e) { toast('Delete failed: ' + e.message) }
  }
  const deleteOneCall = async (cid, e) => {
    if (e) e.stopPropagation()
    const forId = id
    try { await api.deleteCalls(forId, { ids: [cid] }); reloadIfSame(forId) } catch (e2) { toast('Delete failed: ' + e2.message) }
  }
  const clearAllCalls = async () => {
    if (!calls.length) return
    if (!confirm('Clear the entire call history for this line?')) return
    const forId = id
    try { await api.deleteCalls(forId, { all: true }); setCallSelMode(false); setCallSel(new Set()); reloadIfSame(forId); toast('Call history cleared') }
    catch (e) { toast('Delete failed: ' + e.message) }
  }

  // provisioning + connect (only while this page is mounted => only listens for incoming here)
  useEffect(() => {
    if (!id) return
    let alive = true
    setReg('idle'); setCall(null)
    api.softphone(id).then((p) => { if (alive) setProv(p) }).catch(() => {})
    return () => { alive = false; if (phone.current) { phone.current.stop(); phone.current = null } }
  }, [id])

  const clearCallSoon = (endCause) => {
    setCall((c) => c ? { ...c, state: 'ended', endCause } : null)
    setKeypad(false); setMuted(false); setRecording(false)
    setTimeout(() => setCall(null), 2500)
    loadCalls()
  }

  const connect = useCallback(() => {
    if (!prov || !prov.enabled || phone.current) return
    const ph = new Phone((type, data) => {
      if (type === 'registered') setReg(data ? 'registered' : 'unregistered')
      else if (type === 'ws') setReg((r) => data === 'connected' ? (r === 'registered' ? r : 'connecting') : 'disconnected')
      else if (type === 'regfail') setReg('failed')
      else if (type === 'incoming') setCall({ dir: 'in', number: data.from || 'Unknown', state: 'incoming' })
      else if (type === 'calling') setCall({ dir: 'out', number: data.to, state: 'calling' })
      // 'progress' fires for BOTH directions. On an incoming call JsSIP auto-sends 180 and
      // emits progress('local'); mapping that to 'ringing' would blow away the 'incoming'
      // state and hide the Answer/Decline overlay. Only an OUTGOING call still in the
      // dialing/ringing phase should advance to 'ringing' — leave incoming/active/ended alone.
      else if (type === 'progress') setCall((c) => (c && c.dir === 'out' && (c.state === 'calling' || c.state === 'ringing')) ? { ...c, state: 'ringing' } : c)
      else if (type === 'active') setCall((c) => c ? { ...c, state: 'active', startedAt: Date.now() } : c)
      else if (type === 'ended') clearCallSoon(data && data.cause)
      else if (type === 'failed') clearCallSoon(data && data.cause)
    }, audioRef.current)
    ph.start(prov, prov.host || location.hostname)
    phone.current = ph
    setReg('connecting')
  }, [prov])

  useEffect(() => { if (prov && prov.enabled && !phone.current) connect() }, [prov, connect])

  // The <audio> element mounts with the component; make sure the phone (which may have been
  // created before the ref attached) points at it.
  useEffect(() => { if (phone.current && audioRef.current) phone.current.setAudioEl(audioRef.current) })

  // in-call duration timer
  useEffect(() => {
    if (call?.state !== 'active' || !call.startedAt) { setDur(0); return }
    const t = setInterval(() => setDur(Math.floor((Date.now() - call.startedAt) / 1000)), 500)
    return () => clearInterval(t)
  }, [call?.state, call?.startedAt])

  // Physical-keyboard DTMF: while the in-call keypad is open, let the user type 0-9 * #
  // directly instead of only clicking. Clear the echo strip each time the keypad opens.
  useEffect(() => {
    if (!(keypad && call?.state === 'active')) return
    setDtmfSeq('')
    const onKey = (e) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return
      // Shift+3 produces '#'; a bare '3' should stay '3'. e.key already reflects the shifted
      // character, so match on the resulting character directly.
      const k = e.key
      if (/^[0-9*#]$/.test(k)) { e.preventDefault(); pressDTMF(k) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [keypad, call?.state])

  // Watchdog: a call parked in a non-terminal setup phase (calling/ringing/incoming) that
  // never advances to 'active' or 'ended' — e.g. a BYE/terminal JsSIP event was dropped —
  // would otherwise strand the UI forever. Force it back to idle after a timeout. 'active'
  // has no timeout (calls can be long); 'ended' clears on its own via clearCallSoon.
  useEffect(() => {
    if (!call || call.state === 'active' || call.state === 'ended') return
    const ms = call.state === 'incoming' ? 60000 : 65000
    const t = setTimeout(() => {
      // Ask the phone to tear down whatever it thinks it has, then reset the UI.
      try { phone.current?.hangup() } catch {}
      setCall(null); setKeypad(false); setMuted(false); setRecording(false)
    }, ms)
    return () => clearTimeout(t)
  }, [call?.state])

  const dialKey = (k) => {
    if (call?.state === 'active') { phone.current?.sendDTMF(k); setNum((n) => n + k) }
    else setNum((n) => n + k)
  }
  // In-call DTMF: send the tone and echo it into the keypad's display strip.
  const pressDTMF = (k) => { phone.current?.sendDTMF(k); setDtmfSeq((s) => (s + k).slice(-32)) }
  const placeCall = () => { if (phone.current && num) { phone.current.unlockAudio(); phone.current.call(num); setNum('') } }
  const answer = () => { phone.current?.unlockAudio(); phone.current?.answer() }
  // Optimistically move to 'ended' on a local hangup. JsSIP will still fire 'ended'
  // (→ clearCallSoon), but if that event is delayed or missed the UI has already left the
  // active/ringing screen instead of stranding on it.
  const hangup = () => {
    phone.current?.hangup()
    setCall((c) => (c && c.state !== 'ended') ? { ...c, state: 'ended', endCause: c.endCause } : c)
    setKeypad(false); setMuted(false); setRecording(false)
    setTimeout(() => setCall((c) => (c && c.state === 'ended') ? null : c), 2500)
  }
  // Declining a ringing incoming call must send 603 (→ "declined"), not a bare hangup
  // (→ "missed"). reject() picks the right signalling for an un-answered incoming session.
  const decline = () => {
    phone.current?.reject()
    setCall((c) => (c && c.state !== 'ended') ? { ...c, state: 'ended', endCause: 'Rejected' } : c)
    setKeypad(false); setMuted(false); setRecording(false)
    setTimeout(() => setCall((c) => (c && c.state === 'ended') ? null : c), 2500)
  }
  const toggleMute = () => { const m = !muted; setMuted(m); phone.current?.setMuted(m) }
  const toggleRecord = async () => {
    if (!phone.current) return
    if (recording) {
      const blob = await phone.current.stopRecording(); setRecording(false)
      if (blob) {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = `call-${call?.number || 'rec'}-${Date.now()}.webm`; a.click()
        setTimeout(() => URL.revokeObjectURL(url), 10000)
      }
    } else { const ok = await phone.current.startRecording(); setRecording(ok) }
  }

  if (!id) return (
    <div>
      <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} />
      <div style={{ color: 'var(--text-dim)' }}>Select a SIM / line to use the softphone.</div>
    </div>
  )

  const regColor = reg === 'registered' ? GREEN : reg === 'failed' || reg === 'disconnected' ? RED : '#eab308'
  const inCall = call && (call.state === 'active' || call.state === 'calling' || call.state === 'ringing' || call.state === 'incoming' || call.state === 'ended')
  const endLabel = (c) => c === 'Rejected' ? 'Call declined' : c === 'Busy' ? 'Busy' : c === 'Canceled' || c === 'Canceled/Rejected' ? 'Call cancelled' : 'Call ended'

  // Google-Voice-style incoming-call overlay (prominent, full-panel)
  const IncomingOverlay = call?.state === 'incoming' ? (
    <div style={{ position: 'fixed', inset: 0, zIndex: 100, background: 'rgba(6,10,20,0.82)',
      backdropFilter: 'blur(3px)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div className="card" style={{ padding: 40, width: 380, textAlign: 'center',
        boxShadow: '0 20px 60px rgba(0,0,0,.6)', animation: 'none' }}>
        <div style={{ fontSize: 13, color: 'var(--text-mute)', letterSpacing: 1, textTransform: 'uppercase' }}>Incoming call</div>
        <div style={{ margin: '22px 0' }}><Avatar label={call.number} color={GREEN} size={110} /></div>
        <div className="mono" style={{ fontSize: 26, fontWeight: 800 }}>{call.number || 'Unknown'}</div>
        <div style={{ fontSize: 13, color: 'var(--text-mute)', marginTop: 6 }}>{selected?.name || 'VoWiFi line'}</div>
        <div style={{ display: 'flex', justifyContent: 'center', gap: 56, marginTop: 34 }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
            <button onClick={decline} style={{ width: 68, height: 68, borderRadius: '50%', border: 'none',
              cursor: 'pointer', fontSize: 26, background: RED, color: '#fff' }}>✕</button>
            <span style={{ fontSize: 13, color: 'var(--text-soft)' }}>Decline</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
            <button onClick={answer} style={{ width: 68, height: 68, borderRadius: '50%', border: 'none',
              cursor: 'pointer', fontSize: 26, background: GREEN, color: '#fff',
              boxShadow: `0 0 0 0 ${GREEN}`, animation: 'ringpulse 1.4s infinite' }}>✆</button>
            <span style={{ fontSize: 13, color: 'var(--text-soft)' }}>Answer</span>
          </div>
        </div>
      </div>
    </div>
  ) : null

  return (
    <div>
      {/* Persistent remote-audio sink: JsSIP writes the remote MediaStream here. autoPlay +
          a stable DOM element + unlockAudio() on the first click = reliable playback. */}
      <audio ref={audioRef} autoPlay playsInline style={{ display: 'none' }} />
      <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} />
      <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 16 }}>
      {IncomingOverlay}
      <style>{`@keyframes ringpulse{0%{box-shadow:0 0 0 0 ${GREEN}88}70%{box-shadow:0 0 0 16px ${GREEN}00}100%{box-shadow:0 0 0 0 ${GREEN}00}}`}</style>
      {/* ---- Phone panel (Google-Voice style) ---- */}
      <div className="card" style={{ padding: 24, minHeight: 520, display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <div style={{ fontSize: 13, color: 'var(--text-dim)' }}>Softphone</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: regColor }}>
            <span style={{ width: 8, height: 8, borderRadius: 999, background: regColor }} />{reg}
          </div>
        </div>

        {!prov?.enabled && (
          <div style={{ color: '#f97316', fontSize: 13, margin: '12px 0' }}>
            WebRTC is disabled for this SIM. Enable it in SIM Config (needs HTTPS/TLS) to use the browser phone.
          </div>
        )}

        {/* ===== INCOMING handled by full-screen overlay above ===== */}

        {/* ===== OUTGOING RINGING ===== */}
        {(call?.state === 'calling' || call?.state === 'ringing') && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', textAlign: 'center', gap: 16 }}>
            <Avatar label={call.number} />
            <div>
              <div className="mono" style={{ fontSize: 22, fontWeight: 700 }}>{call.number}</div>
              <div style={{ fontSize: 13, color: 'var(--text-mute)', marginTop: 4 }}>{call.state === 'ringing' ? 'Ringing…' : 'Calling…'}</div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', marginTop: 10 }}>
              <RoundBtn icon="✕" label="End" color="#fff" bg={RED} onClick={hangup} />
            </div>
          </div>
        )}

        {/* ===== IN CALL ===== */}
        {call?.state === 'active' && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', textAlign: 'center', gap: 14 }}>
            <Avatar label={call.number} color={GREEN} size={84} />
            <div>
              <div className="mono" style={{ fontSize: 20, fontWeight: 700 }}>{call.number || 'Unknown'}</div>
              <div style={{ fontSize: 15, color: GREEN, marginTop: 4, fontVariantNumeric: 'tabular-nums' }}>{fmtDur(dur)}</div>
              {recording && <div style={{ fontSize: 12, color: RED, marginTop: 2 }}>● Recording</div>}
            </div>
            {keypad && (
              <div style={{ maxWidth: 220, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                {/* Echo strip: shows every digit/symbol entered via click or physical keyboard */}
                <div className="mono" style={{ minHeight: 40, padding: '8px 12px', borderRadius: 8,
                  background: 'var(--surface-2, rgba(255,255,255,0.06))', border: '1px solid var(--border, rgba(255,255,255,0.12))',
                  fontSize: 20, letterSpacing: 2, textAlign: 'center', overflow: 'hidden', whiteSpace: 'nowrap',
                  direction: 'rtl', color: dtmfSeq ? 'var(--text)' : 'var(--text-mute)' }}>
                  {dtmfSeq || 'Type or tap keys'}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8 }}>
                  {KEYS.map(([k]) => (
                    <button key={k} className="btn btn-ghost" style={{ padding: 12, fontSize: 18 }}
                      onClick={() => pressDTMF(k)}>{k}</button>
                  ))}
                </div>
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'center', gap: 22, marginTop: 8 }}>
              <RoundBtn icon={muted ? '🔇' : '🎙'} label={muted ? 'Unmute' : 'Mute'} color="#60a5fa" onClick={toggleMute} active={muted} />
              <RoundBtn icon="⌨" label="Keypad" color="#a78bfa" onClick={() => setKeypad((v) => !v)} active={keypad} />
              <RoundBtn icon="⏺" label={recording ? 'Stop' : 'Record'} color={RED} onClick={toggleRecord} active={recording} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', marginTop: 6 }}>
              <RoundBtn icon="✕" label="Hang up" color="#fff" bg={RED} onClick={hangup} />
            </div>
          </div>
        )}

        {/* ===== ENDED (brief) ===== */}
        {call?.state === 'ended' && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', textAlign: 'center', gap: 12 }}>
            <Avatar label={call.number} color={call.endCause === 'Rejected' ? RED : 'var(--text-mute)'} />
            <div className="mono" style={{ fontSize: 20, fontWeight: 700 }}>{call.number || 'Unknown'}</div>
            <div style={{ fontSize: 14, color: call.endCause === 'Rejected' ? RED : 'var(--text-mute)' }}>{endLabel(call.endCause)}</div>
          </div>
        )}

        {/* ===== DIALER (idle) ===== */}
        {!inCall && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <input value={num} onChange={(e) => setNum(e.target.value)} placeholder="Enter a number"
              className="mono" style={{ fontSize: 24, textAlign: 'center', margin: '10px 0 16px', letterSpacing: 1, border: 'none', background: 'transparent' }} />
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10 }}>
              {KEYS.map(([k, sub]) => (
                <button key={k} onClick={() => dialKey(k)} style={{
                  padding: '10px 0', borderRadius: 12, cursor: 'pointer', background: 'var(--hover)',
                  border: '1px solid var(--border)', color: 'var(--text)', display: 'flex', flexDirection: 'column', alignItems: 'center',
                }}>
                  <span style={{ fontSize: 22, fontWeight: 600 }}>{k}</span>
                  <span style={{ fontSize: 9, color: 'var(--text-mute)', letterSpacing: 1, height: 10 }}>{sub}</span>
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 24, marginTop: 16 }}>
              <div style={{ width: 58 }} />
              <button onClick={placeCall} disabled={reg !== 'registered' || !num} style={{
                width: 64, height: 64, borderRadius: '50%', border: 'none', cursor: 'pointer', fontSize: 26,
                background: (reg === 'registered' && num) ? GREEN : 'var(--border-strong)', color: '#fff',
              }}>✆</button>
              <button onClick={() => setNum((n) => n.slice(0, -1))} style={{
                width: 58, height: 58, borderRadius: '50%', border: 'none', background: 'transparent',
                color: 'var(--text-mute)', cursor: 'pointer', fontSize: 22, visibility: num ? 'visible' : 'hidden',
              }}>⌫</button>
            </div>
          </div>
        )}
      </div>

      {/* ---- Recent calls ---- */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ fontSize: 15, fontWeight: 600 }}>Recent calls</div>
          {calls.length > 0 && (
            callSelMode ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 12, color: 'var(--text-mute)' }}>{callSel.size} selected</span>
                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12, color: RED }}
                  disabled={!callSel.size} onClick={deleteSelectedCalls}>Delete</button>
                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                  onClick={() => { setCallSelMode(false); setCallSel(new Set()) }}>Cancel</button>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                  onClick={() => setCallSelMode(true)}>Select</button>
                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12, color: RED }}
                  onClick={clearAllCalls}>Clear all</button>
              </div>
            )
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {calls.length === 0 && <div style={{ fontSize: 13, color: 'var(--text-mute)' }}>No calls yet.</div>}
          {calls.map((c) => {
            const s = (c.status || '').toLowerCase()
            const color = s === 'answered' ? GREEN : (s === 'rejected' || s === 'busy' || s === 'failed') ? RED
              : (s === 'no answer' || s === 'cancelled' || s === 'missed') ? '#eab308' : 'var(--text-dim)'
            const dlabel = c.direction === 'in' ? '↙ Incoming' : '↗ Outgoing'
            const checked = callSel.has(c.id)
            return (
              <div key={c.id} onClick={() => callSelMode && toggleCallSel(c.id)} className="hover-row"
                style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8,
                  fontSize: 13.5, padding: '10px 12px', borderRadius: 10, cursor: callSelMode ? 'pointer' : 'default',
                  background: checked ? 'var(--active)' : 'var(--input-bg)' }}>
                {callSelMode && <input type="checkbox" readOnly checked={checked} style={{ width: 'auto', flexShrink: 0 }} />}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="mono" style={{ fontWeight: 600 }}>{c.peer}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-mute)' }}>{dlabel} · {new Date(c.start_ts * 1000).toLocaleString()}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ color, fontWeight: 600, textTransform: 'capitalize' }}>{c.status || 'ringing'}</span>
                  {!callSelMode && <>
                    <button className="btn btn-ghost" style={{ padding: '5px 10px' }}
                      disabled={reg !== 'registered'} onClick={(e) => { e.stopPropagation(); phone.current?.unlockAudio(); setNum(c.peer); phone.current?.call(c.peer) }}>Call</button>
                    <button className="row-del" title="Delete this call" aria-label="Delete this call"
                      onClick={(e) => deleteOneCall(c.id, e)}>🗑</button>
                  </>}
                </div>
              </div>
            )
          })}
        </div>
      </div>
      </div>
    </div>
  )
}
