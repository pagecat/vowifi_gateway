import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../api.js'
import SimSelector from './SimSelector.jsx'

export default function Messages({ selected, subscribe, showToast, instances, cards, setSelected }) {
  const id = selected?.id
  const [threads, setThreads] = useState([])
  const [peer, setPeer] = useState(null)
  const [msgs, setMsgs] = useState([])
  const [text, setText] = useState('')
  const [newTo, setNewTo] = useState('')
  const [sending, setSending] = useState(false)
  const [selMode, setSelMode] = useState(false)      // multi-select messages to delete
  const [selIds, setSelIds] = useState(() => new Set())

  const loadThreads = useCallback(async () => {
    if (!id) return
    try { const r = await api.threads(id); setThreads(r.threads) } catch {}
  }, [id])

  const loadMsgs = useCallback(async (p) => {
    if (!id || !p) return
    try { const r = await api.messages(id, p); setMsgs(r.messages) } catch {}
  }, [id])

  useEffect(() => { loadThreads() }, [loadThreads])
  useEffect(() => { if (peer) loadMsgs(peer) }, [peer, loadMsgs])
  // leaving/refreshing a thread resets the selection UI
  useEffect(() => { setSelMode(false); setSelIds(new Set()) }, [peer])
  // if the open conversation empties (delete/clear), leave select mode so its toolbar
  // (rendered only while msgs.length>0) can't strand the UI in select state.
  useEffect(() => { if (!msgs.length) { setSelMode(false); setSelIds(new Set()) } }, [msgs.length])
  useEffect(() => subscribe((msg) => {
    if (msg.type === 'sms' && msg.instance === id) {
      loadThreads()
      if (peer) loadMsgs(peer)
    }
  }), [subscribe, id, peer, loadThreads, loadMsgs])

  const send = async () => {
    const to = peer || newTo
    if (!to || !text) return
    setSending(true)
    try {
      const res = await api.sendSms(id, to, text)
      setText(''); setPeer(to); setNewTo('')
      await loadThreads(); await loadMsgs(to)
      if (res && res.ok === false) {
        const msg = 'SMS not delivered: ' + (res.error || 'unknown error')
        showToast ? showToast(msg) : alert(msg)
      }
    } catch (e) {
      const msg = 'SMS failed: ' + e.message
      showToast ? showToast(msg) : alert(msg)
    }
    setSending(false)
  }

  const toast = (m) => (showToast ? showToast(m) : null)

  const toggleSel = (mid) => setSelIds((s) => {
    const n = new Set(s); n.has(mid) ? n.delete(mid) : n.add(mid); return n
  })
  // The awaited delete may resolve after the user switched SIM lines — only refresh if
  // we're still on the same line, so we don't write the old line's data into state.
  const refreshIfSame = async (forId, p) => {
    if (forId !== id) return
    await loadThreads(); if (p) await loadMsgs(p)
  }

  const deleteSelected = async () => {
    if (!selIds.size) return
    if (!confirm(`Delete ${selIds.size} selected message${selIds.size > 1 ? 's' : ''}?`)) return
    const forId = id, p = peer
    try {
      await api.deleteMessages(forId, { ids: [...selIds] })
      setSelMode(false); setSelIds(new Set())
      await refreshIfSame(forId, p)
      toast('Messages deleted')
    } catch (e) { toast('Delete failed: ' + e.message) }
  }

  const deleteThread = async (p, e) => {
    if (e) e.stopPropagation()
    if (!confirm(`Delete the entire conversation with ${p}? This removes all its messages.`)) return
    const forId = id
    try {
      await api.deleteMessages(forId, { peer: p })
      if (peer === p) { setPeer(null); setMsgs([]) }
      if (forId === id) await loadThreads()
      toast('Conversation deleted')
    } catch (e2) { toast('Delete failed: ' + e2.message) }
  }

  const clearAll = async () => {
    if (!threads.length) return
    if (!confirm('Delete ALL messages on this line? This cannot be undone.')) return
    const forId = id
    try {
      await api.deleteMessages(forId, { all: true })
      if (forId === id) { setPeer(null); setMsgs([]); await loadThreads() }
      toast('All messages deleted')
    } catch (e) { toast('Delete failed: ' + e.message) }
  }

  if (!id) return (
    <div>
      <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} />
      <div style={{ color: 'var(--text-dim)' }}>Select a SIM / line to view and send messages.</div>
    </div>
  )

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ flexShrink: 0 }}>
        <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gridTemplateRows: 'minmax(0, 1fr)', gap: 16, flex: 1, minHeight: 0 }}>
      <div className="card" style={{ padding: 12, overflow: 'auto', minHeight: 0 }}>
        <button className="btn btn-primary" style={{ width: '100%', marginBottom: 8 }} onClick={() => { setPeer(null); setMsgs([]) }}>+ New message</button>
        {threads.length > 0 &&
          <button className="btn btn-ghost" style={{ width: '100%', marginBottom: 10, color: '#ef4444', fontSize: 12 }}
            onClick={clearAll}>Clear all conversations</button>}
        {threads.map((t) => (
          <div key={t.peer} onClick={() => setPeer(t.peer)} className="hover-row"
            style={{ padding: 10, borderRadius: 10, cursor: 'pointer', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 8,
              background: peer === t.peer ? 'var(--active)' : 'transparent' }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 14 }} className="mono">{t.peer}</div>
              <div style={{ fontSize: 12, color: 'var(--text-mute)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.last_body}</div>
            </div>
            <button className="row-del" title="Delete conversation" aria-label={`Delete conversation with ${t.peer}`}
              onClick={(e) => deleteThread(t.peer, e)}>🗑</button>
          </div>
        ))}
        {threads.length === 0 && <div style={{ color: 'var(--text-mute)', fontSize: 13, padding: 8 }}>No conversations yet.</div>}
      </div>

      <div className="card" style={{ display: 'flex', flexDirection: 'column', padding: 0, minHeight: 0 }}>
        <div style={{ padding: 14, borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          {peer ? <span className="mono" style={{ fontWeight: 600, flex: 1 }}>{peer}</span>
            : <input placeholder="Recipient number e.g. +1..." value={newTo} onChange={(e) => setNewTo(e.target.value)} style={{ maxWidth: 300, flex: 1 }} />}
          {peer && msgs.length > 0 && (
            selMode ? (
              <>
                <span style={{ fontSize: 12, color: 'var(--text-mute)' }}>{selIds.size} selected</span>
                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12, color: '#ef4444' }}
                  disabled={!selIds.size} onClick={deleteSelected}>Delete</button>
                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                  onClick={() => { setSelMode(false); setSelIds(new Set()) }}>Cancel</button>
              </>
            ) : (
              <>
                <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }}
                  onClick={() => setSelMode(true)}>Select</button>
                <button className="btn btn-ghost" title="Delete conversation" style={{ padding: '4px 10px', fontSize: 12, color: '#ef4444' }}
                  onClick={() => deleteThread(peer)}>Delete all</button>
              </>
            )
          )}
        </div>
        <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {msgs.map((m) => {
            const failed = m.status === 'failed'
            const checked = selIds.has(m.id)
            return (
              <div key={m.id} onClick={() => selMode && toggleSel(m.id)}
                style={{ alignSelf: m.direction === 'out' ? 'flex-end' : 'flex-start', maxWidth: '74%',
                  cursor: selMode ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 8,
                  flexDirection: m.direction === 'out' ? 'row-reverse' : 'row' }}>
                {selMode && <input type="checkbox" readOnly checked={checked} style={{ width: 'auto', flexShrink: 0 }} />}
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6,
                    flexDirection: m.direction === 'out' ? 'row' : 'row-reverse' }}>
                    {failed && <span title={m.error || 'Delivery failed'}
                      style={{ color: '#ef4444', fontWeight: 800, cursor: 'help', fontSize: 15 }}>❗</span>}
                    <div style={{
                      background: checked ? 'var(--active)' : failed ? 'rgba(239,68,68,.15)' : (m.direction === 'out' ? 'var(--primary)' : 'var(--hover)'),
                      border: failed ? '1px solid rgba(239,68,68,.55)' : '1px solid transparent',
                      padding: '8px 12px', borderRadius: 12, fontSize: 14,
                    }}>{m.body}</div>
                  </div>
                  <div style={{ fontSize: 10, color: failed ? '#ef4444' : 'var(--text-mute)',
                    textAlign: m.direction === 'out' ? 'right' : 'left', marginTop: 2 }}>
                    {new Date(m.ts * 1000).toLocaleString()}
                    {failed ? ' · Failed to deliver' : m.status === 'pending' ? ' · sending…' : ''}
                  </div>
                  {failed && m.error && (
                    <div style={{ fontSize: 10.5, color: '#ef4444', marginTop: 1,
                      textAlign: m.direction === 'out' ? 'right' : 'left', maxWidth: 280 }}>{m.error}</div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
        <div style={{ display: 'flex', gap: 8, padding: 12, borderTop: '1px solid var(--border)', flexShrink: 0 }}>
          <input placeholder="Type a message…" value={text} onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()} />
          <button className="btn btn-primary" disabled={sending || (!peer && !newTo)} onClick={send}>Send</button>
        </div>
      </div>
      </div>
    </div>
  )
}
