import React, { useEffect, useState, useCallback, useMemo } from 'react'
import { api } from '../api.js'
import SimSelector from './SimSelector.jsx'

// Map ANSI SGR color codes to on-theme colors.
const FG = {
  30: '#475569', 31: '#ef4444', 32: '#22c55e', 33: '#eab308', 34: '#3b82f6',
  35: '#a855f7', 36: '#06b6d4', 37: 'var(--text)',
  90: '#64748b', 91: '#f87171', 92: '#4ade80', 93: '#facc15', 94: '#60a5fa',
  95: '#c084fc', 96: '#22d3ee', 97: 'var(--text)',
}

// Parse a string containing ANSI SGR escapes (e.g. "\x1b[1;32mDEBUG\x1b[0m[153]: ")
// into an array of styled React spans. Tolerates a missing ESC byte.
function ansi(text) {
  const out = []
  let style = {}
  let key = 0
  const re = /\x1b?\[([0-9;]*)m/g
  let last = 0
  let m
  const push = (t) => { if (t) out.push(<span key={key++} style={{ ...style }}>{t}</span>) }
  while ((m = re.exec(text)) !== null) {
    push(text.slice(last, m.index))
    const codes = m[1].split(';').filter((s) => s !== '').map(Number)
    if (codes.length === 0) style = {}
    for (const c of codes) {
      if (c === 0) style = {}
      else if (c === 1) style = { ...style, fontWeight: 700 }
      else if (c === 3) style = { ...style, fontStyle: 'italic' }
      else if (c === 4) style = { ...style, textDecoration: 'underline' }
      else if (FG[c]) style = { ...style, color: FG[c] }
    }
    last = re.lastIndex
  }
  push(text.slice(last))
  return out
}

export default function Logs({ selected, instances, cards, setSelected }) {
  const id = selected?.id
  const [logs, setLogs] = useState({ engine: '', charon: '' })
  const [tab, setTab] = useState('engine')
  const [auto, setAuto] = useState(true)

  const load = useCallback(async () => {
    if (!id) return
    try { setLogs(await api.logs(id, 400)) } catch {}
  }, [id])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!auto) return
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [auto, load])

  const rendered = useMemo(() => ansi(logs[tab] || '(empty)'), [logs, tab])

  if (!id) return (
    <div>
      <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} label="Show logs for" />
      <div style={{ color: 'var(--text-dim)' }}>Select a SIM / line to view its engine and IKE logs.</div>
    </div>
  )

  return (
    <div>
      <SimSelector instances={instances} cards={cards} selected={selected} setSelected={setSelected} label="Show logs for" />
      <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
        {['engine', 'charon'].map((t) => (
          <button key={t} className={`btn ${tab === t ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setTab(t)}>
            {t === 'engine' ? 'Asterisk / engine' : 'strongSwan (IKE)'}
          </button>
        ))}
        <button className="btn btn-ghost" onClick={load}>Refresh</button>
        <label style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" style={{ width: 'auto' }} checked={auto} onChange={(e) => setAuto(e.target.checked)} /> auto
        </label>
      </div>
      <pre className="mono card" style={{
        padding: 16, fontSize: 12, lineHeight: 1.5, overflow: 'auto',
        height: 'calc(100vh - 200px)', whiteSpace: 'pre-wrap', color: 'var(--text-soft)',
        background: 'var(--input-bg)',
      }}>
        {rendered}
      </pre>
    </div>
  )
}
