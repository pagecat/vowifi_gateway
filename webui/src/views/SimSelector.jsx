import React, { useEffect } from 'react'

// Per-page SIM/line picker for multi-SIM setups. Labels each line with the physical reader
// it currently occupies (from the detected-cards state) so it's clear which reader's engine
// (docker container) will handle calls/SMS/logs. Switches the global `selected` instance.
//
// Only lines whose physical reader is currently PRESENT are listed — a provisioned line
// whose reader/card is unplugged is dropped from the dropdown (its config stays under SIM
// Config and it reappears when the reader returns).
export default function SimSelector({ instances = [], cards = [], selected, setSelected, label = 'Active SIM / line' }) {
  // A present card that maps to this line (by matched id or ICCID) means its reader is here.
  const readerFor = (i) => cards.find((c) => c.present &&
    (String(c.matched) === String(i.id) || (c.iccid && c.iccid === i.iccid)))
  const live = instances.filter((i) => readerFor(i))

  // If the currently-selected line's reader just went away, move selection to the first
  // still-present line (or clear it) so no view stays pinned to a vanished reader.
  const id = selected?.id
  useEffect(() => {
    if (id && !live.some((i) => i.id === id)) setSelected(live[0]?.id || null)
  }, [id, live.map((i) => i.id).join(',')])  // eslint-disable-line react-hooks/exhaustive-deps

  if (!live.length) return null
  return (
    <div className="card" style={{ padding: '10px 14px', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 12 }}>
      <span style={{ fontSize: 12, color: 'var(--text-mute)', whiteSpace: 'nowrap' }}>{label}</span>
      <select value={id || ''} onChange={(e) => setSelected(e.target.value)} style={{ flex: 1, maxWidth: 460 }}>
        {!id && <option value="">— select —</option>}
        {live.map((i) => {
          const c = readerFor(i)
          const rd = c ? `Reader ${c.index}` : null
          const st = i.status?.label ? ` — ${i.status.label}` : ''
          return <option key={i.id} value={i.id}>{rd ? `${rd} · ` : ''}{i.name || i.imsi}{st}</option>
        })}
      </select>
      {live.length === 1 && <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>only line</span>}
    </div>
  )
}
