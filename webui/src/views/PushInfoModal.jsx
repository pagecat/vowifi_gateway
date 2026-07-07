import React from 'react'

// Explains the outbound push payloads (webhook JSON + Telegram message) so a user can wire
// up a receiver without reading the source. Opened from the info button next to each channel.
const payloadJson = `{
  "event": "incoming_sms",        // or "incoming_call"
  "instance": "1",                // gateway line id
  "sim_name": "TELUS (Canada)",   // line name (may be empty)
  "iccid": "8900000000000000000", // SIM ICCID
  "msisdn": "+15875551234",       // this line's own number (may be "")
  "from": "+14155550001",         // the event's source number
  "text": "Hello there"           // SMS body; null for calls
}`

export default function PushInfoModal({ channel, onClose }) {
  const isTg = channel === 'telegram'
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000a', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50 }}
      onClick={onClose}>
      <div className="card" style={{ padding: 24, width: 620, maxWidth: '94vw', maxHeight: '92vh', overflow: 'auto' }} onClick={(e) => e.stopPropagation()}>
        <h2 style={{ marginTop: 0 }}>{isTg ? 'Telegram push' : 'Webhook push'} — format & notes</h2>

        {!isTg ? (
          <>
            <p style={{ fontSize: 13.5, color: 'var(--text-dim)', lineHeight: 1.6 }}>
              When enabled, the gateway sends an HTTP <b>POST</b> to your URL for each selected
              event. The body is <code>application/json</code> with these fields:
            </p>
            <pre style={{ background: 'var(--sidebar)', border: '1px solid var(--border)', borderRadius: 8,
              padding: '12px 14px', fontSize: 12.5, overflowX: 'auto', lineHeight: 1.5 }}>{payloadJson}</pre>
            <ul style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.7, paddingLeft: 20 }}>
              <li><code>event</code> — <code>incoming_sms</code> or <code>incoming_call</code>.</li>
              <li><code>text</code> — the SMS body for <code>incoming_sms</code>; <code>null</code> for calls.</li>
              <li><code>msisdn</code> — this line's own number; may be empty until learned.</li>
              <li><code>from</code> — the caller / sender number (empty if the caller withheld it).</li>
              <li>Delivery is best-effort with an 8s timeout; a failing endpoint is logged, not retried.</li>
              <li>Self-signed TLS on the target is accepted (certificate not verified).</li>
            </ul>
          </>
        ) : (
          <>
            <p style={{ fontSize: 13.5, color: 'var(--text-dim)', lineHeight: 1.6 }}>
              When enabled, the gateway sends a formatted message to your chat/channel via the
              Telegram Bot API (<code>sendMessage</code>) for each selected event. It carries the
              same core fields as the webhook. Example:
            </p>
            <pre style={{ background: 'var(--sidebar)', border: '1px solid var(--border)', borderRadius: 8,
              padding: '12px 14px', fontSize: 12.5, overflowX: 'auto', lineHeight: 1.5 }}>{`📩 Incoming SMS
SIM: TELUS (Canada) (+15875551234)
From: +14155550001

Hello there`}</pre>
            <p style={{ fontSize: 13, color: 'var(--text-soft)', fontWeight: 600, marginBottom: 4 }}>Setup</p>
            <ul style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.7, paddingLeft: 20 }}>
              <li>Create a bot with <a href="https://t.me/BotFather" target="_blank" rel="noreferrer" style={{ textDecoration: 'underline' }}>@BotFather</a> and copy the <b>bot token</b>.</li>
              <li><b>Chat ID</b>: your own numeric id (from <a href="https://t.me/userinfobot" target="_blank" rel="noreferrer" style={{ textDecoration: 'underline' }}>@userinfobot</a>), or a channel id like <code>-1001234567890</code>.</li>
              <li>Add the bot to the channel/group as a member (and admin, for channels) so it can post.</li>
              <li>Send the bot a message first if pushing to a private chat, so it's allowed to reply.</li>
            </ul>
          </>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 18 }}>
          <button className="btn btn-primary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}
