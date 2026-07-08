// Browser softphone: JsSIP UA over WSS to the engine's Asterisk WebRTC transport.
import JsSIP from 'jssip'

// Surface JsSIP internals in the console to aid troubleshooting (registration, ICE, etc.)
try { JsSIP.debug.enable('JsSIP:*') } catch {}

export class Softphone {
  // audioEl: a persistent <audio> element rendered by React and handed in via ref. Using one
  // stable, DOM-attached element (instead of a per-call `new Audio()`) is what makes remote
  // audio reliable under Chrome/Edge autoplay policy: the element is primed once inside a user
  // gesture (unlockAudio) and then every later srcObject swap plays without a NotAllowedError.
  constructor(onEvent, audioEl) {
    this.onEvent = onEvent            // (type, data) => void
    this.ua = null
    this.session = null
    this.remoteAudio = audioEl || null
    this._dead = false                // set true by stop() to inert late JsSIP events
    this._unlocked = false
    this._rec = null
    this._recCtx = null
    this._recChunks = []
  }

  // A stopped Phone must never emit again. JsSIP's ua.stop() fires 'disconnected' (and possibly
  // 'unregistered') ASYNCHRONOUSLY, ~1s later. When the user switches lines we stop the old Phone
  // and immediately start a new one for the other reader; without this guard the OLD ua's late
  // 'disconnected' bleeds into the component's shared setReg and flips the already-registered new
  // line to red "disconnected". Gate every emit on _dead so a torn-down Phone is inert.
  emit(type, data) { if (this._dead) return; try { this.onEvent(type, data) } catch {} }

  // Point the class at the React-owned <audio> element. Called from the component's ref effect.
  setAudioEl(el) { if (el) this.remoteAudio = el }

  ensureAudio() {
    // Fallback only: if no element was injected (shouldn't happen in the React app), create a
    // hidden, DOM-attached one so audio can still render.
    if (!this.remoteAudio) {
      const el = new Audio()
      el.autoplay = true
      el.setAttribute('playsinline', '')
      el.style.display = 'none'
      try { document.body.appendChild(el) } catch {}
      this.remoteAudio = el
    }
    return this.remoteAudio
  }

  // Prime the sink INSIDE a user gesture (Call / Answer / Connect click). Playing the element
  // (even empty) while the page has transient activation marks it user-activated; every later
  // play() on this SAME element then resolves, defeating the autoplay policy. Must be called
  // synchronously from the click handler — do not await anything before it.
  unlockAudio() {
    if (this._unlocked) return
    const el = this.ensureAudio()
    try {
      el.muted = true
      const p = el.play()
      if (p && p.then) p.then(() => { try { el.pause(); el.currentTime = 0 } catch {} el.muted = false })
                        .catch(() => { el.muted = false })
      else { try { el.pause() } catch {}; el.muted = false }
      this._unlocked = true
    } catch { el.muted = false }
  }

  // Attach a remote MediaStream to the audio element and force playback. The element was
  // primed by unlockAudio() on the click, so play() should resolve; we keep the catch as
  // telemetry + arm a one-time gesture retry as a last resort.
  attachRemote(stream) {
    if (!stream) return
    const el = this.ensureAudio()
    if (el.srcObject !== stream) el.srcObject = stream
    el.muted = false
    el.volume = 1
    const p = el.play()
    if (p && p.catch) p.catch((err) => {
      this.emit('audioblocked', (err && err.name) || 'play-failed')
      const resume = () => { el.play().finally(() => {
        document.removeEventListener('click', resume, true)
        document.removeEventListener('touchend', resume, true)
      }) }
      document.addEventListener('click', resume, true)
      document.addEventListener('touchend', resume, true)
    })
  }

  // prov: { username, password, ws_port, host, realm }
  start(prov, host) {
    if (this.ua) this.stop()
    const wsUrl = `wss://${host}:${prov.ws_port}/ws`
    const socket = new JsSIP.WebSocketInterface(wsUrl)
    const domain = prov.domain || host
    this.ua = new JsSIP.UA({
      sockets: [socket],
      uri: `sip:${prov.username}@${domain}`,
      password: prov.password,
      register: true,
      session_timers: false,
      contact_uri: `sip:${prov.username}@${domain};transport=wss`,
    })
    this.ua.on('connected', () => this.emit('ws', 'connected'))
    this.ua.on('disconnected', () => this.emit('ws', 'disconnected'))
    this.ua.on('registered', () => this.emit('registered', true))
    this.ua.on('unregistered', () => this.emit('registered', false))
    this.ua.on('registrationFailed', (e) => this.emit('regfail', (e && e.cause) || 'failed'))
    this.ua.on('newRTCSession', (e) => this.handleSession(e))
    this.ua.start()
  }

  handleSession(e) {
    const session = e.session
    // If already in a call, reject any second incoming session as busy.
    if (this.session && this.session !== session) {
      if (session.direction === 'incoming') { try { session.terminate({ status_code: 486 }) } catch {} }
      return
    }
    this.session = session
    // Idempotency guard: an outgoing call reaches here twice (once from call(), once from
    // the UA's 'newRTCSession' for the same session). Binding listeners twice would double
    // -fire events; bind exactly once per session.
    if (session.__vowifiBound) return
    session.__vowifiBound = true
    const dir = session.direction  // 'incoming' | 'outgoing'
    if (dir === 'incoming') {
      const from = (session.remote_identity && session.remote_identity.uri && session.remote_identity.uri.user) || 'Unknown'
      this.emit('incoming', { from })
    }
    session.on('progress', () => this.emit('progress'))
    session.on('accepted', () => { this.emit('active'); this.attachFromSession(session) })
    session.on('confirmed', () => { this.emit('active'); this.attachFromSession(session) })
    // 'ended' (BYE received/sent) and 'failed' (setup error / non-2xx) are the terminal
    // events. Always null the session and tell the view so the UI resets to idle even if
    // only one of them fires.
    session.on('ended', (d) => { if (this.session === session) this.session = null; this.emit('ended', { cause: d && d.cause }) })
    session.on('failed', (d) => { if (this.session === session) this.session = null; this.emit('failed', { cause: d && d.cause }) })
    session.on('peerconnection', (ev) => {
      const pc = ev.peerconnection
      // ontrack fires as the remote audio track arrives. te.streams[0] is the usual source,
      // but some stacks deliver a track with no stream — fall back to wrapping the track.
      pc.ontrack = (te) => {
        const stream = (te.streams && te.streams[0]) || new MediaStream([te.track])
        this.attachRemote(stream)
      }
      // Belt-and-suspenders: if a remote track is already present (ontrack raced/missed),
      // build a stream from the receivers so audio still renders.
      const grab = () => {
        try {
          const tracks = pc.getReceivers().map((r) => r.track).filter((t) => t && t.kind === 'audio')
          if (tracks.length) this.attachRemote(new MediaStream(tracks))
        } catch {}
      }
      pc.addEventListener && pc.addEventListener('connectionstatechange', () => {
        if (pc.connectionState === 'connected') grab()
      })
    })
  }

  // Most reliable remote-audio path: once the call is accepted/confirmed, read the remote
  // audio track straight off the session's RTCPeerConnection receivers and play it. This does
  // not depend on the 'peerconnection'/ontrack event having fired in time (the observed
  // failure was hasStream:false — ontrack never attached), and the server has confirmed RTP
  // is flowing, so a receiver track is present here.
  attachFromSession(session) {
    try {
      const pc = session && session.connection
      if (!pc) return
      const tracks = pc.getReceivers().map((r) => r.track).filter((t) => t && t.kind === 'audio')
      if (tracks.length) this.attachRemote(new MediaStream(tracks))
    } catch {}
  }

  call(number) {
    if (!this.ua) return
    const domain = this.ua.configuration.uri.host
    const opts = {
      mediaConstraints: { audio: true, video: false },
      pcConfig: { rtcpMuxPolicy: 'require', iceServers: [] },
    }
    this.emit('calling', { to: number })
    try {
      this.session = this.ua.call(`sip:${number}@${domain}`, opts)
      this.handleSession({ session: this.session })
    } catch (err) {
      // ua.call() can throw synchronously (bad target, no media, etc.) before any session
      // event fires — surface it as a terminal 'failed' so the UI doesn't hang on "calling".
      this.session = null
      this.emit('failed', { cause: (err && err.message) || 'Call failed' })
    }
  }

  answer() {
    if (this.session) {
      this.session.answer({ mediaConstraints: { audio: true, video: false }, pcConfig: { iceServers: [] } })
    }
  }

  hangup() {
    const s = this.session
    if (s) {
      this.session = null
      try { s.terminate() } catch {}
    }
  }

  // Reject an un-answered INCOMING call. JsSIP's bare terminate() on a ringing incoming
  // session sends 480 Temporarily Unavailable, which Asterisk's Dial maps to NOANSWER →
  // the call is logged as "missed". Sending 603 Decline makes the disposition "rejected"
  // (declined) as the user intended. Falls back to hangup() for an outgoing/active session.
  reject() {
    const s = this.session
    if (!s) return
    if (s.direction === 'incoming' && !s.isEstablished?.()) {
      this.session = null
      try { s.terminate({ status_code: 603, reason_phrase: 'Decline' }) } catch { try { s.terminate() } catch {} }
    } else {
      this.hangup()
    }
  }

  sendDTMF(tone) { if (this.session) try { this.session.sendDTMF(tone) } catch {} }

  setMuted(muted) {
    if (!this.session) return
    try { muted ? this.session.mute({ audio: true }) : this.session.unmute({ audio: true }) } catch {}
  }

  // ---- call recording: mix local mic + remote audio and record to a downloadable blob ----
  async startRecording() {
    if (!this.session || !this.session.connection || this._rec) return false
    const pc = this.session.connection
    const Ctx = window.AudioContext || window.webkitAudioContext
    const ctx = new Ctx()
    const dest = ctx.createMediaStreamDestination()
    const local = pc.getSenders().map((s) => s.track).filter((t) => t && t.kind === 'audio')
    const remote = pc.getReceivers().map((r) => r.track).filter((t) => t && t.kind === 'audio')
    if (local.length) try { ctx.createMediaStreamSource(new MediaStream(local)).connect(dest) } catch {}
    if (remote.length) try { ctx.createMediaStreamSource(new MediaStream(remote)).connect(dest) } catch {}
    this._recChunks = []
    try {
      this._rec = new MediaRecorder(dest.stream)
    } catch { try { ctx.close() } catch {}; return false }
    this._recCtx = ctx
    this._rec.ondataavailable = (ev) => { if (ev.data && ev.data.size) this._recChunks.push(ev.data) }
    this._rec.start()
    return true
  }

  stopRecording() {
    return new Promise((resolve) => {
      if (!this._rec) { resolve(null); return }
      this._rec.onstop = () => {
        const blob = new Blob(this._recChunks, { type: this._rec ? this._rec.mimeType : 'audio/webm' })
        try { this._recCtx.close() } catch {}
        this._rec = null; this._recCtx = null; this._recChunks = []
        resolve(blob)
      }
      try { this._rec.stop() } catch { resolve(null) }
    })
  }

  get recording() { return !!this._rec }

  stop() {
    // Mark dead FIRST so any late JsSIP event from ua.stop() (async 'disconnected'/'unregistered')
    // is swallowed by emit() and cannot clobber a newly-started line's state.
    this._dead = true
    this.hangup()
    if (this._rec) { try { this._rec.stop() } catch {}; this._rec = null }
    if (this.ua) { try { this.ua.stop() } catch {} this.ua = null }
    if (this.remoteAudio) {
      try { this.remoteAudio.srcObject = null; this.remoteAudio.remove() } catch {}
      this.remoteAudio = null
    }
  }
}
