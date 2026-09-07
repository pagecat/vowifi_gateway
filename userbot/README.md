# Telegram userbot: calls in and out

Bridges a Telegram 1-on-1 voice call to a SIM line. You dial `/call 12345`, the
userbot rings **you** on Telegram, and once you answer it dials the number over
the gateway. Incoming calls to the SIM ring your Telegram at the same time as
every other extension. It answers for as many SIMs as you give it, and takes
orders from as many Telegram accounts as you authorise.

A **bot** account cannot be in a voice call — only a real user account can, over
MTProto. That is the whole reason this is a separate thing from the Telegram bot
built into the control plane.

## Status

Calls work in both directions on real hardware, on two SIMs at once, with audio
both ways. The table at the bottom says what that covers and what it does not.

Getting there took a run of bugs that shared one nasty property: **the logs look
healthy while the call carries no audio**, or the call connects and dies twenty
seconds later. If you change any of this and a call goes quiet, read "If a call
is silent" below before you suspect the network — every one of those failures
was in this code, not on the wire.

## Optional: prove Telegram audio on its own

`spike_echo.py` puts a Telegram call through with no SIP involved and echoes you
back to yourself. Setup is done in Settings now, so this is a debugging tool
rather than a first step: reach for it when audio is broken and you want to know
which half is at fault.

```bash
cd userbot
pip install -r requirements.txt          # ntgcalls + telethon; PJSIP not needed yet
cp config.example.json config.json       # api_id, api_hash, phone, owner_id
python spike_echo.py
```

If the config was saved from **Settings → Telegram calls**, it already lives on
the data volume. Login with that file instead of a local copy:

```bash
docker run --rm -it -v /path/to/data/userbot:/data/userbot \
  vowifi/userbot python spike_echo.py
```

Get `api_id` / `api_hash` from <https://my.telegram.org/apps> and your numeric
`owner_id` from [@userinfobot](https://t.me/userinfobot). The first run asks for
the login code Telegram sends you; after that the session is cached.

Now call that account from your phone and talk. **You should hear yourself.**
On hangup the script prints a verdict with frame counts.

Answer from a phone or the desktop client. Telegram Web A negotiates a protocol
version ntgcalls does not speak, and the call simply will not connect.

### If a call is silent

A call that connects and carries nothing looks like a network problem and never
is. Every item here has actually happened. PJSIP's own RTP counters, printed
when a call ends, tell you which direction died: `RX` is what arrived from
Asterisk, `TX` is what we sent it. Zero on one side names the half to look at.

1. **PLAYBACK attached too early.** It must come *after* `connect_p2p`, not
   before. In `telegram_call.py` that is `_go_live()`.
2. **Wrong slot.** Inbound frames arrive on the microphone device with
   `mode=PLAYBACK`. It reads backwards and it is correct.
3. **Frames are objects.** `ntgcalls.Frame` carries `ssrc`, `data`,
   `frame_data`; the audio is `frame.data`. `bytes(frame)` raises, and dropping
   every inbound frame that way is a one-way call, not an obvious failure.
4. **Outbound went quiet.** The sender thread must push a frame every 10 ms from
   the moment the call is up, silence included. If it stops, inbound never opens
   and Telegram drops the call after a few seconds. Watch for
   `send_external_frame failed` in the log.
5. **Frame size.** 480 samples = 960 bytes = 10 ms. 20 ms frames are a common
   assumption and they break the sender.
6. **Media bound while still ringing.** An answered inbound call renegotiates on
   our own 200 OK and `onCallMediaState` does not fire again, so the bridge port
   has to be bound again on `CONFIRMED` or whichever direction lost the race
   stays on the dead early media.
7. **TX near zero with no error.** PJSIP suppresses silence, so a starved bridge
   port shows up as a handful of packets rather than none — 34 packets across
   fifteen seconds is silence, not a quiet talker.

Background: [pytgcalls/ntgcalls#44](https://github.com/pytgcalls/ntgcalls/issues/44).
The ordering and slot rules come from the comment dated 2026-07 there and from
[TxPKev/p2p-offline-ai-telegram-bridge](https://github.com/TxPKev/p2p-offline-ai-telegram-bridge),
which reports bidirectional audio on unpatched ntgcalls 2.1.0. These are
community findings, not documented API — hence this step.

## Setup, and the SIP side

Nothing in the engine image changes: the inbound dialplan already rings every
external account, and an INVITE from one lands in `from-local`, which hairpins
it to the IMS trunk.

**Settings → Telegram calls (userbot)** is the whole setup. Fill API id / hash,
the spare account's phone, and your numeric user id; add a card per SIM and, if
you want, further Telegram ids to authorise. Then press **Start**. That one
action builds `vowifi/userbot` if the image is missing (PJSIP compile; the page
shows the log), creates each card's SIP account on its line if it is missing,
sends the Telegram login code, and starts the sidecar once you type the code
(and 2FA password, if asked) in the same card.

Both directions are plain files on the shared volume; the control plane never
talks to this container, it only asks Docker to run it (and, for first login,
uses Telethon in the manager to write the session file). Config is read once at
startup, so Restart is what applies a change. Restart recreates the container,
which costs nothing: the session and the config live on the volume, not in it.

The login code is entered in Settings. A detached container has no stdin, so
Start will not launch the sidecar until a session exists. `spike_echo.py` remains
as a no-SIP audio probe if you want it.

By hand, if you would rather:

```bash
docker run -d --name vowifi-userbot --network host \
  -v /path/to/data/userbot:/data/userbot \
  vowifi/userbot
```

Host networking is the simple option because the SIP leg needs to reach the
engine's SIP port and receive RTP.

Then, in order: registration comes up (`SIP registration: up` in the log),
`/call <number>` places a call, an inbound call to the SIM rings Telegram, and
`/dtmf 1234` sends tones mid-call.

## Commands

`owner_id` plus anything in `owner_ids` is obeyed, each in their own private
chat. Anything else is ignored without a reply. Permissions are flat: everyone
listed may dial on every card, and one call runs at a time.

- `/call <number> [line]` — rings *you* first, dials once you answer
- `/use <line>` — the card your `/call` uses from now on, remembered per account
- `/lines` — the cards, whether each is registered, and who answers it
- `/dtmf <digits>` — multi-digit, PJSUA2 handles the inter-digit timing
- `/hangup`

`dial_allowlist` in the config restricts what may be dialled. This process can
place calls, so if the set of numbers is predictable, pin it down.

The gateway's own notification bot is a different account in a different chat,
so neither ever sees the other's messages. Send it `/call` and it will point you
here; send this one `/status` or `/esim` and it points you back. Note that its
`/use` and `/lines` pick the line SMS and line control act on, while these pick
the SIM to dial from — same names, different scope.

An inbound call is announced in chat before the phone rings, because the
Telegram call itself only names the userbot: the message is what tells you who
is actually calling and which SIM they dialled. One arriving while you are
already talking is reported as missed rather than dropped silently.

When a call is over, whoever was on it gets a summary: the number, the card, the
time it started, how long it took to connect, and how long you talked. A call
nobody took is reported too — for an inbound one that is the only trace the SIM
rang at all. Times are the gateway's own, because the container mounts the
host's `/etc/localtime`.

## Cards

Each entry in `cards` is one SIM the userbot answers for:

```json
{"line": "1", "sip_user": "tgbridge", "answer_owner": 0}
```

`answer_owner` is who gets rung when that SIM receives a call; `0` means the
primary account. **SIP usernames must differ between lines.** Every account is
registered from one PJSUA2 endpoint, and two accounts sharing a
`sip:user@host` identity make an inbound call ambiguous — PJSIP hands it to
whichever it matches first, which may be the wrong SIM. The control plane
refuses a name another line already uses.

A config from before multi-card, carrying a single `sip_line`/`sip_user` pair,
is read as one card with that same username.

## Why it is built this way

**A normal SIP account, not WebRTC.** The browser softphone's WSS endpoint has
exactly one account; registering there would kick the browser softphone off, and
adding a second endpoint means changing the engine templates. External accounts
are already a supported concept and already ring on inbound.

**PJSUA2 rather than raw RTP.** Setting the endpoint clock to 48 kHz makes PJSIP
hand us 48 kHz PCM directly — the rate Telegram wants — while it transcodes to
ulaw on the wire itself. No resampling code of our own, which matters since
Python 3.13 dropped `audioop`. Nothing is lost: the IMS trunk is
`disallow=all / allow=amr`, so the ceiling is narrowband either way. DTMF comes
free with `dialDtmf`.

**Ring the owner before touching the SIP leg.** Outbound, dialling first would
make the callee hear silence while you are still reaching for your phone.
Inbound, we send 180 Ringing and only answer once you pick up — answering
immediately would stop every other extension ringing and quietly make the
userbot the only phone in the house.

## Risks worth knowing

- **Automated user accounts are a grey area on Telegram.** Use a dedicated
  spare account, not your main one.
- **The session file is the account.** It lives on the mounted volume and never
  in the image. Anyone who takes it has the account.
- **This process can dial.** Hence the separate owner check and allow-list here
  rather than trusting the control-plane bot's switches.
- **Two hops of latency.** Telegram P2P plus the IMS tunnel; expect noticeably
  more delay than an ordinary call.

## What is verified and what is not

Exercised on the gateway, two SIMs live, each on its own engine:

| Part | Basis |
| --- | --- |
| Outbound `/call`, both cards | placed, answered, audio both ways, hung up from either end |
| Inbound to either SIM | announced, rang, answered, 200 OK on the SIP leg, audio both ways |
| `/dtmf` mid-call | tones reached the far end |
| Registration | both cards `200 OK`, re-registering on their own timers |
| Card isolation | each line's Asterisk holds only its own account; a call on one card survives another card ringing |

Not covered:

| Part | Why |
| --- | --- |
| Long calls, concurrent calls, quality beyond "we could hold a conversation" | not measured |
| More than two cards | never tried |
| A second authorised account actually driving it | the code paths run, but one person did all the testing |
