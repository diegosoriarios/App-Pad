# AirPad Protocol Specification v2

## Overview
AirPad pairs an Android phone (GATT **Server / Peripheral**) with a Mac (GATT **Client / Central**) over BLE, then streams trackpad gestures over an **encrypted** channel. All gesture traffic is protected by an AES-256-GCM session established through one of two handshakes:

* **Pairing** — first contact, authenticated by a one-time secret delivered out-of-band (QR code shown on the Mac, scanned by the phone; or a 6-digit PIN shown on the Mac, typed on the phone).
* **Reconnect** — subsequent connections, authenticated by the long-term P-256 identity keys exchanged during pairing.

The Android device acts as the GATT server and advertises the AirPad Service. The Mac connects, discovers the single characteristic, and uses it **bidirectionally**:

* Mac → Android: **writes** chunked control frames (Write-With-Response).
* Android → Mac: **notifications** of chunked control frames (handshake) and encrypted traffic frames (gestures).

---

## UUIDs
* **AirPad Service UUID:** `9A3B0001-1234-4567-89AB-CDEF01234567`
* **Data Characteristic UUID:** `9A3B0002-1234-4567-89AB-CDEF01234567`
  * **Properties:** `WRITE` (`0x08`), `NOTIFY` (`0x10`), `READ`
  * **Permissions:** Write (paired central), Read / Client Characteristic Configuration Descriptor (CCCD: `0x2902`)

---

## 1. Fragmentation layer

All bytes on the characteristic — handshake messages **and** traffic frames — use the same chunk header:

| Byte Offset | Field | Size | Description |
|---|---|---|---|
| `0` | `type` | 1 | Frame type (`0x10` traffic, `0x21`–`0x27` control). |
| `1` | `ctrl` | 1 | Bit 7 = last chunk (`0x80`). Bits 0–6 = chunk length in bytes. |
| `2…` | `chunk` | `ctrl & 0x7F` | Payload fragment. |

* **`CHUNK_SIZE = 18`** → max on-wire frame = 20 bytes, which fits the default 20-byte ATT payload at MTU 23 **without MTU negotiation**. Implementations may use a larger chunk size after the central requests a bigger MTU, but receivers must accept 18.
* A message with an empty payload is still sent as one frame with `ctrl = 0x80`.
* The `Defragmenter` accumulates fragments **per `type` byte** and returns the reassembled payload when the frame with bit 7 set arrives. Malformed frames (`length` ≠ remaining bytes) are dropped.
* Encrypted traffic frames are always exactly 36 bytes (see §5) and are therefore a single unfragmented frame at MTU ≥ 39.

---

## 2. Cryptographic primitives

| Primitive | Choice |
|---|---|
| Key agreement | ECDH P-256 (`secp256r1`) |
| Public-key encoding | x9.63 uncompressed: `0x04 ‖ X(32) ‖ Y(32)` = **65 bytes** |
| KDF | HKDF-SHA256 (`ikm`, `salt`, `info`, `length`) |
| MAC | HMAC-SHA256 |
| AEAD | AES-256-GCM, 12-byte nonce, 16-byte tag |
| Randomness | `SecRandomCopyBytes` / `SecureRandom` |

---

## 3. Key schedule

### 3.1 Session secrets
Every handshake produces a 96-byte HKDF output split into three 32-byte keys:

```
[ verifyKeyA (32) | verifyKeyM (32) | session (32) ]
```

* `verifyKeyA` — HMAC key for the **Android** verification tag.
* `verifyKeyM` — HMAC key for the **Mac** verification tag.
* `session` — master secret for traffic-key derivation.

**Pairing** (`info = "AirPad v2 pairing"`):

```
Z1 = ECDH(A_eph, M_eph)          // both ephemeral
Z2 = ECDH(A_lt,  M_lt)           // both long-term identity keys
ikm = Z1 ‖ Z2
okm = HKDF-SHA256(ikm, salt = transcript, info, 96)
```

**Reconnect** (`info = "AirPad v2 reconnect"`):

```
Z1 = ECDH(A_eph, M_eph)
Z2 = ECDH(A_lt,  M_eph)          // phone identity × Mac ephemeral
Z3 = ECDH(A_eph, M_lt)           // phone ephemeral × Mac identity
ikm = Z1 ‖ Z2 ‖ Z3
okm = HKDF-SHA256(ikm, salt = transcript, info, 96)
```

### 3.2 OTP binding (pairing only)
The base secret is mixed with the out-of-band secret so a MITM without it derives different keys and fails both tag checks:

```
bound = HKDF-SHA256(base.session ‖ OTP, salt = transcript,
                    info = "AirPad v2 otp-bind", 96)
```

The OTP is either the 16 random bytes embedded in the QR payload, or — identically on both sides — the PIN fallback:

```
OTP = SHA-256("AirPadPIN" ‖ UTF8(pin))[0..16]
```

Both candidates are computed on the Mac (QR OTP and PIN OTP); the phone's verify tag is checked against each candidate.

### 3.3 Transcripts
The transcript is a SHA-256 digest of the raw handshake payloads (reassembly payloads **without** the chunk headers):

```
pairing:   transcript = SHA-256( 0x21_payload ‖ 0x22_payload )
reconnect: transcript = SHA-256( 0x25_payload ‖ 0x26_payload )
```

### 3.4 Verification tags

```
tagA = HMAC-SHA256(verifyKeyA, 0x41 ‖ transcript)   // sent by Android
tagM = HMAC-SHA256(verifyKeyM, 0x4D ‖ transcript)   // sent by Mac
```

Comparison is constant-time.

### 3.5 Traffic keys
Derived once per session from the (possibly OTP-bound) `session` secret:

```
a2m = HKDF-SHA256(session, salt = "AirPad-traffic", info = 0x01, 32)
m2a = HKDF-SHA256(session, salt = "AirPad-traffic", info = 0x02, 32)
```

---

## 4. Control messages

Every payload starts with a **`minor` version byte** (currently `0x02`); receivers reject messages whose minor differs. Strings are `[len u8][UTF-8 bytes ≤ 255]`.

| Type | Direction | Name |
|---|---|---|
| `0x21` | A → M | Pairing Request |
| `0x22` | M → A | Pairing Response |
| `0x23` | A → M | Verify A |
| `0x24` | M → A | Verify M |
| `0x25` | M → A | Reconnect Init |
| `0x26` | A → M | Reconnect Response |
| `0x27` | both | Error |

### `0x21` Pairing Request
`[minor][deviceId 16][ephPub 65][ltPub 65][nameLen][name]`

### `0x22` Pairing Response
`[minor][macEphPub 65][macLtPub 65][macId 16][nameLen][name]`

The Mac's **long-term** public key is included so a PIN-only phone (which never scanned the QR) can authenticate the Mac and derive Z2.

### `0x23` Verify A
`[tagA 32]`

### `0x24` Verify M
`[tagM 32]`

### `0x25` Reconnect Init
`[minor][macId 16][macEphPub 65]`

### `0x26` Reconnect Response
`[minor][deviceId 16][ephPub 65]`

### `0x27` Error
`[minor][errorCode u8]`

| Code | Meaning |
|---|---|
| `1` | Unknown device (reconnect from an unpaired phone) |
| `2` | Verification failed (tag mismatch) |
| `3` | Busy (handshake already in progress / already ready) |
| `4` | Bad request (malformed payload / ECDH failure) |

---

## 5. Handshake flows

### 5.1 Pairing (phone-initiated)

```
Phone                                     Mac
  | 0x21 request (OTP from QR or PIN)       |
  |---------------------------------------->|
  |                                         | Z1, Z2; try each OTP candidate;
  |                                         | bind, check tagA
  | 0x22 response                           |
  |<----------------------------------------|
  | Z1, Z2; bind OTP; check nothing yet     |
  | 0x23 tagA                               |
  |---------------------------------------->|
  |                                         | match → trust device
  | 0x24 tagM                               |
  |<----------------------------------------|
  | check tagM → READY both sides           |
```

* The phone learns the OTP out-of-band; it does **not** need the QR's `macId`/`key` (they are re-delivered in 0x22). PIN-only pairing works identically.
* Wrong OTP / MITM: tags mismatch → `0x27` code 2; the phone surfaces the failure and resets.
* On success the phone stores `{macId, name, macLT pub, addedAt}`; the Mac stores `{deviceId, name, phoneLT pub, addedAt}`.

### 5.2 Reconnect (Mac-initiated)

```
Mac                                        Phone
  | 0x25 init (macId, macEph)               |
  |---------------------------------------->|
  |                                         | Z1, Z2, Z3 (needs stored macLT)
  | 0x26 response                           |
  |<----------------------------------------|
  | lookup deviceId → phoneLT; Z1, Z2, Z3   |
  | check tagA                              |
  | 0x24 tagM                               |
  |<----------------------------------------|
  | check tagM → READY both sides           |
```

* An **unpaired** phone still answers 0x26 (so the Mac can distinguish "unknown" from "absent") but derives Z3 from garbage → tagA fails → Mac sends `0x27` code 1 → phone enters the "pairing needed" state.
* Reconnect does not re-register the device on either side.

### 5.3 Session state machines
* Phone phases: `IDLE → NEGOTIATING → READY`, or `PAIRING_NEEDED` (Mac rejected us), or `FAILED`.
* A new `0x21` while the Mac session is ready is answered with `0x27` code 3.

---

## 6. Encrypted traffic

Gesture packets (the 15-byte v1 packets specified in §8) are **never sent in the clear**. Each is wrapped in a traffic frame:

| Byte Offset | Field | Size | Description |
|---|---|---|---|
| `0` | `frame_type` | 1 | `0x10` |
| `1 – 4` | `counter` | 4 | Sender's message counter, **little-endian**, starts at 0 |
| `5 – 19` | `ciphertext` | 15 | AES-GCM ciphertext of the v1 packet |
| `20 – 35` | `tag` | 16 | GCM tag |

Total: **36 bytes** → requires negotiated MTU ≥ 39. macOS centrals negotiate ~185 automatically; receivers must not assume more than 20 bytes are writable pre-MTU-exchange (handshake chunks are ≤ 20 bytes for that reason).

* **Nonce (12 bytes):** `prefix(4) ‖ 0x00000000 ‖ counter(u32 BE)` where `prefix` = `"A2M\0"` for Android→Mac frames, `"M2A\0"` for Mac→Android frames. Keys are directional (`a2m` / `m2a`).
* **AAD:** the frame's first 5 bytes (`frame_type ‖ counter`).
* **Replay policy:** a receiver rejects any inbound frame whose `counter` is **less than** the next expected value (equal = replay, rejected). Counters are per-session and per-direction; after a fresh handshake both sides restart at 0.
* Counter exhaustion: `u32` overflow wraps; renegotiate (reconnect) before ~2³² frames — at 60 Hz this is > 1 year.

---

## 7. Pairing offer (QR / PIN)

The Mac regenerates the offer each time the pairing panel opens:

```
{"v":"2","t":"airpad","name":<Mac name>,
 "macId":<b64 of 16 bytes>,"key":<b64 of 65-byte P-256 point>,"otp":<b64 of 16 bytes>}
```

* `t` must be `"airpad"`; `v` is the offer format version.
* The phone scans the QR with zxing and starts §5.1 immediately.
* The Mac also displays a 6-digit PIN derived from `SecureRandom` (uniform `000000–999999`); phones without a camera (or failing scans) type it and derive `OTP = SHA-256("AirPadPIN" ‖ pin)[0..16]`. Both candidates live in the same session; either verifies.
* The offer expires when regenerated; scanning a stale QR fails tag verification (code 2).

---

## 8. Gesture packets (v1.1 wire format — plaintext inside traffic frames)

Every gesture packet is exactly **15 bytes**. All multi-byte values are **Little-Endian**.

| Byte Offset | Field Name | Type | Size | Description |
|---|---|---|---|---|
| `0` | `version` | `uint8` | 1 Byte | Protocol Version (currently `0x01`). |
| `1` | `packet_type` | `uint8` | 1 Byte | Packet type, see below. |

**Versioning policy:** the `version` byte identifies the wire-format family and only changes on breaking changes. New packet types are added additively and keep `version = 0x01`; v1.0 receivers must ignore unknown `packet_type` values.

### `0x01` — Pointer Delta Move (v1.0)

| Byte Offset | Field Name | Type | Size | Description |
|---|---|---|---|---|
| `2` | `finger_count` | `uint8` | 1 Byte | Number of active touch contacts. |
| `3 - 6` | `timestamp_ms` | `uint32` | 4 Bytes | Device uptime (mod 2³²) in ms, captured right before send. |
| `7 - 10` | `dx` | `float32` | 4 Bytes | Accelerated relative horizontal cursor delta in pixels. |
| `11 - 14` | `dy` | `float32` | 4 Bytes | Accelerated relative vertical cursor delta in pixels. |

### `0x02` — Button Click (v1.1)

| Byte Offset | Field Name | Type | Size | Description |
|---|---|---|---|---|
| `2` | `button` | `uint8` | 1 Byte | `0x00` = left, `0x01` = right. |
| `3` | `phase` | `uint8` | 1 Byte | `0x00` = press (down), `0x01` = release (up). |
| `4 - 7` | `timestamp_ms` | `uint32` | 4 Bytes | Same clock as MOVE. |
| `8 - 14` | `reserved` | — | 7 Bytes | Zero-filled. |

A tap-to-click is a LEFT press immediately followed by a LEFT release. Click-and-drag is a LEFT press, a stream of MOVE packets, then a LEFT release.

### `0x03` — Scroll Delta (v1.1)

| Byte Offset | Field Name | Type | Size | Description |
|---|---|---|---|---|
| `2` | `finger_count` | `uint8` | 1 Byte | Always `2` (two-finger scroll). |
| `3 - 6` | `timestamp_ms` | `uint32` | 4 Bytes | Same clock as MOVE. |
| `7 - 10` | `dx` | `float32` | 4 Bytes | Horizontal scroll delta, finger-travel direction. |
| `11 - 14` | `dy` | `float32` | 4 Bytes | Vertical scroll delta, finger-travel direction. |

### `0x04` — Gesture Event (v2)

A recognized **discrete** multi-finger gesture, translated sender-side into a semantic **action** from the catalog below. The Mac maps actions to system shortcuts (see §8.1).

| Byte Offset | Field Name | Type | Size | Description |
|---|---|---|---|---|
| `2` | `action_code` | `uint8` | 1 Byte | Semantic action, see catalog. `0x00` is never sent. |
| `3` | `origin_gesture` | `uint8` | 1 Byte | Raw gesture that produced the action (diagnostics/logging). |
| `4` | `direction` | `uint8` | 1 Byte | Physical finger-travel direction: `0`=up, `1`=down, `2`=left, `3`=right. |
| `5 - 8` | `timestamp_ms` | `uint32` | 4 Bytes | Same clock as MOVE. |
| `9 - 14` | `reserved` | — | 7 Bytes | Zero-filled. |

**Action catalog** (wire codes, stable — must match on both sides):

| Code | Action | Meaning |
|---|---|---|
| `0x00` | Disabled | Never sent (slot disabled sender-side). |
| `0x01` | Mission Control | Show Mission Control. |
| `0x02` | App Expose | Show all windows of the frontmost app. |
| `0x03` | Space Next | Move one Space to the **right** (physical swipe **left** — content follows fingers). |
| `0x04` | Space Prev | Move one Space to the **left** (physical swipe **right**). |
| `0x05` | Show Desktop | Reveal the desktop. |
| `0x06` | Launchpad | Open Launchpad. |
| `0x07` | Notification Center | Open Notification Center. |

**Origin gesture codes:** `0x01` = three-finger swipe, `0x02` = four-finger swipe.

**Behavior rules:**
* One swipe fires **once per contact session**, when the contact centroid travels past the sender's activation threshold (~30 px) along its dominant axis. Further movement during the same contact is swallowed.
* During three/four-finger contact the sender suppresses cursor MOVE and SCROLL packets.
* **Three-finger drag** is an alternative use of three-finger contact (enabled in the phone's gesture settings): after a small slop it emits a LEFT button PRESS (packet `0x02`), then MOVE packets (`finger_count = 3`), then a RELEASE on lift — i.e. it reuses the existing click-and-drag packet stream and needs no dedicated wire type. When enabled it replaces three-finger swipes; four-finger swipes keep working.
* Unknown `action_code` values are ignored (forward compatibility, same policy as unknown `packet_type`).

#### 8.1 Mac-side action mapping (defaults)

| Action | Synthetic shortcut |
|---|---|
| Mission Control | `ctrl` + `↑` |
| App Expose | `ctrl` + `↓` |
| Space Next | `ctrl` + `→` |
| Space Prev | `ctrl` + `←` |
| Show Desktop | `fn` + `F11` (device-dependent: plain `F11` when "use F1/F2 as standard function keys" is on) |
| Launchpad | `fn` + `F4` (same fn caveat) |
| Notification Center | none — no public global shortcut; the action is accepted but unmapped (logged) |

#### 8.2 Pinch / rotate — feasibility & safe approach

* **Rotate:** there is no public macOS API to synthesize rotation gestures. The private routes (`kCGEventGesture`/`NSEvent` gesture monikers, `IOHIDPostEvent`) are undocumented, unstable across macOS releases, and hostile to signing — **not reliably possible**; not implemented.
* **Pinch to zoom:** likewise not possible as a true system-wide gesture event. **Safe approach (proposed, not yet implemented):** the phone recognizes pinch and sends a modifier-latch packet (additive `0x05`, e.g. `ctrl` or `cmd`) followed by ordinary SCROLL packets derived from the scale change, unlatching on lift. `cmd`+scroll zooms in most apps (browsers, editors); `ctrl`+scroll triggers the accessibility full-screen zoom. This uses only public `CGEvent` scroll + flag APIs and reuses the existing SCROLL path. Deferred to a later step.

**Sign conventions:**
* MOVE deltas follow finger travel in screen coordinates (y grows downward); the Mac converts to cursor movement.
* SCROLL deltas follow finger travel in screen coordinates (positive `dy` = fingers moving down). **Natural scrolling is applied sender-side** (Android inverts both axes before sending when the toggle is on).
* Momentum: after the fingers lift, the Android device keeps emitting SCROLL packets with decaying magnitude until inertia stops. The Mac injects them as ordinary scroll events.

---

## 9. Identity persistence

| Side | Store | Contents |
|---|---|---|
| Android | app-private `SharedPreferences` (`airpad.identity`) + `filesDir/trusted_macs.json` | Long-term P-256 private key (PKCS#8), x9.63 public key, `deviceId` (16 B, random, fixed at first launch); per-Mac: `macId`, name, x9.63 Mac LT key, added-at |
| macOS | Keychain (service `com.diego.airpad.identity`) + `UserDefaults`/plist | Long-term P-256 private key, `macId` (16 B); per-device: `deviceId`, name, x9.63 phone LT key, added-at |

Deleting a trusted entry on either side forces the full pairing flow again (the reconnect handshake fails verification by construction).

---

## 10. Latency Measurement Technique

Every gesture packet carries a 32-bit millisecond timestamp (`timestamp_ms`) recorded on the Android device right before the frame is encrypted and notified.

### Measuring End-to-End Latency & Jitter:
1. **Clock Alignment:** Upon BLE connection, the Mac central records its local system time $T_{Mac,0}$ alongside the first packet's $T_{Android,0}$.
2. **Delta Calculation:** For subsequent packets $k$:
   $$\Delta T_{transport} = (T_{Mac,k} - T_{Mac,0}) - (T_{Android,k} - T_{Android,0})$$
3. **Jitter & Frame Rate Tracking:** The Mac calculates time delta $\delta_t = T_{Mac,k} - T_{Mac,k-1}$. At 60 Hz touch sampling, $\delta_t \approx 16.6 \text{ ms}$. Variance in $\delta_t$ measures BLE transmission jitter and scheduling delays.
