# Part B - SmartLock v2 Design Specification

## B.1 Threat model

**Attacker.** A Dolev-Yao network attacker who shares the local link with the hub
and the lock (a guest on the Wi-Fi, a compromised device, or a machine positioned
on-path by ARP spoofing). On that link the attacker can:

- **observe** every byte of every session (the traffic is on a shared medium);
- **modify, drop, reorder, inject, and replay** any TCP segment, in either
  direction, including rewriting handshake fields in flight;
- **run their own** hub, lock, or relay, and open as many sessions as they like;
- **know the full protocol** and all public parameters (suite names, DH group,
  message formats) - nothing is secret by obscurity.

The attacker **cannot**:

- break the standard primitives within the device's lifetime: AES-256-GCM,
  SHA-256, RSA-2048 signatures, or Diffie-Hellman over a 2048-bit MODP group;
- read secrets held only on the endpoints: the lock's RSA **private** key, or the
  hub's **pinned** copy of the lock's public key established at install time;
- observe the one-time out-of-band pairing (the PIN is printed on the device and
  entered by the owner at install), though it **may** capture every later session.

Because the pairing PIN is low-entropy (a dictionary word + three digits), the
design must assume that anything derived from it on the wire is offline-guessable,
and must therefore never expose a guessable function of the PIN.

**Security goals for v2.**

1. **Confidentiality** of every command and reply, and of the pairing secret.
2. **Integrity and authenticity** of every record - no undetected modification,
   injection, reordering, or truncation.
3. **Device authentication**: the hub talks to the genuine lock, not a relay.
4. **Negotiation integrity**: the agreed suite is the strongest both support, and
   a tampered negotiation is detected.
5. **Forward secrecy**: compromise of a long-term key does not expose past
   sessions.
6. **Freshness / replay resistance**: a captured command cannot be re-used.
7. **PIN protection**: the PIN is not recoverable from a capture, and is not
   stored in a fast, unsalted form at rest.

**Non-goal (scoped out).** Record-level *non-repudiation* is not a goal: records
are protected with a shared AES-GCM key, so either party (anyone holding the key)
could have produced a tag, and a third party cannot attribute a record to one side
(per lecture). v2 provides entity authentication (pinned certificate + signed DH)
and message integrity/authenticity, which is what a door lock needs; per-message
non-repudiation would require asymmetric signatures on every record and is not
warranted here.

## B.2 Per-stage mechanisms (each tied to the Part A attack it defeats)

### Stage 1 - Negotiation  (defeats A1, downgrade)
- **Mechanism.** The hub offers only strong AEAD suites; `NULL` is removed from
  the catalogue entirely. The lock's `choose_suite` returns the strongest suite
  common to both and **aborts** rather than fall back; it can never return `NULL`.
  The negotiation is then **bound**: the lock signs the transcript
  `offered | suite | B` with its device key, and the hub verifies it.
- **Why A1 fails.** There is no `NULL` to downgrade to, so rewriting the hub's
  `HELLO` to `suites:NULL` leaves the lock with no acceptable suite and it aborts.
  Any tampering with the offered list changes the signed transcript, so the hub's
  signature check fails. Confidentiality and channel integrity are restored.

### Stage 2 - Authentication  (defeats A2 impersonation/MITM, and the PIN crack)
- **Mechanism (identity).** The lock presents an RSA certificate; the hub
  **pins** the lock's public key at pairing time and, every session, checks that
  the presented key equals the pinned key **and** that the certificate signature
  verifies. A relay that presents its own certificate is rejected.
- **Mechanism (PIN).** The v1 habit of sending a bare MD5 of the PIN in `PAIR` is
  removed. Two layers:
  - *On the wire:* the hub proves knowledge of the PIN with a fresh-nonce
    **challenge-response** - the lock sends a random nonce and the hub returns
    `Hash(PIN, nonce)` (the MS-CHAP pattern from lecture) - and that proof is
    carried **only inside the authenticated, encrypted channel** established in
    Stages 2-3. So the PIN never crosses the wire in any form; the fresh nonce
    stops replay; and because the channel is authenticated (pinned certificate, so
    no man in the middle) and encrypted (ephemeral-DH key), an eavesdropper who
    captures the pairing sees only ciphertext and has nothing to offline-guess,
    even though the PIN itself is low-entropy. (A dedicated PAKE such as SPAKE2
    would give the same guarantee without relying on the outer channel, but it is
    outside our syllabus, so we lean on the authenticated channel instead.)
  - *At rest:* the lock stores the PIN as a **salted, slow KDF** digest -
    Argon2id (or scrypt / PBKDF2 with a high iteration count) - never raw MD5, so
    a stolen device database is not trivially cracked.
  - *Note:* the provided v2 scaffold deliberately keeps the v1 MD5 `PAIR` message
    (a known limitation stated in the brief); the above is the design v2 should
    adopt, and is a design requirement only.
- **Why A2 (and the PIN crack) fail.** Key pinning plus signature verification
  means the man-in-the-middle's certificate is refused ("device key is not the
  pinned key"), so it cannot complete a session as the lock. The in-channel
  challenge-response removes the offline-crackable MD5 from the wire, and the slow
  salted KDF removes the fast unsalted hash at rest.

### Stage 3 - Keying  (defeats A3 keying recovery)
- **Mechanism.** A **fresh ephemeral** Diffie-Hellman exchange over the RFC 3526
  **2048-bit** MODP group every session; the lock **signs** its DH public value
  (inside the Stage-1 transcript) so it cannot be swapped; and the shared secret
  is passed through **HKDF-SHA256**, not used raw, to derive one key per direction
  (`context = "c2s"` / `"s2c"`).
- **Why A3 fails.** The discrete log over a 2048-bit group is infeasible, so `b`
  cannot be recovered. The key is a KDF output bound to the session context, not
  the raw secret, so no structure leaks. The exponent is ephemeral, so recovering
  one session's key never exposes another - **forward secrecy**.

### Stage 4 - Message protection  (defeats A4 nonce reuse)
- **Mechanism.** AES-GCM AEAD with a **unique nonce per record**: the 12-byte
  nonce is a function of the record's sequence number, and the two directions use
  **independent** HKDF keys. No `(key, nonce)` pair is ever repeated.
- **Why A4 fails.** Distinct nonces mean distinct keystreams, so XORing two
  records no longer cancels to `P1 XOR P2` - the two-time pad is gone. Even the
  same sequence number in opposite directions is safe, because the keys differ.
  GCM's tag continues to provide integrity.

### Stage 5 - Teardown / records  (defeats A5 replay)
- **Mechanism.** Every record carries a per-direction **sequence number**, bound
  into the AEAD as additional authenticated data; `open_record` rejects any record
  whose sequence number is not the expected next one, and a tampered record fails
  the tag. The close (`QUIT`) is itself a sequence-bound authenticated record, so a
  truncated or replayed close is detected.
- **Why A5 fails.** A replayed or reordered record arrives with the wrong sequence
  number and is refused; the session is dropped. And because Stage 3 uses a fresh
  ephemeral key per session, a record captured in one session cannot even be
  decrypted in another. The captured-UNLOCK skeleton key is closed on two
  independent levels.

## B.3 v2 handshake diagram

```
        HUB (controller/client)                         LOCK (device/server)
        =======================                         ====================
  (pinned: lock's RSA public key, from pairing)   (holds: RSA private key, PIN-KDF)

  1. HELLO  suites = {AES256-GCM, AES128-GCM}  ------------------------------->
                                                 choose strongest common suite;
                                                 abort if none (never NULL)
  2.                              <-----------------------------  SUITE  suite
        verify suite is one we offered
  3.                              <----------  CERT  name, pubkey, sig
        [AUTH] verify pubkey == PINNED key,
               verify sig over (name|pubkey)        <-- defeats A2
  4. PAIR  PIN proof: challenge-response Hash(PIN,nonce), inside AEAD channel  ->
                                                 verify PIN proof   <-- fixes PIN
  5.                              <----  DH  B = g^b mod p (2048-bit, EPHEMERAL),
                                             sig over transcript (offered|suite|B)
        [AUTH-KEX] verify sig  <-- defeats A1 (binds negotiation) + MITM on DH
  6. DHCLIENT  A = g^a mod p (2048-bit, ephemeral)  ------------------------->
        shared = B^a mod p                              shared = A^b mod p
        [KDF] k_c2s = HKDF(shared, "c2s")               (same derivation)   <-- A3
              k_s2c = HKDF(shared, "s2c")                           (per direction)
  ---------------------------- records (AES-GCM AEAD) ----------------------------
  7.                              <----  MSG rec = seal(k_s2c, seq=0, greeting)
        open_record(k_s2c, rec, expected=0)       [NONCE unique per seq  <-- A4]
  8. MSG rec = seal(k_c2s, seq=0, "STATUS")  ------------------------------->
                                   open_record(k_c2s, rec, expected=0)
                                   [SEQ bound as AAD; wrong seq -> reject  <-- A5]
     ... each record: seq increments per direction; replay/reorder rejected ...
  9. MSG rec = seal(k_c2s, seq=n, "QUIT")  --------------------------------->
        authenticated, sequence-bound close (no silent truncation)
```

Annotations: **[AUTH]** = device identity proven (Stage 2); **[AUTH-KEX]** =
authenticated, signed key exchange (Stages 1+3); **[KDF]** = HKDF key derivation,
per direction (Stage 3); **[NONCE]** = unique nonce per record (Stage 4);
**[SEQ]** = sequence binding / replay rejection (Stage 5).
