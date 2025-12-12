# 🚀 **UG SECURITY ARCHITECTURE — 2025 EDITION**

### *Meta Quest • PlayFab • Photon Fusion • Vercel*

---

# **UG Security Architecture — 2025**

## **Executive Summary**

UG implements a multi-layered, server-authoritative security model based on one foundational assumption:

> **The client may be fully compromised.**

Accordingly:

* Identity, entitlement, bans, and multiplayer eligibility are validated **server-side**.
* Session participation requires passing **three independent authentication systems**:

  1. **Vercel → PlayFab Server Authentication**
  2. **Meta Device Application Integrity Attestation** *(phased rollout)*
  3. **Photon Fusion Meta/Oculus Provider Authentication**
* Matchmaking isolation ensures that even modded or stale clients cannot interact with the legitimate multiplayer population.

The result is a security architecture where **local tampering offers no meaningful access** to live players, progression, or economy.

---

# **1. Design Principles**

UG's security stack is built on these core principles:

* **Server Always Wins** — All meaningful decisions occur server-side.
* **Defense in Depth** — Multiple independent systems validate identity and integrity.
* **Platform-Native Security** — Leverage Meta's attestation and Oculus authentication.
* **Matchmaking Isolation** — Unauthenticated clients never meet real players.
* **Tamper Tolerance, Not Tamper Prevention** — Modding is not blocked; it is made irrelevant.

---

# **2. Authentication Pipeline**

## **2.1 Overview**

UG's login process involves several stages, but from the client's perspective there are two major hops:

1. **Client → Vercel** (which, under the hood, talks to Meta and PlayFab)
2. **Client → PlayFab** (to fetch the rotating ValidationToken), then **Client → Photon Fusion**

### **Minimal Diagram: Authentication Flow**

```
[Quest Client]
    |
    | Entitlement check, user ID, display name, nonce, attestation request
    v
[Meta SDK on Device]
    |
    | nonce + attestationToken
    v
[Vercel Auth Endpoint]
    | - Calls Meta: nonce_validate
    | - Calls Meta: attestation verify
    | - Calls PlayFab: Server/LoginWithCustomId
    v
[PlayFab (via Vercel)]
    |
    | SessionTicket + EntityToken + player info
    v
[Quest Client]
    |
    | Fetch ValidationToken from PlayFab TitleData
    v
[PlayFab TitleData]
    |
    | Join / Create session with VT + version properties
    v
[Photon Fusion]
    | - Validates Meta UserID + nonce via Oculus Provider
    v
[Live Multiplayer Session]
```

Each stage must succeed or the client is blocked or isolated.

---

## **2.2 Detailed Authentication Steps**

### **1. Meta SDK Initialization**

* Confirms app entitlement.
* Retrieves user ID, display name.
* Generates a signed nonce via **Users.GetUserProof()**.

### **2. Meta Attestation Request**

Client computes `SHA256(nonce)` and encodes it as **base64url** (replacing `+` with `-`, `/` with `_`, and trimming `=` padding). This challenge is submitted to the Device Application Integrity API to request an attestation token.

### **3. Vercel Authentication Endpoint**

Client submits:

* `nonce`
* `attestationToken`

Vercel performs:

1. **Meta Nonce Validation** — Calls `user_nonce_validate` to verify the nonce is legitimate and tied to the correct Meta account
2. **Meta Attestation Verification** — Calls `platform_integrity/verify` to validate the attestation token's claims
3. **PlayFab Server/LoginWithCustomId** — Authenticates with PlayFab using the Title Secret Key
4. Returns:

   * SessionTicket
   * EntityToken
   * Player info

### **4. ValidationToken Retrieval**

Client retrieves `ValidationToken` (hourly rotating) from PlayFab TitleData.

Used for **matchmaking isolation**, not authentication enforcement.

### **5. Photon Fusion Authentication (Meta/Oculus Provider)**

When starting a game session, the client builds AuthenticationValues containing:

* `AuthType`: CustomAuthenticationType.Oculus
* `userid`: Meta user's numeric ID
* `nonce`: Fresh nonce from Users.GetUserProof()

Photon validates these credentials **directly with Meta's servers**.

**Invalid clients are rejected at the Photon infrastructure level before joining any session.**

Photon auth is the *final* gate — reached only if all prior layers succeeded.

---

# **3. Meta Device Application Integrity**

UG integrates Meta's Device Application Integrity API for:

* Hardware-level device validation
* App version legitimacy
* Tamper detection (version-based)
* Anti-replay validation via timestamp

## **3.1 Validated Claims**

Vercel validates the following claims after Meta verifies the token's cryptographic signature:

| Claim                    | Requirement                                          |
| ------------------------ | ---------------------------------------------------- |
| `nonce`                  | Must equal SHA256(original_nonce) in base64url format |
| `package_id`             | Must be `com.ContinuumXR.UG`                         |
| `timestamp`              | ±300 seconds of server time                          |
| `app_integrity_state`    | Must be `StoreRecognized`                            |
| `device_integrity_state` | Must be `Advanced`                                   |
| `device_ban`             | Must not have `is_banned = true`                     |

## **3.2 Integrity States Explained**

**App Integrity States:**

| State             | Meaning                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `StoreRecognized` | Package ID and version match a build in any Meta Store release channel  |
| `NotRecognized`   | Version does not match any build in Meta's release channels             |
| `NotEvaluated`    | Meta could not determine app state (typically unreleased dev builds)    |

> ⚠️ **Important:** StoreRecognized is **version-based, not binary-based**. A sideloaded APK will pass as StoreRecognized if its version matches any build in Meta's release channels. Meta does not verify actual binary contents.

**Device Integrity States:**

| State        | Meaning                                                    |
| ------------ | ---------------------------------------------------------- |
| `Advanced`   | Device is unmodified with strong hardware attestation      |
| `Basic`      | Device has basic integrity but may have modifications      |
| `NotTrusted` | Device is rooted, modified, or otherwise compromised       |

---

## **3.3 Enforcement Rollout (Phased)**

**Phase 1 (Current):** Attestation tokens submitted by all players.

* Failures logged to PlayFab InternalData
* No blocking yet
* Used to understand real-world variance and avoid false positives

**Phase 2 (Soon):** Soft enforcement

* Clients with invalid app or device integrity fail login
* Developer bypass available for builds not yet submitted to Meta Store (`NotEvaluated` + `IsDeveloper = true`)

**Phase 3:** Full enforcement

* Invalid clients receive both PlayFab and Meta hardware bans
* Enforcement handled automatically by Vercel logic

This staged process demonstrates **responsible adoption of platform security** suitable for review by Meta.

---

# **4. PlayFab Identity Authority**

## **4.1 Why PlayFab Server Login**

UG exclusively uses:

**PlayFab Server/LoginWithCustomId**
*(requires Title Secret Key held only on Vercel)*

This ensures:

* No Unity client can generate a valid SessionTicket.
* Custom SDKs / MITM proxies cannot impersonate real authentication.
* All identity creation is centralized.

The following client-based login APIs are **disabled** in PlayFab Title Settings:

* `Client/LoginWithCustomId`
* `Client/LoginWithAndroidDeviceId`
* `Client/LoginWithIOSDeviceId`
* `Client/LoginWithNintendoSwitchDeviceId`

---

# **5. Photon Fusion Access Control**

Photon provides an additional infrastructure-level check via the **Oculus Authentication Provider** configured in the Photon Dashboard.

## **5.1 How It Works**

When connecting to Photon, the client provides:

* Meta user ID
* Signed nonce from `Users.GetUserProof()`

Photon's servers validate these credentials **directly with Meta** before allowing the connection.

If validation fails:

> **Photon rejects the connection before gameplay begins.**

Fusion-based games never receive callbacks for unauthorized clients; they simply cannot join.

## **5.2 Position in the Security Stack**

Photon auth is a **late-stage "final confirmation gate"**, not the first line of defense.

By the time a client reaches Photon, they must have already:

* Passed Meta nonce validation
* Passed Meta attestation verification
* Authenticated with PlayFab via Vercel
* Retrieved the correct ValidationToken

This ensures Photon deals only with clients who have already passed UG's core checks.

---

# **6. Matchmaking Isolation**

## **6.1 ValidationToken**

ValidationToken is a **simple, effective isolation mechanism**:

* Generated by Vercel cron job (hourly rotation)
* Stored in PlayFab TitleData (public, readable by authenticated clients)
* Included as a session property (`VT`)
* Matchmaking filters sessions based on the token

## **6.2 Additional Session Properties**

Beyond ValidationToken, sessions include version compatibility properties via `NetworkConfigValidator`:

| Key | Property         | Purpose                                        |
| --- | ---------------- | ---------------------------------------------- |
| VT  | ValidationToken  | Hourly rotating token for session isolation    |
| PH  | PrefabTableHash  | SHA256 hash of network prefab GUIDs (first 16 chars) |
| PC  | PrefabCount      | Number of network prefabs in the build         |
| BV  | BuildVersion     | Application version string                     |
| BT  | BuildTimestamp   | Unix timestamp of when the build was created   |

These ensure clients only match with sessions running compatible builds.

## **6.3 What Matchmaking Isolation Does**

* Prevents stale builds from matching into live population
* Isolates custom backends that can't fetch real TitleData
* Isolates modded clients that skip TitleData fetch
* Creates a "shadow ecosystem" for unauthorized clients

## **6.4 What Matchmaking Isolation Does *Not* Do**

* Does not reject connections at infrastructure level
* Does not ban players
* Is not a cryptographic guarantee

It is **not** a security boundary — it is a **population isolation boundary**.

---

# **7. Client Binary Hardening**

UG uses **Mfuscator IL2CPP Encryption** on every Quest build to:

* Obfuscate all IL2CPP method names to non-human-readable symbols
* Randomize memory layout and addresses **per build**
* Encrypt `global-metadata.dat`
* Clear build folder before each build to avoid stale artifacts

**Effect on attackers:**

* Blocks ~90% of casual modders
* Forces advanced attackers to redo significant reverse engineering **for each release**
* Delays memory hacking and patching by weeks per patch

This discourages casual tampering and slows down advanced modders but is **not relied on for security decisions**. It raises the cost of attack, not the impossibility.

---

# **8. Ban Systems**

## **8.1 PlayFab Account Bans**

Standard bans prevent login and progression. Bans can be:

* **Temporary** — with expiry date displayed to user
* **Permanent** — indefinite duration

## **8.2 Meta Device Bans**

For severe violations:

* Vercel extracts `unique_id` from attestation payload
* Issues a hardware ban via Meta's `platform_integrity/device_ban` API
* Ban survives:

  * Factory reset
  * Reinstall
  * New Meta accounts

Once a device is Meta-banned for UG, that physical headset cannot access UG regardless of account.

## **8.3 Automatic Ban Escalation (When Attestation Enforced)**

1. Failed integrity → PlayFab account ban
2. If `unique_id` present → Meta device ban added
3. If already PlayFab-banned user attempts login with new account + valid `unique_id` → Device ban added to prevent ban evasion

---

# **9. Forensic Logging**

UG logs rich telemetry to PlayFab InternalData (private, not readable by clients):

| Field                              | Description                           |
| ---------------------------------- | ------------------------------------- |
| `DeviceIntegrity_FirstFail`        | Timestamp of first attestation failure |
| `DeviceIntegrity_LastFail`         | Timestamp of most recent failure      |
| `DeviceIntegrity_FailCount`        | Total number of failures              |
| `DeviceIntegrity_WorstAppState`    | Worst app_integrity_state recorded    |
| `DeviceIntegrity_WorstDeviceState` | Worst device_integrity_state recorded |
| `DeviceIntegrity_FailReasons`      | Pipe-separated list of failure reasons |
| `DeviceIntegrity_MetaUniqueId`     | Meta hardware unique identifier       |
| `DeviceIntegrity_VerifyErrorCount` | Count of Meta API verification failures |

**Verification vs Integrity Failures:**

UG distinguishes between:

* **Verification failures** — Meta's API couldn't verify the token (infrastructure issues, timeouts)
* **Integrity failures** — Meta verified the token but claims failed validation (likely tampering)

These are logged separately to avoid conflating infrastructure issues with security incidents.

---

# **10. Threat Model**

## **10.1 Attackers UG Defends Against**

* Modded APKs attempting to join live sessions
* Custom PlayFab backends / fake servers
* MITM proxies intercepting authentication
* Memory editors modifying client state
* Obsolete or debug builds
* Replay attacks using captured nonces
* Device spoofing attempts
* Ban evasion via new accounts

## **10.2 Attacks UG Intentionally Does *Not* Prevent**

* Local-only cosmetic mods (no server impact)
* Offline modifications
* Memory editing that does not affect server decisions
* Single-player tampering

UG's goal is **to prevent malicious impact on other players**, not **to eliminate modding entirely**.

---

# **11. Known Limitations**

| Limitation | Mitigation |
| ---------- | ---------- |
| Meta attestation is **version-based**, not binary-based | Layered auth ensures modded binaries still can't reach live sessions |
| Photon does not enforce ValidationToken at infrastructure level | Game logic uses session property filtering |
| Attestation enforcement not yet globally enabled | Phased rollout with forensic logging active |
| Rooted devices can still tamper locally | Server-authoritative design ignores local state |
| Some PlayFab UserData remains client-editable | Only non-security-critical data; migration planned |

These are acknowledged and deliberately mitigated via the layered architecture.

---

# **12. Defense-in-Depth Summary**

### **Minimal Diagram: Layered Security**

```
┌─────────────────────────────────────┐
│     Meta SDK Entitlement Check      │  ← App ownership verified
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│      Meta Nonce Validation          │  ← Identity tied to real Meta account
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│    Meta Device Attestation          │  ← Hardware + version integrity
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│  Vercel + PlayFab Server Login      │  ← Server-authoritative identity
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   ValidationToken + Version Props   │  ← Population isolation
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│  Photon Fusion Meta Authentication  │  ← Final infrastructure gate
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│      Live Multiplayer Sessions      │  ← Protected game environment
└─────────────────────────────────────┘
```

**Every layer is independent. Compromising one does not compromise the next.**

---

# **13. Security Philosophy**

UG's architecture is built around practical, platform-aware constraints:

> **We do not aim to prevent modding.**
> **We aim to ensure modding cannot impact other players or the live game.**

This aligns with modern multiplayer security design and Meta's guidance for Quest platform integrity.

---

# **Document Information**

| | |
|---|---|
| **Version** | 2025.12 |
| **Status** | Production |
| **Classification** | Internal / Partner Review |
| **Last Updated** | December 2025 |

---

# **End of Document**