# UG SECURITY ARCHITECTURE — 2026 EDITION

### *Meta Quest • PlayFab • Photon Fusion • Vercel*

---

## Executive Summary

UG implements a multi-layered, server-authoritative security model based on one foundational assumption:

> **The client may be fully compromised.**

Accordingly:

* Identity, entitlement, bans, and multiplayer eligibility are validated **server-side**.
* Session participation requires passing **three independent authentication systems**:

  1. **Vercel → PlayFab Server Authentication** (with DoH-pinned connections)
  2. **Meta Device Application Integrity Attestation**
  3. **Photon Fusion Meta/Oculus Provider Authentication**
* Matchmaking isolation ensures that even modded or stale clients cannot interact with the legitimate multiplayer population.
* Outbound PlayFab traffic from the login endpoint is secured against DNS hijacking via **DNS-over-HTTPS connection pinning**, eliminating an attack vector that was exploited three times between December 2025 and March 2026.

The result is a security architecture where **local tampering has no known practical path to live players**, and no intended path to progression or economy impact provided server-authoritative validation remains complete.

---

# 1. Design Principles

* **Server Always Wins** — All meaningful decisions occur server-side.
* **Defense in Depth** — Multiple independent systems validate identity and integrity.
* **Platform-Native Security** — Leverage Meta's attestation and Oculus authentication.
* **Matchmaking Isolation** — Unauthenticated clients never meet real players.
* **Tamper Tolerance, Not Tamper Prevention** — Modding is not blocked; it is made irrelevant.
* **Secure Outbound Connections** — Login endpoint PlayFab traffic uses DNS-over-HTTPS to prevent interception.

---

# 2. Authentication Pipeline

## 2.1 Overview

UG's login process involves several stages. From the client's perspective there are three major phases:

1. **Client → Meta SDK** (entitlement, identity, nonce, attestation token)
2. **Client → Vercel** (which talks to Meta and PlayFab via DoH-pinned connections)
3. **Client → PlayFab → Photon Fusion** (ValidationToken fetch, then multiplayer session join)

### Authentication Flow

```
[Quest Client]
    |
    | Core.AsyncInitialize()
    | Entitlements.IsUserEntitledToApplication()
    | Users.GetLoggedInUser() → MetaId, DisplayName
    | Users.GetAccessToken()
    | Users.GetUserProof() → nonce
    | SHA256(nonce) → base64url challenge
    | DeviceApplicationIntegrity.GetIntegrityToken(challenge) → attestationToken
    v
[Vercel /api/verifyoculuslogin]
    | - DoH resolver: resolve PlayFab IPs via Cloudflare/Google DNS-over-HTTPS
    | - Validate resolved IPs against PlayFab CIDR allowlist
    | - Pin all outbound PlayFab connections to validated IPs
    | - Call Meta: user_nonce_validate (verify nonce is real)
    | - Call Meta: platform_integrity/verify (validate attestation claims)
    | - Enforce attestation: block/ban based on app integrity, device integrity,
    |   certificate hash, version code, and device ban status
    | - Cross-check device ban registry for alt account detection
    | - Call PlayFab: Server/LoginWithCustomID (via DoH-pinned connection)
    | - MITM defense: cross-verify any ban response with GetUserBans
    v
[Quest Client]
    | Receives: SessionTicket, EntityToken, PlayFabId, EntityId, EntityType, InfoPayload
    | Sets PlayFab SDK credentials locally
    |
    | PlayFabClientAPI.GetTitleData("ValidationToken")
    v
[PlayFab TitleData]
    |
    | PlayFabGatekeeper.VerifyGameAccess() — group membership / access control
    v
[Quest Client]
    |
    | Users.GetUserProof() → fresh nonce
    | BuildOculusAuth(MetaId, nonce) → AuthenticationValues
    | NetworkConfigValidator.GenerateConfigHash() → session properties (VT, PH, PC, BV, BT)
    | runner.StartGame(args) with AuthValues + SessionProperties
    v
[Photon Fusion]
    | Validates Meta UserID + nonce via Oculus Provider (server-to-server with Meta)
    | Rejects invalid clients before they join any session
    v
[Live Multiplayer Session]
    |
    | Users.GetUserProof() → fresh nonce for voice
    | FusionVoiceClient authenticates separately via Oculus Provider
    v
[Voice Chat (VoicePatrol moderated)]
```

Each stage must succeed or the client is blocked, banned, or isolated.

---

## 2.2 Detailed Authentication Steps

### Step 1: Meta SDK Initialization

* `Core.AsyncInitialize()` — Initializes the Meta Platform SDK.
* `Entitlements.IsUserEntitledToApplication()` — Confirms app ownership.
* `Users.GetLoggedInUser()` — Retrieves Meta user ID and display name.
* `Users.GetAccessToken()` — Obtains the user's access token.

### Step 2: Nonce and Attestation

* `Users.GetUserProof()` — Generates a signed nonce tied to the Meta account.
* Client computes `SHA256(nonce)` encoded as **base64url** (replacing `+` with `-`, `/` with `_`, trimming `=` padding).
* `DeviceApplicationIntegrity.GetIntegrityToken(challenge)` — Requests an attestation token from Meta's Device Application Integrity API. Retries up to 5 times with 2-second delays on failure.

### Step 3: Vercel Authentication Endpoint

Client POSTs to `/api/verifyoculuslogin` with `userId`, `nonce`, and `attestationToken` (form-encoded or JSON).

Vercel performs (in order):

1. **DoH Resolver Initialization** — Resolves PlayFab IPs via DNS-over-HTTPS (Cloudflare 1.1.1.1, Google 8.8.8.8 fallback), validates all IPs against the PlayFab CIDR allowlist, and pins all outbound PlayFab connections to those validated IPs. System DNS is never used for PlayFab traffic.
2. **Meta Nonce Validation** — Calls `user_nonce_validate` to verify the nonce is legitimate and tied to the correct Meta account.
3. **Meta Attestation Verification** — Calls `platform_integrity/verify` to validate the attestation token. Extracts claims including app integrity state, device integrity state, unique device ID, device ban status, package certificate hash, and version code.
4. **Device Ban Check** — If the device is Meta-banned, blocks login immediately. Checks the device ban registry for alt account detection and creates linked security blobs for evaders.
5. **PlayFab Server/LoginWithCustomID** — Authenticates with PlayFab using the Title Secret Key via a DoH-pinned connection. Retries once on network failure.
6. **MITM Ban Cross-Verification** — If PlayFab returns a ban response (errorCode 1002), independently calls `Server/GetUserBans` to confirm the ban is real. If the cross-check disagrees, the ban is flagged as a MITM payload injection, blocked, and the player is returned a 503 to retry.
7. **Version Gate** — Compares the Meta-attested `versionCode` against `MINIMUM_VERSION_CODE`. Players on versions below the minimum are blocked. Developer accounts bypass this check.
8. **Attestation Enforcement** — Evaluates remaining attestation claims against the enforcement configuration. Actions range from allow (developer bypass) through block (device integrity issues) to ban (sideloaded APKs, certificate mismatches, package tampering).

Returns: `sessionTicket`, `entityToken`, `playFabId`, `entityId`, `entityType`, `infoPayload`, `newlyCreated`.

### Step 4: Client Session Setup

Client receives the Vercel response and:

* Sets PlayFab SDK credentials (`ClientSessionTicket`, `PlayFabId`, `EntityToken`, `EntityId`, `EntityType`).
* Calls `PlayFabClientAPI.GetTitleData` to retrieve the current `ValidationToken` (hourly rotating).
* Runs `PlayFabGatekeeper.VerifyGameAccess()` for group membership and access control checks.

### Step 5: Photon Fusion Authentication

When launching a game session:

* Client requests a **fresh** nonce via `Users.GetUserProof()` (not reused from login).
* Builds `AuthenticationValues` with `AuthType = Oculus`, `userid`, and the fresh `nonce`.
* Generates session properties via `NetworkConfigValidator.GenerateConfigHash()` including ValidationToken, prefab hash, prefab count, build version, and build timestamp.
* Calls `runner.StartGame()` with auth values and session properties. Retries up to 10 times for public matchmaking with progressive backoff.

Photon validates the credentials **directly with Meta's servers**. Invalid clients are rejected at the Photon infrastructure level before joining any session.

### Step 6: Voice Chat Authentication

After the game session is established:

* Client requests another **fresh** nonce via `Users.GetUserProof()`.
* Builds separate `AuthenticationValues` for the `FusionVoiceClient`.
* Voice client authenticates independently via the Oculus Provider.

---

# 3. Meta Device Application Integrity

UG integrates Meta's Device Application Integrity API for hardware-level device validation, app version legitimacy, tamper detection, and anti-replay validation.

## 3.1 Validated Claims

Vercel validates the following claims after Meta verifies the token's cryptographic signature:

| Claim | Requirement |
|---|---|
| `nonce` | Must equal SHA256(original\_nonce) in base64url format |
| `package_id` | Must be `com.ContinuumXR.UG` |
| `timestamp` | ±300 seconds of server time |
| `app_integrity_state` | Must be `StoreRecognized` |
| `device_integrity_state` | Must be `Advanced` |
| `device_ban` | Must not have `is_banned = true` |
| `package_cert_sha256_digest` | Must match expected signing certificate hash |
| `version` | Must be ≥ `MINIMUM_VERSION_CODE` |

## 3.2 Integrity States

**App Integrity States:**

| State | Meaning |
|---|---|
| `StoreRecognized` | Package ID and version match a build in any Meta Store release channel |
| `NotRecognized` | Version does not match any build in Meta's release channels |
| `NotEvaluated` | Meta could not determine app state (typically unreleased dev builds) |

> **Important:** `StoreRecognized` is version-based, not binary-based. A sideloaded APK will pass if its version matches any build in Meta's release channels. Meta does not verify actual binary contents.

**Device Integrity States:**

| State | Meaning |
|---|---|
| `Advanced` | Device is unmodified with strong hardware attestation |
| `Basic` | Device has basic integrity but may have modifications |
| `NotTrusted` | Device is rooted, modified, or otherwise compromised |

## 3.3 Enforcement Configuration

Attestation enforcement is **fully live** with tiered actions:

| Failure | Action | Rationale |
|---|---|---|
| `app_NotRecognized` | **Ban** | Sideloaded or pirated APK |
| `app_NotEvaluated` | **Ban** | Not in any Meta release channel |
| `cert_mismatch` | **Ban** | Modified APK (signing cert doesn't match) |
| `cert_missing` | **Ban** | Missing certificate data |
| `nonce_mismatch` | **Ban** | Likely tampering |
| `package_mismatch` | **Ban** | Wrong package ID |
| `device_NotTrusted` | **Block** | Rooted/modified device — prompted to factory reset |
| `device_Basic` | **Block** | Insufficient device integrity — prompted to factory reset |
| `token_stale` | **Block** | Clock issues — not ban-worthy |
| `verification_failed` | **Block** | Meta API couldn't verify — could be infrastructure issue |
| `no_token` | **Block** | Modified client not sending attestation |
| `version_outdated` | **Block** | Game version below minimum — prompted to update |

Developer accounts (`IsDeveloper = true` in PlayFab InternalData) bypass enforcement for testing builds not yet submitted to Meta Store. Additional hardening of this bypass is recommended — see Section 17.6.

---

# 4. Secure Outbound Connections (DoH Resolver)

## 4.1 The Problem

Between December 2025 and March 2026, attackers exploited DNS hijacking to disrupt UG's login infrastructure three times. By poisoning the DNS resolution for PlayFab's API hostname, they could either intercept traffic (injecting fake ban responses) or trigger UG's own security checks to block all legitimate player logins.

## 4.2 The Solution

All outbound PlayFab API calls from `/api/verifyoculuslogin` are routed through **DNS-over-HTTPS pinned connections**:

1. **DoH Resolution** — PlayFab's hostname is resolved via Cloudflare (1.1.1.1) and Google (8.8.8.8) DNS-over-HTTPS endpoints. These queries travel over encrypted HTTPS connections to hardcoded IP addresses, making them immune to local DNS poisoning.
2. **CIDR Validation** — Every IP returned by DoH is validated against PlayFab's published static IP ranges before being used. IPs outside the known ranges are discarded.
3. **Connection Pinning** — A custom `https.Agent` routes all PlayFab connections through the DoH-resolved, validated IPs. Node.js's system DNS resolver is never consulted for PlayFab traffic.
4. **Caching** — Validated IPs are cached for 2 minutes (fresh) with a 10-minute stale fallback, minimizing DoH queries while ensuring timely updates.

> **Scope note:** The `/api/rotatetoken` cron currently uses standard DNS for its `Admin/SetTitleData` call. The exploitability is low (the attacker would also need to intercept HTTPS, and the worst case is injecting a known ValidationToken for up to one rotation interval), but extending DoH pinning to all Vercel→PlayFab traffic via a shared resolver module would close this gap entirely.

## 4.3 MITM Ban Cross-Verification

Even with DoH pinning, the endpoint includes a defense against payload injection on the PlayFab login response. If PlayFab's `LoginWithCustomID` returns a ban (errorCode 1002), the endpoint makes an independent `GetUserBans` call to confirm the ban is real. If the cross-check shows the player is not actually banned, the fake ban is blocked, a Slack alert fires, and the player receives a 503 to retry.

## 4.4 Slack Alerting

Security events trigger alerts to a Slack channel via webhook (configured via `SLACK_SECURITY_WEBHOOK_URL`). Each alert includes an `Action Required` field with specific guidance:

| Event | Trigger | Severity |
|---|---|---|
| `doh_failure` | Both DoH providers returned no IPs | Warning |
| `doh_invalid_ips` | DoH returned IPs outside PlayFab CIDR ranges | Critical |
| `resolver_down` | No usable IPs, player logins failing | Urgent |
| `mitm_fake_ban` | MITM cross-verify caught a fake ban injection | Critical |

## 4.5 Startup Verification

On each cold start, the resolver logs:

* `[RESOLVER INIT]` — Lists all CIDR ranges loaded, confirming the allowlist is correct.
* `[RESOLVER READY]` — Shows the actual DoH-resolved IPs and which provider was used, confirming the full resolution chain works.

---

# 5. PlayFab Identity Authority

## 5.1 Server-Only Authentication

UG exclusively uses **PlayFab Server/LoginWithCustomId** for all authentication. This is a server-side API that requires the Title Secret Key, which is held only on Vercel — never in the client binary. This ensures:

* No Unity client can generate a valid SessionTicket.
* Custom SDKs or MITM proxies cannot impersonate real authentication.
* All identity creation is centralized through the Vercel security endpoint.
* Every login passes through attestation, version gating, and ban checks before a session is issued.

## 5.2 Why Client Login APIs Must Be Blocked

By default, PlayFab allows clients to authenticate directly using various `Client/Login*` APIs. If any of these remain enabled, an attacker can bypass the Vercel endpoint entirely — calling PlayFab directly to obtain a valid SessionTicket without ever passing through attestation, version checks, or ban verification. This would undermine the entire security architecture.

A secondary attack vector was discovered where players managed to **link** their UG account to alternative identity providers (e.g., Android device ID) using PlayFab's `Client/Link*` APIs. Once linked, they could authenticate via `Client/LoginWithAndroidDeviceId` instead of going through Vercel, completely bypassing all security checks. The `Client/Unlink*` APIs must also be blocked to prevent attackers from cycling linked identities.

## 5.3 PlayFab API Policy

UG enforces a custom API policy via PlayFab's `Admin/UpdatePolicy` endpoint that denies all client-side login, link, and unlink operations for alternative identity providers. The policy can be viewed with `Admin/GetPolicy` and updated with `Admin/UpdatePolicy`.

**Blocked API operations:**

| API Group | Login | Link | Unlink | Rationale |
|---|---|---|---|---|
| CustomID | `Client/LoginWithCustomID` | `Client/LinkCustomID` | `Client/UnlinkCustomID` | Server-only — Vercel uses `Server/LoginWithCustomId` |
| Android | `Client/LoginWithAndroidDeviceId` | `Client/LinkAndroidDeviceId` | `Client/UnlinkAndroidDeviceId` | Prevents cross-platform auth bypass |
| iOS | `Client/LoginWithIOSDeviceId` | `Client/LinkIOSDeviceId` | `Client/UnlinkIOSDeviceId` | Prevents cross-platform auth bypass |
| Nintendo | `Client/LoginWithNintendoSwitchDeviceId` | `Client/LinkNintendoSwitchDeviceId` | `Client/UnlinkNintendoSwitchDeviceId` | Prevents cross-platform auth bypass |

Each rule is implemented as a policy statement with `Effect: Deny` and `Principal: *` (applies to all players). For example:

```json
{
    "Resource": "pfrn:api--/Client/LinkAndroidDeviceId",
    "Action": "*",
    "Effect": "Deny",
    "Principal": "*",
    "Comment": "Block linking Android devices - prevents Vercel auth bypass"
}
```

## 5.4 Policy Maintenance

The policy is versioned (`PolicyVersion`) and should be updated whenever new identity providers are added to PlayFab. When updating, use `OverwritePolicy: false` to append new statements without removing existing ones. Periodically review with `Admin/GetPolicy` to confirm all deny rules are active. Automated policy-drift detection is recommended — see Section 17.2.

---

# 6. Photon Fusion Access Control

## 6.1 How It Works

When connecting to Photon, the client provides a **fresh** nonce (not reused from the Vercel login) and the Meta user ID. Photon's servers validate these credentials **directly with Meta** before allowing the connection.

If validation fails, Photon rejects the connection before gameplay begins. Fusion-based games never receive callbacks for unauthorized clients; they simply cannot join.

## 6.2 Position in the Security Stack

Photon auth is a **late-stage "final confirmation gate"**, not the first line of defense. By the time a client reaches Photon, they must have already:

* Passed Meta entitlement and nonce validation
* Passed Meta attestation verification (all claims)
* Authenticated with PlayFab via Vercel (through DoH-pinned connections)
* Retrieved the correct ValidationToken
* Passed group membership / access control checks

This ensures Photon deals only with clients who have already passed UG's core checks.

## 6.3 Voice Chat Authentication

Voice chat uses a **separate** authentication flow with its own fresh nonce and `AuthenticationValues`, authenticated independently through Photon's Oculus Provider. This prevents session token reuse between game and voice connections.

---

# 7. Matchmaking Isolation

## 7.1 Photon App Version

Every production build increments the **App Version** in Photon's App Settings. Photon enforces this at the infrastructure level — clients on different App Versions cannot see or join each other's sessions. This is the first line of version isolation and is enforced by Photon's servers, not client-side logic.

## 7.2 ValidationToken

ValidationToken provides a second layer of isolation that goes beyond version matching:

* Generated by a Vercel cron job (`/api/rotatetoken`) with hourly rotation.
* Cryptographically random (32 bytes, base64-encoded).
* Stored in PlayFab TitleData (public, readable only by authenticated clients).
* Included as a session property (`VT`).
* Matchmaking filters sessions based on the token.

The critical security property of the ValidationToken is that it **can only be obtained by clients who have successfully authenticated through the Vercel endpoint**. If an attacker somehow manages to play the game but bypasses the Vercel login — for example, by using their own PlayFab backend or a compromised client — they cannot fetch the current token from PlayFab TitleData without a valid SessionTicket issued by Vercel. Without the correct token, they will never match into sessions with the live player population.

## 7.3 Session Properties

Beyond ValidationToken, sessions include version compatibility properties via `NetworkConfigValidator`:

| Key | Property | Purpose |
|---|---|---|
| VT | ValidationToken | Hourly rotating token — requires Vercel-issued SessionTicket to obtain |
| PH | PrefabTableHash | SHA256 hash of network prefab GUIDs (first 16 chars) |
| PC | PrefabCount | Number of network prefabs in the build |
| BV | BuildVersion | Application version string |
| BT | BuildTimestamp | Unix timestamp of when the build was created |

These ensure clients only match with sessions running compatible, authenticated builds.

## 7.4 What Matchmaking Isolation Does

* **Photon App Version** prevents old builds from connecting to current sessions (infrastructure-enforced).
* **ValidationToken** ensures only Vercel-authenticated clients can match into live sessions.
* **Session properties** (PH, PC, BV, BT) prevent structurally incompatible builds from joining the same room.
* Together, these isolate custom backends, modded clients, and bypassed authentication into a "shadow ecosystem" that never intersects with the legitimate player population.

## 7.5 What Matchmaking Isolation Does *Not* Do

* Does not ban players.
* ValidationToken filtering is session-property-based, not infrastructure-enforced (unlike App Version).

The distinction matters: Photon App Version is a hard gate enforced by Photon's servers. ValidationToken is a soft gate enforced by session property matching — a more sophisticated attacker who obtains the token could theoretically bypass it. However, obtaining the token requires a valid Vercel-authenticated SessionTicket, which brings them back through the full security pipeline.

---

# 8. Client Binary Hardening

UG uses **Mfuscator IL2CPP Encryption** on every Quest build to:

* Obfuscate all IL2CPP method names to non-human-readable symbols.
* Randomize memory layout and addresses **per build**.
* Encrypt `global-metadata.dat`.
* Clear build folder before each build to avoid stale artifacts.

**Effect on attackers:**

* Blocks the majority of casual modders.
* Forces advanced attackers to redo significant reverse engineering **for each release**.
* Delays memory hacking and patching by weeks per patch.

This discourages casual tampering and slows down advanced modders but is **not relied on for security decisions**. It raises the cost of attack, not the impossibility.

---

# 9. Ban Systems

## 9.1 PlayFab Account Bans

Standard bans prevent login and progression. Bans can be:

* **Temporary** — with expiry date displayed to user.
* **Permanent** — indefinite duration.

## 9.2 Meta Device Bans

For severe violations:

* Vercel extracts `unique_id` from attestation payload.
* Issues a hardware ban via Meta's `platform_integrity/device_ban` API.
* Ban survives factory reset, reinstall, and new Meta accounts.

Once a device is Meta-banned for UG, that physical headset cannot access UG regardless of account.

## 9.3 Automatic Ban Escalation

1. Failed integrity with ban-level severity → PlayFab account ban.
2. If `unique_id` present → Meta device ban added.
3. If an already PlayFab-banned user attempts login → Device ban added to prevent ban evasion.

## 9.4 Device Ban Registry (Alt Account Detection)

UG maintains a device ban registry in PlayFab Title Internal Data that maps `unique_id` → `{ playFabId, metaId, reason }`.

When a device-banned player creates a new Meta account and attempts to log in:

1. The attestation payload reveals the device ban (`is_banned = true`).
2. The registry is checked for the device's `unique_id`.
3. If found, the original banned account's Security blob is copied to the alt account (with `linkedAlt` marker).
4. If not found but the account has existing ban evidence, the registry is backfilled.

This creates an audit trail linking all accounts used on a banned device.

## 9.5 Device Ban Registry — Limitations

**Meta `unique_id` rotates every ~30 days.** Meta's Device Application Integrity API assigns a new `unique_id` to a device approximately monthly. This means a single physical device will accumulate multiple `unique_id` entries in the registry over time, and a player's Security blob may reference an outdated `unique_id` that no longer matches what the device currently reports.

The practical consequences are:

* The registry grows continuously as expired temp-ban entries are never cleaned up.
* A player whose temp ban has expired may still have a stale registry entry, wasting lookup time.
* If a permanently banned player's `unique_id` rotates, the registry entry for the old ID becomes orphaned — though the Meta device ban itself persists regardless (it's tied to hardware, not the `unique_id`).
* A player's Security blob `uid` field may not match their current `unique_id`, making manual forensic lookups harder.

## 9.6 Device Ban Registry — Planned Improvements

A scheduled maintenance job (Vercel cron) is planned to address the registry staleness:

1. **Iterate the registry** — For each `unique_id` → `{ playFabId }` entry:
   * Call `Server/GetUserBans` to check if the player still has an active PlayFab ban.
   * If **no active ban** (expired temp ban): remove the entry from the registry.
   * If **active ban**: retain the entry.
2. **Update Security blobs** — For players with active bans, check if their current attestation `unique_id` (from their most recent login attempt) differs from what's stored in their blob and in the registry. If the `unique_id` has rotated, update both the blob's `uid` field and the registry entry to reflect the current ID.
3. **Registry compaction** — After cleanup, save the pruned registry back to Title Internal Data.

This keeps the registry lean (only active bans), ensures `unique_id` references stay current, and prevents the Title Internal Data value from growing unbounded over time.

---

# 10. Forensic Logging

UG logs security telemetry to PlayFab InternalData in a compact JSON blob under the `Security` key (private, not readable by clients).

## 10.1 Security Blob Fields

**Device Integrity (`di` object):**

| Field | Description |
|---|---|
| `ff` | Timestamp of first attestation failure |
| `lf` | Timestamp of most recent failure |
| `c` | Total number of failures |
| `wa` | Worst app\_integrity\_state recorded |
| `wd` | Worst device\_integrity\_state recorded |
| `rm` | Bitmask of all failure reasons ever seen |
| `uid` | Meta hardware unique identifier |
| `ch` | Client certificate hash |
| `cmc` | Certificate mismatch count |
| `fcm` | First certificate mismatch timestamp |
| `ntc` | No-token attempt count |
| `ntf` / `ntl` | First / last no-token timestamp |
| `vbc` | Version-block count |
| `vbf` / `vbl` | First / last version-block timestamp |
| `vbv` | Last blocked versionCode |
| `vfe` / `vfl` | Verify-failure count / last timestamp |
| `lastEnforce` | Timestamp of last enforcement action |
| `lastAction` | Last enforcement action taken (block/ban) |
| `linkedAlt` | True if this is a copied blob from a banned alt |
| `linkedTo` | PlayFabId of original banned account |

**Meta Ban (`mb` object):**

| Field | Description |
|---|---|
| `uid` | Device unique ID |
| `bid` | Meta ban ID |
| `ia` | Ban issued at timestamp |
| `r` | Ban reason |
| `dm` | Ban duration in minutes |

**Verification vs Integrity Failures:**

UG distinguishes between verification failures (Meta's API couldn't verify the token — infrastructure issues) and integrity failures (Meta verified the token but claims failed validation — likely tampering). These are logged separately to avoid conflating infrastructure issues with security incidents.

---

# 11. Behavioral Analytics and Monitoring (Mixpanel)

## 11.1 Overview

UG integrates Mixpanel as its primary analytics and behavioral monitoring platform. While PlayFab InternalData stores per-player security state (Section 10), Mixpanel provides the broader operational visibility needed to detect anomalies, investigate exploits, and build confidence for enforcement decisions.

Mixpanel is initialized after successful Vercel authentication (`MixpanelManager.Instance.InitializeFromGameLauncher`), ensuring that all tracked events are tied to an authenticated player identity.

## 11.2 What Is Tracked

Events are sent to Mixpanel across several categories:

* **Player activity** — Session starts, session duration, game actions, progression milestones, and interaction patterns.
* **Economy** — Currency earned, spent, and traded. Item acquisitions, crafting, and marketplace activity. Enables detection of abnormal accumulation rates or suspicious transfer patterns.
* **Errors and failures** — Client-side errors, login failures (via breadcrumb flush), network issues, and crash-adjacent events. Login error breadcrumbs are stored locally in PlayerPrefs and flushed to Mixpanel on the next successful login, closing the observability gap for errors that occur before authentication.

Note: Attestation outcomes, enforcement actions, and version blocks occur during the Vercel login flow — before Mixpanel is initialized — and are therefore only recorded in Vercel logs and PlayFab InternalData (Section 10), not in Mixpanel.

## 11.3 User Profiles

Each player has a Mixpanel user profile with a full historical event timeline. This allows admins to:

* Review a specific player's complete activity history when investigating a report.
* Compare a player's behavior patterns against population norms.
* Identify the exact sequence of events leading up to a suspected exploit.
* Correlate multiple accounts that exhibit similar suspicious patterns.

## 11.4 Dashboard Queries and Anomaly Detection

Custom dashboard queries are configured to surface abnormal behavior, such as:

* Players accumulating currency or items at rates significantly above normal gameplay.
* Unusual patterns in trading activity (potential item duplication or economy exploits).
* Players triggering error events that correlate with known exploit signatures.
* Sudden spikes in specific event types across the population (may indicate a newly discovered exploit being shared).

## 11.5 Role in Enforcement

Mixpanel serves as the evidence layer for manual enforcement decisions. When an admin considers applying a ban or taking action against a player:

1. **Detection** — Dashboard queries or player reports surface suspicious behavior.
2. **Investigation** — The player's Mixpanel profile provides a full event history to confirm or rule out the behavior.
3. **Confidence** — Historical data provides the evidence needed to distinguish between a bug, normal gameplay variance, and deliberate exploitation.
4. **Action** — Admin applies the appropriate response (warning, temp ban, permanent ban) with documented justification.
5. **Remediation** — The same data helps identify the root cause (e.g., a game bug enabling an exploit), allowing the development team to fix the underlying issue.

This ensures bans are evidence-based rather than reactive, and that bugs that enable exploits are identified and fixed alongside any enforcement action.

---

# 12. Threat Model

## 12.1 Attacks UG Defends Against

* Modded APKs attempting to join live sessions
* Custom PlayFab backends / fake servers
* MITM proxies intercepting authentication
* DNS hijacking / BGP attacks on outbound server traffic
* Payload injection (fake ban responses)
* Memory editors modifying client state
* Obsolete or debug builds
* Replay attacks using captured nonces
* Device spoofing attempts
* Ban evasion via new accounts or factory reset
* APK certificate tampering (repackaged builds)
* Scripted mass authentication using harvested MetaIDs (see Section 16.1)

## 12.2 Current Modding/Hacking Status

UG currently has **no known practical bypass that permits unauthorized clients to reach the live production population or compromise progression/economy**. While modded APKs existed for very early versions of the game, those versions can no longer pass authentication, attestation, or version gating — they are completely locked out of the live game.

The layered security architecture makes meaningful client-side attacks impractical:

* **Modded APKs** are caught by attestation (app integrity, certificate hash) and blocked or banned.
* **Memory editing tools** require a rooted or modified device, which fails the device integrity check (`Advanced` required) and is blocked at login.
* **Old/patched builds** are rejected by the version gate (`MINIMUM_VERSION_CODE`) and cannot match into live sessions (Photon App Version enforcement).
* **Custom backends** cannot obtain the hourly ValidationToken (requires a Vercel-issued SessionTicket) and are isolated from the live player population.
* **IL2CPP obfuscation** (Mfuscator) forces attackers to redo reverse engineering per build, and the rotating security layers mean any exploit window closes quickly.

In theory, an attacker with an unmodified device running a store-recognized build could still tamper with local memory in ways that don't affect attestation. In practice, the server-authoritative architecture ensures that local-only tampering has no meaningful impact on other players or the game economy.

---

# 13. Known Limitations

| Limitation | Mitigation |
|---|---|
| Meta attestation is version-based, not binary-based | Layered auth ensures modded binaries still can't reach live sessions; certificate hash validation catches repackaged APKs |
| ValidationToken filtering is session-property-based, not infrastructure-enforced | Photon App Version provides infrastructure-level version isolation; ValidationToken adds auth-gated isolation on top — obtaining it requires a Vercel-issued SessionTicket. Consider signed JWT and shorter rotation (Section 17.7) |
| Unmodified devices could theoretically tamper with local memory | Server-authoritative design ensures local-only tampering has no meaningful impact on other players or economy; trust-boundary audit recommended to confirm completeness (Section 17.1) |
| DoH-resolved IPs are cached (2 min fresh, 10 min stale) | Cache refresh is automatic; Slack alerts fire if resolution fails; consider adding third DoH provider (Section 17.8) |
| `/api/rotatetoken` does not use DoH-pinned connections | Exploitability is low (attacker must also intercept HTTPS); worst case is injecting a known ValidationToken for one rotation interval. Consider extracting the DoH resolver into a shared module |
| PlayFab CIDR ranges could change | `doh_invalid_ips` Slack alert fires immediately; update array and redeploy |
| Some PlayFab UserData remains client-editable | Only non-security-critical data; recommend maintaining an explicit allowlist and auditing per release (Section 17.9) |
| Meta `unique_id` rotates every ~30 days | Device ban persists regardless (hardware-level); registry maintenance cron planned to keep entries current and prune expired temp bans |
| Vercel endpoint is a single point of failure and a high-value target | Secrets should be rotated periodically; dependencies pinned; canary probes recommended (Section 17.3) |
| No rate limiting described on the Vercel login endpoint | Recommended to implement per-IP and/or per-MetaId rate limiting (Section 17.4) |
| Attestation outcomes not persisted to a population-level analytics store | Vercel logs and per-player InternalData only; server-side event ingestion and security dashboard recommended (Section 17.5) |
| PlayFab API deny policy could drift as new identity providers are added | Automated policy-drift detection recommended as CI gate or Vercel cron (Section 17.2) |
| Developer attestation bypass is a single boolean flag | Recommend multi-condition gating and time-bound expiry (Section 17.6) |

These are acknowledged and deliberately mitigated via the layered architecture.

---

# 14. Defense-in-Depth Summary

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
│    Meta Device Attestation          │  ← Hardware + app + cert + version integrity
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│  DoH-Pinned PlayFab Server Login    │  ← Server-authoritative identity via secure channel
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│  MITM Ban Cross-Verification        │  ← Fake ban injection defense
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   ValidationToken + Version Props   │  ← Population isolation
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│  Photon Fusion Meta Authentication  │  ← Final infrastructure gate (fresh nonce)
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│  Voice Chat Meta Authentication     │  ← Separate auth with independent nonce
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│      Live Multiplayer Sessions      │  ← Protected game environment
└─────────────────────────────────────┘
```

**Each layer provides an additional, distinct control. Defeating one layer does not by itself grant access to the live game.**

---

# 15. Security Philosophy

UG's security architecture has evolved from a permissive "tolerate harmless mods" stance to a comprehensive enforcement model where **unauthorized clients have no known practical path to the live game**.

> **Every path to the live game passes through server-side validation.**
> **There are no known practical bypasses, and the cost of finding one is prohibitively high.**

This is achieved not through any single mechanism, but through the cumulative effect of independent security layers — each of which must be passed in sequence. Compromising one layer (e.g., obtaining a modded APK) does not help with the next (e.g., passing attestation on an unmodified device), which does not help with the next (e.g., obtaining a Vercel-issued SessionTicket), and so on.

**Important caveats:** Meta attestation is version-based rather than binary-based, and ValidationToken filtering is session-property-based rather than infrastructure-enforced (Section 13). The system is excellent in practice, but not mathematically closed. Its real security level depends on rigorous server-side validation of all economically and competitively meaningful game actions, and on tight operational discipline around policies, configuration, and rotation schedules.

The architecture is designed to be **resilient to evolution** — as new attack vectors emerge (such as the DNS hijacking incidents of 2025–2026), new layers can be added without restructuring existing ones.

This aligns with modern multiplayer security design and Meta's guidance for Quest platform integrity.

---

# 16. Historical Incidents

## 16.1 PlayFab Mass Account Compromise (Pre-Policy Lockdown)

Prior to the API policy lockdown described in Section 5, UG's PlayFab title had client-side login APIs enabled — the default PlayFab configuration. An attacker exploited this by:

1. **Harvesting MetaIDs** — Meta user IDs are visible in multiplayer contexts (lobby presence, session metadata). The attacker collected MetaIDs from a large portion of the active player base.
2. **Scripted mass authentication** — Using the open `Client/LoginWithCustomID` API, the attacker wrote a script that authenticated as each harvested MetaID in sequence, obtaining valid SessionTickets without going through any server-side validation.
3. **Data wipe** — With valid sessions for each account, the attacker wiped player data across approximately 7,000+ accounts.

**Response and recovery:**

* Pre-existing PlayFab PlayerData scraping utilities enabled bulk export of player data, and the majority of affected accounts were restored from these backups.
* The incident directly motivated the server-only authentication model: all `Client/Login*`, `Client/Link*`, and `Client/Unlink*` APIs were blocked via PlayFab's `Admin/UpdatePolicy` endpoint (Section 5.3).
* The Vercel authentication endpoint was introduced to centralize all login through a server-side gate, ensuring that MetaID alone is no longer sufficient to obtain a valid session.

**Structural outcome:** This attack vector is now permanently closed. No client can authenticate with PlayFab without passing through the Vercel endpoint, which requires a valid Meta nonce, a passing attestation, and a non-banned status. The attacker's original script would fail at the first step.

---

# 17. Recommendations and Open Items

The following items represent areas identified during external review that could further strengthen the architecture. None are architectural vulnerabilities — they are operational hardening opportunities.

Items are prioritized as **High** (ship soon), **Medium** (plan for next quarter), or **Low** (backlog / future hardening).

## 17.1 Trust-Boundary Table — Priority: High

For each meaningful action in UG — currency earn/spend, trading, inventory mutation, unlocks, matchmaking eligibility, moderation actions, progression, cosmetics equip/use — formally document whether it is **client-suggested** or **server-authoritative**, and exactly where it is validated. This would either confirm the strongest claim in this document ("local tampering has no meaningful impact") or expose any actions that still depend too much on client truth.

An attacker operating on an unmodified device with a store-recognized build who manipulates local runtime state will pass attestation. The defense against this is server-authoritative validation of every economically or competitively meaningful action. This table is the audit artifact that proves that defense is complete.

**Recommended format:**

| Action | Client-Suggested or Server-Authoritative | Validation Point | Notes |
|---|---|---|---|
| Currency earn | ? | ? | |
| Currency spend | ? | ? | |
| Item trade | ? | ? | |
| Inventory mutation | ? | ? | |
| ... | ... | ... | |

## 17.2 PlayFab Policy Drift Detection — Priority: High

The architecture depends on PlayFab API deny rules (Section 5.3) remaining complete and correct. New identity providers may be added to PlayFab over time, and policy can be accidentally changed by other team members.

**Recommended actions:**

* Implement an automated policy check — either as a Vercel cron job or a CI deployment gate — that fetches the current policy via `Admin/GetPolicy`, compares it against an expected manifest of deny rules, and alerts (or fails deployment) if any rules are missing or changed.
* Apply the same principle to Photon App Version and `MINIMUM_VERSION_CODE` alignment: verify at build/deploy time that these values are consistent.

## 17.3 Vercel Endpoint Hardening — Priority: Medium

The Vercel endpoint is a high-value target. It holds the PlayFab Title Secret Key, Meta App Secret, and Slack webhook credentials. A compromise of the Vercel environment (e.g., dependency supply chain attack, environment variable leak, or platform vulnerability) would allow an attacker to issue valid SessionTickets without triggering any existing alerts.

**Recommended actions:**

* Establish rotation procedures for all secrets held by the Vercel endpoint (PlayFab Title Secret Key, Meta App Secret, Slack webhook URL).
* Pin dependencies to exact versions with a lockfile and audit for supply chain risks periodically.
* Consider a canary or integrity check mechanism — e.g., a periodic probe that verifies the endpoint's behavior matches expected responses, alerting if it deviates.

## 17.4 Rate Limiting on the Vercel Endpoint — Priority: Medium

The document does not describe rate limiting on `/api/verifyoculuslogin`. Without it, an attacker could brute-force attestation edge cases, probe enforcement logic, or DDoS the login endpoint to deny service to all players.

**Recommended actions:**

* Implement per-IP and/or per-MetaId rate limiting on the Vercel endpoint.
* Consider progressive backoff or temporary block for repeated failed attestation attempts from the same source.

## 17.5 Security Observability Dashboard — Priority: Medium

Attestation outcomes, enforcement actions, and policy-denied auth attempts currently live only in Vercel logs and per-player PlayFab InternalData. Vercel log retention is plan-dependent and does not support population-level trend analysis. A dedicated security dashboard should surface:

* Attestation failures by reason (app integrity, device integrity, cert mismatch, etc.)
* Version blocks by versionCode
* No-token attempt counts and trends
* Device integrity failure rates
* PlayFab policy-denied auth attempts (if any client-side login calls are still being attempted)
* Photon auth rejections
* DoH resolver incidents and ban cross-verification fires

**Recommended actions:**

* Have the Vercel function push attestation outcome events to a persistent store (e.g., server-side Mixpanel ingestion, a dedicated logging service, or a lightweight database).
* Build a dashboard over this data for ongoing security posture monitoring.
* Establish an incident response playbook for critical alerts — particularly when MITM ban cross-verification fires. Document who gets paged, what to check first, and rollback steps.

## 17.6 Developer Bypass Hardening — Priority: Medium

The `IsDeveloper = true` flag in PlayFab InternalData bypasses attestation enforcement. While InternalData is server-write-only and not a client-writable surface, a single boolean flag is a thin gate for a full attestation bypass.

**Recommended actions:**

* Require multiple conditions for developer bypass — e.g., `IsDeveloper = true` **plus** an allowlisted PlayFab account ID, **plus** a non-production environment or time-limited session token.
* Consider making the dev bypass time-bound (e.g., 24-hour expiry) rather than permanent, reducing blast radius if a dev account is ever compromised.
* Audit the current set of accounts carrying this flag periodically.

## 17.7 ValidationToken Strengthening — Priority: Low–Medium

The ValidationToken is a shared secret rotated hourly. All authenticated clients receive the same token, and a single leak would allow unauthenticated clients to match into live sessions for up to one hour.

**Recommended actions:**

* Evaluate whether the rotation interval can be shortened (e.g., 15 minutes) without causing session-join failures during rotation transitions. **The primary risk with the current token is leak radius — lifetime and scope — not format.** A shorter rotation window directly reduces the blast radius of any single token leak.
* Consider replacing the raw random string with a **signed JWT** issued by the `/api/rotatetoken` cron. This would add authenticity (preventing injection of a forged token by an attacker who somehow obtains TitleData write access), but note that JWT alone does not solve the containment problem: if every authenticated client still receives the same signed token, a leaked JWT is just as usable as a leaked random string for the duration of its validity. Signing is a useful secondary improvement, not a substitute for reducing lifetime or moving to per-player/per-session scope.
* Longer term, consider whether per-player or per-session tokens are feasible within Photon's session property matching model. This is the only approach that fully addresses the leak-radius concern.

## 17.8 DoH Resolver Resilience — Priority: Low

The DoH resolver currently uses Cloudflare (1.1.1.1) with Google (8.8.8.8) as fallback.

**Recommended action:**

* Add a third DoH provider (e.g., Quad9 at `9.9.9.9` / `dns.quad9.net`) as a tertiary fallback for further resilience against simultaneous provider outages.

## 17.9 Client-Writable PlayFab UserData Audit — Priority: Low

The document notes that some PlayFab UserData remains client-editable, described as "only non-security-critical data." As UG's feature set evolves, data that is currently non-critical may become exploitable if new features depend on it.

**Recommended actions:**

* Maintain an explicit allowlist of client-writable UserData keys.
* Audit the allowlist against new features with each release to confirm that no client-writable key has gained security or economy significance.

## 17.10 Mixpanel Data Retention and Privacy — Priority: Low–Medium

Mixpanel tracks player activity, economy events, and behavioral patterns. Ensure that data retention and deletion policies are aligned with your privacy policy, particularly for EU and Australian players where regulatory requirements apply (GDPR, Australian Privacy Act).

## 17.11 Client-to-Vercel TLS Considerations — Priority: Low

The document details DoH pinning for the Vercel→PlayFab connection but does not mention TLS certificate pinning on the client→Vercel connection. A MITM on this leg could harvest `userId`, `nonce`, and `attestationToken` in transit. On Quest, this is harder to exploit than on mobile platforms, and the client is already treated as untrusted, so the practical risk is low — but it is worth noting in the threat model for completeness.

## 17.12 Photon Custom Authentication Webhook — Priority: Low (2027)

Consider adding **Photon's custom authentication webhook** as a fourth independent gate. This would allow a final server-side check inside Photon's infrastructure before the client reaches `OnGameJoined` — for example, re-verifying the player's ban status or session validity at the moment of join rather than only at login time. It is cheap to implement and would further harden the stack against any gap between login-time validation and session-join time.

---

# Document Information

| | |
|---|---|
| **Version** | 2026.03-r1 |
| **Status** | Production |
| **Classification** | Internal / Partner Review |
| **Last Updated** | March 2026 (amended with external review findings) |

---

# End of Document