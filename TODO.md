# TODO

Public engineering backlog for go-openlawsvpn. Completed user-facing work is
recorded in [CHANGELOG.md](CHANGELOG.md).

Protocol work must remain an independent implementation based on published
specifications, published patches, observable wire behavior, and mock-server
fixtures. Do not copy reconstructed proprietary source.

## Completed in 1.2.4

- [x] Advertise only implemented, FIPS-approved AES-GCM suites.
- [x] Add AES-192-GCM support and preserve the negotiated AES key length during
  data-channel rekeying.
- [x] Adopt AWS's 1450-byte default MSS packet budget.
- [x] Start reconnect backoff at five seconds.
- [x] Parse static `ping`, `ping-restart`, `ping-exit`, and `keepalive`
  directives with pushed-over-static and last-option-wins semantics.
- [x] Treat `ping-exit` as terminal and prevent automatic CLI reconnect.
- [x] Parse static `ifconfig-ipv6`, prefer server-pushed addressing, and include
  IPv6 fields in mobile TUN configuration JSON.
- [x] Read fragmented and coalesced post-connect TLS application messages with
  a 128 KiB bound.
- [x] Add non-blocking inbound control-message callbacks and serialized
  outbound control-message writes.
- [x] Exercise control-message round trips through the integration mock server.
- [x] Transfer control-message ownership when a rekeyed TLS epoch is promoted.
- [x] Preserve live TLS reads after replaying `PUSH_REPLY` for direct-auth
  sessions.
- [x] Classify generic CRV1 and `CR_TEXT` dynamic authentication challenges
  with secret-safe typed metadata.
- [x] Require a fresh authentication flow after an established session is
  rejected, without reusing the consumed SAML assertion.
- [x] Detect and deduplicate drift in VPN-owned route and DNS state.
- [x] Conservatively restore missing owned routes and DNS while preserving
  pre-existing and later administrator changes.

## Working on an item

Each item below is intended to be usable as a fresh-session handoff. Before
editing, read `AGENTS.md`, `client.go`, and the files listed under **Start at**.
Keep the engine CGo-free and do not add vendor agents, SDKs, or proprietary
protocol implementations. New protocol behavior needs unit tests and, where a
connection lifecycle is involved, an integration fixture in
`mock/mockserver/`.

The minimum completion checks are:

```bash
CGO_ENABLED=0 go test ./...
go test -v -tags=integration -timeout 120s .
go vet ./...
```

Run the relevant Android/iOS cross-build or gomobile build when an exported
mobile surface changes. Tests must not contact AWS or require network access
unless explicitly tagged `integration`.

## Medium

### [ ] M1 — Expose generic control messages through gomobile

**Goal:** Let Android and Apple clients receive and send the generic
post-connect messages already available through `Client.ControlMessageFn` and
`Client.SendControlMessage`.

**Start at:** `client_mobile.go`, `client_mobile_ios.go`,
`client_mobile_darwin.go`, `event.go`, and `client_compat_test.go`.

**Constraints:** Do not add a required method to the existing
`MobileCallbacks` interface; doing so breaks every current Kotlin/Swift
implementation. Preserve `NewMobileClient` and all existing generated method
signatures. Prefer an additive callback interface plus constructor/setter, and
an additive `MobileClient.SendControlMessage` method. Callback delivery must
remain non-blocking, bounded, and documented as untrusted and potentially
sensitive.

**Done when:** Existing mobile consumers still compile unchanged; an opt-in
consumer can receive and reply to a message; callback and write errors have
tests; Android AAR and Apple XCFramework generation succeeds.

### [x] M2 — Classify generic dynamic authentication challenges

**Goal:** Represent dynamic challenges as typed control messages so callers do
not need to inspect raw `AUTH_FAILED`/`CR_TEXT` strings.

**Start at:** `auth/saml/msg.go`, `auth/saml/saml.go`,
`auth/saml/monitor.go`, their fuzz/unit tests, and the message dispatch in
`client.go`.

**Constraints:** Determine grammar from published OpenVPN behavior and
controlled fixtures. Separate safe metadata (kind, flags, prompt presence)
from secret challenge text. Raw payloads must never enter generic errors,
events, or logs. Existing CRV1 SAML classification must remain unchanged.

**Done when:** Typed parsing covers valid and malformed challenges, fuzz tests
cannot panic, errors contain classifications rather than payloads, and the
mock server can deliver a challenge fragmented across control packets.

### [x] M3 — Fresh authentication after server-requested reauthentication

**Goal:** Give applications a reliable way to start a fresh authentication
flow when an established session expires or is re-challenged.

**Start at:** `Client.Reconnect`, `Client.sessionMonitorFor`,
`SessionExpiredError`, `ErrReauthRequired`, state events in `event.go`, and the
CLI reconnect loop in `cmd/cli/main.go`.

**Constraints:** Never reuse a consumed SAML assertion after the server rejects
it. Preserve explicit-disconnect credential clearing. Avoid starting two SAML
flows when keepalive failure and `AUTH_FAILED` arrive together. Mobile callers
must be able to distinguish “retry transport” from “show browser again.”

**Done when:** The mock server can expire a live session; the client emits one
typed reauthentication outcome; CLI behavior is deterministic; and tests cover
concurrent expiry/disconnect, cancellation, and a successful fresh Phase 1/2.

### [x] M4 — Detect route and DNS drift without repairing it

**Goal:** Observe when VPN-owned routes or DNS settings disappear or change and
emit typed events. This first stage is read-only.

**Start at:** `routing/netlink.go`, `routing/netlink_darwin.go`, `dns/`,
`client_tun_linux.go`, `client_tun_darwin.go`, `Client.cleanup`, and `event.go`.

**Constraints:** Do not mutate host state in this item. Polling must stop on
disconnect and remain cheap. Linux unit tests should use captured/synthetic
netlink messages; privileged namespace tests belong behind the `integration`
tag. iOS continues to delegate routes and DNS to NetworkExtension.

**Done when:** Removing or changing a tracked route/DNS setting produces one
deduplicated event, unrelated system changes produce none, and teardown leaves
no monitor goroutines behind.

### [x] M5 — Define conservative route and DNS restoration ownership

**Goal:** Specify and implement safe repair after M4 can detect drift.

**Start at:** `routing.ApplyRoutes`, `routing.DeleteRoutes`, `dns.Apply`,
`dns.Revert`, and the connection cleanup state in `client.go`.

**Constraints:** Record exactly what the current client instance created or
replaced. Never delete a pre-existing route merely because it matches a pushed
destination. Never overwrite a later administrator change during repair or
cleanup. Treat systemd-resolved and resolv.conf as separate ownership models.

**Done when:** Tests cover pre-existing identical/conflicting routes,
administrator changes after connect, repeated repair, disconnect restoration,
and partial failure without damaging unrelated state.

## Medium to high

### [ ] MH1 — Add an application-owned device-posture provider

**Goal:** Define an engine interface that requests posture data from the host
application while keeping platform/vendor SDKs out of this repository.

**Start at:** `ControlMessageFn`, `SendControlMessage`, client callback patterns
in `client.go`, and gomobile adapters only after the Go API is stable.

**Constraints:** The provider must support cancellation and a bounded deadline.
Its result is sensitive and must not be logged. Define behavior for no provider,
empty result, provider error, disconnect during collection, and overlapping
refresh requests. Do not make posture mandatory for endpoints that do not ask
for it.

**Done when:** A pure-Go fake provider can satisfy a mock challenge; all error
paths are typed and secret-safe; and ordinary AWS SAML connections behave
exactly as before when no posture message is received.

### [ ] MH2 — Confirm and parse the posture protocol

**Goal:** Turn observed posture-related application messages into documented,
typed structures.

**Start at:** `auth/saml/msg.go`, the generic control-message integration
fixture in `client_integration_test.go`, and `mock/mockserver/main.go`.

**Research required:** Capture a controlled exchange from an endpoint and
record the meaning, order, and units of every `AWS_CC_MSG` header field; verify
the `aws-auth-device-posture` challenge, base64 JSON `CR_TEXT`, and
`CRV1::POSTURE_CHECK_INTERVAL` forms. Store only sanitized fixtures in this
public repository.

**Done when:** Parsers reject invalid versions, indexes, encodings, and sizes;
round-trip tests use independently constructed fixtures; and documentation
clearly separates confirmed behavior from assumptions.

### [ ] MH3 — Implement posture envelopes, fragmentation, and refresh

**Goal:** Encode provider output into the confirmed versioned envelope, split
it at the verified protocol limit, and refresh it for the session lifetime.

**Start at:** The types produced by MH1/MH2, `Client.SendControlMessage`, rekey
control ownership in `client.go`, and the connection cancellation context.

**Constraints:** Define named limits rather than magic numbers. Validate chunk
indexes/counts and bound total reassembly memory. Cache only for the server
specified lifetime, clear cached posture data on terminal teardown, and ensure
refresh timers follow the promoted TLS control epoch.

**Done when:** Tests cover single/multiple chunks, exact boundary sizes,
out-of-order or duplicate chunks, provider timeout/error, refresh, expiry,
rekey during refresh, disconnect, and server rejection.

### [ ] MH4 — Expand posture integration fixtures

**Goal:** Make posture behavior reproducible without AWS or a proprietary
client.

**Start at:** `testenv/testenv.go`, `mock/mockserver/main.go`, and
`client_integration_test.go`.

**Constraints:** Fixtures must be synthetic and contain no captured identities,
tokens, device attributes, endpoints, or proprietary code. Add explicit mock
configuration instead of changing the default successful connection path.

**Done when:** Integration cases cover malformed challenge, absent provider,
provider error, empty response, multi-part response, periodic refresh, expiry,
and rejection, while the existing CRV1 integration tests remain unchanged.

### [ ] MH5 — Parse and reconcile optional AWS route-enforcement messages

**Goal:** Support the optional control protocol that reports route-enforcement
state, excluded ranges, and the assigned VPN addresses.

**Start at:** The generic control-message API, `routing/push.go`,
`routing/netlink.go`, M4/M5, and mock-server application-message fixtures.

**Dependencies:** Complete M4 before enabling repair, and use M5 ownership
rules for every mutation. Confirm message grammar from published material or
controlled wire observations before implementing it.

**Constraints:** Gate this behavior separately from ordinary OpenVPN pushed
routes. Parse IPv4 and IPv6. Reconcile only missing routes owned by this VPN
instance; never treat the server message as permission to rewrite the whole
routing table.

**Done when:** Parsing and reconciliation tests cover disabled/enabled modes,
excluded ranges, malformed data, IPv4/IPv6, already-correct state, conflicting
routes, and disconnect cleanup.

### [ ] MH6 — Coordinate route ownership across client instances

**Goal:** Prevent two simultaneous VPN clients from deleting or repeatedly
replacing each other’s routes.

**Start at:** The ownership model from M5, route application/cleanup in
`client_tun_linux.go` and `client_tun_darwin.go`, and daemon connection policy.

**Constraints:** Prefer kernel-observable ownership and process-local reference
tracking over global lock files. If persistence is unavoidable, define crash
recovery and restrictive permissions. Do not assume route destination alone
identifies an owner.

**Done when:** Namespace tests run two clients with shared and conflicting
destinations, disconnect them in both orders, simulate one crashing, and prove
that surviving and administrator-owned routes remain intact.

## High

### [ ] H1 — Support SCRV1 Active Directory/MFA challenges

**Goal:** Add SCRV1 challenge/response support behind an explicit application
credential callback.

**Start at:** `auth/saml/saml.go`, dynamic challenge work from M2,
`sendAuthPacket`, `Connect`/`Reconnect`, and mobile callback patterns.

**Dependencies:** Complete M2 first so SCRV1 is not implemented as raw string
matching scattered through the client.

**Constraints:** Passwords, OTPs, prompts, and challenge state are secrets. Do
not log or embed them in generic errors/events. Support cancellation and
multiple challenge rounds, bound all input, clear credentials after use, and
preserve existing certificate, username/password, and CRV1 SAML flows.

**Done when:** Unit and integration tests cover password-only, password+OTP,
cancel, timeout, malformed challenge, repeated challenge, rejection, secret
redaction, and successful tunnel establishment.
