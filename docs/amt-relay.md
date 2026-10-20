# Intel AMT over Relay

This fork adds the ability to reach **Intel AMT / vPro** devices **through a MeshCentral relay agent** (a "relay device"), rather than only over a direct AMT connection (CIRA / direct TCP).

Upstream MeshCentral already supported two things independently:

- **Direct Intel AMT** connections (CIRA / direct TCP to the AMT ports).
- **RDP over Relay** (a remote desktop session tunneled through a MeshAgent).

What was missing was **AMT over Relay** — reaching an AMT device that is *behind* a MeshAgent (for example, on a LAN that the AMT server cannot reach directly, but that a MeshAgent on that LAN can). This fork combines the two mechanisms so that AMT traffic is routed through a selected MeshAgent.

---

## How it works

### 1. The relay channel — `amt/amt-agent-relay.js`

`CreateAmtAgentRelay` opens a **binary WebSocket tunnel** from the MeshCentral server to a MeshAgent, and uses that tunnel to reach an AMT target on the agent's network.

- It connects to `meshrelay.ashx?noping=1&hd=1&auth=<cookie>` on localhost.
- The `auth` cookie encodes `{ nouser, domainid, nodeid, tcpaddr, tcpport }` — i.e. "connect to this node (the MeshAgent), and have it open a TCP connection to `tcpaddr:tcpport` (the AMT device)".
- The AMT target port is one of `AMT_PORTS = [16992, 16993, 16994, 16995]`.
- Writes issued before the tunnel is established are **buffered** (up to 16) and flushed once the tunnel reports it is connected (state `2`, on the `c` / `cr` handshake message).

### 2. Server routing — `webserver.js`

In the AMT WebSocket handler, the server checks whether the requested AMT node's mesh is an **AMT group (`mtype == 1`) that has a `relayid`**. If so, instead of opening a direct CIRA/TCP connection to the AMT device, it:

- Looks up the MeshAgent identified by `relayid`.
- Verifies the user has rights on that agent (`GetNodeRights(user, relayAgent.dbMeshKey, relayid) & 0x00200008`).
- Opens the AMT target through the agent via `CreateAmtAgentRelay`.
- For **TLS AMT** (port 16993/16995), wraps the tunnel with `SerialTunnel` + `tls.connect` so the TLS handshake happens end-to-end over the relay.

Port selection follows the standard AMT convention:

```js
port = (tls > 0) ? 16993 : 16992;
if (p == 2 || p == 4) port += 2;   // 16994 / 16995
```

### 3. Device group types — `meshuser.js`

Device groups use an `mtype` field:

| `mtype` | Meaning |
|---------|---------|
| 1 | Intel AMT |
| 2 | Agent |
| 3 | Local |
| 4 | IP-KVM |

This feature extends **`mtype == 1` (AMT)** so a group may carry a `relayid`. In the UI this appears as the group type **"Intel AMT devices relayed thru agent"** (option `value=101`).

Related `meshuser.js` changes:

- **`amtRoute` flag** — marks relay-backed AMT nodes so the UI shows them as online/usable even when there is no direct AMT connectivity state.
- **`addamtdevice`** — allows adding a WAN-only AMT device when it is relay-backed.
- **`scanamtdevice`** — routes the scan to the relay agent when the mesh has a `relayid`.
- **`CreateMeshUserParseAmtScanRange`** — helper that parses/validates the scan range for the relay path.

### 4. Scanning flow

```
Web client
  └─> scanamtdevice (meshuser.js)
        └─> if mesh has relayid: route to the relay agent
              └─> amtRangeScan (meshagent.js)
                    └─> amtRangeScan (agents/meshcore.js)
                          └─> relay-range-scanner-v19.js
                                └─> results + progress back up the chain
```

- Scan state is stored in `parent.parent.amtRelayScans` with a **150 s timeout**.
- Progress and a "devices found" counter are streamed back to the UI (see the progress bar below).

### 5. The scanners — `agents/modules_meshcore/relay-range-scanner-v*.js`

Several scanner generations were added during development. The **active** scanner is **`relay-range-scanner-v19.js`** (referenced from `agents/meshcore.js`):

| Module | Approach | Notes |
|--------|----------|-------|
| `relay-range-scanner-v2.js` / `v3.js` | RMCP over UDP 623 | v3 adds a TCP fallback when RMCP finds nothing |
| `relay-range-scanner-v16.js` | TCP curl | concurrency 16, no progress |
| `relay-range-scanner-v17.js` | TCP curl | + progress reporting |
| `relay-range-scanner-v18.js` | wrapper | forces a 120 000 ms timeout around v17 |
| **`relay-range-scanner-v19.js`** | **TCP curl** | **active** — concurrency 32, progress + found counter, `P,ip` progress markers |

The RMCP scanners (`v2`/`v3`) send the standard RMCP "Get LAN Discovery" probe (`06000006000011BE80000000`) to UDP 623 and parse the response for the AMT version / TLS / state. When RMCP returns nothing (common behind NAT/firewalls), `v3` falls back to probing the AMT TCP ports (16993 then 16992). The TCP-curl scanners (`v16`–`v19`) probe the AMT TCP ports directly with bounded concurrency.

### 6. UI — `views/*.handlebars`

- An **"AMT Relay"** state indicator.
- The new group-type option (`value=101`) for "Intel AMT devices relayed thru agent".
- A **relay device display** showing which agent the AMT device is routed through.
- A **scan progress bar** (`dp1scanprogress`) driven by the `scanamtdeviceprogress` event.

---

## Files changed by this fork

| File | Change |
|------|--------|
| `amt/amt-agent-relay.js` | **New** — the relay channel (`CreateAmtAgentRelay`). |
| `webserver.js` | AMT relay routing in the AMT WebSocket handler (TLS / `SerialTunnel` handling). |
| `meshuser.js` | `amtRoute` flag, group-type validation (AMT + `relayid`), `addamtdevice` WAN allowance, `scanamtdevice` relay routing, `CreateMeshUserParseAmtScanRange`. |
| `agents/meshcore.js` | `amtRangeScan` command handler (uses `relay-range-scanner-v19` with `onProgress`). |
| `meshagent.js` | `amtRangeScan` result/progress handling, validation, forwarding to the web client. |
| `agents/modules_meshcore/relay-range-scanner-v2/v3/v16/v17/v18/v19.js` | **New** — scanner generations (v19 active). |
| `views/default.handlebars`, `views/default3.handlebars`, `views/default-mobile.handlebars` | UI: AMT Relay state, group type option, relay device display, scan progress bar. |
| `test/amt-agent-relay.test.js` | **New** — tests the relay channel (port validation, write buffering, binary forwarding, handshake). |
| `test/amt-range-scanner.test.js` | **New** — tests the scanner (range parsing, RMCP probes, UDP errors, TCP fallback, progress). |
| `meshcores/*.js` | Regenerated agent-core debug dumps (see note below). |
| `package.json` | Added `loadavg-windows`, `node-windows` dependencies. |

> **Note on `meshcores/`:** these large files are **debug dumps** generated by the `--dumpcores` flag (`meshcentral.js` → `updateMeshCore(..., true)`). They are bundled agent cores with modules inlined via `addModule`. They are not present in upstream and are regenerated when the agent core changes.

---

## Testing

The feature ships with two test suites (run with Node's built-in test runner / `node:test`):

```bash
node test/amt-agent-relay.test.js
node test/amt-range-scanner.test.js
```

Both suites pass on the merged (v1.2.6) codebase.
