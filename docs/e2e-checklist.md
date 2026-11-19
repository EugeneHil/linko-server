# Server-side e2e checklist

The server-side rows of the v0.1 acceptance scenario (design spec 10, items
1, 2, 7, 8, 9). Device-side steps live with the apps; this page is what the
VPS owner verifies while the scenario runs. The full scenario runs before
every release.

Log evidence (items 1, 7, 9): the Windows service manager discards a
service's stderr, so a service-mode run produces no readable request lines
(docs/deploy.md section 8). Capture the request-line evidence from a
console-mode run: `sc.exe stop LinkoServer`, then run the same command line
(`linko-server.exe --config <path> run`) in a terminal while the scenario
runs.

## Item 1 - Setup

- [ ] `invite create` ran twice on the VPS - one invite per user, not per
      device (v0.1 allows one device per user) - and each link was pasted on
      exactly one device (docs/deploy.md step 7; onboarding is paste-only in
      v0.1, the terminal QR is decorative).
- [ ] Both registrations show up in the server log as
      `POST /api/v1/register 201` request lines (the handler answers
      201 Created).
- [ ] `linko-server user list` prints both usernames (`eugene`, `tatsiana`).
- [ ] Each device finds the other through user search
      (`GET /api/v1/users?prefix=... 200` request lines).

## Item 2 - Offline delivery

- [ ] With the iPhone app closed, the Mac's two messages produce no client
      errors on send (envelopes accepted over `/ws`).
- [ ] On the iPhone's reconnect the backlog arrives in order and the
      sequence numbers do not skip: messages show on the iPhone in the
      order the Mac sent them.
- [ ] The Mac's "Delivered" appears after the iPhone fetches, "Read" after
      the conversation is opened - the receipts flow back through the
      server.

## Item 7 - File via server

- [ ] With the iPhone app closed, the Mac's file upload shows
      `PUT /api/v1/files 200`; the digest returned by the server matches
      the sender's SHA-256.
- [ ] On the iPhone's reconnect the download shows
      `GET /api/v1/files/{id} 200` and the file opens, digest-verified.
- [ ] The file lands inside the sender's quota (`userQuotaBytes`) and is
      still within the TTL (`fileTtlDays`), so it was not cleaned up while
      the iPhone was offline.

## Item 8 - Server failure mid-call

- [ ] Stopping the service (`sc.exe stop LinkoServer`) during a call does
      not stop media: coturn runs as a separate process (started per the
      TURN runbook, see docs/deploy.md) and keeps relaying.
- [ ] The hangup still completes via the peers' data channel while the
      signaling service is down.
- [ ] After `sc.exe start LinkoServer` both apps reconnect on their backoff
      and pending messages flow without server-side duplication
      (message ids stay unique; re-sends replay as `msg.stored`).

## Item 9 - Analytics

- [ ] Both calls of the session appear in `linko-server calls list` with
      duration, setup time (`setupMs`), candidate type and end reason - the
      CLI prints only those fields; RTT and loss are read from the report
      JSON that `calls show <callId>` prints.
- [ ] `calls show <callId>` prints the stored reports of that call for both
      sides, including RTT and loss.
- [ ] The report POSTs appear in the log as
      `POST /api/v1/calls/{callId}/report 204` (the report endpoint answers
      204 No Content).
