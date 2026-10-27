# Google Drive export

NmapUI uses the Drive v3 REST API and the narrow `drive.file` permission. It
creates report folders and uploads generated files; it does not request access
to read or manage the entire Drive. A folder must be accessible to the OAuth
client. Copying an arbitrary folder ID does not itself grant access.

## Connect and disconnect

Import the OAuth client JSON in Settings, then select **Connect Google Drive**.
The import validates JSON and preserves the previous client if the new document
is invalid. Sign-in uses Google's system-browser consent page, PKCE S256 and a
single-use state with a ten-minute lifetime. The native elementary client must
hand Google sign-in to the system browser; embedded Google consent is unsupported.

The Settings disclosure explains that connecting creates `nmapui-reports`,
enables future report uploads and attempts to upload the latest completed report.
Select **Disconnect** to remove local tokens, disable automatic Drive sync and
request Google revocation. If revocation cannot be confirmed, Settings says so;
remove the grant from the Google Account before assuming remote revocation.
An already-running network request may finish while disconnect is requested.
Local scans, saved reports and the Daedalus bridge do not require Drive consent.

Access and refresh tokens are encrypted at rest. Tokens, encryption keys and
client configuration are written atomically with owner-only permissions. Back
up encrypted tokens with their matching keys; a missing key is not regenerated
over existing ciphertext. The documented production server uses one worker;
in-process lifecycle and token locks do not provide multi-process coordination.
Revoked refresh grants clear the unusable connection and ask for reconnection.
HTTP responses containing consent state or connection status are not cached.

## Upload behavior

Uploads use a resumable session and at most 8 MiB per transfer chunk, with the
correct file MIME type. On a connection failure, rate limit or server error,
the client asks Google for the confirmed byte offset before sending more data.
It uses bounded backoff and refreshes a rejected access token once. It does not
follow upload redirects, expose session URLs in errors, silently restart an
expired session or report success without a Google file ID. Files that change
during a transfer are rejected. Confirmed earlier files remain listed if a
later file fails, and the overall result remains unsuccessful.

Recovery is within the current upload call. Sessions are not durably resumed
across application restart, and manually retrying a whole report can create a
new report folder or duplicate previously successful files. This is not an
exactly-once delivery guarantee. The Drive export is separate from Daedalus's
durable bridge acknowledgements.

## Google production configuration

The code changes are not evidence that a deployed OAuth project has completed
Google's production requirements. Before distributing the client:

- Use the appropriate client type and registered loopback or HTTPS callback for
  the deployment. Keep production and testing projects separate.
- Confirm the Drive API, `drive.file` scope, brand identity, support contact,
  owned domains, home page, privacy policy and terms match the shipped product.
- Complete applicable branding/scope verification and check Workspace admin
  restrictions. Do not infer production approval from a successful test-user login.
- Keep OAuth clients and tokens out of public source, logs and distributed
  customer data exports. Check folder access and inherited sharing before
  uploading network inventory or vulnerability reports.
- With an authorized account, verify sign-in, a synthetic small and large
  upload, interrupted-transfer recovery, file contents, destination visibility,
  revoked-token recovery and disconnect. Record the exact release, client
  configuration and dated result without recording secrets in public evidence.

Current project/cloud configuration and real-account consent remain separate
release evidence; automated tests use synthetic tokens and a simulated server.

## Verification and performance evidence

`tests/test_google_drive_modules.py` covers token storage, consent lifetime and
replay, refresh serialization, revoked grants and client validation.
`tests/test_google_drive_upload.py` covers chunk bounds, partial acknowledgements,
lost completion responses, 401 refresh, rate limits, malformed responses,
redirect rejection and changed files. Auth-route tests cover origin protection,
HTML escaping and connect/disconnect races. Browser tests cover JSON import,
sign-in window isolation and popup-blocking feedback.

Run `python scripts/benchmark_drive_upload.py --size-mib 32` for a synthetic,
offline comparison against the former Requests multipart preparation. On the
October 25 development host, peak traced Python allocation was 71,321,550 bytes
for the former 32 MiB upload versus 17,014,203 bytes for resumable chunks.
At 128 MiB it was 285,231,142 versus 17,016,487 bytes. These measurements show
bounded application allocation, not measured network throughput or full
process resident memory. The benchmark makes no network requests.

## References

- [Drive upload protocols and recovery](https://developers.google.com/workspace/drive/api/guides/manage-uploads)
- [Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)
- [OAuth token and client best practices](https://developers.google.com/identity/protocols/oauth2/resources/best-practices)
- [Desktop system-browser OAuth](https://developers.google.com/identity/protocols/oauth2/native-app)
- [OAuth policies](https://developers.google.com/identity/protocols/oauth2/policies)
- [Production configuration and verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/policy-compliance)
