# Socket.IO Swift client provenance

Source: https://github.com/socketio/socket.io-client-swift
Official v16.1.1 / commit `42da871d9369f290d6ec4930636c40672143905b`.
Only upstream Sources, Package.swift and MIT LICENSE are vendored.
`privacy-session.patch` is the complete local diff: remove the unavailable
upstream test target; add one URLSessionConfiguration option, copied when
configured and on **every** session reset. Protocol, codec, queue and reconnect
logic remain upstream. Default configuration remains upstream-compatible.
`PROVENANCE.json` records original and distributed file digests. Upstream
whitespace is retained byte for byte; local attributes exempt only these sources
and the unified patch context from whitespace lint.

NmapUI supplies fresh ephemeral configuration with no credential/cookie/cache
stores or ambient proxies, rejects redirects and authentication challenges,
and uses explicit memory-only UTF-8 Basic headers. The adapter disables SDK
retries: reconnect fetches a fresh token and only requests canonical status.
No mutation is replayed. A disconnected start may have reached the server and
is shown as uncertain until status reconciliation or explicit acknowledgement.

Starscream remains the upstream dependency, resolved exactly in the parent
Package.resolved. Its Apache-2.0 license and this SDK's MIT license are included
in NmapUIApp resources and checked in actual optimized bundle tests.
