# Publication contention

Background ingestion and enrichment commit collected evidence, cursors and cache changes before trying the single publication lock. Only the lock owner performs build maintenance and publishes a complete atomic generation. There are no source or model network requests inside the build.

If another publisher owns the lock, the background cycle returns promptly with `publication_pending`, `publication: pending` and no claimed generation. A warning is logged. A durable `publication_request` remains in the native database; this is a scheduling marker, not a new scoring observation. The existing periodic ingestion/enrichment loop retries the build, including previously committed data even if no new source records arrive. The last good generation stays available during contention or a publisher crash. A real collection/build error still raises and reports failure.

`publication_request.requested` preserves the oldest outstanding request time; `latest_requested` records the latest request. A successful publisher writes `publication_completed.request_id` for the request captured before its build. A newer request arriving during that build remains outstanding. Compare these IDs and the current manifest time when diagnosing a backlog. A stopped or persistently failing scheduler still requires operational repair; pending status does not prove current publication. Normal deployments must keep the existing ingest and enrichment schedules active.

Foreground rebuilds retain their bounded 30-second lock wait and propagate failure. No timeout was increased and no lock was removed. List contents, native scoring and retention, allowlist/crawler precedence and AI pilot rules are unchanged.
