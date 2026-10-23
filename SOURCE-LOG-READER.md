# Complete compressed log inputs

`source_log_reader.collect_log_inputs` is a portable local-file reader. The caller
supplies ordered paths, its existing per-file state dictionary, a line consumer,
and the retention cutoff. Parsing, qualification, counters, source timestamps,
event IDs, and output suppression belong to the caller.

A compressed input is copied to a temporary compressed-byte snapshot with a
1 MiB memory rollover threshold plus bounded read/decompression buffers. Its observed inode, size, and modification time must
remain stable during that copy. The complete snapshot is decompressed through
its final checksum before the consumer receives a line. Truncated streams,
invalid checksums, and rotation during capture defer that entire input, preserve
its prior cursor, and report its exact path. Valid prefixes of damaged archives
remain in the original file for retry; they are not emitted speculatively.

Other complete inputs continue. The returned coverage is explicitly `partial`
when any input is deferred. The Private edge adapter persists that coverage in
its existing state file and includes it in its operator summary. Community ships
the same portable reader for collector integrations; it does not bundle the
site-specific Private edge deployment script.

Plain inputs keep their existing incremental text-offset behavior. Completed
unchanged archives are skipped; a changed archive is replayed from its start,
with the caller's existing event-ID/output suppression preventing duplicates.
The state records the captured inode rather than a replacement at the same path.
The reader does not change source files or discard a failed input's saved state.

Validation requires two decompression passes for a new or changed healthy
archive and temporary disk space for one compressed file. This trades additional
archive I/O for avoiding partial-file effects and unbounded memory buffering.
It does not solve long scans of large uncompressed files, repair damaged
archives, or establish complete coverage when a source is deferred.
