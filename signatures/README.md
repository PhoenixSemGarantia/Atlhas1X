# Local signature sources

This directory prepares local, offline sources for a future optional analysis
integration. Nothing here is executed by the current Atlhas1x scan.

- `clamav/` stores a locally managed ClamAV database when ClamAV/freshclam are
  installed separately on Windows.
- `yara/` stores locally supplied `.yar` and `.yara` rules. Preserve the
  author, copyright, licence and source metadata for third-party rules.
- `hashes/` stores the local SQLite SHA-256 reference-hash database.

ClamAV and freshclam are optional external tools; their absence must not block
the scanner. The normal scan remains offline and never updates these sources.
