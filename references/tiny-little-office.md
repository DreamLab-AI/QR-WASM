# Tiny Little Office — upstream reference

- Project: https://github.com/aboard-io/tinylittleoffice
- Website: https://tinylittleoffice.com
- License: MIT (upstream)
- API: https://tinylittleoffice.com/api.js
- Format documentation: https://tinylittleoffice.com/llms.txt

Tiny Little Office stores document state in the URL fragment and loads its application code separately. QR-WASM explores the distinct possibility of encoding executable modules, dependency manifests and integrity information inside QR payloads, including progressive multi-QR loading.

**Integration approach:** link to upstream instead of copying a moving JavaScript codebase. If source is vendored later, pin an exact upstream commit, retain MIT license and notices, and document modifications. Consider a Git submodule only after deciding whether full upstream source is needed.

Research comparisons: fragment encoding; compression and byte budgets; offline operation; content privacy; key-bearing URLs; scanner ergonomics; provenance and browser capability isolation.
