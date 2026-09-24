# NEMESIS_TARGET_CORPUS_IMPORT_001

This is a transport package assembled from original files already present in the conversation runtime.

## Rules
- Original source/evidence bytes are copied without content modification.
- The generated manifest and SHA256SUMS describe transport provenance only.
- Do not infer benchmark completeness from package presence.
- Do not infer scientific validity, model performance, oracle blindness, or independent replication from hashes.
- Missing components are listed explicitly in IMPORT_MANIFEST.json and must remain missing until supplied from a primary artifact.

## Intended repository destination
Suggested path: `evidence/imports/NEMESIS_TARGET_CORPUS_IMPORT_001/` on a dedicated intake branch.

## First gate after import
Re-run R01 TARGET_CORPUS_PRESENCE. Do not run RAW_CHAIN_009 until the canonical task/RAW/scorer/oracle set is located or explicitly marked incomplete.
