# CAIRN: notes for Claude

## Versioning

The version lives in `VERSION` at the top of the repo, as `MAJOR.MINOR.PATCH`. It is shown under
the logo in the sidebar, to signed-in users only.

- **PATCH:** every time you write a set of changes to this source folder, add one to PATCH in the
  same delivery (1.2.0 becomes 1.2.1). One bump per set of changes, not one per file.
- **MAJOR.MINOR:** the owner decides these. Never change them yourself. When the owner sets a new
  MAJOR.MINOR, PATCH starts again at 0.
- Do not bump for changes that never reach the source folder (scratch work, tests run elsewhere).
- Say the new version number in your reply when you bump it.
