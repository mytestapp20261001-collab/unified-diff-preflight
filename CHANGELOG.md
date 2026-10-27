# Changelog

## 2026-10-27

- Reject Unicode decimal digits in hunk positions/counts instead of treating malformed headers as valid ranges. Unicode paths, body lines and optional hunk descriptions remain supported.
- Preserve the original migration record and October 23 receipt; apply the new dated source/test delta after the prior receipt.

## 2026-10-23

- Reject structurally inconsistent content after a no-final-newline marker on the same old/new file side, including later hunks and empty ranges that imply a gap past EOF.
- Preserve valid opposite-side continuation, exact-EOF empty ranges, file creation/deletion, CRLF input and independent file sections. Invalid structures return generic error JSON / exit 2 without source content.
- Keep the original migration record and hashes immutable; the dated maintenance receipt records only the two source/test deltas.

This is the documented offline structural subset, not full Git syntax validation or a patch-applicability guarantee. No base tree is read or patch applied. [GNU Diffutils incomplete-line semantics](https://www.gnu.org/software/diffutils/manual/diffutils.html#Incomplete-Lines) motivate the side-specific EOF check.
