# P4 review note

Independent reviews of everything since the P2 gate (`e66b2f7`) up to the P4 gate working tree, run on 8 Nov 2026 by separate agents
with fresh context. Findings are copied here by severity; none was edited into the verdict.

## Security review (security-reviewer)

Verdict, verbatim: `VERDICT: PASS WITH NOTES`. No BLOCK item. The reviewer found no invariant violation: the capture gate re-reads
the checkout under a row lock, mandate identity is hashed over what the platform signed, the customer binding is insert only, the
assistant only picks read-only tools and answers from templates, and nothing in the evaluation timing wrapper changes production
behaviour.

| # | Severity | Finding | Disposition |
| - | -------- | ------- | ----------- |
| 1 | MEDIUM | Anyone who can reach a demo instance can start attack runs in a loop (no rate limit, admin database URL in the web process, run records grow) | Carry-forward to P5.1, already L66. Fix: operator token or launcher off in demo, per-IP limit, rotate records, separate worker |
| 2 | LOW | The attack-run body is read with `json.loads`, not the strict loader (INV-8) | Fixed in this commit (see PROGRESS) |
| 3 | LOW | Evidence bundles are listable through the unauthenticated dashboard API; a docstring says a caller must already know a capture id | Docstring corrected; the exposure is L57 (no dashboard login). Gate the API in demo before P5 deploy |
| 4 | NOTE | Dashboard "Verify evidence" does not pin keys, so only internal consistency is shown | Carry-forward to P5: pin the merchant key from `/.well-known/ucp` and the platform key from a served public JWK |
| 5 | NOTE | A failed bundle assembly leaves no entry in the hash-chained log | Carry-forward: append `evidence.failed` (relates to L68) |
| 6 | NOTE | `Infinity` in `latest.json` would make the eval endpoint answer 500 | Fixed in this commit: non-finite numbers read as 0 |
| 7 | NOTE | The timing patch swaps a class attribute, not thread safe | Accepted: eval-only, runs are sequential. Revisit if tasks move onto threads |

Also noted by the reviewer: the server holds the platform private key and signs open mandates after a verified device consent, so a
server compromise can mint mandates. That trust model is unchanged by this diff and stays in the threat model.

## Design review (design-reviewer)

Every surface at 375 px and 1440 px, light and dark: the dashboard views and an order detail, the Trusted Surface phone pages, the
evidence verifier page. Not captured with live data: the approve-intent and approve-purchase screens (the pages showed their error
states). No BLOCK. The phone pages and `/verify/` have no horizontal overflow and every control is 44 px or larger; no text overclaims
PayPal protection or dispute outcomes (INV-13).

| Severity | Finding | Disposition |
| -------- | ------- | ----------- |
| HIGH | Results: the Missed group in the Targets grid read 0 (a sum of "met" flags) | Fixed: the grid counts targets, and a browser test asserts the Missed row carries the count |
| HIGH | Results: Totals grid clipped columns and headers | Fixed: short headers |
| HIGH | Results: bundle columns read 0 next to an all-zero headline with no explanation | Fixed: a note under the title, and L68 |
| HIGH | Results: category chart has no legend, full bars are all zero | Partly fixed: the subtitle says bars are baseline and full is 0 (computed from the data); legend and bar thickness are Studio options, carried forward |
| HIGH | Orders: Captured tile reads $0.00 beside completed rows; blocked chart scale; donut legend mismatch | Carry-forward, P5 design polish (older view, not changed in P4.9) |
| HIGH | Setup page shows a "Working" badge before anything is done | Carry-forward (phone page, static file table) |
| MEDIUM | Dashboard at 375 px overflows by 11 px and has 34 to 36 px controls; truncated Orders cells; selected row style; font families inside Studio | Carry-forward |
| MEDIUM | Results intro line was one long sentence | Fixed: split, file path removed |
| MEDIUM | Tile subtitles gave no baseline comparison | Fixed: each tile names the baseline figure |
| LOW | Four dashes in the Orders view text; truncated search placeholder; long sandbox pill; gallery route is a 404 in the app; verify page has no empty-state hint | Carry-forward (the gallery 404 is intended: it is not in the static table) |
