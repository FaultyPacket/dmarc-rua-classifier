# Changelog

## 1.2.0 - 2026-10-29
- Licence changed from MIT to AGPL-3.0-or-later; added NOTICE.
- Moved to RFC 9989 (DMARC, May 2026), RFC 9990 (aggregate reports) and
  RFC 9991 (failure reports). All citations re-pinned to the RFC Editor text.
- Organizational Domain by RFC 9989 4.10 DNS Tree Walk (max 8 queries);
  the PSL result is kept as a legacy comparison and differences are reported.
- Policy discovery per 4.10.1 (own record, Organizational Domain, PSD).
- `np`, `psd`, `t` validated as active tags; `pct`, `rf`, `ri` flagged as
  historic (9.3; `pct` below 100 is a warning, A.6); `fo` grammar (4.8); `!size` flagged obsolete; missing `p`
  is a warning (treated as `p=none`).
- `DMARC1` matched case-sensitively; near-miss records reported.
- New warning when a parent public suffix publishes a record without `psd=y`
  (5.2, 11.8).
- External verification cites RFC 9990 4 / RFC 9991 5; DNS name-length limit
  checked; CSV gains `org_domain_tree_walk` and `org_domain_psl`.

## 1.1.0 - 2026-10-29
- New `--check` own-domain mode: record syntax and values (RFC 7489 6.3/6.4),
  multiple-record rule (6.6.3), subdomain fallback note.
- External report destination verification for `rua` and `ruf`
  (RFC 7489 7.1): queries `<domain>._report._dmarc.<host>` when the
  destination's Organizational Domain differs; flags missing authorisation.
- Organizational Domain via the Public Suffix List (`publicsuffixlist`).
- `--json`, `--version`, `--doh` / `--doh-url`, `--resolver`, `--timeout`.
- Batch input: arguments, `-f/--file` (repeatable, `-` = stdin), piped stdin;
  accepts domains, URLs and email addresses; dedupes; per-domain errors are
  isolated. A positional file path still works (1.0 usage).
- Exit status 1 if any domain fails or any input is invalid.
- Default transport is now port-53 DNS via dnspython; use `--doh` for the 1.0
  DNS-over-HTTPS behaviour. Classify-mode CSV columns are unchanged.

## 1.0.0 - 2026-10-29
- Initial release: rua destination tiers T0-T5, optional providers.csv.
