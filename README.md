# threat-intel

A small threat intelligence operation for the seclab. It collects public threat
intelligence feeds, stores them in SQLite, correlates them (malicious infrastructure,
malware families, ransomware groups, ATT&CK techniques, phishing brand impersonation,
exploited vulnerabilities), keeps a daily history, looks up registration data over RDAP
on demand and serves the result through a pivot/enrichment API and a simple HUD on
`127.0.0.1:8102`.

It works offline: a trimmed snapshot of every feed lives in `fixtures/`, so
`python -m threatintel seed` gives a full demo with no network at all.

## Architecture

```
  public feeds (only hosts on the FEED_HOSTS allowlist are ever contacted)
  CISA KEV  FIRST EPSS  NVD  ATT&CK STIX  Feodo  URLhaus*  ThreatFox*  OpenPhish
  ransomware.live  Spamhaus DROP  Tor exits  iptoasn  SSLBL certs  ET compromised
  CINS Army  blocklist.de  Phishing Army  CIRCL OSINT (MISP)  OTX*   (* needs free key)
        |
        v
  fetch.py  ---- polite HTTP: UA "seclab-ti/0.1", per-host spacing, timeouts,
        |        retries on 429/5xx, ETag / If-Modified-Since, on-disk cache
        v
  collectors/<feed>.py   fetch -> normalise -> store      (fixtures/ in seed mode)
        |                every run logged in feed_runs
        v
  SQLite data/threatintel.db
   indicators + sightings | vulnerabilities | actor_records | techniques/tactics
   software | victims | netblocks | relationships (generic edge table) | clusters
        |
        v
  correlate.py  alias merge (union-find) -> software/malware links -> vuln priority
                -> ASN + DROP containment + confidence -> phishing brands/hosting
                -> clusters (/24, ASN, registered domain, inside DROP)
        |
        |               -> daily_snapshot (trends.py) at the end of every run
        +--> pivot.py    search any value, BFS over relationships -> tables + graph
        +--> enrich.py   POST IOCs or a STIX 2.1 bundle -> verdict + context
        +--> rdap.py     on demand: IANA bootstrap -> registry RDAP server (never the host)
        +--> trends.py   new C2 / phishing per day, leak-site posts per week, snapshots
        +--> export.py   STIX 2.1 bundle, blocklists, CSV
        +--> brief.py    intelligence brief (Markdown + HTML)
        |
  server.py (FastAPI) + scheduler.py (background thread) + static/ HUD
  cli.py: python -m threatintel {seed, collect, correlate, search, brief, export}
```

## Quick start

```
./run.sh                      # creates .venv, seeds the demo DB on first run, serves 127.0.0.1:8102
```

CLI (from the project folder, with `.venv/bin/python` or system `python3`):

```
python -m threatintel seed --fresh          # offline demo data, then correlate
python -m threatintel collect all           # live collection of every enabled feed
python -m threatintel collect nvd           # one feed (nvd and ip2asn are off by default)
python -m threatintel collect all --correlate
python -m threatintel correlate
python -m threatintel search CVE-2023-4966  # also: akira, 50.16.16.211, T1486, "Cobalt Strike", AS14061
python -m threatintel search example.com --rdap   # adds registration data from the registry
python -m threatintel rdap paypal-login.example  # just the RDAP lookup
python -m threatintel brief --days 7        # writes data/reports/brief-*.md and .html
python -m threatintel export [--fanged]     # writes data/exports/
python -m pytest -q                         # 99 tests, offline, about 9 s
```

Optional keys. They are never written to a file or the repo. Store them in the desktop keyring
(Secret Service, encrypted at rest and unlocked with your login):

```bash
.venv/bin/python -m threatintel set-key ABUSECH_AUTH_KEY      # prompts, no echo, no shell history
.venv/bin/python -m threatintel set-key OTX_API_KEY
.venv/bin/python -m threatintel set-key ABUSECH_AUTH_KEY --delete
```

An environment variable with the same name overrides the keyring (useful for containers).

| variable | used by | effect |
|---|---|---|
| `ABUSECH_AUTH_KEY` | urlhaus, threatfox | required; get one free at https://auth.abuse.ch/ . Without it both feeds are skipped cleanly (status `skipped`). |
| `NVD_API_KEY` | nvd | optional; raises the NVD rate limit so pages are spaced 0.7 s instead of 6.5 s. |
| `OTX_API_KEY` | otx | required for the OTX feed (free account at otx.alienvault.com). Without it the feed is `skipped`. |

## HUD tour

The HUD is deliberately plain: three tabs, mostly tables, one button per action.

- **Overview**: counts; the prioritised KEV table with the score breakdown per CVE
  (KEV + EPSS + CVSS + ransomware + recency), a "ransomware-linked only" filter and a
  text filter; ransomware groups with 7 and 30 day post counts, top sectors and
  countries; ATT&CK techniques ranked by how many active groups use them; C2 servers by
  malware family; infrastructure clusters; phishing brands, TLDs, hosting platforms,
  busiest registered domains and IPs inside DROP, with the branded rate per phishing
  source now and with the old keyword matcher; the highest-scoring brand impersonation
  with its reasons; a daily trends table (baseline day marked), C2 listings per day by
  family, phishing first seen per day by brand, leak-site posts per week; indicators per
  source and recent MISP events. Every CVE, group, technique, family, event and indicator
  is a link that opens it in Search.
- **Search & Enrich**: one search box for any value, the entity details (with
  first/last observed and the phishing score and reasons where they apply), an "RDAP"
  tick box for registration data, a force graph of linked nodes (click a node to pivot to
  it) and tables of everything linked. Below it, paste IOCs or a STIX bundle and press
  Enrich ("Sample input" fills in a few known and unknown values; "with RDAP" adds
  registration data).
- **Feeds & Brief**: "Load demo data (offline)", "Run correlation", scheduler on/off,
  one row per feed with an enable checkbox, last status, rows, key status, last error and
  a refresh button; the brief generator with view/download links; export links; recent runs.

## Terminal HUD

A curses view of the same API for SSH sessions. Start the server first (`./run.sh`), then:

```
.venv/bin/python -m threatintel tui                  # 127.0.0.1:8102
.venv/bin/python -m threatintel tui --url http://127.0.0.1:8102 --once   # plain text, for SSH or scripts
```

Views: Overview counts, Vulns (prioritised CVEs), Ransomware groups, Feeds status,
Trends (one row per day: indicators, new, new C2, C2 certificates, phishing URLs and
domains, victim posts) and Phishing (highest scores with brand, method and reasons).

- `1`-`9` or Tab: switch view. Left and right arrows also switch.
- Up and Down arrows (PgUp, PgDn): move through rows. On detail screens they scroll.
- Enter: open a detail. On Vulns and Ransomware this runs a search pivot on the CVE or
  group. On Feeds it shows that feed's recent runs. On Trends it shows every trend table.
  On Phishing it runs an RDAP lookup of the registered domain (registry only, cached).
- Esc or Backspace: back from a detail.
- Action keys, shown in the footer: `c` correlate, `b` brief, `f` refresh the selected feed
  (use it on the Feeds view), `s` load demo data. Each asks `[y/N]` first.
- `r`: refresh the current view. `q`: quit.

`--once` prints every view as plain text and exits 1 if any view cannot reach the API.
Feed collection is never started by `--once`.

## Data sources and terms

Checked on 2026-11-13. "Live" means it worked without a key on that date.

| feed | endpoint | live | licence / terms |
|---|---|---|---|
| CISA KEV | `www.cisa.gov/.../known_exploited_vulnerabilities.json` | yes | US Government work, public domain (CISA publishes it under CC0 1.0) |
| FIRST EPSS | `api.first.org/data/v1/epss?cve=...` (batches of 100) | yes | free to use; FIRST asks for attribution of EPSS |
| NVD CVE API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0?hasKev` (paged) | yes, slow; one 503 seen and retried | public domain; required notice: "This product uses the NVD API but is not endorsed or certified by the NVD." |
| MITRE ATT&CK | `raw.githubusercontent.com/mitre-attack/attack-stix-data/.../enterprise-attack.json` (~55 MB, cached) | yes | ATT&CK Terms of Use: free to use and reproduce with the MITRE copyright notice. (c) The MITRE Corporation. |
| Feodo Tracker | `feodotracker.abuse.ch/downloads/ipblocklist.json` | yes (only 5 entries today) | abuse.ch data is CC0 |
| URLhaus | `urlhaus-api.abuse.ch/v1/urls/recent/limit/N/` | needs key | CC0. The anonymous `downloads/csv_recent/` and `text_recent/` exports now answer 410 Gone. |
| ThreatFox | `POST threatfox-api.abuse.ch/api/v1/ {"query":"get_iocs"}` | needs key | CC0. The anonymous `export/json/recent/` answers 410 Gone. |
| OpenPhish | `raw.githubusercontent.com/openphish/public_feed/.../feed.txt` (openphish.com/feed.txt redirects there) | yes | community feed, free for non-commercial use |
| ransomware.live | `api.ransomware.live/v2/groups`, `/v2/recentvictims`, `/v2/victims/{y}/{m}` | yes | free public API with attribution; it answers "1 per 1 minute" if called faster, so requests are spaced 62 s and a run takes ~3 minutes. Victim posts are criminals' claims, unverified. |
| Spamhaus DROP | `www.spamhaus.org/drop/drop_v4.json` and `drop_v6.json` | yes | free for use in your own network filtering; check the Spamhaus DROP terms before redistributing. EDROP was merged into DROP (edrop.txt only carries a notice). |
| Tor exits | `check.torproject.org/torbulkexitlist` | yes | public data from the Tor Project; used as context, not as a malicious flag |
| iptoasn | `iptoasn.com/data/ip2asn-combined.tsv.gz` (~11 MB) | yes | PDDL v1.0 (public domain) |
| Public Suffix List | trimmed copy in `threatintel/resources/` | bundled | MPL 2.0 |

Added on 2026-11-14 (each URL was checked that day before it was used):

| feed | endpoint | live | licence / terms |
|---|---|---|---|
| abuse.ch SSLBL certificates | `sslbl.abuse.ch/blacklist/sslblacklist.csv` (850 KB, newest 1500 kept) | yes | CC0 (abuse.ch terms). The SSLBL IP blacklist was deprecated on 2025-01-03 (file is empty) and the JA3 list was last updated in 2021, so neither is used. |
| Emerging Threats compromised IPs | `rules.emergingthreats.net/blockrules/compromised-ips.txt` | yes | Proofpoint ET Open, free to use |
| CINS Army | `cinsscore.com/list/ci-badguys.txt` (15 000 IPs, 5000 sampled) | yes | free public list from Sentinel IPS; no redistribution terms in the file |
| blocklist.de | `lists.blocklist.de/lists/ssh.txt` (or `all.txt` with `list = "all"`) | yes | free service, fair use and attribution asked |
| Phishing Army | `phishing.army/download/phishing_army_blocklist.txt` (1 MB, 145 000 domains, 4000 sampled) | yes | free for personal and individual use (phishing.army/license) |
| CIRCL OSINT MISP feed | `www.circl.lu/doc/misp/feed-osint/manifest.json` + the 10 most recently updated events under 2.5 MB | yes | public OSINT feed from CIRCL, events tagged TLP:CLEAR/white |
| AlienVault OTX | `otx.alienvault.com/api/v1/pulses/subscribed` | needs key | OTX terms of service; `pulses/subscribed` and `pulses/activity` answer 403 without a key |
| RDAP (on demand) | `data.iana.org/rdap/{dns,ipv4,ipv6}.json`, then the registry server they name; `rdap.org` as fallback | yes | IANA bootstrap is public; registry RDAP data is public registration data |

Checked and not used: Feodo `ipblocklist_recommended.json` is a subset of the main file
(1 entry today, already in `ipblocklist.json`); the Phishing.Database project has not
updated since 2026-10-02 (its NEW-today lists are empty and the ACTIVE list is 11 MB).

## How the requirements are met

**Collectors** (`threatintel/collectors/`): one module per feed with `fetch`,
`load_fixture`, `normalise` and `store`. `fetch.py` provides the cache in `data/cache/<feed>/`,
ETag / If-Modified-Since (304 means "use the cache"), `min_refetch_s` (cache younger than
this is reused without a request), per-host spacing, timeouts, two retries with backoff on
429/5xx and a fallback to the last good copy if the network fails. `config/feeds.toml`
holds enabled flags, intervals and limits. Every run writes a `feed_runs` row (start,
end, status `ok/cached/stale/skipped/error/seeded`, rows, error, mode live/fixture).

**Data model** (`threatintel/db.py`): `indicators` (ip/cidr/domain/url/hash, first/last
seen, sources, tags, confidence) with one `sightings` row per reporting feed;
`vulnerabilities`; `actor_records` (each source's view) merged into `actors` and
`actor_aliases`; `tactics`, `techniques`, `software`; `relationships` (src, rel, dst,
source, first_seen); `victims`; `netblocks`; `clusters`; `feed_runs`; `feed_state`
(HUD overrides of the enabled flag).

**Correlation** (`threatintel/correlate.py`):
- Group aliases: names are normalised (case, punctuation, suffixes like "ransomware",
  "group", "team", glued forms like "incransom") and mapped through the curated table
  `config/aliases.toml`. A union-find over all names and aliases merges ATT&CK groups
  with ransomware.live groups (for example Akira G1024, INC Ransom G1032, Play G1040,
  Medusa G1051). Live data: 600 records became 579 actors, 11 merged across sources.
- Indicators to malware to ATT&CK: Feodo's `malware` field, ThreatFox `malware`, and
  URLhaus tags (minus generic ones like `elf` or `32-bit`) become `malware:<family>`
  nodes; these link to ATT&CK software by name/alias (`QakBot` -> S0650), and software
  links to the groups that use it and to techniques. Ransomware groups link to their
  family software ("LockBit 3.0", "Akira", "BlackCat"), only when the ATT&CK entry is
  described as ransomware, and to tools from their ransomware.live tool lists.
- CVEs: KEV gives cve -> product -> vendor edges and the ransomware flag; CVE ids in
  ATT&CK group and relationship descriptions become group -> cve "exploits" edges.
- Phishing: URL -> host -> registered domain with `psl.py` (a small Public Suffix
  List implementation with wildcard and exception rules), brand keywords from
  `phishing.py` (ignored when the URL is on the brand's own domain), TLD counts and
  hosting platform (PSL private suffixes such as pages.dev, plus a few site builders).
- Clusters: shared IPv4 /24, shared ASN, shared registered domain (2+ URLs) and IPs
  inside DROP netblocks (bisect over sorted ranges).

**More sources** (round 2): `collectors/iplists.py` holds one parser for the three plain
IP lists (ET, CINS, blocklist.de; private and reserved ranges are dropped so a list can
never flag the lab's own networks). `sslbl.py` stores certificate SHA-1 fingerprints as
`hash` indicators tagged `x509-sha1` with the malware family from the listing reason
(the STIX export writes an `x509-certificate` pattern for them). `phishingarmy.py` adds a
second, much larger phishing population (domains only). `circl.py` reads the MISP
manifest, picks recent events under a size cap and keeps up to 300 `to_ids` attributes
each; event galaxy tags become edges to malware families, ATT&CK techniques and (in
correlation) to actors, so an IP from a CERT-FR Sandworm report pivots to Sandworm.
`otx.py` is the key-only feed. Big lists are cut with a stable hash sample
(`base.stable_sample`: bottom-k by SHA-1), which keeps a fair cross-section and keeps
the same items day to day, so first/last-seen history means something. Rotating lists
have `retention_days` (14 or 21): entries that left the list are pruned after that.

**Phishing analysis** (`threatintel/phishing.py`, brands in `config/brands.toml`, 75
brands with names and their real domains). Each host label is checked as written
(punycode decoded with IDNA) and again after folding to a Latin skeleton (Cyrillic and
Greek confusables, accents) and folding character swaps (0/o, 1/l, 3/e, rn/m, vv/w):

- brand as a host token (`secure-paypal-login`), brand inside a label (`paypalsecure`);
- lookalike by optimal string alignment distance: first letter must match, 6-letter
  brands allow one substitution or swap, 7-8 letters one edit, 9+ letters two; also on
  the start or end of a longer label (`trezurs-logons`). A stoplist removes ordinary
  words one edit away from a brand (looking/booking, finance/binance);
- homoglyph: brand only visible after folding (`xn--80ak6aa92e.com` shows as Cyrillic
  "аррӏе", `g00gle`, `rnicrosoft`);
- brand only in the path or userinfo (weaker). Short brands (ups, att, dhl) only match
  as whole tokens, which removes the old `purchase` -> chase hits.

A brand is never reported for its own registered domains. The score adds signals and
keeps one reason per point:

```
phish score = max(brand evidence: homoglyph 40 | lookalike 35 | brand token 30 | in label 25 | in path 15)
              + punycode 10 + suspicious words 5 each (max 20) + high-abuse TLD 10 + free hosting 10
              + IP host 15 + 3+ subdomain levels 5 + host > 40 chars 5 + 2+ hyphens 5
              + registered < 30 days 20 / < 180 days 10 (RDAP, when looked up) + listed by 2+ feeds 10
              capped at 100
```

The old keyword matcher is kept as `keyword_brands()` and stored next to the new result,
so the before/after rate is measured on the same data (HUD, brief, `/api/phishing`).

**RDAP** (`threatintel/rdap.py`): `/api/rdap?q=`, `/api/search?...&rdap=true`,
`/api/enrich?rdap=true` and `python -m threatintel rdap` return registration date,
expiry, registrar, abuse e-mail and (for IPs) the network name and holder. The lookup
goes by registered domain, uses the IANA bootstrap to find the registry, allows only
bootstrap hosts (also after redirects), spaces requests 2 s apart, caps network lookups
at 8 per API call and caches answers (also "not found") for 7 days. Search and enrich
always show cached RDAP data; they only go to the network when `rdap=true`.

**History and trends** (`threatintel/trends.py`): every sighting keeps `first_obs`,
`last_obs` and `days_seen` (when this lab saw it, separate from the dates a feed
reports). Correlation ends with a snapshot of the key counts into `daily_snapshot`.
`GET /api/trends?days=30` returns the daily table, new C2 per day by family (observed
and feed-reported), phishing first seen per day by brand and by TLD, leak-site posts per
week by group and new indicators per day by source. The first collection day is marked
as the baseline because it counts everything already listed as new. Older databases are
migrated in place: existing sightings get the time of their feed's first run.

**Scoring** (`threatintel/scoring.py`, also shown in the HUD and the brief):

```
indicator confidence (0-100)
  w_s = source weight: spamhaus 0.90, feodo 0.85, sslbl 0.85, threatfox confidence_level/100
        (else 0.75), urlhaus 0.75, openphish 0.70, circl 0.60, phishing_army 0.60, otx 0.55,
        et_compromised 0.55, blocklistde 0.50, cins 0.45, inside a DROP netblock 0.40,
        lab enrichment 0.15, tor 0
        (a single reputation list stays below the "malicious" threshold of 60; two agreeing
        lists, for example CINS + blocklist.de = 1 - 0.55*0.5 = 0.725, reach it)
  C   = 1 - prod(1 - w_s)                         noisy-OR corroboration
  R   = 0.5 ^ (age_days / half_life)              half-life: url 14, ip 30, domain 45, cidr 180, hash 365 days
  confidence = round(100 * C * (0.25 + 0.75 * R))

vulnerability priority (0-100)
  priority = 20*KEV + 30*EPSS + 25*(CVSS/10) + 15*RANSOMWARE + 10*0.5^(days_since_KEV_add/180)
  KEV, RANSOMWARE are 0/1; EPSS is the 30-day probability; CVSS is the NVD base score,
  7.0 is assumed (and flagged with *) when NVD has not been collected.
```

**Pivot API** (`threatintel/pivot.py`): any value is classified (IP, CIDR, URL,
defanged or not, domain, hash, CVE, technique, tactic, ATT&CK group/software id, ASN,
free text for group/malware/software/vendor/brand) and resolved to start nodes. A
breadth-first walk (depth 2, max 120 nodes) collects linked entities. Techniques,
tactics, vendors, brands and (from an actor) shared tools are not walked through, so
"uses T1486" does not make every ransomware crew look related. Typed node ids such as
`net24:203.0.113.0/24` or `campaign:known-ransomware-use` are accepted too.

**Exports** (`threatintel/export.py`): STIX 2.1 bundle built by hand (identity,
indicators with patterns, malware, intrusion-set, vulnerability, relationships, stable
uuid5 ids), plain blocklists per type, and a CSV of all indicators.

**Brief** (`threatintel/brief.py`): new KEVs in the last N days, top-priority vulns with
the score breakdown, most active ransomware groups (7/30 days) with sectors and
countries, new C2 infrastructure by family, phishing trends, ATT&CK techniques most used
by active groups and collection status. Windows end on today, or on the newest data
point if the data is older (offline fixtures); the anchor date is printed.

**Scheduler** (`threatintel/scheduler.py`): a daemon thread checks every 60 s which
enabled feeds are past their `interval_min`, runs them one at a time and re-correlates.
Off by default (`[scheduler] enabled = false`) so starting the HUD never touches the
network by surprise; switch it on from the Feeds tab.

**Offline first**: `fixtures/` holds trimmed real snapshots taken on 2026-11-13 (KEV 259
CVEs with their EPSS and NVD rows, ATT&CK trimmed to 15 groups and the software and
techniques they need, 5 Feodo C2s, 300 OpenPhish URLs stored defanged, 450 sampled
ransomware posts and the groups behind them, 300 DROP netblocks and 300 Tor exits chosen
so that 41 exits fall inside DROP blocks, the ip2asn rows for those IPs).
Round 2 fixtures (2026-11-14) are trimmed real snapshots too: 200 IPs each from ET, CINS
and blocklist.de (IPs on two lists kept first, so corroboration shows offline), 200 SSLBL
certificate rows, 300 Phishing Army domains stored defanged, the 10 CIRCL events with up
to 60 `to_ids` attributes each (URLs and domains defanged, no attachments), 22 real RDAP
answers from the live run (`rdap-cache.json`, loaded into the RDAP cache by `seed`) and
the real IANA bootstrap plus two RDAP answers for the offline tests (`rdap-samples.json`).
The OTX fixture is **synthetic** (the API needs a key), with RFC 5737 IPs and `.example`
names. `scripts/make_fixtures.py --round2` rebuilds only these.
URLhaus and ThreatFox fixtures are **synthetic samples in the real API format**, because
both APIs need a key; they only use RFC 5737 documentation addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), `.example`/`.test` names and made-up
hashes. `fixtures/MANIFEST.json` records this. `scripts/make_fixtures.py` rebuilds the
fixtures from `data/cache` after a live collect.

## Enrichment API (for the other lab projects)

`POST http://127.0.0.1:8102/api/enrich` with any of these JSON bodies:

```
{"iocs": ["203.0.113.50", "update-qakbot.example", "hxxp://bad[.]example/x", "<sha256>"]}
{"text": "one IOC per line or separated by spaces/commas"}
{"type": "bundle", "objects": [...]}          a STIX 2.1 bundle (indicator patterns and
                                              ipv4/ipv6/domain-name/url/file observables)
```

Query parameters: `record=true` stores each IOC as an `enrich` sighting (weight 0.15,
tagged `reported-by:<reporter>`), `reporter=honeypot-net` names the sender, `rdap=true`
looks up registration data for up to 8 domains/IPs not already cached.

New optional fields (added, nothing removed): `observed: {first, last, days_seen}` (when
this lab saw it across runs), `phishing: {score, brands, reasons}` for phishing
URLs/domains, `rdap: {query, status, registered, expires, registrar, abuse_email,
network, country, server, fetched_at}` when RDAP data is cached or asked for.

Response (offline demo database):

```
{"count": 2, "summary": {"malicious": 1, "unknown": 1},
 "results": [
   {"input": "203.0.113.50", "type": "ip", "value": "203.0.113.50", "match": true,
    "verdict": "malicious", "confidence": 87.0, "sources": ["threatfox"],
    "tags": ["botnet_cc", "c2", "tag:qakbot", "tag:synthetic"], "malware": "qakbot",
    "actors": [], "asn": null, "inside_drop": null,
    "first_seen": 1793916000.0, "last_seen": 1793916000.0},
   {"input": "8.8.8.8", "type": "ip", "value": "8.8.8.8", "match": false,
    "verdict": "unknown", "asn": null, "inside_drop": null}]}
```

`actors` lists `{id, name, attack_id}` for groups linked to the malware family (on live
data QakBot links to TA551 and TA577 through ATT&CK). `asn` is
`{asn, as_name, country}` when the IP is in the ip2asn table (full table after
`collect ip2asn`, only a small subset in the fixtures). URL and domain results also
carry `registered_domain` and `related_in_registered_domain`.


Verdicts: `malicious` (confidence >= 60), `suspicious` (>= 25, or inside a DROP block),
`low-confidence`, `context` (only Tor reports it), `unknown`, `unsupported` (not an IOC).
Example: `curl -s -X POST 127.0.0.1:8102/api/enrich -H 'Content-Type: application/json' -d '{"iocs":["1.2.3.4"]}'`

Other endpoints: `GET /api/health`, `/api/overview`, `/api/search?q=&depth=`,
`/api/vulns?ransomware=&q=&limit=`, `/api/ransomware`, `/api/infrastructure`,
`/api/attack?scope=active|all`, `/api/indicators?type=&q=`, `/api/feeds`,
`/api/feeds/runs`, `POST /api/feeds/{name}/refresh`, `POST /api/feeds/{name}/enable
{"enabled": true|false|null}`, `POST /api/scheduler {"enabled": bool}`,
`POST /api/seed[?fresh=true]`, `POST /api/correlate`, `GET /api/jobs/{id}`,
`GET /api/export/stix?min_confidence=`, `/api/export/blocklist/{ip|cidr|domain|url|hash}?fanged=`,
`/api/export/csv`, `GET|POST /api/reports`, `GET /api/reports/{name}.{md|html}`,
`/api/formulas`, and new in round 2: `GET /api/trends?days=`, `GET /api/phishing?limit=&brand=&min_score=`,
`GET /api/rdap?q=&refresh=`, `GET /api/search?...&rdap=true`; `/api/infrastructure` gained
`by_source` and `misp_events`. Search results carry `graph: {nodes: [{id, label, type, start}], links:
[{source, target, rel, origin}]}`, the shape `hud.forceGraph` takes.

## Safety and isolation

- The server binds to 127.0.0.1 only.
- The fetcher refuses every host not on `FEED_HOSTS` in `fetch.py`, also after
  redirects, so phishing and malware URLs are never requested, not even by mistake.
  No DNS lookups are made for indicator hosts.
- URLs and domains are stored and shown defanged (`hxxp://`, `[.]`). The URL and domain
  blocklists are defanged unless `fanged=true` is asked for. STIX patterns carry real
  values because they are meant for machines.
- Leak-site `.onion` addresses and screenshots from ransomware.live are dropped at
  collection time. Victim posts are shown as claims, not facts.
- API keys come from an environment variable or the desktop keyring, never a file; the
  User-Agent is the generic `seclab-ti/0.1`.
- RDAP never contacts the domain or IP being looked up: only IANA, the registry server the
  IANA bootstrap names (checked on every redirect hop) and rdap.org. Lookups use the
  registered domain, so subdomains (which can carry campaign ids) are not sent anywhere.
- CIRCL MISP events can embed attachments and zipped samples as base64. The fetcher's
  transform hook drops every `attachment` / `malware-sample` attribute and every `data`
  field in memory before the body is cached, and event size is capped before and during
  download. The bytes do cross the network once (inside the JSON); nothing is written.
- Bulk lists drop private and reserved addresses, and Phishing Army's built-in test
  domain (amiprotected.it) is skipped.
- Report names are checked before files are served (no path traversal).

## Verified on 2026-11-13/14

- Live `collect all` + `nvd` + `ip2asn`: kev 1781 rows, epss 1781 (18 batched requests),
  nvd 1781 (first try got a 503, the retry worked), attack 21379 objects, feodo 5,
  openphish 300, ransomware 1995 (188 s because of the 62 s spacing), spamhaus 1849,
  tor 1256, ip2asn 579453 ranges; urlhaus and threatfox `skipped` (no key).
- Correlation on live data: 579 actors (11 merged), 1781 vulns scored, 41 Tor exits
  inside DROP, 42 clusters, about 11k derived edges, 3.5 s.
- Seed on a fresh database inside a network namespace with no network: all 12 feeds
  `seeded`, 0.2 s, search and brief work.
- HUD at :8102: all three tabs load with no console errors; searches for CVE-2023-4966,
  akira, 50.16.16.211, LockBit, T1486 and 45.9.168.192 return entities and graphs;
  a refresh from the Feeds tab ran and logged a run.
- `pytest`: 41 passed in about 1 s.

## Verified on 2026-11-14 (round 2)

Live `collect all --correlate` under the heat lock, on the database from 13 Nov (migrated
in place):

| feed | status | rows kept | listed | time |
|---|---|---|---|---|
| sslbl | ok | 1500 | 11 261 certificate rows | 12.7 s |
| et_compromised | ok | 584 | 584 | 1.9 s |
| cins | ok | 5000 | 15 000 | 7.5 s |
| blocklistde (ssh) | ok | 4823 | 4823 | 1.1 s |
| phishing_army | ok | 4000 | 145 362 | 31.8 s |
| circl | ok | 1458 IOCs from 10 events | 1681 events in the manifest | 187.9 s |
| otx | skipped | 0 | needs `OTX_API_KEY` | |

The older feeds ran as before (openphish 300, ransomware 2010, spamhaus 1849, tor 1259,
epss 1781; KEV hit a DNS failure and used its cache, status `stale`). Correlation over
21 459 indicators took 8 s. Database 12 MB -> 27 MB; the new feeds add about 9 MB of cache.

- 49 IPs are on both CINS and blocklist.de and 373 reputation-list IPs reach confidence
  >= 60 through corroboration; a single list alone stays below 60.
- CIRCL events linked to actors through their galaxy tags: Turla (ESET white paper) and
  Sandworm (CERT-FR Centreon report). Searching `sandworm` now reaches the CERT-FR event
  and its hashes.
- RDAP: 22 live lookups (`python -m threatintel rdap example.com 8.8.8.8 --top-phishing 20`),
  servers contacted: data.iana.org plus rdap.centralnic.com, rdap.gmoregistry.net,
  rdap.registry.click, rdap.verisign.com, tld-rdap.verisign.com, rdap.arin.net. No
  indicator host was contacted. All 20 top phishing domains were registered in 2026;
  `amazon-th.shop` was registered on 2026-11-13, a day before it showed up in OpenPhish
  and Phishing Army (score 70: brand token + .shop + registered 1 day ago + 2 feeds).
- Phishing before/after, same data, old keyword matcher stored next to the new result:

| population | total | unbranded, keyword matcher | unbranded, new matcher |
|---|---|---|---|
| OpenPhish URLs (13 + 14 Nov) | 600 | 495 (82.5%) | 375 (62.5%) |
| Phishing Army domains (sample) | 4000 | 3677 (91.9%) | 3650 (91.2%) |

  Where the OpenPhish gain comes from, honestly: of the 120 URLs only the new matcher
  brands, 110 are brands added to `config/brands.toml` in this round (101 Shopee lures on
  blogspot, plus KuCoin, Trust Wallet, Uphold, Bybit and others), and 10 are edit-distance
  or homoglyph lookalikes (robiox -> roblox, ledgrr/ledgeer -> ledger, trezzre -> trezor,
  weebmail -> webmail). The brand additions were chosen after looking at this same live
  data, so this is an in-sample number; expect a smaller gain on new data. Of the 19
  keyword-matcher hits the new one drops (all on Phishing Army), 18 were wrong: phishing
  pages in Google and Amazon storage buckets (hosting, not impersonation), "aol" and "dpd"
  inside random strings, "chase" inside purchase19. One, `dpdpi-pl.icu`, is probably a real
  DPD lure that the new matcher misses (3-letter brands only match whole tokens).
  Most remaining unbranded hosts carry no brand at all (`piro-vanex-28n11.pages.dev`,
  `finzy9-eum62.sbs`).
- Trends: baseline day 2026-11-13 (sightings from the first run were migrated with that
  date), 17 948 indicators first observed on 14 Nov; SSLBL listing dates give real per-day
  C2 history at once (for example 7 FunStealer certificates on 13 Nov, 3 Vidar on 14 Nov).
- HUD at :8102: Overview shows the new phishing, trends, sources and MISP panels with no
  console errors; `tui --once` prints all six views. Server stopped afterwards.
- `pytest`: 99 passed in 8.7 s, offline (RDAP goes through a mock transport serving the
  real captured answers).

## Limitations

- URLhaus and ThreatFox need a free abuse.ch key; without it the demo uses synthetic
  samples, so "multi-source corroboration" in the offline demo is between synthetic
  records. The key path follows the documented API but was not run live here.
- Feodo Tracker currently lists only 5 C2 servers, all last seen months ago, so their
  confidence has decayed to about 21 and C2-by-family panels are thin on live data.
- OpenPhish and Phishing Army give no timestamps; first/last seen is our collection time.
- CIRCL picks the most recently *updated* events, which can be old reports (the ESET
  Turla paper is from 2018 but was updated today), and the Maltrail daily events hit the
  300-attribute cap. Events over 2.5 MB are skipped.
- Brand detection needs the brand's name (or a close lookalike) somewhere in the URL.
  Most phishing hosts are random strings on cheap TLDs or free hosting
  (`finzy9-eum62.sbs`, `*.wixstudio.com`), so the unbranded rate stays high even with
  edit distance and homoglyphs (numbers in "Verified" below). Page content would tell
  more, but fetching phishing pages is exactly what this lab refuses to do.
- The fuzzy rules trade recall for precision (first letter must match, stoplist of
  common words). Lookalikes that change the first letter (`utlook`) are missed unless a
  homoglyph fold explains them. The brand list is curated and Western/European-biased.
- The new-registration signal only counts once RDAP has been asked for that domain
  (on demand or `python -m threatintel rdap --top-phishing N`); correlation itself never
  goes to the network. Many ccTLD registries (for example .de) run no RDAP service and
  come back as `no-service`; thin registries give the registrar but not always an abuse
  contact.
- Reputation lists (CINS, blocklist.de, ET) give no context (no family, no date), and
  CINS and Phishing Army are sampled, so a lab IP that is on the full list but outside
  the sample is reported unknown.
- History starts on the first run of this version (2026-11-14). Days without a
  correlation run have no snapshot; the baseline day counts everything already listed
  as "new".
- The PSL copy is trimmed (ICANN rules up to two labels plus a few hosting suffixes),
  so deep geographic suffixes fall back to their parent.
- Alias merging only knows what ATT&CK, ransomware.live and `config/aliases.toml` say.
  Rebrands not listed there stay separate actors, and small ransomware crews with no
  ATT&CK entry only get techniques if ransomware.live has TTPs for them.
- ATT&CK "exploits" edges come from CVE ids mentioned in descriptions, so coverage is
  partial.
- The ransomware.live rate limit makes a full ransomware run take about 3 minutes.
- The shared force graph gets crowded, so the HUD draws at most 25 nodes (start node
  first, techniques last); the tables list everything.

## Ideas for extension

- Passive DNS or certificate transparency (crt.sh) to grow phishing clusters without
  visiting the sites.
- MISP or TAXII 2.1 export alongside the STIX file.
- Per-source reliability learned from how often a source's indicators are later
  corroborated.
- Push alerts when a KEV with ransomware use matches a product inventory list.
- Feed the honeypot-net attacker IPs in with `record=true` and track which ones later
  appear in public feeds.
