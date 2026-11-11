# Regional tagging

Marks indicators that are registered in East Africa, so the pipeline's global data can later be compared with the region's. Defined in `regions/east_africa.json`: UG, KE, TZ, RW, ET, BI, SS, SO, DJ, ER.

## What the tags mean

The table `indicator_geo` holds one row per indicator and method.

| method | Meaning |
|---|---|
| `rir` | The IPv4 address (or the IP host of a URL) is in a block that AFRINIC lists as registered to that country. |
| `cctld` | The domain (or URL host) ends in a national TLD of the region, such as `.ug` or `.ke`. |

Indicators from other African countries get the region `other_africa` so the East African share can be read against the continent. Hashes have no location and are never tagged.

## Registered in is not hosted in

A registration country says where a block was allocated, not where the machine sits or who operates it. Hosting companies, resellers and transferred blocks all break the link. Results must say "registered in", never "hosted in" or "originating from".

## Data source

The AFRINIC extended delegation file (`delegated-afrinic-extended-latest`), downloaded by `python -m geo.fetch_rir`. The MD5 is checked, and a failed or mismatched download keeps the previous copy. The file is not committed (`data/` is ignored). Blocks are a start address plus a count, which is not always a power of two, so lookups compare integers instead of using CIDR. Only `allocated` and `assigned` blocks count.

## Running it

- `python -m geo.fetch_rir` downloads the file (skipped by the daily run if it is under about 20 hours old).
- `python -m geo.tag` rebuilds `indicator_geo` from `indicators_raw` in one transaction, so a missing row always means "no match".
- Both run in `scripts/daily_run.sh`, before scoring.
- Create the table once with `sql/indicator_geo.sql`.

## Limitations

- IPv4 only; no IPv6 and no ASN yet.
- About half of the URLs use a hostname instead of an IP. Those are tagged only if the TLD is regional, so the result covers URLs with a literal IP plus regional TLDs, not all URLs.
- Domains are not resolved to IPs, so a `.com` domain hosted in the region is missed.
- Counts are small, and URLs from one host are not independent observations. Treat them as a description of this dataset, not as statistics about the region.
- The file changes daily, so tags can shift between runs. `rir_date` records which file produced them.
