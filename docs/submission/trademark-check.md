# Trademark check of the invented catalog brand names

The demo catalog (`data/catalog.yaml`) uses six invented consumer-electronics accessory brands, so no real brand appears in the
demo, the video or the screenshots. This is a quick web search, not a clearance search: web search cannot query the USPTO register
or common-law use, so "nothing found" means only that no obvious well-known brand turned up. The owner will check the USPTO
database by hand (Class 9 and Class 18, 20 for stands and cases).

## The six names, exactly as written in the catalog

1. Brindlewick
2. Ostrander
3. Quillmark
4. Tolliver & Reed
5. Veltro
6. Zephyrine

## Findings (searched 10 Nov 2026)

| Name | What the search found | Risk | Suggested rename if wanted |
| --- | --- | --- | --- |
| Brindlewick | No result for the name in consumer electronics or accessories | low | none |
| Ostrander | No electronics brand of that name; it is a common surname, so unrelated businesses may use it | low | none |
| Quillmark | One owner, Quillmark, Inc., with two old records for PERSONAL BOOKS (not electronics). Unrelated to electronics, but the name is in the register, and the owner's current status was not checked | low to medium | Quillfold, if the manual check shows a live record |
| Tolliver & Reed | No brand of that name. Several unrelated owners named Tolliver (clothing, real estate, music) | low | none |
| Veltro | No electronics brand found. The search returned only look-alikes (Velcro, Vertux, Vention), which are different names; "veltro" is also an Italian word and a surname | low | none |
| Zephyrine | No record of the name. A near-miss, ZEPHYRLINE, was filed in 2023 for charging cables, phone chargers and USB hubs (owner: a Chinese e-commerce company), which overlaps the catalog's chargers and cables | low to medium | Zephyrene is not better; if the manual check objects, use a name with a different stem, such as Marlowe Lane |

No name matched a well-known brand, so none was renamed. If a rename is needed later, change `data/catalog.yaml` brand and product
titles together and regenerate anything that embeds the catalog hash (seeds and the tests that pin it).

## Sources

Third-party register aggregators and retailer listings returned by web search (Justia trademarks for Quillmark, Inc. and for the
ZEPHYRLINE owner, trademarkdir.com owner pages for Tolliver names). None is authoritative; the USPTO search is.
