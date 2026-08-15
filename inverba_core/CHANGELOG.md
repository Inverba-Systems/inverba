# Changelog

## 0.1.3

- Verification paths now enforce an input size bound. Maliciously deep or oversized JSON
  now returns a verification failure instead of raising an exception. No format changes;
  all existing records verify unchanged.

## 0.1.2

- `verify` flags "content NOT CHECKED" when a record is verified without its content,
  so a record separated from its bytes can't be mistaken for fully verified.

## 0.1.1

- Metadata correction: `pip install inverba` installs only `inverba-core`; removed the
  swarm/cloud overclaim from the meta package description.

## 0.1.0

- Initial release: signed, offline-verifiable web-data provenance (Apache-2.0 core).
