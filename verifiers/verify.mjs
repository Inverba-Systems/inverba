#!/usr/bin/env node
// Minimal, dependency-free Inverba record verifier in JavaScript.
//
// Proves the "checkable in any language" claim: a third party with no Inverba
// install, and no npm dependencies, can verify a signed record using only the
// Node standard library. Mirrors inverba.provenance.verify_record.
//
//   node verify.mjs <record.json> [content-file]
//
// Exits 0 if the signature is valid (and, if a content file is given, its bytes
// hash to the signed content_hash); non-zero otherwise.
import { readFileSync } from "node:fs";
import { createPublicKey, verify, createHash } from "node:crypto";

const [recordPath, contentPath] = process.argv.slice(2);
if (!recordPath) { console.error("usage: node verify.mjs <record.json> [content-file]"); process.exit(2); }
const r = JSON.parse(readFileSync(recordPath, "utf8"));

// Reconstruct the exact signed payload: canonical JSON (sorted keys, no spaces),
// matching Python's json.dumps(..., sort_keys=True, separators=(",",":")). Note
// fetched_at is a float, serialized with a trailing ".0" when integer-valued, as
// Python does. (IRF/1's deterministic CBOR is the exact cross-language answer;
// this reproduces the shipped JSON format.)
const s = (v) => JSON.stringify(v);
const pyFloat = (x) => (Number.isInteger(x) ? x.toFixed(1) : String(x));
const payload =
  `{"content_hash":${s(r.content_hash)},"content_type":${s(r.content_type || "")},` +
  `"fetched_at":${pyFloat(r.fetched_at)},"fetched_by":${s(r.fetched_by || "native")},` +
  `"final_url":${s(r.final_url || "")},"status_code":${r.status_code ?? 200},` +
  `"url":${s(r.url)},"v":2}`;

// Wrap the raw 32-byte Ed25519 public key in its fixed DER/SPKI header, then verify.
const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"),
                            Buffer.from(r.worker_public_key, "hex")]);
const pubkey = createPublicKey({ key: spki, format: "der", type: "spki" });
const sigOk = verify(null, Buffer.from(payload, "utf8"), pubkey, Buffer.from(r.signature, "hex"));

let contentOk = true;
if (contentPath) {
  const digest = createHash("sha256").update(readFileSync(contentPath)).digest("hex");
  contentOk = digest === r.content_hash;
}

if (sigOk && contentOk) { console.log("VALID: signature verifies" + (contentPath ? " and content matches" : "")); process.exit(0); }
console.log(`INVALID: signature=${sigOk}${contentPath ? `, content_matches=${contentOk}` : ""}`); process.exit(1);
