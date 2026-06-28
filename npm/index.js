"use strict";
const fs = require("node:fs");
const path = require("node:path");
function load(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "vectors", name), "utf8"));
}
module.exports = {
  qv2Vectors: () => load("qv2_conformance_vectors.json"),
  issuerSignatureVectors: () => load("issuer_signature_vectors.json"),
};
