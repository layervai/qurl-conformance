"use strict";
const fs = require("node:fs");
const path = require("node:path");
function load(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "vectors", name), "utf8"));
}
module.exports = {
  qv2Vectors: () => load("qv2_conformance_vectors.json"),
  issuerSignatureVectors: () => load("issuer_signature_vectors.json"),
  relayKnockVectors: () => load("relay_knock_golden.json"),
  agentRegistrationVectors: () => load("agent_registration_golden.json"),
  agentAssignmentVectors: () => load("agent_assignment_golden.json"),
  agentKnockApplicationVectors: () => load("agent_knock_application_vectors.json"),
  agentApiKeyIdVectors: () => load("agent_api_key_id_vectors.json"),
  assignmentTicketVectors: () => load("assignment_ticket_v1_vectors.json"),
};
