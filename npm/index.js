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
  agentSessionControlVectors: () => load("agent_session_control_vectors.json"),
  agentApiKeyIdVectors: () => load("agent_api_key_id_vectors.json"),
  assignmentTicketVectors: () => load("assignment_ticket_v1_vectors.json"),
  connectorAuthorityLambdaVectors: () => load("connector_authority_lambda_v1_vectors.json"),
  connectorHubRequestIdVectors: () => load("connector_hub_request_id_v1_vectors.json"),
  connectorHubLstCookieVectors: () => load("connector_hub_lst_cookie_v1_vectors.json"),
  agentCredentialRecoveryVectors: () => load("agent_credential_recovery_v1_vectors.json"),
};
