// Independent npm consumer: typed fence inputs must fail before framing.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const artifact = require('../npm').assignmentTicketVectors();
const fields = {
  credential: 'credential_key_hash credential_key_id owner_id status raw_key_type scope_count scope_0 scope_1 expires_at tunnel_slug has_counter has_agent_counter consumed_at consumed_agent_id'.split(' '),
  cell: 'cell_id status endpoint_revision nhp_host nhp_port server_public_key_b64 selection_weight_storage updated_at_storage'.split(' '),
  existing: 'agent_id cell_id assignment_generation state created_at_storage updated_at_storage'.split(' '),
};
const integers = new Set(['scope_count', 'endpoint_revision', 'nhp_port', 'assignment_generation']);
function validate(kind, parts) {
  const names = fields[kind];
  if (!names || parts.length !== names.length || parts.some((part, i) => part.name !== names[i])) return 'required_part';
  const scopes = [];
  let count = 0n;
  for (const part of parts) {
    let expected = 'utf8';
    if (integers.has(part.name)) expected = 'uint64_be';
    else if (part.name === 'credential_key_hash') expected = 'raw_bytes_b64url';
    else if (['has_counter', 'has_agent_counter'].includes(part.name)) expected = 'bool_byte';
    if (part.encoding !== expected) return 'encoding';
    let raw;
    if (expected === 'uint64_be') {
      if (!/^(0|[1-9][0-9]*)$/.test(part.value) || BigInt(part.value) > 18446744073709551615n) return 'uint64';
      raw = Buffer.alloc(8); raw.writeBigUInt64BE(BigInt(part.value));
    } else if (expected === 'bool_byte') {
      if (!['true', 'false'].includes(part.value)) return 'encoding';
      raw = Buffer.from([part.value === 'true' ? 1 : 0]);
    } else if (expected === 'raw_bytes_b64url') {
      raw = Buffer.from(part.value, 'base64url');
      if (raw.toString('base64url') !== part.value) return 'encoding';
    } else raw = Buffer.from(part.value, 'utf8');
    if (raw.toString('hex') !== part.bytes_hex) return 'bytes';
    if (part.name === 'credential_key_hash' && raw.length !== 32) return 'key_length';
    if (part.name === 'scope_count') count = BigInt(part.value);
    else if (part.name.startsWith('scope_')) scopes.push(part.value);
  }
  if (BigInt(scopes.length) !== count || scopes.some((scope, i) => !scope || (i > 0 && scopes[i - 1] >= scope))) return 'canonical_scopes';
  return '';
}
assert.equal(artifact.schema_version, 2);
for (const vector of artifact.fence_vectors) {
  assert.equal(validate(vector.kind, vector.parts), '', vector.name);
  const chunks = [Buffer.from(vector.domain + '\0')];
  for (const part of vector.parts) {
    const raw = Buffer.from(part.bytes_hex, 'hex');
    const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(raw.length));
    chunks.push(length, raw);
  }
  const preimage = Buffer.concat(chunks);
  assert.equal(preimage.toString('hex'), vector.preimage_hex);
  assert.equal(crypto.createHash('sha256').update(preimage).digest('hex'), vector.digest_hex);
}
const names = ['credential_hash_wrong_length', 'credential_scopes_unsorted', 'credential_scopes_duplicate', 'uint64_negative_or_overflow', 'bool_not_single_byte', 'missing_required_cell_part'];
assert.deepEqual(artifact.fence_rejects.map(x => x.name), names);
let count = 0;
for (const reject of artifact.fence_rejects) {
  assert.ok(reject.inputs.length > 0);
  for (const input of reject.inputs) {
    assert.equal(validate(input.kind, input.parts), input.boundary, input.name);
    count++;
  }
}
assert.equal(count, 13);
console.log('npm: three positive fences and 13 typed rejects verified');
