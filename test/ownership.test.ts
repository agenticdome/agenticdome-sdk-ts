import AgenticDomeClient, { OwnershipGuard, OwnershipDenied, ResourceRule, ApprovalRequired, AgenticDomeError, AgenticDomeMCPGateway } from '../index';

const subject = {tenantId: 'tenant-a', principalId: 'alice'};
const fact = {tenantId: 'tenant-a', resourceType: 'record', resourceId: 'record-a', ownerId: 'alice', allowedOperations: ['read', 'cancel']};
const rules: Record<string, ResourceRule> = {'records.cancel': {resourceType: 'record', resourceArgument: 'body.id', operation: 'cancel'}};
const guard = (changes = {}, customRules = rules) => new OwnershipGuard(customRules, {
  resolveSubject: () => subject, resolveResource: () => ({...fact, ...changes}),
});

test.each([{ownerId: 'bob'}, {tenantId: 'tenant-b'}, {resourceId: 'record-b'}, {resourceType: 'volume'}, {allowedOperations: ['read']}])('provider facts override caller claims: %j', async changes => {
  await expect(guard(changes).check('records.cancel', {body: {id: 'record-a', ownerId: 'alice'}})).rejects.toBeInstanceOf(OwnershipDenied);
});
test('own resource passes; unknown tools and bulk requests fail', async () => {
  const g = guard();
  await g.check('records.cancel', {body: {id: 'record-a'}});
  await expect(g.check('unknown', {body: {id: 'record-a'}})).rejects.toBeInstanceOf(OwnershipDenied);
  await expect(g.check('records.cancel', {body: {id: ['record-a', 'record-b']}})).rejects.toBeInstanceOf(OwnershipDenied);
});
test('explicit entitlements allow a non-owner read without permitting deletion', async () => {
  const g = guard({ownerId: 'bob', entitledPrincipals: ['alice']}, {'records.read': {resourceType: 'record', resourceArgument: 'id', operation: 'read', relationship: 'entitled'}});
  await g.check('records.read', {id: 'record-a'});
  await expect(g.check('records.delete', {id: 'record-a'})).rejects.toBeInstanceOf(OwnershipDenied);
});
test('resolver timeout fails closed', async () => {
  const g = new OwnershipGuard(rules, {resolveSubject: () => subject, resolveResource: () => new Promise(() => {}), timeoutMs: 5});
  await expect(g.check('records.cancel', {body: {id: 'record-a'}})).rejects.toBeInstanceOf(OwnershipDenied);
});
test('matching owner in another enforcement tenant is denied', async () => {
  await expect(guard().check('records.cancel', {body: {id: 'record-a'}}, 'tenant-b')).rejects.toBeInstanceOf(OwnershipDenied);
});
test('resource and prompt reads cannot bypass a configured ownership guard', async () => {
  const client = new AgenticDomeClient('https://sidecar.invalid', {apiKey: 'fixture', tenantId: 'tenant-a'});
  const policy = jest.spyOn(client, 'mcpGuardrailValidate').mockResolvedValue({verdict: 'ALLOWED'});
  const g = guard({}, {'mcp.resources/read': {resourceType: 'record', resourceArgument: 'uri', operation: 'read'}});
  const gateway = new AgenticDomeMCPGateway(client, jest.fn(), {ownershipGuard: g, failClosed: false});
  const context = {agentId: 'agent', sessionId: 'run', mcpServerId: 'records'};
  try {
    expect((await gateway.preflight({jsonrpc: '2.0', id: 1, method: 'resources/read', params: {uri: 'record-a'}}, context)).blocked).toBeUndefined();
    expect((await gateway.preflight({jsonrpc: '2.0', id: 2, method: 'resources/read', params: {uri: 'other'}}, context)).blocked).toBeDefined();
    expect((await gateway.preflight({jsonrpc: '2.0', id: 3, method: 'prompts/get', params: {name: 'private'}}, context)).blocked).toBeDefined();
    policy.mockRejectedValue(new Error('offline'));
    expect((await gateway.preflight({jsonrpc: '2.0', id: 4, method: 'resources/read', params: {uri: 'record-a'}}, context)).blocked).toBeDefined();
  } finally {client.close();}
});
test('GraphQL ownership follows interpreted target, not unused variables', async () => {
  const g = guard({}, {'api#Mutation.cancel': {resourceType: 'record', resourceArgument: 'id', operation: 'cancel'}});
  await expect(g.checkHttp('api', {body: {variables: {id: 'record-a'}}}, {graphql_interpretation: 'agenticdome.graphql-actions.v1', graphql_actions: [{coordinate: 'Mutation.cancel', arguments: {id: 'record-b'}}]})).rejects.toBeInstanceOf(OwnershipDenied);
  await expect(g.checkHttp('api', {}, {})).rejects.toBeInstanceOf(OwnershipDenied);
});
test('approval resume rechecks current ownership before HTTP transport', async () => {
  let ownerId = 'alice', approved = false;
  const g = new OwnershipGuard(rules, {resolveSubject: () => subject, resolveResource: () => ({...fact, ownerId})});
  const client = new AgenticDomeClient('https://sidecar.invalid', {apiKey: 'fixture', tenantId: 'tenant-a', ownershipGuard: g});
  const rid = '8d50b9df-d260-4f45-9773-85daceb0edb2';
  jest.spyOn(client as any, 'request').mockImplementation(async (...args: any[]) => {
    if (args[1].endsWith('/grant')) return {approval_grant: 'fixture'};
    if (!approved) return {verdict: 'APPROVAL_REQUIRED', context: {approval: {id: rid}}};
    return {verdict: 'ALLOWED', execution_receipt: 'fixture', enforcement_evidence: {http_request_bound: true}, broker: {verified: true, token_consumed: true, approval_request_id: rid}};
  });
  const transport = jest.spyOn(globalThis, 'fetch');
  try {
    let pending: ApprovalRequired | undefined;
    try {await client.executeHttp({url: 'https://api.invalid/cancel', method: 'POST', agentId: 'agent', toolName: 'records.cancel', body: '{"id":"record-a"}', headers: {'content-type': 'application/json'}});} catch (e) {if (!(e instanceof ApprovalRequired)) throw e; pending = e;}
    expect(pending).toBeDefined(); approved = true; ownerId = 'bob';
    await expect(client.resumeApprovedHttp(pending!)).rejects.toBeInstanceOf(OwnershipDenied);
    expect(transport).not.toHaveBeenCalled();
  } finally {transport.mockRestore(); client.close();}
});
test('GraphQL helper refuses a legacy sidecar without sending', async () => {
  const client = new AgenticDomeClient('https://sidecar.invalid', {apiKey: 'fixture', tenantId: 'tenant-a'});
  jest.spyOn(client as any, 'request').mockResolvedValue({verdict: 'ALLOWED', execution_receipt: 'fixture', enforcement_evidence: {http_request_bound: true}, broker: {verified: true, token_consumed: true}});
  const transport = jest.spyOn(globalThis, 'fetch');
  try {
    await expect(client.executeGraphql({url: 'https://api.invalid/graphql', query: 'query { version }', agentId: 'agent', toolName: 'api'})).rejects.toBeInstanceOf(AgenticDomeError);
    expect(transport).not.toHaveBeenCalled();
  } finally {transport.mockRestore(); client.close();}
});
test('MCP ownership cannot fail open when ordinary screening is configured fail open', async () => {
  const client = new AgenticDomeClient('https://sidecar.invalid', {apiKey: 'fixture', tenantId: 'tenant-a'});
  jest.spyOn(client, 'mcpGuardrailValidate').mockRejectedValue(new Error('offline'));
  const forwarder = jest.fn();
  const gateway = new AgenticDomeMCPGateway(client, forwarder, {failClosed: false, ownershipGuard: guard()});
  try {
    const result = await gateway.preflight({jsonrpc: '2.0', id: 1, method: 'tools/call', params: {name: 'records.cancel', arguments: {body: {id: 'record-a'}}}}, {agentId: 'agent', sessionId: 'run', mcpServerId: 'records'});
    expect(result.blocked).toBeDefined(); expect(forwarder).not.toHaveBeenCalled();
  } finally {client.close();}
});

test('MCP checks final sanitized arguments and snapshots requests before awaiting', async () => {
  const client = new AgenticDomeClient('https://sidecar.invalid', {apiKey: 'fixture', tenantId: 'tenant-a'});
  const policy = jest.spyOn(client, 'mcpGuardrailValidate').mockResolvedValue({verdict: 'REDACTED', sanitized_tool_args: {id: 'record-a'}});
  const g = guard({}, {'records.cancel': {resourceType: 'record', resourceArgument: 'id', operation: 'cancel'}});
  const gateway = new AgenticDomeMCPGateway(client, jest.fn(), {ownershipGuard: g});
  const request = {jsonrpc: '2.0' as const, id: 1, method: 'tools/call', params: {name: 'records.cancel', arguments: {id: 'other'}}};
  const context = {agentId: 'agent', sessionId: 'run', mcpServerId: 'records'};
  try {
    expect((await gateway.preflight(request, context)).request?.params?.arguments).toEqual({id: 'record-a'});
    let release!: (value: any) => void;
    policy.mockImplementation(() => new Promise(resolve => {release = resolve;}));
    request.params.arguments.id = 'record-a';
    const pending = gateway.preflight(request, context);
    request.params.arguments.id = 'other'; release({verdict: 'ALLOWED'});
    expect((await pending).request?.params?.arguments).toEqual({id: 'record-a'});
  } finally {client.close();}
});
