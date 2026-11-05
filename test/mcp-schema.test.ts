import AgenticDomeClient, { AgenticDomeMCPGateway, McpSchemaCache, McpSchemaError, McpSchemaUnavailable } from '../index';

const tool = { name: 'payments.schedule', inputSchema: { type: 'object', properties: { amount: { type: 'number', minimum: 1, maximum: 50000 }, currency: { enum: ['AUD'] } }, required: ['amount', 'currency'], additionalProperties: false } };
const context = { agentId: 'finance', sessionId: 's1', mcpServerId: 'crm', userId: 'alice', tenantId: '2' };
const list = { jsonrpc: '2.0' as const, id: 'list', method: 'tools/list' };
const call = (args: any) => ({ jsonrpc: '2.0' as const, id: 'call', method: 'tools/call', params: { name: tool.name, arguments: args } });

describe('MCP inputSchema parity with the Python host', () => {
  const evidence = process.env.AGENTICDOME_EVIDENCE_ENABLED;
  beforeAll(() => { process.env.AGENTICDOME_EVIDENCE_ENABLED = 'false'; });
  afterAll(() => { if (evidence === undefined) delete process.env.AGENTICDOME_EVIDENCE_ENABLED; else process.env.AGENTICDOME_EVIDENCE_ENABLED = evidence; });
  test('cached constraints distinguish missing, wrong-type, extra and out-of-range arguments', () => {
    const cache = new McpSchemaCache(); cache.install('a', [tool]);
    expect(cache.validate('a', tool.name, { amount: 25, currency: 'AUD' })).toMatch(/^sha256:/);
    for (const args of [{}, { amount: '25', currency: 'AUD' }, { amount: 25, currency: 'USD' }, { amount: 50001, currency: 'AUD' }, { amount: 25, currency: 'AUD', extra: true }]) expect(() => cache.validate('a', tool.name, args)).toThrow(McpSchemaError);
  });
  test('cache TTL, isolation, bounds, schema pinning and catalogue replacement fail closed', () => {
    let now = 0; const cache = new McpSchemaCache({ ttlMs: 50, maxEntries: 2, now: () => now }); cache.install('a', [tool]);
    const digest = cache.validate('a', tool.name, { amount: 1, currency: 'AUD' });
    expect(() => cache.validate('b', tool.name, { amount: 1, currency: 'AUD' })).toThrow(McpSchemaUnavailable);
    cache.install('a', [{ ...tool, inputSchema: { ...tool.inputSchema, description: 'updated' } }]);
    expect(() => cache.validate('a', tool.name, { amount: 1, currency: 'AUD' }, digest)).toThrow(/changed/);
    now = 51; expect(cache.available('a', tool.name)).toBe(false);
    cache.install('a', [tool]); cache.install('a', [], true); expect(cache.available('a', tool.name)).toBe(false);
  });
  test('supports local refs and rejects remote refs, cycles and unsafe schema extensions', () => {
    const cache = new McpSchemaCache(); cache.install('a', [{ name: 'local', inputSchema: { type: 'object', $defs: { id: { type: 'integer' } }, properties: { id: { $ref: '#/$defs/id' } }, required: ['id'] } }]);
    expect(() => cache.validate('a', 'local', { id: 'wrong' })).toThrow(McpSchemaError);
    for (const schema of [{ type: 'object', $ref: 'https://external.test/schema' }, { type: 'object', $defs: { loop: { $ref: '#/$defs/loop' } }, $ref: '#/$defs/loop' }, { type: 'object', properties: { id: { $schema: 'http://json-schema.org/draft-07/schema', type: 'string' } } }, { type: 'object', $async: true }]) expect(() => cache.install('a', [{ name: 'unsafe', inputSchema: schema }])).toThrow(McpSchemaError);
  });
  test('invalid cache bounds and deeply nested arguments fail closed', async () => {
    for (const options of [{ maxEntries: -1 }, { maxBytes: 0 }, { ttlMs: NaN }, { maxEntries: Infinity }]) expect(() => new McpSchemaCache(options)).toThrow(McpSchemaError);
    const client = new AgenticDomeClient('https://runtime.test', { apiKey: 'test' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' });
    const forward = jest.fn(); const gateway = new AgenticDomeMCPGateway(client, forward, { failClosed: false });
    let args: any = {}; for (let n = 0; n < 100; n++) args = { nested: args };
    expect((await gateway.forward(call(args), context)).error).toBeDefined(); expect(forward).not.toHaveBeenCalled(); expect(client.mcpGuardrailValidate).not.toHaveBeenCalled();
    client.close();
  });
  test.each(['http://json-schema.org/draft-07/schema#', 'https://json-schema.org/draft-07/schema#', 'https://json-schema.org/draft/2019-09/schema', 'https://json-schema.org/draft/2020-12/schema'])('accepts supported dialect %s', dialect => {
    const cache = new McpSchemaCache(); cache.install('s', [{ ...tool, inputSchema: { ...tool.inputSchema, $schema: dialect } }]); expect(() => cache.validate('s', tool.name, { amount: 2, currency: 'AUD' })).not.toThrow();
  });
  test('regular expressions use a non-backtracking engine and cached validation has no I/O', () => {
    const cache = new McpSchemaCache(); cache.install('s', [{ name: 'match', inputSchema: { type: 'object', properties: { value: { type: 'string', pattern: '^(a+)+$' } } } }]);
    expect(() => cache.validate('s', 'match', { value: 'a'.repeat(10000) + '!' })).toThrow(McpSchemaError);
    for (let n = 0; n < 500; n++) cache.validate('s', 'match', { value: 'aaa' });
  });
  test('strict Gateway fetches once, blocks invalid arguments before policy and rechecks redaction', async () => {
    const client = new AgenticDomeClient('https://runtime.test', { apiKey: 'test', tenantId: '2' });
    const authorize = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }); client.mcpGuardrailValidate = authorize;
    const forward = jest.fn(async (request: any) => ({ jsonrpc: '2.0' as const, id: request.id, result: request.method === 'tools/list' ? { tools: [tool] } : { content: [] } }));
    const gateway = new AgenticDomeMCPGateway(client, forward, { requireMcpSchema: true, sanitizeOutput: false });
    expect((await gateway.forward(call({ amount: 2, currency: 'AUD' }), context)).error).toBeDefined(); expect(forward).not.toHaveBeenCalled(); expect(authorize).not.toHaveBeenCalled();
    expect((await gateway.forward(list, context)).error).toBeUndefined(); expect((await gateway.forward(call({ amount: 2, currency: 'AUD' }), context)).error).toBeUndefined(); expect(forward).toHaveBeenCalledTimes(2);
    authorize.mockClear(); expect((await gateway.forward(call({ amount: 'wrong', currency: 'AUD' }), context)).error).toBeDefined(); expect(authorize).not.toHaveBeenCalled();
    authorize.mockResolvedValue({ verdict: 'REDACTED', sanitized_tool_args: { amount: 'wrong', currency: 'AUD' } });
    expect((await gateway.forward(call({ amount: 2, currency: 'AUD' }), context)).error).toBeDefined(); expect(forward).toHaveBeenCalledTimes(2);
    client.close();
  });
  test('catalogues are isolated by caller, server and scoped identity, including concurrent sessions', async () => {
    const client = new AgenticDomeClient('https://runtime.test', { apiKey: 'test', tenantId: '2' }); client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' });
    const forward = jest.fn(async (request: any) => ({ jsonrpc: '2.0' as const, id: request.id, result: { tools: [tool] } }));
    const gateway = new AgenticDomeMCPGateway(client, forward, { requireMcpSchema: true, sanitizeOutput: false }); await client.withIdentity({ userToken: 'alice-proof' }, () => gateway.forward(list, context));
    const result = await client.withIdentity({ userToken: 'bob-proof' }, () => gateway.forward(call({ amount: 2, currency: 'AUD' }), context)); expect(result.error).toBeDefined(); expect(forward).toHaveBeenCalledTimes(1);
    client.close();
  });
  test('schema violations cannot use the legacy fail-open option to forward', async () => {
    const client = new AgenticDomeClient('https://runtime.test', { apiKey: 'test' }); client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' });
    const forward = jest.fn(); const gateway = new AgenticDomeMCPGateway(client, forward, { failClosed: false });
    expect((await gateway.forward(call([]), context)).error).toBeDefined(); expect(forward).not.toHaveBeenCalled(); client.close();
  });
});
