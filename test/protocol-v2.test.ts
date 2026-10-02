import { createHash, createPublicKey, verify } from 'node:crypto';

import AgenticDomeClient, {
  AgenticDomeMCPGateway,
  createDpopProof,
  generateRsaProofKey,
} from '../index';

function decodePart(value: string): Record<string, any> {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

describe('AgenticDome protocol v2', () => {
  test('preserves a human subject and nested agent actors together', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', {
      apiKey: 'test-key',
      tenantId: 'tenant-1',
    });
    const request = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' });
    (client as any).request = request;

    await client.guardrailValidate({
      text: 'send approved invoice',
      agentId: 'worker-agent',
      sourceAgentId: 'manager-agent',
      userId: 'alice',
      sourcePlatform: 'langgraph',
      platform: 'pydanticai',
      direction: 'outbound',
    });

    const payload = request.mock.calls[0][2].jsonBody;
    expect(payload.user_id).toBe('alice');
    expect(payload.source_agent_id).toBe('manager-agent');
    expect(payload.policy_context.agenticdome_identity.subject.id).toBe('alice');
    expect(payload.policy_context.agenticdome_identity.actors.map((actor: any) => actor.id)).toEqual([
      'manager-agent',
      'worker-agent',
    ]);
    client.close();
  });

  test('propagates lineage, policy, proof, and atomic consumption fields', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    const request = jest.fn().mockResolvedValue({ result: { verdict: 'ALLOWED' } });
    (client as any).request = request;

    await client.a2aAuthorizeTool({
      text: 'issue refund',
      agentId: 'refund-worker',
      sourceAgentId: 'manager',
      userId: 'alice',
      sourcePlatform: 'langgraph',
      platform: 'pydanticai',
      toolName: 'refund.create',
      toolArgs: { amount: 25 },
      actorChain: [{ id: 'planner', framework: 'crewai' }],
      scopes: ['refund:create'],
      parentJti: 'parent-token',
      rootJti: 'root-token',
      policyId: 'refund-policy',
      policyVersion: '4',
      policyHash: 'sha256:policy',
      proofThumbprint: 'proof-thumbprint',
    });

    const authorizeArgs = request.mock.calls[0][2].jsonBody.params.arguments;
    expect(authorizeArgs.user_id).toBe('alice');
    expect(authorizeArgs.actor_chain).toEqual([{ id: 'planner', framework: 'crewai' }]);
    expect(authorizeArgs.root_jti).toBe('root-token');
    expect(authorizeArgs.proof_thumbprint).toBe('proof-thumbprint');

    request.mockClear();
    await client.a2aVerifyDecisionToken('decision-token', {
      agentId: 'refund-worker',
      sourceAgentId: 'manager',
      userId: 'alice',
      sessionId: 'session-1',
      proofToken: 'signed-proof',
    });
    expect(request.mock.calls[0][2].jsonBody).toMatchObject({
      user_id: 'alice',
      session_id: 'session-1',
      proof_token: 'signed-proof',
      consume: true,
    });
    client.close();
  });

  test('creates a verifiable RS256 DPoP proof bound to method, URI, and token', () => {
    const key = generateRsaProofKey();
    const token = createDpopProof({
      privateKeyPem: key.privateKeyPem,
      accessToken: 'decision-token',
      method: 'POST',
      uri: '/a2a/decision/verify',
      proofJti: 'proof-1',
      issuedAt: 1234,
    });
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
    const header = decodePart(encodedHeader);
    const payload = decodePart(encodedPayload);

    expect(header.typ).toBe('dpop+jwt');
    expect(payload).toMatchObject({
      jti: 'proof-1',
      iat: 1234,
      htm: 'POST',
      htu: '/a2a/decision/verify',
    });
    expect(payload.ath).toBe(createHash('sha256').update('decision-token').digest('base64url'));
    expect(verify(
      'RSA-SHA256',
      Buffer.from(`${encodedHeader}.${encodedPayload}`),
      createPublicKey(key.privateKeyPem),
      Buffer.from(encodedSignature, 'base64url'),
    )).toBe(true);
  });

  test('routes tool authorization through the one-request broker in enforce mode', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', {
      apiKey: 'test-key',
      tenantId: 'tenant-1',
      executionBrokerMode: 'enforce',
    });
    const request = jest.fn().mockResolvedValue({
      verdict: 'ALLOWED',
      execution_receipt: 'signed-receipt',
      broker: { verified: true, token_consumed: true },
    });
    (client as any).request = request;

    const result = await client.guardrailValidate({
      text: 'lookup customer',
      agentId: 'support-agent',
      platform: 'custom_python',
      toolName: 'crm.lookup',
      toolArgs: { id: '123' },
      toolVersion: '1.2.3',
      toolDigest: `sha256:${'a1'.repeat(32)}`,
      executionDestination: 'https://crm.example.test/customers/123',
      executionHttpMethod: 'GET',
      workloadId: 'spiffe://customer.test/agent/support',
    });

    expect(request.mock.calls).toHaveLength(1);
    expect(request.mock.calls[0][1]).toBe('/tools/execution/authorize');
    expect(request.mock.calls[0][2].jsonBody.boundary_id).toMatch(/^sdk:/);
    expect(request.mock.calls[0][2].jsonBody.tool_version).toBe('1.2.3');
    expect(request.mock.calls[0][2].jsonBody.destination).toBe('https://crm.example.test/customers/123');
    expect(request.mock.calls[0][2].jsonBody.http_method).toBe('GET');
    expect(request.mock.calls[0][2].jsonBody.workload_id).toBe('spiffe://customer.test/agent/support');
    expect(client.enforcementHeaders(result, 'spiffe://customer.test/agent/support')).toEqual({
      'X-AgenticDome-Execution-Receipt': 'signed-receipt',
      'X-AgenticDome-Workload-Id': 'spiffe://customer.test/agent/support',
    });
    client.close();
  });

  test('fails closed when an enforced broker receipt is missing', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', {
      apiKey: 'test-key',
      tenantId: 'tenant-1',
      executionBrokerMode: 'enforce',
    });
    (client as any).request = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' });

    await expect(client.guardrailValidate({
      text: 'lookup customer',
      agentId: 'support-agent',
      platform: 'custom_python',
      toolName: 'crm.lookup',
      toolArgs: { id: '123' },
    })).rejects.toThrow('atomically consumed');
    client.close();
  });

  test("derives runtime identity from package metadata and resolves registered tool provenance", async () => {
    const client = new AgenticDomeClient("https://sidecar.example", {
      apiKey: "test-key",
      serviceToken: "service-token",
      toolProvenance: {
        "crm.update": {
          toolPlatform: "custom",
          toolVersion: "2.4.0",
          toolDigest: "sha256:" + "ab".repeat(32),
        },
      },
    });
    expect((client as any).userAgent).toBe("agenticdome-sdk/" + require("../package.json").version);

    const request = jest.fn().mockResolvedValue({ verdict: "ALLOWED" });
    (client as any).request = request;
    await client.guardrailValidate({
      text: "update customer",
      agentId: "support-agent",
      platform: "custom",
      toolPlatform: "custom",
      toolName: "crm.update",
      toolArgs: { id: "123" },
    });
    expect(request.mock.calls[0][2].jsonBody).toMatchObject({
      tool_version: "2.4.0",
      tool_digest: "sha256:" + "ab".repeat(32),
    });

    request.mockClear();
    await client.mcpGuardrailValidate({
      text: "update customer",
      agentId: "support-agent",
      platform: "custom",
      toolPlatform: "custom",
      toolName: "crm.update",
      toolArgs: { id: "123" },
    });
    expect(request.mock.calls[0][2].jsonBody.params.arguments).toMatchObject({
      tool_version: "2.4.0",
      tool_digest: "sha256:" + "ab".repeat(32),
    });

    request.mockClear();
    await client.getRuntimeReadiness();
    expect(request).toHaveBeenCalledWith("GET", "/health/readiness");

    request.mockClear();
    await client.getBehavioralSummary("tenant-1", 5000);
    expect(request).toHaveBeenCalledWith("GET", "/trust/behavior-summary?limit=1000", {
      tenantId: "tenant-1",
      useBearer: false,
      extraHeaders: { "X-Service-Token": "service-token" },
    });

    client.unregisterToolProvenance("crm.update", "custom");
    client.close();
  });

  test('MCP gateway forwards an allowed call exactly once and reviews its response', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    const mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' });
    const meshValidate = jest.fn().mockImplementation(async ({ text }) => ({
      verdict: 'REDACTED', sanitized_text: text.replace('unsafe result', 'safe result'),
    }));
    client.mcpGuardrailValidate = mcpGuardrailValidate as any;
    client.meshValidate = meshValidate as any;
    const forwarder = jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 7, result: { content: [{ type: 'text', text: 'unsafe result' }] },
    });
    const gateway = new AgenticDomeMCPGateway(client, forwarder);

    const response = await gateway.forward(
      { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'crm.lookup', arguments: { id: '123' } } },
      { agentId: 'support-agent', sessionId: 'session-1', mcpServerId: 'crm-mcp', userId: 'alice' },
    );

    expect(forwarder).toHaveBeenCalledTimes(1);
    expect(mcpGuardrailValidate).toHaveBeenCalledWith(expect.objectContaining({
      toolName: 'crm.lookup', toolArgs: { id: '123' }, agentId: 'support-agent', userId: 'alice',
    }));
    expect(meshValidate).toHaveBeenCalledTimes(1);
    expect((response.result as any).content[0].text).toBe('safe result');
    client.close();
  });

  test('MCP gateway never forwards a blocked call', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'BLOCKED', reason: 'policy denied' }) as any;
    const forwarder = jest.fn();
    const gateway = new AgenticDomeMCPGateway(client, forwarder);

    const response = await gateway.forward(
      { jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'billing.refund', arguments: { amount: 5000 } } },
      { agentId: 'support-agent', sessionId: 'session-2', mcpServerId: 'billing-mcp' },
    );

    expect(forwarder).not.toHaveBeenCalled();
    expect(response.error?.code).toBe(-32000);
    client.close();
  });

  test('MCP gateway does not echo sensitive policy reasons to its caller', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'BLOCKED', reason: 'private@example.com' }) as any;
    const gateway = new AgenticDomeMCPGateway(client, jest.fn());
    const request = { jsonrpc: '2.0' as const, id: 10, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } };
    const context = { agentId: 'support', sessionId: 's1', mcpServerId: 'crm' };
    expect(JSON.stringify(await gateway.forward(request, context))).not.toContain('private@example.com');

    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    client.meshValidate = jest.fn().mockResolvedValue({ verdict: 'BLOCKED', reason: 'private@example.com' }) as any;
    const outputGateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({ jsonrpc: '2.0', id: 10, result: {} }));
    expect(JSON.stringify(await outputGateway.forward(request, context))).not.toContain('private@example.com');
    client.close();
  });

  test('MCP gateway requires replacement arguments for a redacted tool call', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    const forwarder = jest.fn().mockResolvedValue({ jsonrpc: '2.0', id: 11, result: {} });
    const gateway = new AgenticDomeMCPGateway(client, forwarder);
    const request = { jsonrpc: '2.0' as const, id: 11, method: 'tools/call', params: { name: 'crm.export', arguments: { scope: 'all' } } };
    const context = { agentId: 'support-agent', sessionId: 'session-5', mcpServerId: 'crm-mcp' };

    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'REDACTED', tool_args: { scope: 'all' } }) as any;
    const missingReplacement = await gateway.forward(request, context);
    expect(missingReplacement.error?.code).toBe(-32000);
    expect(forwarder).not.toHaveBeenCalled();

    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'REDACTED', sanitized_tool_args: {} }) as any;
    const emptyReplacement = await gateway.preflight(request, context);
    expect(emptyReplacement.request?.params?.arguments).toEqual({});
    await gateway.forward(request, context);
    expect(forwarder).toHaveBeenCalledWith(expect.objectContaining({
      params: { name: 'crm.export', arguments: {} },
    }), context);
    forwarder.mockClear();

    const unsupportedRequest = { jsonrpc: '2.0' as const, id: 12, method: 'resources/read', params: { uri: 'file:///private.txt' } };
    const unsupportedReplacement = await gateway.forward(unsupportedRequest, context);
    expect(unsupportedReplacement.error?.code).toBe(-32000);
    expect(forwarder).not.toHaveBeenCalled();
    client.close();
  });

  test('MCP gateway withholds redacted output without one safe replacement', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    client.meshValidate = jest.fn().mockResolvedValue({ verdict: 'REDACTED' }) as any;
    const forwarder = jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 13, result: { content: [{ type: 'text', text: 'private@example.com' }] },
    });
    const gateway = new AgenticDomeMCPGateway(client, forwarder);
    const request = { jsonrpc: '2.0' as const, id: 13, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } };
    const context = { agentId: 'support-agent', sessionId: 'session-6', mcpServerId: 'crm-mcp' };

    const missingReplacement = await gateway.forward(request, context);
    expect(missingReplacement.error?.code).toBe(-32000);
    expect(forwarder).toHaveBeenCalledTimes(1);

    client.meshValidate = jest.fn().mockResolvedValue({ verdict: 'REDACTED', sanitized_text: 'safe' }) as any;
    forwarder.mockResolvedValue({
      jsonrpc: '2.0', id: 13, result: { content: [{ type: 'text', text: 'one secret' }, { type: 'text', text: 'another secret' }] },
    });
    const ambiguousReplacement = await gateway.forward(request, context);
    expect(ambiguousReplacement.error?.code).toBe(-32000);

    forwarder.mockResolvedValue({
      jsonrpc: '2.0', id: 13, result: { content: [{ type: 'text', text: '' }, { type: 'text', text: 'secret' }] },
    });
    const emptyFirstItem = await gateway.forward(request, context);
    expect(emptyFirstItem.error?.code).toBe(-32000);
    client.close();
  });

  test('MCP gateway reviews structured output and text in the same result', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const meshValidate = jest.fn().mockImplementation(async ({ text }) => ({
      verdict: 'REDACTED', sanitized_text: text.replaceAll('alice@example.com', '[REDACTED]'),
    }));
    client.meshValidate = meshValidate as any;
    const forwarder = jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 14, result: {
        content: [{ type: 'text', text: 'Contact alice@example.com' }],
        structuredContent: { email: 'alice@example.com' },
        extra: { owner: 'alice@example.com' },
      },
    });
    const gateway = new AgenticDomeMCPGateway(client, forwarder);

    const response = await gateway.forward(
      { jsonrpc: '2.0', id: 14, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } },
      { agentId: 'support-agent', sessionId: 'session-7', mcpServerId: 'crm-mcp' },
    );

    expect(meshValidate).toHaveBeenCalledTimes(1);
    expect(meshValidate.mock.calls[0][0].text).toContain('structuredContent');
    expect(JSON.stringify(response)).not.toContain('alice@example.com');
    expect((response.result as any).structuredContent.email).toBe('[REDACTED]');
    client.close();
  });

  test('MCP gateway reviews structured-only output', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const meshValidate = jest.fn().mockImplementation(async ({ text }) => ({
      verdict: 'REDACTED', sanitized_text: text.replace('alice@example.com', '[REDACTED]'),
    }));
    client.meshValidate = meshValidate as any;
    const gateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 15, result: { structuredContent: { email: 'alice@example.com' } },
    }));

    const response = await gateway.forward(
      { jsonrpc: '2.0', id: 15, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } },
      { agentId: 'support-agent', sessionId: 'session-8', mcpServerId: 'crm-mcp' },
    );

    expect(meshValidate).toHaveBeenCalledTimes(1);
    expect((response.result as any).structuredContent.email).toBe('[REDACTED]');
    client.close();
  });

  test('MCP booking cancel compares the authenticated member with provider-owned reservation owner', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    client.meshValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const forwarder = jest.fn().mockResolvedValue({ jsonrpc: '2.0', id: 16, result: {} });
    let authenticatedMember = 'member-requester';
    const gateway = new AgenticDomeMCPGateway(client, forwarder, {
      failClosed: false,
      providerActionRules: { 'booking.cancel': { action: 'cancel_booking' } },
      resolveProviderFacts: async (_tool, args) => ({
        reservationId: args.reservation_id as string,
        ownerId: 'member-owner',
        principalId: authenticatedMember,
      }),
    });
    const request = { jsonrpc: '2.0' as const, id: 16, method: 'tools/call', params: {
      name: 'booking.cancel', arguments: { reservation_id: 'res-123', owner_id: 'member-requester' },
    } };
    const context = { agentId: 'booking-agent', sessionId: 's1', mcpServerId: 'gym', userId: 'member-owner' };

    const blocked = await gateway.forward(request, context);
    expect(blocked.error?.code).toBe(-32000);
    expect(forwarder).not.toHaveBeenCalled();

    authenticatedMember = 'member-owner';
    const allowed = await gateway.forward(request, { ...context, userId: 'spoofed' });
    expect(allowed.result).toEqual({});
    expect(forwarder).toHaveBeenCalledTimes(1);
    const missingIntegration = new AgenticDomeMCPGateway(client, forwarder, {
      failClosed: false, providerActionRules: { 'booking.cancel': { action: 'cancel_booking' } },
    });
    expect((await missingIntegration.preflight(request, context)).blocked?.error?.code).toBe(-32000);
    client.mcpGuardrailValidate = jest.fn().mockRejectedValue(new Error('sidecar unavailable')) as any;
    expect((await gateway.preflight(request, context)).blocked?.error?.code).toBe(-32000);
    client.close();
  });

  test('MCP booking horizon checks the provider limit against final sanitized arguments', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const seen: unknown[] = [];
    const gateway = new AgenticDomeMCPGateway(client, jest.fn(), {
      providerActionRules: { 'booking.create': { action: 'create_booking' } },
      resolveProviderFacts: async (_tool, args) => {
        seen.push(args);
        return { principalId: 'member-1', latestAllowedDate: '2026-10-05' };
      },
    });
    const request = { jsonrpc: '2.0' as const, id: 17, method: 'tools/call', params: {
      name: 'booking.create', arguments: { booking_date: '2026-10-10' },
    } };
    const context = { agentId: 'booking-agent', sessionId: 's1', mcpServerId: 'gym' };

    expect((await gateway.preflight(request, context)).blocked?.error?.code).toBe(-32000);
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({
      verdict: 'REDACTED', sanitized_tool_args: { booking_date: '2026-10-04' },
    }) as any;
    expect((await gateway.preflight(request, context)).request?.params?.arguments).toEqual({ booking_date: '2026-10-04' });
    expect(seen).toEqual([{ booking_date: '2026-10-10' }, { booking_date: '2026-10-04' }]);
    client.close();
  });

  test('MCP gateway filters tool discovery using the sidecar decision', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.meshValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({
      verdict: 'ALLOWED', allowed_tools: ['crm.lookup'], blocked_tools: ['admin.delete'],
    }) as any;
    const gateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 9, result: { tools: [{ name: 'crm.lookup' }, { name: 'admin.delete' }] },
    }));

    const response = await gateway.forward(
      { jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} },
      { agentId: 'support-agent', sessionId: 'session-3', mcpServerId: 'crm-mcp' },
    );

    expect((response.result as any).tools).toEqual([{ name: 'crm.lookup' }]);
    client.close();
  });

  test('MCP gateway reviews JSON-RPC sibling and error fields without changing the response shape', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    client.meshValidate = jest.fn().mockImplementation(async ({ text }) => ({
      verdict: 'REDACTED', sanitized_text: text.replaceAll('alice@example.com', '[REDACTED]'),
    })) as any;
    const request = { jsonrpc: '2.0' as const, id: 19, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } };
    const context = { agentId: 'support', sessionId: 's1', mcpServerId: 'crm' };
    const gateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 19, result: { structuredContent: { email: 'alice@example.com' } },
      extension: { email: 'alice@example.com' },
    }));
    const reviewed = await gateway.forward(request, context);
    expect(JSON.stringify(reviewed)).not.toContain('alice@example.com');
    expect(reviewed.id).toBe(19);

    const errors = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 19, error: { code: 400, message: 'alice@example.com' },
    }));
    const reviewedError = await errors.forward(request, context);
    expect(reviewedError.error?.message).toBe('[REDACTED]');

    client.meshValidate = jest.fn().mockResolvedValue({
      verdict: 'REDACTED', sanitized_text: '{"result":{}}',
    }) as any;
    const malformed = await gateway.forward(request, context);
    expect(malformed.error?.code).toBe(-32000);
    client.close();
  });

  test('MCP gateway rejects a non-JSON-RPC forwarder response', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const gateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue('alice@example.com'));
    const response = await gateway.forward(
      { jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } },
      { agentId: 'support', sessionId: 's1', mcpServerId: 'crm' },
    );
    expect(response.error?.code).toBe(-32000);
    expect(JSON.stringify(response)).not.toContain('alice@example.com');
    client.close();
  });

  test('MCP output review returns its immutable JSON snapshot, not a later-mutated forwarder object', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const shared = { jsonrpc: '2.0' as const, id: 21, result: { structuredContent: { email: 'safe' } } };
    client.meshValidate = jest.fn().mockImplementation(async () => {
      shared.result.structuredContent.email = 'alice@example.com';
      return { verdict: 'ALLOWED' };
    }) as any;
    const request = { jsonrpc: '2.0' as const, id: 21, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } };
    const context = { agentId: 'support', sessionId: 's1', mcpServerId: 'crm' };
    const gateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue(shared));
    const reviewed = await gateway.forward(request, context);
    expect((reviewed.result as any).structuredContent.email).toBe('safe');

    const projected = { jsonrpc: '2.0' as const, id: 21, result: { structuredContent: { email: 'alice@example.com' } },
      toJSON: () => ({ jsonrpc: '2.0', id: 21, result: {} }) };
    const projectionGateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue(projected));
    expect((await projectionGateway.forward(request, context)).error?.code).toBe(-32000);
    client.close();
  });

  test('MCP gateway rejects mismatched and redacted response IDs', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const request = { jsonrpc: '2.0' as const, id: 22, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } };
    const context = { agentId: 'support', sessionId: 's1', mcpServerId: 'crm' };
    const mismatch = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({ jsonrpc: '2.0', id: 'alice@example.com', result: {} }));
    expect((await mismatch.forward(request, context)).error?.code).toBe(-32000);

    client.meshValidate = jest.fn().mockResolvedValue({
      verdict: 'REDACTED', sanitized_text: '{"id":"[REDACTED]","result":{}}',
    }) as any;
    const redacted = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({ jsonrpc: '2.0', id: 22, result: {} }));
    expect((await redacted.forward(request, context)).error?.code).toBe(-32000);
    client.close();
  });

  test('MCP gateway blocks partial Mesh scans and large reviews without coverage flags', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const request = { jsonrpc: '2.0' as const, id: 23, method: 'tools/call', params: { name: 'crm.lookup', arguments: {} } };
    const context = { agentId: 'support', sessionId: 's1', mcpServerId: 'crm' };
    const gateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 23, result: { structuredContent: { email: 'alice@example.com' } },
    }));
    client.meshValidate = jest.fn().mockResolvedValue({
      verdict: 'ALLOWED', context: { truncated_for_scan: true, truncated_for_echo: false },
    }) as any;
    expect((await gateway.forward(request, context)).error?.code).toBe(-32000);

    client.meshValidate = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }) as any;
    const largeGateway = new AgenticDomeMCPGateway(client, jest.fn().mockResolvedValue({
      jsonrpc: '2.0', id: 23, result: { structuredContent: { value: 'a'.repeat(6500) } },
    }));
    expect((await largeGateway.forward(request, context)).error?.code).toBe(-32000);
    client.close();
  });

  test('MCP gateway fails closed when policy is unavailable or identity context is incomplete', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    client.mcpGuardrailValidate = jest.fn().mockRejectedValue(new Error('sidecar unavailable')) as any;
    const forwarder = jest.fn();
    const gateway = new AgenticDomeMCPGateway(client, forwarder);
    const request = { jsonrpc: '2.0' as const, id: 10, method: 'tools/call', params: { name: 'crm.lookup' } };

    const unavailable = await gateway.forward(
      request,
      { agentId: 'support-agent', sessionId: 'session-4', mcpServerId: 'crm-mcp' },
    );
    const incomplete = await gateway.forward(
      request,
      { agentId: '', sessionId: 'session-4', mcpServerId: 'crm-mcp' },
    );

    expect(unavailable.error?.message).toContain('MCP preflight unavailable');
    expect(incomplete.error?.message).toContain('MCP preflight unavailable');
    expect(forwarder).not.toHaveBeenCalled();
    client.close();
  });
});
