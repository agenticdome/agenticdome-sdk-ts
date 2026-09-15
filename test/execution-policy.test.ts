import AgenticDomeClient from '../index';

describe('policy-managed execution broker', () => {
  test.each(['off', 'monitor', 'enforce'])('resolves %s in the same action request', async mode => {
    const client = new AgenticDomeClient('https://sidecar.example', {
      apiKey: 'test-key', tenantId: '2', executionBrokerMode: 'policy',
    });
    const request = jest.fn().mockResolvedValue({
      verdict: 'ALLOWED',
      execution_broker_policy: { schema: 'agenticdome.execution-broker-policy.v1', mode },
      broker: { verified: true, token_consumed: true },
    });
    (client as any).request = request;
    await client.guardrailValidate({ text: 'lookup', agentId: 'worker', platform: 'generic', toolName: 'crm.lookup', toolArgs: {} });
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0][1]).toBe('/tools/execution/resolve');
    expect(request.mock.calls[0][2].jsonBody.boundary_id).toBeTruthy();
    client.close();
  });

  test.each([{}, { execution_broker_policy: { schema: 'agenticdome.execution-broker-policy.v1', mode: 'enforce' } }])('fails closed on incomplete policy/receipt evidence', async response => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key', tenantId: '2', executionBrokerMode: 'policy' });
    (client as any).request = jest.fn().mockResolvedValue(response);
    await expect(client.guardrailValidate({ text: 'lookup', agentId: 'worker', platform: 'generic', toolName: 'crm.lookup', toolArgs: {} })).rejects.toThrow();
    client.close();
  });

  test('carries metadata content descriptors and the onboarding workload UUID', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key', tenantId: '2' });
    const request = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' });
    (client as any).request = request;

    await client.guardrailValidate({
      text: 'send document',
      agentId: 'worker',
      platform: 'generic',
      workloadUuid: '21d22fcf-3d72-4d40-8d90-c995a777d1f4',
      contentParts: [{ modality: 'document', content_sha256: `sha256:${'a'.repeat(64)}`, labels: ['confidential'] }],
    });

    const body = request.mock.calls[0][2].jsonBody;
    expect(body.workload_uuid).toBe('21d22fcf-3d72-4d40-8d90-c995a777d1f4');
    expect(body.content_parts).toHaveLength(1);
    client.close();
  });

  test('sends exact action references with a standalone content inspection', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key', tenantId: '2' });
    const request = jest.fn().mockResolvedValue({ verdict: 'BLOCKED' });
    (client as any).request = request;

    await client.inspectContent({
      direction: 'outbound',
      contentParts: [{ modality: 'text', text: 'bounded inspection value' }],
      workloadUuid: '21d22fcf-3d72-4d40-8d90-c995a777d1f4',
      chainId: 'chain-1',
      actionId: 'action-1',
      decisionRefSha256: 'b'.repeat(64),
    });

    expect(request.mock.calls[0][1]).toBe('/mesh/content/inspect');
    expect(request.mock.calls[0][2].jsonBody).toMatchObject({
      direction: 'output',
      workload_uuid: '21d22fcf-3d72-4d40-8d90-c995a777d1f4',
      chain_id: 'chain-1',
      action_id: 'action-1',
      decision_ref_sha256: 'b'.repeat(64),
    });
    client.close();
  });
});
