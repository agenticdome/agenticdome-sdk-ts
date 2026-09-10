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
});
