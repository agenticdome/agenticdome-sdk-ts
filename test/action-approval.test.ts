import AgenticDomeClient, { ApprovalRequired } from '../index';

const id = '8d50b9df-d260-4f45-9773-85daceb0edb2';
const paused = { verdict: 'APPROVAL_REQUIRED', context: { approval: { id }, approval_url: `/agentguard/approvals/${id}` } };
const authorized = { verdict: 'ALLOWED', broker: { verified: true, token_consumed: true, approval_request_id: id }, execution_receipt: 'receipt' };
const options = () => ({ text: 'Generate a report', agentId: 'worker', platform: 'generic', toolName: 'model.chat', toolArgs: { messages: [{ content: 'original private evidence' }] }, tenantId: '2' });

describe('exact-action approval', () => {
  test('pauses before broker-contract fallback and freezes arguments before the asynchronous request', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key', executionBrokerMode: 'policy' });
    const input = options();
    let release!: (value: any) => void;
    const request = jest.fn().mockImplementationOnce(() => new Promise(resolve => { release = resolve; }))
      .mockResolvedValueOnce({ approval_grant: 'signed-grant' }).mockResolvedValueOnce(authorized);
    (client as any).request = request;
    const waiting = client.guardrailValidate(input).catch(error => error);
    input.toolArgs.messages[0].content = 'changed';
    release(paused);
    const pending = await waiting;
    expect(pending).toBeInstanceOf(ApprovalRequired);
    expect(String(pending)).not.toContain('private evidence');
    const executor = jest.fn(args => args);
    const exported = pending.exportPreparedAction();
    const restored = ApprovalRequired.restorePreparedAction(JSON.parse(JSON.stringify(exported)));
    exported.prepared_request.tool_args.messages[0].content = 'changed exported copy';
    const result = await restored.resume(client, executor);
    expect(result.messages[0].content).toBe('original private evidence');
    expect(executor).toHaveBeenCalledTimes(1);
    const resumed = request.mock.calls[2][2];
    expect(resumed.tenantId).toBe('2');
    expect(resumed.jsonBody.policy_context.approval_action_id).toBeTruthy();
    expect(resumed.jsonBody.policy_context.approval_grant).toBe('signed-grant');
    expect(request.mock.calls[1][1]).toBe(`/tools/approvals/${id}/grant`);
    client.close();
  });

  test.each([
    { verdict: 'BLOCKED' }, { ...authorized, verdict: 'APPROVAL_REQUIRED' },
    { ...authorized, execution_receipt: '' },
    { ...authorized, broker: { ...authorized.broker, verified: false } },
    { ...authorized, broker: { ...authorized.broker, token_consumed: false } },
    { ...authorized, broker: { ...authorized.broker, approval_request_id: 'another-request' } },
  ])('never calls the executor without complete approval consumption evidence', async response => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    (client as any).request = jest.fn().mockResolvedValueOnce(paused).mockResolvedValueOnce({ approval_grant: 'grant' }).mockResolvedValueOnce(response);
    const pending = await client.guardrailValidate(options()).catch(error => error);
    const executor = jest.fn();
    await expect(pending.resume(client, executor)).rejects.toThrow();
    expect(executor).not.toHaveBeenCalled();
    client.close();
  });

  test('expired, rejected and revoked grants fail closed without retrying the executor', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    const request = jest.fn().mockResolvedValueOnce(paused).mockRejectedValue(new Error('Grant unavailable'));
    (client as any).request = request;
    const pending = await client.guardrailValidate(options()).catch(error => error);
    const executor = jest.fn();
    await expect(pending.resume(client, executor)).rejects.toThrow('Grant unavailable');
    expect(executor).not.toHaveBeenCalled();
    expect(request).toHaveBeenCalledTimes(2);
    client.close();
  });

  test('each action has a unique nonce; an ordinary allowed action needs no approval fetch', async () => {
    const client = new AgenticDomeClient('https://sidecar.example', { apiKey: 'test-key' });
    const request = jest.fn().mockResolvedValue({ verdict: 'ALLOWED' }); (client as any).request = request;
    await client.guardrailValidate(options()); await client.guardrailValidate(options());
    expect(request).toHaveBeenCalledTimes(2);
    expect(request.mock.calls[0][2].jsonBody.policy_context.approval_action_id).not.toBe(request.mock.calls[1][2].jsonBody.policy_context.approval_action_id);
    client.close();
  });
});
