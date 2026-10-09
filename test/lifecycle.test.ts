import AgenticDomeClient, { VerifiedActionReporter } from '../index';

describe('Automatic lifecycle evidence', () => {
  beforeEach(() => {
    delete process.env.AGENTICDOME_EVIDENCE_API_BASE;
    delete process.env.AGENTICDOME_EVIDENCE_TOKEN;
    delete process.env.AGENTICDOME_EVIDENCE_ENABLED;
  });

  test('uses existing tenant runtime credentials without a portal token', async () => {
    const client = new AgenticDomeClient('https://runtime.example', {apiKey:'tenant-key', tenantId:'2'});
    const request = jest.fn().mockResolvedValue({durably_queued:true});
    (client as any).request = request;
    const context = client.lifecycle.createContext({operationType:'tool_call', arguments:{secret:'RAW_ARGUMENT'}});
    await expect(client.lifecycle.run(context, () => 42, () => ({verdict:'ALLOWED'}))).resolves.toBe(42);
    expect(await client.lifecycle.flush()).toBe(true);
    expect(request.mock.calls.map(call => call[1])).toEqual([
      '/mesh/evidence/events','/mesh/evidence/events','/mesh/evidence/events','/mesh/evidence/events','/mesh/evidence/outcomes',
    ]);
    const payloads = request.mock.calls.map(call => call[2].jsonBody);
    expect(payloads.slice(0,4).map(payload => payload.phase)).toEqual(['requested','authorised','admitted','attempted']);
    expect(new Set(payloads.map(payload => payload.chain_id)).size).toBe(1);
    expect(payloads[4].assurance_level).toBe('sdk_reported');
    expect(JSON.stringify(payloads)).not.toContain('RAW_ARGUMENT');
    client.close();
  });

  test('blocked actions have no attempted phase or invented attempt time', async () => {
    const payloads: any[] = [];
    const reporter = new VerifiedActionReporter({runtimeBase:'https://runtime.example',apiKey:'key',tenantId:'2',sender:async (_kind,payload) => {payloads.push(payload);}});
    const execute = jest.fn();
    await expect(reporter.run(reporter.createContext({operationType:'tool_call'}), execute, () => ({verdict:'BLOCKED'}))).rejects.toThrow('denied');
    expect(await reporter.flush()).toBe(true);
    expect(execute).not.toHaveBeenCalled();
    expect(payloads.map(payload => payload.phase || payload.outcome_class)).toEqual(['requested','authorised','not_attempted']);
    expect(payloads[2].attempted_at).toBeUndefined();
  });

  test('retries keep the original identifier and expose delivery failure', async () => {
    const sender = jest.fn().mockRejectedValue(new Error('offline'));
    const reporter = new VerifiedActionReporter({runtimeBase:'https://runtime.example',apiKey:'key',tenantId:'2',sender});
    reporter.phase(reporter.createContext({operationType:'tool_call'}), 'requested');
    expect(await reporter.flush()).toBe(false);
    expect(sender).toHaveBeenCalledTimes(3);
    expect(new Set(sender.mock.calls.map(call => call[1].event_id)).size).toBe(1);
    expect(reporter.stats()).toMatchObject({failed:1,pending:0});
  });

  test('explicit opt out preserves operation behavior', async () => {
    process.env.AGENTICDOME_EVIDENCE_ENABLED='false';
    const reporter = new VerifiedActionReporter({runtimeBase:'https://runtime.example',apiKey:'key',tenantId:'2'});
    expect(reporter.enabled).toBe(false);
    expect(await reporter.run(reporter.createContext({operationType:'tool_call'}), () => 'ok')).toBe('ok');
    delete process.env.AGENTICDOME_EVIDENCE_ENABLED;
  });
});
