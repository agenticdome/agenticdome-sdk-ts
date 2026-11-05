import { createServer } from 'node:http';
import AgenticDomeClient, { AgenticDomeError, ApprovalRequired } from '../index';

test('denied and paused HTTP mutations never reach a real local API; approved resume sends once', async () => {
  const received: string[] = [];
  const server = createServer((request, response) => {
    let body = '';
    request.on('data', chunk => {body += chunk;});
    request.on('end', () => {received.push(body); response.end('{}');});
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test listener');
  const client = new AgenticDomeClient('https://sidecar.invalid', {apiKey: 'fixture', tenantId: 'test'});
  let mode = 'deny'; let consumed = false;
  const id = '8d50b9df-d260-4f45-9773-85daceb0edb2';
  jest.spyOn(client as any, 'request').mockImplementation(async (...args: any[]) => {
    const [, route, options] = args;
    if (route.endsWith('/grant')) return {approval_grant: 'fixture'};
    if (mode === 'deny' || consumed) return {verdict: 'BLOCKED', broker: {verified: false}};
    if (!options.jsonBody.policy_context.approval_grant) return {verdict: 'APPROVAL_REQUIRED', context: {approval: {id}}};
    consumed = true;
    return {verdict: 'ALLOWED', execution_receipt: 'receipt', enforcement_evidence: {http_request_bound: true}, broker: {verified: true, token_consumed: true, approval_request_id: id}};
  });
  const options = {method: 'POST', url: `http://127.0.0.1:${address.port}/cancel`, body: '{"id":"one"}',
    headers: {'content-type': 'application/json', 'if-match': 'v1'}, agentId: 'agent', toolName: 'bookings.cancel'};
  try {
    await expect(client.executeHttp(options)).rejects.toBeInstanceOf(AgenticDomeError);
    expect(received).toEqual([]); mode = 'approval';
    let pending: ApprovalRequired | undefined;
    try {await client.executeHttp(options);} catch (error) {if (error instanceof ApprovalRequired) pending = error; else throw error;}
    expect(pending).toBeDefined(); expect(received).toEqual([]);
    await client.resumeApprovedHttp(pending!);
    expect(received).toEqual(['{"id":"one"}']);
    await expect(client.resumeApprovedHttp(pending!)).rejects.toBeInstanceOf(AgenticDomeError);
    expect(received).toHaveLength(1);
  } finally { client.close(); await new Promise<void>(resolve => server.close(() => resolve())); }
});
