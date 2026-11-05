import AgenticDomeClient, { AgenticDomeHTTPError } from '../index';

describe('Docker native guard Python/TypeScript contract', () => {
  const event = { hook_event_name: 'tool_guard', agent_name: 'support', tool_name: 'read', tool_input: { id: '42' }, session_id: 's1', tool_use_id: 't1' };
  test('sends one bounded guard event with no extra enrollment exchange or redirects', async () => {
    const client = new AgenticDomeClient('https://runtime.test', { apiKey: 'test' });
    const request = jest.fn().mockResolvedValue({ status: 200, data: { decision: 'deny' } }); (client as any).api.request = request;
    expect(await client.guardNativeTool({ ...event, untrusted_extra: 'omitted' })).toEqual({ decision: 'deny' }); expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0][0]).toMatchObject({ url: '/gateway/v1/guard', maxRedirects: 0, data: { ...event, tool_category: 'unknown', cwd: '' } }); expect(request.mock.calls[0][0].data).not.toHaveProperty('untrusted_extra'); client.close();
  });
  test('rejects malformed arguments locally and refuses redirect responses', async () => {
    const client = new AgenticDomeClient('https://runtime.test', { apiKey: 'test', maxRetries: 0 });
    const request = jest.fn().mockResolvedValue({ status: 302, data: '' }); (client as any).api.request = request;
    await expect(client.guardNativeTool({ ...event, tool_input: [] })).rejects.toThrow(); await expect(client.guardNativeTool({ ...event, tool_input: { value: NaN } })).rejects.toThrow(); expect(request).not.toHaveBeenCalled();
    await expect(client.nativeGuardReady()).rejects.toBeInstanceOf(AgenticDomeHTTPError); expect(request.mock.calls[0][0]).toMatchObject({ url: '/gateway/v1/guard/ready', maxRedirects: 0 }); client.close();
  });
});
