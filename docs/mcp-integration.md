# MCP Gateway Integration for TypeScript

Use `agenticdome-sdk` in the Node.js service that owns the MCP forwarding
boundary. The application asks AgenticDome for an action decision immediately
before calling its existing MCP transport, then reviews returned content before
it re-enters an agent or model context.

The TypeScript package is an API client, not an MCP proxy. It does not install
global interception or forward traffic automatically. It also does not depend
on or certify `@modelcontextprotocol/sdk`; keep the application's existing MCP
transport and its version lifecycle separate.

An MCP provider may place these explicit calls in a provider-controlled tool
dispatcher, or publish a customer-side gateway pattern. That does not protect
unrelated server routes automatically: the correct customer tenant, actor,
agent, server, tool, and argument context must reach AgenticDome before the
provider executes the action.

## Install and configure

```bash
npm install agenticdome-sdk
```

```bash
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example"
export AGENTICDOME_API_KEY="your_runtime_sdk_key"
export AGENTICDOME_TENANT_ID="your_tenant_id"
```

Use the tenant's assigned runtime sidecar, not the AgenticDome admin or
control-plane website.

For managed service, the sidecar is assigned in the customer's selected
supported geographic region, subject to availability. For a contracted
Sovereign deployment, it runs inside the customer-controlled VPC, cloud, or
on-premises boundary. This TypeScript client does not require customer-managed
Redis; any backing services behind a managed sidecar are part of the managed
runtime.

## Authorize immediately before forwarding

```ts
import { AgenticDomeClient } from 'agenticdome-sdk';

type JsonObject = Record<string, unknown>;

const client = new AgenticDomeClient(process.env.AGENTICDOME_API_BASE!, {
  apiKey: process.env.AGENTICDOME_API_KEY!,
  tenantId: process.env.AGENTICDOME_TENANT_ID!,
});

function unwrap(response: JsonObject): JsonObject {
  return typeof response.result === 'object' && response.result !== null
    ? response.result as JsonObject
    : response;
}

function extractTextContent(response: JsonObject): string {
  const result = typeof response.result === 'object' && response.result !== null
    ? response.result as JsonObject
    : {};
  const content = Array.isArray(result.content) ? result.content : [];
  return content
    .filter((item): item is JsonObject => typeof item === 'object' && item !== null)
    .map((item) => typeof item.text === 'string' ? item.text : '')
    .filter(Boolean)
    .join('\n');
}

function replaceTextContent(response: JsonObject, sanitizedText: string): JsonObject {
  const copy = structuredClone(response);
  const result = typeof copy.result === 'object' && copy.result !== null
    ? copy.result as JsonObject
    : null;
  if (!result || !Array.isArray(result.content)) return copy;

  let replaced = false;
  result.content = result.content.map((item) => {
    if (replaced || typeof item !== 'object' || item === null || typeof (item as JsonObject).text !== 'string') {
      return item;
    }
    replaced = true;
    return { ...(item as JsonObject), text: sanitizedText };
  });
  return copy;
}

// Supply your existing MCP client/transport implementation here.
declare function forwardToMcpServer(request: JsonObject): Promise<JsonObject>;

export async function forwardProtectedMcpTool(
  request: {
    jsonrpc: '2.0';
    id: string | number;
    method: 'tools/call';
    params: { name: string; arguments?: JsonObject };
  },
  context: {
    sessionId: string;
    userId?: string;
    sourceAgentId?: string;
    userPrompt: string;
    mcpServerId: string;
  },
): Promise<JsonObject> {
  const decisionResponse = await client.mcpGuardrailValidate({
    text: context.userPrompt,
    agentId: 'typescript-mcp-gateway',
    sourceAgentId: context.sourceAgentId,
    userId: context.userId,
    direction: 'outbound',
    platform: 'mcp',
    toolPlatform: context.mcpServerId,
    toolName: request.params.name,
    toolArgs: request.params.arguments ?? {},
    requestPurpose: 'mcp_tool_execution',
    policyContext: {
      session_id: context.sessionId,
      mcp_server_id: context.mcpServerId,
    },
  });

  const decision = unwrap(decisionResponse);
  const verdict = String(decision.verdict ?? decision.decision ?? 'UNKNOWN').toUpperCase();
  if (verdict === 'BLOCKED' || verdict === 'ERROR' || verdict === 'UNKNOWN') {
    throw new Error(`AgenticDome blocked MCP forwarding: ${String(decision.reason ?? verdict)}`);
  }

  // This is the application's existing MCP transport. Do not retain a second
  // direct route for sensitive tools.
  const response = await forwardToMcpServer(request);

  const returnedText = extractTextContent(response);
  if (!returnedText) return response;

  const outputResponse = await client.meshValidate({
    agentId: 'typescript-mcp-gateway',
    sourceAgentId: context.sourceAgentId,
    userId: context.userId,
    sessionId: context.sessionId,
    direction: 'output',
    platform: 'mcp',
    text: returnedText,
    redactPii: true,
    redactSecrets: true,
    policyContext: {
      request_purpose: 'mcp_tool_output_review',
      mcp_server_id: context.mcpServerId,
      tool_name: request.params.name,
    },
  });

  const output = unwrap(outputResponse);
  const outputVerdict = String(output.verdict ?? output.decision ?? 'UNKNOWN').toUpperCase();
  if (outputVerdict === 'BLOCKED' || outputVerdict === 'ERROR' || outputVerdict === 'UNKNOWN') {
    throw new Error(`AgenticDome blocked MCP result: ${String(output.reason ?? outputVerdict)}`);
  }

  return replaceTextContent(
    response,
    String(output.sanitized_text ?? output.text ?? returnedText),
  );
}
```

Replace the declared `forwardToMcpServer` with your existing MCP transport.
Adapt the small extraction helpers if your server returns a different content
shape. Preserve non-text structured fields, and replace only content the policy
response explicitly sanitizes.

## Production rules

- Treat `BLOCKED`, `ERROR`, `UNKNOWN`, malformed responses and sidecar
  unavailability according to an explicit fail-closed production policy.
- Pass only authenticated human/workload and agent identity. Never synthesize a
  human user for a scheduler or webhook.
- Keep stable session and trace identifiers across request and result checks.
- Bind policy context to the actual MCP server and tool.
- Keep MCP OAuth, token audience validation, user consent, scope checks and
  human confirmation in place. AgenticDome complements them.
- Constrain MCP tool filesystem, process and network access separately.
- Test that blocked requests never reach the real transport.

The Python package provides a higher-level plain-JSON-RPC host adapter with
list filtering, response sanitization, streaming handling and delegated
execution support. See the
[complete MCP Action Firewall guide](https://github.com/agenticdome/agenticdome-python-sdk/blob/main/docs/mcp-integration.md).

Report normal integration problems through the public issue tracker. Follow
[`SECURITY.md`](../SECURITY.md) for private vulnerability disclosure.
