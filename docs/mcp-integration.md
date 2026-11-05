# MCP Gateway Integration for TypeScript

Use `agenticdome-sdk` in the Node.js service that owns the MCP forwarding
boundary. The application asks AgenticDome for an action decision immediately
before calling its existing MCP transport, then reviews returned content before
it re-enters an agent or model context.

The TypeScript package now includes `AgenticDomeMCPGateway`, a transport-neutral
request/response wrapper. It does not install global interception, open a proxy
port, or choose an MCP transport. You inject the application's existing stdio,
HTTP or SSE forwarder. The package does not depend on or certify
`@modelcontextprotocol/sdk`; that transport lifecycle remains separate.

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

Use the fail-closed wrapper for new integrations:

```ts
import AgenticDomeClient, { AgenticDomeMCPGateway } from 'agenticdome-sdk';

const client = new AgenticDomeClient(process.env.AGENTICDOME_API_BASE!, {
  apiKey: process.env.AGENTICDOME_API_KEY!,
  tenantId: process.env.AGENTICDOME_TENANT_ID!,
});

// Keep your existing transport. This function is the only route to it.
const gateway = new AgenticDomeMCPGateway(
  client,
  async (request) => existingMcpTransport.send(request),
  { failClosed: true, sanitizeOutput: true, requireMcpSchema: true },
);

const response = await gateway.forward(request, {
  agentId: authenticatedAgent.id,
  sessionId: trace.sessionId,
  userId: authenticatedUser?.id,
  mcpServerId: configuredServer.id,
  userPrompt: currentUserPrompt,
  policyContext: { business_purpose: approvedBusinessPurpose },
});
```

The wrapper authorizes before the injected forwarder can run, applies sanitized
tool arguments, filters `tools/list`, and reviews the bounded JSON response
payload together, including `content`, `structuredContent`, error data and
sibling extension fields. A redacted replacement must be valid JSON with the
same structure or the wrapper blocks it. It fails closed by default. Do not
keep a second direct route to the upstream server. Opaque/base64 content,
unwrapped routes, disabled review and explicitly fail-open review are outside
this coverage.
Runtime-reported partial scan or echo coverage blocks the response, as does a
large response lacking explicit no-truncation evidence from an older sidecar.

Fetch the server's `tools/list` through this same gateway before calling tools.
The gateway caches published `inputSchema` definitions for at most five minutes,
separately for each tenant, server, session, caller and scoped identity. Valid
cached calls require no extra catalogue request. It checks required fields,
types, enum values, numeric bounds, nested structures and additional properties
before policy authorization, then checks sanitized arguments again. Schema
changes during authorization require a new discovery/retry. A completed new
catalogue removes omitted tools. Paginated catalogues reject repeated tool names
and remain bounded. When the transport receives `notifications/tools/list_changed`,
call `gateway.invalidateSchemas(context)` and fetch the catalogue again.

`requireMcpSchema` defaults to false for existing integrations, matching Python's
compatibility behavior. Published schemas are still checked whenever available;
new integrations should enable it so missing or expired schemas block forwarding.
Schema errors cannot be made fail-open. Local acyclic references and draft-07,
2019-09 and 2020-12 schemas are supported. Remote schema loading, dynamic
references, schema resource IDs and unsupported regex constructs fail closed.
Regex checks use a bounded, non-backtracking engine. Schema and argument size,
depth, catalogue and cache-memory limits apply. Schema validity describes the
request structure; the runtime's policies and identity checks decide authority.

The client also exposes `guardNativeTool(event)` and `nativeGuardReady()` for
Docker mandatory-guard integration, using the same endpoint and event shape as
Python. These checks never execute a tool or cache a permit, and refuse redirects.
The Python `agenticdome-docker-guard` CLI remains the ready-made Docker hook adapter.

The lower-level policy methods remain available for bespoke transports, but
calling `mcpGuardrailValidate()` and scanning only `content[].text` is **not**
equivalent to this wrapper: it can miss `structuredContent` and sibling fields.
If you build a bespoke transport, gate the final arguments before forwarding,
review the complete JSON response, and reject malformed or partial redacted
replacements. Test that no alternate path bypasses those checks.

### Provider-backed booking rules (opt-in)

When an MCP server can access its authenticated member session and reservation
database, configure exact tool names on the gateway:

```ts
const gateway = new AgenticDomeMCPGateway(client, forwardToMcpServer, {
  providerActionRules: {
    'booking.cancel': { action: 'cancel_booking' },
    'booking.create': { action: 'create_booking' },
  },
  resolveProviderFacts: async (toolName, finalArgs) => {
    // These provider-owned interfaces are illustrative, not SDK APIs.
    // Bind the resolver to the authenticated server request scope.
    const memberId = serverSession.requireAuthenticatedMemberId();
    if (toolName === 'booking.cancel') {
      const reservation = await bookingStore.get(finalArgs.reservation_id);
      return { principalId: memberId, reservationId: reservation.id, ownerId: reservation.memberId };
    }
    return { principalId: memberId, latestAllowedDate: await bookingStore.latestAllowedLocalDate(memberId) };
  },
});
```

The default final argument names are `reservation_id` and `booking_date`
(provider-local `YYYY-MM-DD`). Set `reservationIdArgument` or
`bookingDateArgument` for other tool schemas. The gateway blocks a cancellation
unless the requested reservation matches the provider lookup and its owner is
the authenticated member. It blocks a new booking past the provider's horizon.
Missing facts or a sidecar failure also block configured booking tools, even
with `failClosed: false`. Neither `context.userId` nor agent-provided arguments
are proof of membership or ownership. The provider backend must still enforce
ownership and booking limits atomically; this guard cannot protect a browser or
API route that does not pass through it.

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
