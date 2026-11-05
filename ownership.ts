/** Trusted provider resolvers shared by HTTP and MCP; never accept caller ownership claims. */
export class OwnershipDenied extends Error {
  constructor(message: string) { super(message); this.name = 'OwnershipDenied'; }
}
export interface ResourceRule {
  resourceType: string;
  resourceArgument: string;
  operation: string;
  relationship?: 'owner' | 'entitled';
  maxResources?: number;
}
export interface ResourceSubject { tenantId: string; principalId: string }
export interface ResourceRequest extends ResourceSubject {
  resourceType: string; resourceId: string; operation: string; tool: string;
  arguments: Record<string, unknown>;
}
export interface ResourceFact {
  tenantId: string; resourceType: string; resourceId: string;
  ownerId?: string; entitledPrincipals?: string[]; allowedOperations: string[];
}
const validId = (s: unknown): s is string => typeof s === 'string' && !!s.trim() && s.length <= 512;

export function verifyResourceFact(subject: ResourceSubject, request: ResourceRequest, fact: ResourceFact, relationship: 'owner' | 'entitled') {
  if (!subject || !validId(subject.tenantId) || !validId(subject.principalId)) throw new OwnershipDenied('Authenticated tenant and principal are required');
  if (!fact || fact.tenantId !== request.tenantId || fact.resourceType !== request.resourceType || fact.resourceId !== request.resourceId) throw new OwnershipDenied('Provider facts do not match the requested tenant and resource');
  if (!Array.isArray(fact.allowedOperations) || !fact.allowedOperations.includes(request.operation)) throw new OwnershipDenied('Provider does not permit this operation');
  const allowed = relationship === 'owner' ? fact.ownerId === subject.principalId : Array.isArray(fact.entitledPrincipals) && fact.entitledPrincipals.includes(subject.principalId);
  if (!allowed) throw new OwnershipDenied('Authenticated principal has no required resource relationship');
}

export class OwnershipGuard {
  private readonly rules: Record<string, ResourceRule>;
  constructor(rules: Record<string, ResourceRule>, private readonly options: {
    resolveSubject: () => ResourceSubject | Promise<ResourceSubject>;
    resolveResource: (request: ResourceRequest) => ResourceFact | Promise<ResourceFact>;
    denyUnmapped?: boolean; timeoutMs?: number;
  }) {
    this.rules = structuredClone(rules);
    this.options = { ...options };
    if (!Object.keys(this.rules).length || typeof options.resolveSubject !== 'function' || typeof options.resolveResource !== 'function') throw new Error('Supply reviewed resource rules and trusted provider resolvers');
    if (!((options.timeoutMs ?? 5000) > 0 && (options.timeoutMs ?? 5000) <= 30000)) throw new Error('Resolver timeout must be within 30 seconds');
    for (const [tool, rule] of Object.entries(this.rules)) {
      if (!validId(tool) || !validId(rule.resourceType) || !validId(rule.operation) || !/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,7}$/.test(rule.resourceArgument)
          || !['owner', 'entitled'].includes(rule.relationship ?? 'owner') || !Number.isInteger(rule.maxResources ?? 1) || (rule.maxResources ?? 1) < 1 || (rule.maxResources ?? 1) > 50) throw new Error('Invalid resource adapter rule');
    }
  }
  protects(tool: string): boolean { return this.options.denyUnmapped !== false || Object.prototype.hasOwnProperty.call(this.rules, tool); }
  async check(tool: string, args: Record<string, unknown>, expectedTenant?: string): Promise<void> {
    if (!this.protects(tool)) return;
    args = structuredClone(args);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let expired = false;
    const resolve = async () => {
      const rule = Object.prototype.hasOwnProperty.call(this.rules, tool) ? this.rules[tool] : undefined;
      if (!rule) throw new OwnershipDenied('Tool has no reviewed resource adapter');
      const subject = structuredClone(await this.options.resolveSubject());
      if (expired) throw new OwnershipDenied('Provider resource authorization timed out');
      if (!subject || !validId(subject.tenantId) || !validId(subject.principalId)) throw new OwnershipDenied('Authenticated tenant and principal are required');
      if (expectedTenant !== undefined && subject.tenantId !== expectedTenant) throw new OwnershipDenied('Provider subject tenant does not match the enforcement tenant');
      let value: unknown = args;
      for (const part of rule.resourceArgument.split('.')) value = value && typeof value === 'object' && !Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, part) ? (value as Record<string, unknown>)[part] : undefined;
      const ids = Array.isArray(value) ? value : [value];
      if (!ids.length || ids.length > (rule.maxResources ?? 1) || !ids.every(validId)) throw new OwnershipDenied('Missing resource identity or excessive resource scope');
      for (const resourceId of new Set(ids as string[])) {
        if (expired) throw new OwnershipDenied('Provider resource authorization timed out');
        const request = { ...subject, resourceType: rule.resourceType, resourceId, operation: rule.operation, tool, arguments: structuredClone(args) };
        const fact = await this.options.resolveResource(structuredClone(request));
        if (expired) throw new OwnershipDenied('Provider resource authorization timed out');
        verifyResourceFact(subject, request, fact, rule.relationship ?? 'owner');
      }
    };
    try {
      await Promise.race([resolve(), new Promise<never>((_, reject) => {
        timer = setTimeout(() => { expired = true; reject(new OwnershipDenied('Provider resource authorization timed out')); }, this.options.timeoutMs ?? 5000);
      })]);
    } catch (error) {
      if (error instanceof OwnershipDenied) throw error;
      throw new OwnershipDenied('Provider resource authorization unavailable');
    } finally { if (timer) clearTimeout(timer); }
  }
  async checkHttp(tool: string, args: Record<string, unknown>, evidence: Record<string, any>, expectedTenant?: string) {
    if (Object.keys(this.rules).some(k => k.startsWith(tool + '#')) || evidence.graphql_interpretation) {
      if (evidence.graphql_interpretation !== 'agenticdome.graphql-actions.v1' || !Array.isArray(evidence.graphql_actions)) throw new OwnershipDenied('A compatible sidecar must interpret GraphQL before ownership checks');
      for (const action of evidence.graphql_actions) await this.check(tool + '#' + action.coordinate, action.arguments, expectedTenant);
    } else await this.check(tool, args, expectedTenant);
  }
}
