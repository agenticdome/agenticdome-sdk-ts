/** Bounded, caller-partitioned MCP inputSchema cache. No schema network loading. */
import Ajv from 'ajv';
import Ajv2019 from 'ajv/dist/2019.js';
import Ajv2020 from 'ajv/dist/2020.js';
import type { ValidateFunction } from 'ajv';
import type { RegExpEngine } from 'ajv/dist/types';
import { RE2JS } from 're2js';
import { createHash } from 'node:crypto';

type Json = Record<string, any>;
const own = (value: object, key: PropertyKey): boolean => Object.prototype.hasOwnProperty.call(value, key);
export class McpSchemaError extends Error {}
export class McpSchemaUnavailable extends McpSchemaError {}

export function bounded(value: unknown, nodes = 4096, depth = 32): void {
  const seen = new Set<object>();
  function visit(item: any, level: number): void {
    if (--nodes < 0 || level > depth) throw new McpSchemaError('MCP validation complexity limit exceeded');
    if (typeof item === 'number' && !Number.isFinite(item)) throw new McpSchemaError('MCP requires finite JSON numbers');
    if (item === null || ['string', 'boolean', 'number'].includes(typeof item)) return;
    if (typeof item !== 'object' || seen.has(item)) throw new McpSchemaError('MCP requires acyclic JSON values');
    const proto = Object.getPrototypeOf(item);
    if (Array.isArray(item) ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) throw new McpSchemaError('MCP requires plain JSON objects');
    seen.add(item);
    for (const key of Reflect.ownKeys(item)) {
      if (Array.isArray(item) && key === 'length') continue;
      const descriptor = Object.getOwnPropertyDescriptor(item, key)!;
      if (typeof key !== 'string' || !descriptor.enumerable || !('value' in descriptor)) throw new McpSchemaError('MCP requires plain JSON properties');
      visit(descriptor.value, level + 1);
    }
    seen.delete(item);
  }
  visit(value, 0);
}

const safeRegexp: RegExpEngine = Object.assign((pattern: string) => {
  if (pattern.length > 1024) throw new McpSchemaError('MCP schema pattern exceeds limit');
  // No optional lookbehind/backreference extensions and no native backtracking.
  const compiled = RE2JS.compile(RE2JS.translateRegExp(pattern));
  // Ajv interns patterns by toString(); each pattern needs a distinct cache key.
  return { test: (text: string) => compiled.matcher(text).find(), toString: () => JSON.stringify([pattern, 'u']) };
}, { code: 'agenticdomeBoundedRegExp' });

function schemaSnapshot(schema: Json): { schema: Json; bytes: number; digest: string } {
  if (!schema || Array.isArray(schema) || schema.type !== 'object') throw new McpSchemaError('MCP inputSchema must describe an object');
  bounded(schema, 1024, 20);
  const raw = JSON.stringify(schema);
  if (Buffer.byteLength(raw) > 32768) throw new McpSchemaError('MCP inputSchema exceeds 32 KiB');
  const owned = JSON.parse(raw); let remaining = 4096;
  function walk(node: any, references: string[] = []): void {
    if (--remaining < 0) throw new McpSchemaError('MCP schema expansion exceeds limit');
    if (!node || typeof node !== 'object') return;
    if (!Array.isArray(node)) {
      if (node !== owned && own(node, '$schema')) throw new McpSchemaError('Nested schema dialect changes are unsupported');
      if (['$id', '$dynamicRef', '$recursiveRef', '$async'].some(k => own(node, k))) throw new McpSchemaError('MCP schema resource or dynamic references require a reviewed adapter');
      if (own(node, '$ref')) {
        const ref = node.$ref;
        if (typeof ref !== 'string' || !ref.startsWith('#/') || references.includes(ref) || references.length >= 8) throw new McpSchemaError('Only acyclic local schema references are supported');
        let target = owned;
        for (const part of ref.slice(2).split('/').map(p => p.replace(/~1/g, '/').replace(/~0/g, '~'))) {
          if (!target || typeof target !== 'object' || !own(target, part)) throw new McpSchemaError('Unresolved local schema reference');
          target = target[part];
        }
        walk(target, [...references, ref]);
      }
      for (const key of ['anyOf', 'oneOf', 'allOf']) if (Array.isArray(node[key]) && node[key].length > 16) throw new McpSchemaError('MCP schema alternatives exceed limit');
      if (node.pattern !== undefined) { if (typeof node.pattern !== 'string') throw new McpSchemaError('Invalid schema pattern'); safeRegexp(node.pattern, 'u'); }
      if (node.patternProperties) for (const pattern of Object.keys(node.patternProperties)) safeRegexp(pattern, 'u');
    }
    for (const child of Object.values(node)) walk(child, references);
  }
  walk(owned);
  return { schema: owned, bytes: Buffer.byteLength(raw), digest: 'sha256:' + createHash('sha256').update(raw).digest('hex') };
}

interface Entry { scope: string; name: string; expires: number; bytes: number; digest: string; validate: ValidateFunction }
export class McpSchemaCache {
  private entries = new Map<string, Entry>();
  private bytes = 0;
  private compilers = new Map<string, Ajv>();
  readonly ttlMs: number;
  constructor(private options: { ttlMs?: number; maxEntries?: number; maxBytes?: number; now?: () => number } = {}) {
    for (const key of ['ttlMs', 'maxEntries', 'maxBytes'] as const) {
      const value = options[key];
      if (value !== undefined && (!Number.isFinite(value) || value < 1 || !Number.isInteger(value))) throw new McpSchemaError('MCP cache limits must be positive finite integers');
    }
    this.ttlMs = Math.max(1, Math.min(options.ttlMs ?? 300000, 300000));
  }
  private now(): number { return this.options.now?.() ?? performance.now(); }
  private key(scope: string, name: string): string { return JSON.stringify([scope, name]); }
  private remove(key: string): void { const old = this.entries.get(key); if (old) this.bytes -= old.bytes; this.entries.delete(key); }
  private compiler(schema: Json): Ajv {
    const dialect = String(schema.$schema ?? 'https://json-schema.org/draft/2020-12/schema').replace(/#$/, '');
    const versions: Record<string, typeof Ajv> = {
      'https://json-schema.org/draft/2020-12/schema': Ajv2020,
      'https://json-schema.org/draft/2019-09/schema': Ajv2019,
      'https://json-schema.org/draft-07/schema': Ajv,
      'http://json-schema.org/draft-07/schema': Ajv,
    };
    if (!versions[dialect]) throw new McpSchemaError('Unsupported MCP JSON Schema dialect');
    let compiler = this.compilers.get(dialect);
    if (!compiler) {
      compiler = new versions[dialect]({ strict: false, strictNumbers: true, validateFormats: false, allErrors: false, ownProperties: true, inlineRefs: false, code: { regExp: safeRegexp }, logger: false });
      if (dialect === 'https://json-schema.org/draft-07/schema') compiler.addMetaSchema(compiler.getSchema('http://json-schema.org/draft-07/schema')!.schema as Json, dialect);
      this.compilers.set(dialect, compiler);
    }
    return compiler;
  }
  install(scope: string, tools: Json[], replaceScope = false): string[] {
    if (!Array.isArray(tools) || tools.length > 256) throw new McpSchemaError('MCP catalogue exceeds limit');
    const names = new Set<string>(), prepared: Entry[] = [], changed: string[] = [];
    try {
      for (const tool of tools) {
        if (!tool || typeof tool.name !== 'string' || !tool.name || tool.name.length > 2048 || names.has(tool.name)) throw new McpSchemaError('Invalid or duplicate MCP tool definition');
        names.add(tool.name);
        const snap = schemaSnapshot(tool.inputSchema), key = this.key(scope, tool.name), old = this.entries.get(key);
        let validate = old?.digest === snap.digest ? old.validate : undefined;
        if (!validate) { const compiler = this.compiler(snap.schema); try { validate = compiler.compile(snap.schema); } finally { compiler.removeSchema(snap.schema); } }
        prepared.push({ scope, name: tool.name, expires: this.now() + this.ttlMs, bytes: snap.bytes, digest: snap.digest, validate });
        if (old && old.digest !== snap.digest) changed.push(tool.name);
      }
    } catch (error) { if (error instanceof McpSchemaError) throw error; throw new McpSchemaError('Invalid or unsupported MCP inputSchema'); }
    if (replaceScope) this.retainNames(scope, names);
    for (const entry of prepared) { const key = this.key(scope, entry.name); this.remove(key); this.entries.set(key, entry); this.bytes += entry.bytes; }
    const maxEntries = Math.min(this.options.maxEntries ?? 1024, 1024), maxBytes = Math.min(this.options.maxBytes ?? 4194304, 4194304);
    while (this.entries.size > maxEntries || this.bytes > maxBytes) this.remove(this.entries.keys().next().value!);
    return changed;
  }
  available(scope: string, name: string): boolean {
    const key = this.key(scope, name), entry = this.entries.get(key);
    if (entry && entry.expires > this.now()) return true;
    this.remove(key); return false;
  }
  validate(scope: string, name: string, args: Json, expectedDigest?: string): string {
    if (!this.available(scope, name)) throw new McpSchemaUnavailable('Fetch this server’s tools/list catalogue before authorizing a tool call');
    if (!args || Array.isArray(args) || typeof args !== 'object') throw new McpSchemaError('MCP arguments must be an object');
    bounded(args);
    if (Buffer.byteLength(JSON.stringify(args)) > 131072) throw new McpSchemaError('MCP arguments exceed 128 KiB');
    const key = this.key(scope, name), entry = this.entries.get(key)!;
    if (expectedDigest && expectedDigest !== entry.digest) throw new McpSchemaError('MCP inputSchema changed during authorization; discover and retry');
    this.entries.delete(key); this.entries.set(key, entry);
    if (!entry.validate(args)) throw new McpSchemaError('MCP arguments do not satisfy the published inputSchema');
    return entry.digest;
  }
  retainNames(scope: string, names: Set<string>): void { for (const [key, entry] of this.entries) if (entry.scope === scope && !names.has(entry.name)) this.remove(key); }
  invalidate(scope?: string): void { for (const [key, entry] of this.entries) if (scope === undefined || entry.scope === scope) this.remove(key); }
}
