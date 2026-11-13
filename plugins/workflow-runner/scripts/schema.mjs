import { RunnerError } from './errors.mjs';

// The JSON Schema subset the repository's workflows use, which is also the subset
// Codex strict structured output accepts. Anything else fails before dispatch
// rather than being silently simplified.
const annotations = new Set(['description', 'title', 'default', '$comment', 'examples']);
const supported = new Set(['type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const', 'anyOf',
  'minimum', 'maximum', 'minItems', 'maxItems', 'minLength', 'maxLength', 'pattern']);
const kind = value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
const schemaError = message => new RunnerError('SCHEMA_CONFIG', message);

export function checkSchema(schema) {
  if (!schema || kind(schema) !== 'object' || schema.type !== 'object' || kind(schema.properties) !== 'object') {
    throw schemaError('A workflow schema needs {type: "object", properties: {...}} at its root');
  }
  strictSchema(schema);
}

// Codex strict output requires every property and forbids extra ones. Optional
// properties become nullable required ones here, and restoreOptional removes
// the placeholder nulls before the workflow sees the value.
export function strictSchema(original) {
  if (!original || kind(original) !== 'object') throw schemaError('Expected a JSON schema object');
  for (const key of Object.keys(original)) {
    if (!supported.has(key) && !annotations.has(key)) throw schemaError(`Unsupported schema keyword: ${key}`);
  }
  const schema = structuredClone(original);
  if (!schema.type && schema.enum) schema.type = [...new Set(schema.enum.map(kind))];
  if (schema.const !== undefined && !schema.type) schema.type = kind(schema.const);
  if (schema.anyOf) schema.anyOf = schema.anyOf.map(strictSchema);
  if (schema.type === 'object' || schema.properties) {
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
      throw schemaError('Map-shaped object schemas are unsupported; use an array of key/value records');
    }
    schema.type = Array.isArray(schema.type) && schema.type.includes('null') ? ['object', 'null'] : 'object';
    const required = new Set(schema.required ?? []);
    const properties = schema.properties ?? {};
    for (const key of required) if (!Object.hasOwn(properties, key)) throw schemaError(`Required property is not defined: ${key}`);
    schema.properties = Object.fromEntries(Object.entries(properties).map(([key, value]) => {
      const child = strictSchema(value);
      return [key, required.has(key) || permitsNull(value) ? child : { anyOf: [child, { type: 'null' }] }];
    }));
    schema.required = Object.keys(properties);
    schema.additionalProperties = false;
  }
  if (schema.items) schema.items = strictSchema(schema.items);
  return schema;
}

function permitsNull(schema) {
  return schema.type === 'null' || (Array.isArray(schema.type) && schema.type.includes('null'))
    || schema.enum?.includes(null) || schema.anyOf?.some(permitsNull);
}

export function restoreOptional(value, schema) {
  if (schema.anyOf) {
    // The first branch the restored value satisfies is the one the model filled in.
    for (const branch of schema.anyOf) {
      const restored = restoreOptional(value, branch);
      try { validate(restored, branch); return restored; } catch { /* try the next branch */ }
    }
    return value;
  }
  if (Array.isArray(value) && schema.items) return value.map(item => restoreOptional(item, schema.items));
  if (value && kind(value) === 'object' && schema.properties) {
    return Object.fromEntries(Object.entries(value).flatMap(([key, child]) => {
      const property = schema.properties[key];
      if (property && child === null && !(schema.required ?? []).includes(key) && !permitsNull(property)) return [];
      return [[key, property ? restoreOptional(child, property) : child]];
    }));
  }
  return value;
}

export function validate(value, schema, location = '$') {
  const fail = message => { throw new RunnerError('SCHEMA', `Structured result invalid at ${location}: ${message}`); };
  if (schema.anyOf && !schema.anyOf.some(branch => { try { validate(value, branch, location); return true; } catch { return false; } })) {
    fail('no anyOf branch matched');
  }
  const types = schema.type === undefined ? [] : [].concat(schema.type);
  const matches = type => type === 'integer' ? Number.isInteger(value)
    : type === 'number' ? typeof value === 'number' && Number.isFinite(value) : kind(value) === type;
  if (types.length && !types.some(matches)) fail(`expected ${types.join('|')}, got ${kind(value)}`);
  if (schema.enum && !schema.enum.some(item => JSON.stringify(item) === JSON.stringify(value))) fail('value is outside enum');
  if (Object.hasOwn(schema, 'const') && JSON.stringify(value) !== JSON.stringify(schema.const)) fail('const mismatch');
  if (value && kind(value) === 'object') {
    for (const key of schema.required ?? []) if (!Object.hasOwn(value, key)) fail(`missing ${key}`);
    for (const [key, item] of Object.entries(value)) {
      if (schema.properties && Object.hasOwn(schema.properties, key)) validate(item, schema.properties[key], `${location}.${key}`);
      else if (schema.additionalProperties === false) fail(`unexpected property ${key}`);
    }
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) fail('too few items');
    if (schema.maxItems !== undefined && value.length > schema.maxItems) fail('too many items');
    if (schema.items) value.forEach((item, index) => validate(item, schema.items, `${location}[${index}]`));
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) fail('below minimum');
    if (schema.maximum !== undefined && value > schema.maximum) fail('above maximum');
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && [...value].length < schema.minLength) fail('too short');
    if (schema.maxLength !== undefined && [...value].length > schema.maxLength) fail('too long');
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) fail('pattern mismatch');
  }
  return value;
}

// For backends without native structured output: the whole reply, or one
// enclosing ```json fence, must be the JSON value. Surrounding prose is rejected.
export function parseStructured(text) {
  const trimmed = text.trim();
  const fenced = trimmed.match(/^```(?:json)?\s*\n([\s\S]*?)\n```$/);
  try { return JSON.parse(fenced ? fenced[1] : trimmed); }
  catch { throw new RunnerError('SCHEMA', 'Worker reply is not a JSON value'); }
}
