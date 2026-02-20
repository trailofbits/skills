# OpenAPI Parsing Notes

## Supported Versions

| Version | Format | Notes |
|---------|--------|-------|
| Swagger 2.0 | JSON, YAML | `host`/`basePath`/`schemes` for base URL; `in: body` and `in: formData` params |
| OpenAPI 3.0 | JSON, YAML | `servers[0].url` for base URL; `requestBody` content types |
| OpenAPI 3.1 | JSON, YAML | Same as 3.0; JSON Schema vocabulary differences not handled |

## $ref Resolution

Internal `$ref` values (e.g. `"#/components/schemas/User"`) are resolved automatically.
Properties from the resolved schema are extracted as body params.

**Not resolved:**
- External file refs (`$ref: "./other.yaml"`) — skipped with a note in the manifest
- URL refs (`$ref: "https://..."`) — skipped with a note
- Circular refs — detected and broken; affected param gets an empty value

## Path Parameter Substitution

Path params with an `example` or `default` value are substituted into the URL:
- `GET /users/{id}` with `id.example: 42` → URL becomes `/users/42`, segment `fuzzable: true`

Path params without any example/default keep their `{name}` placeholder:
- `GET /sessions/{sessionId}` → URL stays `/sessions/{sessionId}`, `fuzzable: true`

**Action required**: If the manifest contains `{placeholder}` segments, ask the user for a
real value. Most APIs return 404 for literal brace-wrapped strings.

## OData-style Paths

Some APIs use OData key syntax, where entity keys appear inside parentheses within a path segment:
```
/entities({entity_id})/children({child_id})
```

These path segments are preserved verbatim — the `{var}` is embedded inside the segment rather
than standing alone, so normal path-variable substitution does not apply. Affected segments are
marked `fuzzable: false`. To fuzz OData key values, reconstruct the full segment (e.g.
`entities(TARGET_VALUE)`) in the corpus rather than targeting just the key.

## Synthetic Example Values

When a schema has no `example` or `default`, type-based fallbacks are used:

| Schema type | Synthetic value |
|-------------|----------------|
| `string` | `""` |
| `integer`, `number` | `0` |
| `boolean` | `false` |
| `array` | `[]` |
| `object` | `{}` |

These produce structurally valid requests but won't exercise meaningful business logic.
Replace synthetic values (especially for required fields) before fuzzing.

## requestBody Content Types

Only `application/json` and `application/x-www-form-urlencoded` are extracted into
`body_params`. Other content types (e.g. `multipart/form-data`, `application/octet-stream`)
produce a note and `body_format: "raw"` with no body params.

## allOf / anyOf / oneOf

Schema composition keywords are not expanded. Only top-level `properties` from the resolved
schema are extracted. If a schema uses `allOf` to combine a `$ref` with additional fields,
only the fields on the top-level schema (after ref resolution) are included.

## Operation Ordering

Operations are listed in document order (path declaration order), then method order within
each path: GET → POST → PUT → PATCH → DELETE → HEAD → OPTIONS → TRACE.
`--entry N` selects by this stable 0-based index. `--operation operationId` is more robust
for large specs where index positions can shift when the spec is updated.
