import fs from 'node:fs'
import vm from 'node:vm'

export function loadFunction(path, name) {
  const source = fs.readFileSync(path, 'utf8')
  const marker = `function ${name}(`
  const start = source.indexOf(marker)
  if (start < 0) throw new Error(`function not found: ${name}`)
  const brace = source.indexOf('{', start)
  let depth = 0
  let quote = null
  let escaped = false
  for (let index = brace; index < source.length; index += 1) {
    const char = source[index]
    if (quote) {
      if (escaped) escaped = false
      else if (char === '\\') escaped = true
      else if (char === quote) quote = null
      continue
    }
    if (char === "'" || char === '"' || char === '`') {
      quote = char
      continue
    }
    if (char === '{') depth += 1
    if (char === '}') {
      depth -= 1
      if (depth === 0) {
        const body = source.slice(start, index + 1)
        return vm.runInNewContext(`(${body})`)
      }
    }
  }
  throw new Error(`unterminated function: ${name}`)
}
