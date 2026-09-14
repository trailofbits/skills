import { readFileSync } from 'node:fs';
import vm from 'node:vm';

export const template = readFileSync(new URL('../skills/review-walkthrough/template.html', import.meta.url), 'utf8');
export const unusualPath = "src/o'\\\"`$(false)\nname.txt";
export const diff = [
  'diff --git a/both.txt b/both.txt',
  'index 1111111..2222222 100644',
  '--- a/both.txt',
  '+++ b/both.txt',
  '@@ -1,2 +1,2 @@',
  '-old',
  '+new',
  ' same',
  '\\ No newline at end of file',
  'diff --git a/gone.txt b/gone.txt',
  'deleted file mode 100644',
  '--- a/gone.txt',
  '+++ /dev/null',
  '@@ -1 +0,0 @@',
  '-gone',
  'diff --git a/asset.bin b/asset.bin',
  'Binary files a/asset.bin and b/asset.bin differ',
  'diff --git a/old.txt b/new.txt',
  'similarity index 100%',
  'rename from old.txt',
  'rename to new.txt',
  'diff --git a/mode.txt b/mode.txt',
  'old mode 100644',
  'new mode 100755',
  'diff --git a/quoted b/quoted',
  '--- a/quoted',
  '+++ b/quoted',
  '@@ -1 +1 @@',
  '-before',
  '+after',
  '',
].join('\n');
export const files = ['both.txt', 'gone.txt', 'asset.bin', 'new.txt', 'mode.txt', unusualPath];
export const data = {
  STEPS: [{ sha: 'step-1', message: 'Review changes', files, diff }],
  EXPLANATIONS: ['<p>Inspect <code>literal_code</code>.</p>'],
  REVIEWS: [[
    { title: 'Deleted line', severity: 'medium', file: 'both.txt', line: 1, side: 'LEFT', body: '<p>Keep <code>old</code>.</p>' },
    { title: 'Quoted path', severity: 'low', file: unusualPath, line: 1, side: 'RIGHT', body: '<p>Inspect the path.</p>' },
  ]],
  PR_META: { owner: 'example', repo: 'repo', pr_number: 306, head_sha: 'a'.repeat(40) },
};

export function fillTemplate(values = data) {
  return template.replace(/(STEPS|EXPLANATIONS|REVIEWS|PR_META)_PLACEHOLDER/g,
    (_, key) => JSON.stringify(values[key]).replaceAll('<', '\\u003c'))
    .replaceAll('TITLE_PLACEHOLDER', 'Review fixture');
}

// Pure functions run unchanged. DOM behavior is exercised in browser-check.mjs.
export function loadFrontend(values = data) {
  const html = fillTemplate(values);
  const script = html.slice(html.indexOf('<script>') + 8, html.lastIndexOf('</script>'));
  const context = vm.createContext({
    document: {
      getElementById: id => ({ value: id === 'reviewEvent' ? 'COMMENT' : 'A summary' }),
    },
  });
  vm.runInContext(script.slice(0, script.indexOf("var diffPane = document.getElementById")), context);
  return { context, evaluate: expression => vm.runInContext(expression, context) };
}
