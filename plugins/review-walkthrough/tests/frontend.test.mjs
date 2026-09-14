import assert from 'node:assert/strict';
import { test } from 'node:test';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { data, diff, files, loadFrontend, unusualPath } from './frontend-fixture.mjs';

const { context, evaluate } = loadFrontend();

test('every diff file has a separate container, including deletions and metadata-only changes', () => {
  const rendered = context.renderDiff(diff, files);
  assert.equal((rendered.match(/class="diff-file"/g) || []).length, files.length);
  assert.equal((rendered.match(/<div\b/g) || []).length, (rendered.match(/<\/div>/g) || []).length);
  for (const file of files) assert.ok(rendered.includes(context.escape(file)));
  assert.match(rendered, /Binary files a\/asset.bin and b\/asset.bin differ/);
  assert.match(rendered, /rename to new.txt/);
  assert.match(rendered, /new mode 100755/);
});

test('metadata, no-newline markers, and trailing separators are not commentable lines', () => {
  const rendered = context.renderDiff(diff, files);
  assert.equal((rendered.match(/class="diff-line /g) || []).length, 6);
  assert.match(rendered, /data-file="gone.txt" data-line="1" data-old-line="1" data-new-line=""/);
  assert.match(rendered, /data-line="2" data-old-line="2" data-new-line="2"/);
});

test('line lookup distinguishes both sides and supports shifted context', () => {
  assert.equal(context.lineOnSide({ dataset: { oldLine: '12', newLine: '15' } }, 'LEFT'), 12);
  assert.equal(context.lineOnSide({ dataset: { oldLine: '12', newLine: '15' } }, 'RIGHT'), 15);
  assert.equal(context.lineOnSide({ dataset: { oldLine: '', newLine: '15' } }, 'LEFT'), 0);
});

test('Markdown code blocks preserve whitespace, blank lines, HTML, and formatting markers', () => {
  const code = '  **bold** _em_ ~~strike~~\n\n<sup>x</sup> & `ticks`\n';
  const html = context.markdownToHtml('Before\n\n````js\n' + code + '```\n````\n\nAfter');
  assert.ok(html.includes('<pre><code>' + context.escape(code + '```') + '</code></pre>'));
  assert.ok(!html.includes('<strong>'));
  assert.ok(!html.includes('<sup>'));
  assert.match(html, /^<p>Before<\/p>/);
  assert.match(html, /<p>After<\/p>$/);
});

test('inline code spans preserve Markdown punctuation and variable backtick delimiters', () => {
  const html = context.markdownToHtml('A `` **bold** _em_ <sup>x</sup> `tick` `` and **outside**');
  assert.ok(html.includes('<code>**bold** _em_ &lt;sup&gt;x&lt;/sup&gt; `tick`</code>'));
  assert.ok(html.includes('<strong>outside</strong>'));
  assert.equal(context.markdownToHtml('unclosed `` span'), '<p>unclosed `` span</p>');
  assert.equal(context.markdownToHtml('lone ``'), '<p>lone ``</p>');
});

test('review payload preserves line side, ranges, and literal comment text', () => {
  const comment = {
    file: unusualPath, startLine: 3, endLine: 5, side: 'LEFT', startSide: 'LEFT',
    body: "quotes ' \" `ticks` $(false) \\n and actual\nnewline", stepIndex: 0,
  };
  context.comment = comment;
  evaluate('pendingComments = [comment]');
  assert.deepEqual(JSON.parse(JSON.stringify(context.buildReviewPayload())), {
    commit_id: data.PR_META.head_sha, event: 'COMMENT', body: 'A summary',
    comments: [{ path: comment.file, line: 5, side: 'LEFT', body: comment.body, start_line: 3, start_side: 'LEFT' }],
  });
});

for (const shell of ['/bin/sh', '/bin/bash', '/bin/zsh']) {
  test(`generated gh command passes exact JSON and arguments in ${shell}`, { skip: !existsSync(shell) }, () => {
    const temp = mkdtempSync(path.join(os.tmpdir(), 'walkthrough-command-'));
    try {
      const comment = { file: unusualPath, endLine: 1, side: 'RIGHT', body: "' \" `false` $(false) \\n \\t\n\u2028 ✓" };
      context.comment = comment;
      evaluate('pendingComments = [comment]');
      const command = context.buildGhCommand();
      const result = spawnSync(shell, ['-c', 'gh() { printf "%s\\0" "$@" > "$REVIEW_ARGS"; cat; };\n' + command], {
        encoding: 'utf8', env: { ...process.env, REVIEW_ARGS: path.join(temp, 'args') },
      });
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), JSON.parse(JSON.stringify(context.buildReviewPayload())));
      assert.deepEqual(readFileSync(path.join(temp, 'args'), 'utf8').split('\0'), [
        'api', 'repos/example/repo/pulls/306/reviews', '--method', 'POST', '--input', '-', '',
      ]);
    } finally {
      rmSync(temp, { recursive: true });
    }
  });
}
