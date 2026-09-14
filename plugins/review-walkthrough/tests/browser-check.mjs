// Run explicitly with a Chromium executable; portable checks use frontend.test.mjs.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { fillTemplate } from './frontend-fixture.mjs';

const chrome = process.argv[2];
assert.ok(chrome, 'Usage: node browser-check.mjs /path/to/chromium');

async function browserChecks() {
  const results = [];
  function check(name, action) {
    try {
      action();
      results.push({ name, passed: true });
    } catch (error) {
      results.push({ name, passed: false, error: String(error.stack || error) });
    }
  }
  function equal(actual, expected) {
    if (actual !== expected) throw new Error(JSON.stringify({ actual, expected }));
  }
  function truth(value, message) {
    if (!value) throw new Error(message);
  }
  const mount = document.createElement('div');
  document.body.appendChild(mount);
  window.testExecuted = false;

  check('malformed active markup stays inert in the browser', () => {
    const payloads = [
      '<img/src=x onerror="window.testExecuted=true">',
      '<svg/onload="window.testExecuted=true"><a href="javascript:window.testExecuted=true">x</a></svg>',
      '<script>window.testExecuted=true</script>',
      '<iframe srcdoc="<script>parent.testExecuted=true</script>"></iframe>',
      '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=window.testExecuted=true>">',
      '<div onclick="window.testExecuted=true" style="background:url(x)">Text</div>',
      '<a href="jav&#x61;script:window.testExecuted=true">unsafe</a>',
      '<a href="java&#9;script:window.testExecuted=true">unsafe</a>',
    ];
    for (const payload of payloads) {
      mount.innerHTML = sanitizeFragment(payload);
      equal(mount.querySelectorAll('img,svg,script,iframe,math,style,object').length, 0);
      for (const node of mount.querySelectorAll('*')) {
        for (const attr of node.attributes) {
          truth(attr.name === 'href' && /^(https?:\/\/|mailto:|#|\/)/i.test(attr.value), 'Unsafe attribute survived');
        }
      }
      const anchor = mount.querySelector('a');
      if (anchor) truth(!anchor.hasAttribute('href'), 'Unsafe URL survived');
    }
  });

  check('safe formatting and links survive while attributes are removed', () => {
    mount.innerHTML = sanitizeFragment('<p class="x"><strong>Bold</strong> and <code>a &lt; b</code> <a href="https://example.com/?a=1&amp;b=2" target="x">link</a></p>');
    equal(mount.querySelector('strong').textContent, 'Bold');
    equal(mount.querySelector('code').textContent, 'a < b');
    equal(mount.querySelector('a').getAttribute('href'), 'https://example.com/?a=1&b=2');
    equal(mount.querySelector('a').attributes.length, 1);
    equal(mount.querySelector('p').attributes.length, 0);
  });

  check('the diff has six sibling file blocks and exactly six commentable lines', () => {
    equal(document.querySelectorAll('#diffPane > .diff-file').length, 6);
    equal(document.querySelectorAll('#diffPane .diff-file .diff-file').length, 0);
    equal(document.querySelectorAll('#diffPane .diff-line').length, 6);
    equal(Array.from(document.querySelectorAll('.diff-file-header')).map(el => el.textContent).join('\0'), STEPS[0].files.join('\0'));
    const gone = Array.from(document.querySelectorAll('.diff-line')).find(el => el.dataset.file === 'gone.txt');
    equal(gone.dataset.side, 'LEFT');
  });

  check('HTML conversion preserves code characters, whitespace, and delimiters', () => {
    const code = '  **bold** _em_ <sup>x</sup> & `tick`\n\n```\n  end';
    const md = htmlToMarkdown('<p>A <code> x ` y ** z </code> and 2<sup>64</sup>.</p><pre><code>' + escape(code) + '</code></pre>');
    truth(md.includes('``  x ` y ** z  ``'), 'Inline code whitespace or delimiter changed');
    truth(md.includes('2<sup>64</sup>'), 'Superscript lost');
    truth(md.includes('````\n' + code + '\n````'), 'Fenced code changed');
    mount.innerHTML = markdownToHtml(md);
    equal(mount.querySelector('pre code').textContent, code);
    equal(mount.querySelector('p code').textContent, ' x ` y ** z ');
    equal(mount.querySelector('sup').textContent, '64');
    equal(mount.querySelector('pre sup'), null);
  });

  check('HTML entities and quoted markup remain literal during conversion', () => {
    const md = htmlToMarkdown('<p>&lt;img/src=x onerror=alert(1)&gt; &amp; &lt;code&gt;</p>');
    mount.innerHTML = markdownToHtml(md);
    equal(mount.querySelectorAll('img,code').length, 0);
    equal(mount.textContent, '<img/src=x onerror=alert(1)> & <code>');
    const list = htmlToMarkdown('<ul><li>One</li><li>Two</li></ul><p>Next<br>line</p>');
    truth(list.includes('- One\n- Two'), 'List items merged');
    truth(list.includes('Next  \nline'), 'Explicit line break lost');
    equal(htmlToMarkdown('<a href="https://example.com/a(b)">link</a>'), '[link](https://example.com/a%28b%29)');
  });

  Element.prototype.scrollIntoView = function() { window.lastScrolled = this; };
  check('finding links safely navigate paths with quotes and shell characters', () => {
    const link = document.querySelectorAll('.review-item-file')[1];
    equal(link.textContent, STEPS[0].files[5] + ':1');
    truth(!link.getAttribute('onclick').includes(STEPS[0].files[5]), 'Path embedded in JavaScript');
    link.click();
    equal(window.lastScrolled.dataset.file, STEPS[0].files[5]);
    equal(window.lastScrolled.dataset.side, 'RIGHT');
  });

  check('deleted-line findings navigate, render, and export on LEFT', () => {
    document.querySelector('.review-item-file').click();
    equal(window.lastScrolled.dataset.side, 'LEFT');
    convertReviewToComment(0, 0);
    equal(pendingComments[0].side, 'LEFT');
    equal(buildReviewPayload().comments[0].side, 'LEFT');
    const overlay = document.querySelector('.inline-user-comment');
    equal(overlay.previousElementSibling.dataset.side, 'LEFT');
    equal(overlay.previousElementSibling.dataset.oldLine, '1');
    const right = document.querySelector('.diff-line.addition');
    truth(!right.classList.contains('has-comment'), 'Right line marked for a deleted-line comment');
    removeComment(0);
    equal(document.querySelectorAll('.inline-user-comment').length, 0);
  });

  check('context anchors resolve using their old-side coordinates', () => {
    pendingComments = [{ file: 'both.txt', endLine: 2, side: 'LEFT', body: 'Context', stepIndex: 0 }];
    renderInlineComments();
    const row = document.querySelector('.inline-user-comment').previousElementSibling;
    equal(row.dataset.oldLine, '2');
    equal(row.dataset.newLine, '2');
    removeComment(0);
  });

  check('line-comment controls retain literal text in exported JSON', () => {
    const button = document.querySelector('.diff-line.deletion .line-add-btn');
    button.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    document.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
    const input = document.querySelector('#commentTextarea');
    const text = "A 'quote' `tick` $(false) \\ and\nnewline";
    input.value = text;
    input.dispatchEvent(new Event('input'));
    document.querySelector('#btnAddComment').click();
    equal(buildReviewPayload().comments[0].body, text);
    equal(buildReviewPayload().comments[0].side, 'LEFT');
    truth(document.getElementById('ghCommandBox').textContent.startsWith("printf '%s\\n' "), 'Missing shell-safe command');
    removeComment(0);
  });

  await new Promise(resolve => setTimeout(resolve, 100));
  check('sanitized fragments never execute after browser events', () => equal(window.testExecuted, false));
  const output = document.createElement('output');
  output.id = 'frontend-results';
  output.textContent = btoa(unescape(encodeURIComponent(JSON.stringify(results))));
  document.body.appendChild(output);
}

const temp = mkdtempSync(path.join(os.tmpdir(), 'walkthrough-browser-'));
try {
  const script = `(${browserChecks.toString()})();`.replaceAll('</script', '<\\/script');
  const html = fillTemplate().replace('</body>', `<script>${script}</script></body>`);
  const file = path.join(temp, 'check.html');
  writeFileSync(file, html);
  const run = spawnSync(chrome, [
    '--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${path.join(temp, 'profile')}`, '--dump-dom', '--virtual-time-budget=1500',
    pathToFileURL(file).href,
  ], { encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(run.status, 0, String(run.error || run.stderr || run.signal));
  const result = /<output id="frontend-results">([^<]+)<\/output>/.exec(run.stdout);
  assert.ok(result, 'Browser did not execute the tests.\n' + run.stderr);
  const checks = JSON.parse(Buffer.from(result[1], 'base64').toString('utf8'));
  assert.ok(checks.length >= 10, 'Browser test discovery returned too few checks');
  for (const check of checks) {
    process.stdout.write(`${check.passed ? 'PASS' : 'FAIL'} ${check.name}\n`);
    if (!check.passed) process.stderr.write(check.error + '\n');
  }
  assert.equal(checks.filter(check => !check.passed).length, 0, 'Browser checks failed');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
