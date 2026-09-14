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
  document.getElementById('reviewBody').value = 'Review summary';

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

  check('table captions, cells, and rows remain separate in exported comments', () => {
    const review = REVIEWS[0][0];
    const original = review.body;
    try {
      review.body = '<p>Before</p><table><caption>People</caption><thead><tr><th>Name</th><th>Age</th></tr></thead><tbody><tr><td>Alice</td><td>30</td></tr><tr><td>Bob</td><td>25</td></tr></tbody><tfoot><tr><td>Total</td><td>2</td></tr></tfoot></table><p>After</p>';
      convertReviewToComment(0, 0);
      const body = buildReviewPayload().comments[0].body;
      truth(body.replace(/\n{3,}/g, '\n\n').includes('Before\n\nPeople\n\nName | Age  \nAlice | 30  \nBob | 25  \nTotal | 2\n\nAfter'), body);
      truth(!body.includes('Alice30'), 'Table cells fused');
      equal(htmlToMarkdown('<table><tr><td><code>a|b</code></td><td></td><td>x | y</td></tr></table>'), '`a|b` |  | x \\| y');
    } finally {
      review.body = original;
      pendingComments = [];
      render();
    }
  });

  check('export retains blockquotes and literal Markdown punctuation', () => {
    const fragment = '<blockquote><p>Quoted</p><p>Again</p></blockquote><p># Heading</p><p>- Literal</p><p>1. Literal</p><p><strong>Keep # and | literal.</strong></p>';
    const md = htmlToMarkdown(fragment);
    truth(md.includes('> Quoted\n> \n> Again'), md);
    truth(md.includes('\\# Heading') && md.includes('\\- Literal') && md.includes('1\\. Literal'), md);
    mount.innerHTML = markdownToHtml(md);
    equal(mount.querySelector('blockquote').textContent, 'QuotedAgain');
    equal(mount.querySelector('strong').textContent, 'Keep # and | literal.');
    truth(!mount.querySelector('h1,ol,ul'), 'Literal prose became block markup');
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

  check('converting a finding tracks the correct button through navigation and removal', () => {
    const original = REVIEWS[0].slice();
    try {
      REVIEWS[0].unshift({ severity: 'low', title: 'Unanchored', body: '<p>General note.</p>' });
      render();
      let buttons = document.querySelectorAll('#review .btn-convert-comment');
      buttons[0].click();
      equal(pendingComments.length, 1);
      truth(buttons[0].disabled, 'Clicked finding remains enabled');
      truth(!buttons[1].disabled, 'A different finding was disabled');
      buttons[0].click();
      equal(pendingComments.length, 1);
      render();
      buttons = document.querySelectorAll('#review .btn-convert-comment');
      truth(buttons[0].disabled, 'Rerender lost the converted state');
      convertReviewToComment(0, 1);
      equal(pendingComments.length, 1);
      removeComment(0);
      truth(!document.querySelector('#review .btn-convert-comment').disabled, 'Removing the comment did not reenable its finding');
    } finally {
      REVIEWS[0].splice(0, REVIEWS[0].length, ...original);
      pendingComments = [];
      render();
    }
  });

  check('comment and request-changes reviews require a summary before copying', () => {
    const event = document.getElementById('reviewEvent');
    const summary = document.getElementById('reviewBody');
    const copy = document.getElementById('btnCopyCommand');
    const box = document.getElementById('ghCommandBox');
    pendingComments = [{ file: 'both.txt', endLine: 1, side: 'RIGHT', body: 'Inline finding', stepIndex: 0 }];
    try {
      for (const value of ['COMMENT', 'REQUEST_CHANGES']) {
        event.value = value;
        summary.value = '   ';
        event.dispatchEvent(new Event('change'));
        truth(summary.required && copy.disabled, value + ' accepted a blank summary');
        truth(!box.textContent.includes('gh api'), 'Invalid command remains copyable');
        let rejected = false;
        try { buildGhCommand(); } catch (error) { rejected = /summary/i.test(error.message); }
        truth(rejected, 'Command builder accepted missing summary');
        summary.value = 'Please address the inline finding.';
        summary.dispatchEvent(new Event('input'));
        truth(!copy.disabled && box.textContent.includes('gh api'), 'Valid review cannot be copied');
        equal(buildReviewPayload().body, summary.value);
      }
      event.value = 'APPROVE';
      summary.value = '';
      event.dispatchEvent(new Event('change'));
      truth(!summary.required && !copy.disabled, 'Approval requires an unnecessary summary');
      equal(buildReviewPayload().event, 'APPROVE');
      pendingComments = [];
      renderCommentsTab();
      truth(copy.disabled && !box.textContent, 'Empty review retains a stale command');
    } finally {
      event.value = 'COMMENT';
      summary.value = 'Review summary';
      pendingComments = [];
      render();
    }
  });

  check('navigation shortcuts leave a focused dropdown alone', () => {
    const event = document.getElementById('reviewEvent');
    STEPS.push({ ...STEPS[0], sha: 'step-2' });
    EXPLANATIONS.push(EXPLANATIONS[0]);
    REVIEWS.push([]);
    try {
      event.focus();
      event.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
      equal(current, 0);
      event.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', bubbles: true }));
      equal(current, 0);
      event.blur();
      document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', bubbles: true }));
      equal(current, 1);
    } finally {
      current = 0;
      STEPS.pop();
      EXPLANATIONS.pop();
      REVIEWS.pop();
      render();
    }
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
  assert.ok(checks.length >= 15, 'Browser test discovery returned too few checks');
  for (const check of checks) {
    process.stdout.write(`${check.passed ? 'PASS' : 'FAIL'} ${check.name}\n`);
    if (!check.passed) process.stderr.write(check.error + '\n');
  }
  assert.equal(checks.filter(check => !check.passed).length, 0, 'Browser checks failed');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
