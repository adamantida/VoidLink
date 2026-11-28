#!/usr/bin/env node
// Проверка относительных ссылок и якорей в README.md и docs/**/*.md.
// Запуск: node .github/scripts/check-docs-links.mjs
import fs from 'fs';
import path from 'path';

const ROOT = process.cwd();
const START = [path.join(ROOT, 'README.md')];

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith('.md')) out.push(p);
  }
  return out;
}

const files = [...START, ...walk(path.join(ROOT, 'docs'))];
const slugCache = new Map();

function slugify(t) {
  return t.toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/\s/g, '-');
}

function anchorsOf(file) {
  if (slugCache.has(file)) return slugCache.get(file);
  const set = new Set();
  const seen = {};
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = /^#{1,6}\s+(.*?)\s*$/.exec(line);
    if (!m) continue;
    let s = slugify(m[1]);
    const n = seen[s] || 0;
    seen[s] = n + 1;
    if (n) s = s + '-' + n;
    set.add(s);
  }
  slugCache.set(file, set);
  return set;
}

let checked = 0;
let problems = 0;

function checkAnchor(file, target, anchor, label) {
  checked++;
  if (!fs.existsSync(target)) {
    console.log('MISSING  ' + label);
    problems++;
    return;
  }
  if (!anchor) return;
  const a = decodeURIComponent(anchor);
  if (!anchorsOf(target).has(a)) {
    console.log('ANCHOR   ' + label);
    problems++;
  }
}

for (const file of files) {
  const rel = path.relative(ROOT, file).split(path.sep).join('/');
  const text = fs.readFileSync(file, 'utf8');
  const cross = /\]\(([^)\s]+\.md)(#[^)\s]+)?\)/g;
  let m;
  while ((m = cross.exec(text))) {
    if (/^https?:/.test(m[1])) continue;
    const target = path.resolve(path.dirname(file), m[1]);
    checkAnchor(file, target, m[2] ? m[2].slice(1) : '', rel + ' -> ' + m[1] + (m[2] || ''));
  }
  const inner = /\]\((#[^)\s]+)\)/g;
  while ((m = inner.exec(text))) {
    checkAnchor(file, file, m[1].slice(1), rel + ' -> ' + m[1]);
  }
}

console.log('checked ' + checked + ' link(s), problems ' + problems);
process.exit(problems === 0 ? 0 : 1);
