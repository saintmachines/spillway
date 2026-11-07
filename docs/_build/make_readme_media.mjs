// Renders the README's pictures from the project page itself, docs/index.html: the hero, the leak matrix beside the
// ranked bars, the cost cards and means, the demo, the two stress panels and the four steps, in the page's dark theme. Each picture is
// one region of the page with a 16 px margin of the page's own ground, cut to a card with rounded corners on a
// transparent ground, so it sits on either GitHub theme. The README shows a desktop picture at GitHub's README width
// (838 CSS px in a 1280 px window) and a phone picture at 324, and both are made at 2x. Writes the PNGs and MANIFEST.json
// to docs/assets/readme_page/. Needs Node 18+ and playwright-core with a Chromium build.
//   node docs/_build/make_readme_media.mjs [--only hero,leaks] [--out DIR]
//   env: PLAYWRIGHT_CORE (module path, default playwright-core), CHROMIUM (browser executable)
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
const {chromium} = await import(process.env.PLAYWRIGHT_CORE || 'playwright-core');

const DOCS = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const argv = process.argv.slice(2);
const opt = name => { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : null; };
const OUT = path.resolve(opt('out') || path.join(DOCS, 'assets', 'readme_page'));
const ONLY = opt('only') ? opt('only').split(',') : null;
const WIDTH = {desk: 838, phone: 324}, SCALE = 2, MARGIN = 16, RADIUS = 16;
const FONTS = ['Fraunces', 'IBM Plex Sans', 'IBM Plex Mono'];

// What the pictures never show: the sticky header, the menu, buttons, hints and the hidden table views.
const KEEP_OUT = 'header.nav,.menu-panel,#tip,.swipe-hint,.pager,.tv,.copy,button.copy{display:none!important}*{scroll-behavior:auto!important}main a{text-decoration:none!important;color:inherit!important}';
// sel: the region, or a list whose bounding box is the region. vw: the window width that lays the region out as the README
// shows it. A window widens by what a region would scroll sideways, by at most 200 px. hide: parts left out.
// leaks, results and summary, with their _phone copies, are no longer made. They stay in the output folder for copies of the 0.1.0 README that load them.
const SHOTS = [
  // the footnote it marks (#tm) is left out, so its mark is too
  // the long tile wording, which names the episodes the calls range covers, at every picture width
  {name: 'hero', sel: '#top .hero-grid', vw: {desk: 1100, phone: WIDTH.phone},
   css: '#top .hstats .ts{display:none!important}#top .hstats .tl{display:inline!important}',
   hide: '#top .cta,#top nav.pills,#leaks,#top #tm,#top .evalbox,#top a.fn,#top .byline',
   // the phone's README top: the headline and its sentences over the chart, so the first screen shows the competitors
   phone: '#top .hero-eb{display:none!important}#top .hero-head h1{font-size:30px!important;line-height:1.07!important}#top .lede{font-size:15px!important;line-height:1.45!important;margin:10px 0 0!important}' +
          '#top .hero-grid .proofcard{margin-top:14px!important;padding:14px!important}'},
  {name: 'demo', sel: ['#demo .head', '#demo .vt-note'], vw: {desk: 1100, phone: WIDTH.phone},
   css: '.vt-pick::after{display:none!important}.vt tr.sel .vt-pick{text-decoration:none!important}'},
  {name: 'demo_calls', sel: '#demo-box', vw: {desk: 1100, phone: WIDTH.phone}, css: '#infoRet{display:none!important}', prep: () => { document.getElementById('demo-fold').open = true; }},
  // The README's first picture, the page's leak matrix beside its ranked bars, so one look shows every defense on both.
  {name: 'score', sel: '#rm-score', vw: {desk: 1100, phone: WIDTH.phone},
   prep: () => { const b = document.createElement('div'); b.id = 'rm-score'; b.append(document.querySelector('#leaks'), document.querySelector('#c-util')); document.querySelector('#results .wrap').prepend(b); document.querySelectorAll('#c-util .hb-s').forEach(e => e.remove()); document.querySelector('#c-util .hb').classList.remove('side'); const s = document.querySelector('#c-util .sub'); s.textContent = s.textContent.replace(/\s*The ASR column.*$/, ''); },
   css: '#results .wrap>:not(#rm-score){display:none!important}' +
        '#rm-score{display:grid;grid-template-columns:minmax(0,1.14fr) minmax(0,1fr);gap:16px;align-items:stretch}' +
        '#rm-score #c-util .big,#leaks .lk-u,#leaks .lk-dup{display:none!important}' +
        '#rm-score #leaks{margin:0!important;padding:24px!important;background:var(--surface)!important;grid-template-columns:max-content minmax(0,1fr)!important;grid-template-rows:auto auto 1fr!important;grid-template-areas:"big sub" "mx mx" "note note"!important;align-items:center!important;column-gap:20px!important}' +
        '#rm-score #leaks .lk-top{grid-area:big}#rm-score #leaks .lk-sub{grid-area:sub;max-width:none}#rm-score #leaks .mx{grid-area:mx;justify-self:start;zoom:1.2;overflow:visible}' +
        '#rm-score #leaks .lk-note{grid-area:note;align-self:end;padding:12px 0 0!important;border-left:0!important;border-top:1px solid var(--line)!important}',
   phone: '#rm-score{grid-template-columns:minmax(0,1fr)!important}#rm-score #leaks{padding:16px!important;grid-template-columns:minmax(0,1fr)!important;grid-template-rows:none!important;grid-template-areas:"big" "sub" "mx" "note"!important}#rm-score #leaks .mx{zoom:1}#rm-score #leaks .matrix td.n{padding-left:3px;min-width:0}#rm-score #leaks .matrix th.lks{padding-left:3px}'},
  // Cost as its own block, the two other cards of the page's results band
  {name: 'cost', sel: ['#c-calls', '#c-time'], vw: {desk: 1100, phone: WIDTH.phone},
   css: '#c-util,#c-calls .big,#c-time .big{display:none!important}#c-time h3::first-letter{text-transform:uppercase}#results .charts{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:16px!important;overflow:visible!important}' +
        '#results .charts>*{width:auto!important;min-width:0!important;max-width:none!important;flex:none!important}',
   phone: '#results .charts{grid-template-columns:1fr!important}'},
  {name: 'means', sel: '#results .rs', vw: {desk: 1100, phone: WIDTH.phone}},
  {name: 'rope', sel: '#vs-rope', vw: {desk: WIDTH.desk, phone: WIDTH.phone}},
  {name: 'attacks', sel: '#all-attacks', vw: {desk: WIDTH.desk, phone: WIDTH.phone}},
  {name: 'steps', sel: '#how ol.steps', vw: {desk: 1100, phone: WIDTH.phone},
   phone: '#how ol.steps{display:grid!important;grid-template-columns:1fr!important;gap:12px!important;overflow:visible!important}' +
          '#how ol.steps>*{width:auto!important;min-width:0!important;max-width:none!important;flex:none!important}'},
];

// A picture has no links: the phrases that lead to a table or a script go, with the separator before them, and what stays reads as plain text.
const NO_LINKS = () => {
  const dead = /^(Table of values|Recompute|Reproduce the runs|All four attacks|On the results page|Every cell)/;
  document.querySelectorAll('main a').forEach(a => {
    if (a.getAttribute('href') === '#leaks' && a.closest('.vt-note')) {  // a whole sentence hangs on this link
      if (a.nextSibling && a.nextSibling.nodeType === 3) a.nextSibling.remove();
      a.remove();
      return;
    }
    if (!dead.test(a.textContent.trim())) return;
    const prev = a.previousSibling;
    if (prev && prev.nodeType === 3) prev.textContent = prev.textContent.replace(/[\s\u00a0]*·[\s\u00a0]*$/, ' ');
    if (a.parentElement && a.parentElement.classList.contains('nw') && a.parentElement.textContent.trim().startsWith('·')) a.parentElement.remove();
    else a.remove();
  });
  // A still picture of the demo has nothing to choose
  const eb = document.querySelector('#demo .eyebrow');
  if (eb) eb.textContent = eb.textContent.replace(/^Interactive\s*·\s*/, '');
  const cap = document.querySelector('#demo caption');
  if (cap) cap.childNodes.forEach(n => { if (n.nodeType === 3) n.textContent = n.textContent.replace(/\s*Choose a defense to see its calls\./, ''); });
};

const sha256 = f => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const pngSize = f => { const b = fs.readFileSync(f); return [b.readUInt32BE(16), b.readUInt32BE(20)]; };
function serve() {
  const types = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json',
                 '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.woff': 'font/woff', '.pdf': 'application/pdf'};
  return new Promise(done => {
    const srv = http.createServer((req, res) => {
      let p = decodeURIComponent(new URL(req.url, 'http://local').pathname);
      if (p.endsWith('/')) p += 'index.html';
      const f = path.join(DOCS, path.normalize(p));
      if (!f.startsWith(DOCS + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, {'content-type': types[path.extname(f)] || 'application/octet-stream'});
      fs.createReadStream(f).pipe(res);
    }).listen(0, '127.0.0.1', () => done(srv));
  });
}

// The corners are cut in a blank page, so the page's own content rules never apply to the data URL.
async function roundCorners(ctx, png) {
  const blank = await ctx.newPage();
  const out = await blank.evaluate(async ([b64, r]) => {
    const img = new Image();
    img.src = 'data:image/png;base64,' + b64;
    await img.decode();
    const c = document.createElement('canvas');
    c.width = img.naturalWidth;
    c.height = img.naturalHeight;
    const g = c.getContext('2d');
    g.beginPath();
    g.roundRect(0, 0, c.width, c.height, r);
    g.clip();
    g.drawImage(img, 0, 0);
    return c.toDataURL('image/png').split(',')[1];
  }, [png.toString('base64'), RADIUS * SCALE]);
  await blank.close();
  return Buffer.from(out, 'base64');
}

async function shoot(browser, url, s, kind, vw = s.vw[kind]) {
  const ctx = await browser.newContext({viewport: {width: vw, height: 1000}, deviceScaleFactor: SCALE, colorScheme: 'dark', reducedMotion: 'reduce'});
  const page = await ctx.newPage();
  const errors = [], missing = [];
  page.on('pageerror', e => errors.push(String(e)));
  page.on('response', r => { if (r.status() >= 400) missing.push(r.status() + ' ' + r.url()); });
  await page.goto(url, {waitUntil: 'networkidle', timeout: 90000});
  await page.evaluate(() => document.fonts.ready);
  const fonts = await page.evaluate(F => F.filter(f => !document.fonts.check('16px "' + f + '"')), FONTS);
  if (fonts.length) throw new Error(`${s.name} ${kind}: web fonts not loaded: ${fonts.join(', ')}`);
  await page.evaluate(NO_LINKS);
  if (s.prep) await page.evaluate(s.prep, kind);
  await page.addStyleTag({content: KEEP_OUT + (s.css || '') + (kind === 'phone' && s.phone ? s.phone : '') + (s.hide ? s.hide + '{display:none!important}' : '')});
  await page.waitForTimeout(800);
  const box = await page.evaluate(sel => {
    const els = [].concat(sel).map(q => document.querySelector(q));
    if (!els.every(Boolean)) return null;
    const over = Math.max(0, ...els.flatMap(e => [e, ...e.querySelectorAll('*')]).filter(x => ['auto', 'scroll'].includes(getComputedStyle(x).overflowX))
      .map(x => x.scrollWidth - x.clientWidth));
    const rs = els.map(e => e.getBoundingClientRect());
    const r = {left: Math.min(...rs.map(x => x.left)), top: Math.min(...rs.map(x => x.top)), right: Math.max(...rs.map(x => x.right)), bottom: Math.max(...rs.map(x => x.bottom))};
    return {x: r.left + scrollX, y: r.top + scrollY, width: r.right - r.left, height: r.bottom - r.top, over,
            pageW: document.documentElement.scrollWidth, pageH: document.documentElement.scrollHeight,
            dark: matchMedia('(prefers-color-scheme: dark)').matches && document.documentElement.getAttribute('data-theme') !== 'light'};
  }, kind === 'phone' && s.selPhone ? s.selPhone : s.sel);
  if (!box) throw new Error(`${s.name} ${kind}: ${s.sel} not found`);
  if (!box.dark) throw new Error(`${s.name} ${kind}: the page is not in its dark theme`);
  const side = Math.max(box.over, box.pageW - vw);
  if (side > 1) {
    await ctx.close();
    if (vw - s.vw[kind] >= 200) throw new Error(`${s.name} ${kind}: still scrolls sideways by ${side} px at a ${vw} px window`);
    return shoot(browser, url, s, kind, vw + Math.ceil(side) + 2);
  }
  if (errors.length || missing.length) throw new Error(`${s.name} ${kind}: ${errors[0] || missing[0]}`);
  const x0 = Math.max(0, Math.floor(box.x - MARGIN)), y0 = Math.max(0, Math.floor(box.y - MARGIN));
  const x1 = Math.min(box.pageW, Math.ceil(box.x + box.width + MARGIN)), y1 = Math.min(box.pageH, Math.ceil(box.y + box.height + MARGIN));
  const shot = await page.screenshot({clip: {x: x0, y: y0, width: x1 - x0, height: y1 - y0}, fullPage: true});
  const file = path.join(OUT, s.name + (kind === 'phone' ? '_phone' : '') + '.png');
  fs.writeFileSync(file, await roundCorners(ctx, shot));
  await ctx.close();
  console.log(s.name, kind, 'window', vw, 'picture', (x1 - x0) + 'x' + (y1 - y0));
  return {file, vw};
}

fs.mkdirSync(OUT, {recursive: true});
const srv = await serve();
const url = `http://127.0.0.1:${srv.address().port}/`;
const browser = await chromium.launch(process.env.CHROMIUM ? {executablePath: process.env.CHROMIUM} : {});
const files = {};
try {
  for (const s of SHOTS.filter(s => !ONLY || ONLY.includes(s.name)))
    for (const kind of ['desk', 'phone']) {
      const {file, vw} = await shoot(browser, url, s, kind);
      const [w, h] = pngSize(file);
      files[path.basename(file)] = {sha256: sha256(file), bytes: fs.statSync(file).size, pixels: `${w}x${h}`, window: vw};
    }
} finally {
  await browser.close();
  srv.close();
}
if (ONLY) {
  console.log('--only: MANIFEST.json not written');
} else {
  fs.writeFileSync(path.join(OUT, 'MANIFEST.json'), JSON.stringify({
    about: 'Pictures of the project page for the README, made by docs/_build/make_readme_media.mjs from the input below. Run it again after the page changes.',
    inputs: {'docs/index.html': sha256(path.join(DOCS, 'index.html'))},
    theme: 'dark', css_width: WIDTH, scale: SCALE, margin: MARGIN, radius: RADIUS, files,
  }, null, 2) + '\n');
}
console.log('wrote', Object.keys(files).length, 'pictures to', OUT);
