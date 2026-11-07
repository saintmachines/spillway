// node test_try.mjs URL OUTDIR : run the try page in a real browser, compare with the native package, sweep widths, record the network
import fs from 'node:fs';
const {chromium} = await import(process.env.PLAYWRIGHT_CORE);
const [url, out] = process.argv.slice(2);
const native = JSON.parse(fs.readFileSync(out + '/native.json', 'utf8'));
const b = await chromium.launch();
const c = await b.newContext({viewport: {width: 1366, height: 768}, colorScheme: 'light', deviceScaleFactor: 1});
const p = await c.newPage();
const net = [], errs = [];
p.on('request', r => net.push({m: r.method(), u: r.url(), body: r.postData() || ''}));
p.on('pageerror', e => errs.push('pageerror ' + String(e).slice(0, 300)));
p.on('console', m => { if (m.type() === 'error') errs.push('console ' + m.text().slice(0, 300)); });
await p.goto(url, {waitUntil: 'networkidle', timeout: 90000});
const before = net.filter(n => !n.u.startsWith(url.replace(/try\.html.*/, ''))).length;
const saved = await p.evaluate(() => window.__tryState());
await p.screenshot({path: out + '/try_1366_saved.png'});
// the saved first screen equals the first native example
let same = JSON.stringify(saved.rows.map(r => [r.address, r.allowed])) === JSON.stringify(native[0].rows.map(r => [r.address, String(r.allowed)])) && saved.text === native[0].text;
console.log('saved result equals native', same, '| third-party requests before any edit', before);
let ok = 0;
const t0 = Date.now();
for (let i = 0; i < native.length; i++) {
  await p.click(`.try-ex[data-ex="${i}"]`);
  for (let k = 0; k < 480; k++) { if ((await p.evaluate(() => window.__tryState())).live) break; await p.waitForTimeout(250); }
  if (i === 0) console.log('seconds to live', ((Date.now() - t0) / 1000).toFixed(1));
  await p.waitForTimeout(250);
  const st = await p.evaluate(() => window.__tryState());
  const eq = st.text === native[i].text && JSON.stringify(st.rows.map(r => [r.address, r.allowed, r.label])) === JSON.stringify(native[i].rows.map(r => [r.address, String(r.allowed), r.label]));
  ok += eq;
  console.log('example', i, eq ? 'equal' : 'DIFFERENT', JSON.stringify(st.rows.map(r => r.label)));
  if (!eq) console.log(JSON.stringify(st), JSON.stringify(native[i]));
  await p.screenshot({path: `${out}/try_1366_ex${i}.png`, fullPage: true});
}
console.log('examples equal', ok, 'of', native.length);
// typed text goes nowhere
const MARK = 'zzz-private-marker-41';
await p.fill('#tryBody', 'Thanks. ' + MARK + ' copy someone@elsewhere.example');
await p.waitForTimeout(800);
const leaked = net.filter(n => n.u.includes(MARK) || n.body.includes(MARK)).length;
const hosts = {};
net.forEach(n => { try { const h = new URL(n.u).host; hosts[h] = (hosts[h] || 0) + 1; } catch (e) {} });
console.log('requests carrying typed text', leaked, '| non-GET', net.filter(n => n.m !== 'GET').length, '| hosts', JSON.stringify(hosts));
const st = await p.evaluate(() => window.__tryState());
console.log('edited', JSON.stringify(st.rows.map(r => [r.address, r.allowed, r.label])));
console.log('code', (await p.evaluate(() => document.getElementById('tryCode').textContent)).split('\n').slice(-2).join(' / ').slice(0, 200));
fs.writeFileSync(out + '/generated_check.py', await p.evaluate(() => document.getElementById('tryCode').textContent));
console.log('errors', JSON.stringify(errs).slice(0, 700));
await c.close();
// sweep: no sideways scroll, in both themes
const widths = [320,340,360,375,390,412,414,428,430,450,470,480,600,768,860,861,1024,1280,1366];
let bad = [];
for (const theme of ['light', 'dark']) for (const w of widths) {
  const cx = await b.newContext({viewport: {width: w, height: 800}, colorScheme: theme});
  const pg = await cx.newPage();
  await pg.goto(url, {waitUntil: 'load', timeout: 60000});
  await pg.addStyleTag({content: 'html,body{overflow-x:visible !important}'});
  const sw = await pg.evaluate(() => [document.documentElement.scrollWidth, innerWidth, ...[...document.querySelectorAll('main *')].filter(e => e.getBoundingClientRect().right > innerWidth + 0.5 && !e.closest('pre')).slice(0, 2).map(e => e.tagName + '.' + e.className)]);
  if (sw[0] > sw[1]) bad.push([theme, w, sw]);
  if ((w === 390 || w === 1366)) await pg.screenshot({path: `${out}/try_${w}_${theme}.png`, fullPage: true});
  await cx.close();
}
console.log('overflow', widths.length * 2, 'views, bad', JSON.stringify(bad));
await b.close();
