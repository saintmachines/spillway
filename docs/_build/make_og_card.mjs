// Render the code-native social card from og.html. Start a docs server first.
// node docs/_build/make_og_card.mjs http://127.0.0.1:8000/
// PLAYWRIGHT_CORE can point to an installed playwright-core module.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const {chromium}=await import(process.env.PLAYWRIGHT_CORE||'playwright-core');
const docs=path.resolve(path.dirname(new URL(import.meta.url).pathname),'..');
const base=process.argv[2];
if(!base)throw new Error('Pass the docs server base URL, including its trailing slash');
const browser=await chromium.launch({headless:true});
try{
 const page=await browser.newPage({viewport:{width:1200,height:630},deviceScaleFactor:1});
 const errors=[];
 page.on('pageerror',e=>errors.push(String(e)));
 page.on('response',r=>{if(r.status()>=400)errors.push(r.status()+' '+r.url());});
 await page.goto(new URL('_build/og.html',base).href,{waitUntil:'networkidle'});
 await page.evaluate(()=>document.fonts.ready);
 const result=await page.evaluate(()=>({
  missingFonts:['Fraunces','IBM Plex Sans','IBM Plex Mono'].filter(f=>!document.fonts.check('20px "'+f+'"')),
  overflow:[...document.querySelectorAll('.c,h1,.m,.m>div')].filter(e=>e.scrollWidth>e.clientWidth+1).map(e=>e.className||e.tagName),
  bounds:[...document.querySelectorAll('.c>*')].map(e=>{const r=e.getBoundingClientRect();return {right:r.right,bottom:r.bottom};}),
  obsoleteCommand:document.body.textContent.includes('pip install spillway-guard'),
 }))
 if(errors.length||result.missingFonts.length||result.overflow.length||result.obsoleteCommand||result.bounds.some(r=>r.right>1200||r.bottom>630))throw new Error(JSON.stringify({errors,...result}));
 const output=path.join(docs,'assets/og-card.png');
 await page.screenshot({path:output});
 const social=path.join(docs,'assets/social-card-1280x640.png');
 await page.setViewportSize({width:1280,height:640});
 await page.evaluate(()=>document.documentElement.classList.add('social'));
 await page.screenshot({path:social});
 console.log(JSON.stringify({output,width:1200,height:630,sha256:crypto.createHash('sha256').update(fs.readFileSync(output)).digest('hex'),...result},null,2));
}finally{await browser.close();}
