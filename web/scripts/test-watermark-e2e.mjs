// TEST: compiled production UI, genuine loaded-code exports, real AuthGo
// backend and real Worker. No route mocks, no file uploads; localhost reverse proxy.
import assert from 'node:assert/strict';
import {createServer, request as httpRequest} from 'node:http';
import {access, readFile, mkdir, writeFile} from 'node:fs/promises';
import {resolve, extname, sep, basename} from 'node:path';
import {fileURLToPath} from 'node:url';
const out=resolve(process.env.AUTHGO_E2E_OUT), api=process.env.AUTHGO_E2E_API, token=process.env.AUTHGO_E2E_TOKEN;
assert.ok(token && api.startsWith('http://127.0.0.1:'));
const dist=fileURLToPath(new URL('../dist/',import.meta.url));
try { await access(resolve(dist,'index.html')); }
catch { throw new Error('web/dist/index.html 不存在，请先运行 python3 scripts/test-watermark-e2e.py 生成前端产物'); }
const runtimeHtml=async()=>{
  const html=await readFile(resolve(dist,'index.html'),'utf8');
  return html.replace('</head>','<script id="authgo-runtime" type="application/json">{"admin_path":"/admin"}</script></head>');
};
const cases=JSON.parse(await readFile(resolve(out,'browser-inputs.json'),'utf8'));
const {chromium}=await import(process.env.AUTHGO_PLAYWRIGHT || 'playwright');
const screenshots=resolve(out,'screenshots');await mkdir(screenshots,{recursive:true});
const requests=[],results=[],errors=[],workers=[];
let server,browser;
const persist=()=>Promise.all([
  writeFile(resolve(out,'browser-results.json'),JSON.stringify({mockAPI:false,results,errors,workers,privacy:{capturedAllContextRequests:true,requests:requests.length},screenshots},null,2)),
  writeFile(resolve(out,'browser-network.json'),JSON.stringify({mockAPI:false,authorizationHeadersOmitted:true,requests},null,2)),
]);
try {
  server=createServer(async(req,res)=>{
    if(req.url.startsWith('/api/')){
      // Transparent forwarding to actual backend. No fabricated success/result.
      const forwarded=httpRequest(new URL(req.url,api),{method:req.method,headers:{...req.headers,host:new URL(api).host}},up=>{
        res.writeHead(up.statusCode,up.headers);up.pipe(res);
      });
      forwarded.on('error',e=>{errors.push({kind:'backend-proxy',error:e.code});res.writeHead(502).end();});req.pipe(forwarded);return;
    }
    try {
      const name=decodeURIComponent(new URL(req.url,'http://localhost').pathname);
      let file=resolve(dist,'.'+(name==='/'?'/index.html':name));
      assert.ok(file.startsWith(resolve(dist)+sep));
      let bytes;
      try{bytes=await readFile(file);}catch(e){if(e.code!=='ENOENT'||extname(file))throw e;file=resolve(dist,'index.html');bytes=await readFile(file);}
      res.setHeader('Content-Type',({'.js':'text/javascript','.html':'text/html','.css':'text/css','.svg':'image/svg+xml','.woff2':'font/woff2','.png':'image/png','.ico':'image/x-icon'})[extname(file)]||'application/octet-stream');res.end(extname(file)==='.html'?await runtimeHtml():bytes);
    }catch(e){errors.push({kind:'static-server',message:e.message});res.writeHead(404).end();}
  });
  await new Promise((done,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',done);});
  const origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launch({headless:true,args:['--no-sandbox']});
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  await context.addInitScript(value=>{sessionStorage.setItem('authgo.admin.access',value);},token);
  const allowed=new Set(cases.map(row=>row.watermark));
  const filenames=cases.map(row=>basename(row.file));
  // Canary snippets of actual exports; never stored or sent in the network log.
  const snippets=[];
  for(const row of cases){const blob=await readFile(row.file);if(blob.length>=64)snippets.push(blob.subarray(0,64));}
  context.on('request',request=>{
    const bytes=request.postDataBuffer()||Buffer.alloc(0),url=new URL(request.url());
    if(url.origin!==origin){errors.push({kind:'external-request',url:request.url()});return;}
    const record={method:request.method(),path:url.pathname,query:url.search,body:request.postData()||null,contentType:request.headers()['content-type']||''};requests.push(record);
    if(url.pathname.startsWith('/api/')){
      for(const name of filenames)assert.ok(!request.url().includes(name)&&!bytes.includes(Buffer.from(name)),'export filename transferred');
      for(const part of snippets)assert.ok(!bytes.includes(part),'genuine export contents transferred');
      assert.ok(!/multipart\/form-data|application\/octet-stream/i.test(record.contentType));
      if(bytes.length){
        assert.match(url.pathname,/\/watermark-trace$/,'only watermark endpoint may receive a body');
        const body=JSON.parse(bytes.toString());assert.deepEqual(Object.keys(body),['watermark']);assert.ok(allowed.has(body.watermark));
        assert.equal(bytes.toString(),JSON.stringify({watermark:body.watermark}));
      }
    }
  });
  const page=await context.newPage();page.on('pageerror',e=>errors.push({kind:'pageerror',message:e.message}));page.on('worker',w=>workers.push(w.url()));
  for(const row of cases){
    await page.goto(origin+'/admin/applications/'+row.app_id+'?tab=payload-keys');
    const input=page.locator('.watermark-trace input[type=file]');await input.waitFor({state:'visible'});await assert.doesNotReject(()=>input.waitFor({state:'visible'}));
    // Wait on real tags/network, never force disabled/hidden controls.
    await page.waitForFunction(()=>{const node=globalThis.document.querySelector('.watermark-trace input[type=file]');return node&&!node.disabled;});
    const responsePromise=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/admin/applications/'+row.app_id+'/watermark-trace'&&r.request().method()==='POST');
    await input.setInputFiles(row.file);
    const response=await responsePromise;assert.equal(response.status(),200);
    const reply=await response.json();assert.equal(reply.code,'OK');assert.equal(String(reply.data.license_id),String(row.license_id));assert.equal(reply.data.found,true);assert.equal(Boolean(reply.data.is_trial),row.is_trial);
    await page.getByRole('link',{name:'授权 #'+row.license_id,exact:true}).waitFor({state:'visible'});
    assert.equal(await page.locator('.watermark-trace').getByText('已找到授权来源',{exact:false}).count(),1);
    assert.ok(Number.isInteger(row.expected_consistent_slots)&&Number.isInteger(row.expected_total_slots));
    await page.locator('.watermark-trace').getByText(new RegExp('一致非零槽位\\s+'+row.expected_consistent_slots+'\\s*/\\s*全部槽位\\s+'+row.expected_total_slots)).waitFor({state:'visible'});
    results.push({language:row.language,variant:row.variant,license_id:row.license_id,status:'PASS',file:row.file,is_trial:row.is_trial,consistent_slots:row.expected_consistent_slots,total_slots:row.expected_total_slots});
    if(row.variant.startsWith('runtime.')&&!row.variant.endsWith('.jar')){
      const label=row.language+'-'+row.license_id;
      await page.screenshot({path:resolve(screenshots,label+'-1440.png'),fullPage:true});
    }
    console.log('PASS REAL_BROWSER '+row.language+' '+row.variant+' license='+row.license_id);
    await persist();
  }
  for(const width of [1024,375,320]){
    await page.setViewportSize({width,height:1000});
    assert.ok(await page.evaluate(()=>globalThis.document.documentElement.scrollWidth<=globalThis.innerWidth),'narrow viewport overflow');
    await page.screenshot({path:resolve(screenshots,'real-trace-'+width+'.png'),fullPage:true});
  }
  assert.ok(workers.length>0);assert.deepEqual(errors,[]);assert.equal(requests.filter(row=>row.method==='POST').length,cases.length);
  await context.close();console.log('watermark_REAL_BROWSER_DONE 0 cases='+cases.length+' mockAPI=false');
} catch(e){errors.push({kind:'failure',message:e.message,stack:e.stack});console.error('watermark_REAL_BROWSER_DONE 1 '+e.message);process.exitCode=1;}
finally{await persist();if(browser)await browser.close();if(server?.listening)await new Promise(done=>server.close(done));}
