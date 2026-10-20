import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {uiFingerprint} from './ui-fingerprint.mjs';
const filename=fileURLToPath(import.meta.url),root=path.resolve(path.dirname(filename),'../../..');
const stamp=new Date().toISOString().replaceAll(':','-'),out=path.join(root,'artifacts/iterations/frontend-refresh/scale-ui',stamp);await fs.mkdir(out,{recursive:true});
const accounts=JSON.parse(execFileSync('wsl',['-d','Ubuntu','--cd','/mnt/c/Users/Lenovo/Desktop/密码技术竞赛','--exec','.venv/bin/python','-c','from services.sessions import ACCESS_PATH; from services.storage import read; import json; print(json.dumps(read(ACCESS_PATH)["accounts"]))'],{encoding:'utf8'}));
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});const page=await browser.newPage({viewport:{width:1366,height:768}});
const errors=[];page.on('pageerror',value=>errors.push(String(value)));
const report={schema:'GRID_V42_SCALE_BROWSER',started_at:new Date().toISOString(),exit_code:1,screenshots:[],errors};
report.command=['node','apps/web/scripts/v42-scale-check.mjs'];report.versions={node:process.version,browser:browser.version()};
try{
  const before=await uiFingerprint(root);
  await page.goto('http://127.0.0.1:8580/?v42=1',{waitUntil:'networkidle'});
  await page.locator('.v41-account').click();await page.getByLabel('登录账户',{exact:true}).selectOption('grid_operator_A');await page.getByLabel('本机访问口令',{exact:true}).fill(accounts.grid_operator_A);await page.getByRole('button',{name:'登录',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name:'规模实验',exact:true}).click();
  await page.getByRole('button',{name:'读取规模实验',exact:true}).click();await expect(page.getByRole('img',{name:'节点规模与任务耗时',exact:true})).toBeVisible();
  await expect(page.getByText('合成负荷规模实验',{exact:true})).toBeVisible();
  await expect(page.getByText('历史实验记录 REPLAY',{exact:true})).toBeVisible();
  const summary=await(await page.request.get('http://127.0.0.1:8580/lab/expansion/benchmarks')).json();
  if(typeof summary.current_version_matches!=='boolean'||summary.status!=='COMPLETED'||summary.unique_formal_samples!==30||summary.rows.length!==7)throw Error('Incomplete historical series');
  if(summary.rows.some(row=>row.failures!==0||row.samples!==5))throw Error('Wrong measurement counts');
  await expect(page.getByText(summary.current_version_matches?'当前版本实测':'历史版本实测',{exact:true})).toBeVisible();
  await expect(page.locator('tbody tr')).toHaveCount(7);
  for(const [axis,label] of [['nodes','节点规模与任务耗时'],['sources','数据源数量与任务耗时']]){
    const rows=summary.rows.filter(row=>row.axis===axis).sort((a,b)=>axis==='nodes'?a.nodes-b.nodes:a.source_count-b.source_count);
    const points=(await page.getByRole('img',{name:label,exact:true}).locator('polyline').getAttribute('points')).split(' ').map(value=>value.split(',').map(Number));
    const maximum=Math.max(...rows.map(row=>row.max_elapsed_ns),1),maxX=Math.max(...rows.map(row=>axis==='nodes'?row.nodes:row.source_count));
    if(points.length!==rows.length)throw Error('Wrong chart sample count');
    rows.forEach((row,i)=>{const x=60+(axis==='nodes'?row.nodes:row.source_count)/maxX*680,y=210-row.median_elapsed_ns/maximum*175;if(Math.abs(points[i][0]-x)>1e-8||Math.abs(points[i][1]-y)>1e-8)throw Error('Chart differs from actual summary');});
  }
  const event=page.waitForEvent('download');await page.getByRole('button',{name:'下载规模记录',exact:true}).click();const item=await event;const stream=await item.createReadStream();const chunks=[];for await(const chunk of stream)chunks.push(chunk);const downloaded=JSON.parse(Buffer.concat(chunks).toString());
  if(downloaded.core_source_digest!==summary.core_source_digest||JSON.stringify(downloaded.rows)!==JSON.stringify(summary.rows))throw Error('Downloaded measurement differs');
  for(const [width,height] of [[1366,768],[390,844]]){await page.setViewportSize({width,height});await page.screenshot({path:path.join(out,`scale-${width}.png`),fullPage:true});const size=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));if(size.scroll>size.width+1)throw Error('Horizontal overflow');report.screenshots.push(`artifacts/iterations/frontend-refresh/scale-ui/${stamp}/scale-${width}.png`);}
  const after=await uiFingerprint(root);if(before.sha256!==after.sha256)throw Error('UI changed');
  report.ui_fingerprint=after;report.core_source_digest=summary.core_source_digest;report.series=summary.series;report.current_version_matches=summary.current_version_matches;report.unique_formal_samples=30;report.exact_chart_values=true;report.download_matches=true;report.no_horizontal_overflow=true;report.synthetic_scale_origin_explicit=true;report.history_mode_explicit=true;
  if(errors.length)throw Error('Browser errors');report.exit_code=0;
}catch(error){report.failure=String(error);process.exitCode=1;}
finally{report.finished_at=new Date().toISOString();report.driver_sha256=createHash('sha256').update(await fs.readFile(filename)).digest('hex');await fs.writeFile(path.join(out,'validation.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(root,'artifacts/iterations/frontend-refresh/current/scale-browser.json'),JSON.stringify(report,null,2));await browser.close();console.log(JSON.stringify({exit_code:report.exit_code,series:report.series,failure:report.failure}));}
