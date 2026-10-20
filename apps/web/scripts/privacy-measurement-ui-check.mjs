import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {uiFingerprint} from './ui-fingerprint.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const index=JSON.parse(await fs.readFile(path.join(root,'artifacts/iterations/privacy/benchmarks/current.json'),'utf8'));
if(index.status!=='COMPLETED')throw Error('Measurements not ready');
const out=path.join(root,'artifacts/iterations/privacy/browser','measured-'+new Date().toISOString().replaceAll(':','-'));
await fs.mkdir(out,{recursive:true});
const fingerprint=await uiFingerprint(root);
const accounts=JSON.parse(execFileSync('wsl',['-d','Ubuntu','--cd','/mnt/c/Users/Lenovo/Desktop/密码技术竞赛','--exec','.venv/bin/python','-c','from services.sessions import ACCESS_PATH; from services.storage import read; import json; print(json.dumps(read(ACCESS_PATH)["accounts"]))'],{encoding:'utf8'}));
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
page.on('pageerror',error=>errors.push(String(error)));
const record={schema:'GRID_MEASURED_TABLE_BROWSER_CHECK_V1',command:['node','apps/web/scripts/privacy-measurement-ui-check.mjs'],
    started_at:new Date().toISOString(),core_source_digest:index.core_source_digest,versions:{node:process.version,browser:browser.version()},
    ui_fingerprint:fingerprint,driver_sha256:createHash('sha256').update(await fs.readFile(fileURLToPath(import.meta.url))).digest('hex'),
    screenshots:[],exit_code:1,errors};
async function shot(name,width,height){await page.setViewportSize({width,height});const filename=path.join(out,name+'.png');await page.screenshot({path:filename,fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Horizontal page overflow '+name);record.screenshots.push(path.relative(root,filename).replaceAll('\\','/'));}
try{
  await page.goto('http://127.0.0.1:8580/?v42=1',{waitUntil:'domcontentloaded'});
  await page.locator('.v41-account').click();await page.getByLabel('本机访问口令',{exact:true}).fill(accounts.grid_operator_A);await page.getByRole('button',{name:'登录',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name:'规模实验',exact:true}).click();
  await page.getByRole('button',{name:'读取成对实验',exact:true}).click();
  const panel=page.getByRole('region',{name:'发布保护同条件实验'});
  await expect(panel.getByText(index.uniform_source_version===false?'分版本实测':'当前版本实测',{exact:true})).toBeVisible();await expect(panel.locator('tbody tr')).toHaveCount(3);
  const rows=await panel.locator('tbody tr').allTextContents();
  for(const [i,configuration] of index.configurations.entries()){
    if(!rows[i].includes(String(configuration.nodes))||!rows[i].includes((configuration.arms.C1.median_elapsed_ns/1e9).toFixed(2)+'秒'))throw Error('Table does not match measured JSON');
  }
  await expect(page.locator('.grid-page-state')).toContainText('REPLAY');
  const downloadPromise=page.waitForEvent('download');await panel.getByRole('button',{name:'下载实验摘要',exact:true}).click();const download=await downloadPromise;
  const downloaded=path.join(out,'measurement-summary.json');await download.saveAs(downloaded);
  const value=JSON.parse(await fs.readFile(downloaded,'utf8'));
  if(value.current_version_matches!==index.uniform_source_version)throw Error('Code-version label differs');
  for(const [i,row] of value.configurations.entries()){
    const {current_version_matches,...stored}=row;
    if(JSON.stringify(stored)!==JSON.stringify(index.configurations[i]))throw Error('Downloaded summary differs');
    if(current_version_matches!==(row.core_source_digest===index.core_source_digest))throw Error('Per-configuration code label differs');
  }
  const history=await(await page.request.get('http://127.0.0.1:8580/api/expansion/runs')).json();
  const privateIds=[];
  for(const configuration of index.configurations){const raw=JSON.parse(await fs.readFile(path.join(root,configuration.evidence_directory,'raw.json'),'utf8'));privateIds.push(...raw.map(row=>row.run_id));}
  if(history.some(row=>privateIds.includes(row.run_id)))throw Error('Private measurement task entered ordinary history');
  if((await page.request.get('http://127.0.0.1:8580/api/runs/'+privateIds[0])).status()!==403)throw Error('Private authority isolation failed');
  record.private_measurements_hidden_from_business=true;record.download_matches_measurements=true;record.table_matches_measurements=true;
  await shot('paired-desktop',1440,900);await shot('paired-mobile',390,844);await shot('paired-small',320,844);
  if(errors.length||(await uiFingerprint(root)).sha256!==fingerprint.sha256)throw Error('UI errors or source change');record.exit_code=0;
}catch(error){record.failure=String(error);}
finally{for(const secret of Object.values(accounts))if(record.failure)record.failure=record.failure.replaceAll(secret,'[REDACTED]');record.finished_at=new Date().toISOString();await fs.writeFile(path.join(out,'validation.json'),JSON.stringify(record,null,2));await browser.close();console.log(JSON.stringify({exit_code:record.exit_code,record:path.relative(root,path.join(out,'validation.json')),failure:record.failure}));}
process.exitCode=record.exit_code;
