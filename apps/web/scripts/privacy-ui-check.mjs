import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {uiFingerprint} from './ui-fingerprint.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const stamp=new Date().toISOString().replaceAll(':','-');
const out=path.join(root,'artifacts/iterations/privacy/browser',stamp),current=path.join(root,'artifacts/iterations/privacy/current');
await fs.mkdir(out,{recursive:true});await fs.mkdir(current,{recursive:true});
const fingerprint=await uiFingerprint(root);
const wslArgs=['-d','Ubuntu','--cd','/mnt/c/Users/Lenovo/Desktop/密码技术竞赛','--exec','.venv/bin/python'];
// Credentials remain in memory, never in reports or screenshots.
const accounts=JSON.parse(execFileSync('wsl',[...wslArgs,'-c','from services.sessions import ACCESS_PATH; from services.storage import read; import json; print(json.dumps(read(ACCESS_PATH)["accounts"]))'],{encoding:'utf8'}));
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const context=await browser.newContext({viewport:{width:1440,height:900}}),page=await context.newPage();
const errors=[];page.on('pageerror',error=>errors.push(String(error)));
const report={schema:'GRID_V5_BROWSER_VALIDATION_V1',started_at:new Date().toISOString(),command:['node','apps/web/scripts/privacy-ui-check.mjs'],
    versions:{node:process.version,browser:browser.version()},driver_sha256:createHash('sha256').update(await fs.readFile(fileURLToPath(import.meta.url))).digest('hex'),
    ui_fingerprint:fingerprint,screenshots:[],errors,exit_code:1,no_horizontal_overflow:true};
let submissions=0;page.on('request',request=>{if(request.method()==='POST'&&new URL(request.url()).pathname==='/api/response/evaluations')submissions++;});
async function nav(name){await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name,exact:true}).click();}
async function shot(name,width=1440,height=900){await page.setViewportSize({width,height});await page.screenshot({path:path.join(out,name+'.png'),fullPage:true});const dimensions=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));if(dimensions.scroll>dimensions.width+1)throw Error(`Overflow ${name}: ${dimensions.scroll}/${dimensions.width}`);report.screenshots.push(path.relative(root,path.join(out,name+'.png')).replaceAll('\\','/'));}
async function login(subject='grid_operator_A'){await page.getByLabel('登录账户',{exact:true}).selectOption(subject);await page.getByLabel('本机访问口令',{exact:true}).fill(accounts[subject]);await page.getByRole('button',{name:'登录',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);}
async function waitForRun(identifier){for(let i=0;i<600;i++){const response=await page.request.get(`http://127.0.0.1:8580/api/runs/${identifier}`);if(!response.ok())throw Error('Run status HTTP '+response.status());const value=await response.json();if(value.status!=='RUNNING')return value;await new Promise(resolve=>setTimeout(resolve,500));}throw Error('Task timed out');}
try{
  await page.goto('http://127.0.0.1:8580/?v42=1',{waitUntil:'domcontentloaded'});
  await shot('00-scenes');
  await page.getByRole('button',{name:'园区多主体协同',exact:true}).click();await nav('协同任务');
  await expect(page.getByRole('heading',{name:'这次响应，负荷变化了多少',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'运行园区评估',exact:true}).click();await expect(page.getByRole('dialog')).toBeVisible();
  if(submissions!==0)throw Error('Anonymous UI submitted');report.anonymous_login_required=true;
  await login();
  const logout=await page.request.post('http://127.0.0.1:8580/api/session/logout',{data:{}});if(!logout.ok())throw Error('Session invalidation failed');
  const unauthenticated=page.waitForResponse(response=>response.url().endsWith('/api/response/evaluations')&&response.status()===401);
  await page.getByRole('button',{name:'运行园区评估',exact:true}).click();await unauthenticated;await expect(page.getByRole('dialog')).toBeVisible();
  await login();if(submissions!==1)throw Error('Login replayed submission');report.real_401_login_recovery=true;
  await expect(page.getByLabel('评估规模',{exact:true})).toHaveValue('300');
  await page.getByRole('button',{name:'运行园区评估',exact:true}).click();
  await expect(page.locator('.v41-run-strip')).toContainText('已完成',{timeout:240000});
  const identifier=new URL(page.url()).searchParams.get('run');report.run_id=identifier;
  const run=await waitForRun(identifier);if(run.status!=='COMPLETED'||run.protocol_version!==5||run.children.length!==4||run.lab)throw Error('Wrong business evaluation');
  report.core_source_digest=run.core_source_digest;report.protocol_version=5;report.public_real_multi_source=run.logical_source_process_count===3;
  await expect(page.locator('.response-metrics > div')).toHaveCount(4);await expect(page.locator('.response-chart polyline')).toHaveCount(2);
  report.event_curve_points=(await page.locator('.response-chart polyline.observed').getAttribute('points')).split(' ').length;
  if(report.event_curve_points!==4)throw Error('Fabricated curve points');
  await shot('01-response-result');await shot('01-response-mobile',390,844);await shot('01-response-small',320,844);await page.setViewportSize({width:1440,height:900});
  await nav('数据源');await expect(page.getByText('实际mTLS身份已核对',{exact:true})).toHaveCount(3);await expect(page.getByText('读取其他角色秘密的尝试均被拒绝',{exact:true})).toHaveCount(3);report.source_identity_and_isolation_visible=true;
  await nav('密码能力');await expect(page.getByRole('cell',{name:'X25519MLKEM768',exact:true})).toHaveCount(32);await shot('02-crypto-links');
  await nav('回执与审计');await page.getByRole('button',{name:'验证当前回执',exact:true}).click();
  await expect(page.getByText('发布决定与评估指标核验通过',{exact:true})).toBeVisible({timeout:60000});report.business_metrics_recomputed=true;
  const downloadPromise=page.waitForEvent('download');await page.getByRole('link',{name:'下载公开证据',exact:true}).click();const download=await downloadPromise;
  const target=path.join(out,'published-evidence.zip');await download.saveAs(target);report.download_sha256=createHash('sha256').update(await fs.readFile(target)).digest('hex');
  await shot('03-release-proof');
  await page.reload({waitUntil:'domcontentloaded'});await nav('协同任务');await expect(page.locator('.grid-page-state')).toContainText('REPLAY');await expect(page.locator('.response-metrics > div')).toHaveCount(4);report.replay_preserves_source=true;
  await page.getByLabel('评估规模',{exact:true}).selectOption('120');await expect(page.locator('.response-metrics')).toHaveCount(0);report.condition_change_clears_metrics=true;
  const body={dataset_id:'SYN-WEEK-V42',nodes:300,source_count:3,scene_id:'park',region:'A',function:'SUM',day:0,periods:[67],request_nonce:crypto.randomUUID().replaceAll('-',''),fault:'missing'};
  const submitted=await page.request.post('http://127.0.0.1:8580/lab/expansion/collaborations',{data:body,headers:{'Idempotency-Key':crypto.randomUUID()}});
  if(submitted.status()!==202)throw Error('Withheld lab task HTTP '+submitted.status());
  report.withheld_run_id=(await submitted.json()).run_id;const withheld=await waitForRun(report.withheld_run_id);if(withheld.status!=='WITHHELD'||withheld.results.length)throw Error('Incomplete cohort released');
  await page.goto('http://127.0.0.1:8580/?v42=1&run='+report.withheld_run_id,{waitUntil:'domcontentloaded'});await nav('协同任务');await expect(page.getByText('本次结果未发布',{exact:true})).toBeVisible();
  await expect(page.locator('.grid-result-value')).toHaveCount(0);await nav('回执与审计');await page.getByRole('button',{name:'验证当前回执',exact:true}).click();await expect(page.getByText('未发布决定已通过核验',{exact:true})).toBeVisible({timeout:60000});
  await shot('04-withheld');report.withheld_has_no_numeric_view=true;
  const rejected=await page.request.post('http://127.0.0.1:8580/lab/expansion/collaborations',{data:{...body,periods:[66],fault:'invalid_receipt',request_nonce:crypto.randomUUID().replaceAll('-','')},headers:{'Idempotency-Key':crypto.randomUUID()}});
  if(rejected.status()!==202)throw Error('Rejection lab task not accepted');
  report.failed_run_id=(await rejected.json()).run_id;const failed=await waitForRun(report.failed_run_id);
  if(failed.status!=='REJECTED'||failed.results.length)throw Error('Invalid signed receipt not rejected');
  await page.goto('http://127.0.0.1:8580/?v42=1&run='+report.failed_run_id,{waitUntil:'domcontentloaded'});await nav('协同任务');
  await expect(page.locator('.grid-run-strip')).toContainText('已拒绝');await expect(page.locator('.grid-result-value')).toHaveCount(0);report.real_failure_kept=true;await shot('04-real-rejection');
  await nav('数据与曲线');await page.getByLabel('负荷数据',{exact:true}).selectOption('UCI370-WEEK-20130603-V1');await page.getByRole('button',{name:'查看全天曲线',exact:true}).click();await expect(page.getByRole('img',{name:'全天96时段负荷预览曲线'})).toBeVisible();report.daily_preview_points=96;
  await nav('规模实验');await page.getByRole('button',{name:'读取成对实验',exact:true}).click();await expect(page.getByText('尚无正式成对实验记录',{exact:true})).toBeVisible();await shot('05-paired-empty');
  await nav('安全自检');await page.getByRole('button',{name:'执行安全自检',exact:true}).click();await expect(page.getByText('仍有待完善项目',{exact:true})).toBeVisible({timeout:60000});report.open_risks_not_greenwashed=true;
  await page.locator('.v41-account').click();await login('grid_operator_B');
  if((await page.request.get('http://127.0.0.1:8580/api/runs/'+identifier)).status()!==403)throw Error('Cross subject view allowed');report.cross_subject_access_denied=true;
  for(const suffix of ['legacy','v41']){await page.goto(`http://127.0.0.1:8580/?${suffix}=1`,{waitUntil:'domcontentloaded'});await expect(page.getByRole('note')).toContainText('历史研究页面');}
  if(errors.length)throw Error('Browser page errors: '+errors.join(';'));
  if((await uiFingerprint(root)).sha256!==fingerprint.sha256)throw Error('UI changed during checks');
  report.exit_code=0;
}catch(error){report.failure=String(error);}
finally{report.finished_at=new Date().toISOString();for(const secret of Object.values(accounts))if(report.failure)report.failure=report.failure.replaceAll(secret,'[REDACTED]');await fs.writeFile(path.join(out,'validation.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(current,'browser.json'),JSON.stringify(report,null,2));await browser.close();console.log(JSON.stringify({exit_code:report.exit_code,record:path.relative(root,path.join(out,'validation.json')),failure:report.failure,run_id:report.run_id}));}
process.exitCode=report.exit_code;
