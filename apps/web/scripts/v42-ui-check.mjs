import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {uiFingerprint} from './ui-fingerprint.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const stamp=new Date().toISOString().replaceAll(':','-');
const out=path.join(root,'artifacts/iterations/overview-refinement/main-ui',stamp);await fs.mkdir(out,{recursive:true});
const current=path.join(root,'artifacts/iterations/overview-refinement/current');await fs.mkdir(current,{recursive:true});
const before=await uiFingerprint(root);
const accounts=JSON.parse(execFileSync('wsl',['-d','Ubuntu','--cd','/mnt/c/Users/Lenovo/Desktop/密码技术竞赛','--exec','.venv/bin/python','-c','from services.sessions import ACCESS_PATH; from services.storage import read; import json; print(json.dumps(read(ACCESS_PATH)["accounts"]))'],{encoding:'utf8'}));
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const page=await browser.newPage({viewport:{width:1366,height:768}});
const errors=[];page.on('pageerror',value=>errors.push(String(value)));
const report={schema:'GRID_V43_BROWSER_VALIDATION',started_at:new Date().toISOString(),screenshots:[],errors,exit_code:1};
report.command=['node','apps/web/scripts/v42-ui-check.mjs'];report.versions={node:process.version,browser:browser.version()};
let submissions=0;page.on('request',request=>{if(request.method()==='POST'&&new URL(request.url()).pathname.endsWith('/expansion/collaborations'))submissions++;});
async function nav(name){await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name,exact:true}).click();}
async function shot(name,width=1366,height=768){await page.setViewportSize({width,height});await page.screenshot({path:path.join(out,name+'.png'),fullPage:true});const size=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));if(size.scroll>size.width+1)throw Error(`Overflow ${name}: ${size.scroll}/${size.width}`);report.screenshots.push(path.relative(root,path.join(out,`${name}.png`)).replaceAll('\\','/'));}
async function login(subject='grid_operator_A'){await page.getByLabel('登录账户',{exact:true}).selectOption(subject);await page.getByLabel('本机访问口令',{exact:true}).fill(accounts[subject]);await page.getByRole('button',{name:'登录',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.locator('.v41-account')).toHaveAttribute('title',subject);}
try{
  await page.goto('http://127.0.0.1:8580/?v42=1',{waitUntil:'networkidle'});
  await expect(page.getByRole('button',{name:'园区多主体协同',exact:true})).toBeVisible();
  await shot('00-scenes');
  await nav('协同任务');await page.getByRole('button',{name:'运行协同任务',exact:true}).click();await expect(page.getByRole('dialog')).toBeVisible();
  if(submissions!==0)throw Error('Anonymous task submitted');report.anonymous_login_required=true;
  await login();await nav('数据与曲线');
  await expect(page.getByLabel('负荷数据',{exact:true})).toHaveValue('UCI370-WEEK-20130603-V1');
  await page.getByRole('button',{name:'查看全天曲线',exact:true}).click();await expect(page.getByRole('img',{name:'全天96时段负荷预览曲线'})).toBeVisible();
  const count=await page.locator('.v42-curve polyline').getAttribute('points');if(count.trim().split(' ').length!==96)throw Error('Not 96 actual preview points');
  await expect(page.getByText('源数据预览 PREVIEW',{exact:true})).toBeVisible();report.daily_preview_points=96;
  await shot('01-public-day');await shot('01-public-day-mobile',390,844);await page.setViewportSize({width:1366,height:768});
  await nav('场景总览');await page.getByRole('button',{name:'园区多主体协同',exact:true}).click();await nav('协同任务');
  await expect(page.getByLabel('独立数据源',{exact:true})).toHaveValue('3');await page.getByLabel('统计方式',{exact:true}).selectOption('AVG');
  await page.getByRole('button',{name:'运行协同任务',exact:true}).click();await expect(page.locator('.v41-run-strip')).toContainText('已完成',{timeout:120000});
  const runId=new URL(page.url()).searchParams.get('run');report.run_id=runId;
  const run=await(await page.request.get(`http://127.0.0.1:8580/api/runs/${runId}`)).json();
  if(run.oracle_match!==true||run.logical_source_process_count!==3||run.slot_count!==4||run.data_source!=='PUBLIC_OBSERVED_SIMULATED_GROUPS')throw Error('Wrong actual run metadata');
  if(run.protocol_version!==4||!run.uc_result_signatures_verified)throw Error('Managed V4 result signatures were not verified');
  report.core_source_digest=run.core_source_digest;report.public_real_multi_source=true;report.oracle_match=true;report.protocol_version=4;
  await shot('02-results');await shot('02-results-mobile',390,844);await page.setViewportSize({width:1366,height:768});
  await nav('数据源');await expect(page.getByText('实际mTLS身份已核对',{exact:true})).toHaveCount(3);await shot('03-sources');
  await nav('密码能力');await expect(page.getByRole('cell',{name:'X25519MLKEM768',exact:true})).toHaveCount(8);await shot('04-crypto');
  await nav('回执与审计');const verificationResponse=page.waitForResponse(response=>response.url().endsWith('/expansion/verify'),{timeout:30000});await page.getByRole('button',{name:'验证当前回执',exact:true}).click();const verified=await verificationResponse;if(!verified.ok())throw Error('Verification HTTP '+verified.status());await expect(page.getByText('回执签名与关联检查通过',{exact:true})).toBeVisible();await expect(page.getByText('统计端结果声明：签名与内容核对通过',{exact:true})).toBeVisible();report.receipt_source_binding_verified=true;report.uc_result_signature_verified=true;await shot('05-verification');
  await nav('安全自检');await page.getByRole('button',{name:'执行安全自检',exact:true}).click();await expect(page.getByText('统计结果的隐私风险',{exact:true})).toBeVisible({timeout:30000});await expect(page.locator('.grid-check-list').getByText('待进一步论证',{exact:true})).toHaveCount(2);await shot('07-selfcheck');
  for(const name of ['场景总览','数据源','密码能力','回执与审计','规模实验','安全自检']){await nav(name);await shot(`mobile-${name}`,390,844);}await page.setViewportSize({width:1366,height:768});
  await nav('场景总览');await page.locator('.overview-recent>summary').click();if(await page.locator('.grid-history-toggle').count()){await expect(page.locator('.grid-history tbody tr')).toHaveCount(5);await page.locator('.grid-history-toggle').click();if(await page.locator('.grid-history tbody tr').count()<=5)throw Error('Recent history did not expand');await page.locator('.grid-history-toggle').click();await expect(page.locator('.grid-history tbody tr')).toHaveCount(5);report.recent_history_expands_and_collapses=true;}await page.getByRole('button',{name:'查看记录',exact:true}).first().click();await expect(page.getByText('历史回放 REPLAY',{exact:true})).toBeVisible();report.replay_keeps_public_origin=true;
  await nav('协同任务');const previousSubmissions=submissions;await page.request.post('http://127.0.0.1:8580/api/session/logout',{data:{}});await page.getByRole('button',{name:'运行协同任务',exact:true}).click();await expect(page.getByRole('dialog')).toBeVisible();await expect(page.getByRole('status')).toContainText('登录已失效');await login();if(submissions!==previousSubmissions+1)throw Error('Login automatically resubmitted task');report.real_401_login_recovery=true;
  const after=await uiFingerprint(root);if(before.sha256!==after.sha256)throw Error('UI changed during check');report.ui_fingerprint=after;
  if(errors.length)throw Error('Browser errors');report.exit_code=0;
}catch(error){report.failure=String(error);process.exitCode=1;}
finally{report.finished_at=new Date().toISOString();if(report.failure)for(const secret of Object.values(accounts))report.failure=report.failure.replaceAll(secret,'[REDACTED]');await fs.writeFile(path.join(out,'validation.json'),JSON.stringify(report,null,2));await fs.writeFile(path.join(current,'v4-browser.json'),JSON.stringify(report,null,2));await browser.close();console.log(JSON.stringify({exit_code:report.exit_code,record:path.relative(root,path.join(out,'validation.json')),run_id:report.run_id,failure:report.failure}));}
