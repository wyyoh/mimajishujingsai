import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {uiFingerprint} from './ui-fingerprint.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const out=path.join(root,'artifacts/iterations/local-standards/browser',new Date().toISOString().replaceAll(':','-'));
await fs.mkdir(out,{recursive:true});
const fingerprint=await uiFingerprint(root);
const accounts=JSON.parse(execFileSync('wsl',['-d','Ubuntu','--cd','/mnt/c/Users/Lenovo/Desktop/密码技术竞赛','--exec',
  'env','GRID_RUNTIME=/home/jazz/.local/share/grid-collaboration/edeee4306203','.venv/bin/python','-c',
  'from services.sessions import ACCESS_PATH;from services.storage import read;import json;print(json.dumps(read(ACCESS_PATH)["accounts"]))'],{encoding:'utf8'}));
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
page.on('pageerror',error=>errors.push(String(error)));
const report={schema:'GRID_LOCAL_STANDARDS_BROWSER_VALIDATION_V1',command:['node','apps/web/scripts/local-standards-ui-check.mjs'],
  started_at:new Date().toISOString(),versions:{node:process.version,browser:browser.version()},
  driver_sha256:createHash('sha256').update(await fs.readFile(fileURLToPath(import.meta.url))).digest('hex'),ui_fingerprint:fingerprint,
  screenshots:[],exit_code:1,errors};
async function nav(name){await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name,exact:true}).click();}
async function shot(name,width,height){await page.setViewportSize({width,height});const filename=path.join(out,name+'.png');await page.screenshot({path:filename,fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Horizontal page overflow '+name);report.screenshots.push(path.relative(root,filename).replaceAll('\\','/'));}
async function login(subject){await page.getByLabel('登录账户',{exact:true}).selectOption(subject);await page.getByLabel('本机访问口令',{exact:true}).fill(accounts[subject]);await page.getByRole('button',{name:'登录',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);}
async function runCheck(){const waiting=page.waitForResponse(response=>response.url().endsWith('/api/self-check')&&response.request().method()==='POST',{timeout:120000});await page.getByRole('button',{name:'执行安全自检',exact:true}).click();const response=await waiting;if(!response.ok())throw Error('Self-check HTTP '+response.status());return response.json();}
try{
  await page.goto('http://127.0.0.1:8580/?v42=1',{waitUntil:'domcontentloaded'});
  if((await page.request.post('http://127.0.0.1:8580/api/self-check',{data:{}})).status()!==401)throw Error('Anonymous self-check allowed');
  await page.locator('.v41-account').click();await login('grid_operator_A');
  await nav('安全自检');
  const prior=await runCheck();
  if(prior.run_id&&prior.version_matches===false){if(prior.functional_overall==='PASS')throw Error('Historical task reported current pass');await expect(page.getByText('任务来自历史代码版本',{exact:true})).toBeVisible();report.stale_evidence_not_current=true;}
  report.initial_selection=prior.selection;
  await fs.writeFile(path.join(out,'initial-selfcheck.json'),JSON.stringify(prior,null,2));
  await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name:'场景总览',exact:true}).click();
  await page.getByRole('button',{name:'园区多主体协同',exact:true}).click();await nav('协同任务');
  await expect(page.getByLabel('评估规模',{exact:true})).toHaveValue('300');
  await page.getByRole('button',{name:'运行园区评估',exact:true}).click();
  await expect(page.locator('.v41-run-strip')).toContainText('已完成',{timeout:300000});
  const identifier=new URL(page.url()).searchParams.get('run');
  const run=await(await page.request.get('http://127.0.0.1:8580/api/runs/'+identifier)).json();
  if(run.status!=='COMPLETED'||run.lab||run.children.length!==4||run.logical_source_process_count!==3)throw Error('Wrong REAL business evaluation');
  report.run_id=identifier;report.core_source_digest=run.core_source_digest;
  await nav('安全自检');const checked=await runCheck();
  if(checked.run_id!==identifier||checked.functional_overall!=='PASS'||checked.counts.functional_pass!==12||!checked.version_matches)throw Error('Current functional self-check did not pass: '+JSON.stringify(checked.checks.filter(row=>row.category==='functional'&&row.status!=='PASS').map(row=>({id:row.id,status:row.status,evidence:row.evidence}))));
  await expect(page.getByRole('heading',{name:'本机功能检查通过',exact:true})).toBeVisible();
  await expect(page.locator('[data-check-status="PASS"]')).toHaveCount(12);
  await expect(page.locator('[data-check-id="confidentiality"]')).toHaveCount(0);
  await expect(page.locator('[data-check-id="standards"]')).toHaveAttribute('data-check-status','PASS');
  await expect(page.getByRole('region',{name:'研究与部署条件'})).toHaveCount(0);
  if(!checked.checks.some(row=>row.id==='confidentiality'&&row.status==='PENDING'))throw Error('Technical research record changed');
  const standard=checked.checks.find(row=>row.id==='standards');if(standard.evidence.third_party_assessment_required!==false||standard.evidence.vector_checks.length!==11)throw Error('Local standard scope not enforced');
  await expect(page.locator('.grid-footer')).toContainText('密文计算 · 联合签名 · 结果核验');
  const visible=await page.locator('body').innerText();if(visible.includes('参数安全')||visible.includes('开放问题'))throw Error('Repeated research warnings still on presentation page');
  report.functional_checks_passed=12;report.technical_research_record_preserved=true;report.local_standard_vectors_checked=11;report.presentation_focus_verified=true;
  const item=page.locator('[data-check-id="integrity"]');await item.getByText('检查范围与记录',{exact:true}).click();await item.getByText('查看验证字段',{exact:true}).click();
  await expect(item.locator('pre')).toContainText('"window_count": 16');
  await item.getByText('检查范围与记录',{exact:true}).click();
  const downloading=page.waitForEvent('download');await page.getByRole('button',{name:'下载自检记录',exact:true}).click();const download=await downloading;
  const target=path.join(out,'downloaded-selfcheck.json');await download.saveAs(target);
  if(JSON.stringify(JSON.parse(await fs.readFile(target,'utf8')))!==JSON.stringify(checked))throw Error('Downloaded report differs');
  report.download_matches_checked_response=true;
  await shot('selfcheck-desktop',1440,900);await shot('selfcheck-mobile',390,844);await shot('selfcheck-small',320,844);
  await page.setViewportSize({width:1440,height:900});
  await page.goto('http://127.0.0.1:8580/?v42=1',{waitUntil:'domcontentloaded'});await nav('安全自检');
  const automatic=await runCheck();
  if(automatic.selection!=='LATEST_AUTHORIZED'||automatic.run_id!==identifier||automatic.functional_overall!=='PASS')throw Error('Automatic authorized current evidence selection failed');
  report.automatic_current_selection_verified=true;
  await page.locator('.v41-account').click();await login('grid_operator_B');
  if((await page.request.post('http://127.0.0.1:8580/api/self-check',{data:{run_id:identifier}})).status()!==403)throw Error('Cross-subject evidence read allowed');
  report.cross_subject_access_denied=true;
  if(errors.length||(await uiFingerprint(root)).sha256!==fingerprint.sha256)throw Error('Page errors or UI changed during check');
  report.exit_code=0;
}catch(error){report.failure=String(error);}
finally{
  for(const secret of Object.values(accounts))if(report.failure)report.failure=report.failure.replaceAll(secret,'[REDACTED]');
  report.finished_at=new Date().toISOString();await fs.writeFile(path.join(out,'validation.json'),JSON.stringify(report,null,2));
  await browser.close();console.log(JSON.stringify({exit_code:report.exit_code,record:path.relative(root,path.join(out,'validation.json')),run_id:report.run_id,failure:report.failure}));
}
process.exitCode=report.exit_code;
