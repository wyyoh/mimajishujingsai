import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const minutes=Number(process.argv[2]);if(![3,8].includes(minutes))throw new Error('Use 3 or 8 minutes');
const out=path.join(root,'materials/video');await fs.mkdir(out,{recursive:true});
const browser=await chromium.launch({executablePath:process.env.PLAYWRIGHT_EXECUTABLE??'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const context=await browser.newContext({viewport:{width:1366,height:768},recordVideo:{dir:out,size:{width:1366,height:768}},acceptDownloads:true});
const page=await context.newPage(),video=page.video(),started=performance.now(),chapters=[],runs=[],errors=[];
page.on('pageerror',e=>errors.push(String(e)));
async function caption(value){await page.evaluate(value=>{let bar=document.getElementById('recording-caption');if(!bar){bar=document.createElement('div');bar.id='recording-caption';Object.assign(bar.style,{position:'fixed',bottom:'12px',left:'18px',right:'18px',padding:'14px 20px',background:'#18344fed',color:'white',fontSize:'18px',zIndex:'9999',borderRadius:'8px',pointerEvents:'none',fontFamily:'Microsoft YaHei,sans-serif'});document.body.append(bar);}bar.textContent='自动流程彩排（无解说音轨）  '+value;},value);}
async function chapter(title,seconds,action){const at=performance.now();await caption(title);await action();const actionMs=Math.round(performance.now()-at);if(actionMs>seconds*1000)throw new Error('Chapter exceeded its real-time budget: '+title);chapters.push({title,at_ms:Math.round(at-started),budget_seconds:seconds,actual_action_ms:actionMs});await new Promise(r=>setTimeout(r,seconds*1000-actionMs));}
async function nav(label){await page.getByRole('navigation').getByRole('button',{name:new RegExp(label)}).click();await page.evaluate(()=>window.scrollTo(0,0));}
async function runScene(label){await nav('聚合工作台');await page.getByRole('button',{name:label,exact:true}).click();const pending=page.waitForResponse(r=>r.url().endsWith('/lab/runs')&&r.request().method()==='POST');await page.getByRole('button',{name:'运行 SAB 任务',exact:true}).click();const id=(await(await pending).json()).run_id;let record;const deadline=performance.now()+90000;do{record=await(await page.request.get(`http://127.0.0.1:8580/api/runs/${id}`)).json();if(record.status!=='RUNNING')break;await new Promise(r=>setTimeout(r,400));}while(performance.now()<deadline);if(record.status==='RUNNING')throw new Error('Task timeout');await expect(page.locator('.page-heading .badge')).toHaveText({COMPLETED:'已完成',PARTIAL:'部分完成',REJECTED:'未通过'}[record.status]);runs.push(record);return record;}
function normalOK(r,count=40){if(r.status!=='COMPLETED'||!r.oracle_match||!r.results.every(s=>s.counts.accepted===count))throw new Error('Normal set/value assertion failed');}
let normal,exportSha=null;
try{
 await page.goto('http://127.0.0.1:8580/',{waitUntil:'networkidle'});
 await chapter('四角色与安全统计范围；合成负荷、真实密码、真实本机连接。',minutes===8?45:20,async()=>{});
 await page.getByRole('button',{name:'实验入口',exact:true}).click();
 await chapter('真实SAB正常统计；全量120报告、独立集合和值对照。',minutes===8?75:60,async()=>{normal=await runScene('正常统计');normalOK(normal);await nav('验证与报告');await page.getByRole('button',{name:'结果一致性',exact:true}).click();});
 if(minutes===8){
  await chapter('改为居民类别重跑：24目标，内核重新选择，独立对照通过。',45,async()=>{await nav('聚合工作台');await page.getByRole('button',{name:'充电设施',exact:true}).click();normalOK(await runScene('正常统计'),24);await page.locator('.metric-grid').scrollIntoViewIfNeeded();await expect(page.locator('.metric-grid')).toContainText('24');});
  await chapter('报告修改与目标缺报：分别检查完整性和覆盖，缺失不插补。',60,async()=>{await page.getByRole('button',{name:'充电设施',exact:true}).click();const a=await runScene('修改报告');if(a.status!=='PARTIAL'||!a.oracle_match)throw new Error('Modified report assertion');const b=await runScene('20%目标缺报');if(b.status!=='PARTIAL'||!b.oracle_match||!b.results.every(s=>s.counts.accepted===32))throw new Error('Missing report assertion');});
  await chapter('授权和回执签后修改：由真实验证器拒绝，失败仍标REAL。',85,async()=>{for(const label of ['非法授权','非法回执'])if((await runScene(label)).status!=='REJECTED')throw new Error('Invalid object accepted');await expect(page.locator('.mode')).toContainText('REAL');});
  await chapter('不兼容TLS组拒绝；实际双链路组记录可在正常任务中检查。',50,async()=>{if((await runScene('不合规链路')).status!=='REJECTED')throw new Error('Invalid TLS accepted');await nav('验证与报告');await page.getByLabel('选择历史运行').selectOption(normal.run_id);await expect(page.locator('.mode')).toContainText('REPLAY');await caption('正常任务的实际双签与L1/L2组；历史读取明确标REPLAY。');await page.getByRole('button',{name:'签名与链路',exact:true}).click();await page.locator('.report-panel').scrollIntoViewIfNeeded();});
 }else{
  await chapter('实际授权/回执双签与L1/L2混合组；证书身份仍为经典算法。',25,async()=>{await page.getByRole('button',{name:'签名与链路',exact:true}).click();await page.locator('.report-panel').scrollIntoViewIfNeeded();});
  await chapter('后量子回执签后修改：UC拒绝发布，REAL失败保留。',30,async()=>{if((await runScene('非法回执')).status!=='REJECTED')throw new Error('Invalid receipt accepted');await expect(page.locator('.mode')).toContainText('REAL');});
 }
 await chapter('四档已测对照：每档30次；保持原始样本口径，细小差异不作优势。',minutes===8?75:25,async()=>{await nav('验证与报告');await page.getByRole('button',{name:'四组对照',exact:true}).click();await expect(page.locator('.benchmark-row')).toHaveCount(4);await page.locator('.report-panel').scrollIntoViewIfNeeded();});
 await chapter('导出公开证据；策略和报告类别候选识别限制、参数待审。',minutes===8?45:20,async()=>{await page.goto(`http://127.0.0.1:8580/?run=${normal.run_id}`,{waitUntil:'networkidle'});await caption('导出公开证据；策略和报告类别候选识别限制、参数待审。');await nav('验证与报告');const pending=page.waitForEvent('download');await page.getByRole('link',{name:'导出公开证据包',exact:true}).click();const download=await pending;exportSha=createHash('sha256').update(await fs.readFile(await download.path())).digest('hex');await page.getByRole('button',{name:/保护范围/}).first().click();});
 if(errors.length||runs.length!==(minutes===8?7:2)||runs.some(r=>r.core_source_digest!==normal.core_source_digest))throw new Error('Recording provenance assertion');
 const result={schema:'GRID_AUTOMATED_TIMED_REHEARSAL_V1',target_seconds:minutes*60,started_at:new Date(Date.now()-(performance.now()-started)).toISOString(),duration_ms:Math.round(performance.now()-started),chapters,normal_run_id:normal.run_id,param_id:normal.param_id,dataset_digest:normal.dataset_digest,core_source_digest:normal.core_source_digest,recorded_runs:runs.map(r=>({run_id:r.run_id,scenario:r.scenario,status:r.status,started_at:r.started_at,finished_at:r.finished_at,core_source_digest:r.core_source_digest})),export_sha256:exportSha,browser_errors:errors,command:['node','apps/web/scripts/record-rehearsal.mjs',String(minutes)],scope:'automated timed live operation rehearsal with captions, no narration; not a human speaker assessment',exit_code:0};
 await context.close();await video.saveAs(path.join(out,minutes===8?'八分钟自动流程彩排.webm':'三分钟自动流程彩排.webm'));await fs.writeFile(path.join(root,`artifacts/tests/rehearsal_${minutes}min.json`),JSON.stringify(result,null,2));console.log(JSON.stringify(result));
}catch(error){await fs.writeFile(path.join(root,`artifacts/tests/rehearsal_${minutes}min.json`),JSON.stringify({exit_code:1,error:String(error),chapters,scope:'failed automated timed rehearsal'}));throw error;}finally{await browser.close();}
