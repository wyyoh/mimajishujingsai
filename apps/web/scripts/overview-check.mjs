import {chromium,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {uiFingerprint} from './ui-fingerprint.mjs';

const filename=fileURLToPath(import.meta.url),root=path.resolve(path.dirname(filename),'../../..');
const stamp=new Date().toISOString().replaceAll(':','-'),out=path.join(root,'artifacts/iterations/overview-refinement/layout',stamp),current=path.join(root,'artifacts/iterations/overview-refinement/current');
await fs.mkdir(out,{recursive:true});await fs.mkdir(current,{recursive:true});
const browser=await chromium.launch({executablePath:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',headless:true});
const page=await browser.newPage({viewport:{width:1366,height:768}});
const errors=[],external=[];let submissions=0;
page.on('pageerror',error=>errors.push(String(error)));
page.on('request',request=>{if(request.method()==='POST')submissions++;if(/^https?:/.test(request.url())&&new URL(request.url()).hostname!=='127.0.0.1')external.push(new URL(request.url()).origin);});
const result={schema:'GRID_OVERVIEW_LAYOUT_VALIDATION_V1',command:['node','apps/web/scripts/overview-check.mjs'],started_at:new Date().toISOString(),versions:{node:process.version,browser:browser.version()},inputs:{authenticated:false,views:[[1920,1080],[1440,900],[1366,768],[1024,768],[768,1024],[390,844],[320,844]]},screenshots:[],errors,exit_code:1};
const before=await uiFingerprint(root);
async function nav(name){await page.getByRole('navigation',{name:'扩展主导航'}).getByRole('button',{name,exact:true}).click();}
async function shot(name,width,height){await page.setViewportSize({width,height});await page.screenshot({path:path.join(out,name+'.png'),fullPage:true,animations:'disabled'});const size=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));if(size.scroll>size.width+1)throw Error(`Overflow ${name}: ${size.scroll}/${size.width}`);for(const button of await page.locator('.overview-scenes>button').all()){const box=await button.boundingBox();if(!box||box.x<0||box.x+box.width>width+1)throw Error(`Scene clipped ${name}`);}result.screenshots.push(path.relative(root,path.join(out,name+'.png')).replaceAll('\\','/'));}
try {
  await page.goto('http://127.0.0.1:8580/?v42=1',{waitUntil:'networkidle'});
  await expect(page.getByRole('heading',{name:'按授权汇总负荷',exact:true})).toBeVisible();
  await expect(page.locator('.overview-recent')).not.toHaveAttribute('open');
  const text=await page.locator('main').innerText();result.visible_chinese_characters=(text.match(/[\u4e00-\u9fff]/g)||[]).length;
  const baseline=JSON.parse(await fs.readFile(path.join(root,'.build/overview-refinement/before/visible-copy.json'),'utf8'));result.previous_visible_chinese_characters=baseline.chinese_characters;
  if(result.visible_chinese_characters>250||result.visible_chinese_characters>=baseline.chinese_characters*.5)throw Error('Overview copy did not become concise');
  for(const [name,count] of [['区域居民负荷',1],['园区多主体协同',3],['充电设施高峰',1]]){await page.getByRole('button',{name,exact:true}).click();await expect(page.getByRole('button',{name,exact:true})).toHaveAttribute('aria-pressed','true');await expect(page.locator('.overview-source-stack>button')).toHaveCount(count);}
  await page.getByRole('button',{name:'园区多主体协同',exact:true}).focus();await page.keyboard.press('Enter');await expect(page.locator('.overview-source-stack>button')).toHaveCount(3);result.scene_switch_and_keyboard=true;
  await page.getByRole('button',{name:'平均值（AVG）',exact:true}).click();await page.getByRole('button',{name:'创建协同任务',exact:true}).click();await expect(page.getByLabel('统计方式',{exact:true})).toHaveValue('AVG');await expect(page.getByLabel('独立数据源',{exact:true})).toHaveValue('3');await expect(page.getByLabel('业务场景',{exact:true})).toHaveValue('park');
  await nav('场景总览');await page.getByRole('button',{name:'报告数（COUNT）',exact:true}).click();await page.getByRole('button',{name:'查看统计结果',exact:true}).click();await expect(page.getByLabel('统计方式',{exact:true})).toHaveValue('COUNT');result.function_selection_reaches_task=true;
  await nav('场景总览');await page.getByRole('button',{name:'查看数据源1',exact:true}).click();await expect(page.locator('.grid-page-heading h2')).toHaveText('数据源');await nav('场景总览');await page.getByRole('button',{name:'查看PFDAM密码能力',exact:true}).click();await expect(page.locator('.grid-page-heading h2')).toHaveText('密码能力');await nav('场景总览');await page.getByRole('button',{name:'查看数据',exact:true}).click();await expect(page.locator('.grid-page-heading h2')).toHaveText('数据与曲线');result.diagram_navigation=true;
  await nav('场景总览');await page.locator('.overview-recent>summary').focus();await page.keyboard.press('Enter');await expect(page.locator('.overview-recent')).toHaveAttribute('open');await expect(page.getByText('登录后查看当前账户的任务。',{exact:true})).toBeVisible();await page.keyboard.press('Enter');await expect(page.locator('.overview-recent')).not.toHaveAttribute('open');result.history_collapsible_by_keyboard=true;
  await page.emulateMedia({reducedMotion:'reduce'});
  for(const scene of ['区域居民负荷','园区多主体协同']){await page.getByRole('button',{name:scene,exact:true}).click();for(const [width,height] of result.inputs.views)await shot(`${scene}-${width}`,width,height);}
  result.reduced_motion=true;result.no_horizontal_overflow=true;result.no_external_dependencies=external.length===0;result.scene_selection_posts_no_task=submissions===0;
  if(submissions||external.length||errors.length)throw Error('Unexpected request, submission, or browser error');
  result.ui_fingerprint=await uiFingerprint(root);if(result.ui_fingerprint.sha256!==before.sha256)throw Error('UI changed during check');result.exit_code=0;
} catch(error){result.failure=String(error);process.exitCode=1;}
finally {result.finished_at=new Date().toISOString();result.driver_sha256=createHash('sha256').update(await fs.readFile(filename)).digest('hex');await fs.writeFile(path.join(out,'validation.json'),JSON.stringify(result,null,2));await fs.writeFile(path.join(current,'overview-browser.json'),JSON.stringify(result,null,2));await browser.close();console.log(JSON.stringify({exit_code:result.exit_code,record:path.relative(root,path.join(out,'validation.json')),failure:result.failure}));}
