import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';

export async function uiFingerprint(root) {
  const entries=[];
  const add=async filename=>entries.push([filename.replaceAll('\\','/'),createHash('sha256').update(await fs.readFile(path.join(root,filename))).digest('hex')]);
  const walk=async directory=>{
    let children;
    try { children=await fs.readdir(path.join(root,directory),{withFileTypes:true}); }
    catch(error) { if(error.code==='ENOENT')return; throw error; }
    for(const child of children) {
      const filename=path.join(directory,child.name);
      if(child.isDirectory())await walk(filename);
      else if(child.isFile())await add(filename);
    }
  };
  for(const directory of ['apps/web/src','apps/web/public','apps/web/dist'])await walk(directory);
  for(const name of await fs.readdir(path.join(root,'apps/web'))) {
    if(['package.json','package-lock.json','index.html'].includes(name)||/^tsconfig.*\.json$/.test(name)||/^vite\.config\./.test(name))await add(path.join('apps/web',name));
  }
  for(const name of ['ui-check.mjs','v41-ui-check.mjs','v42-ui-check.mjs','ui-fingerprint.mjs'])await add(path.join('apps/web/scripts',name));
  const files=Object.fromEntries(entries.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0));
  return {schema:'GRID_UI_FINGERPRINT_V1',files,sha256:createHash('sha256').update(JSON.stringify(files)).digest('hex')};
}
