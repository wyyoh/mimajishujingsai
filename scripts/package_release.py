"""Build a local review candidate using explicit allowlists. No upload or private runtime copy."""
import hashlib
import json
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services.initialization import ROOT, RUNTIME
from services.versioning import source_version
from services.evidence import PUBLIC_FILES, export_public, verify_export
from services.release import check
from services.storage import read, write
from scripts.verify_acceptance_provenance import executions, references, verify as verify_provenance


def main():
    review=check()
    assert review['engineering_checks_ready'],review
    final_review=read(ROOT/'artifacts/tests/final_review.json')
    assert final_review['exit_code']==0 and final_review['core_source_digest']==source_version()['core_source_digest']
    current_materials={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'materials').rglob('*') if p.is_file()}
    assert current_materials==final_review['materials_sha256'],'Materials changed after final review'
    provenance_result = verify_provenance(ROOT)
    write(ROOT/'artifacts/tests/acceptance_provenance_verification.json',provenance_result)
    acceptance = read(ROOT/'artifacts/tests/acceptance_results.json')
    test_executions = executions(acceptance)
    consumed_references = references(test_executions)
    assert all(Path(name).name in (*PUBLIC_FILES,'oracle_summary.json') for name,expected in consumed_references if name.startswith('artifacts/runs/'))
    video=read(ROOT/'artifacts/tests/video_recording.json')
    assert video['exit_code']==0 and video['duration_ms']>=300000
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    destination=ROOT/'release'/f'grid-platform-0.1.0-candidate-{stamp}'
    assert not destination.exists()
    software=destination/'software';software.mkdir(parents=True)
    def copy(source,target):
        source=Path(source);target=Path(target)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
    for folder in ('services','native','scripts','tests','shared','contracts'):
        shutil.copytree(ROOT/folder,software/folder,ignore=shutil.ignore_patterns('__pycache__','.pytest_cache','history','*.pyc'))
    for name in ('USER_GUIDE.md','DESIGN_REPORT.md','THREAT_MODEL.md','CONTRIBUTIONS.md','CRYPTO_REVIEW.md','CRYPTO_APPLICATION_ASSESSMENT.md','REFERENCE37_REVIEW.md','PROTOCOL_FINDINGS.md','claims_registry.json','STATUS.md','NEXT.md','COMPLETION_AUDIT.md','BENCHMARK_METHOD.md','BENCHMARK_RESULTS.md','THIRD_PARTY_NOTICES.md','DECISIONS.md','DEMO_SCRIPT.md','competition_requirements.md'):
        copy(ROOT/'docs'/name,software/'docs'/name)
    write(software/'docs/REVIEW_DECISION.json',{'scope':'PFDAM is the team\'s own scheme and its paper author is a team member. The paper explains prior team research; the work presents the team scheme and application system. Preserve documented security limitations and standard-library attribution; no external submission authorized.','status':'USER_CONFIRMED','reference37_fallback':read(ROOT/'docs/REVIEW_DECISION.json')['reference37_fallback']})
    for name in ('README.md','requirements.txt','requirements.lock.txt','pytest.ini','AGENTS.md'):
        copy(ROOT/name,software/name)
    shutil.copytree(ROOT/'references/crypto-vectors',software/'references/crypto-vectors')
    # Both source and prebuilt static UI; npm cache is not represented as an offline build toolchain.
    shutil.copytree(ROOT/'apps/web',software/'apps/web',ignore=shutil.ignore_patterns('node_modules','.vite','test-results','playwright-report'))
    copy(ROOT/'.build/libgridcrypto.so',software/'.build/libgridcrypto.so')
    shutil.copytree(ROOT/'.build/wheelhouse',software/'.build/wheelhouse')
    shutil.copytree(ROOT/'.build/licenses',software/'licenses')
    shutil.copytree(ROOT/'.build/sources',software/'third_party_sources')
    shutil.copytree(ROOT/'third_party/mcl',software/'third_party/mcl',
                    ignore=shutil.ignore_patterns('.git','obj','bin','*.o','*.a','*.exe','test','bench'))
    (software/'third_party/mcl/PINNED_COMMIT').write_text('a8cad811f720264e6e140f54c66463be60189789\n',encoding='utf-8')
    evidence=destination/'evidence';evidence.mkdir()
    shutil.copytree(ROOT/'artifacts/benchmarks',evidence/'benchmarks')
    shutil.copytree(ROOT/'artifacts/figures',evidence/'figures')
    shutil.copytree(ROOT/'artifacts/figures',software/'artifacts/figures')
    shutil.copytree(ROOT/'artifacts/screenshots',evidence/'screenshots')
    for name in ('acceptance_results.json','acceptance_provenance_verification.json','crypto_conformance.json','export_prepatch_audit.json','export_type_prepatch.json','export_postpatch_audit.json','key_readiness.json','key_readiness_future.json','ui_results.json','cleanroom_result.json','cleanroom_install.log','cleanroom_run.log','scenario_catalog.json','release_check.json','video_recording.json','rehearsal_8min.json','rehearsal_3min.json','media_review.json','final_review.json'):
        copy(ROOT/'artifacts/tests'/name,evidence/'tests'/name)
        copy(ROOT/'artifacts/tests'/name,software/'artifacts/tests'/name)
    for name, expected in consumed_references:
        if name.startswith(('artifacts/tests/acceptance_executions/','artifacts/tests/acceptance_context/')):
            assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected
            relative=Path(name).relative_to('artifacts/tests')
            copy(ROOT/name,evidence/'tests'/relative)
            copy(ROOT/name,software/name)
    for name in ('primitives.json','policy_audit.json','report_tag_audit.json','build_manifest.json'):
        copy(ROOT/'artifacts/probes'/name,evidence/'probes'/name)
        copy(ROOT/'artifacts/probes'/name,software/'artifacts/probes'/name)
    for name in ('plan.json','summary.json','raw.json','signatures_raw.json','analysis.json'):
        copy(ROOT/'artifacts/benchmarks'/name,software/'artifacts/benchmarks'/name)
    environment=read(ROOT/'artifacts/benchmarks/environment.json')
    environment.pop('kernel',None)
    environment['mcl_commit']['command']=['git','-C','third_party/mcl','rev-parse','HEAD']
    write(evidence/'benchmarks/environment.json',environment)
    trust=evidence/'trusted-role-keys/public';trust.mkdir(parents=True)
    for name in ('key_registry.json','gateway-ecdsa-1.pem','gateway-mldsa-1.pem','utility-ecdsa-1.pem','utility-mldsa-1.pem'):
        copy(RUNTIME/'public'/name,trust/name)
    write(evidence/'trusted-role-keys/fingerprints.json',{'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in trust.iterdir()},
          'instruction':'Reviewer must authenticate these fingerprints independently. The archive verifier does not adopt embedded archive keys.'})
    rows=read(ROOT/'artifacts/benchmarks/raw.json')
    rows+=read(ROOT/'artifacts/benchmarks/nodes_raw.json')
    rows+=read(ROOT/'artifacts/tests/scenario_catalog.json')
    ui=read(ROOT/'artifacts/tests/ui_results.json')
    rows += [{'run_id':ui[key]} for key in ('normal_run_id','failed_run_id')]
    rows += [{'run_id':r['run_id']} for r in video.get('recorded_runs',[])]
    rows += [{'run_id':r['run_id']} for minutes in (8,3) for r in read(ROOT/f'artifacts/tests/rehearsal_{minutes}min.json')['recorded_runs']]
    rows += [{'run_id':p['run_id']} for r in test_executions.values() for p in r['input_provenance'] if 'run_id' in p]
    rows.append({'run_id':read(ROOT/'artifacts/tests/crypto_conformance.json')['real_run_id']})
    rows.append({'run_id':video['normal_run_id']})
    ids=sorted({r['run_id'] for r in rows})
    for run_id in ids:
        path=ROOT/'artifacts/runs'/run_id
        for name in (*PUBLIC_FILES,'oracle_summary.json'):
            if (path/name).exists():copy(path/name,evidence/'runs'/run_id/name)
    checks=[]
    sample_ids=[next(r['run_id'] for r in rows if r.get('profile')==profile) for profile in ('S0','SA','SB','SAB')]
    for run_id in sample_ids:
        archive=export_public(run_id)
        result=verify_export(archive)
        checks.append(result)
        copy(archive,evidence/'exports'/archive.name)
    write(evidence/'export_verification.json',checks)
    shutil.copytree(ROOT/'materials',destination/'materials')
    # Public copies redact only local path metadata. Signed payloads and measured quantities stay byte-identical.
    for path in [* (p for p in (evidence/'tests').rglob('*') if p.suffix in ('.json','.log')), * (p for p in (software/'artifacts/tests').rglob('*') if p.suffix in ('.json','.log')),* (evidence/'probes').glob('*.json'),* (software/'artifacts/probes').glob('*.json'),evidence/'export_verification.json']:
        value=path.read_text(encoding='utf-8')
        for location in (str(ROOT),str(ROOT).replace('/','\\'),'/mnt/c/Users/Lenovo/Desktop/密码技术竞赛',str(RUNTIME)):
            value=value.replace(location.replace('\\','\\\\'),'<local-path>').replace(location,'<local-path>')
        path.write_text(value,encoding='utf-8')
    catalogue=[]
    for name, original_sha in sorted(consumed_references):
        if name.startswith('artifacts/runs/'):
            public_copy=evidence/'runs'/Path(name).relative_to('artifacts/runs')
        elif name.startswith('artifacts/tests/'):
            public_copy=evidence/'tests'/Path(name).relative_to('artifacts/tests')
        elif name.startswith('artifacts/probes/'):
            public_copy=evidence/'probes'/Path(name).relative_to('artifacts/probes')
        else:
            public_copy=software/name
        public_sha=hashlib.sha256(public_copy.read_bytes()).hexdigest()
        catalogue.append({'original_path':name,'original_sha256':original_sha,
                          'public_copy':str(public_copy.relative_to(destination)),
                          'public_sha256':public_sha,
                          'transformation':'byte-identical' if original_sha==public_sha else 'local-path metadata redaction and/or text line-ending normalization'})
    write(evidence/'acceptance_provenance_catalogue.json',{
        'schema':'GRID_PUBLIC_ACCEPTANCE_PROVENANCE_V1','entries':catalogue,
        'scope':'Original hashes identify evidence consumed by the actual tests; public-copy hashes account for declared packaging transformations. Hashes are integrity checks, not authenticity or correctness proofs.'})
    public_provenance=verify_provenance(destination,packaged=True)
    write(evidence/'acceptance_provenance_verification.json',public_provenance)
    forbidden={'private_key','node_id','values_W','token_bundle','alpha','p_prime','q_prime','xag','xgw'}
    def scan(value):
        if isinstance(value,dict):
            assert not set(value)&forbidden,'Private field in evidence'
            for v in value.values():scan(v)
        elif isinstance(value,list):
            for v in value:scan(v)
    for path in destination.rglob('*'):
        if not path.is_file():continue
        assert path.suffix not in ('.key','.pcap'),path
        assert not re.search(rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----\s*\r?\n[A-Za-z0-9+/]{16,}',path.read_bytes()),path
        if path.is_relative_to(evidence) and path.suffix=='.json':scan(json.loads(path.read_text(encoding='utf-8')))
    version=source_version()
    assert version['core_source_digest']==read(ROOT/'artifacts/benchmarks/plan.json')['core_source_digest']
    payload={str(p.relative_to(software)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in software.rglob('*') if p.is_file()}
    write(software/'package_manifest.json',{'schema':'GRID_OFFLINE_SOFTWARE_V1','files':payload,'platform':'Linux x86_64, glibc>=2.43, CPython3.14, OpenSSL>=3.5.5','initial_payload_only':True,**version})
    (destination/'README.md').write_text('# 本地审阅交付候选\n\nsoftware 含源码、原生库、本地界面和离线 wheels。在兼容 WSL 中运行 `bash software/scripts/install_offline.sh`，然后 `bash software/scripts/project serve`。在新目录解压安装；运行产生的新证据会改变初始文件状态。\n\n完整指南在 software/docs/USER_GUIDE.md。evidence 含原始测量、公开运行记录、验签样例和单独的可信公钥指纹。审阅者先独立确认公钥指纹，再使用 `GRID_RUNTIME=<绝对路径>/evidence/trusted-role-keys bash software/scripts/project verify-export --path <公开ZIP>`。\n\nmaterials 含设计报告、答辩稿、演示脚本和自动操作实录。作品编号待填写，审批签字页留空。参数安全复核尚未完成，正式发布门槛保持未通过。该包不含运行私钥、单户明文、敏感令牌或原始研究PDF，未上传。\n',encoding='utf-8')
    (destination/'materials/演示与彩排脚本.md').write_bytes((ROOT/'docs/DEMO_SCRIPT.md').read_bytes())
    manifest={'version':'0.1.0','candidate':True,'formal_release_ready':review['formal_release_ready'],
              'remaining_issues':review['issues'],'core_source_digest':version['core_source_digest'],
              'public_run_count':len(ids),'export_checks':len(checks),'files':{str(p.relative_to(destination)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.rglob('*') if p.is_file()},
              'scope':'local review only; same-host clean install checked separately; no human rehearsal or submission claimed'}
    write(destination/'delivery_manifest.json',manifest)
    archive=Path(str(destination)+'.zip')
    assert not archive.exists()
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for file in destination.rglob('*'):
            if file.is_file():z.write(file,file.relative_to(destination))
    result={'directory':str(destination),'archive':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'bytes':archive.stat().st_size,'run_count':len(ids),'formal_release_ready':False}
    write(ROOT/'artifacts/tests/package_result.json',result)
    print(json.dumps(result))


if __name__=='__main__':main()
