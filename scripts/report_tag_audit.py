"""Test a report-label dictionary relation after public token policy recovery.

The attack function receives no role secrets, plaintext values or private mappings.
Learning a resource/region label does not by itself identify a physical sender.
"""
import json
import sys
import uuid
import hashlib
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services import pfdam
from services.initialization import ROOT,RUNTIME
from services.pairing import Element,GT,ORDER,pairing
from services.storage import read,write
from services.native import utc
from services.versioning import source_version


def attacker(public,token,reports,candidates):
    pairs=[pairing(Element.decode('G1',s),Element.decode('G2',w)) for s,w in zip(public['S'],token)]
    recovered=[]
    for index,tag in enumerate(candidates):
        h=pfdam.scalar_hash(tag);test=GT.scale(0)
        for j,pair in enumerate(pairs):test=test.multiply(pair.scale(pow(h,j,ORDER)))
        if test==Element.decode('GT',public['V']):recovered.append(index)
    coeff=[1]
    for index in recovered:
        h=pfdam.scalar_hash(candidates[index]);next_coeff=[0]*(len(coeff)+1)
        for j,a in enumerate(coeff):
            next_coeff[j]=(next_coeff[j]-h*a)%ORDER
            next_coeff[j+1]=(next_coeff[j+1]+a)%ORDER
        coeff=next_coeff
    assert len(coeff)>2 and coeff[1] and coeff[2]
    inferred=[]
    for report in reports:
        x=pairing(Element.decode('G1',report['D'][1]),Element.decode('G2',token[1])).scale(pow(coeff[1],-1,ORDER))
        y=pairing(Element.decode('G1',report['D'][2]),Element.decode('G2',token[2])).scale(pow(coeff[2],-1,ORDER))
        inferred.append([i for i,candidate in enumerate(candidates) if x.scale(pfdam.scalar_hash(candidate))==y])
    return recovered,inferred


public=read(RUNTIME/'public/parameters.json')
uc=read(RUNTIME/'utility/pfdam.json')
context={'task_nonce':uuid.uuid4().hex,'metric_id':'average_active_power_W'}
candidates=[pfdam.tag(context,'slot-0',region,resource) for region in ('A','B') for resource in ('residential','commercial','charging')]
results=[]
for count in (2,3,5):
    token=pfdam.authorize(public,uc,candidates[:count])
    reports=[pfdam.report(public,100+i,label,utc()) for i,label in enumerate(candidates)]
    recovered,inferred=attacker(public,token,reports,candidates)
    success=recovered==list(range(count)) and inferred==[[i] for i in range(6)]
    results.append({'authorized_count':count,'report_count':6,'recovered_policy_indices':recovered,'inferred_report_label_indices':inferred,'all_labels_identified':success})
assert all(r['all_labels_identified'] for r in results)
output={'status':'DEMONSTRATED_LIMITATION','real_pairing':True,'attacker_inputs':['public_parameters','issued_token','encrypted_reports','public_candidate_labels'],
        'candidate_construction':'grid-tag-v1; public task nonce, slot and metric; A/B regions and three resource classes',
        'param_id':public['param_id'],'finished_at':utc(),'command':[sys.executable,'scripts/report_tag_audit.py'],
        'probe_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),**source_version(),
        'results':results,'scope':'Report-label dictionary identification for degree>=2 with usable nonzero coefficients after policy recovery. Does not recover readings or establish physical-sender linkage.'}
write(ROOT/'artifacts/probes/report_tag_audit.json',output)
print(json.dumps(output))
