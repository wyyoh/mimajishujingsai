"""Read-only algebra/correctness review; never a concrete security proof."""
import hashlib
import json
import math
import sys
import uuid
from pathlib import Path

import gmpy2 as gmp

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from services import pfdam
from services.encoding import Rejected,digest
from services.initialization import ROOT,RUNTIME
from services.native import LIB,utc
from services.storage import read,write
from services.versioning import source_version


def main():
    started, build = utc(),source_version()
    public = read(RUNTIME/'public/parameters.json')
    audit = read(RUNTIME/'ta/parameter_audit.json')
    uc,gw = read(RUNTIME/'utility/pfdam.json'),read(RUNTIME/'gateway/pfdam.json')
    n,h = int(public['N']),int(public['h'])
    p,q,pp,qp = [int(audit[name]) for name in ('p','q','p_prime','q_prime')]
    cp,cq = (p-1)//(2*pp),(q-1)//(2*qp)
    alpha,beta,order = 4*pp*qp,cp*cq,2*pp*qp
    exponent = 2*alpha
    lifted = pow(h,n,n*n)
    checks = {
        'public_parameter_digest':digest({key:value for key,value in public.items() if key!='param_id'}) == public['param_id'],
        'distinct_prime_factors':p!=q and pp!=qp and all(gmp.is_prime(value,40) for value in (p,q,pp,qp)),
        'factorization_and_sizes':p*q==n and n.bit_length()==3072 and pp.bit_length()==qp.bit_length()==384,
        'structured_factors':p==2*pp*cp+1 and q==2*qp*cq+1 and math.gcd(p-1,q-1)==2,
        'coprime_small_and_cofactor_parts':math.gcd(pp*qp,beta)==1,
        'private_parameter_binding':int(uc['alpha'])==alpha==int(audit['alpha']) and uc['param_id']==gw['param_id']==public['param_id'],
        'actual_h_order':pow(h,order,n)==1 and all(pow(h,order//factor,n)!=1 for factor in (2,pp,qp)),
        'lifted_randomizer_order':pow(lifted,order,n*n)==1 and all(pow(lifted,order//factor,n*n)!=1 for factor in (2,pp,qp)),
        'decryption_exponent_cancels_randomizer':exponent%order==0 and pow(lifted,exponent,n*n)==1,
        'full_application_range_without_wrap':exponent*(900*10**9)<n,
    }
    assert all(checks.values()),'Parameter structure or application recovery-domain check failed'
    context={'task_nonce':uuid.uuid4().hex,'metric_id':'average_active_power_W'}
    labels=[pfdam.tag(context,'parameter-review-slot','A',resource) for resource in ('residential','commercial','charging')]
    values=[0,10**9,456]
    selected=[0,1]
    token=pfdam.authorize(public,uc,[labels[index] for index in selected])
    reports=[]
    for label,value in zip(labels,values,strict=True):
        envelope={'task_id':'parameter-scope-review','run_id':'parameter-scope-review','slot_id':'parameter-review-slot',
                  'param_id':public['param_id'],'report':pfdam.report(public,value,label,utc())}
        envelope['report_id']=digest(envelope)
        reports.append(envelope)
    expected_ids={reports[index]['report_id'] for index in selected}
    expected_sum=sum(values[index] for index in selected)
    aggregate,accepted,rejected=pfdam.match_and_aggregate(public,gw,token,reports)
    stamp=utc();signature=pfdam.native_sign(gw,aggregate,stamp)
    recovered=pfdam.verify_recover(public,uc,aggregate,stamp,signature,len(expected_ids))
    assert set(accepted)==expected_ids and recovered==expected_sum and len(rejected)==1
    huge_count=(n+exponent*10**9-1)//(exponent*10**9)
    try:
        pfdam.verify_recover(public,uc,aggregate,stamp,signature,huge_count)
        raise AssertionError('Unsafe integer-division recovery domain accepted')
    except Rejected as exc:
        assert exc.code=='RECOVERY_MESSAGE_BOUND_INVALID'
    after=source_version();assert build==after
    result={'schema':'GRID_PFDAM_PARAMETER_SCOPE_REVIEW_V1','started_at':started,'finished_at':utc(),**build,
            'command':[sys.executable,'scripts/parameter_scope_review.py'],'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'versions':json.loads(LIB.grid_library_info()),'param_id':public['param_id'],'execution_scope':'REAL_LOCAL_COMPONENT_NOT_SAB_VERTICAL_FLOW',
            'inputs':{'own_synthetic_values_W':values,'selected_indices':selected,'maximum_reports':900,'maximum_value_W':10**9},
            'checks':checks,'independent_expected_set_match':True,'independent_integer_sum_match':True,'recovery_overflow_rejected':True,
            'modulus_bits':n.bit_length(),'actual_randomizer_order_bits':order.bit_length(),
            'paper_claimed_order_to_actual_ratio':(2*alpha)//order,
            'recovery_bound_margin_bits':n.bit_length()-(exponent*(900*10**9)).bit_length(),
            'random_exponent_bits':1024,'modular_sampling_bias_loose_upper_bound_log2':order.bit_length()-1024,
            'structural_correctness':'PASS','concrete_parameter_security_proof':'OPEN','policy_hiding':'DEMONSTRATED_LIMITATION',
            'source_plaintexts_or_private_parameters_exported':False,'scope':'Algebra, range and real functional checks; no new security reduction or protocol change',
            'exit_code':0}
    destination=ROOT/'artifacts/iterations/local-standards/parameter-review'/(started.replace(':','-')+'.json')
    write(destination,result)
    print(json.dumps({'record':str(destination.relative_to(ROOT)),'checks':len(checks),'order_ratio':result['paper_claimed_order_to_actual_ratio'],
                      'recovery_bound_margin_bits':result['recovery_bound_margin_bits'],'structural_correctness':'PASS','concrete_security_proof':'OPEN','exit_code':0}))


if __name__=='__main__':main()
