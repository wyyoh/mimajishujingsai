"""Authenticated evaluation entry. No intervention or protection override switch."""
from types import SimpleNamespace
from fastapi import Request, Header, HTTPException
from .encoding import Rejected, digest
from .sessions import principal
from .response import EvaluationRequest
from .publication import prepare, rules
from .storage import read
from .initialization import ROOT


def install(app,enqueue,summary):
    @app.get('/lab/publication/benchmarks')
    def matched_measurements():
        import os
        if os.environ.get('GRID_LAB')!='1':
            raise HTTPException(403,'LAB_DISABLED')
        path=ROOT/'artifacts/iterations/privacy/benchmarks/current.json'
        value=read(path) if path.is_file() else {'status':'NOT_RUN','configurations':[]}
        from .versioning import source_version
        current=source_version()['core_source_digest']
        configurations=[{**row,'current_version_matches':row.get('core_source_digest')==current} for row in value['configurations']]
        return {**value,'configurations':configurations,
                'current_version_matches':bool(configurations) and all(row['current_version_matches'] for row in configurations)}

    @app.get('/api/publication/config')
    def configuration():
        return {'rules':rules(),'mode':'EXACT_FIXED_GROUP_RELEASE','differential_privacy':False,
                'scope':'Registered metering points; honest Source/trusted UC and host; same physical machine',
                'legacy_business':'OFFLINE_VERIFICATION_ONLY'}

    @app.post('/api/response/evaluations',status_code=202)
    def create(data:EvaluationRequest,request:Request,idempotency_key:str|None=Header(default=None)):
        subject=principal(request)
        if data.periods!=rules()['event_periods']:
            raise HTTPException(422,'EVALUATION_FIXED_EVENT_PERIODS_REQUIRED')
        try:
            response=rules()['demo_response_basis_points'] if data.dataset_id=='SYN-WEEK-V42' else 0
            policy,_,_=prepare(data,subject,parent='pending',response=response)
        except Rejected as exc:
            raise HTTPException(403,exc.code) from exc
        adapter=SimpleNamespace(region=policy['region'],resources=policy['resources'],scenario='normal',model_dump=lambda:data.model_dump())
        return enqueue(adapter,idempotency_key,False,governance=policy,evaluation=data.model_dump(),
                       request_digest=digest({'kind':'RESPONSE_EVALUATION','subject':subject,'request':data.model_dump()}))

    @app.get('/api/runs/{run_id}/evaluation')
    def result(run_id:str,request:Request):
        subject=principal(request)
        current=summary(run_id)
        if current.get('requester_id')!=subject or current.get('evaluation_id')!=run_id:
            raise HTTPException(403,'EVALUATION_ACCESS_DENIED')
        directory=ROOT/'artifacts/runs'/run_id
        if current.get('publication_status')!='PUBLISHED':
            return {'publication_status':current.get('publication_status'),'evaluation':None}
        return {name:read(directory/f'{name}.json') for name in ('evaluation','evaluation_statement','release','release_statement')}
