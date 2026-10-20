"""Application self-checks must fail on missing/tampered evidence, not turn green."""
import copy
import hashlib
import shutil
import uuid

import pytest
from fastapi.testclient import TestClient

from services import selfcheck, selfcheck_probes as probes
from services.encoding import Rejected, canonical, digest
from services.initialization import ROOT, RUNTIME
from services.storage import read
from tests.provenance import record_run, observe


@pytest.fixture(scope='module')
def evaluation():
    from services.response import execute, EvaluationRequest
    result = execute(EvaluationRequest(nodes=300, source_count=3, request_nonce=uuid.uuid4().hex), 'grid_operator_A', lab=True)
    assert result['status'] == 'COMPLETED'
    for child in result['children']:
        assert read(ROOT/'artifacts/runs'/child['run_id']/'run_manifest.json')['oracle_match']
    return result


@pytest.fixture(scope='module')
def aggregate():
    from services.publication import prepare
    from services.expansion_schemas import ExpansionRequest
    from services.expansion_orchestrator import execute
    policy, _, _ = prepare(ExpansionRequest(nodes=300, periods=[52], scene_id='park', source_count=1,
                                            algorithm_suite='V41_HYBRID', request_nonce=uuid.uuid4().hex), 'grid_operator_A')
    result = execute(policy, lab=True)
    assert result['status'] == 'COMPLETED' and result['oracle_match']
    return result


def rows(report):
    return {row['id']: row for row in report['checks']}


def test_current_real_parent_all_functional_checks_and_limits(evaluation):
    from services.custody import load_root
    from services.evidence import export_public
    record_run(evaluation['run_id'])
    archive = export_public(evaluation['run_id'])
    original = hashlib.sha256(archive.read_bytes()).hexdigest()
    ledger = digest(load_root(RUNTIME)['publication_state'])
    report = selfcheck.check(evaluation['run_id'], subject='grid_operator_A')
    assert report['schema'] == 'GRID_APPLICATION_SELF_CHECK_V3'
    assert report['functional_overall'] == 'PASS' and report['version_matches']
    assert report['counts'] == {'functional_pass': 12, 'functional_total': 12, 'functional_not_applicable': 0, 'open_assurance': 1}
    checked = rows(report)
    assert checked['integrity']['evidence']['window_count'] == 16
    assert checked['communication']['evidence']['endpoint_records'] == 32
    assert checked['publication']['evidence']['commit']['registered_participation_windows_rechecked'] == 16
    assert all(item['passed'] for item in checked['agility']['evidence']['negative_checks'])
    assert checked['confidentiality']['status'] == 'PENDING' and checked['standards']['status'] == 'PASS'
    assert checked['standards']['evidence']['third_party_assessment_required'] is False
    assert checked['standards']['evidence']['whole_standard_conformance_claimed'] is False
    assert len(checked['standards']['evidence']['vector_checks']) == 11
    assert report['overall'] == 'HAS_OPEN_ITEMS' and report['formal_evaluation'] is False
    assert digest(load_root(RUNTIME)['publication_state']) == ledger
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == original
    assert not any(key in canonical(report).decode() for key in ('value_W', 'values_W', 'registered_metering_points', 'oracle_mapping', 'sum_W', 'private_key'))
    observe('current_selfcheck', {'report_path': report['record_path'], 'report_sha256': hashlib.sha256((ROOT/report['record_path']).read_bytes()).hexdigest(),
                                  'functional_count': 12, 'research_and_assurance_open': True, 'publication_ledger_unchanged': True})


def test_real_hybrid_without_sm_is_checked_as_selected_path(aggregate):
    record_run(aggregate['run_id'])
    report = selfcheck.check(aggregate['run_id'], subject='grid_operator_A')
    assert report['functional_overall'] == 'PASS'
    assert report['counts']['functional_pass'] == 11
    assert rows(report)['agility']['evidence']['required_algorithms'] == ['ECDSA-P256-SHA256', 'ML-DSA-65']
    assert rows(report)['communication']['evidence']['endpoint_records'] == 4
    assert rows(report)['communication']['evidence']['sm4_required'] is False
    stale = {**selfcheck.source_version(), 'core_source_digest': '0'*64}
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(selfcheck, 'source_version', lambda: stale)
        historical = selfcheck.check(aggregate['run_id'], subject='grid_operator_A')
    assert historical['functional_overall'] == 'STALE'
    assert rows(historical)['integrity']['status'] == 'STALE'


def test_missing_child_and_wrong_parent_never_pass(evaluation, monkeypatch):
    record_run(evaluation['run_id'])
    original_read = probes.read
    child_id = evaluation['children'][0]['run_id']
    target = RUNTIME/'runs'/child_id/'utility/computed.json'
    def missing(path, **kwargs):
        if path == target:
            raise FileNotFoundError('PRIVATE_SENTINEL_MUST_NOT_REACH_REPORT')
        return original_read(path, **kwargs)
    monkeypatch.setattr(probes, 'read', missing)
    report = selfcheck.check(evaluation['run_id'], subject='grid_operator_A')
    assert report['functional_overall'] == 'FAIL'
    assert rows(report)['integrity']['status'] == 'FAIL' and rows(report)['audit']['status'] == 'FAIL'
    assert 'PRIVATE_SENTINEL' not in canonical(report).decode()
    monkeypatch.setattr(probes, 'read', original_read)
    wrong = copy.deepcopy(evaluation); wrong['children'][0]['run_id'] = evaluation['children'][1]['run_id']
    with pytest.raises(Rejected, match='SELF_CHECK_CHILD_SET_MISMATCH'):
        probes.components(wrong)


def test_missing_endpoint_in_one_day_cannot_be_hidden_by_other_days(evaluation, monkeypatch):
    record_run(evaluation['run_id'])
    target = ROOT/'artifacts/runs'/evaluation['run_id']/'connection_evidence.json'
    original_read = probes.read
    def incomplete(path, **kwargs):
        value = original_read(path, **kwargs)
        return value[1:] if path == target else value
    monkeypatch.setattr(probes, 'read', incomplete)
    with pytest.raises(Rejected, match='SELF_CHECK_TLS_ENDPOINTS_INCOMPLETE'):
        probes.communication(evaluation)
    monkeypatch.setattr(probes, 'read', original_read)
    def false_identity(path, **kwargs):
        value = original_read(path, **kwargs)
        if path == target:
            value[0]['peer_identity_verified'] = False
        return value
    monkeypatch.setattr(probes, 'read', false_identity)
    with pytest.raises(Rejected):
        probes.communication(evaluation)


def test_fresh_archive_verification_does_not_trust_a_good_cached_zip(aggregate, tmp_path, monkeypatch):
    from services.evidence import export_public
    from services import publication_evidence
    record_run(aggregate['run_id'])
    cached = export_public(aggregate['run_id'])
    before = cached.read_bytes()
    target = tmp_path/'artifacts/runs'/aggregate['run_id']
    shutil.copytree(ROOT/'artifacts/runs'/aggregate['run_id'], target)
    shutil.copytree(ROOT/'artifacts/exports', tmp_path/'artifacts/exports', ignore=lambda directory, names: [name for name in names if name != cached.name])
    value = read(target/'receipts.json')
    sig = value[0]['signatures'][0]['value']
    value[0]['signatures'][0]['value'] = ('A' if sig[0] != 'A' else 'B')+sig[1:]
    (target/'receipts.json').write_bytes(canonical(value))
    monkeypatch.setattr(publication_evidence, 'ROOT', tmp_path)
    with pytest.raises(Rejected, match='OBJECT_SIGNATURE_INVALID'):
        selfcheck._verify(aggregate)
    assert cached.read_bytes() == before


def test_no_task_is_not_an_all_pass_and_guard_failures_stop_check(monkeypatch):
    monkeypatch.setattr(probes, 'choose_run', lambda subject, core: None)
    report = selfcheck.check(subject='grid_operator_A')
    assert report['selection'] == 'NO_ELIGIBLE_RUN' and report['functional_overall'] == 'NOT_RUN'
    assert rows(report)['publication']['status'] == 'NOT_RUN'
    original = probes.authorization
    from services import governance
    # Fault injection: the guard now wrongly accepts a lower-security suite.
    real_decide = governance.decide
    def broken(request, subject, **kwargs):
        if request['algorithm_suite'] == 'V41_CLASSIC':
            return {}
        return real_decide(request, subject, **kwargs)
    monkeypatch.setattr(governance, 'decide', broken)
    with pytest.raises(Rejected, match='SELF_CHECK_AUTHORIZATION_ENFORCEMENT_FAILED'):
        original()


def test_api_selects_only_authorized_current_runtime_task(aggregate, evaluation, monkeypatch):
    import sqlite3
    from services import api
    from services.sessions import ACCESS_PATH
    monkeypatch.setenv('GRID_LAB', '1'); monkeypatch.setattr(api, 'LAB', True)
    # Explicit test index fixtures: not presented as API-submitted business runs.
    fake = copy.deepcopy(aggregate); fake.update(run_id=uuid.uuid4().hex, private_experiment=True)
    foreign = copy.deepcopy(aggregate); foreign.update(run_id=uuid.uuid4().hex, runtime_instance='0'*96)
    wrong_owner = copy.deepcopy(aggregate); wrong_owner.update(run_id=uuid.uuid4().hex, requester_id='grid_operator_B')
    stale = copy.deepcopy(aggregate); stale.update(run_id=uuid.uuid4().hex, core_source_digest='0'*64)
    from services.storage import write
    for fixture in (fake, foreign, wrong_owner, stale):
        write(ROOT/'artifacts/runs'/fixture['run_id']/'run_manifest.json', fixture)
    with sqlite3.connect(RUNTIME/'api.sqlite') as db:
        db.execute('CREATE TABLE IF NOT EXISTS v41_nonces (subject TEXT, nonce TEXT, run_id TEXT, PRIMARY KEY(subject,nonce))')
        for value in (aggregate, fake, foreign, wrong_owner, stale):
            db.execute('INSERT INTO v41_nonces VALUES(?,?,?)', ('grid_operator_A', uuid.uuid4().hex, value['run_id']))
    assert probes.choose_run('grid_operator_A', selfcheck.source_version()['core_source_digest']) == aggregate['run_id']
    with TestClient(api.app) as client:
        assert client.post('/api/self-check', json={}).status_code == 401
        credentials = read(ACCESS_PATH)['accounts']
        assert client.post('/api/session', json={'subject': 'grid_operator_A', 'password': credentials['grid_operator_A']}).status_code == 200
        response = client.post('/api/self-check', json={})
        assert response.status_code == 200 and response.json()['run_id'] == aggregate['run_id']
        assert response.json()['functional_overall'] == 'PASS'
        assert client.post('/api/self-check', json={'run_id': fake['run_id']}).status_code == 403
        assert client.post('/api/self-check', json={'run_id': foreign['run_id']}).status_code == 403
        assert client.post('/api/self-check', json={'run_id': wrong_owner['run_id']}).status_code == 403
        assert client.post('/api/session', json={'subject': 'grid_operator_B', 'password': credentials['grid_operator_B']}).status_code == 200
        assert client.post('/api/self-check', json={'run_id': evaluation['run_id']}).status_code == 403
    record_run(aggregate['run_id']); record_run(evaluation['run_id'])


def test_withheld_has_no_invented_result_signature(monkeypatch):
    from services.publication import prepare
    from services.expansion_schemas import ExpansionRequest
    from services.expansion_orchestrator import execute
    policy, _, _ = prepare(ExpansionRequest(nodes=300, periods=[51], scene_id='park', source_count=3, request_nonce=uuid.uuid4().hex), 'grid_operator_A')
    result = execute(policy, lab=True, fault='missing')
    assert result['status'] == 'WITHHELD' and result['oracle_match']
    report = selfcheck.check(result['run_id'], subject='grid_operator_A')
    checked = rows(report)
    assert report['functional_overall'] == 'PASS' and report['counts']['functional_not_applicable'] == 3
    assert checked['publication']['status'] == 'PASS'
    assert all(checked[key]['status'] == 'NOT_APPLICABLE' for key in ('integrity', 'audit', 'result_statement'))
    assert 'value_W' not in canonical(report).decode()
    record_run(result['run_id'])


def test_local_standard_profile_fails_on_bad_vector_or_task_control(evaluation, monkeypatch):
    from services import standards_profile
    record_run(evaluation['run_id'])
    report = selfcheck.check(evaluation['run_id'], subject='grid_operator_A')
    mapping = read(ROOT/'docs/STANDARDS_ALIGNMENT_EXECUTION.json')
    # External certification/deployment is outside this selected local profile.
    reference = copy.deepcopy(mapping)
    reference['pending_documents'] = ['OUT_OF_SCOPE_EXTERNAL_DOCUMENT']
    reference['conditions_not_enabled'] = ['OUT_OF_SCOPE_DEVICE']
    result = standards_profile.evaluate(report['checks'], reference)
    assert result['status'] == 'PASS' and result['third_party_assessment_required'] is False
    bad_controls = copy.deepcopy(report['checks'])
    next(row for row in bad_controls if row['id']=='communication')['status'] = 'FAIL'
    assert standards_profile.evaluate(bad_controls, reference)['status'] == 'FAIL'
    monkeypatch.setattr(standards_profile, 'sm3', lambda data: '0'*64)
    with pytest.raises(Rejected, match='LOCAL_STANDARD_VECTOR_CHECK_FAILED'):
        standards_profile.evaluate(report['checks'], reference)
