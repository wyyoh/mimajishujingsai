"""Managed-result binding and real transport limits, without changing shared trust."""
import copy
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from services import native
from services.encoding import Rejected
from services.expansion_governance import prepare
from services.expansion_orchestrator import execute
from services.expansion_schemas import ExpansionRequest
from services.initialization import ROOT, RUNTIME
from services.orchestrator import initialize, free_port
from services.result_attestation import verify_statement
from services.storage import read
from tests.provenance import observe, record_run


def test_real_sm4_limits_close_connection_and_full_handshake_changes_keys():
    initialize()
    old_keys = None
    for boundary in ('tx_sequence', 'rx_bytes'):
        port = free_port()
        listener = native.Listener(port, 'gateway', 'source', 'X25519MLKEM768', RUNTIME, 'L1', True)
        with ThreadPoolExecutor(max_workers=1) as pool:
            accepted = pool.submit(listener.accept)
            try:
                with native.TLS.connect(port, 'source', 'gateway', 'X25519MLKEM768', RUNTIME, 'L1', True) as client, accepted.result(timeout=10) as server:
                    assert client.sm4[0] == server.sm4[1] and client.sm4[1] == server.sm4[0]
                    assert client.sm4[0] != client.sm4[1]
                    if old_keys is not None:
                        assert client.sm4[:2] != old_keys
                    old_keys = client.sm4[:2]
                    client.send({'request_id':'limit-probe','value':17})
                    assert server.receive()['value'] == 17
                    server.send({'request_id':'limit-reply','value':23})
                    assert client.receive()['value'] == 23
                    with pytest.raises(Rejected, match='SM4_CHANNEL_ALREADY_INITIALIZED'):
                        client.enable_sm4('source','gateway')
                    if boundary == 'tx_sequence':
                        client.tx_sequence = native.SM4_MAX_FRAMES
                        with pytest.raises(Rejected, match='SM4_KEY_USAGE_LIMIT'):
                            client.send({'value':1})
                        assert client.pointer is None
                        with pytest.raises(Rejected, match='TLS_CONNECTION_CLOSED'):
                            client.send({'value':2})
                    else:
                        server.rx_key_bytes = native.SM4_MAX_KEY_BYTES
                        client.send({'value':1})
                        with pytest.raises(Rejected, match='SM4_KEY_USAGE_LIMIT'):
                            server.receive()
                        assert server.pointer is None
                        with pytest.raises(Rejected, match='TLS_CONNECTION_CLOSED'):
                            server.receive()
                        with pytest.raises(Rejected, match='SM4_KEY_USAGE_LIMIT'):
                            client.sm4_budget(0,0,native.SM4_MAX_PLAINTEXT+1)
            finally:
                listener.close()
    observe('real_sm4_usage_limits', {'full_handshakes':2,'actual_group':'X25519MLKEM768','directional_keys_distinct':True,
            'new_connection_keys_changed':True,'sender_and_receiver_close_at_limits':True,
            'boundary_method':'Inject counters/declared length into real authenticated connections; not a billion-byte traffic measurement',
            'private_keys_or_exporter_material_recorded':False})


def test_uc_result_signature_binds_value_units_function_and_context():
    policy, _, _ = prepare(ExpansionRequest(source_count=2,scene_id='park',function='AVG',periods=[68],request_nonce=uuid.uuid4().hex),'grid_operator_A')
    run = execute(policy)
    record_run(run['run_id'])
    assert run['status']=='COMPLETED' and run['oracle_match'] and run['uc_result_signatures_verified']
    directory = ROOT/'artifacts/runs'/run['run_id']
    result, receipt = run['results'][0], read(directory/'receipts.json')[0]['payload']
    statement = read(directory/'result_statements.json')[0]
    assert verify_statement(statement,result,receipt,policy,RUNTIME)['result_content_binding_valid']
    mutations = []
    for field, value in (('value_W',result['value_W']+1),('unit','kW'),('slot_id','slot-other')):
        changed=copy.deepcopy(result);changed[field]=value;mutations.append(('result.'+field,changed,receipt,policy))
    for field, value in (('function','COUNT'),('unit','reports'),('denominator',result['published_value']['denominator']+1)):
        changed=copy.deepcopy(result);changed['published_value'][field]=value;mutations.append(('presentation.'+field,changed,receipt,policy))
    changed=copy.deepcopy(result);changed['counts']['accepted']+=1;mutations.append(('result.counts',changed,receipt,policy))
    for field, value in (('run_id','another-run'),('task_id','another-task'),('snapshot_root','0'*64),('authorization_digest','0'*96),('accepted_set_digest','0'*96)):
        changed=copy.deepcopy(receipt);changed[field]=value;mutations.append(('receipt.'+field,result,changed,policy))
    for field, value in (('function','COUNT'),('dataset_digest','0'*96)):
        changed=copy.deepcopy(policy);changed[field]=value;mutations.append(('policy.'+field,result,receipt,changed))
    for label, candidate, candidate_receipt, candidate_policy in mutations:
        with pytest.raises(Rejected, match='UC_RESULT_STATEMENT_MISMATCH'):
            verify_statement(statement,candidate,candidate_receipt,candidate_policy,RUNTIME)
    for index in range(len(statement['signatures'])):
        changed=copy.deepcopy(statement);changed['signatures'].pop(index)
        with pytest.raises(Rejected, match='REQUIRED_SIGNATURE_MISSING'):
            verify_statement(changed,result,receipt,policy,RUNTIME)
    observe('uc_statement_binding', {'mutated_fields':[row[0] for row in mutations], 'required_signature_removal_cases':len(statement['signatures']),
            'independent_expected_set_and_integer_sum_verified':True, 'public_decryption_proof_claimed':False})
