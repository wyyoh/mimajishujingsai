"""Selected local application requirements, checked by executable evidence.

This profile is deliberately distinct from full-standard or product assessment.
The original 37-item applicability inventory is kept as a historical reference.
"""
import base64
import subprocess
import tempfile
from pathlib import Path

from .agility import sm2_verify, sm3, sm4_gcm
from .encoding import Rejected

PROFILE = 'GRID_LOCAL_APPLICATION_STANDARD_PROFILE_V1'
REFERENCES = ['GB/T 32905-2016', 'GB/T 32918.2-2016', 'GB/T 32918.5-2017',
              'GM/T 0002-2012', 'GB/T 36624-2018', 'GB/T 39786-2021（所选应用条款）']


def vectors():
    checks = []
    def checked(identifier, standard, passed):
        checks.append({'id': identifier, 'standard': standard, 'status': 'PASS' if passed else 'FAIL'})
    checked('SM3_abc', REFERENCES[0], sm3(b'abc') == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
    checked('SM3_multiblock', REFERENCES[0], sm3(b'abcd'*16) == 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')
    point = bytes.fromhex('09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13')
    der = bytes.fromhex('3059301306072a8648ce3d020106082a811ccf5501822d03420004')+point
    signature = bytes.fromhex('3046022100F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3022100B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA')
    with tempfile.TemporaryDirectory(prefix='grid-local-standard-') as temporary:
        public = Path(temporary)/'published-example.pem'
        raw = base64.b64encode(der)
        public.write_bytes(b'-----BEGIN PUBLIC KEY-----\n'+b'\n'.join(raw[i:i+64] for i in range(0,len(raw),64))+b'\n-----END PUBLIC KEY-----\n')
        checked('SM2_recommended_curve_example', REFERENCES[2], sm2_verify(public,b'message digest','1234567812345678',signature))
        checked('SM2_identity_bound', REFERENCES[1], not sm2_verify(public,b'message digest','different-id',signature))
        checked('SM2_message_bound', REFERENCES[1], not sm2_verify(public,b'message digest changed','1234567812345678',signature))
        try:
            accepted = sm2_verify(public,b'message digest','1234567812345678',signature+b'\0')
        except Rejected:
            accepted = False
        checked('SM2_strict_signature_encoding', REFERENCES[1], not accepted)
    block = bytes.fromhex('0123456789abcdeffedcba9876543210')
    process = subprocess.run(['openssl','enc','-sm4-ecb','-nopad','-nosalt','-K',block.hex()],input=block,capture_output=True,timeout=10)
    checked('SM4_single_block_example', REFERENCES[3], process.returncode == 0 and process.stdout.hex() == '681edf34d206965e86b3e94f536e4246')
    key, nonce = bytes(16), bytes(12)
    for identifier, data, expected, expected_tag in [('SM4_GCM_C5_empty',b'','','232f0cfe308b49ea6fc88229b5dc858d'),
                                                   ('SM4_GCM_C5_block',bytes(16),'7de2aa7f1110188218063be1bfeb6d89','b851b5f39493752be508f1bb4482c557')]:
        ciphertext, tag = sm4_gcm(key,nonce,data)
        checked(identifier, REFERENCES[4]+' 资料性C.5',ciphertext.hex() == expected and tag.hex() == expected_tag and sm4_gcm(key,nonce,ciphertext,b'',tag) == data)
    ciphertext, tag = sm4_gcm(key,nonce,b'local-standard-example',b'bound-context')
    rejected = False
    try:
        sm4_gcm(key,nonce,ciphertext,b'changed-context',tag)
    except Rejected as exc:
        rejected = exc.code == 'SM4_AUTHENTICATION_FAILED'
    checked('SM4_GCM_context_authentication', REFERENCES[4],rejected)
    from .custody import _derive
    derived = _derive(bytes.fromhex('0b'*22),bytes.fromhex('000102030405060708090a0b0c'),bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'))
    checked('HKDF_SHA256_case1_prefix','RFC 5869 A.1',derived == bytes.fromhex('3cb25f25faacd57a90434f64d0362f2a'))
    if not all(row['status'] == 'PASS' for row in checks):
        raise Rejected('LOCAL_STANDARD_VECTOR_CHECK_FAILED')
    return checks


def evaluate(rows, mapping):
    actual_vectors = vectors()
    by_id = {row['id']: row for row in rows}
    controls = [
        ('SM201/SM202', 'SM2身份与签验、规范编码', 'primitives'),
        ('SYM01/MOD02', '算法已知答案和运行前检查', 'primitives'),
        ('K01/K02', '软件托管、活动密钥与证书登记', 'keys'),
        ('A02', '分类授权和安全策略关联', 'authorization'),
        ('A03/N01', '业务链路身份、混合组与认证加密', 'communication'),
        ('A05/DOC01', '回执、数据范围与密文快照关联', 'integrity'),
        ('D03', '回执绑定的审计检查点', 'audit'),
        ('D04', '已批准程序与受保护管理审计', 'management'),
        ('DOC02', '统计端签名结果及任务关联', 'result_statement'),
    ]
    observations = [{'engineering_reference': reference, 'check': label, 'source_check': identifier,
                     'status': by_id[identifier]['status']} for reference,label,identifier in controls]
    inventory = {row['id'] for row in mapping['items']}
    if not all(set(row['engineering_reference'].split('/')) <= inventory for row in observations):
        raise Rejected('LOCAL_STANDARD_REFERENCE_MAPPING_INVALID')
    statuses = {row['status'] for row in observations}
    status = 'FAIL' if 'FAIL' in statuses else 'STALE' if 'STALE' in statuses else 'NOT_RUN' if statuses-{'PASS','NOT_APPLICABLE'} else 'PASS'
    return {'profile_id': PROFILE, 'status': status, 'scope': 'LOCAL_SOFTWARE_SELECTED_FUNCTIONAL_REQUIREMENTS',
            'standard_references': REFERENCES, 'vector_checks': actual_vectors, 'control_checks': observations,
            'current_task_evidence_required': True, 'third_party_assessment_required': False,
            'whole_standard_conformance_claimed': False, 'formal_evaluation': False,
            'business_ecb_enabled': False, 'reference_inventory_items': len(mapping['items']),
            'reference_inventory_core_source_digest': mapping['core_source_digest']}
