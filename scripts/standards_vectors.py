"""Selected standard examples and an independent GmSSL peer; not certification."""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.agility import sm2_sign, sm2_verify, sm3, sm4_gcm
from services.custody import _derive
from services.encoding import Rejected
from services.initialization import ROOT
from services.native import utc
from services.storage import write
from services.versioning import source_version


def main():
    before, started = source_version(), utc()
    peer = ROOT / '.build/standards-interop/interop_sm'
    metadata = json.loads((ROOT / 'references/standards/20261017/supplemental/GmSSL-build.json').read_text())
    gmssl = Path(metadata['executable'])
    commands, rows = [], []
    def call(args, data=b'', inherited=()):
        command = [str(value) for value in args]
        commands.append(command)
        return subprocess.run(command, input=data, capture_output=True, pass_fds=inherited, timeout=20)
    def peer_call(action, data, *arguments, inherited=()):
        result = call([peer, action, *arguments], data, inherited)
        if result.returncode:
            raise Rejected('INDEPENDENT_PEER_OPERATION_FAILED')
        return result.stdout

    assert _derive(bytes.fromhex('0b'*22), bytes.fromhex('000102030405060708090a0b0c'), bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')) == bytes.fromhex('3cb25f25faacd57a90434f64d0362f2a')
    rows.append({'id': 'HKDF_SHA256_RFC5869_1', 'status': 'PASS', 'scope': 'First 16 output bytes of RFC 5869 case 1'})
    for data, expected in [(b'abc', '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
                           (b'abcd'*16, 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')]:
        assert sm3(data) == expected == peer_call('sm3', data).hex()
    rows.append({'id': 'SM3_STANDARD_EXAMPLES', 'status': 'PASS', 'examples': 2})
    block = bytes.fromhex('0123456789abcdeffedcba9876543210')
    expected_block = bytes.fromhex('681edf34d206965e86b3e94f536e4246')
    assert peer_call('block', block, block.hex()) == expected_block
    assert call(['openssl', 'enc', '-sm4-ecb', '-nopad', '-nosalt', '-K', block.hex()], block).stdout == expected_block
    rows.append({'id': 'SM4_SINGLE_BLOCK_STANDARD_EXAMPLE', 'status': 'PASS', 'business_ecb_enabled': False})
    key, nonce = bytes(16), bytes(12)
    for data, expected, tag in [(b'', '', '232f0cfe308b49ea6fc88229b5dc858d'),
                                (bytes(16), '7de2aa7f1110188218063be1bfeb6d89', 'b851b5f39493752be508f1bb4482c557')]:
        ciphertext, actual = sm4_gcm(key, nonce, data)
        assert ciphertext.hex() == expected and actual.hex() == tag
        assert peer_call('gcm-encrypt', data, key.hex(), nonce.hex(), '') == ciphertext+actual
    rows.append({'id': 'SM4_GCM_GBT36624_C5', 'status': 'PASS', 'examples': 2, 'pdf_page': 24,
                 'source': 'references/standards/20261017/supplemental/GB_T36624-2018.pdf', 'appendix': 'Informative C.5'})
    for length in (0, 1, 16, 257):
        key, nonce, aad = bytes(range(16)), bytes(range(12)), b'GRID-INDEPENDENT-INTEROP'
        data = bytes(index%251 for index in range(length))
        ciphertext, tag = sm4_gcm(key, nonce, data, aad)
        assert peer_call('gcm-encrypt', data, key.hex(), nonce.hex(), aad.hex()) == ciphertext+tag
        assert peer_call('gcm-decrypt', ciphertext, key.hex(), nonce.hex(), aad.hex(), tag.hex()) == data
        changed = bytes([tag[0]^1])+tag[1:]
        assert call([peer, 'gcm-decrypt', key.hex(), nonce.hex(), aad.hex(), changed.hex()], ciphertext).returncode != 0
        try:
            sm4_gcm(key, nonce, ciphertext, aad, changed)
        except Rejected as exc:
            assert exc.code == 'SM4_AUTHENTICATION_FAILED'
        else:
            raise AssertionError('Native accepted an incorrect authentication tag')
    rows.append({'id': 'SM4_GCM_INDEPENDENT_INTEROP', 'status': 'PASS', 'lengths': [0, 1, 16, 257], 'bad_tags_rejected_by_both': True})
    with tempfile.TemporaryDirectory(prefix='grid-sm-peer-') as temporary:
        directory = Path(temporary)
        standard_public = directory / 'standard-public.pem'
        point = bytes.fromhex('09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13')
        der = bytes.fromhex('3059301306072a8648ce3d020106082a811ccf5501822d03420004')+point
        def pem_public(path, raw):
            encoded = base64.b64encode(raw)
            path.write_bytes(b'-----BEGIN PUBLIC KEY-----\n'+b'\n'.join(encoded[i:i+64] for i in range(0,len(encoded),64))+b'\n-----END PUBLIC KEY-----\n')
        pem_public(standard_public, der)
        r = bytes.fromhex('F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3')
        s = bytes.fromhex('B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA')
        standard_signature = b'\x30\x46\x02\x21\x00'+r+b'\x02\x21\x00'+s
        assert sm2_verify(standard_public, b'message digest', '1234567812345678', standard_signature)
        standard_data, standard_sig = directory/'standard-message', directory/'standard-signature'
        standard_data.write_bytes(b'message digest')
        standard_sig.write_bytes(standard_signature)
        assert call([gmssl, 'sm2verify', '-pubkey', standard_public, '-id', '1234567812345678', '-in', standard_data, '-sig', standard_sig]).returncode == 0
        invalid_point = directory/'invalid-point.pem'
        pem_public(invalid_point, der[:-64]+b'\xff'*64)
        try:
            accepted = sm2_verify(invalid_point, b'message digest', '1234567812345678', standard_signature)
        except Rejected:
            accepted = False
        assert not accepted
        assert call([gmssl, 'sm2verify', '-pubkey', invalid_point, '-id', '1234567812345678', '-in', standard_data, '-sig', standard_sig]).returncode != 0
        rows.append({'id': 'SM2_GBT32918_5_A2', 'status': 'PASS', 'pdf_pages': [7,8], 'identity_preprocessing_checked_by_known_signature': True,
                     'off_curve_public_point_rejected_by_both': True, 'scope': 'Published recommended-curve example, not custom-curve examples'})
        public = directory / 'public.pem'
        private = peer_call('keygen', b'', public)
        descriptor = os.memfd_create('grid-ephemeral-interop-key', os.MFD_CLOEXEC)
        try:
            os.write(descriptor, private)
            private = b''
            key_path = Path(f'/proc/self/fd/{descriptor}')
            data, signature_file, data_file = b'GRID-REAL-INDEPENDENT-INTEROP', directory/'signature.der', directory/'message.bin'
            data_file.write_bytes(data)
            for identity in ('GRID-TASK-AUTH-V4', 'GRID-AGG-RECEIPT-V4', 'GRID-UC-RESULT-V1'):
                generated = peer_call('sign', data, key_path, identity, inherited=(descriptor,))
                assert sm2_verify(public, data, identity, generated)
                assert not sm2_verify(public, data, identity+'-WRONG', generated)
                assert not sm2_verify(public, data+b'x', identity, generated)
                native_signature = sm2_sign(key_path, data, identity)
                signature_file.write_bytes(native_signature)
                assert call([gmssl, 'sm2verify', '-pubkey', public, '-id', identity, '-in', data_file, '-sig', signature_file]).returncode == 0
                assert call([gmssl, 'sm2verify', '-pubkey', public, '-id', identity+'-WRONG', '-in', data_file, '-sig', signature_file]).returncode != 0
            def integer(value):
                encoded = value.to_bytes(max(1, (value.bit_length()+7)//8), 'big')
                if encoded[0]&128:
                    encoded = b'\0'+encoded
                return b'\x02'+bytes([len(encoded)])+encoded
            order = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
            invalid = []
            for r, s in ((0,1), (1,0), (order,1), (1,order)):
                content = integer(r)+integer(s)
                invalid.append(b'\x30'+bytes([len(content)])+content)
            invalid += [b'', b'\x30\x03\x02\x01\x00', generated[:-1], generated+b'\0']
            labels = ['r_zero', 's_zero', 'r_order', 's_order', 'empty', 'malformed_der', 'truncated', 'trailing_bytes']
            peer_acceptances = []
            for label, value in zip(labels, invalid, strict=True):
                try:
                    accepted = sm2_verify(public, data, 'GRID-UC-RESULT-V1', value)
                except Rejected:
                    accepted = False
                assert not accepted
                signature_file.write_bytes(value)
                peer_accepted = call([gmssl, 'sm2verify', '-pubkey', public, '-id', 'GRID-UC-RESULT-V1', '-in', data_file, '-sig', signature_file]).returncode == 0
                if peer_accepted:
                    peer_acceptances.append(label)
                assert not peer_accepted or label == 'trailing_bytes', label
        finally:
            os.close(descriptor)
    rows.append({'id': 'SM2_INDEPENDENT_BIDIRECTIONAL', 'status': 'PASS', 'object_contexts': 3, 'wrong_identity_and_message_rejected': True,
                 'ephemeral_private_fixture': 'Linux memory fd only; no real role key shared with the peer'})
    rows.append({'id': 'SM2_INTEGER_AND_DER_BOUNDARIES', 'status': 'PASS', 'native_negative_cases': len(invalid),
                 'peer_accepted_boundary_cases': peer_acceptances, 'peer_limitation': 'GmSSL CLI accepts trailing signature bytes when observed; application rejects them'})
    after = source_version()
    assert before == after
    result = {'schema': 'GRID_SELECTED_STANDARDS_VECTORS_V1', 'started_at': started, 'finished_at': utc(), **before,
              'command': [sys.executable, 'scripts/standards_vectors.py'], 'commands': commands,
              'test_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'peer_source_sha256': hashlib.sha256((ROOT/'tests/interop_sm.c').read_bytes()).hexdigest(),
              'peer_executable_sha256': hashlib.sha256(peer.read_bytes()).hexdigest(), 'independent_implementation': metadata,
              'observations': rows, 'exit_code': 0, 'formal_evaluation': False,
              'scope': 'Selected examples, boundaries and real independent SM2/SM3/SM4 interop; not whole algorithm/module certification'}
    destination = ROOT / 'artifacts/iterations/standards/vectors' / (started.replace(':','-')+'.json')
    write(destination, result)
    print(json.dumps({'record': str(destination.relative_to(ROOT)), 'observations': len(rows), 'exit_code': 0}))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
