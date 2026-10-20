"""Test-only process barrier after an actual committed publication.

No API or production configuration exposes this fault. The test harness changes
only the install timing; real encryption, signatures, ledger and TLS run normally.
"""
import os
from pathlib import Path
import time
import uvicorn


def main():
    if os.environ.get('GRID_TEST_PAUSE_AFTER_COMMIT')=='1':
        from services import publication_runtime
        original=publication_runtime.install_package
        def barrier(manifest,computed,package):
            from services.initialization import RUNTIME
            from services.storage import write
            write(RUNTIME/'runs'/manifest['run_id']/'utility/test-after-commit.json',{'run_id':manifest['run_id']},True)
            until=time.monotonic()+120
            while time.monotonic()<until:time.sleep(.05)
            return original(manifest,computed,package)
        publication_runtime.install_package=barrier
    uvicorn.run('services.api:app',host='127.0.0.1',port=int(os.environ['GRID_TEST_SERVER_PORT']),log_level='warning')


if __name__=='__main__':main()
