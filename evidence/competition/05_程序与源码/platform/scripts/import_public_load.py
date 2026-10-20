"""Import an attributed public load week; raw and per-customer values stay outside the repo."""
import csv
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.initialization import RUNTIME, ROOT
from services.encoding import digest
from services.storage import write

URL = 'https://archive.ics.uci.edu/static/public/321/electricityloaddiagrams20112014.zip'
PAGE = 'https://archive.ics.uci.edu/dataset/321/electricityloadformatting'

def main():
    directory = RUNTIME / 'datasets/uci321'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive = directory / 'original.zip'
    if not archive.exists():
        temporary = directory / 'original.zip.part'
        total = 0
        with urllib.request.urlopen(URL, timeout=60) as response, temporary.open('wb') as out:
            while block := response.read(4 * 1024 * 1024):
                out.write(block)
                total += len(block)
                if total % (32 * 1024 * 1024) == 0:
                    print(f'Downloaded {total // 1048576} MiB', flush=True)
        temporary.replace(archive)
    raw_hash = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
    start = datetime(2013, 6, 3, tzinfo=ZoneInfo('Europe/Lisbon'))
    end = start + timedelta(days=7)
    records, labels = [], []
    with zipfile.ZipFile(archive) as zipped:
        member = next(name for name in zipped.namelist() if name.endswith('LD2011_2014.txt') and not name.startswith('__MACOSX'))
        with io.TextIOWrapper(zipped.open(member), encoding='utf-8-sig') as stream:
            header = next(csv.reader([next(stream)], delimiter=';'))
            columns = header[1:]
            assert len(columns) == 370
            for line in stream:
                # Skip years before the selected week without parsing 370 numeric columns.
                timestamp = line.split(';', 1)[0].strip('"\r\n')
                local = datetime.fromisoformat(timestamp).replace(tzinfo=ZoneInfo('Europe/Lisbon'))
                if local <= start:
                    continue
                if local > end:
                    break
                row = next(csv.reader([line], delimiter=';'))
                values = [int((Decimal(value.replace(',', '.')) * 1000).quantize(Decimal('1'), rounding=ROUND_HALF_UP)) for value in row[1:]]
                assert len(values) == 370 and all(0 <= value <= 10**9 for value in values)
                records.append(values)
                labels.append(local.astimezone(timezone.utc))
    assert len(records) == 7 * 96
    assert all(b - a == timedelta(minutes=15) for a, b in zip(labels, labels[1:]))
    def fmt(value):
        return value.isoformat(timespec='seconds').replace('+00:00', 'Z')
    nodes = []
    for index, original_id in enumerate(columns):
        region = 'A' if index < 185 else 'B'
        offset = index % 185
        resource = 'residential' if offset < 74 else 'commercial' if offset < 136 else 'charging'
        nodes.append({'node_id': f'PUB-{region}-{offset:04d}', 'region': region, 'resource_class': resource,
                      'original_column': original_id, 'values_W': [row[index] for row in records]})
    data = {'dataset_id': 'UCI370-WEEK-20130603-V1', 'node_count': 370, 'slot_count': 672, 'nodes': nodes,
            'slots': [{'slot_id': f'period-{i:04d}', 'slot_start': fmt(value - timedelta(minutes=15)), 'slot_end': fmt(value)} for i, value in enumerate(labels)],
            'unit': 'W', 'source': 'PUBLIC_OBSERVED_SIMULATED_GROUPS', 'raw_sha256': raw_hash,
            'reading_origin': 'UCI observed load; rounded from kW to integer W',
            'grouping_origin': 'SIMULATED region and resource class; not original customer attributes'}
    data['dataset_digest'] = digest(data)
    write(directory / 'week.json', data, True)
    manifest = {'schema': 'GRID_PUBLIC_DATA_IMPORT_V1', 'dataset_id': data['dataset_id'], 'node_count': 370,
                'slot_count': 672, 'point_count': 370 * 672, 'source_page': PAGE, 'download_url': URL,
                'citation': 'Trindade, A. (2015). ElectricityLoadDiagrams20112014. UCI Machine Learning Repository. DOI:10.24432/C58C86',
                'license': 'CC BY 4.0', 'license_url': 'https://creativecommons.org/licenses/by/4.0/',
                'raw_sha256': raw_hash, 'raw_bytes': archive.stat().st_size, 'dataset_digest': data['dataset_digest'],
                'selected_local_start': start.isoformat(), 'selected_local_end': end.isoformat(), 'timezone': 'Europe/Lisbon',
                'original_timestamp_semantics': 'interval end; selected June week has no DST transition',
                'conversion': 'Decimal(kW)*1000 rounded to nearest W using ROUND_HALF_UP; reject negatives or values above 1e9 W',
                'labels': data['grouping_origin'], 'raw_and_customer_values': 'private runtime only; excluded from gateway and public exports',
                'importer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    write(ROOT / 'references/datasets/uci321/import.json', manifest)
    print(json.dumps(manifest, ensure_ascii=False), flush=True)

if __name__ == '__main__':
    main()
