"""Decode the delivered recordings and extract frames for separate visual review."""
import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('--ffmpeg',required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
frames=root/'artifacts/screenshots/media-qa'
frames.mkdir(parents=True,exist_ok=True)
records=[]
for minutes,name,record_name,positions in (
    (5,'五分钟真实操作实录.webm','video_recording.json',(255,285)),
    (8,'八分钟自动流程彩排.webm','rehearsal_8min.json',(145,370,460)),
    (3,'三分钟自动流程彩排.webm','rehearsal_3min.json',(90,165)),
):
    path=root/'materials/video'/name
    record=json.loads((root/'artifacts/tests'/record_name).read_text(encoding='utf-8'))
    assert record['exit_code']==0 and record['duration_ms']>=minutes*60000
    probe=subprocess.run([args.ffmpeg,'-hide_banner','-i',str(path)],capture_output=True,text=True,timeout=30,encoding='utf-8',errors='replace')
    match=re.search(r'Duration: (\d+):(\d+):(\d+(?:\.\d+)?)',probe.stderr)
    assert match,probe.stderr[-1000:]
    seconds=int(match[1])*3600+int(match[2])*60+float(match[3])
    assert abs(seconds-record['duration_ms']/1000)<3
    assert '1366x768' in probe.stderr and 'Video: vp9' in probe.stderr
    files=[]
    for at in positions:
        output=frames/f'video-{minutes}min-{at}s.png'
        process=subprocess.run([args.ffmpeg,'-hide_banner','-loglevel','error','-ss',str(at),'-i',str(path),'-frames:v','1','-y',str(output)],capture_output=True,text=True,timeout=30)
        assert process.returncode==0 and output.stat().st_size>10000
        files.append(str(output.relative_to(root)).replace('\\','/'))
    records.append({'file':str(path.relative_to(root)).replace('\\','/'),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'duration_seconds':seconds,'operation_record_duration_ms':record['duration_ms'],'core_source_digest':record['core_source_digest'],'extracted_frames':files,'scope':record['scope']})
assert len({r['core_source_digest'] for r in records})==1
result={'schema':'GRID_RECORDING_DECODE_QA_V1','finished_at':datetime.now(timezone.utc).isoformat(),'recordings':records,'ffmpeg_sha256':hashlib.sha256(Path(args.ffmpeg).read_bytes()).hexdigest(),'visual_inspection':'Frames extracted for separate Agent inspection; this script does not judge appearance or human narration','exit_code':0}
(root/'artifacts/tests/media_review.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
