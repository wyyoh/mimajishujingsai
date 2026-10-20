"""Use the packaged DOCX rasterize pipeline with installed Word as the conversion backend.

Bundled LibreOffice/Poppler are unavailable on this host; the skill is imported
unchanged. Conversion uses a new hidden Word instance and rasterization uses PDFium.
"""
import argparse
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import pypdfium2 as pdfium

parser=argparse.ArgumentParser()
parser.add_argument('input')
parser.add_argument('--output',required=True)
parser.add_argument('--skill',required=True)
args=parser.parse_args()
spec=importlib.util.spec_from_file_location('packaged_docx_renderer',Path(args.skill)/'render_docx.py')
renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
root=Path(__file__).resolve().parents[1]

def convert(input_path,user_profile,convert_tmp_dir,stem,verbose=False):
    output=Path(convert_tmp_dir)/(stem+'.pdf')
    result=subprocess.run(['pwsh.exe','-NoProfile','-NonInteractive','-File',str(root/'scripts/export_word.ps1'),
                           '-InputPath',str(input_path),'-OutputPath',str(output)],capture_output=True,text=True,timeout=90)
    if result.returncode:raise RuntimeError(result.stdout+result.stderr)
    return str(output),result.stdout

def raster(pdf_path,dpi,fmt,thread_count,output_folder,paths_only,output_file):
    paths=[]
    document=pdfium.PdfDocument(pdf_path)
    for i in range(len(document)):
        path=Path(output_folder)/f'page0001-{i+1:02d}.png'
        document[i].render(scale=dpi/72).to_pil().save(path);paths.append(str(path))
    return paths

renderer.convert_to_pdf=convert
renderer.convert_from_path=raster
paths=renderer.rasterize(str(Path(args.input).resolve()),str(Path(args.output).resolve()),120,False,True)
record={'backend':'Microsoft Word COM hidden instance + PDFium; packaged renderer.rasterize imported unchanged',
        'input':str(Path(args.input).resolve()),'pages':len(paths),'page_images':paths}
Path(args.output,'render_record.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'pages':len(paths),'output':args.output}))
