"""One stable server runtime; swap the manifest last and serialize updates with readers."""
from pathlib import Path
from threading import RLock
import hashlib,io,json,os,shutil,sys,tempfile,zipfile
from security import archive_members

class RuntimeStore:
    def __init__(self):
        self.lock=RLock();self.root=Path(tempfile.mkdtemp(prefix='vitadairy-runtime-'));self.version=None

    def install(self,data,version):
        if self.version==version:return False
        with tempfile.TemporaryDirectory(prefix='vitadairy-stage-') as temp:
            stage=Path(temp)
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for member in archive_members(z):
                    path=stage/member.filename
                    if member.is_dir():path.mkdir(parents=True,exist_ok=True)
                    else:
                        path.parent.mkdir(parents=True,exist_ok=True)
                        with z.open(member) as src,path.open('wb') as dst:shutil.copyfileobj(src,dst)
            manifest=stage/'local/manifest.json'
            if not (stage/'app.py').is_file() or not manifest.is_file():raise ValueError('Incomplete payload')
            meta=json.loads(manifest.read_text(encoding='utf-8'));database=meta['database']
            if Path(database).name!=database or not (stage/'local'/database).is_file():raise ValueError('Missing database')
            files=[p for p in stage.rglob('*') if p.is_file() and p!=manifest]+[manifest]
            presentation_changed=False
            for src in files:
                dst=self.root/src.relative_to(stage)
                if dst.is_file() and hashlib.sha256(dst.read_bytes()).digest()==hashlib.sha256(src.read_bytes()).digest():continue
                # Asset registries and base64 images use module-level caches too.
                # An image-only release must invalidate them just like new code.
                presentation_changed|=src.suffix=='.py' or src.relative_to(stage).parts[0]=='assets'
                dst.parent.mkdir(parents=True,exist_ok=True)
                temp_dst=dst.with_name(dst.name+'.updating');shutil.copyfile(src,temp_dst);os.replace(temp_dst,dst)
            if presentation_changed:
                for name,module in list(sys.modules.items()):
                    location=getattr(module,'__file__',None)
                    if location and Path(location).is_relative_to(self.root):sys.modules.pop(name,None)
            self.version=version
            return presentation_changed
