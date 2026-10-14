"""Archive validation. No report data in this module."""
from pathlib import PurePosixPath
import stat

def archive_members(archive,max_bytes=3_000_000_000):
    members=archive.infolist();seen=set();total=0
    for member in members:
        name=member.filename;path=PurePosixPath(name)
        if (not name or '\\' in name or ':' in name or path.is_absolute()
            or '..' in path.parts or str(path) in seen
            or stat.S_ISLNK(member.external_attr>>16)):
            raise ValueError('Unsafe or duplicate archive member')
        seen.add(str(path));total+=member.file_size
        if total>max_bytes:raise ValueError('Archive exceeds allowed size')
    return members
