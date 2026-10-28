# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Pure content extraction for the isolated worker. Never fetches or opens files.

No detector result is an execution capability. The only accepted input is a
bounded byte string; the only output is static text and inspection metadata.
"""
import io,json,stat,zipfile
from pathlib import PurePosixPath
MAX_FILE=512*1024
MAX_TEXT=24000
PARSER_VERSION='axr-content-2.0.0'
class ContentError(ValueError):pass

def _archive(content):
    if not content.startswith((b'PK\x03\x04',b'PK\x05\x06')):raise ContentError('attachment_format_mismatch')
    archive=zipfile.ZipFile(io.BytesIO(content));entries=archive.infolist();names=set()
    try:
        if len(entries)>256 or sum(e.file_size for e in entries)>8*1024*1024:raise ContentError('attachment_archive_budget')
        for e in entries:
            if e.orig_filename!=e.filename:raise ContentError('attachment_archive_noncanonical_path')
            path=PurePosixPath(e.filename)
            if (e.filename in names or path.is_absolute() or '..' in path.parts or '\\' in e.filename or ':' in e.filename or
                    len(e.filename)>512 or any(ord(c)<32 for c in e.filename) or
                    stat.S_ISLNK(e.external_attr>>16) or e.flag_bits&1 or e.file_size>2*1024*1024 or
                    e.file_size>max(1,e.compress_size)*100):raise ContentError('attachment_archive_budget')
            names.add(e.filename)
        return archive
    except BaseException:archive.close();raise

def _xml(content):
    from defusedxml import ElementTree
    if len(content)>2*1024*1024:raise ContentError('attachment_xml_budget')
    return ElementTree.fromstring(content)

def extract_safe_text(content,filename,*,_depth=0,_remaining=None):
    if not isinstance(content,bytes) or len(content)>MAX_FILE:raise ContentError('attachment_file_budget')
    if not isinstance(filename,str) or len(filename)>255 or '\x00' in filename:raise ContentError('attachment_filename_invalid')
    suffix=PurePosixPath(filename).suffix.lower()
    if content.startswith((b'MZ',b'\x7fELF',b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xd0\xcf\x11\xe0')):
        raise ContentError('attachment_binary_quarantined')
    removed=[];kind='document';remaining=_remaining or [8*1024*1024]
    remaining[0]-=len(content)
    if remaining[0]<0:raise ContentError('attachment_archive_budget')
    if suffix in {'.txt','.md','.csv','.json','.py','.sh','.ps1','.js','.ts','.rb','.bat','.cmd'}:
        if content.startswith((b'PK\x03\x04',b'%PDF-')):raise ContentError('attachment_format_mismatch')
        value=content.decode('utf-8-sig',errors='strict')
        if '\x00' in value:raise ContentError('attachment_binary_quarantined')
        kind='code-as-data' if suffix in {'.py','.sh','.ps1','.js','.ts','.rb','.bat','.cmd'} else 'text'
    elif suffix in {'.docx','.xlsx','.pptx'}:
        with _archive(content) as archive:
            names=archive.namelist()
            if any(x.lower().endswith(('vbaproject.bin','.exe','.dll','.js','.vbs')) or '/activex/' in x.lower() or '/embeddings/' in x.lower() for x in names):
                raise ContentError('attachment_active_content_quarantined')
            if suffix=='.docx':
                if 'word/document.xml' not in names:raise ContentError('attachment_format_mismatch')
                root=_xml(archive.read('word/document.xml'))
                ns='{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
                value='\n'.join(''.join(p.itertext()) for p in root.iter(ns+'p'))
            elif suffix=='.pptx':
                slides=sorted(n for n in names if n.startswith('ppt/slides/slide') and n.endswith('.xml'))
                if not slides or len(slides)>50:raise ContentError('attachment_presentation_budget')
                value='\n'.join(' '.join(n.text or '' for n in _xml(archive.read(p)).iter() if n.tag.endswith('}t')) for p in slides)
            else:
                sheets=sorted(n for n in names if n.startswith('xl/worksheets/sheet') and n.endswith('.xml'))
                if not sheets or len(sheets)>50:raise ContentError('attachment_spreadsheet_budget')
                strings=[]
                if 'xl/sharedStrings.xml' in names:
                    strings=[''.join(n.itertext()) for n in _xml(archive.read('xl/sharedStrings.xml'))]
                parts=[]
                for name in sheets:
                    for row in _xml(archive.read(name)):
                        for cell in row.iter():
                            if not cell.tag.endswith('}c'):continue
                            # Formulas are never evaluated. Only cached/static values.
                            values=[n.text or '' for n in cell.iter() if n.tag.endswith(('}v','}t'))]
                            if cell.attrib.get('t')=='s':
                                values=[strings[int(v)] if v.isdigit() and int(v)<len(strings) else '' for v in values]
                            parts.append(' '.join(values))
                value='\n'.join(parts)
            if any(n.endswith('.rels') for n in names):removed.append('external-relationships-not-loaded')
    elif suffix=='.pdf':
        if not content.startswith(b'%PDF-'):raise ContentError('attachment_format_mismatch')
        from pypdf import PdfReader
        reader=PdfReader(io.BytesIO(content),strict=True)
        if reader.is_encrypted or len(reader.pages)>50:raise ContentError('attachment_pdf_budget_or_encrypted')
        root=reader.trailer['/Root']
        if any(k in root for k in ('/OpenAction','/AA','/AcroForm')):removed.append('document-actions-not-executed')
        if '/Names' in root:removed.append('named-resources-not-loaded')
        parts=[];size=0
        for page in reader.pages:
            text=page.extract_text() or '';parts.append(text);size+=len(text.encode())
            if size>MAX_TEXT:break
        value='\n'.join(parts)
    elif suffix=='.zip':
        if _depth>=3:raise ContentError('attachment_archive_depth')
        parts=[]
        with _archive(content) as archive:
            for entry in archive.infolist():
                if entry.is_dir():continue
                if entry.file_size>MAX_FILE:raise ContentError('attachment_file_budget')
                nested=extract_safe_text(archive.read(entry),PurePosixPath(entry.filename).name,_depth=_depth+1,_remaining=remaining)
                parts.append(entry.filename+'\n'+nested['text'])
                if sum(len(x.encode()) for x in parts)>MAX_TEXT:break
        value='\n\n'.join(parts);kind='archive-static-text'
    else:raise ContentError('attachment_format_unsupported')
    encoded=value.encode('utf8')
    return {'text':encoded[:MAX_TEXT].decode('utf8','ignore'),'truncated':len(encoded)>MAX_TEXT,'format':suffix[1:],
            'representation':'static-text','content_kind':kind,'execution_allowed':False,'remote_resources_loaded':False,
            'removed_features':removed,'parser_version':PARSER_VERSION}
