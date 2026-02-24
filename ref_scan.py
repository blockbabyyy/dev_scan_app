#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ref_scan.py — Ground-truth reference validator for DevScan.

Implements the same signature logic as signatures.json / Scanner.cpp in pure
Python and produces counts for the 4 test targets:
  2026/   001.zip   280.zip   001.pcap

For folder/ZIP targets: anchored scan (signature at file start), one match
per file per type, same as DevScanApp in normal mode.

For PCAP:  two reference modes are shown side by side:
  [per-pkt]  — parse packets, classify each payload from its start.
               Semantic ground truth: «how many packets carry each file type».
  [full-blob] — search the entire PCAP binary with Python re (same approach
               as DevScanApp: unanchored, count every occurrence).
"""

import re, struct, zipfile, tempfile, shutil, subprocess, os, sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(r'C:\projects\dev_scan_app')
APP  = ROOT / 'out' / 'bin' / 'DevScanApp.exe'

# -----------------------------------------------------------------
# Magic-byte constants (mirrors signatures.json)
# -----------------------------------------------------------------
OLE_HDR  = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'  # DOC/XLS/PPT container
ZIP_HDR  = b'PK\x03\x04'                          # ZIP / DOCX / XLSX / PPTX

# UTF-16LE OLE stream names
DOC_STR  = b'W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00'
XLS_STR  = b'W\x00o\x00r\x00k\x00b\x00o\x00o\x00k\x00'
PPT_STR  = (b'P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t\x00'
            b' \x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00')

# -----------------------------------------------------------------
# Anchored file classifier
# Reproduces build_pattern(anchored=true) + Scanner::scan(count_all=false)
# Returns a set of type names that match the given buffer.
# -----------------------------------------------------------------
def classify_anchored(data: bytes) -> set:
    t = set()
    n = len(data)

    # -- OLE family ----------------------------------------------
    if n >= 512 and data[:8] == OLE_HDR:
        t.add('OLE')
        if n >= 4096:
            if DOC_STR in data: t.add('DOC')
            if XLS_STR in data: t.add('XLS')
            if PPT_STR in data: t.add('PPT')

    # -- ZIP family ----------------------------------------------
    if n >= 22 and data[:4] == ZIP_HDR:
        t.add('ZIP')
        if n >= 1024:
            if b'word/document.xml'   in data: t.add('DOCX')
            if b'xl/workbook.xml'     in data: t.add('XLSX')
            if b'ppt/presentation.xml' in data: t.add('PPTX')

    # -- Binary singletons ----------------------------------------
    if n >= 64    and data[:4]  == b'%PDF':                   t.add('PDF')
    if n >= 32    and data[:8]  == b'Rar!\x1a\x07\x01\x00':  t.add('RAR5')
    elif n >= 32  and data[:7]  == b'Rar!\x1a\x07\x00':      t.add('RAR4')
    if n >= 33    and data[:8]  == b'\x89PNG\r\n\x1a\n':      t.add('PNG')
    if n >= 200   and data[:3]  == b'\xff\xd8\xff':           t.add('JPG')
    if n >= 26    and data[:4]  == b'GIF8':                   t.add('GIF')
    # BMP: signature = BM + 4-byte file-size + 2-byte reserved1=0 + 2-byte reserved2=0
    if n >= 54    and data[:2]  == b'BM' and data[6:10] == b'\x00\x00\x00\x00':
        t.add('BMP')
    if n >= 100   and data[:4]  == b'\x1aE\xdf\xa3':          t.add('MKV')
    if n >= 10000 and data[:3]  == b'ID3':                    t.add('MP3')
    if n >= 32    and data[:6]  == b'7z\xbc\xaf\x27\x1c':    t.add('7Z')
    if n >= 100   and data[:3]  == b'\x1f\x8b\x08':           t.add('GZIP')
    if n >= 1024  and data[:2]  == b'MZ' and b'PE\x00\x00' in data:
        t.add('PE')
    if n >= 512   and data[:16] == b'SQLite format 3\x00': t.add('SQLITE')
    if n >= 100   and data[:4]  == b'fLaC':                   t.add('FLAC')
    if n >= 44    and data[:4]  == b'RIFF' and data[8:12] == b'WAVE':
        t.add('WAV')

    # -- Text signatures -----------------------------------------
    try:
        head_txt = data[:4096].decode('utf-8', errors='replace')
        s = head_txt.lstrip()
        if n >= 10  and re.match(r'\{\s*"[^"]+"\s*:', head_txt[:300]):
            t.add('JSON')
        if n >= 50  and re.search(r'<html', head_txt[:500], re.I) \
                    and re.search(r'</html>', head_txt, re.I):
            t.add('HTML')
        if n >= 20  and s[:5] == '<?xml':
            t.add('XML')
        if n >= 100 and re.match(
                r'From:\s.+\r?\n(?:To|Subject|Date|MIME-Version):', head_txt):
            t.add('EMAIL')
    except Exception:
        pass

    return t


# -----------------------------------------------------------------
# Deduction + exclusive filter  (mirrors apply_deduction /
# apply_exclusive_filter in Scanner.cpp)
# -----------------------------------------------------------------
DEDUCT = {
    'DOC': 'OLE', 'XLS': 'OLE', 'PPT': 'OLE',
    'DOCX': 'ZIP', 'XLSX': 'ZIP', 'PPTX': 'ZIP',
}
# (loser, winner) — loser is removed when winner also present
EXCLUSIVE = [('RAR4', 'RAR5')]


def apply_deduction(m: dict):
    for child, parent in DEDUCT.items():
        if child in m and parent in m:
            m[parent] = max(0, m[parent] - m[child])

def apply_exclusive(m: dict):
    for loser, winner in EXCLUSIVE:
        if loser in m and winner in m:
            del m[loser]


# -----------------------------------------------------------------
# Office system-file filter  (mirrors is_office_system_file in Scanner.h)
# -----------------------------------------------------------------
MEDIA_DIRS  = ('word/media/', 'xl/media/', 'ppt/media/')
SYSTEM_DIRS = ('word/', 'xl/', 'ppt/', 'docProps/', 'customXml/', '_rels/')
# Root-level system files that are always skipped in Office containers
SYSTEM_ROOT_FILES = {'[Content_Types].xml', '.rels'}

def is_office_system(rel: str) -> bool:
    rel = rel.replace('\\', '/')
    if rel in SYSTEM_ROOT_FILES: return True
    for md in MEDIA_DIRS:
        if rel.startswith(md): return False   # media = user content, keep
    for sd in SYSTEM_DIRS:
        if rel.startswith(sd): return True
    if '/_rels/' in rel or rel.endswith('.rels') or rel.endswith('.xml.rels'):
        return True
    return False


# -----------------------------------------------------------------
# Scanner behaviour constants  (mirrors Scanner.h / main_cli.cpp)
# NOTE: RAR and 7Z are NOT extracted (same limitation as DevScanApp).
# -----------------------------------------------------------------
MAX_CONTAINER_DEPTH    = 5
MAX_CONTAINER_ENTRIES  = 1000
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024   # 100 MB


def extract_zip(src: Path, dst: Path, is_office: bool) -> list:
    """Extract ZIP (or Office Open XML) respecting entry count + size limits.
    Mirrors extract_zip_entries() in main_cli.cpp."""
    extracted = []
    try:
        with zipfile.ZipFile(src, 'r') as zf:
            entries = [e for e in zf.infolist() if not e.is_dir()]
            if len(entries) > MAX_CONTAINER_ENTRIES:
                return extracted   # too many entries — skip whole archive
            total = 0
            for entry in entries:
                rel = entry.filename.replace('\\', '/')
                if is_office and is_office_system(rel):
                    continue
                if total + entry.file_size > MAX_UNCOMPRESSED_BYTES:
                    break          # uncompressed size limit reached
                try:
                    out = dst / entry.filename
                    out.parent.mkdir(parents=True, exist_ok=True)
                    data = zf.read(entry.filename)
                    out.write_bytes(data)
                    extracted.append(out)
                    total += entry.file_size
                except Exception:
                    pass
    except Exception:
        pass
    return extracted


# -----------------------------------------------------------------
# Recursive scanner for folders / ZIP archives
# NOTE: RAR and 7Z containers are detected but NOT recursed into,
#       matching DevScanApp behaviour (to-do #5 — not yet implemented).
# -----------------------------------------------------------------

def scan_file(path: Path, depth: int,
              standalone: dict, embedded: dict,
              in_container: bool, tmp_roots: list):
    try:
        n = path.stat().st_size
        if n == 0: return
        data = path.read_bytes()
    except Exception:
        return

    types = classify_anchored(data)
    if not types: return

    target = embedded if in_container else standalone
    for tp in types:
        target[tp] = target.get(tp, 0) + 1

    if depth >= MAX_CONTAINER_DEPTH: return

    # Recurse only into ZIP-family containers (RAR/7Z not extracted — mirrors scanner)
    is_zip_family = bool(types & {'ZIP', 'DOCX', 'XLSX', 'PPTX'})
    if not is_zip_family: return

    is_office = bool(types & {'DOCX', 'XLSX', 'PPTX'})
    tmp = Path(tempfile.mkdtemp(prefix='ref_'))
    tmp_roots.append(tmp)
    for child in extract_zip(path, tmp, is_office=is_office):
        scan_file(child, depth + 1, standalone, embedded,
                  in_container=True, tmp_roots=tmp_roots)


def scan_folder(root: Path):
    standalone, embedded, tmp_roots = {}, {}, []
    try:
        for entry in root.rglob('*'):
            if entry.is_file():
                scan_file(entry, 0, standalone, embedded,
                          in_container=False, tmp_roots=tmp_roots)
    finally:
        for t in tmp_roots: shutil.rmtree(t, ignore_errors=True)

    apply_deduction(standalone); apply_exclusive(standalone)
    apply_deduction(embedded);   apply_exclusive(embedded)
    return standalone, embedded


def scan_zip_true(path: Path):
    """True reference: read ALL entries from ZIP by magic bytes (no size limit).
    Each unique file is counted once. Shows what SHOULD be found."""
    embedded = {}
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            for info in zf.infolist():
                if info.is_dir(): continue
                try:
                    data = zf.read(info.filename)
                except Exception:
                    continue
                types = classify_anchored(data)
                for tp in types:
                    embedded[tp] = embedded.get(tp, 0) + 1
    except Exception:
        pass
    apply_deduction(embedded); apply_exclusive(embedded)
    # outer ZIP itself = 1 standalone
    standalone = {'ZIP': 1}
    return standalone, embedded


# -----------------------------------------------------------------
# PCAP parser
# -----------------------------------------------------------------
def read_pcap_packets(path: Path):
    """Yield raw packet payloads from a PCAP file."""
    with open(path, 'rb') as f:
        magic = struct.unpack('<I', f.read(4))[0]
        if magic == 0xa1b2c3d4:
            bo = '<'
        elif magic == 0xd4c3b2a1:
            bo = '>'
        else:
            return
        f.read(20)  # rest of global header
        while True:
            hdr = f.read(16)
            if len(hdr) < 16: break
            _, _, incl, _ = struct.unpack(bo + 'IIII', hdr)
            payload = f.read(incl)
            if len(payload) < incl: break
            yield payload


def scan_pcap_per_packet(path: Path):
    """Reference mode 1: classify each packet payload from its start.
    Semantics: «how many packets contain each file type»."""
    counts = {}
    for pkt in read_pcap_packets(path):
        for tp in classify_anchored(pkt):
            counts[tp] = counts.get(tp, 0) + 1
    apply_deduction(counts); apply_exclusive(counts)
    return counts


def _pcap_regex_counts(data: bytes) -> dict:
    """Reference mode 2: count pattern occurrences in the full PCAP binary
    using Python re — mirrors DevScanApp unanchored stream scan."""

    # Helper: find all non-overlapping matches in binary data
    def count_re(pat_bytes, flags=re.DOTALL):
        return len(re.findall(pat_bytes, data, flags))

    c = {}

    def add(name, n):
        if n > 0: c[name] = c.get(name, 0) + n

    # OLE family — head only  (stream names searched separately below)
    ole_positions = [m.start() for m in
                     re.finditer(re.escape(OLE_HDR), data)]
    add('OLE', len(ole_positions))
    doc_n = count_re(re.escape(OLE_HDR) + b'.*?' + re.escape(DOC_STR))
    xls_n = count_re(re.escape(OLE_HDR) + b'.*?' + re.escape(XLS_STR))
    ppt_n = count_re(re.escape(OLE_HDR) + b'.*?' + re.escape(PPT_STR))
    add('DOC', doc_n); add('XLS', xls_n); add('PPT', ppt_n)

    # ZIP family
    zip_n = count_re(re.escape(ZIP_HDR) + b'.*?' + re.escape(b'PK\x05\x06'))
    add('ZIP', zip_n)
    add('DOCX', count_re(re.escape(ZIP_HDR) + b'.*?' + re.escape(b'word/document.xml')))
    add('XLSX', count_re(re.escape(ZIP_HDR) + b'.*?' + re.escape(b'xl/workbook.xml')))
    add('PPTX', count_re(re.escape(ZIP_HDR) + b'.*?' + re.escape(b'ppt/presentation.xml')))

    # Binary singletons with tail
    add('PDF',  count_re(b'%PDF' + b'.*?' + b'%%EOF'))
    add('PNG',  count_re(re.escape(b'\x89PNG\r\n\x1a\n') + b'.*?' +
                         re.escape(b'IEND\xaeB`\x82')))
    add('JPG',  count_re(re.escape(b'\xff\xd8\xff') + b'.*?' +
                         re.escape(b'\xff\xd9')))
    add('GIF',  count_re(b'GIF8' + b'.*?' + b';'))

    # Binary head-only (simple count)
    def cnt_head(head): return data.count(head)
    add('RAR5', cnt_head(b'Rar!\x1a\x07\x01\x00'))
    add('RAR4', max(0, cnt_head(b'Rar!\x1a\x07\x00') -
                       cnt_head(b'Rar!\x1a\x07\x01\x00')))
    add('BMP',  count_re(b'BM.{4}\x00\x00\x00\x00'))
    add('MKV',  cnt_head(b'\x1aE\xdf\xa3'))
    add('MP3',  cnt_head(b'ID3'))
    add('7Z',   cnt_head(b'7z\xbc\xaf\x27\x1c'))
    add('GZIP', cnt_head(b'\x1f\x8b\x08'))
    add('PE',   count_re(re.escape(b'MZ') + b'.*?' + re.escape(b'PE\x00\x00')))
    add('SQLITE', cnt_head(b'SQLite format 3\x00'))
    add('FLAC', cnt_head(b'fLaC'))
    add('WAV',  count_re(re.escape(b'RIFF') + b'.*?' + re.escape(b'WAVE')))

    # Text signatures (search in UTF-8/Latin-1 decoded view)
    try:
        txt = data.decode('latin-1')
        add('JSON',  len(re.findall(r'\{\s*"[^"]+"\s*:', txt)))
        add('HTML',  len(re.findall(r'<html.*?</html>', txt, re.I | re.S)))
        add('XML',   len(re.findall(r'<\?xml', txt)))
        add('EMAIL', len(re.findall(
            r'From:\s.+\r?\n(?:To|Subject|Date|MIME-Version):', txt)))
    except Exception:
        pass

    apply_deduction(c); apply_exclusive(c)
    return c


# -----------------------------------------------------------------
# Run DevScanApp and parse its output
# -----------------------------------------------------------------
def run_scanner(target: Path) -> dict:
    """Returns {'standalone': {name: n}, 'embedded': {name: m}}"""
    try:
        r = subprocess.run(
            [str(APP), str(target), '--no-report'],
            capture_output=True, timeout=600,
            cwd=str(APP.parent),
            encoding='utf-8', errors='replace')
        output = r.stdout + r.stderr
    except Exception as e:
        print(f'  [scanner error] {e}')
        return {'standalone': {}, 'embedded': {}}

    standalone, embedded = {}, {}
    for line in output.splitlines():
        # "found 136 PDF (68 embedded)"  or  "found 12 DOCX"
        m = re.match(r'found\s+(\d+)\s+(\w+)(?:\s+\((\d+)\s+embedded\))?', line)
        if m:
            total = int(m.group(1))
            name  = m.group(2)
            emb   = int(m.group(3)) if m.group(3) else 0
            standalone[name] = total - emb
            if emb: embedded[name] = emb
    return {'standalone': standalone, 'embedded': embedded}


# -----------------------------------------------------------------
# Comparison table printer
# -----------------------------------------------------------------
W = 12

def _fmt(s, e):
    if s or e:
        base = str(s) if s else '-'
        return base + (f'({e}e)' if e else '')
    return '-'


def compare_table(ref_s, ref_e, scan_s, scan_e, label=''):
    keys = sorted(set(ref_s) | set(ref_e) | set(scan_s) | set(scan_e))
    header = f'{"TYPE":<8}  {"REF":>10}  {"SCANNER":>10}  STATUS'
    print(f'\n  {header}')
    print('  ' + '-' * 48)
    ok = fail = 0
    for k in keys:
        rs = ref_s.get(k, 0); re_ = ref_e.get(k, 0)
        ss = scan_s.get(k, 0); se  = scan_e.get(k, 0)
        ref_str  = _fmt(rs, re_)
        scan_str = _fmt(ss, se)
        if rs == ss and re_ == se:
            status = 'OK'; ok += 1
        else:
            status = f'DIFF'; fail += 1
        flag = '!' if status == 'DIFF' else ' '
        print(f'  {flag} {k:<8} {ref_str:>10}  {scan_str:>10}  {status}')
    print(f'  {"-"*48}')
    print(f'  Result: {ok} OK, {fail} DIFF\n')
    return fail


# -----------------------------------------------------------------
# Main
# -----------------------------------------------------------------
def section(title):
    print('\n' + '=' * 70)
    print(f'  {title}')
    print('=' * 70)


total_diff = 0

# -- 1. 2026/ folder ----------------------------------------------
section('1/4  FOLDER SCAN:  2026/')
path_2026 = ROOT / '2026'
print('  Computing reference …')
ref_s, ref_e = scan_folder(path_2026)
print('  Running DevScanApp …')
scan_out = run_scanner(path_2026)
scan_s, scan_e = scan_out['standalone'], scan_out['embedded']

print('\n  [Reference — magic-bytes anchored, recursive extraction]')
for k in sorted(set(ref_s) | set(ref_e)):
    rs = ref_s.get(k,0); re_ = ref_e.get(k,0)
    emb = f'  ({re_} emb)' if re_ else ''
    if rs or re_: print(f'    {k}: {rs}{emb}')

print('\n  [DevScanApp output]')
for k in sorted(set(scan_s) | set(scan_e)):
    ss = scan_s.get(k,0); se = scan_e.get(k,0)
    emb = f'  ({se} emb)' if se else ''
    if ss or se: print(f'    {k}: {ss}{emb}')

total_diff += compare_table(ref_s, ref_e, scan_s, scan_e)


def zip_section(label, path):
    """Common logic for ZIP targets. Explains scanner architecture issues."""
    section(f'ZIP SCAN:  {label}')
    print('  Computing TRUE reference (all entries, magic bytes, no size limit) ...')
    ref_s, ref_e = scan_zip_true(path)
    print('  Running DevScanApp ...')
    scan_out = run_scanner(path)
    scan_s, scan_e = scan_out['standalone'], scan_out['embedded']

    # Scanner shows total=standalone+embedded for each type.
    # Due to the dual-path architecture (pre-extract to file_paths + re-extract
    # in scan_chunk), each file inside the ZIP is counted TWICE:
    #   - once at depth=0  (standalone count)
    #   - once at depth=1  (embedded count, from scan_chunk re-extraction)
    # So scanner's  unique_found = scan_e[t]  (embedded = re-extracted = depth-1 count)
    # and          displayed_total = scan_s[t] + scan_e[t]  = 2 × unique_found
    print('\n  NOTE: Scanner double-counts ZIP contents (pre-extract depth=0 + re-extract')
    print('  depth=1 in scan_chunk). scanner_embedded = true unique count found within')
    print('  the 100 MB extraction limit. ref_embedded = true count (no limit).')

    print('\n  [True reference  — all files, no size limit]')
    for k in sorted(set(ref_s) | set(ref_e)):
        rs = ref_s.get(k,0); re_ = ref_e.get(k,0)
        emb = f'  ({re_} emb)' if re_ else ''
        if rs or re_: print(f'    {k}: {rs}{emb}')

    print('\n  [DevScanApp output  — with double-counting + 100 MB limit]')
    for k in sorted(set(scan_s) | set(scan_e)):
        ss = scan_s.get(k,0); se = scan_e.get(k,0)
        emb = f'  ({se} emb)' if se else ''
        if ss or se: print(f'    {k}: {ss + se}{emb}')

    # Compare ref_embedded vs scan_embedded (scanner_embedded = unique found within limit)
    print('\n  Comparing ref_emb (true unique) vs scanner_emb (found, within 100 MB limit):')
    keys = sorted(set(ref_e) | set(scan_e) | {'ZIP'})
    print(f'  {"TYPE":<8}  {"REF(true)":>10}  {"SCAN(emb)":>10}  {"COVERED%":>9}')
    print('  ' + '-' * 46)
    diffs = 0
    for k in keys:
        re_ = ref_e.get(k, 0)
        se  = scan_e.get(k, 0)
        if k == 'ZIP':
            rs = ref_s.get('ZIP', 0); ss = scan_s.get('ZIP', 0)
            if rs == ss: print(f'  {"ZIP":<8}  {"1":>10}  {"1":>10}  {"100%":>9}  OK')
            else: print(f'  ! {"ZIP":<7}  {rs:>10}  {ss:>10}  DIFF')
            diffs += (0 if rs == ss else 1)
            continue
        if re_ == 0 and se == 0: continue
        pct = f'{100*se//re_}%' if re_ > 0 else 'N/A'
        flag = ' ' if re_ == se else ('!' if se > re_ else ' ')
        note = 'OK' if re_ == se else ('overcount' if se > re_ else f'missing {re_-se}')
        print(f'  {flag} {k:<8}  {re_:>10}  {se:>10}  {pct:>9}  {note}')
        if re_ != se: diffs += 1
    return diffs

# -- 2. 001.zip ---------------------------------------------------
total_diff += zip_section('001.zip', ROOT / '001.zip')

# -- 3. 280.zip ---------------------------------------------------
total_diff += zip_section('280.zip', ROOT / '280.zip')


# -- 4. 001.pcap --------------------------------------------------
section('4/4  PCAP SCAN:  001.pcap')
path_pcap = ROOT / '001.pcap'
pcap_data  = path_pcap.read_bytes()

print('  Computing reference [per-packet] …')
ref_pkt = scan_pcap_per_packet(path_pcap)

print('  Computing reference [full-blob / Python re] …')
ref_blob = _pcap_regex_counts(pcap_data)

print('  Running DevScanApp …')
scan_out = run_scanner(path_pcap)
scan_s, scan_e = scan_out['standalone'], scan_out['embedded']

print('\n  [Reference per-packet]  |  [Reference full-blob]  |  [DevScanApp]')
keys_p = sorted(set(ref_pkt) | set(ref_blob) | set(scan_s) | set(scan_e))
print(f'  {"TYPE":<8}  {"per-pkt":>9}  {"full-blob":>10}  {"scanner":>9}')
print('  ' + '-' * 46)
for k in keys_p:
    pp = ref_pkt.get(k, 0)
    fb = ref_blob.get(k, 0)
    sc = scan_s.get(k, 0)
    print(f'  {k:<8}  {pp:>9}  {fb:>10}  {sc:>9}')

print()
print('  NOTE: per-packet counts each PCAP payload from its start (semantic).')
print('        full-blob/scanner search the entire PCAP binary for patterns')
print('        (can match across packet boundaries; counts may differ).')

print('\n  Comparing full-blob reference vs scanner:')
total_diff += compare_table(ref_blob, {}, scan_s, scan_e)


# -- Summary ------------------------------------------------------
print('=' * 70)
print(f'  TOTAL DIFFERENCES: {total_diff}')
print('=' * 70)
