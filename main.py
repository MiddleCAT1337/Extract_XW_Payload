from __future__ import annotations
import argparse
import base64
import hashlib
import json
import logging
import re
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional
try:
    import dnfile
    from dnfile.enums import CorFieldAttrFlags
except ImportError as e:
    raise SystemExit('Install dependencies: pip install dnfile pycryptodome') from e
from Crypto.Cipher import AES
for _dn_log in ('dnfile', 'dnfile.stream', 'dnfile.base', 'dnfile.utils'):
    logging.getLogger(_dn_log).setLevel(logging.CRITICAL)

def _set_dnfile_log_level(debug: bool) -> None:
    level = logging.WARNING if debug else logging.CRITICAL
    for name in ('dnfile', 'dnfile.stream', 'dnfile.base', 'dnfile.utils'):
        logging.getLogger(name).setLevel(level)
ELEMENT_TYPE_STRING = 14
B64_RE = re.compile('^[A-Za-z0-9+/]{8,}={0,2}$')
SEED_RE = re.compile('^[A-Za-z0-9]{8,32}$')
IP_RE = re.compile('^\\d{1,3}(\\.\\d{1,3}){3}$')
_FD_STATIC = int(CorFieldAttrFlags.fdStatic)
_FD_LITERAL = int(CorFieldAttrFlags.fdLiteral)

def _flag_int(flags) -> int:
    try:
        return int(flags)
    except (TypeError, ValueError):
        return 0

def field_is_config_candidate(flags) -> bool:
    if hasattr(flags, 'fdLiteral') and flags.fdLiteral:
        return True
    if hasattr(flags, 'fdStatic') and flags.fdStatic:
        return True
    fi = _flag_int(flags)
    return bool(fi & (_FD_STATIC | _FD_LITERAL))

@dataclass
class XWormConfig:
    path: str
    assembly: str = ''
    kind: str = ''
    config_type: str = ''
    mutex_seed: str = ''
    binder_mutex: str = ''
    embedded_from: str = ''
    drops: list[str] = field(default_factory=list)
    host: str = ''
    port: str = ''
    key: str = ''
    group: str = ''
    spl: str = ''
    decrypted: dict[str, str] = field(default_factory=dict)
    error: str = ''
    payload_from: str = ''

def iter_mdtable(pe: dnfile.dnPE, table_name: str) -> Iterable:
    md = getattr(getattr(pe, 'net', None), 'mdtables', None)
    if md is None:
        return
    table = getattr(md, table_name, None)
    if table is None:
        return
    yield from table

def _read_compressed_uint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError('truncated serstring')
    b0 = data[offset]
    if b0 & 128 == 0:
        return (b0, offset + 1)
    if b0 & 192 == 128:
        if offset + 1 >= len(data):
            raise ValueError('truncated serstring')
        return ((b0 & 63) << 8 | data[offset + 1], offset + 2)
    if offset + 4 >= len(data):
        raise ValueError('truncated serstring')
    return (struct.unpack_from('<I', data, offset + 1)[0], offset + 5)

def heap_blob_bytes(blob) -> bytes:
    if blob is None:
        return b''
    if isinstance(blob, (bytes, bytearray, memoryview)):
        return bytes(blob)
    if hasattr(blob, 'value'):
        inner = blob.value
        if isinstance(inner, (bytes, bytearray, memoryview)):
            return bytes(inner)
    if hasattr(blob, 'value_bytes'):
        raw = blob.value_bytes()
        if isinstance(raw, (bytes, bytearray, memoryview)):
            return bytes(raw)
    for attr in ('__data__', 'data'):
        if hasattr(blob, attr):
            raw = getattr(blob, attr)
            if isinstance(raw, (bytes, bytearray, memoryview)):
                return bytes(raw)
    if hasattr(blob, '__bytes__'):
        return bytes(blob)
    raise TypeError(f'unsupported blob type: {type(blob)!r}')

def _decode_serstring_utf8(blob: bytes, offset: int=0) -> Optional[str]:
    try:
        length, pos = _read_compressed_uint(blob, offset)
        raw = blob[pos:pos + length]
        return raw.decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        return None

def parse_constant_blob(blob, element_type: Optional[int]=None) -> Optional[str]:
    blob = heap_blob_bytes(blob)
    if not blob:
        return None
    et = int(element_type) if element_type is not None else None
    if blob[0] == ELEMENT_TYPE_STRING:
        return _decode_serstring_utf8(blob, 1)
    if et == ELEMENT_TYPE_STRING:
        s = _decode_serstring_utf8(blob, 0)
        if s is not None:
            return s
        return _decode_serstring_utf8(blob, 1)
    return None

def build_field_constant_map(pe: dnfile.dnPE) -> dict[int, str]:
    out: dict[int, str] = {}
    for const in iter_mdtable(pe, 'Constant'):
        parent = const.Parent
        if parent.table.name != 'Field':
            continue
        s = parse_constant_blob(const.Value, int(const.Type))
        if s is None:
            s = parse_constant_blob(const.Value, ELEMENT_TYPE_STRING)
        if s is not None and '\x00' not in s:
            out[int(parent.row_index)] = s
    return out

def _us_heap_data(us) -> bytes:
    for attr in ('_ClrStream__data__', '__data__', 'data'):
        raw = getattr(us, attr, None)
        if isinstance(raw, (bytes, bytearray, memoryview)):
            return bytes(raw)
    return b''

def iter_user_strings(pe: dnfile.dnPE) -> Iterable[str]:
    us = getattr(pe.net, 'user_strings', None) if pe.net else None
    if us is None:
        return
    data = _us_heap_data(us)
    if len(data) <= 1:
        return
    offset = 1
    while offset < len(data):
        try:
            byte_len, pos = _read_compressed_uint(data, offset)
        except ValueError:
            offset += 1
            continue
        if byte_len <= 0 or byte_len > 512 * 1024:
            offset += 1
            continue
        end = pos + byte_len
        if end >= len(data):
            offset += 1
            continue
        raw = data[pos:end]
        stride = pos - offset + byte_len + 1
        if stride <= 0 or offset + stride > len(data):
            offset += 1
            continue
        offset += stride
        if len(raw) % 2 != 0:
            continue
        try:
            text = raw.decode('utf-16le').strip()
        except UnicodeDecodeError:
            continue
        if text and '\x00' not in text:
            yield text

def harvest_pe_strings(raw: bytes, pe: Optional[dnfile.dnPE]) -> list[str]:
    found: set[str] = set()
    if pe is not None and getattr(pe, 'net', None):
        for s in iter_user_strings(pe):
            found.add(s)
        for s in build_field_constant_map(pe).values():
            if s and '\x00' not in s:
                found.add(s)
    for m in B64_IN_BIN.finditer(raw):
        try:
            found.add(m.group().decode('ascii'))
        except UnicodeDecodeError:
            continue
    for m in UTF16_ASCII.finditer(raw):
        try:
            found.add(m.group().decode('utf-16le').rstrip('\x00'))
        except UnicodeDecodeError:
            continue
    _b64_token = re.compile('[A-Za-z0-9+/]{8,}={0,2}')
    for s in harvest_utf16_runs(raw, _B64_CHARS, 16, 512):
        for tok in _b64_token.findall(s):
            if is_likely_b64(tok):
                found.add(tok)
        if is_likely_b64(s):
            found.add(s)
    for s in harvest_utf16_runs(raw, _SEED_CHARS, 14, 20):
        if is_likely_seed(s):
            found.add(s)
    for m in SEED_IN_BIN.finditer(raw):
        try:
            s = m.group(1).decode('ascii')
        except UnicodeDecodeError:
            continue
        if is_likely_seed(s):
            found.add(s)
    cleaned: list[str] = []
    for s in found:
        if not s or len(s) > 512:
            continue
        if s.startswith('System.') or s.startswith('Microsoft.'):
            continue
        if 'mscorlib' in s or ('Runtime' in s and len(s) > 40):
            continue
        cleaned.append(s)
    return cleaned

def derive_aes_key(seed: str) -> bytes:
    h = hashlib.md5(seed.encode('utf-8')).digest()
    key = bytearray(32)
    key[0:16] = h
    key[15:31] = h[0:16]
    return bytes(key)

def aes_ecb_decrypt_raw(ciphertext: bytes, key16: bytes) -> Optional[bytes]:
    if len(key16) < 16 or len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
        return None
    try:
        pt = AES.new(key16[:16], AES.MODE_ECB).decrypt(ciphertext)
    except ValueError:
        return None
    if not pt:
        return None
    pad = pt[-1]
    if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt[:-pad]

def aes_ecb_decrypt_b64(ciphertext_b64: str, seed: str) -> Optional[str]:
    try:
        ct = base64.b64decode(ciphertext_b64)
    except (ValueError, base64.binascii.Error):
        return None
    if len(ct) % 16 != 0:
        return None
    try:
        pt = AES.new(derive_aes_key(seed), AES.MODE_ECB).decrypt(ct)
    except ValueError:
        return None
    if not pt:
        return None
    pad = pt[-1]
    if pad < 1 or pad > 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    try:
        return pt[:-pad].decode('utf-8')
    except UnicodeDecodeError:
        return None

def is_likely_b64(s: str) -> bool:
    if not B64_RE.match(s):
        return False
    if '+' not in s and (not s.endswith('=')):
        if len(s) <= 24 and SEED_RE.match(s):
            return False
    try:
        base64.b64decode(s)
    except (ValueError, base64.binascii.Error):
        return False
    return len(s) >= 16

def is_likely_seed(s: str) -> bool:
    if not s or '\x00' in s:
        return False
    if not SEED_RE.match(s):
        return False
    if is_likely_b64(s):
        return False
    if len(s) > 20:
        return False
    low = s.lower()
    if low == 'abcdefghijklmnopqrstuvwxyz' or low.startswith('abcdefgh'):
        return False
    return True
B64_IN_BIN = re.compile(b'[A-Za-z0-9+/][A-Za-z0-9+/=]{14,}={0,2}')
UTF16_ASCII = re.compile(b'(?:[\\x20-\\x7e]\\x00){8,24}\\x00')
_B64_CHARS = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
_SEED_CHARS = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
SEED_IN_BIN = re.compile(b'(?<![A-Za-z0-9])([A-Za-z0-9]{14,18})(?![A-Za-z0-9])')

def harvest_utf16_runs(raw: bytes, charset: set[bytes], min_chars: int, max_chars: int) -> list[str]:
    out: list[str] = []
    i = 0
    n = len(raw)
    while i < n - 1:
        if raw[i + 1] != 0 or raw[i] not in charset:
            i += 1
            continue
        j = i
        buf = bytearray()
        while j < n - 1 and raw[j + 1] == 0 and (raw[j] in charset) and (len(buf) < max_chars):
            buf.append(raw[j])
            j += 2
        if len(buf) >= min_chars:
            try:
                out.append(buf.decode('ascii'))
            except UnicodeDecodeError:
                pass
        i = j if j > i else i + 1
    return out
BINDER_SPL = '-=>'
BINDER_LIST_RE = re.compile('([^\\s\\"\']+\\.exe)' + re.escape(BINDER_SPL) + '(True|False)' + re.escape(BINDER_SPL) + '(True|False)', re.IGNORECASE)

def is_xbinder_stub(harvested: list[str], raw: bytes) -> bool:
    if any((BINDER_SPL in s and '.exe' in s for s in harvested)):
        return True
    if BINDER_SPL.encode('ascii') in raw and b'.exe' in raw:
        return True
    if b'GetTheResource' in raw or b'AES_Decryptor' in raw:
        return True
    return False

def parse_binder_drop_list(harvested: list[str], raw: bytes) -> list[str]:
    drops: list[str] = []
    for s in harvested:
        for m in BINDER_LIST_RE.finditer(s):
            drops.append(m.group(1))
    if not drops:
        try:
            text = raw.decode('utf-16le', errors='ignore')
        except UnicodeDecodeError:
            text = ''
        for m in BINDER_LIST_RE.finditer(text):
            drops.append(m.group(1))
    return list(dict.fromkeys(drops))

def binder_mutex_candidates(harvested: list[str], drop_list: list[str]) -> list[str]:
    seeds = [s for s in harvested if is_likely_seed(s)]
    seeds.sort(key=lambda s: (len(s) != 16, s))
    return list(dict.fromkeys(seeds))

def iter_manifest_resource_blobs(pe: dnfile.dnPE) -> Iterable[tuple[str, bytes]]:
    try:
        resources = pe.net.resources
    except Exception:
        return
    if not resources:
        return
    for rsrc in resources:
        name = str(getattr(rsrc, 'name', '') or '')
        data = getattr(rsrc, 'data', None)
        entries = getattr(data, 'entries', None)
        if not entries:
            continue
        for entry in entries:
            ename = str(getattr(entry, 'name', None) or name or 'resource')
            val = getattr(entry, 'value', None)
            if isinstance(val, (bytes, bytearray)) and len(val) > 256:
                yield (ename, bytes(val))

def try_extract_xbinder(cfg: XWormConfig, pe: dnfile.dnPE, raw: bytes, harvested: list[str], depth: int) -> bool:
    if depth > 1 or not is_xbinder_stub(harvested, raw):
        return False
    cfg.kind = 'xbinder'
    cfg.drops = parse_binder_drop_list(harvested, raw)
    payloads = list(iter_manifest_resource_blobs(pe))
    if not payloads:
        cfg.error = 'xbinder stub: could not read embedded .resources'
        return False
    mutexes = binder_mutex_candidates(harvested, cfg.drops)
    if not mutexes:
        cfg.error = 'xbinder stub: no binder mutex candidate'
        return False
    for mutex in mutexes:
        key = hashlib.md5(mutex.encode('utf-8')).digest()
        for res_name, enc in payloads:
            plain = aes_ecb_decrypt_raw(enc, key)
            if not plain or plain[:2] != b'MZ':
                continue
            inner_label = f'{Path(cfg.path).name}!{res_name}'
            inner = extract_pe_bytes(plain, inner_label, depth + 1)
            if inner.host or inner.port or inner.key:
                cfg.binder_mutex = mutex
                cfg.embedded_from = res_name
                cfg.host = inner.host
                cfg.port = inner.port
                cfg.key = inner.key
                cfg.group = inner.group
                cfg.spl = inner.spl
                cfg.mutex_seed = inner.mutex_seed
                cfg.config_type = inner.config_type
                cfg.decrypted = inner.decrypted
                cfg.assembly = inner.assembly or cfg.assembly
                cfg.error = ''
                return True
    cfg.error = f'xbinder stub: decrypted {len(payloads)} resource(s) but no XWorm client config (mutex candidates: {len(mutexes)}, drops: {cfg.drops})'
    return False

def _traffic_key_score(token: str) -> int:
    if not (token.startswith('<') and token.endswith('>')):
        return -999
    inner = token[1:-1]
    if len(inner) <= 3 and set(inner) <= {'|', '<', '>'}:
        return -1
    score = min(len(inner), 12)
    if inner.isdigit():
        score += 20
    if any((c.isalpha() for c in inner)):
        score += 5
    return score

def classify_decrypted(values: Iterable[str]) -> tuple[str, str, str, str, str]:
    host = port = key = group = spl = ''
    bracket: list[str] = []
    for v in values:
        if not v:
            continue
        if v.isdigit() and 1 <= int(v) <= 65535 and (not port):
            port = v
            continue
        if IP_RE.match(v) or (re.match('^[A-Za-z0-9.\\-]+$', v) and '.' in v and (not v.endswith('.exe')) and ('%' not in v) and (len(v) < 64) and (not host)):
            host = v
            continue
        if v.startswith('<') and v.endswith('>'):
            bracket.append(v)
            continue
    if bracket:
        ranked = sorted(bracket, key=_traffic_key_score, reverse=True)
        for tok in ranked:
            if _traffic_key_score(tok) < 0:
                spl = tok
                break
        key_candidates = [t for t in ranked if _traffic_key_score(t) >= 0]
        if key_candidates:
            key = key_candidates[0]
        rest = [t for t in bracket if t not in (key, spl)]
        if rest:
            group = rest[0]
    return (host, port, key, group, spl)

def type_literal_strings(pe: dnfile.dnPE, field_constants: dict[int, str]) -> dict[str, list[tuple[str, str]]]:
    by_type: dict[str, list[tuple[str, str]]] = {}
    for td in iter_mdtable(pe, 'TypeDef'):
        name = str(td.TypeName)
        if name.startswith('<') or 'PrivateImplementationDetails' in name:
            continue
        items: list[tuple[str, str]] = []
        for fidx in td.FieldList:
            frow = fidx.row
            if not field_is_config_candidate(frow.Flags):
                continue
            val = field_constants.get(int(fidx.row_index))
            if val is None:
                continue
            items.append((str(frow.Name), val))
        if items:
            by_type[name] = items
    return by_type

def module_literal_pool(field_constants: dict[int, str]) -> list[tuple[str, str]]:
    return [(f'field_{idx}', val) for idx, val in sorted(field_constants.items())]

def brute_force_seed_blobs(seeds: list[str], blobs: list[str]) -> Optional[tuple[str, dict[str, str]]]:
    uniq_seeds = list(dict.fromkeys(seeds))
    uniq_blobs = list(dict.fromkeys(blobs))
    if not uniq_seeds or not uniq_blobs:
        return None
    best: Optional[tuple[str, dict[str, str], int]] = None
    for seed in uniq_seeds:
        decrypted: dict[str, str] = {}
        score = 0
        for i, val in enumerate(uniq_blobs):
            plain = aes_ecb_decrypt_b64(val, seed)
            if plain is None:
                continue
            decrypted[f'b{i}'] = plain
            if IP_RE.match(plain) or (plain.isdigit() and 1 <= int(plain) <= 65535):
                score += 2
            if plain.startswith('<') and plain.endswith('>'):
                score += 1
        if score >= 3 and (best is None or score > best[2]):
            best = (seed, decrypted, score)
    if not best:
        return None
    return (best[0], best[1])

def extract_from_literals(literals: list[tuple[str, str]]) -> Optional[tuple[str, str, dict[str, str]]]:
    seeds = [v for _, v in literals if is_likely_seed(v)]
    blobs = [v for _, v in literals if is_likely_b64(v)]
    got = brute_force_seed_blobs(seeds, blobs)
    if not got:
        return None
    seed, decrypted = got
    return (seed, '', decrypted)

def apply_extraction_result(cfg: XWormConfig, tname: str, seed: str, decrypted: dict[str, str], best_score: int) -> tuple[int, int]:
    host, port, key, group, spl = classify_decrypted(decrypted.values())
    score = sum((1 for x in (host, port, key) if x)) * 3 + len(decrypted)
    if score > best_score:
        cfg.config_type = tname
        cfg.mutex_seed = seed
        cfg.decrypted = decrypted
        cfg.host, cfg.port, cfg.key, cfg.group, cfg.spl = (host, port, key, group, spl)
        cfg.error = ''
        return (score, score)
    return (best_score, score)

def extract_pe_bytes(raw: bytes, display_path: str, depth: int=0) -> XWormConfig:
    cfg = XWormConfig(path=display_path)
    pe: Optional[dnfile.dnPE] = None
    try:
        pe = dnfile.dnPE(data=raw)
    except Exception as e:
        cfg.error = f'not a valid PE: {e}'
        return cfg
    if not getattr(pe, 'net', None) or pe.net.metadata is None:
        cfg.error = 'no .NET metadata (not a managed XWorm stub?)'
        return cfg
    for mod in iter_mdtable(pe, 'Module'):
        cfg.assembly = str(mod.Name).removesuffix('.exe').removesuffix('.dll')
    field_constants = build_field_constant_map(pe)
    by_type = type_literal_strings(pe, field_constants)
    harvested = harvest_pe_strings(raw, pe)
    candidates: list[tuple[str, list[tuple[str, str]]]] = []
    if harvested:
        candidates.append(('@pe_harvest', [(f'h{i}', s) for i, s in enumerate(harvested)]))
    candidates.extend(by_type.items())
    if field_constants:
        candidates.append(('@module', module_literal_pool(field_constants)))
    best_score = -1
    for tname, literals in candidates:
        if len(literals) < 3:
            continue
        got = extract_from_literals(literals)
        if not got:
            continue
        seed, _, decrypted = got
        best_score, _ = apply_extraction_result(cfg, tname, seed, decrypted, best_score)
    if not cfg.host:
        seeds = [s for s in harvested if is_likely_seed(s)]
        b64s = [s for s in harvested if is_likely_b64(s)]
        got = brute_force_seed_blobs(seeds, b64s)
        if got:
            seed, decrypted = got
            apply_extraction_result(cfg, '@pe_harvest', seed, decrypted, best_score)
            cfg.kind = cfg.kind or 'client'
        elif not try_extract_xbinder(cfg, pe, raw, harvested, depth):
            if not cfg.error:
                cfg.error = f'no XWorm config matched (harvested {len(harvested)} strings, {len(seeds)} seed candidates, {len(b64s)} base64 candidates)'
    else:
        cfg.kind = cfg.kind or 'client'
    return cfg
_PS_B64 = re.compile('-(?:enc(?:odedcommand)?|e)\\s+([A-Za-z0-9+/=]{20,})', re.IGNORECASE)
_BAT_B64_CHUNK = re.compile('[A-Za-z0-9+/=\\r\\n]{200,}')
_BAT_HEX_CHUNK = re.compile('(?:[0-9A-Fa-f]{2}){200,}')

def normalize_bat_text(text: str) -> str:
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = re.sub('\\^\\s*\\n', '', text)
    text = text.replace('^', '')
    return text

def _pe_slice(data: bytes) -> Optional[bytes]:
    idx = data.find(b'MZ')
    if idx < 0:
        return None
    return data[idx:]

def _try_decode_b64_chunk(chunk: str) -> list[bytes]:
    out: list[bytes] = []
    cleaned = re.sub('\\s+', '', chunk)
    if len(cleaned) < 120:
        return out
    pad = -len(cleaned) % 4
    if pad:
        cleaned += '=' * pad
    try:
        raw = base64.b64decode(cleaned, validate=False)
    except (ValueError, base64.binascii.Error):
        return out
    if len(raw) < 128:
        return out
    pe = _pe_slice(raw)
    if pe and len(pe) >= 128:
        out.append(pe)
    return out

def _try_decode_hex_chunk(chunk: str) -> list[bytes]:
    cleaned = re.sub('[^0-9A-Fa-f]', '', chunk)
    if len(cleaned) < 256 or len(cleaned) % 2:
        return []
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        return []
    pe = _pe_slice(raw)
    if pe and len(pe) >= 128:
        return [pe]
    return []

def harvest_bat_pe_payloads(text: str) -> list[tuple[str, bytes]]:
    norm = normalize_bat_text(text)
    found: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    def add(label: str, blob: bytes) -> None:
        pe = _pe_slice(blob)
        if not pe or len(pe) < 128:
            return
        sig = pe[:256]
        if sig in seen:
            return
        seen.add(sig)
        found.append((label, pe))
    for m in _PS_B64.finditer(norm):
        try:
            ps = base64.b64decode(m.group(1))
            script = ps.decode('utf-16le', errors='ignore')
        except (ValueError, UnicodeDecodeError):
            continue
        for i, pe in enumerate(harvest_bat_pe_payloads(script)):
            add(f'ps_enc#{i}', pe)
        for inner in _BAT_B64_CHUNK.findall(script):
            for pe in _try_decode_b64_chunk(inner):
                add('ps_script_b64', pe)
    for i, chunk in enumerate(_BAT_B64_CHUNK.findall(norm)):
        for pe in _try_decode_b64_chunk(chunk):
            add(f'b64#{i}', pe)
    for i, chunk in enumerate(_BAT_HEX_CHUNK.findall(norm)):
        for pe in _try_decode_hex_chunk(chunk):
            add(f'hex#{i}', pe)
    if b'TVq' in norm.encode('latin-1', errors='ignore'):
        for m in re.finditer('TVq[A-Za-z0-9+/=]{80,}', norm):
            for pe in _try_decode_b64_chunk(m.group(0)):
                add('tvq_inline', pe)
    return found

def extract_bat_file(path: Path) -> XWormConfig:
    cfg = XWormConfig(path=str(path), kind='bat')
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError as e:
        cfg.error = f'cannot read batch: {e}'
        return cfg
    payloads = harvest_bat_pe_payloads(text)
    if not payloads:
        cfg.error = 'batch: no embedded PE payload found (base64/hex/PowerShell -enc)'
        return cfg
    best: Optional[XWormConfig] = None
    best_score = -1
    for label, pe_bytes in payloads:
        inner = extract_pe_bytes(pe_bytes, f'{path.name}!{label}', depth=0)
        score = sum((3 for x in (inner.host, inner.port, inner.key) if x)) + len(inner.decrypted)
        if score > best_score:
            best_score = score
            best = inner
    if best is None or not (best.host or best.port or best.key):
        cfg.error = f'batch: found {len(payloads)} PE blob(s) but no XWorm config'
        return cfg
    cfg.kind = best.kind or 'client'
    cfg.assembly = best.assembly
    cfg.config_type = best.config_type
    cfg.mutex_seed = best.mutex_seed
    cfg.host = best.host
    cfg.port = best.port
    cfg.key = best.key
    cfg.group = best.group
    cfg.spl = best.spl
    cfg.decrypted = best.decrypted
    cfg.payload_from = best.path
    cfg.error = ''
    return cfg

def extract_file(path: Path) -> XWormConfig:
    if path.suffix.lower() in ('.bat', '.cmd'):
        return extract_bat_file(path)
    raw = path.read_bytes()
    return extract_pe_bytes(raw, str(path), depth=0)

def debug_pe(path: Path, cfg: Optional[XWormConfig]=None) -> None:
    if path.suffix.lower() in ('.bat', '.cmd'):
        if cfg is not None:
            print(f'--- {path.name} (batch) ---', file=sys.stderr)
            if cfg.payload_from:
                print(f'  payload_from: {cfg.payload_from}', file=sys.stderr)
            if cfg.error:
                print(f'  error: {cfg.error}', file=sys.stderr)
        text = path.read_text(encoding='utf-8', errors='ignore')
        payloads = harvest_bat_pe_payloads(text)
        print(f'embedded PE candidates: {len(payloads)}', file=sys.stderr)
        for label, blob in payloads[:8]:
            print(f'  {label}: {len(blob)} bytes', file=sys.stderr)
        return
    raw = path.read_bytes()
    pe = dnfile.dnPE(str(path))
    fmap = build_field_constant_map(pe)
    harvested = harvest_pe_strings(raw, pe)
    seeds = [s for s in harvested if is_likely_seed(s)]
    b64s = [s for s in harvested if is_likely_b64(s)]
    if cfg is not None:
        print(f'--- {path.name} ---', file=sys.stderr)
        if cfg.error:
            print(f'  error: {cfg.error}', file=sys.stderr)
        if cfg.kind:
            print(f'  kind: {cfg.kind}', file=sys.stderr)
        if cfg.assembly:
            print(f'  assembly: {cfg.assembly}', file=sys.stderr)
        if cfg.binder_mutex:
            print(f'  binder_mutex: {cfg.binder_mutex}', file=sys.stderr)
        if cfg.drops:
            print(f'  drops: {cfg.drops}', file=sys.stderr)
        if cfg.embedded_from:
            print(f'  embedded_from: {cfg.embedded_from}', file=sys.stderr)
        if cfg.config_type:
            print(f'  config_type: {cfg.config_type}', file=sys.stderr)
    print(f'field string constants (metadata): {len(fmap)}', file=sys.stderr)
    for idx, val in sorted(fmap.items())[:15]:
        preview = val if len(val) < 60 else val[:57] + '...'
        print(f'  Field[{idx}] = {preview!r}', file=sys.stderr)
    print(f'harvested strings: {len(harvested)}', file=sys.stderr)
    print(f'  seed candidates ({len(seeds)}): {seeds[:12]!r}', file=sys.stderr)
    print(f'  base64 candidates: {len(b64s)}', file=sys.stderr)
    for s in b64s[:12]:
        print(f'    b64: {s!r}', file=sys.stderr)
    by_type = type_literal_strings(pe, fmap)
    print(f'types with metadata literals: {len(by_type)}', file=sys.stderr)
    for tname, lits in sorted(by_type.items(), key=lambda x: -len(x[1]))[:5]:
        print(f'  {tname}: {len(lits)} literals', file=sys.stderr)

def traffic_key_md5(key_field: str) -> str:
    return hashlib.md5(key_field.encode('utf-8')).hexdigest()

def run_self_test() -> None:
    vectors = [('96XK7SHWyJNjE9Pg', 'Nf3mCo5mMvNFMR6eKNFvkA==', '85.203.4.222'), ('96XK7SHWyJNjE9Pg', 'DYfePhvuQW4koIT/C6nL5A==', '6000'), ('96XK7SHWyJNjE9Pg', 'ZmkB0K/IzHI03y7k7+duUQ==', '<666666>'), ('uB7cFNbcdraSiDrQ', 'jjpycIlNDxdgLEwNGUXlTA==', '185.84.161.148'), ('JLqoPz2Cm9pbQNvn', 'e1B3+sm2Mcq/OUxhonRnGQ==', '185.84.161.148')]
    for seed, b64, expect in vectors:
        got = aes_ecb_decrypt_b64(b64, seed)
        assert got == expect, (seed, b64, got, expect)
    blob = b'padding jjpycIlNDxdgLEwNGUXlTA== qoePRnbfQ6tMyCNsc8zecw== T3NJH6JEJITX1GjUX/mxSQ== seed=uB7cFNbcdraSiDrQ;'
    hs = harvest_pe_strings(blob, None)
    assert 'jjpycIlNDxdgLEwNGUXlTA==' in hs
    assert 'uB7cFNbcdraSiDrQ' in hs
    got = extract_from_literals([(f'x{i}', s) for i, s in enumerate(hs)])
    assert got is not None
    _, _, dec = got
    assert any((v == '185.84.161.148' for v in dec.values()))
    u16 = 'Nf3mCo5mMvNFMR6eKNFvkA=='.encode('utf-16le')
    u16 += 'DYfePhvuQW4koIT/C6nL5A=='.encode('utf-16le')
    u16 += 'ZmkB0K/IzHI03y7k7+duUQ=='.encode('utf-16le')
    u16 += '96XK7SHWyJNjE9Pg'.encode('utf-16le')
    hs2 = harvest_pe_strings(u16, None)
    assert 'Nf3mCo5mMvNFMR6eKNFvkA==' in hs2
    assert '96XK7SHWyJNjE9Pg' in hs2
    bf = brute_force_seed_blobs([s for s in hs2 if is_likely_seed(s)], [s for s in hs2 if is_likely_b64(s)])
    assert bf is not None
    _, dec2 = bf
    assert dec2.get('b0') == '85.203.4.222' or any((v == '85.203.4.222' for v in dec2.values()))
    print('self-test: OK', file=sys.stderr)

def main() -> int:
    ap = argparse.ArgumentParser(description='Extract IP/Port/Key from XWorm .NET client payloads')
    ap.add_argument('paths', nargs='*', help='.exe/.dll files or directories')
    ap.add_argument('--json', action='store_true', help='JSON lines output')
    ap.add_argument('--verbose', action='store_true', help='print all decrypted fields')
    ap.add_argument('--self-test', action='store_true', help='run built-in decrypt vectors')
    ap.add_argument('--debug', action='store_true', help='print metadata extraction diagnostics to stderr')
    args = ap.parse_args()
    _set_dnfile_log_level(args.debug)
    if args.self_test:
        run_self_test()
        return 0
    targets: list[Path] = []
    for p in args.paths or ['.']:
        path = Path(p)
        if path.is_dir():
            targets.extend(sorted(path.glob('*.exe')))
            targets.extend(sorted(path.glob('*.dll')))
            targets.extend(sorted(path.glob('*.bat')))
            targets.extend(sorted(path.glob('*.cmd')))
        elif path.is_file():
            targets.append(path)
    if not targets:
        print('No input files. Pass paths or --self-test.', file=sys.stderr)
        return 1
    exit_code = 0
    for t in targets:
        cfg = extract_file(t)
        if cfg.error and (not cfg.host):
            exit_code = 1
        if args.debug:
            debug_pe(t, cfg)
        has_extracted = bool(cfg.host or cfg.port or cfg.key)
        if not has_extracted and (not args.debug):
            continue
        if args.json:
            d = asdict(cfg)
            if not args.debug:
                d.pop('error', None)
                if not cfg.host:
                    continue
            print(json.dumps(d, ensure_ascii=False))
        elif args.debug:
            print(f'=== {Path(cfg.path).name} ===', file=sys.stderr)
            if cfg.kind == 'xbinder':
                print(f'  type:         Xbinder dropper', file=sys.stderr)
                if cfg.embedded_from:
                    print(f'  payload:      {cfg.embedded_from}', file=sys.stderr)
            if cfg.mutex_seed:
                print(f'  mutex_seed:   {cfg.mutex_seed}', file=sys.stderr)
            print(f"  Host:         {cfg.host or '?'}", file=sys.stderr)
            print(f"  Port:         {cfg.port or '?'}", file=sys.stderr)
            print(f"  Key:          {cfg.key or '?'}", file=sys.stderr)
            if cfg.group:
                print(f'  Group:        {cfg.group}', file=sys.stderr)
            if cfg.spl:
                print(f'  SPL:          {cfg.spl}', file=sys.stderr)
            if cfg.payload_from:
                print(f'  payload_from: {cfg.payload_from}', file=sys.stderr)
            if cfg.key:
                print(f'  traffic_md5:  {traffic_key_md5(cfg.key)}', file=sys.stderr)
            if cfg.decrypted and args.verbose:
                for k, v in sorted(cfg.decrypted.items()):
                    print(f'    {k}: {v}', file=sys.stderr)
            print(file=sys.stderr)
        else:
            label = Path(cfg.path).name
            print(f'=== {label} ===')
            if cfg.host:
                print(f'  Host:  {cfg.host}')
            if cfg.port:
                print(f'  Port:  {cfg.port}')
            if cfg.key:
                print(f'  Key:   {cfg.key}')
            if cfg.group:
                print(f'  Group: {cfg.group}')
            if cfg.spl:
                print(f'  SPL:   {cfg.spl}')
            if cfg.mutex_seed:
                print(f'  Mutex: {cfg.mutex_seed}')
            print()
    return exit_code
if __name__ == '__main__':
    raise SystemExit(main())
