# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Offline arm64 Mach-O evidence. Never loads an image or authorizes a call.

Addresses are unslid virtual addresses, not universal-file offsets. A matched
function fingerprint establishes code identity only, never a private ABI.
"""
import bisect
import hashlib
import struct
import uuid
from dataclasses import dataclass
from .aet import AXRError


@dataclass(frozen=True)
class Section:
    address: int
    size: int
    offset: int


class NativeImage:
    MAXIMUM_BYTES = 512 * 1024 * 1024

    def __init__(self, data):
        if not isinstance(data, bytes) or not 32 <= len(data) <= self.MAXIMUM_BYTES:
            raise AXRError('native_image_size_invalid')
        self.file_sha256 = hashlib.sha256(data).hexdigest()
        self.slice_offset = 0
        magic = data[:4]
        if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
            wide = magic[-1] == 0xbf
            count = struct.unpack_from('>I', data, 4)[0]
            stride = 32 if wide else 20
            if not 1 <= count <= 16 or 8 + count * stride > len(data):
                raise AXRError('native_fat_header_invalid')
            slices = []
            for i in range(count):
                fields = struct.unpack_from('>IIQQII' if wide else '>IIIII', data, 8 + i * stride)
                cpu, _, offset, size, align = fields[:5]
                if align > 30 or offset % (1 << align) or offset < 8 + count * stride or size < 32 or offset + size > len(data):
                    raise AXRError('native_fat_slice_invalid')
                if any(offset < end and start < offset + size for start, end, _ in slices):
                    raise AXRError('native_fat_overlap')
                slices.append((offset, offset + size, cpu))
            choices = [(a, z) for a, z, cpu in slices if cpu == 0x0100000c]
            if len(choices) != 1:
                raise AXRError('native_arm64_slice_missing_or_ambiguous')
            self.slice_offset, end = choices[0]
            data = data[self.slice_offset:end]
        if data[:4] != b'\xcf\xfa\xed\xfe' or struct.unpack_from('<I', data, 4)[0] != 0x0100000c:
            raise AXRError('native_arm64_macho_required')
        count, command_bytes = struct.unpack_from('<II', data, 16)
        if not 1 <= count <= 4096 or command_bytes > 1024 * 1024 or 32 + command_bytes > len(data):
            raise AXRError('native_load_commands_invalid')
        self.data = data
        self.sections = {}
        self.uuid = None
        self.starts = ()
        segments = []
        self._file_segments = []
        self._fixups = None
        self.image_base = None
        starts_data = None
        cur, limit = 32, 32 + command_bytes
        for _ in range(count):
            if cur + 8 > limit:
                raise AXRError('native_load_commands_invalid')
            cmd, length = struct.unpack_from('<II', data, cur)
            if length < 8 or length % 8 or cur + length > limit:
                raise AXRError('native_load_commands_invalid')
            if cmd == 0x1b:
                if length != 24 or self.uuid is not None:
                    raise AXRError('native_uuid_invalid')
                self.uuid = str(uuid.UUID(bytes=data[cur + 8:cur + 24]))
            elif cmd == 0x19:
                if length < 72:
                    raise AXRError('native_segment_invalid')
                name = self._name(data[cur + 8:cur + 24])
                va, vs, off, size, _, protection, nsect = struct.unpack_from('<QQQQiiI', data, cur + 24)
                if length != 72 + nsect * 80 or size > vs or off + size > len(data):
                    raise AXRError('native_segment_invalid')
                if any(va < end and start < va + vs for start, end in segments):
                    raise AXRError('native_segment_overlap')
                segments.append((va, va + vs))
                self._file_segments.append((va, vs, off, size))
                if name == '__TEXT':
                    if self.image_base is not None:
                        raise AXRError('native_text_segment_duplicate')
                    self.image_base = va
                for j in range(nsect):
                    at = cur + 72 + j * 80
                    section_name = self._name(data[at:at + 16])
                    if self._name(data[at + 16:at + 32]) != name:
                        raise AXRError('native_section_segment_mismatch')
                    address, section_size, section_offset = struct.unpack_from('<QQI', data, at + 32)
                    flags = struct.unpack_from('<I', data, at + 64)[0]
                    # Zero-fill sections have no file-backed bytes.
                    if flags & 0xff in (1, 0xc, 0x12):
                        continue
                    if (not va <= address <= va + size or address + section_size > va + size or
                            section_offset != off + address - va or section_offset + section_size > off + size):
                        raise AXRError('native_section_bounds_invalid')
                    key = (name, section_name)
                    if key in self.sections:
                        raise AXRError('native_section_duplicate')
                    if key in {('__TEXT', '__text'), ('__TEXT', '__stubs'), ('__TEXT', '__objc_stubs')} and not protection & 4:
                        raise AXRError('native_text_not_executable')
                    self.sections[key] = Section(address, section_size, section_offset)
            elif cmd == 0x26:
                if length != 16 or starts_data is not None:
                    raise AXRError('native_function_starts_invalid')
                off, size = struct.unpack_from('<II', data, cur + 8)
                if off + size > len(data) or size > 8 * 1024 * 1024:
                    raise AXRError('native_function_starts_invalid')
                starts_data = data[off:off + size]
            elif cmd == 0x80000034:
                if length != 16 or self._fixups is not None:
                    raise AXRError('native_fixups_invalid')
                off, size = struct.unpack_from('<II', data, cur + 8)
                if size < 28 or size > 4 * 1024 * 1024 or off + size > len(data):
                    raise AXRError('native_fixups_invalid')
                self._fixups = data[off:off + size]
            cur += length
        if cur != limit or not self.uuid or ('__TEXT', '__text') not in self.sections or starts_data is None:
            raise AXRError('native_image_metadata_missing')
        text = self.sections['__TEXT', '__text']
        # Mach-O function-start deltas are relative to the __TEXT segment base.
        text_base = next(a for a, z in segments if a <= text.address < z)
        values = []
        current, value, shift, terminated = text_base, 0, 0, False
        for byte in starts_data:
            if terminated:
                if byte:
                    raise AXRError('native_function_starts_invalid')
                continue
            value |= (byte & 127) << shift
            if byte & 128:
                shift += 7
                if shift >= 64:
                    raise AXRError('native_function_starts_invalid')
                continue
            if not value:
                if shift:
                    raise AXRError('native_function_starts_invalid')
                terminated = True
                continue
            current += value
            if current % 4 or not text.address <= current < text.address + text.size:
                raise AXRError('native_function_starts_outside_text')
            if len(values) >= 1000000:
                raise AXRError('native_function_starts_budget')
            values.append(current)
            value = shift = 0
        if not terminated or not values:
            raise AXRError('native_function_starts_invalid')
        self.starts = tuple(values)

    def chained_rebase(self, address):
        """Prove an on-disk format-6 rebase by walking its page chain.

        Returns an unslid image address, never a process pointer. Unsupported
        formats, imports, tagged pointers and unlisted words fail closed. The
        bit layout follows Apple's mach-o/fixup-chains.h; no loader is invoked.
        """
        if type(address) is not int or address % 4 or self._fixups is None:
            raise AXRError('native_rebase_request_invalid')
        data = self._fixups

        def unpack(fmt, at, limit=len(data)):
            size = struct.calcsize(fmt)
            if at < 0 or at + size > limit:
                raise AXRError('native_fixups_invalid')
            return struct.unpack_from(fmt, data, at)

        version, starts, _, _, _, _, _ = unpack('<7I', 0)
        if version != 0 or starts < 28:
            raise AXRError('native_fixups_invalid')
        count, = unpack('<I', starts)
        if count != len(self._file_segments):
            raise AXRError('native_fixups_invalid')
        offsets = unpack('<' + 'I' * count, starts + 4)
        index = next((i for i, (va, _, _, size) in enumerate(self._file_segments)
                      if va <= address and address + 8 <= va + size), None)
        if index is None or offsets[index] == 0:
            raise AXRError('native_rebase_not_listed')
        rel = offsets[index]
        if rel < 4 + count * 4:
            raise AXRError('native_fixups_invalid')
        at = starts + rel
        length, page_size, kind, segment_offset, maximum, pages = unpack('<IHHQIH', at)
        va, _, file_offset, file_size = self._file_segments[index]
        if (length < 22 + pages * 2 or at + length > len(data) or
                page_size not in (4096, 16384) or maximum != 0 or
                va != self.image_base + segment_offset or
                pages > (file_size + page_size - 1) // page_size):
            raise AXRError('native_fixups_invalid')
        if kind != 6:
            raise AXRError('native_fixup_format_unsupported')
        page = (address - va) // page_size
        if page >= pages:
            raise AXRError('native_rebase_not_listed')
        start, = unpack('<H', at + 22 + page * 2, at + length)
        if start == 0xffff:
            raise AXRError('native_rebase_not_listed')
        if start & 0x8000:
            raise AXRError('native_fixup_multistart_unsupported')
        cursor = page * page_size + start
        page_end = min((page + 1) * page_size, file_size)
        # At most one page is walked; next offsets are forward, four-byte units.
        for _ in range(page_size // 4):
            if cursor % 4 or cursor < page * page_size or cursor + 8 > page_end:
                raise AXRError('native_fixup_chain_invalid')
            word, = struct.unpack_from('<Q', self.data, file_offset + cursor)
            if not word >> 63 and (word >> 44) & 0x7f:
                raise AXRError('native_fixup_chain_invalid')
            if va + cursor == address:
                if word >> 63:
                    raise AXRError('native_rebase_import_denied')
                if (word >> 36) & 0xff:
                    raise AXRError('native_rebase_tagged_denied')
                target = self.image_base + (word & ((1 << 36) - 1))
                if not any(a <= target < a + size for a, _, _, size in self._file_segments):
                    raise AXRError('native_rebase_target_outside_image')
                return target
            step = ((word >> 51) & 0xfff) * 4
            if not step or va + cursor > address:
                raise AXRError('native_rebase_not_listed')
            if step < 8:
                raise AXRError('native_fixup_chain_invalid')
            cursor += step
        raise AXRError('native_fixup_chain_budget')

    @staticmethod
    def _name(raw):
        try:
            return raw.split(b'\0', 1)[0].decode('ascii')
        except UnicodeError:
            raise AXRError('native_section_name_invalid') from None

    def read(self, address, size, *, section=('__TEXT', '__text')):
        selected = self.sections.get(section)
        if (not selected or type(address) is not int or type(size) is not int or size < 1 or
                address < selected.address or address + size > selected.address + selected.size):
            raise AXRError('native_address_outside_section')
        offset = selected.offset + address - selected.address
        return self.data[offset:offset + size]

    def function(self, address):
        self.read(address, 1)
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0:
            raise AXRError('native_function_boundary_missing')
        start = self.starts[index]
        text = self.sections['__TEXT', '__text']
        end = self.starts[index + 1] if index + 1 < len(self.starts) else text.address + text.size
        if end - start > 1024 * 1024:
            raise AXRError('native_function_size_budget')
        return {'start': start, 'end': end,
                'sha256': hashlib.sha256(self.read(start, end - start)).hexdigest()}

    def direct_calls(self, start):
        function = self.function(start)
        if function['start'] != start:
            raise AXRError('native_function_entry_required')
        result = []
        raw = self.read(start, function['end'] - start)
        for pos in range(0, len(raw), 4):
            word = struct.unpack_from('<I', raw, pos)[0]
            if word & 0xfc000000 != 0x94000000:
                continue
            delta = word & 0x3ffffff
            if delta & 0x2000000:
                delta -= 0x4000000
            target = start + pos + delta * 4
            target_section = next((key for key, section in self.sections.items()
                if key in {('__TEXT', '__text'), ('__TEXT', '__stubs'), ('__TEXT', '__objc_stubs')}
                and section.address <= target and target + 4 <= section.address + section.size), None)
            if target_section is None:
                raise AXRError('native_call_target_outside_code')
            result.append({'site': start + pos, 'target': target, 'section': target_section[1]})
        return result

    def adjacent_string_refs(self, start, *, maximum_bytes=256):
        """Only proven adjacent ADRP/ADD pairs; no register-state guesses."""
        function = self.function(start)
        if function['start'] != start or type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 512:
            raise AXRError('native_reference_request_invalid')
        raw = self.read(start, function['end'] - start)
        result = []
        for pos in range(0, len(raw) - 4, 4):
            page, add = struct.unpack_from('<II', raw, pos)
            if page & 0x9f000000 != 0x90000000 or add & 0xffc00000 != 0x91000000:
                continue
            if page & 31 != (add >> 5) & 31 or page & 31 == 31:
                continue
            delta = (((page >> 5) & 0x7ffff) << 2) | ((page >> 29) & 3)
            if delta & 0x100000:
                delta -= 0x200000
            address = ((start + pos) & ~4095) + (delta << 12) + ((add >> 10) & 4095)
            section = self.sections.get(('__TEXT', '__cstring'))
            if not section or not section.address <= address < section.address + section.size:
                continue
            size = min(maximum_bytes + 1, section.address + section.size - address)
            value = self.read(address, size, section=('__TEXT', '__cstring'))
            end = value.find(b'\0')
            if end < 1 or end > maximum_bytes or any(c < 32 or c > 126 for c in value[:end]):
                continue
            result.append({'site': start + pos, 'address': address, 'text': value[:end].decode('ascii')})
        return result
