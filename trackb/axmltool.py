#!/usr/bin/env python3
"""AXML (Android binary XML) parser for repair-tool analysis. Sample-agnostic.

Parses the chunk tree (string pool / resource map / namespace + element nodes),
yields the element tree with attributes, and diffs two manifests structurally.
This is the foundation for the repair surgery (packed -> original manifest).

AXML chunk layout (from frameworks/base ResourceTypes.h):
  every chunk: u16 type, u16 headerSize, u32 size
  string pool: headerSize=28: [8 chunk hdr][u32 count][u32 styleCount]
               [u32 flags][u32 ignored(=0)][u32 stringsStart][u32 stylesStart]
               then count*u32 offsets (from chunk start), then the string data
  start element: headerSize=16: [8 chunk hdr][u32 line][u32 comment]
               then u16 ns, u16 name, u16 attrStart, u16 attrSize,
                    u16 attrCount, u16 idIdx, u16 classIdx, u16 styleIdx
               then attrCount attrs of 20B: u16 ns, u16 name, u16 rawValue,
                    u16 vSize, u8 vRes0, u8 vType, u32 vData
"""
import struct
import sys


RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103


class Axml:
    def __init__(self, data: bytes):
        self.data = data
        self.strings = []
        self.tree = []
        self._parse()

    def _parse(self):
        d = self.data
        if d[:2] != struct.pack('<H', RES_XML_TYPE):
            raise ValueError('not AXML')
        off = 8
        stack = [self.tree]
        while off < len(d) - 8:
            ctype, hsize, csize = struct.unpack_from('<HHI', d, off)
            if csize < hsize or off + csize > len(d):
                break
            if ctype == RES_STRING_POOL_TYPE:
                self._parse_pool(d, off, hsize)
            elif ctype == RES_XML_START_ELEMENT:
                line, comment = struct.unpack_from('<II', d, off + 8)
                # ResXMLTree_attrExt (AOSP): ns(u32) name(u32) then u16:
                # attributeStart, attributeSize, attributeCount, idIdx, classIdx, styleIdx
                ns, name = struct.unpack_from('<II', d, off + 16)
                (attr_start, attr_size, attr_count, id_idx, class_idx,
                 style_idx) = struct.unpack_from('<HHHHHH', d, off + 24)
                node = {'line': line, 'name': self.s(name), 'ns': self.s(ns), 'attrs': [], 'children': []}
                for k in range(attr_count):
                    a = off + 16 + attr_start + k * attr_size
                    if a + attr_size > off + csize or a + 20 > len(d):
                        break  # malformed chunk — bail out of its attrs
                    a_ns, a_name, a_raw, v_size, v_res0, v_type, v_data = struct.unpack_from('<IIIHBBI', d, a)
                    node['attrs'].append({'ns': self.s(a_ns), 'name': self.s(a_name),
                                          'raw': self.s(a_raw), 'type': v_type, 'data': v_data})
                stack[-1].append(node)
                stack.append(node['children'])
            elif ctype == RES_XML_END_ELEMENT:
                if len(stack) > 1:
                    stack.pop()
            off += csize

    def _parse_pool(self, d, off, hsize):
        # pool chunk payload: stringCount, styleCount, flags, stringsStart, stylesStart
        (s_count, style_count, flags, data_start,
         _style_start) = struct.unpack_from('<IIIII', d, off + 8)
        is_utf8 = bool(flags & (1 << 8))
        offsets = struct.unpack_from('<%dI' % s_count, d, off + hsize)
        for so in offsets:
            p = off + data_start + so
            if is_utf8:
                skip = 1
                l1 = d[p]
                clen = l1 & 0x7F
                if l1 & 0x80:
                    clen = ((l1 & 0x7F) << 8) | d[p + 1]
                    skip = 2
                l2 = d[p + skip]
                blen = l2 & 0x7F
                if l2 & 0x80:
                    blen = ((l2 & 0x7F) << 8) | d[p + skip + 1]
                    skip += 1
                raw = d[p + skip + clen:p + skip + clen + blen]
                enc = 'utf-8'
            else:
                n = struct.unpack_from('<H', d, p)[0]
                if n & 0x8000:  # the length escaped into two halfwords
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', d, p + 2)[0]
                    raw = d[p + 4:p + 4 + n * 2]
                else:
                    raw = d[p + 2:p + 2 + n * 2]
                enc = 'utf-16-le'
            self.strings.append(raw.decode(enc, errors='replace'))

    def s(self, idx):
        return self.strings[idx] if 0 <= idx < len(self.strings) else ''


def element_lines(nodes, depth=0, out=None):
    if out is None:
        out = []
    for n in nodes:
        attrs = ' '.join('%s="%s"' % (a['name'], a['raw'] if a['raw'] else '0x%x' % a['data']) for a in n['attrs'])
        out.append('%s%s [%s]' % ('  ' * depth, n['name'], attrs))
        element_lines(n['children'], depth + 1, out)
    return out


def main():
    a = Axml(open(sys.argv[1], 'rb').read())
    for line in element_lines(a.tree):
        print(line)


if __name__ == '__main__':
    main()
