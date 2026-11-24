//! Reading what a served `.git` folder holds: the index (which file has which blob), loose
//! objects and pack files, deltas included. The role of ZAP's GitMetadata (ascanrulesBeta,
//! Apache License 2.0), written from Git's own format documentation (gitformat-index,
//! gitformat-pack) rather than line by line: ZAP's reader misreads version 4 index names and
//! has no REF_DELTA support. Everything here reads data a server sent, so every length and
//! offset is checked, and inflated data is capped.

use std::io::Read;

/// The most an object may inflate to; a source file is far smaller.
const MAX_OBJECT: u64 = 16 << 20;
/// The most deltas one object may be built through.
const MAX_DELTA_DEPTH: usize = 64;
/// The most index entries read; a repository with more is read in part.
const MAX_ENTRIES: u32 = 200_000;

/// A big-endian reader over untrusted bytes: every read is checked.
struct Bytes<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Bytes<'a> {
    fn new(data: &'a [u8], at: usize) -> Self {
        Self { data, at }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.data.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Whether `s` is a 40-digit lower-case hex object name.
pub(super) fn is_sha1(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Git's "offset" varint (index v4 name prefixes, OFS_DELTA distances).
fn offset_varint(r: &mut Bytes) -> Option<u64> {
    let mut b = r.u8()?;
    let mut v = u64::from(b & 0x7f);
    for _ in 0..9 {
        if b & 0x80 == 0 {
            return Some(v);
        }
        b = r.u8()?;
        v = (v.checked_add(1)? << 7) | u64::from(b & 0x7f);
    }
    None
}

/// The files an index lists, with their blob names, in index order.
pub(super) fn index_entries(data: &[u8]) -> Option<Vec<(String, String)>> {
    let mut r = Bytes::new(data, 0);
    if r.take(4)? != b"DIRC" {
        return None;
    }
    let version = r.u32()?;
    if !(2..=4).contains(&version) {
        return None;
    }
    let count = r.u32()?.min(MAX_ENTRIES);
    let mut out = Vec::new();
    let mut previous: Vec<u8> = Vec::new();
    for _ in 0..count {
        let start = r.at;
        r.take(40)?; // ctime, mtime, dev, ino, mode, uid, gid, size
        let sha = hex(r.take(20)?);
        let flags = r.u16()?;
        if version >= 3 && flags & 0x4000 != 0 {
            r.u16()?;
        }
        let name = if version == 4 {
            let strip = usize::try_from(offset_varint(&mut r)?).ok()?;
            let keep = previous.len().checked_sub(strip)?;
            let rest = &r.data[r.at..];
            let nul = rest.iter().position(|&b| b == 0)?;
            let mut name = previous[..keep].to_vec();
            name.extend_from_slice(&rest[..nul]);
            r.at += nul + 1;
            name
        } else {
            let rest = &r.data[r.at..];
            let nul = rest.iter().position(|&b| b == 0)?;
            let name = rest[..nul].to_vec();
            // The entry is NUL-padded to a multiple of 8 bytes (at least one NUL).
            let len = r.at - start + nul;
            r.at = start + (len + 8) / 8 * 8;
            name
        };
        if !name.is_empty() {
            out.push((String::from_utf8_lossy(&name).into_owned(), sha));
        }
        previous = name;
    }
    Some(out)
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data).take(MAX_OBJECT + 1).read_to_end(&mut out).ok()?;
    (out.len() as u64 <= MAX_OBJECT).then_some(out)
}

/// A loose object file's content when it is a blob.
pub(super) fn loose_blob(data: &[u8]) -> Option<Vec<u8>> {
    let raw = inflate(data)?;
    let nul = raw.iter().position(|&b| b == 0)?;
    let header = std::str::from_utf8(&raw[..nul]).ok()?;
    let size: usize = header.strip_prefix("blob ")?.parse().ok()?;
    raw.get(nul + 1..nul + 1 + size).map(<[u8]>::to_vec)
}

/// The pack file a `objects/info/packs` file names first.
pub(super) fn pack_name(info: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(info).ok()?;
    let name = text.lines().find_map(|l| l.strip_prefix("P "))?.trim();
    let sha = name.strip_prefix("pack-")?.strip_suffix(".pack")?;
    is_sha1(sha).then(|| name.to_string())
}

/// A pack index: object names and their offsets in the pack.
pub(super) struct PackIndex {
    entries: Vec<(String, u64)>,
}

impl PackIndex {
    /// Reads an index of version 1 or 2.
    pub(super) fn parse(data: &[u8]) -> Option<Self> {
        let mut r = Bytes::new(data, 0);
        let v2 = data.starts_with(b"\xfftOc");
        if v2 {
            r.take(4)?;
            if r.u32()? != 2 {
                return None;
            }
        }
        let mut fanout = 0;
        for _ in 0..256 {
            fanout = r.u32()?;
        }
        let n = usize::try_from(fanout).ok()?;
        // Every entry takes at least 24 bytes: a count beyond the data is a lie.
        if n > data.len() / 24 {
            return None;
        }
        let mut entries = Vec::with_capacity(n);
        if !v2 {
            for _ in 0..n {
                let offset = u64::from(r.u32()?);
                entries.push((hex(r.take(20)?), offset));
            }
            return Some(Self { entries });
        }
        let names: Vec<String> = (0..n).map(|_| r.take(20).map(hex)).collect::<Option<_>>()?;
        r.take(n.checked_mul(4)?)?; // CRC32s
        let offsets: Vec<u32> = (0..n).map(|_| r.u32()).collect::<Option<_>>()?;
        let large = r.at;
        for (name, off) in names.into_iter().zip(offsets) {
            let offset = if off & 0x8000_0000 == 0 {
                u64::from(off)
            } else {
                let i = usize::try_from(off & 0x7fff_ffff).ok()?;
                let mut big = Bytes::new(data, large.checked_add(i.checked_mul(8)?)?);
                (u64::from(big.u32()?) << 32) | u64::from(big.u32()?)
            };
            entries.push((name, offset));
        }
        Some(Self { entries })
    }

    fn offset_of(&self, sha: &str) -> Option<u64> {
        self.entries.iter().find(|(n, _)| n == sha).map(|(_, o)| *o)
    }
}

/// The blob `sha` from a pack (version 2 or 3) and its index, deltas resolved.
pub(super) fn packed_blob(pack: &[u8], index: &PackIndex, sha: &str) -> Option<Vec<u8>> {
    if !pack.starts_with(b"PACK") {
        return None;
    }
    let version = u32::from_be_bytes(pack.get(4..8)?.try_into().ok()?);
    if !(2..=3).contains(&version) {
        return None;
    }
    let (kind, data) = object_at(pack, index, index.offset_of(sha)?, 0)?;
    (kind == 3).then_some(data)
}

/// The object at `offset`: its type (1 commit, 2 tree, 3 blob, 4 tag) and content.
fn object_at(pack: &[u8], index: &PackIndex, offset: u64, depth: usize) -> Option<(u8, Vec<u8>)> {
    if depth > MAX_DELTA_DEPTH {
        return None;
    }
    let mut r = Bytes::new(pack, usize::try_from(offset).ok()?);
    let mut b = r.u8()?;
    let kind = (b >> 4) & 7;
    // The size (its low 4 bits, then 7 per byte) isn't needed: inflating ends the object.
    while b & 0x80 != 0 {
        b = r.u8()?;
    }
    match kind {
        1..=4 => Some((kind, inflate(pack.get(r.at..)?)?)),
        6 => {
            let distance = offset_varint(&mut r)?;
            let base_at = offset.checked_sub(distance).filter(|&o| o < offset)?;
            let delta = inflate(pack.get(r.at..)?)?;
            let (base_kind, base) = object_at(pack, index, base_at, depth + 1)?;
            Some((base_kind, apply_delta(&base, &delta)?))
        }
        7 => {
            let base_sha = hex(r.take(20)?);
            let delta = inflate(pack.get(r.at..)?)?;
            let (base_kind, base) = object_at(pack, index, index.offset_of(&base_sha)?, depth + 1)?;
            Some((base_kind, apply_delta(&base, &delta)?))
        }
        _ => None,
    }
}

/// Git's little-endian size varint (delta headers).
fn size_varint(r: &mut Bytes) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let b = r.u8()?;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// `base` rebuilt by a delta's copy and insert instructions.
fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    let mut r = Bytes::new(delta, 0);
    if size_varint(&mut r)? != base.len() as u64 {
        return None;
    }
    let size = size_varint(&mut r)?;
    if size > MAX_OBJECT {
        return None;
    }
    let mut out = Vec::with_capacity(usize::try_from(size).ok()?);
    while r.at < delta.len() {
        let op = r.u8()?;
        if op & 0x80 != 0 {
            let mut offset = 0usize;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    offset |= usize::from(r.u8()?) << (8 * i);
                }
            }
            let mut len = 0usize;
            for i in 0..3 {
                if op & (0x10 << i) != 0 {
                    len |= usize::from(r.u8()?) << (8 * i);
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            out.extend_from_slice(base.get(offset..offset.checked_add(len)?)?);
        } else if op != 0 {
            out.extend_from_slice(r.take(usize::from(op))?);
        } else {
            return None;
        }
        if out.len() as u64 > size {
            return None;
        }
    }
    (out.len() as u64 == size).then_some(out)
}

#[cfg(test)]
pub(super) mod tests {
    use std::io::Write;

    use super::*;

    pub(in super::super) fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    pub(in super::super) fn sha1_hex(data: &[u8]) -> String {
        use sha1::Digest;
        hex(&sha1::Sha1::digest(data))
    }

    /// A version 2 index listing `files` (name, blob sha).
    pub(in super::super) fn index_v2(files: &[(&str, &str)]) -> Vec<u8> {
        let mut out = b"DIRC".to_vec();
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&(files.len() as u32).to_be_bytes());
        for (name, sha) in files {
            let start = out.len();
            out.extend_from_slice(&[0u8; 40]);
            out.extend((0..20).map(|i| u8::from_str_radix(&sha[i * 2..i * 2 + 2], 16).unwrap()));
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
            let len = out.len() - start;
            out.resize(start + (len + 8) / 8 * 8, 0);
        }
        out
    }

    fn index_v4(files: &[(&str, &str)]) -> Vec<u8> {
        let mut out = b"DIRC".to_vec();
        out.extend_from_slice(&4u32.to_be_bytes());
        out.extend_from_slice(&(files.len() as u32).to_be_bytes());
        let mut prev = "";
        for (name, sha) in files {
            out.extend_from_slice(&[0u8; 40]);
            out.extend((0..20).map(|i| u8::from_str_radix(&sha[i * 2..i * 2 + 2], 16).unwrap()));
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            let common = prev.bytes().zip(name.bytes()).take_while(|(a, b)| a == b).count();
            out.push((prev.len() - common) as u8);
            out.extend_from_slice(&name.as_bytes()[common..]);
            out.push(0);
            prev = name;
        }
        out
    }

    /// A pack header for an object of `kind` and `size`.
    fn obj_header(kind: u8, mut size: usize) -> Vec<u8> {
        let mut out = vec![(kind << 4) | (size & 0x0f) as u8];
        size >>= 4;
        while size > 0 {
            *out.last_mut().unwrap() |= 0x80;
            out.push((size & 0x7f) as u8);
            size >>= 7;
        }
        out
    }

    /// A version 2 pack holding `base` and `target` (as an OFS_DELTA on it), and its v2 index.
    pub(in super::super) fn pack_with_delta(base: &[u8], target: &[u8]) -> (Vec<u8>, Vec<u8>, String, String) {
        let mut pack = b"PACK".to_vec();
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());
        let base_at = pack.len();
        pack.extend(obj_header(3, base.len()));
        pack.extend(zlib(base));
        // Delta: copy the base's first half, insert the rest of the target.
        let half = base.len() / 2;
        assert!(target.starts_with(&base[..half]));
        let mut delta = vec![base.len() as u8, target.len() as u8];
        delta.extend([0x80 | 0x10, half as u8]);
        for chunk in target[half..].chunks(127) {
            delta.push(chunk.len() as u8);
            delta.extend_from_slice(chunk);
        }
        let delta_at = pack.len();
        pack.extend(obj_header(6, delta.len()));
        pack.push((delta_at - base_at) as u8);
        pack.extend(zlib(&delta));
        let blob = |d: &[u8]| sha1_hex(&[format!("blob {}\0", d.len()).as_bytes(), d].concat());
        let (base_sha, target_sha) = (blob(base), blob(target));
        let mut objects = [(base_sha.clone(), base_at as u32), (target_sha.clone(), delta_at as u32)];
        objects.sort();
        let mut idx = b"\xfftOc".to_vec();
        idx.extend_from_slice(&2u32.to_be_bytes());
        for i in 0..256u32 {
            let n = objects.iter().filter(|(s, _)| u32::from_str_radix(&s[..2], 16).unwrap() <= i).count() as u32;
            idx.extend_from_slice(&n.to_be_bytes());
        }
        for (s, _) in &objects {
            idx.extend((0..20).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()));
        }
        idx.extend_from_slice(&[0u8; 8]);
        for (_, o) in &objects {
            idx.extend_from_slice(&o.to_be_bytes());
        }
        (pack, idx, base_sha, target_sha)
    }

    #[test]
    fn index_versions_2_and_4() {
        let a = "0123456789abcdef0123456789abcdef01234567";
        let b = "89abcdef0123456789abcdef0123456789abcdef";
        let files = [("app/index.php", a), ("app/login.php", b)];
        assert_eq!(
            index_entries(&index_v2(&files)).unwrap(),
            [("app/index.php".into(), a.into()), ("app/login.php".into(), b.into())]
        );
        assert_eq!(index_entries(&index_v4(&files)).unwrap()[1], ("app/login.php".into(), b.into()));
        assert!(index_entries(b"DIRC\0\0\0\x02\0\0\0\x05short").is_none());
        assert!(index_entries(b"<html>").is_none());
    }

    #[test]
    fn loose_and_packed_objects() {
        let src = b"<?php echo 'hi'; ?>\n";
        let loose = zlib(&[format!("blob {}\0", src.len()).as_bytes(), src].concat());
        assert_eq!(loose_blob(&loose).unwrap(), src);
        assert!(loose_blob(&zlib(b"tree 3\0abc")).is_none());
        let base = b"<?php\n// version one of the file, long enough to copy from\n$a = 1;\n";
        let target = [&base[..base.len() / 2], b"rewritten tail\n$a = 2;\n".as_slice()].concat();
        let (pack, idx, base_sha, target_sha) = pack_with_delta(base, &target);
        let index = PackIndex::parse(&idx).unwrap();
        assert_eq!(packed_blob(&pack, &index, &base_sha).unwrap(), base);
        assert_eq!(packed_blob(&pack, &index, &target_sha).unwrap(), target);
        assert!(packed_blob(&pack, &index, &"0".repeat(40)).is_none());
        assert_eq!(pack_name(b"P pack-0123456789abcdef0123456789abcdef01234567.pack\n\n").unwrap().len(), 50);
        assert!(pack_name(b"P ../../etc/passwd\n").is_none());
    }

    #[test]
    fn hostile_data_is_refused() {
        // A delta asking to copy past its base, and an index claiming more entries than it has.
        assert!(apply_delta(b"abc", &[3, 4, 0x91, 0, 4]).is_none());
        let mut idx = b"\xfftOc\0\0\0\x02".to_vec();
        idx.extend(std::iter::repeat_n(0xffu8, 1024));
        assert!(PackIndex::parse(&idx).is_none());
    }
}
