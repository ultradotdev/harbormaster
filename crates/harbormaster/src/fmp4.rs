//! Just enough understanding of fragmented MP4 to buffer and forward it:
//! finding the video track, telling which fragments hold a keyframe, and
//! cutting a byte stream into its header and fragments.
//!
//! An MP4 file is a sequence of *boxes*, each a four-byte length, a
//! four-letter type and a payload that is often more boxes.

/// Larger boxes than this are treated as corruption.
const MAX_BOX: usize = 64 * 1024 * 1024;

/// The boxes directly inside `data`, as `(type, payload)`. Stops quietly at
/// anything malformed.
fn boxes(mut data: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    std::iter::from_fn(move || {
        let size = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
        let kind = data.get(4..8)?;
        let (header, size) = match size {
            // The real length follows the type as eight bytes.
            1 => (16, usize::try_from(u64::from_be_bytes(data.get(8..16)?.try_into().ok()?)).ok()?),
            // "To the end of the file", which a stream never uses.
            0 => return None,
            n => (8, n),
        };
        let payload = data.get(header..size)?;
        data = &data[size..];
        Some((kind, payload))
    })
}

fn child<'a>(data: &'a [u8], kind: &[u8; 4]) -> Option<&'a [u8]> {
    boxes(data).find(|(k, _)| k == kind).map(|(_, payload)| payload)
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

/// The id of the video track described by an MP4 header.
pub fn video_track(init: &[u8]) -> Option<u32> {
    let moov = child(init, b"moov")?;
    boxes(moov).filter(|(kind, _)| kind == b"trak").find_map(|(_, trak)| {
        let handler = child(child(trak, b"mdia")?, b"hdlr")?;
        if handler.get(8..12)? != b"vide" {
            return None;
        }
        let header = child(trak, b"tkhd")?;
        // Version 1 stores its two timestamps in eight bytes each.
        u32_at(header, if *header.first()? == 1 { 20 } else { 12 })
    })
}

/// Whether an MP4 header describes a track of the given kind: `vide` for
/// video, `soun` for sound.
pub fn has_track(init: &[u8], handler: &[u8; 4]) -> bool {
    let Some(moov) = child(init, b"moov") else { return false };
    boxes(moov).filter(|(kind, _)| kind == b"trak").any(|(_, trak)| {
        child(trak, b"mdia").and_then(|mdia| child(mdia, b"hdlr")).and_then(|h| h.get(8..12)) == Some(&handler[..])
    })
}

/// Whether a fragment contains a keyframe of the given track, which makes
/// it a place a decoder can start from.
pub fn has_keyframe(fragment: &[u8], track: u32) -> bool {
    const NOT_A_KEYFRAME: u32 = 0x0001_0000;
    boxes(fragment)
        .filter(|(kind, _)| kind == b"moof")
        .flat_map(|(_, moof)| boxes(moof).filter(|(kind, _)| kind == b"traf"))
        .any(|(_, traf)| {
            let Some(header) = child(traf, b"tfhd") else { return false };
            let (Some(flags), Some(id)) = (u32_at(header, 0), u32_at(header, 4)) else { return false };
            if id != track {
                return false;
            }
            // Optional fields precede the default sample flags.
            let skip = [(0x01, 8), (0x02, 4), (0x08, 4), (0x10, 4)];
            let offset = 8 + skip.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, n)| n).sum::<usize>();
            let default = if flags & 0x20 != 0 { u32_at(header, offset) } else { None };
            boxes(traf).filter(|(kind, _)| kind == b"trun").any(|(_, run)| {
                let (Some(flags), Some(count)) = (u32_at(run, 0), u32_at(run, 4)) else { return false };
                let mut offset = 8 + if flags & 0x01 != 0 { 4 } else { 0 };
                let first = if flags & 0x04 != 0 {
                    offset += 4;
                    u32_at(run, offset - 4)
                } else {
                    None
                };
                let fields = [0x100, 0x200, 0x400, 0x800];
                let entry = fields.iter().filter(|bit| flags & **bit != 0).count() * 4;
                let before_flags = fields[..2].iter().filter(|bit| flags & **bit != 0).count() * 4;
                (0..count as usize).any(|i| {
                    let own = if flags & 0x400 != 0 { u32_at(run, offset + i * entry + before_flags) } else { None };
                    let sample = if i == 0 { first.or(own) } else { own };
                    sample.or(default).is_some_and(|f| f & NOT_A_KEYFRAME == 0)
                })
            })
        })
}

/// One piece cut from an MP4 byte stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Piece {
    /// Everything before the first fragment.
    Header(Vec<u8>),
    /// One fragment: its index box and its media.
    Fragment(Vec<u8>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

/// Cuts a stream of fragmented MP4, arriving in arbitrary chunks, into its
/// header and fragments.
#[derive(Default)]
pub struct Splitter {
    pending: Vec<u8>,
    current: Vec<u8>,
    header_sent: bool,
}

impl Splitter {
    pub fn feed(&mut self, bytes: &[u8], out: &mut Vec<Piece>) -> Result<(), Malformed> {
        self.pending.extend_from_slice(bytes);
        let mut offset = 0;
        while let Some(start) = self.pending.get(offset..offset + 8) {
            let size = match u32::from_be_bytes([start[0], start[1], start[2], start[3]]) as usize {
                1 => match self.pending.get(offset + 8..offset + 16) {
                    Some(wide) => usize::try_from(u64::from_be_bytes(wide.try_into().unwrap())).map_err(|_| Malformed)?,
                    None => break,
                },
                n => n,
            };
            if !(8..=MAX_BOX).contains(&size) {
                return Err(Malformed);
            }
            let Some(whole) = self.pending.get(offset..offset + size) else { break };
            let kind = &whole[4..8];
            if kind == b"moof" && !self.header_sent {
                self.header_sent = true;
                out.push(Piece::Header(std::mem::take(&mut self.current)));
            }
            // The index written when a file is finished is not part of any fragment.
            if kind != b"mfra" {
                self.current.extend_from_slice(whole);
            }
            if kind == b"mdat" && self.header_sent {
                out.push(Piece::Fragment(std::mem::take(&mut self.current)));
            }
            offset += size;
        }
        self.pending.drain(..offset);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out
    }

    fn track(id: u32, handler: &[u8; 4]) -> Vec<u8> {
        let mut header = vec![0u8; 12];
        header.extend_from_slice(&id.to_be_bytes());
        let mut hdlr = vec![0u8; 8];
        hdlr.extend_from_slice(handler);
        boxed(b"trak", &[boxed(b"tkhd", &header), boxed(b"mdia", &boxed(b"hdlr", &hdlr))].concat())
    }

    /// A fragment for `track` whose samples carry the given flags.
    fn fragment(track: u32, samples: &[u32]) -> Vec<u8> {
        let mut tfhd = 0u32.to_be_bytes().to_vec();
        tfhd.extend_from_slice(&track.to_be_bytes());
        // Per-sample size and flags.
        let mut trun = 0x600u32.to_be_bytes().to_vec();
        trun.extend_from_slice(&(samples.len() as u32).to_be_bytes());
        for flags in samples {
            trun.extend_from_slice(&100u32.to_be_bytes());
            trun.extend_from_slice(&flags.to_be_bytes());
        }
        let traf = boxed(b"traf", &[boxed(b"tfhd", &tfhd), boxed(b"trun", &trun)].concat());
        [boxed(b"moof", &traf), boxed(b"mdat", b"media")].concat()
    }

    const KEY: u32 = 0x0200_0000;
    const DELTA: u32 = 0x0101_0000;

    #[test]
    fn finds_the_video_track_and_its_keyframes() {
        let init = [boxed(b"ftyp", b"isom"), boxed(b"moov", &[track(1, b"soun"), track(2, b"vide")].concat())].concat();
        assert_eq!(video_track(&init), Some(2));
        assert_eq!(video_track(&boxed(b"moov", &track(1, b"soun"))), None);
        assert_eq!(video_track(b"garbage"), None);
        assert!(has_track(&init, b"soun") && has_track(&init, b"vide"));
        assert!(!has_track(&boxed(b"moov", &track(2, b"vide")), b"soun"), "a camera with its microphone off");
        assert!(!has_track(b"garbage", b"soun"));

        assert!(has_keyframe(&fragment(2, &[KEY, DELTA]), 2));
        assert!(has_keyframe(&fragment(2, &[DELTA, KEY]), 2), "a keyframe anywhere in the fragment counts");
        assert!(!has_keyframe(&fragment(2, &[DELTA, DELTA]), 2));
        // Audio samples are all "keyframes"; they must not count for video.
        assert!(!has_keyframe(&fragment(1, &[KEY]), 2));
        assert!(!has_keyframe(b"garbage", 2));
    }

    #[test]
    fn default_and_first_sample_flags_are_honoured() {
        // Default flags say "not a keyframe"; the first sample overrides that.
        let mut tfhd = 0x20u32.to_be_bytes().to_vec();
        tfhd.extend_from_slice(&2u32.to_be_bytes());
        tfhd.extend_from_slice(&DELTA.to_be_bytes());
        let run = |first: Option<u32>| {
            let mut trun = (if first.is_some() { 0x205u32 } else { 0x201 }).to_be_bytes().to_vec();
            trun.extend_from_slice(&3u32.to_be_bytes());
            trun.extend_from_slice(&0u32.to_be_bytes());
            if let Some(flags) = first {
                trun.extend_from_slice(&flags.to_be_bytes());
            }
            trun.extend_from_slice(&[0; 12]);
            boxed(b"moof", &boxed(b"traf", &[boxed(b"tfhd", &tfhd), boxed(b"trun", &trun)].concat()))
        };
        assert!(has_keyframe(&run(Some(KEY)), 2));
        assert!(!has_keyframe(&run(None), 2));
    }

    #[test]
    fn splits_a_stream_at_any_chunk_boundary() {
        let header = [boxed(b"ftyp", b"isom"), boxed(b"moov", b"tracks")].concat();
        let first = fragment(2, &[KEY]);
        let second = [boxed(b"styp", b"msdh"), fragment(2, &[DELTA])].concat();
        let stream = [header.clone(), first.clone(), second.clone(), boxed(b"mfra", b"index")].concat();
        let expected = [Piece::Header(header), Piece::Fragment(first), Piece::Fragment(second)];
        for split in 0..=stream.len() {
            let mut splitter = Splitter::default();
            let mut out = Vec::new();
            splitter.feed(&stream[..split], &mut out).unwrap();
            splitter.feed(&stream[split..], &mut out).unwrap();
            assert_eq!(out, expected, "split at {split}");
        }
    }

    #[test]
    fn rejects_impossible_box_sizes() {
        let mut out = Vec::new();
        assert_eq!(Splitter::default().feed(&[0, 0, 0, 4, b'f', b't', b'y', b'p'], &mut out), Err(Malformed));
        assert_eq!(Splitter::default().feed(&[0xFF, 0xFF, 0xFF, 0xFF, b'm', b'd', b'a', b't'], &mut out), Err(Malformed));
    }
}
