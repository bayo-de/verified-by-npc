"""Media probe for audio and video intake (stdlib only).

Reads the facts a media file declares about itself, straight from
its bytes: container format, duration, codecs, and for video the
frame dimensions, for audio the channel count and sample rate. Pure
Python header parsing (ISO BMFF, RIFF/WAVE, FLAC, Ogg, MP3 frame
headers): no probe binary ships in the Lambda runtime, and none is
needed for these containers.

Honesty rules: a fact is reported only when the bytes carry it;
durations derived from file size and bitrate are marked estimated;
anything unrecognized returns None so the caller records the probe
as not run. No frames are decoded: there is no video decoder in the
runtime, so frame-level checks stay pending in the registry with
that reason. Never raises.
"""
import struct

_MP4_VIDEO_CODECS = {
    "avc1": "H.264", "avc3": "H.264", "hev1": "H.265/HEVC",
    "hvc1": "H.265/HEVC", "vp09": "VP9", "av01": "AV1",
    "mp4v": "MPEG-4 Visual", "encv": "encrypted video",
}
_MP4_AUDIO_CODECS = {
    "mp4a": "AAC", "ac-3": "AC-3", "ec-3": "E-AC-3",
    "opus": "Opus", "flac": "FLAC", "alac": "ALAC",
    "enca": "encrypted audio", "lpcm": "PCM", "sowt": "PCM",
    "twos": "PCM", "in24": "PCM", "in32": "PCM", "fl32": "PCM",
    "fl64": "PCM",
}


def _u32(b):
    return struct.unpack(">I", b)[0]


def _u64(b):
    return struct.unpack(">Q", b)[0]


def _iter_boxes(data, start, end):
    """Yield (type, content_start, content_end) per BMFF box."""
    off = start
    while off + 8 <= end:
        size = _u32(data[off:off + 4])
        btype = data[off + 4:off + 8].decode("latin-1")
        header = 8
        if size == 1:
            if off + 16 > end:
                return
            size = _u64(data[off + 8:off + 16])
            header = 16
        elif size == 0:
            size = end - off
        if size < header or off + size > end:
            return
        yield btype, off + header, off + size, off, off + size
        off += size


def _find_box(data, start, end, want):
    for btype, cs, ce, _bs, _be in _iter_boxes(data, start, end):
        if btype == want:
            return cs, ce
    return None


# -- ISO BMFF (MP4 / MOV / M4A) ---------------------------------------------
def _probe_bmff(data):
    ftyp = _find_box(data, 0, len(data), "ftyp")
    brand = None
    if ftyp:
        cs, _ce = ftyp
        brand = data[cs:cs + 4].decode("latin-1").strip()
    moov = _find_box(data, 0, len(data), "moov")
    if moov is None:
        return None
    mcs, mce = moov
    out = {"family": None, "container": "mp4", "brand": brand}
    duration_ms = None
    tracks = []
    for btype, cs, ce, _bs, _be in _iter_boxes(data, mcs, mce):
        if btype == "mvhd" and duration_ms is None:
            duration_ms = _mvhd_duration(data, cs, ce)
        elif btype == "trak":
            track = _probe_track(data, cs, ce)
            if track:
                tracks.append(track)
    if duration_ms is None:
        for t in tracks:
            if t.get("duration_ms"):
                duration_ms = t["duration_ms"]
                break
    if duration_ms is not None:
        out["duration_ms"] = duration_ms
    video = next((t for t in tracks if t["type"] == "video"), None)
    audio = next((t for t in tracks if t["type"] == "audio"), None)
    if video:
        out["family"] = "video"
        out["video_codec"] = video.get("codec")
        if video.get("width"):
            out["width"] = video["width"]
        if video.get("height"):
            out["height"] = video["height"]
        if audio:
            out["audio_codec"] = audio.get("codec")
            if audio.get("channels"):
                out["audio_channels"] = audio["channels"]
            if audio.get("sample_rate"):
                out["audio_sample_rate"] = audio["sample_rate"]
    elif audio:
        out["family"] = "audio"
        out["audio_codec"] = audio.get("codec")
        if audio.get("channels"):
            out["channels"] = audio["channels"]
        if audio.get("sample_rate"):
            out["sample_rate"] = audio["sample_rate"]
    elif tracks:
        out["family"] = "video" if any(
            t["type"] == "video" for t in tracks) else "audio"
    return out if out["family"] else None


def _mvhd_duration(data, cs, ce):
    if ce - cs < 20:
        return None
    version = data[cs]
    try:
        if version == 1:
            timescale = _u32(data[cs + 20:cs + 24])
            duration = _u64(data[cs + 24:cs + 32])
        else:
            timescale = _u32(data[cs + 12:cs + 16])
            duration = _u32(data[cs + 16:cs + 20])
    except struct.error:
        return None
    if not timescale:
        return None
    return int(duration * 1000 // timescale)


def _probe_track(data, cs, ce):
    mdia = _find_box(data, cs, ce, "mdia")
    if mdia is None:
        return None
    mcs, mce = mdia
    handler = None
    hdlr = _find_box(data, mcs, mce, "hdlr")
    if hdlr:
        hcs, _hce = hdlr
        handler = data[hcs + 8:hcs + 12].decode("latin-1")
    mdhd = _find_box(data, mcs, mce, "mdhd")
    duration_ms = None
    if mdhd:
        dcs, dce = mdhd
        duration_ms = _mvhd_duration(data, dcs, dce)
    track = {"type": {"vide": "video", "soun": "audio"}.get(
        handler, "other"), "duration_ms": duration_ms}
    tkhd = None
    outer = _find_box(data, cs, ce, "tkhd")
    if outer:
        tcs, tce = outer
        if tce - tcs >= 8:
            width = _u32(data[tce - 8:tce - 4]) >> 16
            height = _u32(data[tce - 4:tce]) >> 16
            if width:
                track["width"] = width
            if height:
                track["height"] = height
    minf = _find_box(data, mcs, mce, "minf")
    if minf:
        stbl = _find_box(data, minf[0], minf[1], "stbl")
        if stbl:
            stsd = _find_box(data, stbl[0], stbl[1], "stsd")
            if stsd:
                _probe_sample_entry(data, stsd[0], stsd[1], track)
    return track


def _probe_sample_entry(data, cs, ce, track):
    # stsd content: version/flags (4) + entry count (4), then the
    # first entry: size (4) + format (4) + reserved (6) + data
    # reference index (2), then the format-specific fields.
    if ce - cs < 16:
        return
    entry = cs + 8  # first sample entry starts here
    if entry + 16 > ce:
        return
    fmt = data[entry + 4:entry + 8].decode("latin-1")
    if track["type"] == "video":
        track["codec"] = _MP4_VIDEO_CODECS.get(fmt, fmt)
        # VisualSampleEntry: 16 bytes of pre-defined/reserved fields
        # follow the 16-byte entry header; then width and height.
        if entry + 36 <= ce:
            width = struct.unpack(">H",
                                  data[entry + 32:entry + 34])[0]
            height = struct.unpack(">H",
                                   data[entry + 34:entry + 36])[0]
            if width and "width" not in track:
                track["width"] = width
            if height and "height" not in track:
                track["height"] = height
    elif track["type"] == "audio":
        track["codec"] = _MP4_AUDIO_CODECS.get(fmt, fmt)
        # AudioSampleEntry v0: version (2) + revision (2) + vendor
        # (4), then channel count (2), sample size (2), compression
        # (2), packet size (2), sample rate (4, 16.16 fixed point).
        if entry + 34 <= ce:
            channels = struct.unpack(
                ">H", data[entry + 24:entry + 26])[0]
            rate = struct.unpack(
                ">I", data[entry + 32:entry + 36])[0] >> 16
            if channels:
                track["channels"] = channels
            if rate:
                track["sample_rate"] = rate


# -- WAV (RIFF) ---------------------------------------------------------------
def _probe_wav(data):
    if len(data) < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    out = {"family": "audio", "container": "wav", "format": None,
           "channels": None, "sample_rate": None, "duration_ms": None}
    off = 12
    byte_rate = None
    data_size = None
    while off + 8 <= len(data):
        cid = data[off:off + 4]
        size = struct.unpack("<I", data[off + 4:off + 8])[0]
        body = off + 8
        if cid == b"fmt " and size >= 16 and body + 16 <= len(data):
            fmt, channels, rate, brate = struct.unpack(
                "<HHII", data[body:body + 12])
            out["format"] = {1: "PCM", 3: "IEEE float",
                             85: "MP3"}.get(fmt, "format %d" % fmt)
            out["channels"] = channels or None
            out["sample_rate"] = rate or None
            byte_rate = brate or None
        elif cid == b"data":
            data_size = size
            if size == 0 or off + 8 + size > len(data):
                data_size = len(data) - body  # truncated file: rest
            break
        off += 8 + size + (size & 1)
    if byte_rate and data_size:
        out["duration_ms"] = int(data_size * 1000 // byte_rate)
    return {k: v for k, v in out.items() if v is not None} \
        if out["channels"] or out["sample_rate"] else None


# -- FLAC -----------------------------------------------------------------------
def _probe_flac(data):
    if len(data) < 42 or data[:4] != b"fLaC":
        return None
    # First metadata block: STREAMINFO, 34 bytes at offset 8.
    si = data[8:42]
    packed = struct.unpack(">Q", si[10:18])[0]
    sample_rate = (packed >> 44) & 0xFFFFF
    channels = ((packed >> 41) & 0x7) + 1
    total_samples = packed & ((1 << 36) - 1)
    out = {"family": "audio", "container": "flac", "codec": "FLAC",
           "channels": channels}
    if sample_rate:
        out["sample_rate"] = sample_rate
        if total_samples:
            out["duration_ms"] = int(total_samples * 1000 // sample_rate)
    return out


# -- OGG (Vorbis / Opus) ---------------------------------------------------------
def _probe_ogg(data):
    if len(data) < 27 or data[:4] != b"OggS":
        return None
    out = {"family": "audio", "container": "ogg"}
    head = data[:65536]
    if b"\x01vorbis" in head:
        # Identification packet: marker, version u32, channels u8,
        # sample rate u32 (all little-endian).
        pos = head.find(b"\x01vorbis") + 7
        if pos + 9 <= len(head):
            channels = head[pos + 4]
            rate = struct.unpack("<I", head[pos + 5:pos + 9])[0]
            if channels and rate:
                out.update({"codec": "Vorbis", "channels": channels,
                            "sample_rate": rate})
    elif b"OpusHead" in head:
        pos = head.find(b"OpusHead") + 8
        if pos + 12 <= len(head):
            channels = head[pos + 1]
            rate = struct.unpack("<I", head[pos + 8:pos + 12])[0]
            out.update({"codec": "Opus", "channels": channels,
                        "sample_rate": rate})
    else:
        return None
    # Duration from the last page's granule position (best effort:
    # sampled media may place it further out; stated only when the
    # final page is in hand).
    tail = data[-65536:]
    idx = tail.rfind(b"OggS")
    if idx >= 0 and idx + 14 <= len(tail):
        granule = struct.unpack("<q", tail[idx + 6:idx + 14])[0]
        rate = out.get("sample_rate")
        if granule > 0 and rate:
            out["duration_ms"] = int(granule * 1000 // rate)
    return out


# -- MP3 ------------------------------------------------------------------------
_MP3_BR_V1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224,
              256, 320, 0]
_MP3_BR_V2 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144,
              160, 0]
_MP3_SR = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000],
           0: [11025, 12000, 8000]}


def _mp3_frame_header(data, off):
    if off + 4 > len(data):
        return None
    if data[off] != 0xFF or (data[off + 1] & 0xE0) != 0xE0:
        return None
    version = (data[off + 1] >> 3) & 0x3
    layer = (data[off + 1] >> 1) & 0x3
    if version == 1 or layer != 1:  # Layer III only
        return None
    br_idx = (data[off + 2] >> 4) & 0xF
    sr_idx = (data[off + 2] >> 2) & 0x3
    if br_idx in (0, 15) or sr_idx == 3:
        return None
    bitrate = (_MP3_BR_V1 if version == 3 else _MP3_BR_V2)[br_idx]
    rate = _MP3_SR[version][sr_idx]
    channels = 1 if ((data[off + 3] >> 6) & 0x3) == 3 else 2
    return bitrate * 1000, rate, channels


def _probe_mp3(data):
    start = 0
    if data[:3] == b"ID3" and len(data) > 10:
        size = 0
        for b in data[6:10]:
            size = (size << 7) | (b & 0x7F)
        start = 10 + size
    frame = None
    off = start
    while off < start + 4096 and off + 4 <= len(data):
        frame = _mp3_frame_header(data, off)
        if frame:
            break
        off += 1
    if not frame:
        return None
    bitrate, rate, channels = frame
    out = {"family": "audio", "container": "mp3", "codec": "MP3",
           "channels": channels, "sample_rate": rate,
           "bitrate": bitrate}
    # Xing header carries an exact frame count when present.
    xing_at = None
    for marker in (b"Xing", b"Info"):
        pos = data.find(marker, start, start + 1200)
        if pos >= 0:
            xing_at = pos
            break
    if xing_at is not None and xing_at + 12 <= len(data):
        flags = _u32(data[xing_at + 4:xing_at + 8])
        if flags & 0x1:
            frames = _u32(data[xing_at + 8:xing_at + 12])
            samples = frames * 1152
            out["duration_ms"] = int(samples * 1000 // rate)
            return out
    audio_bytes = len(data) - start
    out["duration_ms"] = int(audio_bytes * 8 * 1000 // bitrate)
    out["duration_estimated"] = True
    return out


# -- WebM -----------------------------------------------------------------------
def _probe_webm(data):
    if len(data) < 4 or data[:4] != b"\x1a\x45\xdf\xa3":
        return None
    head = data[:4096]
    if b"webm" not in head:
        return None
    return {"family": "video", "container": "webm",
            "detail": "WebM container read; track detail is not "
                      "parsed by this probe yet."}


# -- entry point ------------------------------------------------------------------
def probe_media(data, declared_kind):
    """Probe fetched media bytes. Returns a checks_run entry dict
    ({"check": "media_probe", ...}) or None when the bytes are not a
    readable media container this probe knows. Never raises."""
    try:
        if not data:
            return None
        found = None
        if len(data) >= 8 and data[4:8] == b"ftyp":
            found = _probe_bmff(data)
        elif data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            found = _probe_wav(data)
        elif data[:4] == b"fLaC":
            found = _probe_flac(data)
        elif data[:4] == b"OggS":
            found = _probe_ogg(data)
        elif data[:4] == b"\x1a\x45\xdf\xa3":
            found = _probe_webm(data)
        else:
            found = _probe_mp3(data)
        if found is None:
            return None
        entry = {"check": "media_probe", "status": "probed",
                 "declared_kind": declared_kind}
        entry.update(found)
        detected = found.get("family")
        entry["detected_kind"] = detected
        entry["kind_match"] = (detected == declared_kind)
        facts = []
        if found.get("duration_ms") is not None:
            facts.append("about %d seconds long"
                         % max(1, round(found["duration_ms"] / 1000)))
        if found.get("family") == "video":
            bits = [found.get("video_codec")]
            if found.get("width") and found.get("height"):
                bits.append("%dx%d" % (found["width"],
                                       found["height"]))
            facts.append("video: " + ", ".join(b for b in bits if b))
        if found.get("family") == "audio":
            facts.append("audio: %s" % (
                found.get("codec") or found.get("audio_codec") or
                found.get("format") or ""))
        entry["detail"] = "Container facts read from the file itself" \
            + (": " + "; ".join(facts) if facts else ".")
        if not entry["kind_match"]:
            entry["detail"] += (
                " The file reads as %s, not the %s it was registered "
                "as." % (detected, declared_kind))
        return entry
    except Exception:
        return None
