"""Reference BEP 52 / BEP 3 vectors from libtorrent for the sealed-launcher tests.

Run with libtorrent 2.0.15 (pip). Data is deterministic, so the Rust and JS
implementations regenerate identical inputs:
  block i of size n = SHA-256(b"qrw-bep52" || u32be(n) || u32be(i)), concatenated, cut to n.

    python -I tools/libtorrent-vectors.py <workdir> > vectors/bep52-libtorrent.json
"""
import hashlib, json, os, struct, sys
import libtorrent as lt

PIECE, NAME = 16384, "m"
SIZES = [1, 775, 16384, 16385, 32768, 49152, 49153, 65536, 131072]

def data(n):
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(b"qrw-bep52" + struct.pack(">II", n, i)).digest()
        i += 1
    return bytes(out[:n])

def make(path, flags):
    fs = lt.file_storage(); lt.add_files(fs, path)
    t = lt.create_torrent(fs, PIECE, flags=flags)
    lt.set_piece_hashes(t, os.path.dirname(path))
    return t.generate()[b"info"]

work = sys.argv[1]
rows = []
for n in SIZES:
    d = os.path.join(work, str(n)); os.makedirs(d, exist_ok=True)
    p = os.path.join(d, NAME); open(p, "wb").write(data(n))
    v2 = make(p, lt.create_torrent.v2_only)
    v1 = make(p, lt.create_torrent.v1_only)
    root = v2[b"file tree"][NAME.encode()][b""][b"pieces root"]
    rows.append({"length": n, "sha256": hashlib.sha256(data(n)).hexdigest(), "piecesRoot": root.hex(),
                 "infohashV2": hashlib.sha256(lt.bencode(v2)).hexdigest(),
                 "infohashV1": hashlib.sha1(lt.bencode(v1)).hexdigest(),
                 "v1InfoKeys": sorted(k.decode() for k in v1), "v2InfoKeys": sorted(k.decode() for k in v2)})
print(json.dumps({"generator": "libtorrent " + lt.__version__, "pieceLength": PIECE, "name": NAME, "vectors": rows}, indent=2))
