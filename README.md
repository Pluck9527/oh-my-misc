# oh-my-misc

A native, extensible CLI toolkit for CTF Misc analysis and forensics.

`oh-my-misc` provides deterministic file inspection, image analysis and artifact extraction with both human-readable and stable JSON output. It runs directly on Python without requiring Docker.

## Install for development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Current CLI

```bash
omm --version
omm inspect challenge.png
omm inspect challenge.png --json
python -m oh_my_misc inspect challenge.png --json

omm image watermark single watermarkh embed source.png --text 'flag{demo}' -o watermarked.png
omm image watermark single watermarkh extract watermarked.png -o extracted.png

omm image watermark dual chishaxie embed source.png --watermark mark.png -o watermarked.png
omm image watermark dual chishaxie extract watermarked.png --reference source.png -o extracted-mark.png

omm image watermark dual ww23-dct embed source.png --watermark mark.png -o watermarked.png
omm image watermark dual ww23-dct extract watermarked.png -o extracted-spectrum.png

omm image split frames glance.gif -o frames/
omm image split grid sprite.png --columns 4 --rows 3 -o tiles/
omm image join frames/frame-*.png --columns 0 --gap 0 -o joined.png
omm image flip reverse.jpg --axis horizontal -o reversed.jpg
omm image combine first.png second.png --operation xor -o combined.png
omm image stereogram magic-eye.png --offset 90 -o revealed.png
omm image pixeljihad decode apngframe*.png -o flag.txt
omm image pixeljihad decode encoded.png --wordlist passwords.txt --contains 'flag{' -o flag.txt
omm image pixeljihad encode cover.png --text 'flag{demo}' -o encoded.png
omm image cloacked-pixel hide cover.png --payload secret.zip --password 'p@ss' -o stego.png
omm image cloacked-pixel extract stego.png --password 'p@ss' -o secret.zip
omm image cloacked-pixel extract stego.png --wordlist passwords.txt --contains 'flag{' -o secret.bin
omm image cloacked-pixel brute stego.png --wordlist passwords.txt --contains 'flag{' -o secret.bin
omm image cloacked-pixel analyse stego.png --json
omm image image-steganography hide cover.png --text 'flag{demo}' -o stego.png
omm image image-steganography extract stego.png -o payload.bin
omm image image-steganography hide cover.png --mode difference --payload secret.bin -o diff.png
omm image image-steganography extract diff.png --mode difference --reference cover.png -o secret.bin
omm image stegpy extract stego.png --password 'p@ss' -o payload.bin
omm image stegpy extract stego.png --wordlist passwords.txt --contains 'flag{' -o payload.bin
omm stego steghide extract stego.jpg -p '' -o hidden.bin
omm stego steghide extract stego.jpg --wordlist passwords.txt --contains 'flag{' -o hidden.bin
omm image steghide extract stego.jpg -p '' -o hidden.bin
omm image outguess extract suspect.jpg -k 'abc' -o flag.txt
omm image outguess extract suspect.jpg --wordlist passwords.txt --contains 'flag{' -o flag.txt
omm image jsteg reveal suspect.jpg -o hidden.bin
omm image jsteg hide cover.jpg --text 'flag{demo}' -o stego.jpg
omm image raw-lsb extract sample.ARW -o payload.bin
omm image raw-lsb scan sample.ARW -o raw-lsb-candidates/
omm image stegdetect suspect.jpg -t jopi -s 10.0 --json
omm image f5 extract beautiful.jpg -p passwd -o output.txt
omm image f5 extract beautiful.jpg --wordlist passwords.txt --contains 'flag{' -o output.txt
omm image wbstego extract carrier.bmp -o hidden.bin
omm stego wbstego extract carrier.txt --carrier txt -o hidden.bin
omm image jphs extract suspect.jpg --password '' -o hidden.bin
omm image sample challenge.png --start 0x0 --end 3828x2148 --step 12x12 -o hidden.png
omm image spacefill decode peano.png --curve peano --order 6 -o flag.png
omm image spacefill decode hilbert.png --curve hilbert --order 9 --no-flip-y -o flag.png
omm image arnold decode scrambled.png --rounds 12 --a 0 --b 9 -o flag.png
omm image arnold brute cat.png --rounds 1:6 --a 1:11 --b 1:11 -o arnold-candidates/
omm image mosaic depix pixelated.png --search debruijn.png --block-width 8 -o depix.png
omm image acropalypse restore cropped.png --width 1920 --height 1080 --mode rgba -o restored.png
omm image puzzle analyze shuffled-sheet.png --tile-size 125 --json
omm image puzzle solve pieces/*.png --rows 10 --columns 18 -o solved.png
omm text whitespace run hidden.txt -o flag.txt
omm text whitespace show hidden.txt -o visible.txt
omm text whitespace encode --text 'flag{demo}' -o flag.ws
omm text snow hide cover.txt --text 'flag{demo}' -o stego.txt
omm text snow extract stego.txt -o flag.txt
omm text snow capacity cover.txt --line-length 72 --json
omm text spammimic encode --text 'flag{demo}' -o spam.txt
omm text spammimic decode spam.txt -o flag.txt
omm text spammimic decode spam.txt --backend remote -o flag.txt
omm text spammimic decode spam.txt --wordlist passwords.txt --contains 'flag{' -o flag.txt
omm text zwc inspect suspect.txt --json
omm text zwc extract suspect.txt --chars U+200B,U+200C -o flag.txt
omm text cloakify decloak cipher.txt --cipher passwd.txt -o payload.bin
omm zip crack encrypted.zip --wordlist passwords.txt --json
omm zip invisible-password encrypted.zip --password-b64 AP8= -o out/
omm zip invisible-password encrypted.zip --brute-raw --max-bytes 2 --backend native
omm zip crc list challenge.zip --json
omm zip crc brute challenge.zip --charset printable -o recovered.bin
omm zip crc reverse --crc 0x7c2df918 --length 4 --charset all -o candidate.bin
omm zip nested flag.zip -o unrolled/
omm zip timestamp extract challenge.zip --include .txt --base 1737276000 --offset 1 -o hidden.bin
omm zip timestamp extract out/ --source dir --sort numeric --base 1737276000 -o hidden.bin
omm zip ntfs-stream extract challenge.rar -o ads_out/
omm stego oursecret extract carrier.bin -o oursecret_out/
omm stego deegger inspect carrier.bin --json
omm stego deegger extract carrier.bin -o hidden.bin
omm stego deegger extract-files carrier.bin -o hidden_files/
omm stego deegger hide carrier.jpg --payload secret.txt -o stego.jpg
omm stego silenteye extract carrier.wav --password silenteye -o hidden.bin
omm stego silenteye hide carrier.bmp --text 'flag{demo}' --password silenteye -o stego.bmp
omm audio sstv inspect flag.wav --json
omm audio sstv decode flag.wav -o result.png
omm audio ham decode latlong.wav --mode afsk1200 -o aprs.txt
omm audio ham inspect latlong.wav --json
omm audio wavdata info audio.wav --json
omm audio wavdata lsb audio.wav --channel left -o hidden.bin
omm audio wavdata channel-diff stereo.wav --map 1:0 --map 2:1 -o bits.txt
omm audio wavdata fft-map tones.wav --freqs 800,900,1000 --alphabet abc -o decoded.txt
omm audio wavdata to-image flag.wav --width 1021 --height 761 --stride 5 -o flag.png
omm audio velato inspect program.mid --json
omm audio velato decode program.mid -o printed.txt
omm audio velato encode --text 'flag{demo}' -o program.mid
omm audio midi-qr events.txt -o qr.png --midi-output recovered.mid
omm audio midi-qr song.mid -o qr.png --source midi
omm audio mp3stego extract sound.mp3 -p pass -o hidden.txt
omm audio mp3stego brute sound.mp3 --wordlist passwords.txt --contains 'flag{' -o hidden.txt
omm audio mp3stego encode cover.mp3 --payload data.txt -p pass -o sound.mp3
omm audio mp3-field extract suspect.mp3 --field copyright -o hidden.bin
omm audio mp3-field extract suspect.mp3 --start 0x0F05A4 --end 0xC125A3 --field copyright --base-frame-size 1044 -o flag.txt
omm audio mp3-field scan suspect.mp3 -o mp3-field-candidates/
omm audio lyra inspect voice.lyra --json
omm audio lyra decode voice.lyra --bitrate 3200 -o voice.wav
omm audio lyra encode voice.wav --bitrate 3200 -o voice.lyra
```

## Audio SSTV decoding

`omm audio sstv` is a top-level audio branch, parallel to `image`, `text`, `zip`
and `stego`. It decodes slow-scan television (SSTV) WAV signals into PNG images
without requiring RX-SSTV, QSSTV or SciPy/soundfile.

The native decoder reads PCM WAV, mixes stereo to mono, searches the standard
1900/1200/1900/1200 Hz SSTV calibration header, decodes the VIS mode byte, then
maps the 1500..2300 Hz scan tones back to pixel values. Supported VIS modes are
Martin 1/2, Scottie 1/2/DX and Robot 36/72.

```bash
# Detect VIS mode and expected output geometry.
omm audio sstv inspect flag.wav --json

# Decode to PNG.
omm audio sstv decode flag.wav -o result.png

# Useful CTF variants: reversed audio, inverted image, forced mode and preview.
omm audio sstv decode reversed.wav --reverse-audio -o result.png
omm audio sstv decode inverted.wav --invert-image -o result.png
omm audio sstv decode noisy.wav --skip 1.5 --mode robot36 --max-lines 80 -o preview.png
```


## Amateur radio AFSK1200 / AX.25 / APRS decoding

`omm audio ham` implements the common CTF workflow from WAV amateur-radio data to decoded packet text. The native backend reads PCM WAV directly, mixes stereo to mono, resamples for demodulation, detects Bell 202 AFSK1200 mark/space tones, applies NRZI decoding, splits HDLC `0x7e` frames, removes bit stuffing, verifies AX.25 FCS, and renders APRS UI-frame text. The legacy backend spellings `auto` and `multimon` are accepted for CLI compatibility and route to the same Python implementation.

```bash
# Native Python decoder for the article's latlong.wav style challenge.
omm audio ham decode latlong.wav --mode afsk1200 --output aprs.txt

# Inspect packet count and APRS messages without writing output.
omm audio ham inspect latlong.wav --json

# Export raw while decoding natively.
omm audio ham decode latlong.wav --backend auto --raw-output latlong.raw -o aprs.txt

# Generate a local AX.25/APRS AFSK1200 sample for tests or demos.
omm audio ham encode --source N0CALL --destination APRS --text 'flag{demo}' -o aprs.wav
```

Use `--reverse-audio` or `--invert-audio` for CTF files that have been reversed or phase-inverted. JSON output includes decoded packets, callsigns, digipeater path, info text and flag/APRS hints.


## WAV raw-data scripting helpers

`omm audio wavdata` turns the guide's ad-hoc WAV scripts into reusable commands. It reads PCM WAV metadata, exposes integer and normalized sample data, extracts LSB bit streams, maps stereo channel differences to bits, performs chunked FFT frequency-index decoding, compares two WAV files through scaled sample differences, reconstructs images from sample words, and maps dominant frequencies back to characters.

```bash
# Basic parameters: channels, sample width, sample rate, frames and duration.
omm audio wavdata info audio.wav --json

# WAV LSB extraction; output can be bytes, bits or decoded text.
omm audio wavdata lsb audio.wav --bit 0 --channel left --format bytes -o hidden.bin
omm audio wavdata lsb audio.wav --bits 0,1 --channel all --format bits -o bits.txt

# Left/right difference coding, e.g. left-right 1 -> 0 and 2 -> 1.
omm audio wavdata channel-diff stereo.wav --map 1:0 --map 2:1 -o bits.txt

# DASCTF-style 100ms FFT frequency indexes; two indexes form one alphabet index.
omm audio wavdata fft-map tones.wav \
  --chunk-ms 100 \
  --freqs 800,900,1000,1100,1200,1300,1400,1500,1600,1700 \
  --alphabet 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_}{-?!' \
  -o decoded.txt

# Compare two WAVs and map scaled differences to bit pairs.
omm audio wavdata compare secret.wav cover.wav \
  --scale 1e7 --map 9:00 --map 19:01 --map 29:10 --map 39:11 \
  -o payload.bin

# Convert stereo 16-bit samples to RGBA pixels: left hi/lo -> R/G, right hi/lo -> B/A.
omm audio wavdata to-image flag.wav --width 1021 --height 761 --stride 5 --mode rgba16stereo -o flag.png

# Dominant-frequency character mapping with optional custom char:freq entries.
omm audio wavdata freq-chars video.wav --chunk-ms 100 --tolerance 30 -o text.txt
omm audio wavdata freq-chars video.wav --map a:440 --map b:466 -o text.txt
```

All extraction commands emit JSON with bit counts, decoded previews, per-chunk/sample entries and flag/file-signature hints when `--json` is used.

## Velato MIDI programming language

`omm audio velato` implements the Velato CTF workflow: read a Standard MIDI File, collect note-on events from the first note track, use the first note as the root, map following note intervals to Velato commands/expressions, and recover text written by `print` commands. It also generates small Velato MIDI samples that print a chosen string, useful for tests and challenge fixtures.

```bash
# Show MIDI metadata, note interval trace, parsed commands and text hints.
omm audio velato inspect program.mid --json

# Extract concatenated Velato print output.
omm audio velato decode program.mid -o printed.txt

# Generate a C4-rooted program that prints text through char literals.
omm audio velato encode --text 'flag{velato}' -o program.mid
```

The parser follows Velato 2.x interval rules used by the upstream project: major-sixth + perfect-fifth starts `print`, minor/major-third starts value expressions, perfect-fourth selects char literals, and digit intervals terminate on a perfect fifth marker.

## MIDI note-grid / QR image renderer

`omm audio midi-qr` implements the MIDI-to-QR helper from the pasted script as a
native command. It accepts either a standard `.mid` file or a text log whose
lines are `timestamp<TAB>hex-midi-message`, keeps NOTE ON events, starts a new
row when the time gap exceeds `--row-gap`, maps distinct MIDI notes to columns,
and writes a black/white PNG matrix.

```bash
# Article/script-style input: 1722159321.608646000<TAB>904064
omm audio midi-qr events.txt -o qr.png --row-gap 0.01 --cell-size 20

# Also rebuild a playable MIDI from the parsed note events without mido.
omm audio midi-qr events.txt -o qr.png --midi-output recovered.mid --bpm 120 --ppq 480

# Direct MIDI file input; auto detects MThd, or force it with --source midi.
omm audio midi-qr song.mid -o qr.png --source midi --json
```

## MP3Stego parity steganography

`omm audio mp3stego` handles the classic MP3Stego tool workflow described as
`encode -E data.txt -P pass sound.wav sound.mp3` and
`decode -X -P pass sound.mp3`. MP3Stego stores selected payload bits in the
parity of each MP3 Layer III granule/channel `part2_3_length` side-info field;
selection is driven by the passphrase, so an empty password is also supported.

The native implementation is a Python port of the MP3Stego `StegoLib` state
machine: `CompressEncryptFile` is represented by deterministic gzip + 3DES-CBC,
`StegoOpenEmbeddedText`/`StegoGetNextBit` streams the little-endian length header
then encrypted bytes LSB-first, and `StegoCreateEmbeddedText`/`SaveHiddenBit`
rebuilds that stream while the SHA-1 PRNG selects carrier fields. Native encoding
patches only the selected Layer III `part2_3_length` parity bits in an existing
MP3 carrier; the old WAV-shaped command path now builds a deterministic local
MPEG-frame carrier instead of invoking `Encode.exe`.

```bash
# Inspect frame count, selectable bits and embedded encrypted payload length.
omm audio mp3stego inspect sound.mp3 -p '' --json

# Extract with a known or empty password.
omm audio mp3stego extract sound.mp3 -p pass -o hidden.txt
omm audio mp3stego extract sound.mp3 -p '' -o hidden.txt

# If the password is unknown, try a wordlist and optional hit filter.
omm audio mp3stego brute sound.mp3 \
  --wordlist passwords.txt --contains 'flag{' \
  -o hidden.txt

# Native carrier patching / fixture generation.
omm audio mp3stego encode cover.mp3 \
  --payload data.txt -p pass \
  -o sound.mp3
omm audio mp3stego encode sound.wav --payload data.txt -p pass -o fixture.mp3
```

## MP3 frame-header field steganography

`omm audio mp3-field` extracts hidden bit streams from mutable MPEG audio frame-header fields such as `copyright`, `private`, `original` and `padding`. This implements the CTF trick where one bit is stored per MP3 frame in a header flag; by default it parses real MP3 frame headers and follows each frame's bitrate/sample-rate/padding length.

```bash
# Common copyright-bit extraction; groups every 8 frame bits MSB-first into bytes.
omm audio mp3-field extract suspect.mp3 --field copyright --output hidden.bin

# Article-compatible mode: manually provide the frame range and use base size + padding.
omm audio mp3-field extract 1.mp3 \
  --start 0x0F05A4 --end 0xC125A3 \
  --field copyright --base-frame-size 1044 \
  --output flag.txt

# The private-field example with 417/418 byte stepping.
omm audio mp3-field extract 2.mp3 \
  --start 0x0399D0 --end 0x294C6A \
  --field private --base-frame-size 417 \
  --output flag.txt

# Scan likely fields and both byte orders; manifest.json records file/flag hints.
omm audio mp3-field scan suspect.mp3 \
  --fields copyright,private,original --orders msb,lsb \
  --output mp3-field-candidates/
```

Use `--format bits` when you want the raw ASCII `0`/`1` stream instead of grouped bytes, and `--limit-bits` for quick previews on long audio.

## Audio Lyra codec

`omm audio lyra` handles Google Lyra low-bitrate speech-compression challenges.
The `.lyra` files produced by Google's sample tools are raw packet streams, so
they do not carry a self-describing header; `inspect` reports packet-size
candidates for the supported 3200/6000/9200 bps modes.

The project now vendors Google's Apache-2.0 Lyra 1.3.2 source under
`src/oh_my_misc/_vendor/google_lyra` and calls it through a small C ABI wrapper
loaded by Python `ctypes`. Encode/decode call the bundled wrapper directly instead
of spawning standalone command-line programs. Build the bundled wrapper once when
you need speech reconstruction:

```bash
cd src/oh_my_misc/_vendor/google_lyra
bazel build -c opt //omm_native:libomm_lyra_native.so
```

`omm` searches the bundled Bazel output automatically. You can also pass
`--library /path/to/libomm_lyra_native.so` or set `OMM_LYRA_LIBRARY`. The default
model path is the bundled `lyra/model_coeffs` directory; override with
`--model-path` or `OMM_LYRA_MODEL_PATH`.

```bash
# Inspect likely bitrate candidates from raw packet length.
omm audio lyra inspect challenge.lyra --json
omm audio lyra inspect challenge.lyra --bitrate 3200

# Decode a CTF-provided .lyra stream to WAV through the native wrapper.
omm audio lyra decode challenge.lyra \
  --bitrate 3200 --sample-rate 16000 \
  -o decoded.wav

# Encode a WAV into the same raw .lyra stream format through the native wrapper.
omm audio lyra encode speech.wav \
  --bitrate 3200 \
  -o speech.lyra
```

## Image separation and joining

The native image commands replace the ImageMagick `convert` and `montage` workflow used in CTF image challenges. They preserve transparency, sort input names naturally and do not require Docker or ImageMagick.

```bash
# GIF/APNG/WebP frame extraction
omm image split frames glance.gif --output frames/

# Split a sprite sheet into a 4 × 3 grid
omm image split grid sprite.png --columns 4 --rows 3 --output tiles/

# Horizontal join by default; use --columns for a montage grid
omm image join frames/frame-*.png --columns 0 --gap 0 --output flag.png

# ImageMagick -flop / -flip equivalents
omm image flip input.png --axis horizontal --output horizontal.png
omm image flip input.png --axis vertical --output vertical.png
```

`split` outputs stable zero-padded names. `join` accepts different image sizes, supports a configurable background and gap, and lays images out in natural filename order.

## Equidistant pixel extraction

Extract a regular pixel lattice from a chosen inclusive coordinate range. This reproduces the CTFD `Get_Pixels.py` workflow and can enlarge the recovered low-resolution image with lossless nearest-neighbour scaling.

```bash
# Equivalent to: -p 0x0+3828x2148 -n 12x12
omm image sample arcaea.png \
  --start 0x0 --end 3828x2148 --step 12x12 \
  --output hidden.png

# Sample every tenth pixel and enlarge each recovered pixel into a 10 × 10 block
omm image sample challenge.png --step 10x10 --scale 10 --output hidden-large.png
```

Coordinates are zero-based and `--end` is inclusive. If `--end` is omitted, sampling continues through the last reachable pixel before the image's bottom-right corner. Horizontal and vertical steps may differ.

## Arnold cat-map transform

Recover or create images scrambled by Arnold cat-face transforms. Known parameters map directly to the usual `shuffle_times`, `a` and `b` scripts; unknown parameters can be brute-forced into a candidate directory. Square images use the standard cat map naturally, and rectangular images follow the common CTF variant that applies the row formula modulo height and the column formula modulo width.

```bash
# Restore with known parameters
omm image arnold decode scrambled.png \
  --rounds 12 --a 0 --b 9 \
  --output flag.png

# Create a scrambled sample
omm image arnold encode source.png \
  --rounds 1 --a 2 --b 3 \
  --output scrambled.png

# Brute-force candidates; ranges are START:STOP with STOP excluded
omm image arnold brute cat.png \
  --rounds 1:6 --a 1:11 --b 1:11 \
  --output arnold-candidates/
```

The implemented formulas are the standard forward map `(x + b*y, a*x + (a*b+1)*y)` and inverse map `((a*b+1)*x - b*y, -a*x + y)`, with each coordinate reduced modulo the active image dimension.

## Space-filling curve scramble

Restore images whose pixels were flattened or written along a Peano or Hilbert curve. This is the common CTF trick behind “填满空间的曲线”: the hidden image is not stored in low bits; all pixels are present, but their order follows a recursive curve instead of normal row-major order.

```bash
# Peano curve: side length must be 3^order, e.g. order 6 => 729 × 729
omm image spacefill decode peano-scrambled.png \
  --curve peano --order 6 \
  --output restored.png

# Hilbert curve: side length must be 2^order; try --no-flip-y or --reverse for variants
omm image spacefill decode hilbert-scrambled.png \
  --curve hilbert --order 9 --no-flip-y \
  --output restored.png

# Create a challenge-style scrambled image
omm image spacefill encode source.png \
  --curve peano --order 4 \
  --output scrambled.png
```

`decode` maps row-major pixels from the scrambled image back to coordinates generated by the curve. By default it uses the same `height - 1 - y` vertical flip shown in the guide's Peano script; `--no-flip-y` disables it, and `--reverse` tries the curve in reverse order. If `--order` is omitted, the command infers it from the square image side length.

The standalone implementation is in `src/oh_my_misc/spacefill.py`; it includes the Peano/Hilbert coordinate generators and both reversible image transforms.

## PaperBack / backpaper

Encode files as PaperBack 1.10 compatible 32×32-dot paper-backup pages, or recover files from clean exports and high-contrast scans. The native port includes the original block layout, CRC-16, shortened RS(255,223), XOR recovery blocks, bzip2 compression and optional AES-192/PBKDF2 encryption.

```bash
# Create one or more point-matrix pages
omm image backpaper encode flag.zip -o paper.png

# Recover the original file (multiple pages may be passed in any order)
omm image backpaper decode paper_*.png -o flag.zip

# PaperBack 1.10 encrypted format
omm image backpaper encode secret.bin -o paper.png --password 'ctf-key'
omm image backpaper decode paper.png -o secret.bin --password 'ctf-key'
```

`paperbak` is accepted as an alias for `backpaper`. The implementation source is `src/oh_my_misc/backpaper.py`.

## Piet / npiet image programs

Execute Piet programs directly from PNG, GIF or PPM images. The interpreter implements the 20 standard colours, colour-block sizes, DP/CC movement, white sliding, all 17 stack/I/O commands, automatic codel-size detection, unknown-colour policies and bounded execution.

```bash
# Equivalent to running npiet solved.png
omm image npiet solved.png

# Supply stdin and inspect a stable execution trace
omm image npiet challenge.png --input '42' --trace --json

# Equivalent to npiet -tpic: overlay the visited path
omm image npiet solved.png --trace-image npiet-trace.png
```

`piet` is accepted as an alias. Use `--codel-size` when a noisy or resized challenge prevents automatic zoom detection, and `--unknown nearest` for slightly altered palette colours.

## Mosaic depixelization helper

Recover pixelated CTF screenshots with a local Depix-style average-colour matcher. The command expects a cropped pixelated region plus a search image rendered with the same font, antialiasing and colours, such as a De Bruijn sequence screenshot. Each mosaic block is matched against same-sized windows in the search image by average RGB value, then replaced with the unique matching patch or the average of multiple matching patches.

```bash
# Restore a cropped pixelated region with a known 8 × 8 block size
omm image mosaic depix pixelated.png \
  --search debruijn-search.png \
  --block-width 8 --block-height 8 \
  --output recovered.png

# Let the command detect same-colour rectangles and allow small RGB tolerance
omm image mosaic depix pixelated.png \
  --search search.png --tolerance 2 \
  --background 250,250,250 \
  --output recovered.png

# Generate a local pixelated sample for testing
omm image mosaic pixelate source.png \
  --block-width 8 --output pixelated.png
```

The matcher supports Depix's two RGB average modes: `--average gammacorrected` (default arithmetic RGB) and `--average linear` (linear-light average). As with Depix, good results depend on matching the original rendering environment in the search image.

## StegSolve-compatible Image Combiner

Combine two images pixel by pixel using the 13 transformations from StegSolve. XOR is the default and is commonly used when two incomplete images or QR codes complement one another.

```bash
omm image combine first.png second.png --operation xor --output xor.png
omm image combine first.png second.png --operation sub-rgb --output difference.png
omm image combine first.png second.png --operation all --output combine-results/
```

Available operations are `xor`, `or`, `and`, packed `add`, `sub`, `mul`, channel-wise `add-rgb`, `sub-rgb`, `mul-rgb`, `lightest`, `darkest`, `interlace-h` and `interlace-v`. Packed arithmetic retains StegSolve's 24-bit overflow and channel-carry behavior. The `all` mode writes every result with a stable numbered filename.

## StegSolve-compatible stereogram solver

Reveal the disparity pattern in a single-image stereogram by XORing every pixel with the pixel at a horizontally wrapped offset, matching StegSolve's `Stereogram Solver` transformation and direction.

```bash
# Known offset
omm image stereogram magic-eye.png --offset 90 --output revealed.png

# Unknown offset: produce candidates 1 through 199 and a JSON manifest
omm image stereogram magic-eye.png --start 1 --stop 200 --output candidates/

# Invert the black-background XOR result when that makes the shape easier to read
omm image stereogram magic-eye.png --offset 90 --invert --output revealed-inverted.png
```

Offsets wrap at the right image boundary exactly like the original Java implementation. Batch mode uses a half-open `--start`/`--stop` range and writes stable `offset-NNN.png` names plus `manifest.json` for quick browsing.

## cloacked-pixel RGB LSB steganography

Embed, extract and analyse images compatible with [`livz/cloacked-pixel`](https://github.com/livz/cloacked-pixel) and the Python 3 port. The implementation follows the original layout: payload bytes are AES-CBC encrypted with `sha256(password)` as the key, prefixed with a 16-byte IV, length-prefixed with a 4-byte little-endian integer, then written bit-by-bit into the least significant bits of RGB channels in row-major order. Alpha is preserved.

```bash
# Hide any binary payload into a PNG output
omm image cloacked-pixel hide cover.png \
  --payload secret.zip --password 'p@ssw0rd' \
  --output stego.png

# Extract and decrypt the payload
omm image cloacked-pixel extract stego.png \
  --password 'p@ssw0rd' \
  --output secret.zip

# Extract can also brute-force the AES password from a custom wordlist
omm image cloacked-pixel extract stego.png \
  --wordlist passwords.txt --contains 'flag{' \
  --output secret.bin

# Equivalent explicit brute subcommand; filters reduce padding false positives
omm image cloacked-pixel brute stego.png \
  --wordlist passwords.txt --contains 'flag{' \
  --output secret.bin

omm image cloacked-pixel brute stego.png \
  --wordlist passwords.txt --prefix 'PK' \
  --output secret.zip

# Basic cloacked-pixel detection: encrypted LSB regions trend toward 0.5
omm image cloacked-pixel analyse stego.png \
  --block-size 100 --threshold 0.08 --json
```

`extract --wordlist` and `brute` read normal text dictionaries (one password per line), accept candidates with valid AES-CBC padding, and can additionally require `--contains` or `--prefix` bytes in the decrypted payload to avoid padding-only false positives. `analyse` reports RGB LSB means and how many blocks are close to 0.5, matching the original tool's detection idea for encrypted high-entropy payloads.



## Top-level stego namespace

`omm stego` is reserved for cross-carrier steganography tools: tools that can work across image and audio-style carriers, like OurSecret/SilentEye-style workflows. Format-specific image-only tools stay under `omm image ...`. The older `omm image stegpy ...` and `omm image steghide ...` forms remain available for compatibility.

```bash
omm stego steghide extract stego.jpg --password '' -o hidden.bin
omm stego steghide extract stego.wav --wordlist passwords.txt --contains 'flag{' -o hidden.bin
omm stego stegpy extract stego.png --wordlist passwords.txt --contains 'flag{' -o payload.bin
omm stego stegpy extract stego.wav --password 'p@ss' -o payload.bin
omm stego oursecret extract carrier.bin --password 'pw' -o hidden/
omm stego oursecret hide carrier.bmp --payload secret.txt --password 'pw' --mode lsb -o stego.bmp
omm stego deegger inspect carrier.bin --json
omm stego deegger extract carrier.bin -o hidden.bin
omm stego deegger extract-files carrier.bin -o hidden_files/
omm stego deegger hide carrier.jpg --payload secret.txt -o stego.jpg
omm stego deepsound analyze carrier.wav --json
omm stego deepsound extract carrier.wav -o hidden/
```

`omm stego silenteye` is a native Python port of SilentEye's GPL modules for BMP-style image carriers and PCM WAV carriers. It mirrors the source layout: 32-bit little-endian hidden-size header, LSB chunks read little-endian through `EncodedData`, default qCompress wrapping, optional AES128/AES256-CBC-PKCS7 with SilentEye's fixed module key and MD5-derived IV, and the default options from `seformatbmp.conf`/`seformatwav.conf` (`3` bits, equidistant distribution, BMP `signature` header, WAV `ending` header).

```bash
# Decode the common CTF path; default GUI password is often silenteye.
omm stego silenteye extract carrier.wav --password silenteye --output hidden.bin
omm stego silenteye extract carrier.bmp --password silenteye --output hidden.bin

# Try unencrypted/uncompressed or custom GUI options.
omm stego silenteye extract carrier.wav --compressed no --bits 1 --channels 1 -o hidden.bin
omm stego silenteye extract carrier.bmp --colors b --bits 1 --header-position signature -o hidden.bin

# Create compatible carriers from text or a file.
omm stego silenteye hide cover.wav --text 'flag{demo}' --password silenteye -o stego.wav
omm stego silenteye hide cover.bmp --payload secret.zip --password silenteye -o stego.bmp
```

`--carrier auto` maps WAV files to the WAV module and image files to the BMP-style module. The BMP-style writer outputs BMP because that is the lossless format used by SilentEye's BMP module.


`omm stego deegger` implements the DeEgger Embedder 1.2.1.1 format recovered
from the provided MSI. DeEgger is an arbitrary-carrier append format:
`host || BREAK_START || bitwise-not(payload) || BREAK_STOP ||
bitwise-not(extension + NUL)`, where the recovered markers are
`&)($#^@*#^(\0` and `$#&)*@&(#^*\0`. Multi-Hidden mode stores multiple files as
a Microsoft Cabinet payload with extension `.1`; extraction is pure Python for
uncompressed and MSZIP CAB blocks, and native hiding can create compatible
uncompressed CAB payloads.

```bash
# Check for DeEgger markers and the hidden extension.
omm stego deegger inspect suspect.bin --json

# Extract one hidden file; if the output has no suffix, the recovered suffix is used.
omm stego deegger extract suspect.bin --output hidden

# Extract and unpack Multi-Hidden CAB payloads.
omm stego deegger extract-files suspect.bin --output out/

# Build compatible arbitrary-carrier samples.
omm stego deegger hide carrier.jpg --payload secret.txt --output stego.jpg
omm stego deegger hide carrier.bin --payload a.txt --payload b.dat -o multi.bin
```

`omm stego deepsound` is a native Python implementation of the common DeepSound 2.x WAV CTF path. It scans the WAV `data` chunk for the normal-quality encoded `DSCF` header, supports the official quality factors (`low=2`, `normal=4`, `high=8`), extracts unencrypted/no-password `DSCF` file records, and reports the SHA1 password verifier found in encrypted headers for dictionary workflows. The encoder writes the no-password layout used by the extractor and keeps the original RIFF chunks intact except for carrier bytes touched by the DeepSound bit/nibble packing.

```bash
# Scan a suspicious WAV; encrypted samples expose password_hash in JSON.
omm stego deepsound analyze suspect.wav --json

# Extract no-password DeepSound payloads to a directory or single file.
omm stego deepsound extract suspect.wav --output out/
omm stego deepsound extract suspect.wav --output hidden.bin

# Build no-password DeepSound WAV carriers for local repro/tests.
omm stego deepsound hide cover.wav --payload secret.txt --quality normal -o stego.wav
omm stego deepsound hide cover.wav --text 'flag{demo}' --text-name flag.txt -o stego.wav
```

`omm stego oursecret` implements the OurSecret-style format recovered from the provided script and verified against `OurSecret.exe` 2.5.5.0: arbitrary-file append mode (`carrier || 40-byte OurSecret EOF signature || Blowfish-ECB(zip) || 28-byte HI trailer`) and 24-bit BMP LSB mode. The password is checked against `MD5(password) ^ 0x08` in the trailer; the payload cipher key is the fixed OurSecret Blowfish key, so extraction can also run without a password when you only need the embedded ZIP. Existing legacy samples without the 40-byte signature are still accepted, and `inspect` also reports signature-only carrier hits.

```bash
# Check HI trailer / BMP LSB marker
omm stego oursecret inspect suspect.bin --json

# Extract appended OurSecret data
omm stego oursecret extract suspect.bin -o out/

# Verify password tag before extracting
omm stego oursecret extract suspect.bin --password 'pass123' -o out/

# Build compatible carriers
omm stego oursecret hide carrier.bin --payload secret.txt --password 'pass123' -o stego.bin
omm stego oursecret hide carrier.bin --payload secret.txt --no-signature -o legacy.bin
omm stego oursecret hide carrier.bmp --text 'flag{demo}' --mode lsb -o stego.bmp
```

Image/JPEG-specific tools remain under `omm image`, for example `pixeljihad`, `jphs`, `stegdetect`, and `cloacked-pixel`.

## Top-level text namespace, Whitespace, SNOW, SpamMimic and zero-width steganography

`omm text` is for text carriers and text-only esolangs. The Whitespace implementation follows the classic language model: only space, tab and linefeed are meaningful; all visible characters are ignored as comments. The interpreter supports stack manipulation, arithmetic, heap access, flow control and I/O, so CTF files that hide a Whitespace program inside ordinary-looking text can be run locally.

```bash
# Run hidden Whitespace and write stdout
omm text whitespace run hidden.txt --output flag.txt

# Print stdout directly; decode is an alias for run
omm text ws decode hidden.txt

# Make invisible code visible as S/T/L tokens
omm text whitespace show hidden.txt --style stl --output visible.txt

# Generate a simple Whitespace program that prints a flag or payload bytes
omm text whitespace encode --text 'flag{demo}' --output flag.ws
omm text whitespace encode --payload secret.bin --output secret.ws
```

`run` accepts `--input` or `--input-file` for programs that use Whitespace read instructions, and `--max-steps` prevents accidental infinite loops. `show --style unicode` uses visible symbols (`·`, `⇥`, `↵`) instead of `S/T/L`.

SNOW/stegsnow hides ordinary bytes in trailing spaces and tabs at the end of text lines. The Python backend implements the classic start-tab plus 3-bit space-count line-end encoding and keeps the visible text unchanged after stripping line-end whitespace. Password mode (`-p`) and compression (`-C`) are handled in-process with a native protected payload wrapper, so `auto`, `native` and the legacy `tool` backend spelling all stay inside Python.

```bash
# Native no-password SNOW hide/extract
omm text snow hide cover.txt --payload secret.bin --output stego.txt
omm text snow extract stego.txt --output recovered.bin

# Alias and capacity check
omm text stegsnow capacity cover.txt --line-length 72 --json

# Native -C / -p
omm text snow hide cover.txt --text 'flag{demo}' -C -p 'pw' --backend native --output stego.txt
omm text snow extract stego.txt -C -p 'pw' --backend native --output flag.txt
```


SpamMimic-style linguistic steganography turns a short payload into junk-mail prose. The native backend is deterministic and offline: it uses a spam grammar with reversible production choices, supports a `space` variant using trailing spaces/tabs, and can wrap the payload with a password-derived stream for CTF dictionary attacks. The legacy `remote` and `auto` backend spellings are accepted for CLI compatibility and route to the same Python implementation.

```bash
# Offline native spam grammar
omm text spammimic encode --text 'flag{demo}' --output spam.txt
omm text spammimic decode spam.txt --backend native --output flag.txt

# Legacy backend spelling, still native Python
omm text spammimic decode spam.txt --backend remote --output flag.txt

# Password and custom dictionary workflows
omm text spammimic encode --text 'flag{demo}' -p 'pw' --output spam.txt
omm text spammimic decode spam.txt -p 'pw' --output flag.txt
omm text spammimic decode spam.txt --wordlist passwords.txt --contains 'flag{' --output flag.txt

# Space variant
omm text spammimic encode --mode space --cover cover.txt --text 'flag{demo}' --output stego.txt
omm text spammimic decode --mode space stego.txt --output flag.txt
```

Zero-width character steganography hides data in invisible Unicode format/control characters. The default alphabet matches the 330k web tool (`U+200C U+200D U+202C U+FEFF`) and `--chars` lets you decode CTF samples that use another set after `inspect` shows which code points are present. `--mode binary` stores raw bytes; `--mode text` follows the 330k UTF-16 text codec.

```bash
# See which invisible characters exist before choosing a charset
omm text zwc inspect suspect.txt --json

# Decode with the 330k default charset
omm text zerowidth extract suspect.txt --output hidden.bin

# Decode a two-symbol 0/1 charset discovered by inspect/vim
omm text zwc extract suspect.txt --chars U+200B,U+200C --output flag.txt

# Embed text and clean a file
omm text zwc hide cover.txt --text 'flag{demo}' --output stego.txt
omm text zwc strip stego.txt --output clean.txt
```

Cloakify maps Base64 characters to lines from a shared cipher list. The implementation follows the standalone scripts: Base64-encode any file, translate each Base64 character with the first 65 non-empty unique cipher entries, then reverse the mapping with the same cipher during decloak. This covers the CTF workflow where you receive `cipher.txt` plus `passwd.txt`/dictionary and run `decloakify.py cipher.txt passwd.txt`.

```bash
# Decode a Cloakify challenge sample
omm text cloakify decloak cipher.txt --cipher passwd.txt --output payload.bin

# Inspect line count and dictionary hits before decoding
omm text cloakify inspect cipher.txt --cipher passwd.txt --json

# Create a compatible Cloakify text from any payload
omm text cloakify cloak secret.zip --cipher passwd.txt --output cloaked.txt
```

## Top-level zip namespace, password cracking and CRC32 brute force

`omm zip` is for archive-focused CTF workflows. `omm zip crack` performs fast password cracking for encrypted archives. For classic ZIP/ZipCrypto it uses a native verifier that decrypts only the 12-byte encryption header before doing a full CRC check, so large dictionaries are filtered quickly. 7z archives are checked and extracted natively through py7zr; no `7z`/`7zz` executable is required.

```bash
# Fast custom dictionary attack; one password per line
omm zip crack encrypted.zip --wordlist passwords.txt --workers 0 --json

# Generate numeric PIN candidates without a dictionary
omm zip crack encrypted.zip --charset digits --min-length 1 --max-length 6

# Crack a 7z archive through the native py7zr backend and extract after a hit
omm zip crack secret.7z --backend 7z --wordlist passwords.txt --output unpacked/
```

`omm zip plaintext` is a native Python implementation of the bkcrack-style ZipCrypto known-plaintext workflow. Provide a known plaintext file, or a ZIP containing the matching plaintext entry, to recover the three internal keys. Then export a passwordless ZIP, change the password, or enumerate an equivalent original password from known keys.

```bash
# List built-in classic CTF known-plaintext presets
omm zip plaintext presets --json

# Presets for the eight classic cases: text/png/zip/exe/pcapng/xml/svg/vmdk
omm zip plaintext preset png flag.zip --entry 2.png -o out.zip
omm zip plaintext preset text flag.zip --entry flag.txt --plain-text 'lag{16e3' --extra-text '29:74f6' -o out.zip
omm zip plaintext preset zip flag.zip --entry flag.zip --inner-name flag.txt -o out.zip
omm zip plaintext preset exe flag.zip --entry nc64.exe -o out.zip
omm zip plaintext preset pcapng flag.zip --entry capture.pcapng -o out.zip
omm zip plaintext preset xml flag.zip --entry 123/web.xml -o out.zip
omm zip plaintext preset svg flag.zip --entry spiral.svg -o out.zip
omm zip plaintext preset vmdk flag.zip --entry flag.vmdk -o out.zip

# Fully custom plaintext: file/text/hex + offset + extra fragments
omm zip plaintext preset custom flag.zip \
  --entry mystery.bin \
  --plain-hex 255044462d312e37 \
  --offset 0 \
  --extra-text '128:stream' \
  -o out.zip

# Reusable custom preset JSON with name/offset/plain_hex or plain_text/plain_file/extra_text
omm zip plaintext preset custom flag.zip --entry mystery.bin --preset-file pdf.json -o out.zip

# Recover keys from a known plaintext file and export a ZIP with empty password
omm zip plaintext attack flag.zip --entry hint.jpg --plain-file hint.jpg --output out.zip

# If the known plaintext must be compressed the same way, point at a plaintext ZIP
omm zip plaintext attack flag.zip --entry sha512.txt --plain-zip sha512.zip --plain-entry sha512.txt

# Use already recovered keys to remove password protection
omm zip plaintext keys flag.zip --keys afb9fee3 f8795353 f6de1d4e --decrypt -o clear.zip

# Recover an equivalent password from keys
omm zip plaintext recover-password flag.zip --keys afb9fee3 f8795353 f6de1d4e --length 1..8 --charset '?l?u?d'
```

`omm zip invisible-password` targets the CTF trick where the archive password is invisible or non-printable. It can try explicit Base64-encoded password bytes, text candidates, brute-force raw byte sequences like `\x00`, and common zero-width Unicode passwords. The JSON output always includes `found_password_hex`, so invisible hits remain observable.

```bash
# The password bytes are not printable; provide them as Base64
omm zip invisible-password encrypted.zip --password-b64 AP8= --backend native --output out/

# Try all one/two-byte raw passwords 00..ff without writing a wordlist
omm zip invisible-password encrypted.zip --brute-raw --min-bytes 1 --max-bytes 2 --backend native

# Try common zero-width Unicode characters as password text
omm zip invis-pass encrypted.zip --zero-width --min-chars 1 --max-chars 2 --json
```

`omm zip timestamp` handles timestamp steganography in ZIP entries and extracted directories. The decoder computes `value=(timestamp-base)/scale+offset` for each selected file and writes those values as bytes; this covers the common `chr(modified_timestamp - 1737276000 + 1)` pattern as `--base 1737276000 --offset 1`. ZIP reads keep archive order by default, while directory reads default to numeric filename order.

```bash
# Inspect ZIP entry modification timestamps and decoded characters
omm zip timestamp list challenge.zip --include .txt --base 1737276000 --offset 1 --json

# Extract from encrypted or normal ZIP metadata without reading file contents
omm zip timestamp extract challenge.zip --include .txt --base 1737276000 --offset 1 -o hidden.bin

# If extraction preserved filesystem mtimes, decode from the output directory
omm zip timestamp extract out/ --source dir --sort numeric --base 1737276000 -o hidden.bin

# Create a timestamp-stego ZIP; scale 2 avoids ZIP's two-second timestamp granularity
omm zip timestamp embed cover.zip --text 'flag{demo}' --base 1737276000 -o time.zip
```

`omm zip ntfs-stream` extracts NTFS Alternate Data Streams saved inside RAR4/RAR5
archives, the RAR-side form used by WinRAR's "Save file streams" option. It
scans service headers named `STM`, maps each `host:stream` pair to a portable
sidecar file under `<host>.streams/`, and writes `ads_manifest.json` so the
original stream path remains visible on non-NTFS systems.

```bash
# List hidden NTFS streams without extracting
omm zip ntfs-stream list challenge.rar --json

# Extract streams to sidecar files like out/docs/readme.txt.streams/secret
omm zip ntfs-stream extract challenge.rar --output out/

# Filter by host+stream name and replace existing sidecar files
omm zip ads extract challenge.rar --include ':Zone.Identifier' --overwrite -o out/
```

`omm zip crc` targets the common ZIP CRC32 small-file challenge: ZIP headers store the original file CRC32 and uncompressed size, so very short entries can be recovered by reversing/bruteforcing CRC32 without knowing the compressed bytes. The default charset is all bytes (`0x00..0xff`) to cover non-printable payloads; use `--charset printable`, `--prefix`, or `--suffix` to reduce ambiguous candidates.

```bash
# See ZIP entry names, CRC32 and original size
omm zip crc list challenge.zip --json

# Recover the only file in a ZIP using printable bytes
omm zip crc brute challenge.zip --charset printable --output recovered.bin

# Select an entry and use known flag constraints
omm zip crc brute challenge.zip --entry tiny.txt --charset flag \
  --prefix 'flag{' --suffix '}' --output candidates/

# Raw CRC32 reverse without a ZIP file
omm zip crc reverse --crc 0x7c2df918 --length 4 --charset all --output candidate.bin
```

When there is one candidate, `--output` is written as a file. When multiple candidates are found, `--output` is treated as a directory and receives `candidate_000.bin`, `candidate_001.bin`, etc. `--max-prefixes` caps the length-4 prefix enumeration for large searches.

`omm zip nested` recursively unpacks archive dolls. Native handlers cover ZIP, TAR, tar.gz, tar.bz2, tar.xz, gzip, bzip2, xz and 7z through py7zr. Each layer is written into a numbered directory, so intermediate archives are kept for review.

```bash
# Auto-detect by signature/format and keep extracting nested archives
omm zip nested flag.zip --output unrolled/

# Mixed chain with limits and optional password for zip/7z
omm zip unpack shell9999.tar.gz --output unrolled/ --max-depth 200 --password 'pw'

# JSON report includes every layer, archive type and final files
omm zip nested flag.zip -o unrolled/ --json
```

## steghide empty-password and dictionary extraction

`omm stego steghide` uses an in-process native backend. The native backend extracts steghide 0.5.x payloads from JPEG DCT, BMP and PCM WAV/AU carriers, including the common empty-password case and AES/Rijndael-128-CBC payloads. `--backend auto`, `--backend native` and the legacy `--backend tool` spelling all route to the Python implementation.

```bash
# Empty-password extraction through the built-in backend when possible.
omm stego steghide extract stego.jpg --password '' --output hidden.bin

# Explicit native selector.
omm stego steghide extract stego.wav --backend native -p '' -o hidden.bin

# Dictionary mode tries empty password first unless --no-empty is set.
omm stego steghide brute stego.wav \
  --wordlist passwords.txt --contains 'flag{' \
  --backend auto --output hidden.txt

# Legacy backend spelling, still native Python.
omm stego steghide extract stego.bmp \
  --backend tool \
  --password pass --output hidden.bin
```

The older `omm image steghide ...` spelling remains available.

## Image Steganography 1.4.5.2 native mode

`omm image image-steganography` implements the VB.NET tool recovered from the
attached `Image Steganography 1.4.5.2 Setup.zip`. The native backend matches the
two engine modes: `enlarge` stores data in 2× enlarged 2x2 pixel blocks, and
`difference` stores one byte per pixel as R/B channel deltas and needs the
original image for extraction. Password mode mirrors the binary's
AES-CBC/PKCS7 + PBKDF2-HMAC-SHA1 derivation with the 14-byte static salt found
in `AESCryptByte`.

```bash
# Default Enlarge mode: output dimensions are doubled.
omm image image-steganography hide cover.png --text 'flag{demo}' \
  --password 'p@ss' --output stego.png
omm image image-steganography extract stego.png --password 'p@ss' \
  --output payload.bin

# Difference mode: keep the original image and pass it back as --reference.
omm image image-steganography hide cover.png --payload secret.bin \
  --mode difference --output diff.png
omm image image-steganography extract diff.png --mode difference \
  --reference cover.png --output secret.bin

# Aliases: image-steg, imgsteg, img-steg.
omm image image-steg inspect stego.png --json
```

## stegpy stegv3 LSB steganography

Decode and create stegpy-compatible `stegv3` LSB payloads for PNG/BMP/GIF/WebP images and WAV files. Password mode follows stegpy's `-p` layout: PBKDF2-SHA256 derives a Fernet key, the salt is stored before the token, then the encrypted payload is embedded in low bits. Password-protected extraction also accepts a custom dictionary.

```bash
# Hide text or a file; --password matches stegpy -p encryption
omm image stegpy hide cover.png --text 'flag{demo}' --password 'p@ss' \
  --output stego.png

omm image stegpy hide cover.png --payload secret.zip --bits 2 \
  --output stego.png

# Extract with a known password
omm image stegpy extract stego.png --password 'p@ss' \
  --output payload.bin

# Or try one password per line from a custom dictionary
omm image stegpy extract stego.png \
  --wordlist passwords.txt --contains 'flag{' \
  --output payload.bin

omm image stegpy brute stego.png \
  --wordlist passwords.txt --prefix 'PK' \
  --output secret.zip
```

`--bits` supports 1, 2 or 4 low bits per carrier byte; the default is stegpy-compatible 2-bit embedding. JPEG DCT carriers are not rewritten by this native implementation, so use PNG/BMP/GIF/WebP/WAV hosts here.


## OutGuess JPEG/PNM steganography

Use the native OutGuess backend for the CTF workflow shown in the guide: `outguess -k "abc" -r mmm.jpg flag.txt`. The Python backend ports the source algorithm's ARC4/MD5 encryption stream, adaptive iterator, header/body layout, PNM LSB handler and baseline-JPEG DCT coefficient handler. OutGuess is a JPEG/PNM image steganography tool, so this command stays under `omm image` rather than the cross-carrier `omm stego` namespace.

```bash
# Extract with a known key
omm image outguess extract mmm.jpg -k 'abc' --backend native --output flag.txt

# Try a custom key dictionary; empty key is tried first unless --no-empty is set
omm image outguess extract mmm.jpg \
  --wordlist passwords.txt --contains 'flag{' \
  --backend native --output flag.txt

# Explicit brute alias
omm image outguess brute mmm.jpg \
  --wordlist passwords.txt --prefix 'PK' \
  --output hidden.zip

# Create an OutGuess stego file
omm image outguess hide cover.jpg --payload secret.zip \
  -k 'abc' --backend native --output stego.jpg
```

`--backend auto`, `--backend native` and the legacy `--backend tool` spelling all route to the Python implementation for PNM/PPM/PGM and baseline JPEG files.

## jsteg JPEG DCT LSB steganography

`jsteg` is a JPEG-only DCT coefficient LSB scheme, so it lives under `omm image`. The native implementation follows [`lukechampine/jsteg`](https://github.com/lukechampine/jsteg): AC coefficients from the first scan component are read in JPEG zig-zag order, coefficients with values -1, 0 and 1 are skipped, and bits are packed least-significant-bit first. The command-compatible mode stores the upstream CLI wrapper format: `jsteg` magic, a 32-bit little-endian length, then the payload.

```bash
# Extract data produced by the upstream jsteg CLI wrapper
omm image jsteg reveal suspect.jpg --output hidden.bin

# Inspect raw coefficient LSB bytes when no magic/length wrapper is present
omm image jsteg reveal suspect.jpg --raw --output stream.bin

# Embed text or a file into an existing baseline JPEG
omm image jsteg hide cover.jpg --text 'flag{demo}' --output stego.jpg
omm image jsteg hide cover.jpg --payload secret.zip --output stego.jpg
```

The writer modifies the existing baseline sequential JPEG DCT coefficients directly and preserves the selected coefficients outside the -1/0/1 skip range, so a later reveal uses the same coefficient positions. Use `--raw` for challenge samples that use the package-level raw byte stream instead of the CLI magic/length wrapper.

## RAW/ARW Bayer LSB steganography

Extract LSB streams directly from camera RAW sensor data with `rawpy`. This matches the common CTF workflow of reading `raw.raw_image_visible`, taking the low bit from each Bayer sample, flattening it and rebuilding bytes. Install the optional dependency before using real RAW files:

```bash
pip install -e '.[raw]'
```

```bash
# Article-style extraction: bit 0, visible Bayer area, MSB-first byte packing
omm image raw-lsb extract sample.ARW --output payload.bin

# Try another bit plane / packing order and crop the RAW array first
omm image raw-lsb extract sample.ARW \
  --bit 1 --order lsb --crop 100,200,1024,768 \
  --offset 0 --limit 65536 --output stream.bin

# Scan common bit planes and write candidates whose stream contains a known file header
omm image raw-lsb scan sample.ARW --bits 0:4 --orders msb,lsb \
  --output raw-lsb-candidates/
```

`scan` writes `manifest.json` plus candidate streams when it sees headers such as ZIP, PNG, JPEG, PDF, GIF, RAR, 7z, gzip, SQLite, ELF or BMP. Use `--source full` to read `raw_image` including sensor margins instead of the default `raw_image_visible`, and `--write-all` to dump every tested bit/order stream even without a header hit.

## stegdetect-style JPEG stego triage

Run a native stegdetect-style triage command for legacy JPEG steganography hints. It accepts the familiar `-t` and `-s` options used by the old `stegdetect.exe -t jopi -s 10.0 file.jpg` workflow and reports candidate tools such as JSteg, OutGuess, JPHide, Invisible Secrets, F5 markers and appended data.

```bash
omm image stegdetect 0.jpg -t jopi -s 10.0
omm image stegdetect *.jpg --types jopifa --sensitivity 10.0 \
  --output stegdetect-report.txt
omm image stegdetect 0.jpg -t jopi -s 10.0 --json
```

The native implementation is a deterministic CTF triage helper: it follows the original stegdetect selector letters (`j/o/p/i/f/F/a`), parses JPEG markers, comments, scan data and post-EOI appended bytes for known tool signatures and simple hints, then emits scores and `*`/`**`/`***` confidence marks. A three-star result is still only a lead, matching the original tool's common CTF usage.

## wbStego4open native steganography

`wbStego4open` is GPL source for hiding data in BMP/TXT/HTML/PDF. This project implements the carrier formats natively from the Pascal source: BMP LSB replacement including uncompressed 24/8/4-bit and BMP RLE8/RLE4 carriers, TXT/HTML line-prefix insertion, PDF line-prefix insertion outside `obj ... endobj`, and the ASCII replacement mode (`asc`) that maps payload bits onto existing space/NUL bytes. The payload layout follows `DataFile.pas`: three extension bytes, a 24-bit little-endian length, optional distributed filler, plus the original control-byte password wrapper for legacy MLK/BBS XOR crypt, Mix matrix permutation and Transmit password verification.

Source reviewed:

- [wbStego official download page](https://bailer.at/wbstego/fs_download.html)
- [wbStego4open overview](https://bailer.at/wbstego/pr_4ixopen.htm)
- `BMPReplace.pas`, `ASCIIReplace.pas`, `ASCIIInsert.pas`, `PDFInsert.pas`, `DataFile.pas` from the official `wbs43open-src.zip`

```bash
# wbStego4open is available in the general stego namespace; image remains as a compatibility alias
omm stego wbstego extract carrier.bmp -o hidden.bin
omm image wbstego extract carrier.bmp -o hidden.bin

# Auto-detect BMP/HTML/PDF by extension; other files default to txt line-prefix mode
omm stego wbstego extract carrier.html -o hidden.bin
omm stego wbstego extract carrier.pdf -o hidden.bin

# Force a specific carrier mode
omm stego wbstego extract carrier.txt --carrier txt -o hidden.bin
omm stego wbstego extract carrier.txt --carrier asc -o hidden.bin
omm stego wbstego extract carrier.html --carrier html -o hidden.bin
omm stego wbstego extract carrier.pdf --carrier pdf -o hidden.bin

# Embed payloads in matching wbStego4open no-password layouts
omm stego wbstego hide cover.bmp --payload secret.txt -o stego.bmp
omm stego wbstego hide cover.txt --carrier txt --payload secret.txt -o stego.txt
omm stego wbstego hide cover.txt --carrier asc --payload secret.txt -o stego.asc
omm stego wbstego hide cover.html --carrier html --payload secret.txt -o stego.html
omm stego wbstego hide cover.pdf --carrier pdf --payload secret.txt -o stego.pdf

# Match wbStego's optional distributed filler mode
omm stego wbstego hide cover.bmp --payload secret.txt --distribute -o stego.bmp

# Password-compatible legacy wrapper: control byte + MLK/BBS XOR, optional Mix/Transmit
omm stego wbstego hide cover.txt --carrier txt --payload secret.txt \
  --password abc123 --mix --transmit-password -o stego.txt
omm stego wbstego extract stego.txt --carrier txt --password abc123 -o hidden.bin

# Custom dictionary brute force for password-protected carriers
omm stego wbstego extract stego.asc --carrier asc --wordlist passwords.txt \
  --contains 'flag{' -o hidden.bin

# Show capacity
omm stego wbstego analyse cover.pdf --carrier pdf --json
```

`omm stego wbstego` is the preferred namespace because wbStego4open covers image and text/PDF carriers; `omm image wbstego` is kept as a compatibility alias. The native BMP backend supports uncompressed 24-bit, 8-bit and 4-bit BMP carriers plus BMP RLE8/RLE4 streams. `--carrier auto` maps `.bmp` to BMP, `.htm/.html` to HTML, `.pdf` to PDF, and other extensions to TXT; use `--carrier asc` for the wbStego ASCIIReplace space/NUL mode. Password mode mirrors the original v3 control-byte flow (`Crypt`, `Mix`, `Transmit`) for legacy files; v4 block-cipher headers are detected as password-wrapped data but the deterministic native path currently targets the common MLK/BBS password mode. Output extension recovery is reported in JSON as `embedded_extension`.

## F5-steganography native JPEG implementation

F5 is Andreas Westfeld's JPEG DCT steganography algorithm. The guide's Java workflow is `java Extract beautiful.jpg -p passwd`; this project implements the same extraction path natively in Python: SHA1PRNG-compatible password stream, F5 permutation, status-word decoding, matrix-code extraction and JPEG Huffman/DCT coefficient parsing.

Source mirrored for compatibility work:

- [`matthewgao/F5-steganography`](https://github.com/matthewgao/F5-steganography)
- [Google Code archive: F5 Steganography in Java](https://code.google.com/archive/p/f5-steganography/)

```bash
# Known password, equivalent to: java Extract beautiful.jpg -p passwd
omm image f5 extract beautiful.jpg -p passwd -o output.txt

# F5's original default password is abc123
omm image f5 extract beautiful.jpg -o output.txt

# Custom dictionary; abc123 is tried first unless --no-default is set
omm image f5 extract beautiful.jpg \
  --wordlist passwords.txt --contains 'flag{' \
  -o output.txt

# Explicit brute alias
omm image f5 brute beautiful.jpg \
  --wordlist passwords.txt --prefix 'PK' \
  -o hidden.zip

# Native embed into an existing baseline JPEG coefficient stream
omm image f5 hide cover.jpg --payload secret.zip \
  -p passwd -o stego.jpg
```

The extractor is compatible with original Java F5 stego JPEGs. The native embedder writes modified baseline sequential JPEG DCT coefficients directly; it expects a baseline JPEG input.

## JPHS / JPHide and JPSeek

JPHS is Allan Latham's JPHide/JPSeek JPEG steganography pair. This project implements the JPHS read/write path in Python for baseline sequential JPEG files: it parses JPEG Huffman scan data into quantized DCT coefficients, follows the JPHS `ltable` coefficient order, uses Blowfish for the pseudo-random stream, and writes the modified DCT coefficients back into a JPEG entropy scan.

Original/forked source:

- [`h3xx/jphs`](https://github.com/h3xx/jphs)
- [`thezakman/jphs`](https://github.com/thezakman/jphs)

The default backend is `python` for `hide`, `extract` and `brute`. The legacy `tool` and `auto` backend spellings are accepted for CLI compatibility and route to the same Python implementation.

```bash
# Pure Python extract
omm image jphs extract suspect.jpg \
  --password 'p@ss' \
  --output hidden.bin

# Pure Python custom dictionary; empty password is tried first unless --no-empty is set
omm image jphs extract suspect.jpg \
  --wordlist passwords.txt --contains 'flag{' \
  --output hidden.txt

# Pure Python explicit brute alias
omm image jphs brute suspect.jpg \
  --wordlist passwords.txt --prefix 'PK' \
  --output hidden.zip

# Pure Python embed
omm image jphs hide cover.jpg --payload secret.zip \
  --password 'p@ss' \
  --output stego.jpg

# Legacy backend spelling, still native Python
omm image jphs extract suspect.jpg --backend auto --password 'p@ss' \
  --output hidden.bin
```

Python backend notes: the JPEG must be 8-bit baseline sequential with three components and no DRI restart interval when writing. Passwords use the local Blowfish implementation path exposed through PyCryptodome; the empty passphrase path is mapped to the native zero-key compatibility path.

## PixelJihad empty-password steganography

Decode PixelJihad images locally without opening the online tool. The decoder follows PixelJihad's SHA-256 based LSB location order, skips alpha bytes like the original canvas implementation, and extracts the empty-password JSON `text` payload. Multiple input images are sorted by natural filename order and concatenated, which matches common APNG-frame CTF workflows.

```bash
# Decode one image and print the hidden text
omm image pixeljihad decode encoded.png

# Decode split APNG/GIF frames and join their hidden text
omm image pixeljihad decode apngframe*.png --output flag.txt

# Try a custom password dictionary for password-protected bit locations
omm image pixeljihad decode encoded.png \
  --wordlist passwords.txt --contains 'flag{' \
  --output flag.txt

# Keep the raw embedded JSON/SJCL string instead of selecting the text field
omm image pixeljihad decode encoded.png --raw --json

# Create an empty-password PixelJihad sample for testing
omm image pixeljihad encode cover.png --text 'flag{demo}' --output encoded.png
```

Password-protected PixelJihad samples use the password to choose bit locations and then store an SJCL JSON ciphertext. `decode --password ... --raw` returns that ciphertext for a separate SJCL decryption step; `decode --wordlist passwords.txt` tries one location password per line and reports `found_password`/`attempts`; empty-password samples return the plaintext directly.

## CVE-2023-28303 / aCropalypse screenshot recovery

Restore PNG screenshots affected by the Windows Snipping Tool / Snip & Sketch truncation issue. The restore command looks for trailing `IDAT` data, reconstructs a shifted DEFLATE stream and writes the recovered pixels onto a magenta-filled canvas. This follows the approach used by Acropalypse-Multi-Tool and SnipRecover-CLI.

```bash
# Restore with the original screenshot dimensions and colour mode
omm image acropalypse restore cropped.png \
  --width 1920 --height 1080 --mode rgba \
  --output restored.png
```

Use the original screenshot size where possible. Unknown regions remain magenta; recovered bytes are placed at the end of the target scanline buffer, matching the public PoC recovery workflow.

## Grid puzzle solver

Restore shuffled, equally sized image tiles by minimizing colour and gradient discontinuities along every internal edge. The solver accepts separate tile files or one montage sheet and does not require Docker, ImageMagick, `gaps` or Puzzle-Merak.

```bash
# Inspect tile dimensions and possible row/column combinations
omm image puzzle analyze shuffled-sheet.png --tile-size 125 --json

# Solve separate pieces; auto uses exact search for small puzzles and a genetic solver for larger ones
omm image puzzle solve pieces/*.png --rows 10 --columns 18 \
  --algorithm auto --generations 300 --seed 2026 \
  --output solved.png

# Split and solve a montage while considering 90-degree rotations
omm image puzzle solve shuffled-sheet.png --tile-size 125 \
  --rows 10 --columns 18 --rotate 90 \
  --output solved.png
```

`solve` writes the reconstructed image and a sibling `*.puzzle.json` manifest containing every source tile, position, rotation, score and deterministic seed. Use `--manifest` to choose another manifest path. `--algorithm` accepts `auto`, `exact`, `genetic` and `greedy`; exact search is bounded to small puzzles, while the genetic solver supports the larger challenge layouts commonly passed to `gaps`.

## WaterMarkH-compatible single-image blind watermark

The single-image watermark command reproduces WaterMarkH's three-channel FFT workflow: power-of-two image preparation, symmetric text rendering, orthonormal frequency-domain embedding, inverse FFT reconstruction and magnitude-spectrum extraction.

```bash
omm image watermark single watermarkh embed source.png \
  --text 'flag{demo}' --strength 20 --scheme best \
  --font /path/to/font.ttf --font-size 32 \
  --output watermarked.png

omm image watermark single watermarkh extract watermarked.png \
  --brightness 5 --scheme best \
  --output extracted.png
```

`--scheme` accepts `best`, `high`, `low`, `pad` and `partial`, corresponding to the five image-size strategies in WaterMarkH. Font rasterization and image codecs use the local Pillow backend; the FFT scaling, strength, brightness, symmetry and channel-processing rules follow the recovered executable behavior.

## Dual-image frequency-domain blind watermark

The dual-image command implements the shuffled, centrally symmetric frequency-domain image-watermark workflow used by `chishaxie/BlindWaterMark` and `linyacool/blind-watermark`. Extraction requires the original carrier image.

```bash
omm image watermark dual chishaxie embed source.png \
  --watermark mark.png \
  --output watermarked.png

omm image watermark dual chishaxie extract watermarked.png \
  --reference source.png \
  --width 224 --height 150 \
  --output extracted-mark.png
```

`chishaxie` defaults to seed `20160930` and alpha `3`; `linyacool` defaults to seed `width + height` and alpha `5`. Use `--seed` and `--alpha` for non-default samples. Supplying the known watermark `--width` and `--height` gives a deterministic crop; otherwise the command estimates the occupied area, while `--no-crop` retains the full recovered upper half of the carrier.

## ww23 DCT/DFT blind watermark

The `ww23` command reproduces the image-watermark paths from [`ww23/BlindWatermark`](https://github.com/ww23/BlindWatermark). Its default DCT mode embeds a centered watermark independently into all three carrier channels and extracts it from the watermarked image alone. The older DFT path remains available for challenge compatibility.

```bash
omm image watermark dual ww23-dct embed source.png \
  --watermark mark.png \
  --output watermarked.png

omm image watermark dual ww23-dct extract watermarked.png \
  --output extracted-spectrum.png
```

DCT defaults to alpha `0.03`; DFT defaults to alpha `8`. Override the embedding strength with `--alpha`.

## Planned commands

```text
omm inspect FILE
omm image analyze FILE [--quick|--full]
omm image planes FILE
omm image lsb scan|extract FILE
omm image frames FILE
omm image repair FILE
omm image carve FILE
```

## Design principles

- Native installation; no Docker runtime requirement.
- Stable JSON for agents and readable terminal output for humans.
- Deterministic, bounded analysis with explicit evidence and artifacts.
- Independent implementations informed by format specifications and public test vectors.
- Extensible analyzers for images, audio, archives, traffic and documents.

## License

GPL-3.0-only.
