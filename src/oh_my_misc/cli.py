from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from oh_my_misc import __version__
from oh_my_misc.acropalypse import restore_acropalypse_png
from oh_my_misc.archive_crack import crack_archive_password
from oh_my_misc.backpaper import decode_backpaper, encode_backpaper
from oh_my_misc.cloacked_pixel import (
    analyse_cloacked_pixel,
    brute_cloacked_pixel,
    extract_cloacked_pixel,
    hide_cloacked_pixel,
)
from oh_my_misc.deepsound import analyze_deepsound, extract_deepsound, hide_deepsound
from oh_my_misc.f5 import brute_f5, extract_f5, hide_f5
from oh_my_misc.ham_radio import decode_ham_radio, encode_ax25_afsk1200_wav, inspect_ham_radio
from oh_my_misc.image_ops import (
    COMBINE_OPERATIONS,
    arnold_transform_image,
    brute_arnold_images,
    combine_images,
    depixelize_mosaic,
    flip_image,
    join_images,
    pixelate_image,
    sample_pixels,
    split_frames,
    split_grid,
)
from oh_my_misc.inspection import inspect_file
from oh_my_misc.jphs import brute_jphs, extract_jphs, hide_jphs
from oh_my_misc.jsteg import hide_jsteg, reveal_jsteg
from oh_my_misc.lyra import SUPPORTED_BITRATES as LYRA_SUPPORTED_BITRATES
from oh_my_misc.lyra import SUPPORTED_SAMPLE_RATES as LYRA_SUPPORTED_SAMPLE_RATES
from oh_my_misc.lyra import decode_lyra, encode_lyra, inspect_lyra
from oh_my_misc.midi_qr import render_midi_qr
from oh_my_misc.mp3_frame_stego import FIELD_CHOICES as MP3_FIELD_CHOICES
from oh_my_misc.mp3_frame_stego import extract_mp3_frame_field, scan_mp3_frame_fields
from oh_my_misc.mp3stego import (
    DEFAULT_MAX_PAYLOAD_BYTES as MP3STEGO_DEFAULT_MAX_PAYLOAD_BYTES,
)
from oh_my_misc.mp3stego import (
    brute_mp3stego,
    encode_mp3stego,
    extract_mp3stego,
    inspect_mp3stego,
)
from oh_my_misc.npiet import run_piet
from oh_my_misc.oursecret import extract_oursecret, hide_oursecret, inspect_oursecret
from oh_my_misc.outguess import brute_outguess, extract_outguess, hide_outguess
from oh_my_misc.pixeljihad import (
    brute_pixeljihad_images,
    decode_pixeljihad_images,
    encode_pixeljihad_image,
)
from oh_my_misc.puzzle import analyze_puzzle, solve_puzzle
from oh_my_misc.rar_ntfs import extract_rar_ntfs_streams, list_rar_ntfs_streams
from oh_my_misc.raw_lsb import extract_raw_lsb, scan_raw_lsb
from oh_my_misc.silenteye import extract_silenteye, hide_silenteye
from oh_my_misc.spacefill import transform_spacefill_image
from oh_my_misc.spammimic import brute_spammimic, decode_spammimic, encode_spammimic
from oh_my_misc.sstv import MODE_CHOICES as SSTV_MODE_CHOICES
from oh_my_misc.sstv import decode_sstv, inspect_sstv
from oh_my_misc.stegdetect import run_stegdetect
from oh_my_misc.steghide import brute_steghide, extract_steghide
from oh_my_misc.stegpy_compat import brute_stegpy, extract_stegpy, hide_stegpy
from oh_my_misc.stereogram import solve_stereogram
from oh_my_misc.text_cloakify import cloakify_file, decloakify_file, inspect_cloakify
from oh_my_misc.text_snow import capacity_snow, extract_snow, hide_snow
from oh_my_misc.text_whitespace import encode_whitespace_text, render_whitespace, run_whitespace
from oh_my_misc.text_zerowidth import (
    extract_zero_width,
    hide_zero_width,
    inspect_zero_width,
    strip_zero_width_file,
)
from oh_my_misc.velato import decode_velato, encode_velato_text, inspect_velato
from oh_my_misc.watermark import (
    embed_dual_watermark,
    embed_single_watermark,
    embed_ww23_watermark,
    extract_dual_watermark,
    extract_single_watermark,
    extract_ww23_watermark,
)
from oh_my_misc.wavdata import (
    compare_wavdata,
    extract_channel_diff,
    extract_wav_lsb,
    fft_map_wavdata,
    freq_chars_wavdata,
    info_wavdata,
    wavdata_to_image,
)
from oh_my_misc.wbstego import analyse_wbstego, brute_wbstego, extract_wbstego, hide_wbstego
from oh_my_misc.zip_crc import brute_zip_crc, list_zip_crc, parse_crc32, reverse_crc32_direct
from oh_my_misc.zip_invisible import DEFAULT_INVISIBLE_CHARS, crack_invisible_archive_password
from oh_my_misc.zip_nested import unpack_nested_archives
from oh_my_misc.zip_plaintext import (
    PLAINTEXT_PRESET_ALIASES,
    known_plaintext_attack,
    known_plaintext_preset_attack,
    list_plaintext_presets,
    recover_password_from_keys,
)
from oh_my_misc.zip_timestamp import (
    embed_zip_timestamps,
    extract_timestamp_payload,
    list_archive_timestamps,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="omm", description="Native CTF Misc toolkit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    inspect_parser = commands.add_parser("inspect", help="生成文件基础画像")
    inspect_parser.add_argument("file", type=Path, help="待检查文件")
    inspect_parser.add_argument("--json", action="store_true", dest="as_json", help="输出稳定 JSON")
    image_parser = commands.add_parser("image", help="图片分析与隐写")
    image_commands = image_parser.add_subparsers(dest="image_command", required=True)

    zip_parser = commands.add_parser("zip", help="压缩包分析与修复，和 image 同级")
    zip_commands = zip_parser.add_subparsers(dest="zip_command", required=True)
    crc_parser = zip_commands.add_parser("crc", help="ZIP CRC32 信息查看与小文件反推爆破")
    crc_actions = crc_parser.add_subparsers(dest="crc_action", required=True)

    crc_list = crc_actions.add_parser(
        "list", aliases=["info"], help="列出 ZIP 条目的 CRC32 和原始大小"
    )
    crc_list.add_argument("file", type=Path, help="ZIP 文件")
    crc_list.add_argument("--json", action="store_true", dest="as_json")

    crc_brute = crc_actions.add_parser(
        "brute", aliases=["recover"], help="根据 ZIP 条目的 CRC32 和大小反推出小文件内容"
    )
    crc_brute.add_argument("file", type=Path, help="ZIP 文件")
    crc_brute.add_argument("--entry", help="ZIP 内文件名；只有一个文件时可省略")
    crc_brute.add_argument("-o", "--output", type=Path, help="输出文件；多个候选时作为目录")
    _add_zip_crc_reverse_options(crc_brute)
    crc_brute.add_argument("--json", action="store_true", dest="as_json")

    crc_reverse = crc_actions.add_parser(
        "reverse", aliases=["raw"], help="直接用 CRC32 与长度反推字节串"
    )
    crc_reverse.add_argument("--crc", required=True, help="目标 CRC32，例如 0x7c2df918")
    crc_reverse.add_argument("--length", type=int, required=True, help="目标明文长度")
    crc_reverse.add_argument("-o", "--output", type=Path, help="输出文件；多个候选时作为目录")
    _add_zip_crc_reverse_options(crc_reverse)
    crc_reverse.add_argument("--json", action="store_true", dest="as_json")

    crack_parser = zip_commands.add_parser(
        "crack", aliases=["brute"], help="高速爆破 ZIP/7z/RAR 等压缩包密码"
    )
    crack_parser.add_argument("file", type=Path, help="加密压缩包")
    crack_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    crack_parser.add_argument(
        "--charset",
        choices=(
            "all",
            "printable",
            "ascii",
            "digits",
            "lower",
            "upper",
            "alpha",
            "alnum",
            "hex",
            "flag",
        ),
        default="digits",
        help="无字典时的枚举字符集，默认 digits",
    )
    crack_parser.add_argument("--chars", help="自定义枚举字符，会覆盖 --charset")
    crack_parser.add_argument("--min-length", type=int, default=1, help="无字典时的最小总密码长度")
    crack_parser.add_argument("--max-length", type=int, help="无字典时的最大总密码长度")
    crack_parser.add_argument("--prefix", default="", help="已知密码前缀")
    crack_parser.add_argument("--suffix", default="", help="已知密码后缀")
    crack_parser.add_argument("--encoding", default="utf-8", help="密码文本编码，默认 utf-8")
    crack_parser.add_argument(
        "--backend",
        choices=("auto", "native", "7z"),
        default="auto",
        help="native 对 ZipCrypto 做 12 字节头快速筛选；7z 兼容更多格式",
    )
    crack_parser.add_argument("--workers", type=int, default=0, help="并发进程数，0=CPU 核数")
    crack_parser.add_argument("--chunk-size", type=int, default=4096, help="每个任务块候选数")
    crack_parser.add_argument("--max-attempts", type=int, help="最多尝试多少个候选")
    crack_parser.add_argument(
        "--no-verify", action="store_true", help="只做 ZIP 加密头筛选，不读完整条目校验"
    )
    crack_parser.add_argument("--sevenzip", type=Path, help="7z/7zz 可执行文件路径")
    crack_parser.add_argument("-o", "--output", type=Path, help="命中后解压到目录")
    crack_parser.add_argument("--json", action="store_true", dest="as_json")

    nested_parser = zip_commands.add_parser(
        "nested", aliases=["unpack", "unroll"], help="递归解压 ZIP/TAR/GZ/BZ2/XZ/7z/RAR 套娃"
    )
    nested_parser.add_argument("file", type=Path, help="初始压缩包")
    nested_parser.add_argument("-o", "--output", type=Path, required=True, help="输出目录")
    nested_parser.add_argument("--max-depth", type=int, default=100, help="最大递归深度，默认 100")
    nested_parser.add_argument(
        "--max-files", type=int, default=5000, help="最多解出文件数，默认 5000"
    )
    nested_parser.add_argument(
        "--max-output-bytes", type=int, default=1_000_000_000, help="最多解出总字节，默认 1GB"
    )
    nested_parser.add_argument("--password", help="传给 zip/7z/rar 的密码")
    nested_parser.add_argument(
        "--sevenzip", type=Path, help="7z/7zz/7za 可执行文件路径，用于 7z/rar"
    )
    nested_parser.add_argument(
        "--flatten-single", action="store_true", help="单文件链式套娃时优先沿唯一下一层继续解"
    )
    nested_parser.add_argument("--json", action="store_true", dest="as_json")

    invisible_parser = zip_commands.add_parser(
        "invisible-password",
        aliases=["invisible", "invis-pass"],
        help="爆破不可见字符/不可打印字节压缩包密码",
    )
    invisible_parser.add_argument("file", type=Path, help="加密压缩包")
    invisible_parser.add_argument(
        "--password-b64", action="append", help="直接提供 Base64 形式的密码字节，可重复"
    )
    invisible_parser.add_argument("--b64-file", type=Path, help="Base64 密码候选文件，一行一个")
    invisible_parser.add_argument(
        "--password-text", action="append", help="直接提供文本密码候选，可重复"
    )
    invisible_parser.add_argument("--text-file", type=Path, help="文本密码候选文件，一行一个")
    invisible_parser.add_argument(
        "--brute-raw", action="store_true", help="枚举原始不可打印字节 0x00..0xff"
    )
    invisible_parser.add_argument(
        "--min-bytes", type=int, default=1, help="--brute-raw 最小字节长度，默认 1"
    )
    invisible_parser.add_argument(
        "--max-bytes", type=int, default=2, help="--brute-raw 最大字节长度，默认 2"
    )
    invisible_parser.add_argument(
        "--zero-width", action="store_true", help="枚举常见零宽 Unicode 字符密码"
    )
    invisible_parser.add_argument(
        "--min-chars", type=int, default=1, help="--zero-width 最小字符数，默认 1"
    )
    invisible_parser.add_argument(
        "--max-chars", type=int, default=2, help="--zero-width 最大字符数，默认 2"
    )
    invisible_parser.add_argument(
        "--zero-width-chars", default=DEFAULT_INVISIBLE_CHARS, help="自定义零宽字符集合"
    )
    invisible_parser.add_argument(
        "--encoding", default="utf-8", help="文本/零宽密码编码，默认 utf-8"
    )
    invisible_parser.add_argument(
        "--backend",
        choices=("auto", "native", "7z"),
        default="auto",
        help="native 支持 ZipCrypto；7z 兼容更多格式",
    )
    invisible_parser.add_argument("--workers", type=int, default=0, help="并发进程数，0=CPU 核数")
    invisible_parser.add_argument("--chunk-size", type=int, default=4096, help="每个任务块候选数")
    invisible_parser.add_argument("--max-attempts", type=int, help="最多尝试多少个候选")
    invisible_parser.add_argument(
        "--no-verify", action="store_true", help="只做 ZIP 加密头筛选，不读完整条目校验"
    )
    invisible_parser.add_argument("--sevenzip", type=Path, help="7z/7zz 可执行文件路径")
    invisible_parser.add_argument("-o", "--output", type=Path, help="命中后解压到目录")
    invisible_parser.add_argument("--json", action="store_true", dest="as_json")

    timestamp_parser = zip_commands.add_parser(
        "timestamp",
        aliases=["time-stego", "time"],
        help="压缩包/目录文件时间戳隐写提取与写入",
    )
    timestamp_actions = timestamp_parser.add_subparsers(dest="timestamp_action", required=True)

    timestamp_list = timestamp_actions.add_parser(
        "list", aliases=["scan"], help="列出 ZIP 条目或目录文件时间戳，可按基准解码字符"
    )
    timestamp_list.add_argument("file", type=Path, help="ZIP 文件或已解压目录")
    _add_zip_timestamp_common_options(timestamp_list)
    timestamp_list.add_argument("--json", action="store_true", dest="as_json")

    timestamp_extract = timestamp_actions.add_parser(
        "extract", aliases=["decode"], help="按 timestamp-base 公式提取隐写字节"
    )
    timestamp_extract.add_argument("file", type=Path, help="ZIP 文件或已解压目录")
    timestamp_extract.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    _add_zip_timestamp_common_options(timestamp_extract, require_base=True)
    timestamp_extract.add_argument("--json", action="store_true", dest="as_json")

    timestamp_embed = timestamp_actions.add_parser(
        "embed", aliases=["hide"], help="把字节写入 ZIP 条目修改时间"
    )
    timestamp_embed.add_argument("file", type=Path, help="输入 ZIP 文件")
    timestamp_payload = timestamp_embed.add_mutually_exclusive_group(required=True)
    timestamp_payload.add_argument("--text", help="要嵌入的 UTF-8 文本")
    timestamp_payload.add_argument("--payload", type=Path, help="要嵌入的二进制载荷文件")
    timestamp_embed.add_argument("-o", "--output", type=Path, required=True, help="输出 ZIP 文件")
    _add_zip_timestamp_common_options(
        timestamp_embed,
        include_source=False,
        include_field=False,
        require_base=True,
        default_scale=2,
    )
    timestamp_embed.add_argument("--json", action="store_true", dest="as_json")

    ntfs_parser = zip_commands.add_parser(
        "ntfs-stream",
        aliases=["ads", "rar-ads"],
        help="提取 RAR5 中保存的 NTFS Alternate Data Streams",
    )
    ntfs_actions = ntfs_parser.add_subparsers(dest="ntfs_action", required=True)

    ntfs_list = ntfs_actions.add_parser("list", aliases=["scan"], help="列出 RAR5 内的 NTFS 数据流")
    ntfs_list.add_argument("file", type=Path, help="RAR5 压缩包")
    ntfs_list.add_argument(
        "--include", default="", help="仅处理 host+stream 名称包含该子串的数据流"
    )
    ntfs_list.add_argument(
        "--glob", default="", help="仅处理匹配该 glob 的数据流，如 '*.txt:secret'"
    )
    ntfs_list.add_argument("--no-crc", action="store_true", help="不校验未压缩 stream CRC32")
    ntfs_list.add_argument("--json", action="store_true", dest="as_json")

    ntfs_extract = ntfs_actions.add_parser(
        "extract", aliases=["dump"], help="提取 RAR5 NTFS 数据流到 sidecar 文件"
    )
    ntfs_extract.add_argument("file", type=Path, help="RAR5 压缩包")
    ntfs_extract.add_argument("-o", "--output", type=Path, required=True, help="输出目录")
    ntfs_extract.add_argument(
        "--include", default="", help="仅处理 host+stream 名称包含该子串的数据流"
    )
    ntfs_extract.add_argument(
        "--glob", default="", help="仅处理匹配该 glob 的数据流，如 '*.txt:secret'"
    )
    ntfs_extract.add_argument(
        "--overwrite", action="store_true", help="覆盖已存在的输出 stream 文件"
    )
    ntfs_extract.add_argument("--no-manifest", action="store_true", help="不写 ads_manifest.json")
    ntfs_extract.add_argument("--no-crc", action="store_true", help="不校验未压缩 stream CRC32")
    ntfs_extract.add_argument("--json", action="store_true", dest="as_json")

    plaintext_parser = zip_commands.add_parser(
        "plaintext", aliases=["known-plaintext", "bkcrack"], help="ZipCrypto 明文攻击与三段密钥使用"
    )
    plaintext_actions = plaintext_parser.add_subparsers(dest="plaintext_action", required=True)

    attack_parser = plaintext_actions.add_parser("attack", help="用已知明文恢复三段 ZipCrypto 密钥")
    attack_parser.add_argument("file", type=Path, help="待攻击的加密 ZIP")
    attack_parser.add_argument("--entry", help="ZIP 内要攻击的加密条目；单加密条目可省略")
    attack_parser.add_argument(
        "--plain-file", type=Path, help="已知明文文件，或配合 --plain-zip 指定其中条目名"
    )
    attack_parser.add_argument("--plain-zip", type=Path, help="包含已知明文条目的 ZIP")
    attack_parser.add_argument(
        "--plain-entry", help="--plain-zip 内明文条目名，默认取 --plain-file 文件名或 --entry"
    )
    attack_parser.add_argument(
        "--offset", type=int, help="明文相对密文数据区偏移，不含 12 字节加密头"
    )
    attack_parser.add_argument("--extra", action="append", help="附加部分明文 OFFSET:HEX，可重复")
    attack_parser.add_argument("--truncate", type=int, help="最多读取多少明文字节")
    attack_parser.add_argument(
        "--ignore-check-byte", action="store_true", help="不自动使用 check byte"
    )
    attack_parser.add_argument("--jobs", type=int, default=0, help="bkcrack 线程数，0=默认")
    attack_parser.add_argument("--bkcrack", type=Path, help="bkcrack 可执行文件路径")
    attack_parser.add_argument(
        "--new-password", default="", help="命中后用 -U 改成的新密码，默认空密码"
    )
    attack_parser.add_argument(
        "--decrypt", action="store_true", help="命中后用 -D 直接生成去密码 ZIP"
    )
    attack_parser.add_argument(
        "--keep-header", action="store_true", help="配合 --decrypt 保留加密头"
    )
    attack_parser.add_argument(
        "-o", "--output", type=Path, help="命中后导出的 ZIP；不提供则只输出 keys"
    )
    attack_parser.add_argument("--json", action="store_true", dest="as_json")

    presets_parser = plaintext_actions.add_parser(
        "presets", aliases=["list-presets"], help="列出 8 种经典明文攻击预设"
    )
    presets_parser.add_argument("--json", action="store_true", dest="as_json")

    preset_parser = plaintext_actions.add_parser(
        "preset", help="使用 8 种经典题型预设自动生成明文参数"
    )
    preset_parser.add_argument(
        "preset",
        choices=tuple(PLAINTEXT_PRESET_ALIASES),
        help="预设：text/png/zip/exe/pcapng/xml/svg/vmdk/custom，也支持 png-header/inner-zip/raw 等别名",
    )
    preset_parser.add_argument("file", type=Path, help="待攻击的加密 ZIP")
    preset_parser.add_argument("--entry", help="ZIP 内要攻击的加密条目；单加密条目可省略")
    preset_parser.add_argument(
        "--inner-name", default="flag.txt", help="zip 预设的内层文件名，默认 flag.txt"
    )
    preset_parser.add_argument(
        "--plain-file", type=Path, help="覆盖预设明文为文件内容；custom 也可用"
    )
    preset_parser.add_argument("--plain-text", help="覆盖预设明文为文本；text/custom 预设可用")
    preset_parser.add_argument("--plain-hex", help="覆盖预设明文为十六进制；text/custom 预设可用")
    preset_parser.add_argument("--preset-file", type=Path, help="JSON 自定义预设文件")
    preset_parser.add_argument("--offset", type=int, help="覆盖预设偏移")
    preset_parser.add_argument("--extra", action="append", help="附加部分明文 OFFSET:HEX，可重复")
    preset_parser.add_argument(
        "--extra-text", action="append", help="附加文本明文 OFFSET:TEXT，可重复"
    )
    preset_parser.add_argument(
        "--extra-hex", action="append", help="附加十六进制明文 OFFSET:HEX，可重复"
    )
    preset_parser.add_argument("--truncate", type=int, help="最多读取多少明文字节")
    preset_parser.add_argument(
        "--ignore-check-byte", action="store_true", help="不自动使用 check byte"
    )
    preset_parser.add_argument("--jobs", type=int, default=0, help="bkcrack 线程数，0=默认")
    preset_parser.add_argument("--bkcrack", type=Path, help="bkcrack 可执行文件路径")
    preset_parser.add_argument(
        "--new-password", default="", help="命中后用 -U 改成的新密码，默认空密码"
    )
    preset_parser.add_argument(
        "--decrypt", action="store_true", help="命中后用 -D 直接生成去密码 ZIP"
    )
    preset_parser.add_argument(
        "--keep-header", action="store_true", help="配合 --decrypt 保留加密头"
    )
    preset_parser.add_argument("--encoding", default="utf-8", help="文本预设编码，默认 utf-8")
    preset_parser.add_argument(
        "-o", "--output", type=Path, help="命中后导出的 ZIP；不提供则只输出 keys"
    )
    preset_parser.add_argument("--json", action="store_true", dest="as_json")

    keys_parser = plaintext_actions.add_parser("keys", help="已知三段密钥后改密码或导出去密码 ZIP")
    keys_parser.add_argument("file", type=Path, help="加密 ZIP")
    keys_parser.add_argument(
        "--keys", nargs=3, required=True, metavar=("X", "Y", "Z"), help="三段 32-bit 十六进制密钥"
    )
    keys_parser.add_argument("--new-password", default="", help="-U 导出的新密码，默认空密码")
    keys_parser.add_argument("--decrypt", action="store_true", help="用 -D 直接生成去密码 ZIP")
    keys_parser.add_argument("--bkcrack", type=Path, help="bkcrack 可执行文件路径")
    keys_parser.add_argument("-o", "--output", type=Path, required=True, help="导出 ZIP")
    keys_parser.add_argument("--json", action="store_true", dest="as_json")

    recover_parser = plaintext_actions.add_parser(
        "recover-password", help="已知三段密钥后反向枚举原密码"
    )
    recover_parser.add_argument("file", type=Path, help="加密 ZIP")
    recover_parser.add_argument(
        "--keys", nargs=3, required=True, metavar=("X", "Y", "Z"), help="三段 32-bit 十六进制密钥"
    )
    recover_parser.add_argument("--charset", default="?l?u?d", help="bkcrack 字符集，默认 ?l?u?d")
    recover_parser.add_argument("--length", help="长度范围，如 1..6、..8 或 6")
    recover_parser.add_argument("--mask", help="掩码模式，如 ?u?l?l?l?d?d")
    recover_parser.add_argument("--jobs", type=int, default=0, help="bkcrack 线程数，0=默认")
    recover_parser.add_argument("--bkcrack", type=Path, help="bkcrack 可执行文件路径")
    recover_parser.add_argument("--json", action="store_true", dest="as_json")

    audio_parser = commands.add_parser("audio", help="音频分析与解码，和 image 同级")
    audio_commands = audio_parser.add_subparsers(dest="audio_command", required=True)
    lyra_parser = audio_commands.add_parser("lyra", help="Google Lyra 低码率语音压缩编码/解码")
    lyra_actions = lyra_parser.add_subparsers(dest="lyra_action", required=True)
    lyra_inspect = lyra_actions.add_parser("inspect", aliases=["info"], help="分析 .lyra 包长度")
    lyra_inspect.add_argument("file", type=Path, help="输入 .lyra 文件")
    lyra_inspect.add_argument(
        "--bitrate",
        type=int,
        choices=LYRA_SUPPORTED_BITRATES,
        help="已知码率；不填时列出所有 3200/6000/9200 bps 候选",
    )
    lyra_inspect.add_argument("--json", action="store_true", dest="as_json")

    lyra_decode = lyra_actions.add_parser(
        "decode", aliases=["decompress"], help="调用 Google Lyra decoder_main 解码 .lyra 到 WAV"
    )
    lyra_decode.add_argument("file", type=Path, help="输入 .lyra 文件")
    lyra_decode.add_argument("-o", "--output", type=Path, required=True, help="输出 WAV 文件")
    lyra_decode.add_argument(
        "--bitrate",
        type=int,
        choices=LYRA_SUPPORTED_BITRATES,
        default=3200,
        help="Lyra 码率，默认 3200",
    )
    lyra_decode.add_argument(
        "--sample-rate",
        type=int,
        choices=LYRA_SUPPORTED_SAMPLE_RATES,
        default=16000,
        help="输出采样率，默认 16000",
    )
    lyra_decode.add_argument("--decoder", type=Path, help="Google Lyra decoder_main 路径")
    lyra_decode.add_argument("--model-path", type=Path, help="Google Lyra model_coeffs 路径")
    lyra_decode.add_argument(
        "--randomize-num-samples",
        action="store_true",
        help="传给 decoder_main 的随机请求样本数调试开关",
    )
    lyra_decode.add_argument("--packet-loss-rate", type=float, default=0.0, help="模拟丢包率")
    lyra_decode.add_argument(
        "--average-burst-length", type=float, default=1.0, help="Gilbert 丢包模型平均突发长度"
    )
    lyra_decode.add_argument(
        "--fixed-packet-loss-pattern",
        default="",
        help="固定丢包模式，格式沿用 decoder_main: start,duration,...",
    )
    lyra_decode.add_argument("--json", action="store_true", dest="as_json")

    lyra_encode = lyra_actions.add_parser(
        "encode", aliases=["compress"], help="调用 Google Lyra encoder_main 编码 WAV 到 .lyra"
    )
    lyra_encode.add_argument("file", type=Path, help="输入 16-bit mono WAV 文件")
    lyra_encode.add_argument("-o", "--output", type=Path, required=True, help="输出 .lyra 文件")
    lyra_encode.add_argument(
        "--bitrate",
        type=int,
        choices=LYRA_SUPPORTED_BITRATES,
        default=3200,
        help="Lyra 码率，默认 3200",
    )
    lyra_encode.add_argument("--encoder", type=Path, help="Google Lyra encoder_main 路径")
    lyra_encode.add_argument("--model-path", type=Path, help="Google Lyra model_coeffs 路径")
    lyra_encode.add_argument(
        "--enable-preprocessing", action="store_true", help="启用 Lyra no-op/预处理开关"
    )
    lyra_encode.add_argument("--enable-dtx", action="store_true", help="启用 DTX 静音包抑制")
    lyra_encode.add_argument("--json", action="store_true", dest="as_json")

    mp3stego_parser = audio_commands.add_parser(
        "mp3stego", aliases=["mp3-stego"], help="MP3Stego part2_3_length 奇偶位隐写"
    )
    mp3stego_actions = mp3stego_parser.add_subparsers(dest="mp3stego_action", required=True)
    mp3stego_inspect = mp3stego_actions.add_parser(
        "inspect", aliases=["info"], help="查看 MP3Stego 可提取位和嵌入长度"
    )
    mp3stego_inspect.add_argument("file", type=Path, help="输入 MP3 文件")
    mp3stego_inspect.add_argument("-p", "--password", default="", help="密码，默认空密码")
    mp3stego_inspect.add_argument(
        "--length-size",
        choices=("4", "8", "auto"),
        default="4",
        help="长度头字节数，32-bit 构建默认 4；auto 兼容 64-bit",
    )
    mp3stego_inspect.add_argument(
        "--max-payload-bytes",
        type=int,
        default=MP3STEGO_DEFAULT_MAX_PAYLOAD_BYTES,
        help="最大嵌入密文字节数",
    )
    mp3stego_inspect.add_argument("--json", action="store_true", dest="as_json")

    mp3stego_extract = mp3stego_actions.add_parser(
        "extract", aliases=["decode"], help="原生提取 MP3Stego 隐藏文件"
    )
    mp3stego_extract.add_argument("file", type=Path, help="输入 MP3 文件")
    mp3stego_extract.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    mp3stego_extract.add_argument("-p", "--password", default="", help="密码，默认空密码")
    mp3stego_extract.add_argument(
        "--length-size",
        choices=("4", "8", "auto"),
        default="4",
        help="长度头字节数，32-bit 构建默认 4；auto 兼容 64-bit",
    )
    mp3stego_extract.add_argument("--raw", action="store_true", help="只输出加密压缩后的原始载荷")
    mp3stego_extract.add_argument(
        "--max-payload-bytes",
        type=int,
        default=MP3STEGO_DEFAULT_MAX_PAYLOAD_BYTES,
        help="最大嵌入密文字节数",
    )
    mp3stego_extract.add_argument("--json", action="store_true", dest="as_json")

    mp3stego_brute = mp3stego_actions.add_parser(
        "brute", help="用字典尝试 MP3Stego 密码并提取隐藏文件"
    )
    mp3stego_brute.add_argument("file", type=Path, help="输入 MP3 文件")
    mp3stego_brute.add_argument("--wordlist", type=Path, required=True, help="密码字典，一行一个")
    mp3stego_brute.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    mp3stego_brute.add_argument("--contains", help="成功判定：解密解压后的载荷包含该文本")
    mp3stego_brute.add_argument("--prefix", help="成功判定：解密解压后的载荷以该文本开头")
    mp3stego_brute.add_argument("--no-empty", action="store_true", help="不先尝试空密码")
    mp3stego_brute.add_argument("--encoding", default="utf-8", help="字典编码，默认 utf-8")
    mp3stego_brute.add_argument(
        "--length-size",
        choices=("4", "8", "auto"),
        default="4",
        help="长度头字节数，32-bit 构建默认 4；auto 兼容 64-bit",
    )
    mp3stego_brute.add_argument(
        "--max-payload-bytes",
        type=int,
        default=MP3STEGO_DEFAULT_MAX_PAYLOAD_BYTES,
        help="最大嵌入密文字节数",
    )
    mp3stego_brute.add_argument("--json", action="store_true", dest="as_json")

    mp3stego_encode = mp3stego_actions.add_parser(
        "encode", aliases=["hide"], help="调用 MP3Stego Encode/Encode.exe 从 WAV 生成 MP3"
    )
    mp3stego_encode.add_argument("file", type=Path, help="输入 WAV 文件")
    mp3stego_encode.add_argument("--payload", type=Path, required=True, help="要隐藏的文件")
    mp3stego_encode.add_argument("-o", "--output", type=Path, required=True, help="输出 MP3 文件")
    mp3stego_encode.add_argument("-p", "--password", default="", help="密码，默认空密码")
    mp3stego_encode.add_argument("--encoder", type=Path, help="MP3Stego Encode/Encode.exe 路径")
    mp3stego_encode.add_argument("--json", action="store_true", dest="as_json")

    sstv_parser = audio_commands.add_parser(
        "sstv",
        aliases=["slow-scan-tv", "slow-scan"],
        help="SSTV 慢扫描电视 WAV 解码",
    )
    sstv_actions = sstv_parser.add_subparsers(dest="sstv_action", required=True)
    sstv_inspect = sstv_actions.add_parser(
        "inspect", aliases=["scan", "info"], help="识别 SSTV 校准头和 VIS 模式"
    )
    sstv_inspect.add_argument("file", type=Path, help="输入 WAV 音频")
    sstv_inspect.add_argument(
        "--mode",
        choices=SSTV_MODE_CHOICES,
        default="auto",
        help="强制模式；默认从 VIS 自动识别",
    )
    sstv_inspect.add_argument("--skip", type=float, default=0.0, help="跳过开头秒数")
    sstv_inspect.add_argument("--reverse-audio", action="store_true", help="先反转音频再解码")
    sstv_inspect.add_argument("--json", action="store_true", dest="as_json")

    sstv_decode = sstv_actions.add_parser(
        "decode", aliases=["extract"], help="把 SSTV WAV 信号解码为 PNG 图片"
    )
    sstv_decode.add_argument("file", type=Path, help="输入 WAV 音频")
    sstv_decode.add_argument("-o", "--output", type=Path, required=True, help="输出 PNG 图片")
    sstv_decode.add_argument(
        "--mode",
        choices=SSTV_MODE_CHOICES,
        default="auto",
        help="强制模式；默认从 VIS 自动识别",
    )
    sstv_decode.add_argument("--skip", type=float, default=0.0, help="跳过开头秒数")
    sstv_decode.add_argument("--reverse-audio", action="store_true", help="先反转音频再解码")
    sstv_decode.add_argument("--invert-image", action="store_true", help="输出前反相 RGB 图像")
    sstv_decode.add_argument("--max-lines", type=int, help="只解前 N 行，便于快速预览")
    sstv_decode.add_argument("--json", action="store_true", dest="as_json")

    ham_parser = audio_commands.add_parser(
        "ham",
        aliases=["radio", "aprs", "afsk"],
        help="业余无线电 AFSK1200/AX.25/APRS WAV 数据解码",
    )
    ham_actions = ham_parser.add_subparsers(dest="ham_action", required=True)
    ham_inspect = ham_actions.add_parser(
        "inspect", aliases=["scan", "info"], help="检查 WAV 并尝试原生 AFSK1200 分帧"
    )
    ham_inspect.add_argument("file", type=Path, help="输入 WAV 音频")
    ham_inspect.add_argument("--mode", choices=("afsk1200",), default="afsk1200")
    ham_inspect.add_argument("--reverse-audio", action="store_true", help="先反转音频再解码")
    ham_inspect.add_argument("--invert-audio", action="store_true", help="先反相音频再解码")
    ham_inspect.add_argument("--max-seconds", type=float, help="只分析开头 N 秒")
    ham_inspect.add_argument("--json", action="store_true", dest="as_json")

    ham_decode = ham_actions.add_parser(
        "decode", aliases=["extract"], help="解码 AFSK1200 AX.25/APRS 文本"
    )
    ham_decode.add_argument("file", type=Path, help="输入 WAV 音频")
    ham_decode.add_argument("-o", "--output", type=Path, required=True, help="输出文本文件")
    ham_decode.add_argument("--mode", choices=("afsk1200",), default="afsk1200")
    ham_decode.add_argument(
        "--backend",
        choices=("native", "multimon", "auto"),
        default="native",
        help="默认 native；multimon 调用 multimon-ng",
    )
    ham_decode.add_argument("--reverse-audio", action="store_true", help="先反转音频再解码")
    ham_decode.add_argument("--invert-audio", action="store_true", help="先反相音频再解码")
    ham_decode.add_argument("--max-seconds", type=float, help="只处理开头 N 秒")
    ham_decode.add_argument(
        "--raw-output", type=Path, help="同时导出 multimon-ng 可用的 signed 16-bit raw"
    )
    ham_decode.add_argument("--multimon", type=Path, help="multimon-ng 可执行文件路径")
    ham_decode.add_argument("--json", action="store_true", dest="as_json")

    ham_encode = ham_actions.add_parser(
        "encode", aliases=["synth"], help="生成 AX.25 UI/APRS AFSK1200 WAV 测试样本"
    )
    ham_encode.add_argument("-o", "--output", type=Path, required=True, help="输出 WAV 文件")
    ham_encode.add_argument("--source", default="N0CALL", help="AX.25 源呼号，默认 N0CALL")
    ham_encode.add_argument("--destination", default="APRS", help="AX.25 目的呼号，默认 APRS")
    ham_encode.add_argument("--path", action="append", default=[], help="digipeater 路径，可重复")
    ham_encode.add_argument("--text", required=True, help="APRS info 文本")
    ham_encode.add_argument("--sample-rate", type=int, default=9600, help="输出采样率，默认 9600")
    ham_encode.add_argument("--json", action="store_true", dest="as_json")

    midi_qr_parser = audio_commands.add_parser(
        "midi-qr",
        aliases=["midiqr", "midi-qrcode", "midi-to-qr"],
        help="把 MIDI 文件或 timestamp+hex MIDI 事件日志转成二维码矩阵图片",
    )
    midi_qr_parser.add_argument("file", type=Path, help="输入 .mid 或每行 timestamp<TAB>hex 的日志")
    midi_qr_parser.add_argument("-o", "--output", type=Path, required=True, help="输出 PNG 图片")
    midi_qr_parser.add_argument(
        "--source",
        choices=("auto", "midi", "log"),
        default="auto",
        help="输入类型，默认 auto",
    )
    midi_qr_parser.add_argument(
        "--row-gap",
        type=float,
        default=0.01,
        help="相邻 NOTE ON 时间差大于该秒数时换行，默认 0.01",
    )
    midi_qr_parser.add_argument("--cell-size", type=int, default=20, help="每个矩阵格子的像素边长")
    midi_qr_parser.add_argument("--invert", action="store_true", help="黑白反相输出")
    midi_qr_parser.add_argument(
        "--midi-output", type=Path, help="同时把解析出的 NOTE 事件重建为 MIDI"
    )
    midi_qr_parser.add_argument("--ppq", type=int, default=480, help="重建 MIDI 的 ticks per beat")
    midi_qr_parser.add_argument("--bpm", type=float, default=120.0, help="重建 MIDI 的 BPM")
    midi_qr_parser.add_argument(
        "--min-duration-ms",
        type=float,
        default=120.0,
        help="重建 MIDI 时保证 note off 至少延后该毫秒数",
    )
    midi_qr_parser.add_argument("--json", action="store_true", dest="as_json")

    wavdata_parser = audio_commands.add_parser(
        "wavdata",
        aliases=["wav-data", "wavraw"],
        help="脚本化提取/分析 WAV 原始采样、LSB、声道差、频率和图像数据",
    )
    wavdata_actions = wavdata_parser.add_subparsers(dest="wavdata_action", required=True)

    wavdata_info = wavdata_actions.add_parser("info", aliases=["inspect"], help="查看 WAV 基础参数")
    wavdata_info.add_argument("file", type=Path, help="输入 WAV 文件")
    wavdata_info.add_argument("--json", action="store_true", dest="as_json")

    wavdata_lsb = wavdata_actions.add_parser("lsb", help="提取 WAV 采样低位 bitstream")
    wavdata_lsb.add_argument("file", type=Path, help="输入 WAV 文件")
    wavdata_lsb.add_argument("-o", "--output", type=Path, required=True, help="输出文件")
    wavdata_lsb.add_argument("--bit", type=int, default=0, help="提取单个 bit 位，默认 0")
    wavdata_lsb.add_argument("--bits", help="提取多个 bit 位，如 0,1,2；覆盖 --bit")
    wavdata_lsb.add_argument("--channel", default="all", help="all/left/right/0/1，默认 all")
    wavdata_lsb.add_argument("--sample-step", type=int, default=1, help="采样步长，默认 1")
    wavdata_lsb.add_argument("--order", choices=("msb", "lsb"), default="msb", help="组字节位序")
    wavdata_lsb.add_argument(
        "--format", choices=("bytes", "bits", "text"), default="bytes", dest="output_format"
    )
    wavdata_lsb.add_argument("--limit-bits", type=int, help="最多提取多少 bit")
    wavdata_lsb.add_argument("--json", action="store_true", dest="as_json")

    wavdata_diff = wavdata_actions.add_parser(
        "channel-diff", aliases=["diff"], help="左右声道差值映射 bit"
    )
    wavdata_diff.add_argument("file", type=Path, help="输入双声道 WAV 文件")
    wavdata_diff.add_argument("-o", "--output", type=Path, required=True, help="输出文件")
    wavdata_diff.add_argument(
        "--map",
        action="append",
        required=True,
        dest="maps",
        help="差值到 bit 的映射，如 1:0，可重复",
    )
    wavdata_diff.add_argument("--left-channel", type=int, default=0)
    wavdata_diff.add_argument("--right-channel", type=int, default=1)
    wavdata_diff.add_argument("--order", choices=("msb", "lsb"), default="msb")
    wavdata_diff.add_argument(
        "--format", choices=("bytes", "bits", "text"), default="bits", dest="output_format"
    )
    wavdata_diff.add_argument("--json", action="store_true", dest="as_json")

    wavdata_fft = wavdata_actions.add_parser(
        "fft-map", aliases=["freq-index"], help="按固定频率表分块 FFT 映射字符"
    )
    wavdata_fft.add_argument("file", type=Path, help="输入 WAV 文件")
    wavdata_fft.add_argument("-o", "--output", type=Path, required=True, help="输出文本文件")
    wavdata_fft.add_argument("--freqs", required=True, help="频率列表，如 800,900,1000")
    wavdata_fft.add_argument("--alphabet", required=True, help="索引字符表")
    wavdata_fft.add_argument("--chunk-ms", type=float, default=100.0)
    wavdata_fft.add_argument("--group-size", type=int, default=2)
    wavdata_fft.add_argument("--threshold", type=float, help="最小频谱幅值；默认不限制")
    wavdata_fft.add_argument("--channel", default="left")
    wavdata_fft.add_argument("--json", action="store_true", dest="as_json")

    wavdata_compare = wavdata_actions.add_parser(
        "compare", aliases=["float-diff"], help="两个 WAV 采样差值映射 bit"
    )
    wavdata_compare.add_argument("first", type=Path, help="第一个/secret WAV")
    wavdata_compare.add_argument("second", type=Path, help="第二个/cover WAV")
    wavdata_compare.add_argument("-o", "--output", type=Path, required=True, help="输出文件")
    wavdata_compare.add_argument("--scale", type=float, default=1.0)
    wavdata_compare.add_argument(
        "--map",
        action="append",
        required=True,
        dest="maps",
        help="差值到 bit 的映射，如 19:01，可重复",
    )
    wavdata_compare.add_argument("--channel", default="left")
    wavdata_compare.add_argument("--samples", type=int, help="只处理前 N 个采样")
    wavdata_compare.add_argument("--order", choices=("msb", "lsb"), default="msb")
    wavdata_compare.add_argument(
        "--format", choices=("bytes", "bits", "text"), default="bytes", dest="output_format"
    )
    wavdata_compare.add_argument("--json", action="store_true", dest="as_json")

    wavdata_image = wavdata_actions.add_parser(
        "to-image", aliases=["image"], help="把 WAV 采样值映射为图片"
    )
    wavdata_image.add_argument("file", type=Path, help="输入 WAV 文件")
    wavdata_image.add_argument("-o", "--output", type=Path, required=True, help="输出 PNG/BMP")
    wavdata_image.add_argument("--width", type=int, required=True)
    wavdata_image.add_argument("--height", type=int, required=True)
    wavdata_image.add_argument("--stride", type=int, default=1)
    wavdata_image.add_argument("--offset", type=int, default=0)
    wavdata_image.add_argument(
        "--mode", choices=("rgba16stereo", "rgb16mono", "gray8"), default="rgba16stereo"
    )
    wavdata_image.add_argument("--json", action="store_true", dest="as_json")

    wavdata_chars = wavdata_actions.add_parser(
        "freq-chars", aliases=["tone-chars"], help="主频映射字符"
    )
    wavdata_chars.add_argument("file", type=Path, help="输入 WAV 文件")
    wavdata_chars.add_argument("-o", "--output", type=Path, required=True, help="输出文本文件")
    wavdata_chars.add_argument("--chunk-ms", type=float, default=100.0)
    wavdata_chars.add_argument("--tolerance", type=float, default=30.0)
    wavdata_chars.add_argument("--no-dedupe", action="store_true", help="长音重复块也记录字符")
    wavdata_chars.add_argument("--channel", default="left")
    wavdata_chars.add_argument(
        "--map",
        action="append",
        dest="maps",
        help="字符到频率映射，如 a:440，可重复；默认使用内置表",
    )
    wavdata_chars.add_argument("--json", action="store_true", dest="as_json")

    velato_parser = audio_commands.add_parser(
        "velato",
        aliases=["midi-velato"],
        help="Velato MIDI 编程语言：按音程解析 print 文本或生成样例 MIDI",
    )
    velato_actions = velato_parser.add_subparsers(dest="velato_action", required=True)
    velato_inspect = velato_actions.add_parser(
        "inspect", aliases=["info"], help="解析 MIDI 音符、音程和 Velato 命令"
    )
    velato_inspect.add_argument("file", type=Path, help="输入 .mid/.midi 文件")
    velato_inspect.add_argument("--json", action="store_true", dest="as_json")

    velato_decode = velato_actions.add_parser(
        "decode", aliases=["extract"], help="提取 Velato print 命令输出文本"
    )
    velato_decode.add_argument("file", type=Path, help="输入 .mid/.midi 文件")
    velato_decode.add_argument("-o", "--output", type=Path, required=True, help="输出文本文件")
    velato_decode.add_argument("--json", action="store_true", dest="as_json")

    velato_encode = velato_actions.add_parser("encode", help="生成打印指定文本的 Velato MIDI 样例")
    velato_encode.add_argument("-o", "--output", type=Path, required=True, help="输出 .mid 文件")
    velato_encode.add_argument("--text", required=True, help="要由 Velato 程序打印的文本")
    velato_encode.add_argument("--root-note", type=int, default=60, help="MIDI 根音，默认 60(C4)")
    velato_encode.add_argument("--velocity", type=int, default=80, help="note-on velocity，默认 80")
    velato_encode.add_argument(
        "--duration", type=int, default=120, help="每个音符 tick 长度，默认 120"
    )
    velato_encode.add_argument(
        "--no-separator", action="store_true", help="字符之间不插入根音占位符"
    )
    velato_encode.add_argument("--json", action="store_true", dest="as_json")

    mp3_field_parser = audio_commands.add_parser(
        "mp3-field",
        aliases=["mp3-frame-field", "mp3-header"],
        help="提取 MP3 帧头 padding/private/copyright 等字段隐写",
    )
    mp3_field_actions = mp3_field_parser.add_subparsers(dest="mp3_field_action", required=True)
    mp3_extract = mp3_field_actions.add_parser(
        "extract", aliases=["decode"], help="从一个 MP3 帧头字段提取 bit 流"
    )
    mp3_extract.add_argument("file", type=Path, help="输入 MP3 文件")
    mp3_extract.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    mp3_extract.add_argument(
        "--field",
        choices=MP3_FIELD_CHOICES,
        default="copyright",
        help="提取字段，默认 copyright",
    )
    mp3_extract.add_argument("--start", type=_parse_int_auto, help="起始帧偏移，如 0x0F05A4")
    mp3_extract.add_argument("--end", type=_parse_int_auto, help="结束偏移，如 0xC125A3")
    mp3_extract.add_argument(
        "--order", choices=("msb", "lsb"), default="msb", help="8 个字段 bit 组字节的位序"
    )
    mp3_extract.add_argument("--limit-bits", type=int, help="最多提取多少个帧字段 bit")
    mp3_extract.add_argument(
        "--format",
        choices=("bytes", "bits"),
        default="bytes",
        dest="output_format",
        help="输出组字节结果或 ASCII 0/1 bit 串",
    )
    mp3_extract.add_argument(
        "--base-frame-size",
        type=int,
        help="兼容文章脚本：每帧步长为该值 + padding bit，不解析码率",
    )
    mp3_extract.add_argument("--json", action="store_true", dest="as_json")

    mp3_scan = mp3_field_actions.add_parser("scan", help="扫描常见帧头字段并写出可疑候选")
    mp3_scan.add_argument("file", type=Path, help="输入 MP3 文件")
    mp3_scan.add_argument("-o", "--output", type=Path, required=True, help="输出候选目录")
    mp3_scan.add_argument(
        "--fields",
        default="copyright,private,original",
        help="字段列表，默认 copyright,private,original",
    )
    mp3_scan.add_argument("--start", type=_parse_int_auto, help="起始帧偏移")
    mp3_scan.add_argument("--end", type=_parse_int_auto, help="结束偏移")
    mp3_scan.add_argument("--orders", default="msb,lsb", help="位序列表：msb,lsb / msb / lsb")
    mp3_scan.add_argument("--limit-bits", type=int, help="每个字段最多提取多少个 bit")
    mp3_scan.add_argument(
        "--base-frame-size", type=int, help="每帧步长为该值 + padding bit，不解析码率"
    )
    mp3_scan.add_argument("--write-all", action="store_true", help="写出所有字段/位序候选")
    mp3_scan.add_argument("--json", action="store_true", dest="as_json")

    split_parser = image_commands.add_parser("split", help="分离图片帧或网格")
    split_modes = split_parser.add_subparsers(dest="split_mode", required=True)
    frames_parser = split_modes.add_parser("frames", help="分离 GIF、APNG 或 WebP 帧")
    frames_parser.add_argument("file", type=Path, help="待分帧图片")
    frames_parser.add_argument("-o", "--output", type=Path, required=True, help="输出目录")
    frames_parser.add_argument("--prefix", default="frame", help="帧文件名前缀")
    frames_parser.add_argument("--json", action="store_true", dest="as_json")
    grid_parser = split_modes.add_parser("grid", help="按规则网格切割图片")
    grid_parser.add_argument("file", type=Path, help="待切割图片")
    grid_parser.add_argument("-o", "--output", type=Path, required=True, help="输出目录")
    grid_parser.add_argument("--columns", type=int, required=True, help="列数")
    grid_parser.add_argument("--rows", type=int, required=True, help="行数")
    grid_parser.add_argument("--prefix", default="tile", help="切片文件名前缀")
    grid_parser.add_argument("--json", action="store_true", dest="as_json")

    join_parser = image_commands.add_parser("join", help="按自然文件名顺序拼接图片")
    join_parser.add_argument("files", nargs="+", type=Path, help="输入图片")
    join_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
    join_parser.add_argument("--columns", type=int, default=0, help="每行列数；默认全部横排")
    join_parser.add_argument("--gap", type=int, default=0, help="图片间距")
    join_parser.add_argument("--background", default="transparent", help="背景颜色")
    join_parser.add_argument("--json", action="store_true", dest="as_json")

    flip_parser = image_commands.add_parser("flip", help="镜像翻转图片")
    flip_parser.add_argument("file", type=Path, help="输入图片")
    flip_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
    flip_parser.add_argument(
        "--axis", choices=("horizontal", "vertical"), required=True, help="翻转方向"
    )
    flip_parser.add_argument("--json", action="store_true", dest="as_json")

    sample_parser = image_commands.add_parser("sample", help="提取等距像素点并用近邻法放大")
    sample_parser.add_argument("file", type=Path, help="输入图片")
    sample_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
    sample_parser.add_argument("--start", default="0x0", help="起始坐标 XxY，默认 0x0")
    sample_parser.add_argument("--end", help="终止坐标 XxY（包含），默认图片右下角")
    sample_parser.add_argument("--step", required=True, help="采样间距 XxY，例如 12x12")
    sample_parser.add_argument("--scale", type=int, default=1, help="近邻放大倍数，默认 1")
    sample_parser.add_argument("--json", action="store_true", dest="as_json")

    spacefill_parser = image_commands.add_parser(
        "spacefill", help="Peano/Hilbert 填满空间曲线图像置乱与恢复"
    )
    spacefill_actions = spacefill_parser.add_subparsers(dest="spacefill_action", required=True)
    for action, help_text in (
        ("encode", "按曲线路径读取像素并按行写出置乱图"),
        ("decode", "把按行像素放回曲线路径恢复图像"),
    ):
        curve_parser = spacefill_actions.add_parser(action, help=help_text)
        curve_parser.add_argument("file", type=Path, help="输入图片")
        curve_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
        curve_parser.add_argument(
            "--curve", choices=("peano", "hilbert"), required=True, help="曲线类型"
        )
        curve_parser.add_argument("--order", type=int, help="曲线阶数；默认由正方形边长推断")
        curve_parser.add_argument(
            "--no-flip-y", action="store_true", help="不执行文章脚本中的 height - 1 - y 翻转"
        )
        curve_parser.add_argument("--reverse", action="store_true", help="反向使用曲线路径")
        curve_parser.add_argument("--json", action="store_true", dest="as_json")

    backpaper_parser = image_commands.add_parser(
        "backpaper", aliases=["paperbak"], help="PaperBack 点阵纸备份编码与恢复"
    )
    backpaper_actions = backpaper_parser.add_subparsers(dest="backpaper_action", required=True)
    backpaper_encode = backpaper_actions.add_parser("encode", help="把文件编码为点阵页面")
    backpaper_encode.add_argument("file", type=Path, help="输入文件")
    backpaper_encode.add_argument("-o", "--output", type=Path, required=True, help="输出 PNG/BMP")
    backpaper_encode.add_argument("--no-compress", action="store_true", help="关闭 bzip2 压缩")
    backpaper_encode.add_argument("--password", help="启用兼容 PaperBack 1.10 的 AES-192 加密")
    backpaper_encode.add_argument("--redundancy", type=int, default=5, help="恢复组大小 2..10")
    backpaper_encode.add_argument("--columns", type=int, default=8, help="页面列数，默认 8")
    backpaper_encode.add_argument("--rows", type=int, default=12, help="页面最大行数，默认 12")
    backpaper_encode.add_argument("--dot-step", type=int, default=3, help="点间距像素，默认 3")
    backpaper_encode.add_argument("--dot-percent", type=int, default=70, help="点大小百分比")
    backpaper_encode.add_argument("--border", type=int, default=25, help="页面留白像素")
    backpaper_encode.add_argument("--json", action="store_true", dest="as_json")

    backpaper_decode = backpaper_actions.add_parser("decode", help="从点阵页面恢复文件")
    backpaper_decode.add_argument("files", nargs="+", type=Path, help="按任意顺序提供页面图片")
    backpaper_decode.add_argument("-o", "--output", type=Path, required=True, help="恢复文件路径")
    backpaper_decode.add_argument("--password", help="加密页面的密码")
    backpaper_decode.add_argument("--threshold", type=int, help="手动黑白阈值 0..255")
    backpaper_decode.add_argument("--json", action="store_true", dest="as_json")

    npiet_parser = image_commands.add_parser(
        "npiet", aliases=["piet"], help="执行 Piet 图片程序并输出运行轨迹"
    )
    npiet_parser.add_argument("file", type=Path, help="Piet PNG/GIF/PPM 程序图片")
    npiet_parser.add_argument("--input", default="", help="提供给 in(number)/in(char) 的输入")
    npiet_parser.add_argument("--input-file", type=Path, help="从文件读取程序输入")
    npiet_parser.add_argument("--codel-size", type=int, help="codel 像素尺寸；默认自动推断")
    npiet_parser.add_argument("--max-steps", type=int, default=100_000, help="最大执行步数")
    npiet_parser.add_argument(
        "--unknown",
        choices=("white", "black", "error", "nearest"),
        default="white",
        help="非标准颜色处理方式，默认 white",
    )
    npiet_parser.add_argument("--trace", action="store_true", help="在 JSON 中附带逐步轨迹")
    npiet_parser.add_argument("--trace-limit", type=int, default=1_000, help="轨迹最大记录条数")
    npiet_parser.add_argument("--trace-image", type=Path, help="输出类似 npiet -tpic 的路径图")
    npiet_parser.add_argument("--json", action="store_true", dest="as_json")

    arnold_parser = image_commands.add_parser("arnold", help="Arnold 猫脸变换编码、恢复和参数爆破")
    arnold_actions = arnold_parser.add_subparsers(dest="arnold_action", required=True)
    for action, help_text in (
        ("encode", "执行 Arnold 正向置乱"),
        ("decode", "执行 Arnold 逆向恢复"),
    ):
        action_parser = arnold_actions.add_parser(action, help=help_text)
        action_parser.add_argument("file", type=Path, help="输入图片")
        action_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
        action_parser.add_argument(
            "--rounds", type=int, required=True, help="变换轮数 shuffle_times"
        )
        action_parser.add_argument("--a", type=int, required=True, help="Arnold 参数 a")
        action_parser.add_argument("--b", type=int, required=True, help="Arnold 参数 b")
        action_parser.add_argument("--json", action="store_true", dest="as_json")
    brute_parser = arnold_actions.add_parser("brute", help="按范围批量输出候选恢复图片")
    brute_parser.add_argument("file", type=Path, help="输入图片")
    brute_parser.add_argument("-o", "--output", type=Path, required=True, help="输出目录")
    brute_parser.add_argument("--rounds", required=True, help="轮数范围 START:STOP，STOP 不包含")
    brute_parser.add_argument("--a", required=True, help="a 范围 START:STOP，STOP 不包含")
    brute_parser.add_argument("--b", required=True, help="b 范围 START:STOP，STOP 不包含")
    brute_parser.add_argument(
        "--mode", choices=("decode", "encode"), default="decode", help="爆破方向，默认 decode"
    )
    brute_parser.add_argument("--json", action="store_true", dest="as_json")

    combine_parser = image_commands.add_parser(
        "combine", help="使用 StegSolve Image Combiner 算法组合两张图片"
    )
    combine_parser.add_argument("first", type=Path, help="第一张图片")
    combine_parser.add_argument("second", type=Path, help="第二张图片")
    combine_parser.add_argument("-o", "--output", type=Path, required=True, help="输出文件或目录")
    combine_parser.add_argument(
        "--operation",
        choices=(*COMBINE_OPERATIONS, "all"),
        default="xor",
        help="组合操作，默认 xor；all 输出全部 13 种结果",
    )
    combine_parser.add_argument("--json", action="store_true", dest="as_json")

    stereogram_parser = image_commands.add_parser(
        "stereogram", help="使用 StegSolve 偏移异或算法还原立体图"
    )
    stereogram_parser.add_argument("file", type=Path, help="立体图输入文件")
    stereogram_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出图片或目录"
    )
    stereogram_parser.add_argument("--offset", type=int, help="已知水平偏移；提供后只输出一张图片")
    stereogram_parser.add_argument("--start", type=int, default=1, help="批量偏移起点，默认 1")
    stereogram_parser.add_argument("--stop", type=int, help="批量偏移终点（不包含），默认图片宽度")
    stereogram_parser.add_argument("--invert", action="store_true", help="反相输出以增强暗色图案")
    stereogram_parser.add_argument("--manifest", type=Path, help="批量输出清单路径")
    stereogram_parser.add_argument("--json", action="store_true", dest="as_json")

    mosaic_parser = image_commands.add_parser("mosaic", help="图片马赛克生成与 Depix 风格恢复")
    mosaic_actions = mosaic_parser.add_subparsers(dest="mosaic_action", required=True)
    pixelate_parser = mosaic_actions.add_parser("pixelate", help="按块平均颜色生成马赛克样本")
    pixelate_parser.add_argument("file", type=Path, help="输入图片")
    pixelate_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
    pixelate_parser.add_argument("--block-width", type=int, required=True, help="块宽")
    pixelate_parser.add_argument("--block-height", type=int, help="块高，默认等于块宽")
    pixelate_parser.add_argument(
        "--average",
        choices=("gammacorrected", "linear"),
        default="gammacorrected",
        help="平均颜色算法，默认兼容 Depix gammacorrected",
    )
    pixelate_parser.add_argument("--json", action="store_true", dest="as_json")

    depix_parser = mosaic_actions.add_parser("depix", help="用搜索图匹配平均颜色来恢复马赛克块")
    depix_parser.add_argument("file", type=Path, help="只包含马赛克区域或待恢复区域的图片")
    depix_parser.add_argument("--search", type=Path, required=True, help="同字体/同环境的搜索图")
    depix_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
    depix_parser.add_argument("--block-width", type=int, help="已知块宽；不提供则自动扫描同色矩形")
    depix_parser.add_argument("--block-height", type=int, help="已知块高，默认等于块宽")
    depix_parser.add_argument("--tolerance", type=int, default=0, help="RGB 通道匹配容差，默认 0")
    depix_parser.add_argument(
        "--average",
        choices=("gammacorrected", "linear"),
        default="gammacorrected",
        help="平均颜色算法，默认兼容 Depix gammacorrected",
    )
    depix_parser.add_argument("--background", help="额外忽略的背景色 R,G,B；默认忽略纯黑和纯白")
    depix_parser.add_argument("--json", action="store_true", dest="as_json")

    acropalypse_parser = image_commands.add_parser(
        "acropalypse", help="恢复 CVE-2023-28303 / aCropalypse PNG 尾部残留"
    )
    acropalypse_actions = acropalypse_parser.add_subparsers(
        dest="acropalypse_action", required=True
    )
    acropalypse_restore_parser = acropalypse_actions.add_parser(
        "restore", help="从残留 IDAT/DEFLATE 数据恢复裁剪前截图"
    )
    acropalypse_restore_parser.add_argument("file", type=Path, help="存在尾部残留的 PNG")
    acropalypse_restore_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出 PNG"
    )
    acropalypse_restore_parser.add_argument(
        "--width", type=int, default=1920, help="原始截图宽度，默认 1920"
    )
    acropalypse_restore_parser.add_argument(
        "--height", type=int, default=1080, help="原始截图高度，默认 1080"
    )
    acropalypse_restore_parser.add_argument(
        "--mode", choices=("rgb", "rgba"), default="rgba", help="原始颜色模式，默认 rgba"
    )
    acropalypse_restore_parser.add_argument("--json", action="store_true", dest="as_json")

    cloacked_parser = image_commands.add_parser(
        "cloacked-pixel", help="cloacked-pixel 兼容 AES-CBC + RGB LSB 隐写"
    )
    cloacked_actions = cloacked_parser.add_subparsers(dest="cloacked_action", required=True)
    cloacked_hide_parser = cloacked_actions.add_parser("hide", help="加密并嵌入文件到 RGB LSB")
    cloacked_hide_parser.add_argument("file", type=Path, help="原始图片")
    cloacked_hide_parser.add_argument("--payload", type=Path, required=True, help="待隐藏文件")
    cloacked_hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出 PNG")
    cloacked_hide_parser.add_argument("--password", required=True, help="AES 密码")
    cloacked_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    cloacked_extract_parser = cloacked_actions.add_parser(
        "extract", help="从 RGB LSB 提取并解密文件"
    )
    cloacked_extract_parser.add_argument("file", type=Path, help="隐写图片")
    cloacked_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    cloacked_extract_parser.add_argument("--password", help="AES 密码")
    cloacked_extract_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    cloacked_extract_parser.add_argument(
        "--contains", help="字典模式可选：要求解密结果包含该文本，减少 padding 误判"
    )
    cloacked_extract_parser.add_argument(
        "--prefix", help="字典模式可选：要求解密结果以该文本开头，如 flag{ 或 PK"
    )
    cloacked_extract_parser.add_argument(
        "--keep-padding", action="store_true", help="保留原工具 Python3 端可能遗留的 padding"
    )
    cloacked_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    cloacked_brute_parser = cloacked_actions.add_parser("brute", help="用密码字典爆破并提取载荷")
    cloacked_brute_parser.add_argument("file", type=Path, help="隐写图片")
    cloacked_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密码字典，一行一个密码"
    )
    cloacked_brute_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    cloacked_brute_parser.add_argument(
        "--contains", help="可选：要求解密结果包含该文本，减少 padding 误判"
    )
    cloacked_brute_parser.add_argument(
        "--prefix", help="可选：要求解密结果以该文本开头，如 flag{ 或 PK"
    )
    cloacked_brute_parser.add_argument(
        "--keep-padding", action="store_true", help="保留解密 padding"
    )
    cloacked_brute_parser.add_argument("--json", action="store_true", dest="as_json")

    cloacked_analyse_parser = cloacked_actions.add_parser(
        "analyse", help="统计 RGB LSB 均值检测可疑区域"
    )
    cloacked_analyse_parser.add_argument("file", type=Path, help="待分析图片")
    cloacked_analyse_parser.add_argument(
        "--block-size", type=int, default=100, help="统计块大小，默认 100"
    )
    cloacked_analyse_parser.add_argument(
        "--threshold", type=float, default=0.08, help="判定接近 0.5 的阈值，默认 0.08"
    )
    cloacked_analyse_parser.add_argument("--json", action="store_true", dest="as_json")

    stegpy_parser = image_commands.add_parser(
        "stegpy", help="stegpy 兼容 LSB 隐写嵌入、提取和字典爆破"
    )
    stegpy_actions = stegpy_parser.add_subparsers(dest="stegpy_action", required=True)
    stegpy_hide_parser = stegpy_actions.add_parser(
        "hide", help="按 stegpy stegv3 格式嵌入文本或文件"
    )
    stegpy_hide_parser.add_argument("file", type=Path, help="宿主 PNG/BMP/GIF/WebP/WAV")
    stegpy_hide_payload = stegpy_hide_parser.add_mutually_exclusive_group(required=True)
    stegpy_hide_payload.add_argument("--text", help="要嵌入的 UTF-8 文本")
    stegpy_hide_payload.add_argument("--payload", type=Path, help="要嵌入的文件")
    stegpy_hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出宿主文件")
    stegpy_hide_parser.add_argument("--password", help="可选：按 stegpy -p Fernet/PBKDF2 加密")
    stegpy_hide_parser.add_argument(
        "--bits", type=int, choices=(1, 2, 4), default=2, help="每个载体字节使用的低位数，默认 2"
    )
    stegpy_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    stegpy_extract_parser = stegpy_actions.add_parser("extract", help="提取 stegpy stegv3 载荷")
    stegpy_extract_parser.add_argument("file", type=Path, help="含 stegpy 数据的宿主文件")
    stegpy_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    stegpy_extract_parser.add_argument("--password", help="加密载荷密码")
    stegpy_extract_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    stegpy_extract_parser.add_argument("--contains", help="字典模式可选：要求解出载荷包含该文本")
    stegpy_extract_parser.add_argument("--prefix", help="字典模式可选：要求解出载荷以该文本开头")
    stegpy_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    stegpy_brute_parser = stegpy_actions.add_parser("brute", help="用字典爆破 stegpy -p 密码")
    stegpy_brute_parser.add_argument("file", type=Path, help="含加密 stegpy 数据的宿主文件")
    stegpy_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密码字典，一行一个密码"
    )
    stegpy_brute_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    stegpy_brute_parser.add_argument("--contains", help="可选：要求解出载荷包含该文本")
    stegpy_brute_parser.add_argument("--prefix", help="可选：要求解出载荷以该文本开头")
    stegpy_brute_parser.add_argument("--json", action="store_true", dest="as_json")

    steghide_parser = image_commands.add_parser(
        "steghide", help="调用 steghide 提取 JPG/BMP/WAV/AU 隐写，支持空密码和字典"
    )
    steghide_actions = steghide_parser.add_subparsers(dest="steghide_action", required=True)
    steghide_extract_parser = steghide_actions.add_parser(
        "extract", help="调用 steghide extract 提取隐藏文件"
    )
    steghide_extract_parser.add_argument("file", type=Path, help="含 steghide 数据的宿主文件")
    steghide_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    steghide_extract_parser.add_argument(
        "-p", "--password", default="", help="steghide passphrase；默认空密码"
    )
    steghide_extract_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    steghide_extract_parser.add_argument("--contains", help="字典模式可选：要求输出包含该文本")
    steghide_extract_parser.add_argument("--prefix", help="字典模式可选：要求输出以该文本开头")
    steghide_extract_parser.add_argument(
        "--no-empty", action="store_true", help="字典模式不先尝试空密码"
    )
    steghide_extract_parser.add_argument("--steghide", type=Path, help="steghide 可执行文件路径")
    steghide_extract_parser.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="后端：auto 默认先用内置 JPEG/BMP/WAV/AU native，再回退 steghide 工具",
    )
    steghide_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    steghide_brute_parser = steghide_actions.add_parser(
        "brute", help="用字典循环调用 steghide extract"
    )
    steghide_brute_parser.add_argument("file", type=Path, help="含 steghide 数据的宿主文件")
    steghide_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密码字典，一行一个密码"
    )
    steghide_brute_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    steghide_brute_parser.add_argument("--contains", help="可选：要求输出包含该文本")
    steghide_brute_parser.add_argument("--prefix", help="可选：要求输出以该文本开头")
    steghide_brute_parser.add_argument("--no-empty", action="store_true", help="不先尝试空密码")
    steghide_brute_parser.add_argument("--steghide", type=Path, help="steghide 可执行文件路径")
    steghide_brute_parser.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="后端：auto 默认先用内置 JPEG/BMP/WAV/AU native，再回退 steghide 工具",
    )
    steghide_brute_parser.add_argument("--json", action="store_true", dest="as_json")

    outguess_parser = image_commands.add_parser(
        "outguess", help="调用 OutGuess 处理 JPEG/PNM 隐写，支持密钥和字典"
    )
    outguess_actions = outguess_parser.add_subparsers(dest="outguess_action", required=True)
    outguess_extract_parser = outguess_actions.add_parser(
        "extract", help="调用 outguess -r 提取隐藏文件"
    )
    outguess_extract_parser.add_argument("file", type=Path, help="含 OutGuess 数据的 JPEG/PNM")
    outguess_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    outguess_extract_parser.add_argument(
        "-k", "--key", default="", help="OutGuess 解密密钥；默认空密钥"
    )
    outguess_extract_parser.add_argument("--wordlist", type=Path, help="密钥字典，一行一个密钥")
    outguess_extract_parser.add_argument("--contains", help="字典模式可选：要求输出包含该文本")
    outguess_extract_parser.add_argument("--prefix", help="字典模式可选：要求输出以该文本开头")
    outguess_extract_parser.add_argument(
        "--no-empty", action="store_true", help="字典模式不先尝试空密钥"
    )
    outguess_extract_parser.add_argument("--outguess", type=Path, help="outguess 可执行文件路径")
    outguess_extract_parser.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="后端：auto 对 PNM/baseline JPEG 用原生实现；native 仅原生；tool 调 outguess",
    )
    outguess_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    outguess_brute_parser = outguess_actions.add_parser("brute", help="用字典循环调用 outguess -r")
    outguess_brute_parser.add_argument("file", type=Path, help="含 OutGuess 数据的 JPEG/PNM")
    outguess_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密钥字典，一行一个密钥"
    )
    outguess_brute_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    outguess_brute_parser.add_argument("--contains", help="可选：要求输出包含该文本")
    outguess_brute_parser.add_argument("--prefix", help="可选：要求输出以该文本开头")
    outguess_brute_parser.add_argument("--no-empty", action="store_true", help="不先尝试空密钥")
    outguess_brute_parser.add_argument("--outguess", type=Path, help="outguess 可执行文件路径")
    outguess_brute_parser.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="后端：auto 对 PNM/baseline JPEG 用原生实现；native 仅原生；tool 调 outguess",
    )
    outguess_brute_parser.add_argument("--json", action="store_true", dest="as_json")

    outguess_hide_parser = outguess_actions.add_parser("hide", help="调用 outguess -d 嵌入文件")
    outguess_hide_parser.add_argument("file", type=Path, help="输入 JPEG/PNM")
    outguess_hide_parser.add_argument("--payload", type=Path, required=True, help="待隐藏文件")
    outguess_hide_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出 JPEG/PNM"
    )
    outguess_hide_parser.add_argument("-k", "--key", default="", help="OutGuess 密钥；默认空密钥")
    outguess_hide_parser.add_argument("--outguess", type=Path, help="outguess 可执行文件路径")
    outguess_hide_parser.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="后端：auto 对 PNM/baseline JPEG 用原生实现；native 仅原生；tool 调 outguess",
    )
    outguess_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    jsteg_parser = image_commands.add_parser("jsteg", help="jsteg JPEG DCT LSB 隐写提取与嵌入")
    jsteg_actions = jsteg_parser.add_subparsers(dest="jsteg_action", required=True)
    jsteg_reveal_parser = jsteg_actions.add_parser(
        "reveal", aliases=["extract"], help="提取 jsteg 隐藏数据"
    )
    jsteg_reveal_parser.add_argument("file", type=Path, help="含 jsteg 数据的 baseline JPEG")
    jsteg_reveal_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    jsteg_reveal_parser.add_argument(
        "--raw", action="store_true", help="输出原始 DCT LSB 字节流，不解析 jsteg magic/length"
    )
    jsteg_reveal_parser.add_argument("--json", action="store_true", dest="as_json")

    jsteg_hide_parser = jsteg_actions.add_parser(
        "hide", aliases=["embed"], help="嵌入 jsteg 隐藏数据"
    )
    jsteg_hide_parser.add_argument("file", type=Path, help="输入 baseline JPEG")
    jsteg_payload = jsteg_hide_parser.add_mutually_exclusive_group(required=True)
    jsteg_payload.add_argument("--payload", type=Path, help="待隐藏文件")
    jsteg_payload.add_argument("--text", help="待隐藏 UTF-8 文本")
    jsteg_hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出 JPEG")
    jsteg_hide_parser.add_argument(
        "--raw", action="store_true", help="按原始字节嵌入，不加 jsteg CLI magic/length"
    )
    jsteg_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    raw_lsb_parser = image_commands.add_parser(
        "raw-lsb", aliases=["rawlsb"], help="RAW/ARW Bayer 原始数据 LSB 提取与扫描"
    )
    raw_lsb_actions = raw_lsb_parser.add_subparsers(dest="raw_lsb_action", required=True)
    raw_lsb_extract_parser = raw_lsb_actions.add_parser(
        "extract", help="从 RAW Bayer 位平面提取字节流"
    )
    raw_lsb_extract_parser.add_argument(
        "file", type=Path, help="输入 RAW/ARW/NEF/DNG 等相机 RAW 文件"
    )
    raw_lsb_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    raw_lsb_extract_parser.add_argument("--bit", type=int, default=0, help="提取的位平面，默认 0")
    raw_lsb_extract_parser.add_argument(
        "--order", choices=("msb", "lsb"), default="msb", help="8 个像素组字节的位序，默认 msb"
    )
    raw_lsb_extract_parser.add_argument(
        "--source",
        choices=("visible", "full"),
        default="visible",
        help="rawpy 数组来源，默认 raw_image_visible",
    )
    raw_lsb_extract_parser.add_argument("--crop", help="裁剪 RAW 阵列区域 X,Y,W,H")
    raw_lsb_extract_parser.add_argument(
        "--offset", type=int, default=0, help="组字节后的起始偏移，默认 0"
    )
    raw_lsb_extract_parser.add_argument("--limit", type=int, help="最多写出多少字节")
    raw_lsb_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    raw_lsb_scan_parser = raw_lsb_actions.add_parser(
        "scan", help="扫描多个 RAW LSB 位平面并写出命中文件头的候选"
    )
    raw_lsb_scan_parser.add_argument("file", type=Path, help="输入 RAW/ARW/NEF/DNG 等相机 RAW 文件")
    raw_lsb_scan_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出候选目录"
    )
    raw_lsb_scan_parser.add_argument(
        "--bits", default="0:4", help="位平面列表或范围，如 0,1,2 或 0:4；默认 0:4"
    )
    raw_lsb_scan_parser.add_argument(
        "--orders", default="msb,lsb", help="位序列表：msb,lsb / msb / lsb"
    )
    raw_lsb_scan_parser.add_argument(
        "--source",
        choices=("visible", "full"),
        default="visible",
        help="rawpy 数组来源，默认 raw_image_visible",
    )
    raw_lsb_scan_parser.add_argument("--crop", help="裁剪 RAW 阵列区域 X,Y,W,H")
    raw_lsb_scan_parser.add_argument(
        "--max-bytes", type=int, default=1_048_576, help="每个流最多组字节数"
    )
    raw_lsb_scan_parser.add_argument(
        "--search-window", type=int, default=4096, help="文件头搜索窗口字节数"
    )
    raw_lsb_scan_parser.add_argument(
        "--write-all", action="store_true", help="即使命中文件头也写出所有 bit/order 原始流"
    )
    raw_lsb_scan_parser.add_argument("--json", action="store_true", dest="as_json")

    stegdetect_parser = image_commands.add_parser(
        "stegdetect", help="stegdetect 风格 JPEG 隐写类型检测"
    )
    stegdetect_parser.add_argument("files", nargs="+", type=Path, help="待检测 JPEG 文件")
    stegdetect_parser.add_argument(
        "-t",
        "--types",
        default="jopifa",
        help="检测类型字母：j=jsteg, o=outguess, p=jphide, i=invisible-secrets, f=F5, F=F5 slow, a=appended；默认 jopifa",
    )
    stegdetect_parser.add_argument(
        "-s", "--sensitivity", type=float, default=10.0, help="命中阈值，默认 10.0"
    )
    stegdetect_parser.add_argument("-o", "--output", type=Path, help="写出文本报告")
    stegdetect_parser.add_argument("--json", action="store_true", dest="as_json")

    _add_wbstego_command(image_commands)

    f5_parser = image_commands.add_parser(
        "f5", help="F5-steganography JPEG 原生隐写提取、嵌入和字典爆破"
    )
    f5_actions = f5_parser.add_subparsers(dest="f5_action", required=True)
    f5_extract_parser = f5_actions.add_parser("extract", help="原生提取 F5 隐藏文件")
    f5_extract_parser.add_argument("file", type=Path, help="含 F5 数据的 JPEG")
    f5_extract_parser.add_argument("-o", "--output", type=Path, required=True, help="输出隐藏文件")
    f5_extract_parser.add_argument(
        "-p", "--password", default="abc123", help="F5 密码，默认 abc123"
    )
    f5_extract_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    f5_extract_parser.add_argument("--contains", help="字典模式可选：要求输出包含该文本")
    f5_extract_parser.add_argument("--prefix", help="字典模式可选：要求输出以该文本开头")
    f5_extract_parser.add_argument(
        "--no-default", action="store_true", help="字典模式不先尝试默认密码 abc123"
    )
    f5_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    f5_brute_parser = f5_actions.add_parser("brute", help="用字典爆破 F5 密码")
    f5_brute_parser.add_argument("file", type=Path, help="含 F5 数据的 JPEG")
    f5_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密码字典，一行一个密码"
    )
    f5_brute_parser.add_argument("-o", "--output", type=Path, required=True, help="输出隐藏文件")
    f5_brute_parser.add_argument("--contains", help="可选：要求输出包含该文本")
    f5_brute_parser.add_argument("--prefix", help="可选：要求输出以该文本开头")
    f5_brute_parser.add_argument(
        "--no-default", action="store_true", help="不先尝试默认密码 abc123"
    )
    f5_brute_parser.add_argument("--json", action="store_true", dest="as_json")

    f5_hide_parser = f5_actions.add_parser("hide", help="原生 F5 嵌入文件到 JPEG DCT 系数")
    f5_hide_parser.add_argument("file", type=Path, help="输入 baseline JPEG")
    f5_hide_parser.add_argument("--payload", type=Path, required=True, help="待隐藏文件")
    f5_hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出 JPEG")
    f5_hide_parser.add_argument("-p", "--password", default="abc123", help="F5 密码，默认 abc123")
    f5_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    jphs_parser = image_commands.add_parser(
        "jphs", help="JPHS / JPHide+JPSeek JPEG 隐写封装，支持空密码和字典"
    )
    jphs_actions = jphs_parser.add_subparsers(dest="jphs_action", required=True)
    jphs_hide_parser = jphs_actions.add_parser("hide", help="用纯 Python 或 jphide 嵌入文件到 JPEG")
    jphs_hide_parser.add_argument("file", type=Path, help="输入 JPEG")
    jphs_hide_parser.add_argument("--payload", type=Path, required=True, help="待隐藏文件")
    jphs_hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出 JPEG")
    jphs_hide_parser.add_argument("--password", default="", help="JPHS pass phrase；默认空密码")
    jphs_hide_parser.add_argument("--jphide", type=Path, help="jphide 可执行文件路径")
    jphs_hide_parser.add_argument("--wine", type=Path, help="运行 jphs05 Windows exe 的 wine 路径")
    jphs_hide_parser.add_argument(
        "--backend",
        choices=("python", "tool", "auto"),
        default="python",
        help="嵌入后端：默认 python；tool 调 jphide；auto 先 python 后 tool",
    )
    jphs_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    jphs_extract_parser = jphs_actions.add_parser(
        "extract", help="用纯 Python 或 jpseek 提取隐藏文件"
    )
    jphs_extract_parser.add_argument("file", type=Path, help="含 JPHS 数据的 JPEG")
    jphs_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    jphs_extract_parser.add_argument("--password", default="", help="JPHS pass phrase；默认空密码")
    jphs_extract_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    jphs_extract_parser.add_argument("--contains", help="字典模式可选：要求输出包含该文本")
    jphs_extract_parser.add_argument("--prefix", help="字典模式可选：要求输出以该文本开头")
    jphs_extract_parser.add_argument(
        "--no-empty", action="store_true", help="字典模式不先尝试空密码"
    )
    jphs_extract_parser.add_argument("--jpseek", type=Path, help="jpseek 可执行文件路径")
    jphs_extract_parser.add_argument(
        "--wine", type=Path, help="运行 jphs05 Windows exe 的 wine 路径"
    )
    jphs_extract_parser.add_argument(
        "--backend",
        choices=("python", "tool", "auto"),
        default="python",
        help="提取后端：默认 python；tool 调 jpseek；auto 先 python 后 tool",
    )
    jphs_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    jphs_brute_parser = jphs_actions.add_parser("brute", help="用字典爆破 JPHS pass phrase")
    jphs_brute_parser.add_argument("file", type=Path, help="含 JPHS 数据的 JPEG")
    jphs_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密码字典，一行一个密码"
    )
    jphs_brute_parser.add_argument("-o", "--output", type=Path, required=True, help="输出隐藏文件")
    jphs_brute_parser.add_argument("--contains", help="可选：要求输出包含该文本")
    jphs_brute_parser.add_argument("--prefix", help="可选：要求输出以该文本开头")
    jphs_brute_parser.add_argument("--no-empty", action="store_true", help="不先尝试空密码")
    jphs_brute_parser.add_argument("--jpseek", type=Path, help="jpseek 可执行文件路径")
    jphs_brute_parser.add_argument("--wine", type=Path, help="运行 jphs05 Windows exe 的 wine 路径")
    jphs_brute_parser.add_argument(
        "--backend",
        choices=("python", "tool"),
        default="python",
        help="爆破后端：默认 python；tool 调 jpseek",
    )
    jphs_brute_parser.add_argument("--json", action="store_true", dest="as_json")

    pixeljihad_parser = image_commands.add_parser(
        "pixeljihad", help="PixelJihad 空密码图片隐写提取与嵌入"
    )
    pixeljihad_actions = pixeljihad_parser.add_subparsers(dest="pixeljihad_action", required=True)
    pixeljihad_decode_parser = pixeljihad_actions.add_parser(
        "decode", help="提取 PixelJihad 隐写文本，默认按空密码读取"
    )
    pixeljihad_decode_parser.add_argument("files", nargs="+", type=Path, help="输入图片")
    pixeljihad_decode_parser.add_argument(
        "-o", "--output", type=Path, help="把多图结果拼接写入文本文件"
    )
    pixeljihad_decode_parser.add_argument(
        "--password", default="", help="位序密码，默认空；有密钥样本输出 SJCL 密文"
    )
    pixeljihad_decode_parser.add_argument(
        "--wordlist", type=Path, help="密码字典，一行一个位序密码"
    )
    pixeljihad_decode_parser.add_argument("--contains", help="字典模式可选：要求拼接结果包含该文本")
    pixeljihad_decode_parser.add_argument(
        "--raw", action="store_true", help="输出原始 JSON/SJCL 字符串而不是 text 字段"
    )
    pixeljihad_decode_parser.add_argument("--json", action="store_true", dest="as_json")

    pixeljihad_encode_parser = pixeljihad_actions.add_parser(
        "encode", help="按 PixelJihad 空密码格式嵌入文本"
    )
    pixeljihad_encode_parser.add_argument("file", type=Path, help="原始图片")
    pixeljihad_encode_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出 PNG"
    )
    pixeljihad_encode_parser.add_argument("--text", required=True, help="要嵌入的文本")
    pixeljihad_encode_parser.add_argument(
        "--password", default="", help="保留参数；当前仅空密码嵌入兼容 PixelJihad"
    )
    pixeljihad_encode_parser.add_argument("--json", action="store_true", dest="as_json")

    puzzle_parser = image_commands.add_parser("puzzle", help="分析并自动还原规则网格拼图")
    puzzle_actions = puzzle_parser.add_subparsers(dest="puzzle_action", required=True)
    puzzle_analyze_parser = puzzle_actions.add_parser("analyze", help="分析拼图块和候选网格")
    puzzle_analyze_parser.add_argument("files", nargs="+", type=Path, help="拼图块或蒙太奇图片")
    _add_puzzle_tile_options(puzzle_analyze_parser)
    puzzle_analyze_parser.add_argument("--json", action="store_true", dest="as_json")

    puzzle_solve_parser = puzzle_actions.add_parser("solve", help="按边缘连续性自动排列拼图")
    puzzle_solve_parser.add_argument("files", nargs="+", type=Path, help="拼图块或蒙太奇图片")
    puzzle_solve_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
    puzzle_solve_parser.add_argument("--rows", type=int, required=True, help="拼图行数")
    puzzle_solve_parser.add_argument("--columns", type=int, required=True, help="拼图列数")
    _add_puzzle_tile_options(puzzle_solve_parser)
    puzzle_solve_parser.add_argument(
        "--algorithm",
        choices=("auto", "exact", "genetic", "greedy"),
        default="auto",
        help="求解算法，默认按块数自动选择",
    )
    puzzle_solve_parser.add_argument(
        "--rotate", choices=("none", "90"), default="none", help="是否搜索 90 度旋转"
    )
    puzzle_solve_parser.add_argument("--generations", type=int, default=200, help="遗传算法代数")
    puzzle_solve_parser.add_argument("--population", type=int, default=0, help="种群大小，0 为自动")
    puzzle_solve_parser.add_argument("--edge-width", type=int, default=2, help="边缘采样宽度")
    puzzle_solve_parser.add_argument("--seed", type=int, default=0, help="随机种子")
    puzzle_solve_parser.add_argument("--manifest", type=Path, help="布局 JSON 输出路径")
    puzzle_solve_parser.add_argument("--json", action="store_true", dest="as_json")

    watermark_parser = image_commands.add_parser("watermark", help="水印嵌入与提取")
    watermark_modes = watermark_parser.add_subparsers(dest="watermark_mode", required=True)
    single_parser = watermark_modes.add_parser("single", help="单图盲水印")
    single_profiles = single_parser.add_subparsers(dest="watermark_profile", required=True)
    watermarkh_parser = single_profiles.add_parser("watermarkh", help="WaterMarkH 文字盲水印")
    single_actions = watermarkh_parser.add_subparsers(dest="watermark_action", required=True)

    embed_parser = single_actions.add_parser("embed", help="嵌入兼容 WaterMarkH 的文字水印")
    embed_parser.add_argument("file", type=Path, help="原始图片")
    embed_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
    embed_parser.add_argument("--text", required=True, help="水印文字")
    embed_parser.add_argument("--strength", type=float, default=20, help="水印强度，默认 20")
    embed_parser.add_argument("--font", type=Path, help="TTF/TTC 字体路径")
    embed_parser.add_argument("--font-size", type=int, default=32, help="字体大小，默认 32")
    _add_watermark_common_options(embed_parser)

    extract_parser = single_actions.add_parser("extract", help="从单张图片提取盲水印")
    extract_parser.add_argument("file", type=Path, help="水印图片")
    extract_parser.add_argument("-o", "--output", type=Path, required=True, help="输出频谱图")
    extract_parser.add_argument("--brightness", type=float, default=5, help="显示亮度，默认 5")
    _add_watermark_common_options(extract_parser)

    dual_parser = watermark_modes.add_parser("dual", help="双图频域盲水印")
    dual_profiles = dual_parser.add_subparsers(dest="watermark_profile", required=True)
    for profile, help_text in (
        ("chishaxie", "chishaxie/BlindWaterMark"),
        ("linyacool", "linyacool/blind-watermark"),
    ):
        profile_parser = dual_profiles.add_parser(profile, help=help_text)
        dual_actions = profile_parser.add_subparsers(dest="watermark_action", required=True)
        dual_embed_parser = dual_actions.add_parser("embed", help="将水印图片嵌入载体图片")
        dual_embed_parser.add_argument("file", type=Path, help="原始载体图片")
        dual_embed_parser.add_argument("--watermark", type=Path, required=True, help="水印图片")
        dual_embed_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
        _add_dual_watermark_options(dual_embed_parser)

        dual_extract_parser = dual_actions.add_parser("extract", help="使用原图提取水印图片")
        dual_extract_parser.add_argument("file", type=Path, help="含水印图片")
        dual_extract_parser.add_argument(
            "--reference", type=Path, required=True, help="原始载体图片"
        )
        dual_extract_parser.add_argument(
            "-o", "--output", type=Path, required=True, help="输出水印"
        )
        dual_extract_parser.add_argument("--width", type=int, help="已知水印宽度")
        dual_extract_parser.add_argument("--height", type=int, help="已知水印高度")
        dual_extract_parser.add_argument(
            "--no-crop",
            action="store_true",
            help="保留原始载体尺寸的上半区，不自动裁掉空白",
        )
        _add_dual_watermark_options(dual_extract_parser)

    for profile, transform, help_text in (
        ("ww23-dct", "dct", "ww23/BlindWatermark DCT 默认算法"),
        ("ww23-dft", "dft", "ww23/BlindWatermark DFT 旧版算法"),
    ):
        profile_parser = dual_profiles.add_parser(profile, help=help_text)
        profile_parser.set_defaults(watermark_transform=transform)
        ww23_actions = profile_parser.add_subparsers(dest="watermark_action", required=True)
        ww23_embed_parser = ww23_actions.add_parser("embed", help="嵌入图片水印")
        ww23_embed_parser.add_argument("file", type=Path, help="原始载体图片")
        ww23_embed_parser.add_argument("--watermark", type=Path, required=True, help="水印图片")
        ww23_embed_parser.add_argument("-o", "--output", type=Path, required=True, help="输出图片")
        _add_ww23_options(ww23_embed_parser, include_alpha=True)

        ww23_extract_parser = ww23_actions.add_parser("extract", help="盲提取水印频谱")
        ww23_extract_parser.add_argument("file", type=Path, help="含水印图片")
        ww23_extract_parser.add_argument(
            "-o", "--output", type=Path, required=True, help="输出水印"
        )
        _add_ww23_options(ww23_extract_parser, include_alpha=False)
    text_parser = commands.add_parser("text", help="文本隐写与文本型 esolang")
    text_commands = text_parser.add_subparsers(dest="text_command", required=True)
    whitespace_parser = text_commands.add_parser(
        "whitespace", aliases=["ws"], help="Whitespace 语言隐写运行、可视化和生成"
    )
    whitespace_actions = whitespace_parser.add_subparsers(dest="whitespace_action", required=True)
    whitespace_run = whitespace_actions.add_parser(
        "run", aliases=["decode"], help="运行隐藏在文本中的 Whitespace 程序"
    )
    whitespace_run.add_argument("file", type=Path, help="含空格/Tab/LF 程序的文本文件")
    whitespace_run.add_argument(
        "-o", "--output", type=Path, help="把程序 stdout 写入文件；默认打印到终端"
    )
    whitespace_run.add_argument("--input", default="", help="提供给 Whitespace read 指令的输入")
    whitespace_run.add_argument("--input-file", type=Path, help="从文件读取程序输入")
    whitespace_run.add_argument(
        "--max-steps", type=int, default=1_000_000, help="最大执行步数，默认 1000000"
    )
    whitespace_run.add_argument("--json", action="store_true", dest="as_json")

    whitespace_show = whitespace_actions.add_parser(
        "show", aliases=["visible"], help="把不可见空白程序转换成可见 S/T/L 表示"
    )
    whitespace_show.add_argument("file", type=Path, help="含 Whitespace 的文本文件")
    whitespace_show.add_argument("-o", "--output", type=Path, required=True, help="输出可见文本")
    whitespace_show.add_argument(
        "--style", choices=("stl", "unicode"), default="stl", help="显示风格，默认 stl"
    )
    whitespace_show.add_argument("--json", action="store_true", dest="as_json")

    whitespace_encode = whitespace_actions.add_parser(
        "encode", help="生成打印指定文本/文件的 Whitespace 程序"
    )
    whitespace_payload = whitespace_encode.add_mutually_exclusive_group(required=True)
    whitespace_payload.add_argument("--text", help="要由 Whitespace 程序输出的 UTF-8 文本")
    whitespace_payload.add_argument(
        "--payload", type=Path, help="要由 Whitespace 程序输出的文件字节"
    )
    whitespace_encode.add_argument(
        "-o", "--output", type=Path, required=True, help="输出 Whitespace 程序"
    )
    whitespace_encode.add_argument("--json", action="store_true", dest="as_json")

    spammimic_parser = text_commands.add_parser(
        "spammimic", aliases=["spam-mimic", "spam"], help="SpamMimic 垃圾邮件/空白文本隐写"
    )
    spammimic_actions = spammimic_parser.add_subparsers(dest="spammimic_action", required=True)

    spammimic_encode = spammimic_actions.add_parser(
        "encode", aliases=["hide", "embed"], help="把文本或文件编码成垃圾邮件样式文本"
    )
    spammimic_payload = spammimic_encode.add_mutually_exclusive_group(required=True)
    spammimic_payload.add_argument("--text", help="要隐藏的 UTF-8 文本")
    spammimic_payload.add_argument("--payload", type=Path, help="要隐藏的文件")
    spammimic_encode.add_argument("-o", "--output", type=Path, required=True, help="输出隐写文本")
    spammimic_encode.add_argument(
        "-p", "--password", help="密码；native 使用本地 XOR 帧，remote 传给 spammimic.com"
    )
    spammimic_encode.add_argument(
        "--mode",
        choices=("spam", "space"),
        default="spam",
        help="spam 垃圾邮件文本；space 空白模式",
    )
    spammimic_encode.add_argument("--cover", type=Path, help="space 模式使用的可见载体文本")
    spammimic_encode.add_argument(
        "--backend",
        choices=("native", "remote"),
        default="native",
        help="native 本地；remote 调用 spammimic.com",
    )
    spammimic_encode.add_argument("--json", action="store_true", dest="as_json")

    spammimic_decode = spammimic_actions.add_parser(
        "decode", aliases=["extract", "reveal"], help="从 SpamMimic 文本提取载荷"
    )
    spammimic_decode.add_argument("file", type=Path, help="含 SpamMimic 隐写的文本")
    spammimic_decode.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    spammimic_decode.add_argument("-p", "--password", help="解码密码")
    spammimic_decode.add_argument("--wordlist", type=Path, help="逐行读取密码字典爆破")
    spammimic_decode.add_argument("--contains", help="爆破成功判定：输出包含该文本")
    spammimic_decode.add_argument("--prefix", help="爆破成功判定：输出以该文本开头")
    spammimic_decode.add_argument("--no-default", action="store_true", help="爆破时不先尝试空密码")
    spammimic_decode.add_argument(
        "--mode",
        choices=("spam", "space"),
        default="spam",
        help="spam 垃圾邮件文本；space 空白模式",
    )
    spammimic_decode.add_argument(
        "--backend",
        choices=("auto", "native", "remote"),
        default="auto",
        help="auto 先 native 后 remote",
    )
    spammimic_decode.add_argument("--json", action="store_true", dest="as_json")

    snow_parser = text_commands.add_parser(
        "snow", aliases=["stegsnow"], help="SNOW/stegsnow 行尾空白隐写嵌入、提取和容量估算"
    )
    snow_actions = snow_parser.add_subparsers(dest="snow_action", required=True)

    snow_hide = snow_actions.add_parser(
        "hide", aliases=["embed"], help="按 SNOW 格式在文本行尾嵌入载荷"
    )
    snow_hide.add_argument("file", type=Path, help="载体文本")
    snow_payload = snow_hide.add_mutually_exclusive_group(required=True)
    snow_payload.add_argument("--text", help="要嵌入的 UTF-8 文本")
    snow_payload.add_argument("--payload", type=Path, help="要嵌入的文件")
    snow_hide.add_argument("-o", "--output", type=Path, required=True, help="输出含行尾空白的文本")
    snow_hide.add_argument("-p", "--password", help="调用 stegsnow 后端时使用 ICE 密码")
    snow_hide.add_argument(
        "-C", "--compress", action="store_true", help="调用 stegsnow 后端启用 Huffman 压缩"
    )
    snow_hide.add_argument("-l", "--line-length", type=int, default=80, help="最大行宽，默认 80")
    snow_hide.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="auto/native/tool，默认 auto",
    )
    snow_hide.add_argument("--snow", type=Path, help="stegsnow/snow 可执行文件路径")
    snow_hide.add_argument("--json", action="store_true", dest="as_json")

    snow_extract = snow_actions.add_parser(
        "extract", aliases=["decode"], help="从 SNOW 文本提取载荷"
    )
    snow_extract.add_argument("file", type=Path, help="含 SNOW 行尾空白的文本")
    snow_extract.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    snow_extract.add_argument("-p", "--password", help="调用 stegsnow 后端解密")
    snow_extract.add_argument(
        "-C", "--compress", action="store_true", help="调用 stegsnow 后端解压"
    )
    snow_extract.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="auto/native/tool，默认 auto",
    )
    snow_extract.add_argument("--snow", type=Path, help="stegsnow/snow 可执行文件路径")
    snow_extract.add_argument("--json", action="store_true", dest="as_json")

    snow_capacity = snow_actions.add_parser(
        "capacity", aliases=["space"], help="估算指定行宽下的 SNOW 可用容量"
    )
    snow_capacity.add_argument("file", type=Path, help="载体文本")
    snow_capacity.add_argument(
        "-l", "--line-length", type=int, default=80, help="最大行宽，默认 80"
    )
    snow_capacity.add_argument("--json", action="store_true", dest="as_json")

    zw_parser = text_commands.add_parser(
        "zerowidth",
        aliases=["zero-width", "zwc"],
        help="零宽字符文本隐写嵌入、提取、检查和清理",
    )
    zw_actions = zw_parser.add_subparsers(dest="zerowidth_action", required=True)

    zw_hide = zw_actions.add_parser(
        "hide", aliases=["embed"], help="把文本或文件编码成零宽字符并插入载体文本"
    )
    zw_hide.add_argument("file", type=Path, help="载体文本")
    zw_payload = zw_hide.add_mutually_exclusive_group(required=True)
    zw_payload.add_argument("--text", help="要嵌入的 UTF-8 文本")
    zw_payload.add_argument("--payload", type=Path, help="要嵌入的文件")
    zw_hide.add_argument("-o", "--output", type=Path, required=True, help="输出隐写文本")
    zw_hide.add_argument(
        "--mode",
        choices=("binary", "text"),
        default="binary",
        help="binary 按字节；text 兼容 330k UTF-16 文本模式",
    )
    zw_hide.add_argument(
        "--alphabet",
        default="330k",
        help="预置字符表：330k/default/all4/zwsp-bit/joiner-bit/separator-bit",
    )
    zw_hide.add_argument("--chars", help="自定义字符表，可写原字符、\u200b\u200c 或 U+200B,U+200C")
    zw_hide.add_argument(
        "--placement",
        choices=("spread", "start", "end"),
        default="spread",
        help="插入位置，默认 spread",
    )
    zw_hide.add_argument("--json", action="store_true", dest="as_json")

    zw_extract = zw_actions.add_parser("extract", aliases=["decode"], help="提取零宽字符隐写载荷")
    zw_extract.add_argument("file", type=Path, help="含零宽字符的文本")
    zw_extract.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    zw_extract.add_argument(
        "--mode",
        choices=("binary", "text"),
        default="binary",
        help="binary 按字节；text 兼容 330k UTF-16 文本模式",
    )
    zw_extract.add_argument(
        "--alphabet",
        default="330k",
        help="预置字符表：330k/default/all4/zwsp-bit/joiner-bit/separator-bit",
    )
    zw_extract.add_argument(
        "--chars", help="自定义字符表，可写原字符、\u200b\u200c 或 U+200B,U+200C"
    )
    zw_extract.add_argument("--json", action="store_true", dest="as_json")

    zw_inspect = zw_actions.add_parser("inspect", aliases=["scan"], help="统计文本中的常见零宽字符")
    zw_inspect.add_argument("file", type=Path, help="待检查文本")
    zw_inspect.add_argument("--json", action="store_true", dest="as_json")

    zw_strip = zw_actions.add_parser(
        "strip", aliases=["clean"], help="删除常见零宽字符并写出干净文本"
    )
    zw_strip.add_argument("file", type=Path, help="输入文本")
    zw_strip.add_argument("-o", "--output", type=Path, required=True, help="输出文本")
    zw_strip.add_argument("--json", action="store_true", dest="as_json")

    cloakify_parser = text_commands.add_parser(
        "cloakify", aliases=["cloak"], help="Cloakify 列表字典隐写编码、解码和检查"
    )
    cloakify_actions = cloakify_parser.add_subparsers(dest="cloakify_action", required=True)

    cloakify_cloak = cloakify_actions.add_parser(
        "cloak", aliases=["hide", "encode"], help="Base64 后按字典行映射生成 Cloakify 文本"
    )
    cloakify_cloak.add_argument("file", type=Path, help="任意载荷文件")
    cloakify_cloak.add_argument(
        "--cipher", type=Path, required=True, help="Cloakify 字典/密码本，至少 65 个非空唯一条目"
    )
    cloakify_cloak.add_argument(
        "-o", "--output", type=Path, required=True, help="输出 Cloakify 文本"
    )
    cloakify_cloak.add_argument("--json", action="store_true", dest="as_json")

    cloakify_decloak = cloakify_actions.add_parser(
        "decloak", aliases=["extract", "decode"], help="使用同一字典把 Cloakify 文本还原为载荷"
    )
    cloakify_decloak.add_argument("file", type=Path, help="Cloakify 密文文本")
    cloakify_decloak.add_argument("--cipher", type=Path, required=True, help="Cloakify 字典/密码本")
    cloakify_decloak.add_argument("-o", "--output", type=Path, required=True, help="输出还原载荷")
    cloakify_decloak.add_argument(
        "--ignore-unknown", action="store_true", help="跳过不在字典中的非空行"
    )
    cloakify_decloak.add_argument("--json", action="store_true", dest="as_json")

    cloakify_inspect = cloakify_actions.add_parser(
        "inspect", aliases=["scan"], help="统计 Cloakify 行数；提供字典时统计命中/未知行"
    )
    cloakify_inspect.add_argument("file", type=Path, help="待检查 Cloakify 文本")
    cloakify_inspect.add_argument("--cipher", type=Path, help="可选：Cloakify 字典/密码本")
    cloakify_inspect.add_argument("--json", action="store_true", dest="as_json")

    stego_parser = commands.add_parser("stego", help="跨载体隐写工具，和 image 同级")
    stego_commands = stego_parser.add_subparsers(dest="image_command", required=True)
    _add_stego_commands(stego_commands)

    return parser


def _add_oursecret_command(
    subcommands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    oursecret_parser = subcommands.add_parser(
        "oursecret",
        aliases=["our-secret"],
        help="OurSecret 兼容任意文件追加/BMP LSB 隐写提取与嵌入",
    )
    oursecret_actions = oursecret_parser.add_subparsers(dest="oursecret_action", required=True)

    inspect_parser = oursecret_actions.add_parser(
        "inspect", aliases=["scan"], help="检查 OurSecret HI 尾部或 BMP LSB 标记"
    )
    inspect_parser.add_argument("file", type=Path, help="待检查载体")
    inspect_parser.add_argument(
        "--mode",
        choices=("auto", "append", "lsb"),
        default="auto",
        help="检测模式，默认 auto",
    )
    inspect_parser.add_argument("--json", action="store_true", dest="as_json")

    extract_parser = oursecret_actions.add_parser(
        "extract", aliases=["reveal"], help="提取 OurSecret 隐藏 ZIP 载荷"
    )
    extract_parser.add_argument("file", type=Path, help="含 OurSecret 数据的载体")
    extract_parser.add_argument("-o", "--output", type=Path, required=True, help="输出目录")
    extract_parser.add_argument("--password", help="可选：校验 OurSecret 密码标记")
    extract_parser.add_argument(
        "--mode",
        choices=("auto", "append", "lsb"),
        default="auto",
        help="提取模式，默认 auto",
    )
    extract_parser.add_argument("--overwrite", action="store_true", help="覆盖同名输出文件")
    extract_parser.add_argument("--json", action="store_true", dest="as_json")

    hide_parser = oursecret_actions.add_parser(
        "hide", aliases=["embed"], help="生成 OurSecret 兼容载体"
    )
    hide_parser.add_argument("file", type=Path, help="输入载体")
    oursecret_payload = hide_parser.add_mutually_exclusive_group(required=True)
    oursecret_payload.add_argument(
        "--payload", type=Path, action="append", help="待隐藏文件，可重复"
    )
    oursecret_payload.add_argument("--text", help="隐藏 UTF-8 文本")
    hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出载体")
    hide_parser.add_argument("--password", default="", help="OurSecret 密码标记，默认空密码")
    hide_parser.add_argument("--text-name", default="Message", help="--text 写入 ZIP 的条目名")
    hide_parser.add_argument(
        "--mode",
        choices=("append", "lsb"),
        default="append",
        help="嵌入方式：append 任意载体；lsb 仅 24-bit BMP",
    )
    hide_parser.add_argument("--lsb", action="store_true", help="等同于 --mode lsb")
    hide_parser.add_argument("--json", action="store_true", dest="as_json")


def _add_wbstego_command(
    subcommands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    wbstego_parser = subcommands.add_parser(
        "wbstego", help="wbStego4open BMP/TXT/HTML/PDF 原生隐写提取与嵌入"
    )
    wbstego_actions = wbstego_parser.add_subparsers(dest="wbstego_action", required=True)
    wbstego_extract_parser = wbstego_actions.add_parser(
        "extract", help="提取 wbStego4open 隐藏文件"
    )
    wbstego_extract_parser.add_argument("file", type=Path, help="含 wbStego 数据的载体")
    wbstego_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    wbstego_extract_parser.add_argument(
        "--carrier",
        choices=("auto", "bmp", "asc", "txt", "html", "pdf"),
        default="auto",
        help="载体类型：auto 按扩展名判断；asc 是空格/NUL 替换，txt/html/pdf 是行前插入",
    )
    wbstego_extract_parser.add_argument(
        "-p", "--password", help="按 wbStego4open 控制字节解密隐藏数据"
    )
    wbstego_extract_parser.add_argument(
        "--wordlist", type=Path, help="从自定义字典逐行尝试 wbStego 密码"
    )
    wbstego_extract_parser.add_argument("--contains", help="爆破成功判定：输出包含该文本")
    wbstego_extract_parser.add_argument("--prefix", help="爆破成功判定：输出以该文本开头")
    wbstego_extract_parser.add_argument(
        "--no-default", action="store_true", help="爆破时不先尝试空密码"
    )
    wbstego_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    wbstego_hide_parser = wbstego_actions.add_parser(
        "hide", help="嵌入文件，兼容 wbStego4open 原生模式"
    )
    wbstego_hide_parser.add_argument("file", type=Path, help="输入载体")
    wbstego_hide_parser.add_argument("--payload", type=Path, required=True, help="待隐藏文件")
    wbstego_hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出载体")
    wbstego_hide_parser.add_argument(
        "--carrier",
        choices=("auto", "bmp", "asc", "txt", "html", "pdf"),
        default="auto",
        help="载体类型：auto 按扩展名判断；asc 是空格/NUL 替换，txt/html/pdf 是行前插入",
    )
    wbstego_hide_parser.add_argument(
        "--distribute", action="store_true", help="按 wbStego 的分散模式填充载荷"
    )
    wbstego_hide_parser.add_argument(
        "-p", "--password", help="按 wbStego4open 控制字节加密隐藏数据"
    )
    wbstego_hide_parser.add_argument(
        "--no-crypt",
        action="store_true",
        help="密码模式只写控制字节/可配合 --mix，不执行 MLK/BBS XOR",
    )
    wbstego_hide_parser.add_argument(
        "--mix", action="store_true", help="启用 wbStego4open Mix 矩阵置乱"
    )
    wbstego_hide_parser.add_argument(
        "--transmit-password",
        action="store_true",
        help="按原版 Transmit 模式把密码混入隐藏数据用于校验",
    )
    wbstego_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    wbstego_analyse_parser = wbstego_actions.add_parser("analyse", help="查看 wbStego 可用容量")
    wbstego_analyse_parser.add_argument("file", type=Path, help="输入载体")
    wbstego_analyse_parser.add_argument(
        "--carrier",
        choices=("auto", "bmp", "asc", "txt", "html", "pdf"),
        default="auto",
        help="载体类型",
    )
    wbstego_analyse_parser.add_argument("--json", action="store_true", dest="as_json")


def _add_zip_timestamp_common_options(
    parser: argparse.ArgumentParser,
    *,
    include_source: bool = True,
    include_field: bool = True,
    require_base: bool = False,
    default_scale: int = 1,
) -> None:
    if include_source:
        parser.add_argument(
            "--source",
            choices=("auto", "zip", "dir"),
            default="auto",
            help="读取来源：auto 自动识别 ZIP/目录，默认 auto",
        )
    if include_field:
        parser.add_argument(
            "--field",
            choices=("modified", "created", "accessed"),
            default="modified",
            help="用于解码的时间字段，ZIP 仅支持 modified",
        )
    parser.add_argument(
        "--sort",
        choices=("auto", "archive", "name", "numeric", "timestamp"),
        default="auto",
        help="条目顺序：ZIP 默认 archive，目录默认 numeric",
    )
    parser.add_argument("--include", default="", help="仅处理名称包含该子串的条目")
    parser.add_argument("--glob", default="", help="仅处理匹配该 glob 的条目，如 '*.txt'")
    parser.add_argument(
        "--timezone",
        choices=("local", "utc"),
        default="local",
        help="ZIP date_time 到 Unix 时间戳的解释方式，默认 local",
    )
    parser.add_argument(
        "--base",
        type=int,
        required=require_base,
        help="基准 Unix 时间戳；解码公式 value=(timestamp-base)/scale+offset",
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="解码后偏移；示例 chr(timestamp-base+1) 可写 --offset 1",
    )
    parser.add_argument(
        "--scale",
        type=int,
        default=default_scale,
        help=f"每个字符占用的秒数，默认 {default_scale}",
    )


def _add_zip_crc_reverse_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--charset",
        choices=(
            "all",
            "printable",
            "ascii",
            "digits",
            "lower",
            "upper",
            "alpha",
            "alnum",
            "hex",
            "flag",
        ),
        default="all",
        help="候选字符集，默认 all 包含 0x00..0xff",
    )
    parser.add_argument("--chars", help="自定义候选字节；也可写 hex:000102ff")
    parser.add_argument("--prefix", default="", help="已知 UTF-8 前缀")
    parser.add_argument("--suffix", default="", help="已知 UTF-8 后缀")
    parser.add_argument("--prefix-hex", default="", help="已知十六进制前缀，例如 89504e47")
    parser.add_argument("--suffix-hex", default="", help="已知十六进制后缀")
    parser.add_argument("--limit", type=int, default=100, help="最多保存/显示候选数，默认 100")
    parser.add_argument(
        "--max-prefixes",
        type=int,
        default=2_000_000,
        help="最多枚举的 length-4 前缀数量；0 表示不限制",
    )


def _add_stego_commands(
    stego_commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Expose only cross-carrier steganography tools outside image.

    These parsers intentionally reuse ``image_command`` and the existing handler
    branch so the old ``omm image ...`` commands remain compatible while the new
    ``omm stego ...`` namespace is reserved for tools that operate on multiple
    carrier families such as images and audio.
    """

    _add_wbstego_command(stego_commands)
    _add_oursecret_command(stego_commands)
    _add_silenteye_command(stego_commands)
    _add_deepsound_command(stego_commands)

    stegpy_parser = stego_commands.add_parser(
        "stegpy", help="stegpy 兼容 LSB 隐写嵌入、提取和字典爆破"
    )
    stegpy_actions = stegpy_parser.add_subparsers(dest="stegpy_action", required=True)
    stegpy_hide_parser = stegpy_actions.add_parser(
        "hide", help="按 stegpy stegv3 格式嵌入文本或文件"
    )
    stegpy_hide_parser.add_argument("file", type=Path, help="宿主 PNG/BMP/GIF/WebP/WAV")
    stegpy_hide_payload = stegpy_hide_parser.add_mutually_exclusive_group(required=True)
    stegpy_hide_payload.add_argument("--text", help="要嵌入的 UTF-8 文本")
    stegpy_hide_payload.add_argument("--payload", type=Path, help="要嵌入的文件")
    stegpy_hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出宿主文件")
    stegpy_hide_parser.add_argument("--password", help="可选：按 stegpy -p Fernet/PBKDF2 加密")
    stegpy_hide_parser.add_argument(
        "--bits", type=int, choices=(1, 2, 4), default=2, help="每个载体字节使用的低位数，默认 2"
    )
    stegpy_hide_parser.add_argument("--json", action="store_true", dest="as_json")

    stegpy_extract_parser = stegpy_actions.add_parser("extract", help="提取 stegpy stegv3 载荷")
    stegpy_extract_parser.add_argument("file", type=Path, help="含 stegpy 数据的宿主文件")
    stegpy_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    stegpy_extract_parser.add_argument("--password", help="加密载荷密码")
    stegpy_extract_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    stegpy_extract_parser.add_argument("--contains", help="字典模式可选：要求解出载荷包含该文本")
    stegpy_extract_parser.add_argument("--prefix", help="字典模式可选：要求解出载荷以该文本开头")
    stegpy_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    stegpy_brute_parser = stegpy_actions.add_parser("brute", help="用字典爆破 stegpy -p 密码")
    stegpy_brute_parser.add_argument("file", type=Path, help="含加密 stegpy 数据的宿主文件")
    stegpy_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密码字典，一行一个密码"
    )
    stegpy_brute_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出载荷文件"
    )
    stegpy_brute_parser.add_argument("--contains", help="可选：要求解出载荷包含该文本")
    stegpy_brute_parser.add_argument("--prefix", help="可选：要求解出载荷以该文本开头")
    stegpy_brute_parser.add_argument("--json", action="store_true", dest="as_json")

    steghide_parser = stego_commands.add_parser(
        "steghide", help="调用 steghide 提取 JPG/BMP/WAV/AU 隐写，支持空密码和字典"
    )
    steghide_actions = steghide_parser.add_subparsers(dest="steghide_action", required=True)
    steghide_extract_parser = steghide_actions.add_parser(
        "extract", help="调用 steghide extract 提取隐藏文件"
    )
    steghide_extract_parser.add_argument("file", type=Path, help="含 steghide 数据的宿主文件")
    steghide_extract_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    steghide_extract_parser.add_argument(
        "-p", "--password", default="", help="steghide passphrase；默认空密码"
    )
    steghide_extract_parser.add_argument("--wordlist", type=Path, help="密码字典，一行一个密码")
    steghide_extract_parser.add_argument("--contains", help="字典模式可选：要求输出包含该文本")
    steghide_extract_parser.add_argument("--prefix", help="字典模式可选：要求输出以该文本开头")
    steghide_extract_parser.add_argument(
        "--no-empty", action="store_true", help="字典模式不先尝试空密码"
    )
    steghide_extract_parser.add_argument("--steghide", type=Path, help="steghide 可执行文件路径")
    steghide_extract_parser.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="后端：auto 默认先用内置 JPEG/BMP/WAV/AU native，再回退 steghide 工具",
    )
    steghide_extract_parser.add_argument("--json", action="store_true", dest="as_json")

    steghide_brute_parser = steghide_actions.add_parser(
        "brute", help="用字典循环调用 steghide extract"
    )
    steghide_brute_parser.add_argument("file", type=Path, help="含 steghide 数据的宿主文件")
    steghide_brute_parser.add_argument(
        "--wordlist", type=Path, required=True, help="密码字典，一行一个密码"
    )
    steghide_brute_parser.add_argument(
        "-o", "--output", type=Path, required=True, help="输出隐藏文件"
    )
    steghide_brute_parser.add_argument("--contains", help="可选：要求输出包含该文本")
    steghide_brute_parser.add_argument("--prefix", help="可选：要求输出以该文本开头")
    steghide_brute_parser.add_argument("--no-empty", action="store_true", help="不先尝试空密码")
    steghide_brute_parser.add_argument("--steghide", type=Path, help="steghide 可执行文件路径")
    steghide_brute_parser.add_argument(
        "--backend",
        choices=("auto", "native", "tool"),
        default="auto",
        help="后端：auto 默认先用内置 JPEG/BMP/WAV/AU native，再回退 steghide 工具",
    )
    steghide_brute_parser.add_argument("--json", action="store_true", dest="as_json")


def _add_deepsound_command(
    subcommands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    deepsound_parser = subcommands.add_parser(
        "deepsound",
        aliases=["deep-sound"],
        help="DeepSound 2.x WAV DSCF 原生无密码隐写分析、提取与嵌入",
    )
    deepsound_actions = deepsound_parser.add_subparsers(dest="deepsound_action", required=True)

    analyze_parser = deepsound_actions.add_parser(
        "analyze",
        aliases=["analyse", "inspect", "scan"],
        help="扫描 WAV data chunk 中的 DeepSound DSCF 头",
    )
    analyze_parser.add_argument("file", type=Path, help="待检查 WAV 文件")
    analyze_parser.add_argument("-p", "--password", help="可选：校验加密头内 SHA1 密码摘要")
    analyze_parser.add_argument("--json", action="store_true", dest="as_json")

    extract_parser = deepsound_actions.add_parser(
        "extract", aliases=["decode", "reveal"], help="提取无密码 DeepSound 隐藏文件"
    )
    extract_parser.add_argument("file", type=Path, help="含 DeepSound 数据的 WAV 文件")
    extract_parser.add_argument("-o", "--output", type=Path, required=True, help="输出文件或目录")
    extract_parser.add_argument("-p", "--password", help="加密样本仅用于 SHA1 校验/提示")
    extract_parser.add_argument(
        "--raw", action="store_true", help="直接写出解码后的 DeepSound 字节流"
    )
    extract_parser.add_argument("--overwrite", action="store_true", help="覆盖已存在输出文件")
    extract_parser.add_argument("--json", action="store_true", dest="as_json")

    hide_parser = deepsound_actions.add_parser(
        "hide", aliases=["embed", "encode"], help="按 DeepSound DSCF 无密码格式嵌入文本或文件"
    )
    hide_parser.add_argument("file", type=Path, help="输入 WAV 载体")
    payload = hide_parser.add_mutually_exclusive_group(required=True)
    payload.add_argument("--payload", type=Path, action="append", help="待隐藏文件，可重复")
    payload.add_argument("--text", help="待隐藏 UTF-8 文本")
    hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出 WAV 文件")
    hide_parser.add_argument(
        "--text-name", default="message.txt", help="--text 在 DeepSound 中记录的文件名"
    )
    hide_parser.add_argument(
        "--quality",
        choices=("low", "normal", "high"),
        default="normal",
        help="DeepSound 质量/容量模式，默认 normal",
    )
    hide_parser.add_argument("--json", action="store_true", dest="as_json")


def _add_silenteye_command(
    subcommands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    silenteye_parser = subcommands.add_parser(
        "silenteye", aliases=["silent-eye"], help="SilentEye 源码兼容 BMP/WAV LSB 隐写提取与嵌入"
    )
    silenteye_actions = silenteye_parser.add_subparsers(dest="silenteye_action", required=True)

    extract_parser = silenteye_actions.add_parser(
        "extract", aliases=["decode", "reveal"], help="提取 SilentEye 隐藏消息或文件"
    )
    extract_parser.add_argument("file", type=Path, help="含 SilentEye 数据的 BMP/PNG/JPG/WAV")
    extract_parser.add_argument("-o", "--output", type=Path, required=True, help="输出载荷文件")
    _add_silenteye_common_options(extract_parser)
    extract_parser.add_argument(
        "--compressed",
        choices=("auto", "yes", "no"),
        default="auto",
        help="载荷是否 qCompress 压缩，默认自动",
    )
    extract_parser.add_argument(
        "--raw", action="store_true", help="只输出 SilentEye 内层原始字节，不解析格式/解密"
    )
    extract_parser.add_argument("--json", action="store_true", dest="as_json")

    hide_parser = silenteye_actions.add_parser(
        "hide", aliases=["embed", "encode"], help="按 SilentEye 源码格式嵌入文本或文件"
    )
    hide_parser.add_argument("file", type=Path, help="输入 BMP/PNG/JPG/WAV 载体")
    payload = hide_parser.add_mutually_exclusive_group(required=True)
    payload.add_argument("--text", help="要嵌入的 UTF-8 文本")
    payload.add_argument("--payload", type=Path, help="要嵌入的文件")
    hide_parser.add_argument("-o", "--output", type=Path, required=True, help="输出载体")
    _add_silenteye_common_options(hide_parser)
    hide_parser.add_argument(
        "--no-compress", action="store_true", help="不使用 SilentEye 默认 qCompress"
    )
    hide_parser.add_argument("--json", action="store_true", dest="as_json")


def _add_silenteye_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--carrier", choices=("auto", "bmp", "wav"), default="auto", help="载体类型，默认按扩展名"
    )
    parser.add_argument(
        "-p", "--password", help="启用 SilentEye AES 解密/加密；常见默认密钥为 silenteye"
    )
    parser.add_argument(
        "--crypto",
        choices=("aes128", "aes256"),
        default="aes256",
        help="SilentEye 加密模块，默认 AES256",
    )
    parser.add_argument("--bits", type=int, help="每个颜色/声道使用的低位数；默认 BMP/WAV 均为 3")
    parser.add_argument("--channels", type=int, help="WAV 使用的前 N 个声道；默认使用全部声道")
    parser.add_argument("--colors", default=None, help="BMP 使用颜色顺序，如 rgb/r/g/b；默认 rgb")
    parser.add_argument(
        "--distribution", choices=("inline", "equi"), help="数据分布方式；默认 equi"
    )
    parser.add_argument(
        "--header-position", help="BMP: top/bottom/signature；WAV: beginning/ending"
    )


def _add_watermark_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scheme",
        choices=("best", "high", "low", "pad", "partial"),
        default="best",
        help="转换方案，默认 best",
    )
    parser.add_argument("--json", action="store_true", dest="as_json", help="输出稳定 JSON")


def _add_puzzle_tile_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tile-size", type=int, help="单图输入的正方形块尺寸")
    parser.add_argument("--tile-width", type=int, help="单图输入的块宽")
    parser.add_argument("--tile-height", type=int, help="单图输入的块高")


def _add_dual_watermark_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed", type=int, help="覆盖默认置乱种子")
    parser.add_argument("--alpha", type=float, help="覆盖默认频域强度")
    parser.add_argument("--json", action="store_true", dest="as_json", help="输出稳定 JSON")


def _add_ww23_options(parser: argparse.ArgumentParser, *, include_alpha: bool) -> None:
    if include_alpha:
        parser.add_argument("--alpha", type=float, help="覆盖默认嵌入强度")
    parser.add_argument("--json", action="store_true", dest="as_json", help="输出稳定 JSON")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "zip":
        try:
            if args.zip_command in {"crack", "brute"}:
                result = crack_archive_password(
                    args.file,
                    args.output,
                    wordlist=args.wordlist,
                    charset=args.charset,
                    chars=args.chars,
                    min_length=args.min_length,
                    max_length=args.max_length,
                    prefix=args.prefix,
                    suffix=args.suffix,
                    encoding=args.encoding,
                    backend=args.backend,
                    workers=args.workers,
                    chunk_size=args.chunk_size,
                    max_attempts=args.max_attempts,
                    verify=not args.no_verify,
                    sevenzip=args.sevenzip,
                )
            elif args.zip_command in {"nested", "unpack", "unroll"}:
                result = unpack_nested_archives(
                    args.file,
                    args.output,
                    max_depth=args.max_depth,
                    max_files=args.max_files,
                    max_output_bytes=args.max_output_bytes,
                    password=args.password,
                    sevenzip=args.sevenzip,
                    flatten_single=args.flatten_single,
                )
            elif args.zip_command in {"plaintext", "known-plaintext", "bkcrack"}:
                if args.plaintext_action in {"presets", "list-presets"}:
                    result = list_plaintext_presets()
                elif args.plaintext_action == "preset":
                    result = known_plaintext_preset_attack(
                        args.file,
                        args.preset,
                        cipher_entry=args.entry,
                        inner_name=args.inner_name,
                        plain_file=args.plain_file,
                        plain_text=args.plain_text,
                        plain_hex=args.plain_hex,
                        preset_file=args.preset_file,
                        output=args.output,
                        new_password=args.new_password,
                        offset=args.offset,
                        extra=args.extra,
                        extra_text=args.extra_text,
                        extra_hex=args.extra_hex,
                        truncate=args.truncate,
                        decrypt=args.decrypt,
                        keep_header=args.keep_header,
                        ignore_check_byte=args.ignore_check_byte,
                        jobs=args.jobs,
                        bkcrack=args.bkcrack,
                        encoding=args.encoding,
                    )
                elif args.plaintext_action == "attack":
                    result = known_plaintext_attack(
                        args.file,
                        cipher_entry=args.entry,
                        plain_file=args.plain_file,
                        plain_zip=args.plain_zip,
                        plain_entry=args.plain_entry,
                        output=args.output,
                        new_password=args.new_password,
                        offset=args.offset,
                        extra=args.extra,
                        truncate=args.truncate,
                        decrypt=args.decrypt,
                        keep_header=args.keep_header,
                        ignore_check_byte=args.ignore_check_byte,
                        jobs=args.jobs,
                        bkcrack=args.bkcrack,
                    )
                elif args.plaintext_action == "keys":
                    result = known_plaintext_attack(
                        args.file,
                        keys=tuple(args.keys),
                        output=args.output,
                        new_password=args.new_password,
                        decrypt=args.decrypt,
                        bkcrack=args.bkcrack,
                    )
                else:
                    result = recover_password_from_keys(
                        args.file,
                        tuple(args.keys),
                        charset=args.charset,
                        length=args.length,
                        mask=args.mask,
                        jobs=args.jobs,
                        bkcrack=args.bkcrack,
                    )
            elif args.zip_command in {"invisible-password", "invisible", "invis-pass"}:
                result = crack_invisible_archive_password(
                    args.file,
                    args.output,
                    password_b64=args.password_b64,
                    b64_file=args.b64_file,
                    password_text=args.password_text,
                    text_file=args.text_file,
                    brute_raw=args.brute_raw,
                    min_bytes=args.min_bytes,
                    max_bytes=args.max_bytes,
                    zero_width=args.zero_width,
                    min_chars=args.min_chars,
                    max_chars=args.max_chars,
                    zero_width_chars=args.zero_width_chars,
                    encoding=args.encoding,
                    backend=args.backend,
                    workers=args.workers,
                    chunk_size=args.chunk_size,
                    max_attempts=args.max_attempts,
                    verify=not args.no_verify,
                    sevenzip=args.sevenzip,
                )
            elif args.zip_command in {
                "timestamp",
                "time-stego",
                "time",
            } and args.timestamp_action in {
                "list",
                "scan",
            }:
                result = list_archive_timestamps(
                    args.file,
                    source=args.source,
                    field=args.field,
                    sort=args.sort,
                    include=args.include,
                    glob=args.glob,
                    base=args.base,
                    offset=args.offset,
                    scale=args.scale,
                    timezone=args.timezone,
                )
            elif args.zip_command in {
                "timestamp",
                "time-stego",
                "time",
            } and args.timestamp_action in {
                "extract",
                "decode",
            }:
                result = extract_timestamp_payload(
                    args.file,
                    args.output,
                    source=args.source,
                    field=args.field,
                    sort=args.sort,
                    include=args.include,
                    glob=args.glob,
                    base=args.base,
                    offset=args.offset,
                    scale=args.scale,
                    timezone=args.timezone,
                )
            elif args.zip_command in {"timestamp", "time-stego", "time"}:
                result = embed_zip_timestamps(
                    args.file,
                    args.output,
                    payload_path=args.payload,
                    text=args.text,
                    base=args.base,
                    offset=args.offset,
                    scale=args.scale,
                    sort=args.sort,
                    include=args.include,
                    glob=args.glob,
                    timezone=args.timezone,
                )
            elif args.zip_command in {"ntfs-stream", "ads", "rar-ads"} and args.ntfs_action in {
                "list",
                "scan",
            }:
                result = list_rar_ntfs_streams(
                    args.file,
                    include=args.include,
                    glob=args.glob,
                    verify_crc=not args.no_crc,
                )
            elif args.zip_command in {"ntfs-stream", "ads", "rar-ads"}:
                result = extract_rar_ntfs_streams(
                    args.file,
                    args.output,
                    include=args.include,
                    glob=args.glob,
                    overwrite=args.overwrite,
                    manifest=not args.no_manifest,
                    verify_crc=not args.no_crc,
                )
            elif args.zip_command == "crc" and args.crc_action in {"list", "info"}:
                result = list_zip_crc(args.file)
            elif args.zip_command == "crc" and args.crc_action in {"brute", "recover"}:
                result = brute_zip_crc(
                    args.file,
                    args.output,
                    entry=args.entry,
                    charset=args.charset,
                    chars=args.chars,
                    prefix=args.prefix,
                    suffix=args.suffix,
                    prefix_hex=args.prefix_hex,
                    suffix_hex=args.suffix_hex,
                    limit=args.limit,
                    max_prefixes=args.max_prefixes,
                )
            else:
                result = reverse_crc32_direct(
                    parse_crc32(args.crc),
                    args.length,
                    args.output,
                    charset=args.charset,
                    chars=args.chars,
                    prefix=args.prefix,
                    suffix=args.suffix,
                    prefix_hex=args.prefix_hex,
                    suffix_hex=args.suffix_hex,
                    limit=args.limit,
                    max_prefixes=args.max_prefixes,
                )
        except (FileNotFoundError, OSError, ValueError) as error:
            if args.as_json:
                print(
                    json.dumps(
                        {
                            "status": "failed",
                            "operation": f"zip.{args.zip_command}",
                            "error": str(error),
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(f"[error] {error}", file=sys.stderr)
            return 2
        if args.as_json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print("状态：success")
            print(f"操作：{result.operation}")
            if hasattr(result, "found_password"):
                print(f"后端：{result.backend}")
                if result.entry != "-":
                    print(f"条目：{result.entry}")
                print(f"尝试：{result.attempts}")
                print(f"速度：{result.rate_per_second}/s")
                print(f"校验：{result.verified}")
                print(f"命中密码：{result.found_password if result.found_password else '<未命中>'}")
                if result.output_paths:
                    print("输出：" + ", ".join(result.output_paths[:5]))
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
            elif getattr(result, "operation", "") == "zip.plaintext.presets":
                print(f"预设数量：{result.count}")
                for preset in result.presets:
                    print(
                        f"{preset['name']}: offset={preset['default_offset']} "
                        f"plain={preset['plain_hex']} extra={preset['extra']}"
                    )
            elif getattr(result, "operation", "").startswith("zip.plaintext"):
                print(f"模式：{result.mode}")
                print(f"工具：{result.tool_path}")
                if getattr(result, "preset", ""):
                    print(f"预设：{result.preset}")
                    print(f"预设明文hex：{result.generated_plaintext_hex}")
                    if result.extra_plaintexts:
                        print("附加明文：" + ", ".join(result.extra_plaintexts))
                if result.keys:
                    print("Keys：" + " ".join(result.keys))
                if result.new_password:
                    print(f"密码：{result.new_password}")
                if result.output_paths:
                    print("输出：" + ", ".join(result.output_paths[:5]))
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
            elif hasattr(result, "archives_processed"):
                print(f"输出：{result.output_path}")
                print(f"已解压压缩包：{result.archives_processed}")
                print(f"层数：{result.layers}")
                print(f"最终文件：{len(result.final_files)}")
                print(f"写出：{result.total_written_bytes} bytes")
                if result.final_files:
                    print("文件：" + ", ".join(result.final_files[:5]))
                if result.skipped_archives:
                    print("跳过：" + ", ".join(result.skipped_archives[:5]))
            elif getattr(result, "operation", "").startswith("zip.timestamp"):
                print(f"来源：{result.source}")
                print(f"字段：{result.field}")
                print(f"排序：{result.sort}")
                print(f"条目：{result.entries_count}")
                if result.base is not None:
                    print(f"基准：{result.base}")
                    print(f"偏移：{result.offset}")
                    print(f"倍数：{result.scale}")
                if result.output_paths:
                    print("输出：" + ", ".join(result.output_paths[:5]))
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                    print(f"文本预览：{result.decoded_text[:80]}")
                if result.timestamp_entries:
                    for entry in result.timestamp_entries[:10]:
                        decoded = (
                            f" decoded={entry['decoded_value']!r} char={entry['decoded_char']!r}"
                            if entry.get("decoded_value") is not None
                            else ""
                        )
                        print(
                            f"{entry['name']} mtime={entry['modified_unix']} "
                            f"mtime_iso={entry['modified_iso']}{decoded}"
                        )
            elif getattr(result, "operation", "").startswith("zip.ntfs-stream"):
                print(f"格式：{result.format}")
                print(f"后端：{result.backend}")
                print(f"数据流：{result.streams_count}")
                if result.output_path != "-":
                    print(f"输出：{result.output_path}")
                if result.manifest_path:
                    print(f"清单：{result.manifest_path}")
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
                for stream in result.streams[:10]:
                    print(
                        f"{stream['stream_path']} size={stream['unpacked_size']} "
                        f"method={stream['method']} crc_ok={stream['crc_ok']} "
                        f"status={stream['status']}"
                    )
                    if stream.get("output_path"):
                        print(f"  -> {stream['output_path']}")
            elif result.entries is not None:
                for entry in result.entries:
                    print(
                        f"{entry['filename']} crc={entry['crc32']} size={entry['file_size']} "
                        f"compressed={entry['compress_size']} encrypted={entry['encrypted']}"
                    )
            else:
                print(f"CRC32：{result.crc32}")
                print(f"长度：{result.length}")
                if result.entry != "-":
                    print(f"条目：{result.entry}")
                print(f"字符集：{result.charset} ({result.charset_size})")
                if result.prefix_hex:
                    print(f"前缀hex：{result.prefix_hex}")
                if result.suffix_hex:
                    print(f"后缀hex：{result.suffix_hex}")
                print(f"枚举前缀：{result.attempts}")
                print(f"候选：{result.candidates}" + ("（已截断）" if result.truncated else ""))
                if result.candidate_text:
                    print("预览：" + ", ".join(result.candidate_text[:5]))
                if result.output_paths:
                    print("输出：" + ", ".join(result.output_paths[:5]))
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
        return 0

    if args.command == "audio":
        try:
            if args.audio_command == "lyra" and args.lyra_action in {"inspect", "info"}:
                result = inspect_lyra(args.file, bitrate=args.bitrate)
            elif args.audio_command == "lyra" and args.lyra_action in {"decode", "decompress"}:
                result = decode_lyra(
                    args.file,
                    args.output,
                    bitrate=args.bitrate,
                    sample_rate=args.sample_rate,
                    decoder=args.decoder,
                    model_path=args.model_path,
                    randomize_num_samples=args.randomize_num_samples,
                    packet_loss_rate=args.packet_loss_rate,
                    average_burst_length=args.average_burst_length,
                    fixed_packet_loss_pattern=args.fixed_packet_loss_pattern,
                )
            elif args.audio_command == "lyra":
                result = encode_lyra(
                    args.file,
                    args.output,
                    bitrate=args.bitrate,
                    encoder=args.encoder,
                    model_path=args.model_path,
                    enable_preprocessing=args.enable_preprocessing,
                    enable_dtx=args.enable_dtx,
                )
            elif args.audio_command in {"mp3stego", "mp3-stego"} and args.mp3stego_action in {
                "inspect",
                "info",
            }:
                result = inspect_mp3stego(
                    args.file,
                    password=args.password,
                    length_size=args.length_size,
                    max_payload_bytes=args.max_payload_bytes,
                )
            elif args.audio_command in {"mp3stego", "mp3-stego"} and args.mp3stego_action in {
                "extract",
                "decode",
            }:
                result = extract_mp3stego(
                    args.file,
                    args.output,
                    password=args.password,
                    length_size=args.length_size,
                    raw=args.raw,
                    max_payload_bytes=args.max_payload_bytes,
                )
            elif (
                args.audio_command in {"mp3stego", "mp3-stego"} and args.mp3stego_action == "brute"
            ):
                result = brute_mp3stego(
                    args.file,
                    args.wordlist,
                    args.output,
                    length_size=args.length_size,
                    include_default=not args.no_empty,
                    contains=args.contains.encode() if args.contains is not None else None,
                    prefix=args.prefix.encode() if args.prefix is not None else None,
                    max_payload_bytes=args.max_payload_bytes,
                    encoding=args.encoding,
                )
            elif args.audio_command in {"mp3stego", "mp3-stego"}:
                result = encode_mp3stego(
                    args.file,
                    args.output,
                    payload_path=args.payload,
                    password=args.password,
                    encoder=args.encoder,
                )
            elif args.audio_command in {
                "sstv",
                "slow-scan-tv",
                "slow-scan",
            } and args.sstv_action in {
                "decode",
                "extract",
            }:
                result = decode_sstv(
                    args.file,
                    args.output,
                    mode=args.mode,
                    skip=args.skip,
                    reverse_audio=args.reverse_audio,
                    invert_image=args.invert_image,
                    max_lines=args.max_lines,
                )
            elif args.audio_command in {"ham", "radio", "aprs", "afsk"} and args.ham_action in {
                "inspect",
                "scan",
                "info",
            }:
                result = inspect_ham_radio(
                    args.file,
                    mode=args.mode,
                    reverse_audio=args.reverse_audio,
                    invert_audio=args.invert_audio,
                    max_seconds=args.max_seconds,
                )
            elif args.audio_command in {"ham", "radio", "aprs", "afsk"} and args.ham_action in {
                "decode",
                "extract",
            }:
                result = decode_ham_radio(
                    args.file,
                    args.output,
                    mode=args.mode,
                    backend=args.backend,
                    reverse_audio=args.reverse_audio,
                    invert_audio=args.invert_audio,
                    max_seconds=args.max_seconds,
                    raw_output=args.raw_output,
                    multimon=args.multimon,
                )
            elif args.audio_command in {"ham", "radio", "aprs", "afsk"}:
                result = encode_ax25_afsk1200_wav(
                    args.output,
                    source=args.source,
                    destination=args.destination,
                    info=args.text,
                    path=args.path,
                    sample_rate=args.sample_rate,
                )
            elif args.audio_command in {"midi-qr", "midiqr", "midi-qrcode", "midi-to-qr"}:
                result = render_midi_qr(
                    args.file,
                    args.output,
                    source=args.source,
                    row_gap_seconds=args.row_gap,
                    cell_size=args.cell_size,
                    invert=args.invert,
                    midi_output_path=args.midi_output,
                    ppq=args.ppq,
                    bpm=args.bpm,
                    min_duration_ms=args.min_duration_ms,
                )
            elif args.audio_command in {
                "wavdata",
                "wav-data",
                "wavraw",
            } and args.wavdata_action in {
                "info",
                "inspect",
            }:
                result = info_wavdata(args.file)
            elif (
                args.audio_command in {"wavdata", "wav-data", "wavraw"}
                and args.wavdata_action == "lsb"
            ):
                result = extract_wav_lsb(
                    args.file,
                    args.output,
                    bit=args.bit,
                    bits=_parse_nonnegative_int_csv(args.bits) if args.bits else None,
                    channel=args.channel,
                    sample_step=args.sample_step,
                    byte_order=args.order,
                    output_format=args.output_format,
                    limit_bits=args.limit_bits,
                )
            elif args.audio_command in {
                "wavdata",
                "wav-data",
                "wavraw",
            } and args.wavdata_action in {
                "channel-diff",
                "diff",
            }:
                result = extract_channel_diff(
                    args.file,
                    args.output,
                    mapping=_parse_key_value_map(args.maps),
                    left_channel=args.left_channel,
                    right_channel=args.right_channel,
                    byte_order=args.order,
                    output_format=args.output_format,
                )
            elif args.audio_command in {
                "wavdata",
                "wav-data",
                "wavraw",
            } and args.wavdata_action in {
                "fft-map",
                "freq-index",
            }:
                result = fft_map_wavdata(
                    args.file,
                    args.output,
                    freqs=_parse_float_csv(args.freqs),
                    alphabet=args.alphabet,
                    chunk_ms=args.chunk_ms,
                    group_size=args.group_size,
                    threshold=args.threshold,
                    channel=args.channel,
                )
            elif args.audio_command in {
                "wavdata",
                "wav-data",
                "wavraw",
            } and args.wavdata_action in {
                "compare",
                "float-diff",
            }:
                result = compare_wavdata(
                    args.first,
                    args.second,
                    args.output,
                    scale=args.scale,
                    mapping=_parse_key_value_map(args.maps),
                    channel=args.channel,
                    samples=args.samples,
                    byte_order=args.order,
                    output_format=args.output_format,
                )
            elif args.audio_command in {
                "wavdata",
                "wav-data",
                "wavraw",
            } and args.wavdata_action in {
                "to-image",
                "image",
            }:
                result = wavdata_to_image(
                    args.file,
                    args.output,
                    width=args.width,
                    height=args.height,
                    stride=args.stride,
                    offset=args.offset,
                    mode=args.mode,
                )
            elif args.audio_command in {"wavdata", "wav-data", "wavraw"}:
                result = freq_chars_wavdata(
                    args.file,
                    args.output,
                    freq_map=_parse_float_value_map(args.maps) if args.maps else None,
                    chunk_ms=args.chunk_ms,
                    tolerance=args.tolerance,
                    dedupe=not args.no_dedupe,
                    channel=args.channel,
                )
            elif args.audio_command in {"velato", "midi-velato"} and args.velato_action in {
                "inspect",
                "info",
            }:
                result = inspect_velato(args.file)
            elif args.audio_command in {"velato", "midi-velato"} and args.velato_action in {
                "decode",
                "extract",
            }:
                result = decode_velato(args.file, args.output)
            elif args.audio_command in {"velato", "midi-velato"}:
                result = encode_velato_text(
                    args.output,
                    args.text,
                    root_note=args.root_note,
                    velocity=args.velocity,
                    duration=args.duration,
                    separator=not args.no_separator,
                )
            elif args.audio_command in {
                "mp3-field",
                "mp3-frame-field",
                "mp3-header",
            } and args.mp3_field_action in {"extract", "decode"}:
                result = extract_mp3_frame_field(
                    args.file,
                    args.output,
                    field=args.field,
                    start=args.start,
                    end=args.end,
                    order=args.order,
                    limit_bits=args.limit_bits,
                    output_format=args.output_format,
                    base_frame_size=args.base_frame_size,
                )
            elif args.audio_command in {"mp3-field", "mp3-frame-field", "mp3-header"}:
                result = scan_mp3_frame_fields(
                    args.file,
                    args.output,
                    fields=_parse_choice_list(args.fields, MP3_FIELD_CHOICES, "fields"),
                    start=args.start,
                    end=args.end,
                    orders=_parse_orders(args.orders),
                    limit_bits=args.limit_bits,
                    base_frame_size=args.base_frame_size,
                    write_all=args.write_all,
                )
            else:
                result = inspect_sstv(
                    args.file,
                    mode=args.mode,
                    skip=args.skip,
                    reverse_audio=args.reverse_audio,
                )
        except (FileNotFoundError, EOFError, OSError, ValueError) as error:
            if args.as_json:
                print(
                    json.dumps(
                        {
                            "status": "failed",
                            "operation": f"audio.{args.audio_command}",
                            "error": str(error),
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(f"[error] {error}", file=sys.stderr)
            return 2
        if args.as_json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print("状态：success")
            print(f"操作：{result.operation}")
            if getattr(result, "operation", "").startswith("audio.midi-qr"):
                print(f"来源：{result.source}")
                print(f"行数：{result.rows}")
                print(f"列数：{result.columns}")
                print(f"音符数：{result.note_count}")
                print(f"NOTE ON：{result.note_on_count}")
                print(f"事件数：{result.event_count}")
                print(f"格子：{result.cell_size}px")
                if result.midi_output_path:
                    print(f"MIDI：{result.midi_output_path}")
                    print(f"MIDI写出：{result.midi_written_bytes} bytes")
            elif getattr(result, "operation", "").startswith("audio.wavdata"):
                print(f"模式：{result.mode}")
                print(f"采样率：{result.sample_rate} Hz")
                print(f"声道：{result.channels}")
                print(f"采样位宽：{result.bits_per_sample}")
                print(f"帧数：{result.frames}")
                print(f"时长：{result.duration_seconds:.3f}s")
                if result.width and result.height:
                    print(f"尺寸：{result.width} × {result.height}")
                if result.bit_count:
                    print(f"bit数：{result.bit_count}")
                if result.byte_count:
                    print(f"字节数：{result.byte_count}")
                if result.decoded_text:
                    print(f"文本预览：{result.decoded_text[:120]}")
                for finding in result.findings[:10]:
                    text = f" text={finding.get('text')}" if finding.get("text") else ""
                    print(
                        f"命中：offset={finding.get('offset', finding.get('index', 0))} kind={finding['kind']}{text}"
                    )
            elif getattr(result, "operation", "").startswith("audio.velato"):
                print(f"模式：{result.mode}")
                if result.root_note is not None:
                    print(f"根音：{result.root_name} ({result.root_note})")
                print(f"MIDI格式：{result.format}")
                print(f"轨道：{result.tracks}")
                if result.ticks_per_quarter is not None:
                    print(f"TPQ：{result.ticks_per_quarter}")
                print(f"音符：{result.note_count}")
                print(f"命令：{result.command_count}")
                if result.printed_text:
                    print(f"打印文本：{result.printed_text[:120]}")
                if result.output_paths:
                    print("输出：" + ", ".join(result.output_paths[:5]))
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
                for finding in result.findings[:10]:
                    text = f" text={finding.get('text')}" if finding.get("text") else ""
                    print(f"命中：offset={finding.get('offset', 0)} kind={finding['kind']}{text}")
            elif getattr(result, "operation", "").startswith("audio.mp3-field"):
                if result.field:
                    print(f"字段：{result.field}")
                else:
                    print("字段：" + ", ".join(result.fields))
                if result.order:
                    print(f"位序：{result.order}")
                else:
                    print("位序：" + ", ".join(result.orders))
                print(f"范围：0x{result.start:x}..0x{result.end:x}")
                print(f"帧数：{result.frame_count}")
                print(f"bit数：{result.bit_count}")
                print(f"解析帧头：{result.parsed_frames}")
                if result.base_frame_size is not None:
                    print(f"基础帧长：{result.base_frame_size}+padding")
                print(f"输出格式：{result.output_format}")
                print(f"写出：{result.written_bytes} bytes")
                if result.output_paths:
                    print("输出：" + ", ".join(result.output_paths[:5]))
                for finding in result.findings[:10]:
                    extra = (
                        f" -> {finding.get('output_path')}" if finding.get("output_path") else ""
                    )
                    text = f" text={finding.get('text')}" if finding.get("text") else ""
                    field = finding.get("field", result.field)
                    order = finding.get("order", result.order)
                    print(
                        f"命中：field={field} order={order} offset={finding['offset']} kind={finding['kind']}{text}{extra}"
                    )
            elif getattr(result, "operation", "").startswith("audio.mp3stego"):
                print(f"模式：{result.mode}")
                print(f"帧数：{result.frames}")
                print(f"候选位：{result.candidate_bits}")
                print(f"选定位：{result.selected_bits}")
                if result.embedded_bytes:
                    print(f"嵌入密文：{result.embedded_bytes} bytes")
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                if result.raw_bytes:
                    print(f"原始载荷：{result.raw_bytes} bytes")
                print(f"长度头：{result.length_size} bytes")
                if result.password_used:
                    print("密码：yes")
                if result.found_password is not None:
                    print(f"命中密码：{result.found_password!r}")
                if result.attempts:
                    print(f"尝试：{result.attempts}")
                if result.executable:
                    print(f"工具：{result.executable}")
                if result.frame_entries:
                    for frame in result.frame_entries[:5]:
                        print(
                            f"frame#{frame['index']} off=0x{frame['offset']:x} "
                            f"ver={frame['version']} {frame['bitrate_kbps']}kbps "
                            f"{frame['sample_rate']}Hz bits={''.join(str(bit) for bit in frame['hidden_bits'])}"
                        )
            elif getattr(result, "operation", "").startswith("audio.lyra"):
                print(f"模式：{result.mode}")
                if result.bitrate is not None:
                    print(f"码率：{result.bitrate}")
                if result.sample_rate is not None:
                    print(f"采样率：{result.sample_rate} Hz")
                if result.packet_size is not None:
                    print(f"包大小：{result.packet_size} bytes")
                if result.packet_count is not None:
                    print(f"包数：{result.packet_count}")
                if result.trailing_bytes:
                    print(f"尾部余数：{result.trailing_bytes} bytes")
                if result.duration_seconds is not None:
                    print(f"估计时长：{result.duration_seconds:.3f}s")
                if result.executable:
                    print(f"工具：{result.executable}")
                if result.candidates:
                    for candidate in result.candidates:
                        suffix = " exact" if candidate["exact"] else ""
                        print(
                            f"{candidate['bitrate']}bps packet={candidate['packet_size']} "
                            f"count={candidate['packet_count']} "
                            f"tail={candidate['trailing_bytes']}{suffix}"
                        )
            else:
                print(f"模式：{result.mode}")
                print(f"VIS：{result.vis_code if result.vis_code is not None else '<forced>'}")
                print(f"采样率：{result.sample_rate} Hz")
                print(f"声道：{result.channels}")
                print(f"时长：{result.duration_seconds:.3f}s")
                print(f"尺寸：{result.width} × {result.height}")
                if result.decoded_lines:
                    print(f"解码行：{result.decoded_lines}")
                if result.reverse_audio:
                    print("音频反转：yes")
                if result.invert_image:
                    print("图像反相：yes")
            if result.output_path != "-":
                print(f"输出：{result.output_path}")
            if result.written_bytes:
                print(f"写出：{result.written_bytes} bytes")
        return 0

    if args.command in {"image", "stego"} and args.image_command != "watermark":
        try:
            if args.image_command == "split" and args.split_mode == "frames":
                result = split_frames(args.file, args.output, prefix=args.prefix)
            elif args.image_command == "split":
                result = split_grid(
                    args.file,
                    args.output,
                    columns=args.columns,
                    rows=args.rows,
                    prefix=args.prefix,
                )
            elif args.image_command == "join":
                result = join_images(
                    args.files,
                    args.output,
                    columns=args.columns,
                    gap=args.gap,
                    background=args.background,
                )
            elif args.image_command == "spacefill":
                result = transform_spacefill_image(
                    args.file,
                    args.output,
                    curve=args.curve,
                    action=args.spacefill_action,
                    order=args.order,
                    flip_y=not args.no_flip_y,
                    reverse=args.reverse,
                )
            elif (
                args.image_command in {"backpaper", "paperbak"}
                and args.backpaper_action == "encode"
            ):
                result = encode_backpaper(
                    args.file,
                    args.output,
                    compress=not args.no_compress,
                    password=args.password,
                    redundancy=args.redundancy,
                    columns=args.columns,
                    rows=args.rows,
                    dot_step=args.dot_step,
                    dot_percent=args.dot_percent,
                    border=args.border,
                )
            elif args.image_command in {"backpaper", "paperbak"}:
                result = decode_backpaper(
                    args.files,
                    args.output,
                    password=args.password,
                    threshold=args.threshold,
                )
            elif args.image_command in {"npiet", "piet"}:
                input_data = (
                    args.input_file.read_text(encoding="utf-8")
                    if args.input_file is not None
                    else args.input
                )
                result = run_piet(
                    args.file,
                    input_data=input_data,
                    codel_size=args.codel_size,
                    max_steps=args.max_steps,
                    unknown=args.unknown,
                    trace=args.trace,
                    trace_limit=args.trace_limit,
                    trace_image_path=args.trace_image,
                )
            elif args.image_command == "arnold" and args.arnold_action in {"encode", "decode"}:
                result = arnold_transform_image(
                    args.file,
                    args.output,
                    action=args.arnold_action,
                    rounds=args.rounds,
                    a=args.a,
                    b=args.b,
                )
            elif args.image_command == "arnold":
                result = brute_arnold_images(
                    args.file,
                    args.output,
                    rounds_range=_parse_range(args.rounds, "轮数范围"),
                    a_range=_parse_range(args.a, "a 范围"),
                    b_range=_parse_range(args.b, "b 范围"),
                    action=args.mode,
                )
            elif args.image_command == "combine":
                result = combine_images(
                    args.first,
                    args.second,
                    args.output,
                    operation=args.operation,
                )
            elif args.image_command == "stereogram":
                result = solve_stereogram(
                    args.file,
                    args.output,
                    offset=args.offset,
                    offset_start=args.start,
                    offset_stop=args.stop,
                    invert=args.invert,
                    manifest_path=args.manifest,
                )
            elif args.image_command == "acropalypse":
                result = restore_acropalypse_png(
                    args.file,
                    args.output,
                    width=args.width,
                    height=args.height,
                    mode=args.mode,
                )
            elif args.image_command == "cloacked-pixel" and args.cloacked_action == "hide":
                result = hide_cloacked_pixel(
                    args.file,
                    args.payload,
                    args.output,
                    password=args.password,
                )
            elif args.image_command == "cloacked-pixel" and args.cloacked_action == "extract":
                if args.wordlist is not None:
                    result = brute_cloacked_pixel(
                        args.file,
                        args.wordlist,
                        args.output,
                        keep_padding=args.keep_padding,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                    )
                else:
                    if args.password is None:
                        raise ValueError("cloacked-pixel extract 需要 --password 或 --wordlist")
                    result = extract_cloacked_pixel(
                        args.file,
                        args.output,
                        password=args.password,
                        keep_padding=args.keep_padding,
                    )
            elif args.image_command == "cloacked-pixel" and args.cloacked_action == "brute":
                result = brute_cloacked_pixel(
                    args.file,
                    args.wordlist,
                    args.output,
                    keep_padding=args.keep_padding,
                    contains=args.contains.encode() if args.contains is not None else None,
                    prefix=args.prefix.encode() if args.prefix is not None else None,
                )
            elif args.image_command == "cloacked-pixel":
                result = analyse_cloacked_pixel(
                    args.file,
                    block_size=args.block_size,
                    threshold=args.threshold,
                )
            elif args.image_command in {"oursecret", "our-secret"} and args.oursecret_action in {
                "inspect",
                "scan",
            }:
                result = inspect_oursecret(args.file, mode=args.mode)
            elif args.image_command in {"oursecret", "our-secret"} and args.oursecret_action in {
                "extract",
                "reveal",
            }:
                result = extract_oursecret(
                    args.file,
                    args.output,
                    password=args.password,
                    mode=args.mode,
                    overwrite=args.overwrite,
                )
            elif args.image_command in {"oursecret", "our-secret"}:
                result = hide_oursecret(
                    args.file,
                    args.output,
                    payload_paths=args.payload,
                    text=args.text,
                    text_name=args.text_name,
                    password=args.password,
                    mode="lsb" if args.lsb else args.mode,
                )
            elif args.image_command in {"deepsound", "deep-sound"} and args.deepsound_action in {
                "analyze",
                "analyse",
                "inspect",
                "scan",
            }:
                result = analyze_deepsound(args.file, password=args.password)
            elif args.image_command in {"deepsound", "deep-sound"} and args.deepsound_action in {
                "extract",
                "decode",
                "reveal",
            }:
                result = extract_deepsound(
                    args.file,
                    args.output,
                    password=args.password,
                    raw=args.raw,
                    overwrite=args.overwrite,
                )
            elif args.image_command in {"deepsound", "deep-sound"}:
                result = hide_deepsound(
                    args.file,
                    args.output,
                    payload_paths=args.payload,
                    text=args.text,
                    text_name=args.text_name,
                    quality=args.quality,
                )
            elif args.image_command in {"silenteye", "silent-eye"} and args.silenteye_action in {
                "extract",
                "decode",
                "reveal",
            }:
                result = extract_silenteye(
                    args.file,
                    args.output,
                    carrier=args.carrier,
                    password=args.password,
                    crypto=args.crypto,
                    compressed=args.compressed,
                    bits=args.bits,
                    channels=args.channels,
                    colors=args.colors,
                    distribution=args.distribution,
                    header_position=args.header_position,
                    raw=args.raw,
                )
            elif args.image_command in {"silenteye", "silent-eye"}:
                result = hide_silenteye(
                    args.file,
                    args.output,
                    text=args.text,
                    payload_path=args.payload,
                    carrier=args.carrier,
                    password=args.password,
                    crypto=args.crypto,
                    compress=not args.no_compress,
                    bits=args.bits,
                    channels=args.channels,
                    colors=args.colors,
                    distribution=args.distribution,
                    header_position=args.header_position,
                )
            elif args.image_command == "stegpy" and args.stegpy_action == "hide":
                result = hide_stegpy(
                    args.file,
                    args.output,
                    text=args.text,
                    payload_path=args.payload,
                    password=args.password,
                    bits=args.bits,
                )
            elif args.image_command == "stegpy" and args.stegpy_action == "extract":
                if args.wordlist is not None:
                    result = brute_stegpy(
                        args.file,
                        args.wordlist,
                        args.output,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                    )
                else:
                    result = extract_stegpy(args.file, args.output, password=args.password)
            elif args.image_command == "stegpy":
                result = brute_stegpy(
                    args.file,
                    args.wordlist,
                    args.output,
                    contains=args.contains.encode() if args.contains is not None else None,
                    prefix=args.prefix.encode() if args.prefix is not None else None,
                )
            elif args.image_command == "steghide" and args.steghide_action == "extract":
                if args.wordlist is not None:
                    result = brute_steghide(
                        args.file,
                        args.wordlist,
                        args.output,
                        steghide_path=args.steghide,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                        include_empty=not args.no_empty,
                        backend=args.backend,
                    )
                else:
                    result = extract_steghide(
                        args.file,
                        args.output,
                        password=args.password,
                        steghide_path=args.steghide,
                        backend=args.backend,
                    )
            elif args.image_command == "steghide":
                result = brute_steghide(
                    args.file,
                    args.wordlist,
                    args.output,
                    steghide_path=args.steghide,
                    contains=args.contains.encode() if args.contains is not None else None,
                    prefix=args.prefix.encode() if args.prefix is not None else None,
                    include_empty=not args.no_empty,
                    backend=args.backend,
                )
            elif args.image_command == "outguess" and args.outguess_action == "extract":
                if args.wordlist is not None:
                    result = brute_outguess(
                        args.file,
                        args.wordlist,
                        args.output,
                        outguess_path=args.outguess,
                        backend=args.backend,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                        include_empty=not args.no_empty,
                    )
                else:
                    result = extract_outguess(
                        args.file,
                        args.output,
                        key=args.key,
                        outguess_path=args.outguess,
                        backend=args.backend,
                    )
            elif args.image_command == "outguess" and args.outguess_action == "brute":
                result = brute_outguess(
                    args.file,
                    args.wordlist,
                    args.output,
                    outguess_path=args.outguess,
                    backend=args.backend,
                    contains=args.contains.encode() if args.contains is not None else None,
                    prefix=args.prefix.encode() if args.prefix is not None else None,
                    include_empty=not args.no_empty,
                )
            elif args.image_command == "outguess":
                result = hide_outguess(
                    args.file,
                    args.output,
                    args.payload,
                    key=args.key,
                    outguess_path=args.outguess,
                    backend=args.backend,
                )
            elif args.image_command == "jsteg" and args.jsteg_action in {"reveal", "extract"}:
                result = reveal_jsteg(args.file, args.output, raw=args.raw)
            elif args.image_command == "jsteg":
                result = hide_jsteg(
                    args.file,
                    args.output,
                    payload_path=args.payload,
                    text=args.text,
                    raw=args.raw,
                )
            elif args.image_command in {"raw-lsb", "rawlsb"} and args.raw_lsb_action == "extract":
                result = extract_raw_lsb(
                    args.file,
                    args.output,
                    bit=args.bit,
                    order=args.order,
                    source=args.source,
                    crop=_parse_crop(args.crop) if args.crop else None,
                    offset=args.offset,
                    limit=args.limit,
                )
            elif args.image_command in {"raw-lsb", "rawlsb"}:
                result = scan_raw_lsb(
                    args.file,
                    args.output,
                    bits=_parse_int_list_or_range(args.bits, "位平面"),
                    orders=_parse_orders(args.orders),
                    source=args.source,
                    crop=_parse_crop(args.crop) if args.crop else None,
                    max_bytes=args.max_bytes,
                    search_window=args.search_window,
                    write_all=args.write_all,
                )
            elif args.image_command == "stegdetect":
                result = run_stegdetect(
                    args.files,
                    types=args.types,
                    sensitivity=args.sensitivity,
                    output_path=args.output,
                )
            elif args.image_command == "wbstego" and args.wbstego_action == "hide":
                result = hide_wbstego(
                    args.file,
                    args.output,
                    args.payload,
                    carrier=args.carrier,
                    distribute=args.distribute,
                    password=args.password,
                    crypt=not args.no_crypt,
                    mix=args.mix,
                    transmit_password=args.transmit_password,
                )
            elif args.image_command == "wbstego" and args.wbstego_action == "extract":
                if args.wordlist is not None:
                    result = brute_wbstego(
                        args.file,
                        args.wordlist,
                        args.output,
                        carrier=args.carrier,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                        include_default=not args.no_default,
                    )
                else:
                    result = extract_wbstego(
                        args.file, args.output, carrier=args.carrier, password=args.password
                    )
            elif args.image_command == "wbstego":
                result = analyse_wbstego(args.file, carrier=args.carrier)
            elif args.image_command == "f5" and args.f5_action == "hide":
                result = hide_f5(
                    args.file,
                    args.output,
                    args.payload,
                    password=args.password,
                )
            elif args.image_command == "f5" and args.f5_action == "extract":
                if args.wordlist is not None:
                    result = brute_f5(
                        args.file,
                        args.wordlist,
                        args.output,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                        include_default=not args.no_default,
                    )
                else:
                    result = extract_f5(
                        args.file,
                        args.output,
                        password=args.password,
                    )
            elif args.image_command == "f5":
                result = brute_f5(
                    args.file,
                    args.wordlist,
                    args.output,
                    contains=args.contains.encode() if args.contains is not None else None,
                    prefix=args.prefix.encode() if args.prefix is not None else None,
                    include_default=not args.no_default,
                )
            elif args.image_command == "jphs" and args.jphs_action == "hide":
                result = hide_jphs(
                    args.file,
                    args.output,
                    args.payload,
                    password=args.password,
                    jphide_path=args.jphide,
                    wine_path=args.wine,
                    backend=args.backend,
                )
            elif args.image_command == "jphs" and args.jphs_action == "extract":
                if args.wordlist is not None:
                    result = brute_jphs(
                        args.file,
                        args.wordlist,
                        args.output,
                        jpseek_path=args.jpseek,
                        wine_path=args.wine,
                        backend=args.backend,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                        include_empty=not args.no_empty,
                    )
                else:
                    result = extract_jphs(
                        args.file,
                        args.output,
                        password=args.password,
                        jpseek_path=args.jpseek,
                        wine_path=args.wine,
                        backend=args.backend,
                    )
            elif args.image_command == "jphs":
                result = brute_jphs(
                    args.file,
                    args.wordlist,
                    args.output,
                    jpseek_path=args.jpseek,
                    wine_path=args.wine,
                    backend=args.backend,
                    contains=args.contains.encode() if args.contains is not None else None,
                    prefix=args.prefix.encode() if args.prefix is not None else None,
                    include_empty=not args.no_empty,
                )
            elif args.image_command == "mosaic" and args.mosaic_action == "pixelate":
                result = pixelate_image(
                    args.file,
                    args.output,
                    block_width=args.block_width,
                    block_height=args.block_height,
                    average_type=args.average,
                )
            elif args.image_command == "mosaic":
                result = depixelize_mosaic(
                    args.file,
                    args.search,
                    args.output,
                    block_width=args.block_width,
                    block_height=args.block_height,
                    tolerance=args.tolerance,
                    average_type=args.average,
                    background_color=_parse_color(args.background) if args.background else None,
                )
            elif args.image_command == "pixeljihad" and args.pixeljihad_action == "decode":
                if args.wordlist is not None:
                    result = brute_pixeljihad_images(
                        args.files,
                        args.wordlist,
                        output_path=args.output,
                        raw=args.raw,
                        contains=args.contains,
                    )
                else:
                    result = decode_pixeljihad_images(
                        args.files,
                        password=args.password,
                        output_path=args.output,
                        raw=args.raw,
                    )
            elif args.image_command == "pixeljihad":
                result = encode_pixeljihad_image(
                    args.file,
                    args.output,
                    args.text,
                    password=args.password,
                )
            elif args.image_command == "puzzle" and args.puzzle_action == "analyze":
                result = analyze_puzzle(
                    args.files,
                    tile_size=args.tile_size,
                    tile_width=args.tile_width,
                    tile_height=args.tile_height,
                )
            elif args.image_command == "puzzle":
                result = solve_puzzle(
                    args.files,
                    args.output,
                    rows=args.rows,
                    columns=args.columns,
                    tile_size=args.tile_size,
                    tile_width=args.tile_width,
                    tile_height=args.tile_height,
                    algorithm=args.algorithm,
                    rotate=args.rotate,
                    generations=args.generations,
                    population=args.population,
                    edge_width=args.edge_width,
                    seed=args.seed,
                    manifest_path=args.manifest,
                )
            elif args.image_command == "sample":
                start_x, start_y = _parse_pair(args.start, "起始坐标")
                end_x, end_y = _parse_pair(args.end, "终止坐标") if args.end else (None, None)
                step_x, step_y = _parse_pair(args.step, "采样间距")
                result = sample_pixels(
                    args.file,
                    args.output,
                    start_x=start_x,
                    start_y=start_y,
                    end_x=end_x,
                    end_y=end_y,
                    step_x=step_x,
                    step_y=step_y,
                    scale=args.scale,
                )
            else:
                result = flip_image(args.file, args.output, axis=args.axis)
        except (FileNotFoundError, OSError, ValueError) as error:
            if args.as_json:
                print(
                    json.dumps(
                        {
                            "status": "failed",
                            "operation": f"image.{args.image_command}",
                            "error": str(error),
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(f"[error] {error}", file=sys.stderr)
            return 2
        if args.as_json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        elif result.operation == "image.npiet.run":
            print(result.stdout, end="")
        else:
            print("状态：success")
            print(f"操作：{result.operation}")
            if hasattr(result, "output_path"):
                print(f"输出：{result.output_path}")
            if hasattr(result, "width"):
                print(f"尺寸：{result.width} × {result.height}")
            print(f"数量：{result.count}")
            if result.operation.startswith("image.cloacked-pixel"):
                print(f"容量：{result.capacity_bytes} bytes")
                if result.operation.endswith("analyse"):
                    print(f"LSB 均值：{result.channel_means}")
                    print(f"可疑块：{result.suspicious_blocks}")
                elif result.operation.endswith("hide"):
                    print(f"载荷：{result.payload_bytes} bytes")
                    print(f"加密后：{result.encrypted_bytes} bytes")
                elif result.operation.endswith("extract"):
                    print(f"写出：{result.written_bytes} bytes")
                elif result.operation.endswith("brute"):
                    print(f"命中密码：{result.found_password}")
                    print(f"尝试：{result.attempts}")
                    print(f"写出：{result.written_bytes} bytes")
            elif result.operation.startswith("image.spacefill"):
                print(f"曲线：{result.curve}")
                print(f"阶数：{result.order}")
                print(f"Y 翻转：{result.flip_y}")
            elif result.operation == "image.mosaic.depix":
                print(f"匹配块：{result.matched}/{result.blocks}")
                print(f"未匹配：{result.unmatched}")
            elif result.operation.startswith("stego.silenteye"):
                print(f"载体：{result.carrier_format}")
                print(f"格式：{result.data_format}")
                if result.payload_name:
                    print(f"文件名：{result.payload_name}")
                print(f"低位数：{result.bits}")
                if result.channels is not None:
                    print(f"声道：{result.channels}")
                if result.colors is not None:
                    print(f"颜色：{result.colors}")
                print(f"分布：{result.distribution}")
                print(f"头位置：{result.header_position}")
                print(f"压缩：{result.compressed}")
                print(f"加密：{result.encrypted}")
                print(f"容量：{result.capacity_bytes} bytes")
                print(f"嵌入数据：{result.embedded_bytes} bytes")
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
                if result.findings:
                    for finding in result.findings:
                        text = f" text={finding.get('text')}" if finding.get("text") else ""
                        print(f"命中：offset={finding['offset']} kind={finding['kind']}{text}")
            elif result.operation.startswith("stego.deepsound"):
                print(f"载体：{result.carrier_format}")
                print(f"找到：{result.found}")
                if result.quality:
                    print(f"质量：{result.quality} mode={result.mode}")
                print(f"加密：{result.encrypted}")
                if result.password_hash:
                    print(f"密码SHA1：{result.password_hash}")
                if result.password_verified is not None:
                    print(f"密码校验：{result.password_verified}")
                if result.header_offset is not None:
                    print(f"DSCF偏移：{result.header_offset}")
                print(f"容量：{result.capacity_bytes} bytes")
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
                for entry in result.files[:10]:
                    target = f" -> {entry['output_path']}" if entry.get("output_path") else ""
                    print(f"{entry['name']} size={entry['size']} sha256={entry['sha256']}{target}")
                if result.findings:
                    for finding in result.findings:
                        text = f" text={finding.get('text')}" if finding.get("text") else ""
                        print(f"命中：offset={finding['offset']} kind={finding['kind']}{text}")
            elif result.operation.startswith("stego.oursecret"):
                print(f"方式：{result.mode}")
                print(f"载体：{result.carrier_format}")
                print(f"数据长度：{result.data_size} bytes")
                print(f"密码标记：{result.password_tag}")
                if result.password_verified is not None:
                    print(f"密码校验：{result.password_verified}")
                if result.payload_bytes:
                    print(f"ZIP载荷：{result.payload_bytes} bytes")
                if result.capacity_bytes:
                    print(f"容量：{result.capacity_bytes} bytes")
                if result.output_paths:
                    print("输出：" + ", ".join(result.output_paths[:5]))
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
                for entry in result.entries[:10]:
                    print(f"{entry['name']} size={entry['size']} -> {entry['output_path']}")
            elif result.operation.startswith("image.stegpy"):
                print(f"格式：{result.host_format}")
                print(f"低位数：{result.bits}")
                print(f"容量：{result.capacity_bytes} bytes")
                if result.operation.endswith("hide"):
                    print(f"载荷：{result.payload_bytes} bytes")
                    print(f"嵌入后：{result.embedded_bytes} bytes")
                else:
                    if result.found_password:
                        print(f"命中密码：{result.found_password}")
                    if result.attempts:
                        print(f"尝试：{result.attempts}")
                    print(f"写出：{result.written_bytes} bytes")
            elif result.operation.startswith("image.steghide"):
                print(f"工具：{result.tool_path}")
                print(f"后端：{result.backend}")
                if getattr(result, "carrier_format", ""):
                    print(f"载体：{result.carrier_format}")
                if getattr(result, "embedded_name", ""):
                    print(f"内嵌文件名：{result.embedded_name}")
                if result.found_password is not None:
                    print(f"命中密码：{result.found_password!r}")
                if result.attempts:
                    print(f"尝试：{result.attempts}")
                print(f"写出：{result.written_bytes} bytes")
            elif result.operation.startswith("image.outguess"):
                print(f"工具：{result.tool_path}")
                print(f"后端：{result.backend}")
                if result.found_key is not None:
                    print(f"命中密钥：{result.found_key!r}")
                if result.attempts:
                    print(f"尝试：{result.attempts}")
                print(f"写出：{result.written_bytes} bytes")
            elif result.operation.startswith("image.jsteg"):
                print(f"工具：{result.tool_path}")
                print(f"容量：{result.capacity_bytes} bytes")
                print(f"载荷：{result.payload_bytes} bytes")
                print(f"原始流：{result.raw}")
                print(f"写出：{result.written_bytes} bytes")
            elif result.operation.startswith("image.raw-lsb"):
                print(f"工具：{result.tool_path}")
                print(f"来源：{result.source}")
                if result.bit is not None:
                    print(f"位平面：{result.bit}")
                if result.order is not None:
                    print(f"位序：{result.order}")
                if result.crop is not None:
                    print(f"裁剪：{result.crop}")
                print(f"写出：{result.written_bytes} bytes")
                if result.findings:
                    for finding in result.findings:
                        extra = (
                            f" -> {finding.get('output_path')}"
                            if finding.get("output_path")
                            else ""
                        )
                        print(
                            f"命中：bit={finding.get('bit', result.bit)} order={finding.get('order', result.order)} offset={finding['offset']} kind={finding['kind']}{extra}"
                        )
            elif result.operation == "image.stegdetect":
                print(f"类型：{result.types}")
                print(f"阈值：{result.sensitivity}")
                print(f"命中：{result.positive_count}/{result.count}")
                for finding in result.findings:
                    status = (
                        f"{finding['kind']}{finding['stars']}"
                        if finding["positive"]
                        else "negative"
                    )
                    evidence = "; ".join(finding["evidence"]) if finding["evidence"] else "-"
                    print(f"{finding['input_path']}：{status} score={finding['score']} {evidence}")
            elif result.operation.startswith("image.wbstego"):
                if result.found_password is not None:
                    print(f"命中密码：{result.found_password!r}")
                if result.attempts:
                    print(f"尝试：{result.attempts}")
                print(f"载体：{result.carrier_format} {result.bit_count}-bit")
                print(f"容量：{result.capacity_bytes} bytes")
                if result.embedded_extension:
                    print(f"扩展名：{result.embedded_extension}")
                print(f"分散模式：{result.distributed}")
                print(f"密码模式：{result.password_protected}")
                if result.password_verified:
                    print("密码校验：True")
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                if result.written_bytes:
                    print(f"写出：{result.written_bytes} bytes")
            elif result.operation.startswith("image.f5"):
                if result.found_password is not None:
                    print(f"命中密码：{result.found_password!r}")
                if result.attempts:
                    print(f"尝试：{result.attempts}")
                print(f"写出：{result.written_bytes} bytes")
            elif result.operation.startswith("image.jphs"):
                print(f"工具：{result.tool_path}")
                if result.runner_path:
                    print(f"运行器：{result.runner_path}")
                if result.found_password is not None:
                    print(f"命中密码：{result.found_password!r}")
                if result.attempts:
                    print(f"尝试：{result.attempts}")
                print(f"写出：{result.written_bytes} bytes")
            elif result.operation == "image.stereogram.solve":
                print(f"偏移：{result.offset}")
            elif result.operation == "image.stereogram.scan":
                print(f"偏移范围：{result.offset_start}..{result.offset_stop - 1}")
                print(f"清单：{result.manifest_path}")
            elif result.operation == "image.acropalypse.restore":
                print(f"模式：{result.mode}")
                print(f"尾部残留：{result.trailing_bytes} bytes")
                print(f"恢复数据：{result.recovered_bytes} bytes")
                print(f"bit offset：{result.bit_offset}")
            elif result.operation.startswith("image.arnold"):
                if result.output_paths and result.output_path != result.output_paths[0]:
                    print(f"候选目录：{result.output_path}")
            elif result.operation == "image.pixeljihad.decode":
                for message in result.messages:
                    value = message["raw"] if args.raw else (message["text"] or message["raw"])
                    print(f"{message['input_path']}：{value}")
                if result.output_path:
                    print(f"文本：{result.output_path}")
            elif result.operation == "image.pixeljihad.encode":
                print(f"字符数：{result.message_size}/{result.max_message_size}")
            elif result.operation == "image.puzzle.analyze":
                print(f"块尺寸：{result.tile_width} × {result.tile_height}")
                print(
                    "候选网格："
                    + ", ".join(
                        f"{candidate['rows']}×{candidate['columns']}"
                        for candidate in result.candidate_grids
                    )
                )
            elif result.operation == "image.puzzle.solve":
                print(f"网格：{result.rows} × {result.columns}")
                print(f"算法：{result.algorithm}")
                print(f"分数：{result.normalized_score:.6f}")
                print(f"布局：{result.manifest_path}")
        return 0
    if args.command == "text":
        try:
            if args.text_command in {"whitespace", "ws"}:
                if args.whitespace_action in {"run", "decode"}:
                    input_data = (
                        args.input_file.read_text(encoding="utf-8")
                        if args.input_file is not None
                        else args.input
                    )
                    result = run_whitespace(
                        args.file,
                        args.output,
                        input_data=input_data,
                        max_steps=args.max_steps,
                    )
                elif args.whitespace_action in {"show", "visible"}:
                    result = render_whitespace(args.file, args.output, style=args.style)
                else:
                    result = encode_whitespace_text(
                        args.output,
                        text=args.text,
                        payload_path=args.payload,
                    )
            elif args.text_command in {
                "spammimic",
                "spam-mimic",
                "spam",
            } and args.spammimic_action in {
                "encode",
                "hide",
                "embed",
            }:
                result = encode_spammimic(
                    args.output,
                    payload_path=args.payload,
                    text=args.text,
                    cover_path=args.cover,
                    password=args.password,
                    mode=args.mode,
                    backend=args.backend,
                )
            elif args.text_command in {
                "spammimic",
                "spam-mimic",
                "spam",
            } and args.spammimic_action in {
                "decode",
                "extract",
                "reveal",
            }:
                if args.wordlist is not None:
                    result = brute_spammimic(
                        args.file,
                        args.wordlist,
                        args.output,
                        mode=args.mode,
                        backend=args.backend,
                        contains=args.contains.encode() if args.contains is not None else None,
                        prefix=args.prefix.encode() if args.prefix is not None else None,
                        include_default=not args.no_default,
                    )
                else:
                    result = decode_spammimic(
                        args.file,
                        args.output,
                        password=args.password,
                        mode=args.mode,
                        backend=args.backend,
                    )
            elif args.text_command in {"snow", "stegsnow"} and args.snow_action in {
                "hide",
                "embed",
            }:
                result = hide_snow(
                    args.file,
                    args.output,
                    payload_path=args.payload,
                    text=args.text,
                    password=args.password,
                    compress=args.compress,
                    line_length=args.line_length,
                    backend=args.backend,
                    snow_path=args.snow,
                )
            elif args.text_command in {"snow", "stegsnow"} and args.snow_action in {
                "extract",
                "decode",
            }:
                result = extract_snow(
                    args.file,
                    args.output,
                    password=args.password,
                    compress=args.compress,
                    backend=args.backend,
                    snow_path=args.snow,
                )
            elif args.text_command in {"snow", "stegsnow"}:
                result = capacity_snow(args.file, line_length=args.line_length)
            elif args.text_command in {
                "zerowidth",
                "zero-width",
                "zwc",
            } and args.zerowidth_action in {
                "hide",
                "embed",
            }:
                result = hide_zero_width(
                    args.file,
                    args.output,
                    payload_path=args.payload,
                    text=args.text,
                    mode=args.mode,
                    alphabet=args.alphabet,
                    chars=args.chars,
                    placement=args.placement,
                )
            elif args.text_command in {
                "zerowidth",
                "zero-width",
                "zwc",
            } and args.zerowidth_action in {
                "extract",
                "decode",
            }:
                result = extract_zero_width(
                    args.file,
                    args.output,
                    mode=args.mode,
                    alphabet=args.alphabet,
                    chars=args.chars,
                )
            elif args.text_command in {
                "zerowidth",
                "zero-width",
                "zwc",
            } and args.zerowidth_action in {
                "inspect",
                "scan",
            }:
                result = inspect_zero_width(args.file)
            elif args.text_command in {"zerowidth", "zero-width", "zwc"}:
                result = strip_zero_width_file(args.file, args.output)
            elif args.text_command in {"cloakify", "cloak"} and args.cloakify_action in {
                "cloak",
                "hide",
                "encode",
            }:
                result = cloakify_file(args.file, args.cipher, args.output)
            elif args.text_command in {"cloakify", "cloak"} and args.cloakify_action in {
                "decloak",
                "extract",
                "decode",
            }:
                result = decloakify_file(
                    args.file, args.cipher, args.output, ignore_unknown=args.ignore_unknown
                )
            else:
                result = inspect_cloakify(args.file, cipher_path=args.cipher)
        except (FileNotFoundError, OSError, ValueError) as error:
            if args.as_json:
                print(
                    json.dumps(
                        {
                            "status": "failed",
                            "operation": f"text.{args.text_command}",
                            "error": str(error),
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(f"[error] {error}", file=sys.stderr)
            return 2
        if args.as_json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        elif result.operation == "text.whitespace.run" and args.output is None:
            print(result.stdout, end="")
        else:
            print("状态：success")
            print(f"操作：{result.operation}")
            print(f"输出：{result.output_path}")
            if hasattr(result, "backend"):
                print(f"后端：{result.backend}")
                if hasattr(result, "mode"):
                    print(f"模式：{result.mode}")
                if getattr(result, "tool_path", ""):
                    print(f"工具：{result.tool_path}")
                if getattr(result, "line_length", 0):
                    print(f"行宽：{result.line_length}")
                if getattr(result, "capacity_bits_high", 0):
                    print(f"容量：{result.capacity_bits_low}..{result.capacity_bits_high} bits")
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                if getattr(result, "extra_lines", 0):
                    print(f"追加空行：{result.extra_lines}")
                if result.password_used:
                    print("密码：yes")
                if getattr(result, "password_verified", False):
                    print("密码校验：yes")
                if getattr(result, "found_password", None) is not None:
                    print(f"命中密码：{result.found_password!r}")
                if getattr(result, "attempts", 0):
                    print(f"尝试：{result.attempts}")
                if getattr(result, "compressed", False):
                    print("压缩：yes")
            elif hasattr(result, "char_codes"):
                print(f"模式：{result.mode}")
                print(f"字符表：{result.alphabet} {' '.join(result.char_codes)}")
                print(f"零宽字符：{result.hidden_chars}")
                print(f"可见字符：{result.visible_chars}")
                if result.counts:
                    for name, value in result.counts.items():
                        print(f"{name}: {value}")
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                if result.preview:
                    print(f"预览：{result.preview}")
            elif hasattr(result, "cipher_path"):
                print(f"字典：{result.cipher_path}")
                print(f"字母表：{result.alphabet_size}")
                print(f"字典条目：{result.cipher_entries}")
                print(f"密文行：{result.cloaked_lines}")
                if result.known_lines:
                    print(f"命中行：{result.known_lines}")
                if result.unknown_lines:
                    print(f"未知行：{result.unknown_lines}")
                if result.base64_chars:
                    print(f"Base64字符：{result.base64_chars}")
                if result.payload_bytes:
                    print(f"载荷：{result.payload_bytes} bytes")
                if result.preview:
                    print(f"预览：{result.preview}")
            else:
                print(f"指令数：{result.instructions}")
                if result.steps:
                    print(f"步数：{result.steps}")
            if result.written_bytes:
                print(f"写出：{result.written_bytes} bytes")
        return 0

    if args.command == "image" and args.image_command == "watermark":
        try:
            if args.watermark_mode == "single" and args.watermark_action == "embed":
                result = embed_single_watermark(
                    args.file,
                    args.output,
                    args.text,
                    strength=args.strength,
                    scheme=args.scheme,
                    font_path=args.font,
                    font_size=args.font_size,
                )
            elif args.watermark_mode == "single":
                result = extract_single_watermark(
                    args.file,
                    args.output,
                    brightness=args.brightness,
                    scheme=args.scheme,
                )
            elif (
                args.watermark_mode == "dual"
                and not args.watermark_profile.startswith("ww23-")
                and args.watermark_action == "embed"
            ):
                result = embed_dual_watermark(
                    args.file,
                    args.watermark,
                    args.output,
                    variant=args.watermark_profile,
                    seed=args.seed,
                    alpha=args.alpha,
                )
            elif args.watermark_mode == "dual" and not args.watermark_profile.startswith("ww23-"):
                if (args.width is None) != (args.height is None):
                    raise ValueError("--width 与 --height 必须同时提供")
                result = extract_dual_watermark(
                    args.reference,
                    args.file,
                    args.output,
                    variant=args.watermark_profile,
                    seed=args.seed,
                    alpha=args.alpha,
                    crop=not args.no_crop,
                    watermark_size=(args.width, args.height) if args.width is not None else None,
                )
            elif args.watermark_action == "embed":
                result = embed_ww23_watermark(
                    args.file,
                    args.watermark,
                    args.output,
                    transform=args.watermark_transform,
                    alpha=args.alpha,
                )
            else:
                result = extract_ww23_watermark(
                    args.file,
                    args.output,
                    transform=args.watermark_transform,
                )
        except (FileNotFoundError, OSError, ValueError) as error:
            if args.as_json:
                print(
                    json.dumps(
                        {
                            "status": "failed",
                            "operation": (
                                "watermark."
                                f"{args.watermark_mode}.{args.watermark_profile}."
                                f"{args.watermark_action}"
                            ),
                            "error": str(error),
                        },
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                print(f"[error] {error}", file=sys.stderr)
            return 2
        if args.as_json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        else:
            print("状态：success")
            print(f"操作：{result.operation}")
            print(f"输入：{result.input_path}")
            print(f"输出：{result.output_path}")
            print(f"尺寸：{result.width} × {result.height}")
            print(f"FFT：{result.work_width} × {result.work_height}")
            if result.transform is not None:
                print(f"变换：{result.transform}")
                if result.alpha is not None:
                    print(f"强度：{result.alpha}")
            elif result.variant is not None:
                print(f"变体：{result.variant}")
                print(f"种子：{result.seed}")
                print(f"强度：{result.alpha}")
            else:
                print(f"方案：{result.scheme}")
        return 0
    result = inspect_file(args.file)
    if args.as_json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"状态：{result.status}")
        print(f"文件：{result.input_path}")
        if result.summary:
            print(f"类型：{result.summary['kind']} ({result.summary['media_type']})")
            print(f"大小：{result.summary['size']} bytes")
            print(f"SHA-256：{result.summary['sha256']}")
            if "width" in result.summary:
                print(f"尺寸：{result.summary['width']} × {result.summary['height']}")
        for finding in result.findings:
            print(f"[{finding.severity}] {finding.title}：{finding.evidence}")
        for error in result.errors:
            print(f"[error] {error['message']}", file=sys.stderr)
    return 0 if result.status in {"success", "empty"} else 2


def _parse_int_auto(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"整数格式错误：{value}") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"整数必须非负：{value}")
    return parsed


def _parse_float_csv(value: str) -> list[float]:
    try:
        items = [float(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as error:
        raise ValueError(f"浮点列表格式错误：{value}") from error
    if not items:
        raise ValueError(f"浮点列表不能为空：{value}")
    return items


def _parse_nonnegative_int_csv(value: str) -> list[int]:
    try:
        items = [int(part.strip(), 0) for part in value.split(",") if part.strip()]
    except ValueError as error:
        raise ValueError(f"整数列表格式错误：{value}") from error
    if not items or any(item < 0 for item in items):
        raise ValueError(f"整数列表必须非负且不能为空：{value}")
    return items


def _parse_key_value_map(items: Sequence[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f"映射格式必须为 key:value：{item}")
        key, value = item.split(":", 1)
        mapping[key.strip()] = value.strip()
    if not mapping:
        raise ValueError("映射不能为空")
    return mapping


def _parse_float_value_map(items: Sequence[str]) -> dict[str, float]:
    parsed: dict[str, float] = {}
    for key, value in _parse_key_value_map(items).items():
        try:
            parsed[key] = float(value)
        except ValueError as error:
            raise ValueError(f"频率映射值必须是数字：{key}:{value}") from error
    return parsed


def _parse_choice_list(value: str, choices: Sequence[str], label: str) -> list[str]:
    items = [part.strip() for part in value.split(",") if part.strip()]
    allowed = set(choices)
    if not items or any(item not in allowed for item in items):
        raise ValueError(f"{label} 只能包含 {', '.join(choices)}：{value}")
    return items


def _parse_crop(value: str) -> tuple[int, int, int, int]:
    parts = value.split(",")
    if len(parts) != 4 or not all(part.strip().lstrip("-").isdigit() for part in parts):
        raise ValueError(f"crop 格式必须为 X,Y,W,H：{value}")
    x, y, width, height = (int(part.strip()) for part in parts)
    if x < 0 or y < 0 or width <= 0 or height <= 0:
        raise ValueError(f"crop 必须为非负 X,Y 和正 W,H：{value}")
    return x, y, width, height


def _parse_int_list_or_range(value: str, label: str) -> list[int]:
    if ":" in value:
        return list(_parse_range(value, label))
    parts = value.split(",")
    if not parts or not all(part.strip().isdigit() for part in parts):
        raise ValueError(f"{label}格式必须为 START:STOP 或逗号分隔整数：{value}")
    return [int(part.strip()) for part in parts]


def _parse_orders(value: str) -> list[str]:
    orders = [part.strip() for part in value.split(",") if part.strip()]
    if not orders or any(order not in {"msb", "lsb"} for order in orders):
        raise ValueError(f"orders 只能包含 msb 或 lsb：{value}")
    return orders


def _parse_pair(value: str, label: str) -> tuple[int, int]:
    parts = value.lower().split("x")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ValueError(f"{label}格式必须为 XxY：{value}")
    return int(parts[0]), int(parts[1])


def _parse_range(value: str, label: str) -> range:
    parts = value.split(":")
    if len(parts) != 2 or not all(part.lstrip("-").isdigit() for part in parts):
        raise ValueError(f"{label}格式必须为 START:STOP：{value}")
    start, stop = int(parts[0]), int(parts[1])
    if stop <= start:
        raise ValueError(f"{label}的 STOP 必须大于 START：{value}")
    return range(start, stop)


def _parse_color(value: str) -> tuple[int, int, int]:
    parts = value.split(",")
    if len(parts) != 3 or not all(part.strip().isdigit() for part in parts):
        raise ValueError(f"颜色格式必须为 R,G,B：{value}")
    color = tuple(int(part.strip()) for part in parts)
    if any(channel > 255 for channel in color):
        raise ValueError(f"颜色通道必须在 0..255：{value}")
    return color
