#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhoenixGSM - GitHub Clean Project Archiver (Python Edition)
يقوم بضغط ملفات المشروع مع استبعاد كل ما تم استثناؤه في .gitignore، تماماً كما يتم رفعه إلى GitHub.
"""

import os
import sys
import time
import argparse
import subprocess
import zipfile
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def get_repo_root() -> Path:
    try:
        root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8"
        ).strip()
        return Path(root).resolve()
    except Exception:
        print("[!] خطأ: هذا المجلد ليس مستودع Git أو لم يتم العثور على أداة git في النظام.")
        sys.exit(1)


def get_working_tree_files(repo_root: Path) -> list:
    result = subprocess.run(
        ["git", "ls-files", "-c", "-o", "--exclude-standard"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True
    )
    raw_lines = result.stdout.splitlines()
    valid_files = []
    for line in raw_lines:
        rel = line.strip()
        if not rel:
            continue
        full_path = repo_root / rel
        if full_path.is_file():
            valid_files.append((rel, full_path))
    return valid_files


def compress_working_tree(repo_root: Path, output_zip: Path):
    files = get_working_tree_files(repo_root)
    if not files:
        print("[!] لم يتم العثور على ملفات مؤهلة للضغط.")
        sys.exit(1)

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()

    total_raw_bytes = 0
    archived_count = 0

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for rel_path, full_path in files:
            # تجنب ضغط ملف الأرشيف نفسه إذا كان داخل المستودع
            if full_path.resolve() == output_zip.resolve():
                continue
            total_raw_bytes += full_path.stat().st_size
            zf.write(str(full_path), rel_path.replace("\\", "/"))
            archived_count += 1

    return archived_count, total_raw_bytes


def compress_git_head(repo_root: Path, output_zip: Path):
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()

    cmd = ["git", "archive", "--format=zip", "-o", str(output_zip), "HEAD"]
    subprocess.run(cmd, cwd=str(repo_root), check=True)

    archived_count = 0
    total_raw_bytes = 0
    with zipfile.ZipFile(output_zip, "r") as zf:
        for info in zf.infolist():
            if not info.is_dir():
                archived_count += 1
                total_raw_bytes += info.file_size

    return archived_count, total_raw_bytes


def main():
    parser = argparse.ArgumentParser(
        description="ضغط ملفات المشروع مع استثناء ملفات .gitignore لمطابقة ما يرفع إلى GitHub."
    )
    parser.add_argument(
        "--mode",
        choices=["working", "head"],
        default="working",
        help="وضع التصدير: working (الملفات الحالية مع التعديلات) أو head (آخر commit نظيف)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="مسار ملف الأرشيف الناتج (ZIP)"
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="فتح المجلد بعد إنشاء الملف المضغوط"
    )

    args = parser.parse_args()
    repo_root = get_repo_root()
    repo_name = repo_root.name
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    if args.output:
        output_zip = Path(args.output).resolve()
    else:
        output_name = f"{repo_name}_GitHub_{args.mode.capitalize()}_{timestamp}.zip"
        output_zip = repo_root / output_name

    print("=" * 60)
    print("      أداة ضغط وتصدير ملفات المشروع النظيفة لـ GitHub       ")
    print("=" * 60)
    print(f"[+] مسار المشروع: {repo_root}")
    print(f"[+] وضع التصدير : {args.mode}")
    print(f"[+] مسار الأرشيف : {output_zip}")
    print("-" * 60)

    t0 = time.time()
    if args.mode == "head":
        print("[*] جاري استخراج آخر نسخة معتمدة من Git (HEAD)...")
        file_count, raw_bytes = compress_git_head(repo_root, output_zip)
    else:
        print("[*] جاري فحص ملفات المشروع واستبعاد مستثنيات .gitignore...")
        file_count, raw_bytes = compress_working_tree(repo_root, output_zip)

    elapsed = time.time() - t0
    zip_bytes = output_zip.stat().st_size
    raw_mb = raw_bytes / (1024 * 1024)
    zip_mb = zip_bytes / (1024 * 1024)
    ratio = (1 - (zip_bytes / raw_bytes)) * 100 if raw_bytes > 0 else 0

    print("-" * 60)
    print("[✔] تم إنشاء الأرشيف بنجاح!")
    print(f"    • عدد الملفات المضمنة   : {file_count} ملف")
    print(f"    • الحجم قبل الضغط       : {raw_mb:.2f} MB")
    print(f"    • الحجم بعد الضغط       : {zip_mb:.2f} MB (نسبة تقليص: {ratio:.1f}%)")
    print(f"    • الوقت المستغرق        : {elapsed:.2f} ثانية")
    print(f"    • مسار الملف المضغوط    : {output_zip}")
    print("=" * 60)

    if args.open:
        if sys.platform == "win32":
            subprocess.run(["explorer.exe", f"/select,{output_zip}"])
        elif sys.platform == "darwin":
            subprocess.run(["open", "-R", str(output_zip)])
        else:
            subprocess.run(["xdg-open", str(output_zip.parent)])


if __name__ == "__main__":
    main()
