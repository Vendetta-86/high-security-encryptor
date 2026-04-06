import base64
import csv
import ctypes
import io
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from getpass import getpass
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import Type, hash_secret_raw
from tkinterdnd2 import DND_FILES, TkinterDnD


SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32

ARGON_TIME = 3
ARGON_MEM = 65536
ARGON_PARALLEL = 4

MAGIC = b"GCM1"
VERSION = 1
HEADER_LEN = len(MAGIC) + 1
MIN_BLOB_LEN = HEADER_LEN + SALT_LEN + NONCE_LEN + TAG_LEN
VERIFY_SALT_LEN = 16
VERIFY_HASH_LEN = 32
MANIFEST_PREFIX = "aes_batch_manifest_"
MANIFEST_SUFFIX = ".json.gcm"
LEGACY_MANIFEST_SUFFIX = ".json"


def wipe(buffer) -> None:
    if isinstance(buffer, (bytearray, memoryview)):
        for index in range(len(buffer)):
            buffer[index] = 0


def secure_password(password: str) -> bytearray:
    if not password:
        raise ValueError("密码不能为空")
    return bytearray(password.encode("utf-8"))


def generate_random_password(length: int = 24) -> str:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(length)).decode("ascii")
    return raw.rstrip("=")


def derive_key(password_buffer: bytearray, salt: bytes) -> bytearray:
    try:
        key = hash_secret_raw(
            secret=bytes(password_buffer),
            salt=salt,
            time_cost=ARGON_TIME,
            memory_cost=ARGON_MEM,
            parallelism=ARGON_PARALLEL,
            hash_len=KEY_LEN,
            type=Type.ID,
        )
        return bytearray(key)
    finally:
        wipe(password_buffer)


def build_header() -> bytes:
    return MAGIC + bytes([VERSION])


def build_password_verifier(password: str) -> dict:
    salt = secrets.token_bytes(VERIFY_SALT_LEN)
    check = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEM,
        parallelism=ARGON_PARALLEL,
        hash_len=VERIFY_HASH_LEN,
        type=Type.ID,
    )
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "check": base64.b64encode(check).decode("ascii"),
    }


def verify_password_verifier(password: str, verifier: dict) -> bool:
    salt = base64.b64decode(verifier["salt"])
    expected = base64.b64decode(verifier["check"])
    actual = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEM,
        parallelism=ARGON_PARALLEL,
        hash_len=VERIFY_HASH_LEN,
        type=Type.ID,
    )
    return secrets.compare_digest(actual, expected)


def validate_blob(blob: bytes) -> None:
    if len(blob) < MIN_BLOB_LEN:
        raise ValueError("密文长度无效")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("不是受支持的密文格式")
    if blob[len(MAGIC)] != VERSION:
        raise ValueError("密文版本不受支持")


def encrypt_bytes(data: bytes, password: str) -> bytes:
    password_buffer = secure_password(password)
    salt = get_random_bytes(SALT_LEN)
    nonce = get_random_bytes(NONCE_LEN)
    key = derive_key(password_buffer, salt)

    try:
        header = build_header()
        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return header + salt + nonce + tag + ciphertext
    finally:
        wipe(key)


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    validate_blob(blob)

    salt_start = HEADER_LEN
    nonce_start = salt_start + SALT_LEN
    tag_start = nonce_start + NONCE_LEN
    data_start = tag_start + TAG_LEN

    header = blob[:HEADER_LEN]
    salt = blob[salt_start:nonce_start]
    nonce = blob[nonce_start:tag_start]
    tag = blob[tag_start:data_start]
    ciphertext = blob[data_start:]

    password_buffer = secure_password(password)
    key = derive_key(password_buffer, salt)

    try:
        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        return cipher.decrypt_and_verify(ciphertext, tag)
    finally:
        wipe(key)


def encrypt_text(plaintext: str, password: str) -> str:
    blob = encrypt_bytes(plaintext.encode("utf-8"), password)
    return base64.b64encode(blob).decode("ascii")


def decrypt_text(ciphertext_b64: str, password: str) -> str:
    try:
        blob = base64.b64decode(ciphertext_b64, validate=True)
    except Exception as exc:
        raise ValueError("文本密文不是有效的 Base64") from exc
    return decrypt_bytes(blob, password).decode("utf-8")


def _report_progress(callback, value: int, message: str) -> None:
    if callback is not None:
        callback(value, message)


def refresh_explorer(path: str) -> None:
    directory = path if os.path.isdir(path) else os.path.dirname(path)
    if not directory:
        return
    try:
        ctypes.windll.shell32.SHChangeNotify(0x00002000, 0x0005, None, None)
        ctypes.windll.shell32.SHChangeNotify(0x00000008, 0x0005, directory, None)
    except Exception:
        pass


def get_encrypted_output_path(path: str) -> str:
    return path + ".gcm"


def get_folder_encrypted_output_path(path: str) -> str:
    return path.rstrip("\\/") + ".zip.gcm"


def get_source_encrypted_output_path(path: str) -> str:
    return get_folder_encrypted_output_path(path) if os.path.isdir(path) else get_encrypted_output_path(path)


def get_decrypted_output_path(path: str) -> str:
    if not path.endswith(".gcm"):
        raise ValueError("只支持解密 .gcm 文件")
    return path[:-4]


def iter_folder_files(path: str) -> list[str]:
    result = []
    for root, _, files in os.walk(path):
        for name in files:
            result.append(os.path.join(root, name))
    return sorted(result)


def to_posix_path(path: str) -> str:
    return path.replace("\\", "/")


def folder_child_scope(folder_path: str) -> str:
    return os.path.basename(folder_path.rstrip("\\/")) or folder_path


def folder_child_relative_path(folder_path: str, child_path: str) -> str:
    return to_posix_path(os.path.relpath(child_path, folder_path))


def folder_child_encrypted_name(folder_path: str, child_path: str) -> str:
    return to_posix_path(os.path.join(folder_child_scope(folder_path), folder_child_relative_path(folder_path, child_path) + ".gcm"))


def build_folder_package(
    path: str,
    password: str,
    individually_encrypt_files: set[str] | None = None,
    child_password_map: dict[str, str] | None = None,
    staging_root: str | None = None,
) -> str:
    if not os.path.isdir(path):
        raise FileNotFoundError(path)
    individually_encrypt_files = {os.path.normpath(item) for item in (individually_encrypt_files or set())}
    child_password_map = {os.path.normpath(key): value for key, value in (child_password_map or {}).items()}
    working_root = staging_root or tempfile.mkdtemp(prefix="aes_folder_")
    package_root = os.path.join(working_root, os.path.basename(path.rstrip("\\/")) or "folder")
    os.makedirs(package_root, exist_ok=True)
    named_passwords: dict[str, str] = {}

    for root, dirs, files in os.walk(path):
        relative_root = os.path.relpath(root, path)
        target_root = package_root if relative_root == "." else os.path.join(package_root, relative_root)
        for directory in dirs:
            os.makedirs(os.path.join(target_root, directory), exist_ok=True)
        for name in files:
            source = os.path.join(root, name)
            destination = os.path.join(target_root, name)
            if os.path.normpath(source) in individually_encrypt_files:
                item_password = child_password_map.get(os.path.normpath(source), password)
                with open(source, "rb") as file_obj:
                    encrypted_blob = encrypt_bytes(file_obj.read(), item_password)
                with open(destination + ".gcm", "wb") as file_obj:
                    file_obj.write(encrypted_blob)
                named_passwords[folder_child_encrypted_name(path, source)] = item_password
            else:
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                shutil.copy2(source, destination)

    if named_passwords:
        manifest = build_manifest_for_named_entries(named_passwords, mode="folder_inner_batch")
        save_manifest(manifest, os.path.join(package_root, "batch_manifest.json.gcm"), password)

    archive_path = os.path.join(working_root, os.path.basename(package_root) + ".zip")
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(package_root):
            for name in files:
                source = os.path.join(root, name)
                arcname = os.path.relpath(source, working_root)
                zip_file.write(source, arcname=arcname)
    return archive_path


def encrypt_folder(
    path: str,
    password: str,
    individually_encrypt_files: set[str] | None = None,
    child_password_map: dict[str, str] | None = None,
    progress_callback=None,
    keep_source: bool = True,
    overwrite: bool = False,
) -> str:
    out_path = get_folder_encrypted_output_path(path)
    if os.path.exists(out_path) and not overwrite:
        raise FileExistsError(out_path)
    _report_progress(progress_callback, 10, "正在整理文件夹内容")
    with tempfile.TemporaryDirectory(prefix="aes_folder_pack_") as temp_dir:
        archive_path = build_folder_package(
            path,
            password,
            individually_encrypt_files=individually_encrypt_files,
            child_password_map=child_password_map,
            staging_root=temp_dir,
        )
        _report_progress(progress_callback, 55, "正在加密文件夹打包内容")
        with open(archive_path, "rb") as file_obj:
            blob = encrypt_bytes(file_obj.read(), password)
    _report_progress(progress_callback, 80, "正在写入文件夹加密文件")
    with open(out_path, "wb") as file_obj:
        file_obj.write(blob)
    if keep_source:
        _report_progress(progress_callback, 100, "文件夹加密完成，已保留原文件夹")
    else:
        _report_progress(progress_callback, 95, "正在普通删除原文件夹")
        shutil.rmtree(path)
        _report_progress(progress_callback, 100, "文件夹加密完成，原文件夹已普通删除")
    return out_path


def encrypt_file(
    path: str,
    password: str,
    progress_callback=None,
    keep_source: bool = True,
    overwrite: bool = False,
) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if path.endswith(".gcm"):
        raise ValueError("该文件已经是 .gcm 文件")
    out_path = get_encrypted_output_path(path)
    if os.path.exists(out_path) and not overwrite:
        raise FileExistsError(out_path)

    _report_progress(progress_callback, 10, "正在读取原文件")
    with open(path, "rb") as file_obj:
        data = file_obj.read()

    _report_progress(progress_callback, 45, "正在执行加密")
    blob = encrypt_bytes(data, password)

    _report_progress(progress_callback, 75, "正在写入加密文件")
    with open(out_path, "wb") as file_obj:
        file_obj.write(blob)

    if keep_source:
        _report_progress(progress_callback, 100, "文件加密完成，已保留原文件")
    else:
        _report_progress(progress_callback, 95, "正在普通删除原文件")
        os.remove(path)
        _report_progress(progress_callback, 100, "文件加密完成，原文件已普通删除")
    return out_path


def decrypt_file(path: str, password: str, progress_callback=None, keep_source: bool = True) -> str:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if not path.endswith(".gcm"):
        raise ValueError("只支持解密 .gcm 文件")
    out_path = get_decrypted_output_path(path)

    _report_progress(progress_callback, 10, "正在读取加密文件")
    with open(path, "rb") as file_obj:
        blob = file_obj.read()

    _report_progress(progress_callback, 45, "正在执行解密")
    data = decrypt_bytes(blob, password)

    _report_progress(progress_callback, 75, "正在写入解密文件")
    with open(out_path, "wb") as file_obj:
        file_obj.write(data)

    if keep_source:
        _report_progress(progress_callback, 100, "文件解密完成，已保留源 .gcm 文件")
    else:
        _report_progress(progress_callback, 95, "正在普通删除 .gcm 文件")
        os.remove(path)
        _report_progress(progress_callback, 100, "文件解密完成，源 .gcm 文件已普通删除")
    return out_path


def summarize_paths(paths: list[str]) -> str:
    if not paths:
        return ""
    if len(paths) == 1:
        return paths[0]
    return f"{os.path.basename(paths[0])} 等 {len(paths)} 个文件"


def get_common_directory(paths: list[str]) -> str:
    if not paths:
        return ""
    directories = [os.path.dirname(path) or os.getcwd() for path in paths]
    try:
        common_path = os.path.commonpath(directories)
    except ValueError:
        common_path = directories[0]
    if not os.path.isdir(common_path):
        common_path = directories[0]
    return common_path


def build_bundle_output_path(paths: list[str]) -> str:
    base_dir = get_common_directory(paths) or os.getcwd()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_dir, f"batch_bundle_{timestamp}.zip.gcm")


def build_manifest_path(paths: list[str]) -> str:
    base_dir = get_common_directory(paths) or os.getcwd()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_dir, f"{MANIFEST_PREFIX}{timestamp}{MANIFEST_SUFFIX}")


def build_password_table_output_path(paths: list[str]) -> str:
    base_dir = get_common_directory(paths) or os.getcwd()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_dir, f"batch_password_table_{timestamp}.csv.gcm")


def build_password_template_path(paths: list[str]) -> str:
    base_dir = get_common_directory(paths) or os.getcwd()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(base_dir, f"batch_password_template_{timestamp}.csv")


def collect_existing_paths(paths: list[str]) -> list[str]:
    return [path for path in paths if os.path.exists(path)]


def save_manifest(manifest: dict, path: str, password: str) -> str:
    blob = encrypt_bytes(json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"), password)
    with open(path, "wb") as file_obj:
        file_obj.write(blob)
    return path


def load_manifest(path: str, password: str | None = None) -> dict:
    if path.lower().endswith(".gcm"):
        if not password:
            raise ValueError("读取加密 manifest 需要先提供主密码")
        with open(path, "rb") as file_obj:
            blob = file_obj.read()
        return load_manifest_from_blob(blob, password)
    with open(path, "r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


def load_manifest_from_blob(blob: bytes, password: str) -> dict:
    return json.loads(decrypt_bytes(blob, password).decode("utf-8"))


def find_manifest_for_files(paths: list[str], password: str | None = None) -> str | None:
    if not paths:
        return None
    common_dir = get_common_directory(paths)
    if not common_dir or not os.path.isdir(common_dir):
        return None
    target_names = {os.path.basename(path) for path in paths}
    target_relative_names = {to_posix_path(os.path.relpath(path, common_dir)) for path in paths}
    for name in os.listdir(common_dir):
        if not (
            name.startswith(MANIFEST_PREFIX)
            and (name.endswith(MANIFEST_SUFFIX) or name.endswith(LEGACY_MANIFEST_SUFFIX))
        ):
            continue
        manifest_path = os.path.join(common_dir, name)
        try:
            manifest = load_manifest(manifest_path, password=password)
        except Exception:
            continue
        entry_names = {entry["encrypted_name"] for entry in manifest.get("entries", [])}
        if target_names.issubset(entry_names) or target_relative_names.issubset(entry_names):
            return manifest_path
    return None


def build_manifest_for_batch(outputs: list[str], password_map: dict[str, str], mode: str) -> dict:
    named_passwords = {os.path.basename(output_path): password_map[output_path] for output_path in outputs}
    return build_manifest_for_named_entries(named_passwords, mode)


def build_manifest_for_named_entries(named_passwords: dict[str, str], mode: str) -> dict:
    groups: dict[str, dict] = {}
    password_group_lookup: dict[str, str] = {}
    entries = []

    for encrypted_name, password in named_passwords.items():
        if password not in password_group_lookup:
            group_id = str(uuid.uuid4())
            password_group_lookup[password] = group_id
            groups[group_id] = {
                "group_id": group_id,
                "label": f"密码组{len(groups) + 1}",
                "verifier": build_password_verifier(password),
            }
        group_id = password_group_lookup[password]
        entries.append(
            {
                "encrypted_name": encrypted_name,
                "group_id": group_id,
            }
        )

    return {
        "version": 1,
        "mode": mode,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "groups": list(groups.values()),
        "entries": entries,
    }


def manifest_group_map(manifest: dict) -> dict[str, dict]:
    return {group["group_id"]: group for group in manifest.get("groups", [])}


def manifest_entry_map(manifest: dict) -> dict[str, dict]:
    return {entry["encrypted_name"]: entry for entry in manifest.get("entries", [])}


def export_password_table(
    rows: list[dict[str, str]],
    main_password: str,
    output_path: str | None = None,
) -> str | None:
    unique_passwords = {row["password"] for row in rows}
    if len(unique_passwords) <= 1:
        return None

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["source_file", "source_scope", "source_type", "encrypted_name", "password"])
    for row in rows:
        writer.writerow([
            row["source_file"],
            row.get("source_scope", ""),
            row.get("source_type", "root"),
            row["encrypted_name"],
            row["password"],
        ])

    blob = encrypt_bytes(buffer.getvalue().encode("utf-8"), main_password)
    target_path = output_path or build_password_table_output_path([row["source_path"] for row in rows])
    with open(target_path, "wb") as file_obj:
        file_obj.write(blob)
    return target_path


def export_password_template(rows: list[dict[str, str]], output_path: str | None = None) -> str:
    target_path = output_path or build_password_template_path([row["source_path"] for row in rows])
    with open(target_path, "w", encoding="utf-8-sig", newline="") as file_obj:
        writer = csv.writer(file_obj)
        writer.writerow(["source_file", "source_scope", "source_type", "password"])
        for row in rows:
            writer.writerow([row["source_file"], row.get("source_scope", ""), row.get("source_type", "root"), row["password"]])
    return target_path


def export_encrypted_password_template(
    rows: list[dict[str, str]],
    password: str,
    output_path: str | None = None,
) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["source_file", "source_scope", "source_type", "password"])
    for row in rows:
        writer.writerow([
            row["source_file"],
            row.get("source_scope", ""),
            row.get("source_type", "root"),
            row["password"],
        ])

    blob = encrypt_bytes(buffer.getvalue().encode("utf-8"), password)
    target_path = output_path or (build_password_template_path([row["source_path"] for row in rows]) + ".gcm")
    with open(target_path, "wb") as file_obj:
        file_obj.write(blob)
    return target_path


def build_template_password_rows(
    source_paths: list[str],
    password_map: dict[str, str],
    batch_mode: str,
    folder_individual_encrypt_map: dict[str, set[str]] | None = None,
    folder_child_password_map: dict[str, str] | None = None,
    export_marked_folder_children_only: bool = False,
) -> list[dict[str, str]]:
    folder_individual_encrypt_map = folder_individual_encrypt_map or {}
    folder_child_password_map = folder_child_password_map or {}
    rows = []
    for index, source in enumerate(source_paths, start=1):
        source_output_name = os.path.basename(get_source_encrypted_output_path(source))
        if batch_mode == "bundle_encrypt" and len(source_paths) > 1:
            encrypted_name = f"{index:03d}_{source_output_name}"
        else:
            encrypted_name = source_output_name
        rows.append(
            {
                "source_path": source,
                "source_file": os.path.basename(source),
                "source_scope": "",
                "source_type": "folder" if os.path.isdir(source) else "root",
                "encrypted_name": encrypted_name,
                "password": password_map.get(source, ""),
            }
        )
        if os.path.isdir(source):
            if export_marked_folder_children_only:
                child_paths = sorted(folder_individual_encrypt_map.get(source, set()))
            else:
                child_paths = iter_folder_files(source)
            for child_path in child_paths:
                rows.append(
                    {
                        "source_path": child_path,
                        "source_file": folder_child_relative_path(source, child_path),
                        "source_scope": folder_child_scope(source),
                        "source_type": "folder_child",
                        "encrypted_name": folder_child_encrypted_name(source, child_path),
                        "password": folder_child_password_map.get(child_path, "") if child_path in folder_individual_encrypt_map.get(source, set()) else "",
                    }
                )
    return rows


def build_folder_child_password_rows(
    folder_path: str,
    folder_password: str,
    folder_individual_encrypt_map: dict[str, set[str]] | None = None,
    folder_child_password_map: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    rows = []
    for child_path in sorted((folder_individual_encrypt_map or {}).get(folder_path, set())):
        rows.append(
            {
                "source_path": child_path,
                "source_file": folder_child_relative_path(folder_path, child_path),
                "source_scope": folder_child_scope(folder_path),
                "source_type": "folder_child",
                "encrypted_name": folder_child_encrypted_name(folder_path, child_path),
                "password": (folder_child_password_map or {}).get(child_path, folder_password),
            }
        )
    return [row for row in rows if row["password"]]


def extract_zip_to_directory(zip_path: str) -> str:
    target_dir = os.path.splitext(zip_path)[0] + "_unzipped"
    os.makedirs(target_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        safe_extract_zip(zip_file, target_dir)
    return target_dir


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return (mode & 0o170000) == 0o120000


def safe_extract_zip(zip_file: zipfile.ZipFile, target_dir: str) -> None:
    target_root = os.path.abspath(target_dir)
    for info in zip_file.infolist():
        member_name = info.filename.replace("\\", "/")
        if not member_name or member_name.endswith("/"):
            continue
        if member_name.startswith("/") or member_name.startswith("\\"):
            raise ValueError(f"压缩包包含非法绝对路径: {info.filename}")
        if len(member_name) >= 2 and member_name[1] == ":":
            raise ValueError(f"压缩包包含非法盘符路径: {info.filename}")
        parts = [part for part in member_name.split("/") if part not in ("", ".")]
        if any(part == ".." for part in parts):
            raise ValueError(f"压缩包包含非法跳目录路径: {info.filename}")
        if _is_zip_symlink(info):
            raise ValueError(f"压缩包包含不受支持的符号链接: {info.filename}")

        destination = os.path.abspath(os.path.join(target_root, *parts))
        if os.path.commonpath([target_root, destination]) != target_root:
            raise ValueError(f"压缩包条目越界: {info.filename}")

        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with zip_file.open(info, "r") as source, open(destination, "wb") as target:
            shutil.copyfileobj(source, target)


def discover_inner_gcm_files(directory: str) -> list[str]:
    result = []
    for root, _, files in os.walk(directory):
        for name in files:
            if name.endswith(".gcm"):
                result.append(os.path.join(root, name))
    return sorted(result)


def discover_manifest_in_directory(directory: str) -> str | None:
    for root, _, files in os.walk(directory):
        for name in files:
            if name in ("batch_manifest.json.gcm", "batch_manifest.json"):
                return os.path.join(root, name)
    return None


def encrypt_files_individually(
    paths: list[str],
    password_map: dict[str, str],
    main_password: str,
    folder_individual_encrypt_map: dict[str, set[str]] | None = None,
    folder_child_password_map: dict[str, str] | None = None,
    keep_source: bool = True,
    overwrite: bool = False,
    progress_callback=None,
) -> tuple[list[str], str, str | None]:
    results = []
    total = len(paths)
    if total == 0:
        raise ValueError("未选择文件")

    for index, path in enumerate(paths, start=1):
        start = int(((index - 1) / total) * 100)
        end = int((index / total) * 100)
        _report_progress(progress_callback, max(start, 1), f"正在处理第 {index}/{total} 个文件")

        def item_progress(value: int, message: str) -> None:
            scaled = start + int((end - start) * value / 100)
            _report_progress(progress_callback, scaled, f"[{index}/{total}] {message}")

        if os.path.isdir(path):
            results.append(
                encrypt_folder(
                    path,
                    password_map[path],
                    individually_encrypt_files=(folder_individual_encrypt_map or {}).get(path, set()),
                    child_password_map=folder_child_password_map,
                    progress_callback=item_progress,
                    keep_source=keep_source,
                    overwrite=overwrite,
                )
            )
        else:
            results.append(
                encrypt_file(
                    path,
                    password_map[path],
                    progress_callback=item_progress,
                    keep_source=keep_source,
                    overwrite=overwrite,
                )
            )
    output_password_map = {output: password_map[source] for source, output in zip(paths, results)}
    manifest = build_manifest_for_batch(results, output_password_map, mode="individual_batch")
    manifest_path = save_manifest(manifest, build_manifest_path(paths), main_password)
    password_rows = [
        {
            "source_path": source,
            "source_file": os.path.basename(source),
            "source_scope": "",
            "source_type": "folder" if os.path.isdir(source) else "root",
            "encrypted_name": os.path.basename(output),
            "password": password_map[source],
        }
        for source, output in zip(paths, results)
    ]
    for source, output in zip(paths, results):
        if not os.path.isdir(source):
            continue
        for child_path in sorted((folder_individual_encrypt_map or {}).get(source, set())):
            password_rows.append(
                {
                    "source_path": child_path,
                    "source_file": folder_child_relative_path(source, child_path),
                    "source_scope": folder_child_scope(source),
                    "source_type": "folder_child",
                    "encrypted_name": folder_child_encrypted_name(source, child_path),
                    "password": (folder_child_password_map or {}).get(child_path, password_map[source]),
                }
            )
    password_rows = [row for row in password_rows if row["password"]]
    password_table_path = export_password_table(password_rows, main_password)
    _report_progress(progress_callback, 100, f"批量加密完成，共 {total} 个文件")
    return results, manifest_path, password_table_path


def decrypt_files_individually(
    paths: list[str],
    password_map: dict[str, str],
    keep_source: bool = True,
    progress_callback=None,
) -> list[str]:
    results = []
    total = len(paths)
    if total == 0:
        raise ValueError("未选择文件")

    for index, path in enumerate(paths, start=1):
        start = int(((index - 1) / total) * 100)
        end = int((index / total) * 100)
        _report_progress(progress_callback, max(start, 1), f"正在处理第 {index}/{total} 个文件")

        def item_progress(value: int, message: str) -> None:
            scaled = start + int((end - start) * value / 100)
            _report_progress(progress_callback, scaled, f"[{index}/{total}] {message}")

        results.append(
            decrypt_file(
                path,
                password_map[path],
                progress_callback=item_progress,
                keep_source=keep_source,
            )
        )
    _report_progress(progress_callback, 100, f"批量解密完成，共 {total} 个文件")
    return results


def encrypt_files_bundle(
    paths: list[str],
    file_password_map: dict[str, str],
    bundle_password: str,
    main_password: str,
    folder_individual_encrypt_map: dict[str, set[str]] | None = None,
    folder_child_password_map: dict[str, str] | None = None,
    keep_source: bool = True,
    overwrite: bool = False,
    output_path: str | None = None,
    progress_callback=None,
) -> tuple[str, str | None]:
    if not paths:
        raise ValueError("未选择文件")

    bundle_path = output_path or build_bundle_output_path(paths)
    if os.path.exists(bundle_path) and not overwrite:
        raise FileExistsError(bundle_path)

    with tempfile.TemporaryDirectory(prefix="aes_batch_") as temp_dir:
        encrypted_dir = os.path.join(temp_dir, "encrypted")
        os.makedirs(encrypted_dir, exist_ok=True)
        total = len(paths)

        for index, path in enumerate(paths, start=1):
            target_name = f"{index:03d}_{os.path.basename(get_source_encrypted_output_path(path))}"
            target_path = os.path.join(encrypted_dir, target_name)
            start = int(((index - 1) / total) * 55)
            end = int((index / total) * 55)

            def item_progress(value: int, message: str) -> None:
                scaled = start + int((end - start) * value / 100)
                _report_progress(progress_callback, scaled, f"[{index}/{total}] {message}")

            _report_progress(progress_callback, max(start, 1), f"正在预加密第 {index}/{total} 个文件")
            if os.path.isdir(path):
                with tempfile.TemporaryDirectory(prefix="aes_bundle_folder_") as folder_temp_dir:
                    archive_path = build_folder_package(
                        path,
                        file_password_map[path],
                        individually_encrypt_files=(folder_individual_encrypt_map or {}).get(path, set()),
                        child_password_map=folder_child_password_map,
                        staging_root=folder_temp_dir,
                    )
                    with open(archive_path, "rb") as file_obj:
                        blob = encrypt_bytes(file_obj.read(), file_password_map[path])
            else:
                with open(path, "rb") as file_obj:
                    blob = encrypt_bytes(file_obj.read(), file_password_map[path])
            with open(target_path, "wb") as file_obj:
                file_obj.write(blob)
            item_progress(100, "单文件加密完成")

        inner_outputs = [
            os.path.join(encrypted_dir, f"{index:03d}_{os.path.basename(get_source_encrypted_output_path(path))}")
            for index, path in enumerate(paths, start=1)
        ]
        inner_password_map = {
            os.path.join(encrypted_dir, f"{index:03d}_{os.path.basename(get_source_encrypted_output_path(path))}"): file_password_map[path]
            for index, path in enumerate(paths, start=1)
        }
        manifest = build_manifest_for_batch(inner_outputs, inner_password_map, mode="bundle_inner_batch")
        save_manifest(manifest, os.path.join(encrypted_dir, "batch_manifest.json.gcm"), main_password)

        _report_progress(progress_callback, 60, "正在打包已加密文件")
        zip_path = os.path.join(temp_dir, "encrypted_files.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
            for name in sorted(os.listdir(encrypted_dir)):
                source = os.path.join(encrypted_dir, name)
                zip_file.write(source, arcname=name)

        _report_progress(progress_callback, 80, "正在对压缩包执行二次加密")
        with open(zip_path, "rb") as file_obj:
            final_blob = encrypt_bytes(file_obj.read(), bundle_password)
        with open(bundle_path, "wb") as file_obj:
            file_obj.write(final_blob)

    if not keep_source:
        _report_progress(progress_callback, 92, "正在普通删除原始文件")
        for path in paths:
            if os.path.exists(path):
                os.remove(path)

    password_rows = [
        {
            "source_path": source,
            "source_file": os.path.basename(source),
            "source_scope": "",
            "source_type": "folder" if os.path.isdir(source) else "root",
            "encrypted_name": f"{index:03d}_{os.path.basename(get_source_encrypted_output_path(source))}",
            "password": file_password_map[source],
        }
        for index, source in enumerate(paths, start=1)
    ]
    for source in paths:
        if not os.path.isdir(source):
            continue
        for child_path in sorted((folder_individual_encrypt_map or {}).get(source, set())):
            password_rows.append(
                {
                    "source_path": child_path,
                    "source_file": folder_child_relative_path(source, child_path),
                    "source_scope": folder_child_scope(source),
                    "source_type": "folder_child",
                    "encrypted_name": folder_child_encrypted_name(source, child_path),
                    "password": (folder_child_password_map or {}).get(child_path, file_password_map[source]),
                }
            )
    password_rows = [row for row in password_rows if row["password"]]
    password_table_path = export_password_table(password_rows, main_password)
    _report_progress(progress_callback, 100, "批量打包加密完成")
    return bundle_path, password_table_path


def run_cli() -> None:
    print("1. 文本加密")
    print("2. 文本解密")
    print("3. 文件加密")
    print("4. 文件解密")

    choice = input("选择操作: ").strip()
    password = getpass("输入密码: ")

    if choice == "1":
        text = input("输入明文: ")
        print("\nBase64 密文:\n")
        print(encrypt_text(text, password))
    elif choice == "2":
        ciphertext = input("输入 Base64 密文: ").strip()
        print("\n解密结果:\n")
        print(decrypt_text(ciphertext, password))
    elif choice == "3":
        path = input("输入文件路径: ").strip().strip('"')
        print(f"已加密: {encrypt_file(path, password, keep_source=True)}")
    elif choice == "4":
        path = input("输入 .gcm 文件路径: ").strip().strip('"')
        print(f"已解密: {decrypt_file(path, password, keep_source=True)}")
    else:
        print("无效选项")


class AESGCMApp:
    def __init__(self, root: tk.Tk) -> None:
        self.clipboard_clear_job = None
        self.root = root
        self.root.title("AES-GCM 加解密工具")
        self.root.geometry("920x700")
        self.root.minsize(820, 620)
        self.root.configure(bg="#f4f1ea")

        self.mode_var = tk.StringVar(value="text_encrypt")
        self.password_var = tk.StringVar()
        self.bundle_password_var = tk.StringVar()
        self.file_path_var = tk.StringVar()
        self.file_summary_var = tk.StringVar()
        self.file_result_var = tk.StringVar()
        self.password_table_var = tk.StringVar()
        self.password_table_input_var = tk.StringVar()
        self.status_var = tk.StringVar(value="就绪")
        self.progress_var = tk.IntVar(value=0)
        self.keep_source_var = tk.BooleanVar(value=True)
        self.batch_mode_var = tk.StringVar(value="individual")
        self.template_marked_children_only_var = tk.BooleanVar(value=True)
        self.action_var = tk.StringVar(value="开始加密")
        self.selected_files: list[str] = []
        self.file_password_overrides: dict[str, str] = {}
        self.file_password_sources: dict[str, str] = {}
        self.file_group_labels: dict[str, str] = {}
        self.folder_individual_encrypt_files: dict[str, set[str]] = {}
        self.folder_child_password_overrides: dict[str, str] = {}
        self.folder_child_password_sources: dict[str, str] = {}
        self.current_manifest_path: str | None = None
        self.password_table_imported = False
        self.plaintext_template_paths: set[str] = set()
        self.pending_template_delete_path: str | None = None
        self.template_encrypted_copy_path: str | None = None
        self._worker = None
        self.mode_buttons = {}
        self.defer_sensitive_clear = False

        self._build_ui()
        self._refresh_mode()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("App.TFrame", background="#f4f1ea")
        style.configure("Panel.TLabelframe", background="#fbfaf6", borderwidth=1)
        style.configure("Panel.TLabelframe.Label", background="#fbfaf6", foreground="#2b2118", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("Info.TLabel", background="#f4f1ea", foreground="#46362a", font=("Microsoft YaHei UI", 9))
        style.configure("Hint.TLabel", background="#fbfaf6", foreground="#6b5b4f", font=("Microsoft YaHei UI", 9))
        style.configure("Action.TButton", font=("Microsoft YaHei UI", 9, "bold"), padding=(7, 3))
        style.configure("Secondary.TButton", font=("Microsoft YaHei UI", 9), padding=(7, 3))
        style.configure("Accent.Horizontal.TProgressbar", troughcolor="#e7ddd0", background="#198754", bordercolor="#e7ddd0", lightcolor="#198754", darkcolor="#198754")

        container = ttk.Frame(self.root, padding=12, style="App.TFrame")
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=3)
        container.columnconfigure(1, weight=2)

        title = tk.Label(
            container,
            text="AES-GCM 最终版",
            font=("Microsoft YaHei UI", 17, "bold"),
            bg="#f4f1ea",
            fg="#20150d",
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w")

        subtitle = ttk.Label(
            container,
            text="支持文本 Base64 加解密和 .gcm 文件加解密",
            style="Info.TLabel",
        )
        subtitle.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 6))

        self.mode_hint = ttk.Label(
            container,
            text="当前模式：文本加密。输入明文和密码后，点击“开始加密”。",
            style="Info.TLabel",
        )
        self.mode_hint.grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 8))

        mode_frame = ttk.LabelFrame(container, text="快速操作", padding=8, style="Panel.TLabelframe")
        mode_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        mode_frame.columnconfigure(0, weight=1)
        mode_frame.columnconfigure(1, weight=1)

        options = [
            ("文本加密", "text_encrypt"),
            ("文本解密", "text_decrypt"),
            ("文件加密", "file_encrypt"),
            ("文件解密", "file_decrypt"),
        ]
        for index, (text, value) in enumerate(options):
            button = tk.Button(
                mode_frame,
                text=text,
                command=lambda selected=value: self._select_mode(selected),
                font=("Microsoft YaHei UI", 10, "bold"),
                relief="flat",
                bd=0,
                padx=8,
                pady=6,
                cursor="hand2",
            )
            row, col = divmod(index, 2)
            button.grid(row=row, column=col, sticky="ew", padx=3, pady=3)
            self.mode_buttons[value] = button

        self.password_box = ttk.LabelFrame(container, text="密码", padding=8, style="Panel.TLabelframe")
        self.password_box.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        self.password_box.columnconfigure(1, weight=3)

        self.password_label = ttk.Label(self.password_box, text="密码", style="Hint.TLabel")
        self.password_label.grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.password_entry = ttk.Entry(self.password_box, textvariable=self.password_var, show="*", font=("Consolas", 10))
        self.password_entry.grid(row=0, column=1, columnspan=2, sticky="ew")
        self.password_show_button = ttk.Button(self.password_box, text="显示", command=self._toggle_password, style="Secondary.TButton")
        self.password_show_button.grid(row=0, column=3, padx=(8, 0))
        self.password_generate_button = ttk.Button(self.password_box, text="自动生成", command=self._generate_password, style="Secondary.TButton")
        self.password_generate_button.grid(row=0, column=4, padx=(8, 0))
        self.password_copy_button = ttk.Button(self.password_box, text="复制密码", command=self._copy_main_password, style="Secondary.TButton")
        self.password_copy_button.grid(row=0, column=5, padx=(8, 0))
        self.bundle_password_label = ttk.Label(self.password_box, text="打包密码", style="Hint.TLabel")
        self.bundle_password_entry = ttk.Entry(self.password_box, textvariable=self.bundle_password_var, show="*", font=("Consolas", 10))
        self.bundle_password_show_button = ttk.Button(
            self.password_box,
            text="显示",
            command=self._toggle_bundle_password,
            style="Secondary.TButton",
        )
        self.bundle_password_generate_button = ttk.Button(
            self.password_box,
            text="自动生成",
            command=self._generate_bundle_password,
            style="Secondary.TButton",
        )
        self.bundle_password_copy_button = ttk.Button(
            self.password_box,
            text="复制密码",
            command=self._copy_bundle_password,
            style="Secondary.TButton",
        )

        self.action_box = ttk.LabelFrame(container, text="操作", padding=6, style="Panel.TLabelframe")
        self.action_box.grid(row=4, column=1, padx=(12, 0), pady=(8, 0), sticky="nsew")
        self.action_box.columnconfigure(0, weight=1)
        self.action_box.columnconfigure(1, weight=1)
        self.run_button = ttk.Button(self.action_box, textvariable=self.action_var, command=self._execute, style="Action.TButton")
        self.run_button.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Button(self.action_box, text="复制", command=self._copy_output, style="Secondary.TButton").grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(self.action_box, text="清空", command=self._clear_all, style="Secondary.TButton").grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(6, 0))

        self.file_frame = ttk.LabelFrame(container, text="文件", padding=8, style="Panel.TLabelframe")
        self.file_frame.columnconfigure(0, weight=1)

        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_summary_var, font=("Consolas", 10))
        self.file_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(self.file_frame, text="选择文件", command=self._browse_file, style="Secondary.TButton").grid(row=0, column=1, padx=(8, 0))
        ttk.Button(self.file_frame, text="选择文件夹", command=self._browse_folder, style="Secondary.TButton").grid(row=0, column=2, padx=(8, 0))
        ttk.Button(
            self.file_frame,
            text="查看已选内容",
            command=self._show_selected_files,
            style="Secondary.TButton",
        ).grid(row=0, column=3, padx=(8, 0))
        ttk.Checkbutton(self.file_frame, text="保留原文件", variable=self.keep_source_var).grid(row=0, column=4, padx=(10, 0))
        self.drop_hint = ttk.Label(self.file_frame, text="可拖拽文件或文件夹到路径输入框", style="Hint.TLabel")
        self.drop_hint.grid(row=1, column=0, columnspan=5, sticky="w", pady=(4, 0))
        self.delete_hint = ttk.Label(
            self.file_frame,
            text="关闭“保留原文件”后仅执行普通删除，不等于安全擦除，文件仍可能被恢复。",
            style="Hint.TLabel",
        )
        self.delete_hint.grid(row=2, column=0, columnspan=5, sticky="w", pady=(4, 0))
        self.batch_mode_frame = ttk.Frame(self.file_frame, style="App.TFrame")
        self.batch_mode_frame.grid(row=3, column=0, columnspan=5, sticky="w", pady=(6, 0))
        ttk.Label(self.batch_mode_frame, text="批量策略", style="Hint.TLabel").grid(row=0, column=0, padx=(0, 8))
        ttk.Radiobutton(
            self.batch_mode_frame,
            text="逐个加密输出",
            value="individual",
            variable=self.batch_mode_var,
            command=self._refresh_mode,
        ).grid(row=0, column=1, padx=(0, 8))
        ttk.Radiobutton(
            self.batch_mode_frame,
            text="逐个加密后打包再加密",
            value="bundle_encrypt",
            variable=self.batch_mode_var,
            command=self._refresh_mode,
        ).grid(row=0, column=2)
        self.password_table_frame = ttk.Frame(self.file_frame, style="App.TFrame")
        self.password_table_frame.grid(row=4, column=0, columnspan=5, sticky="ew", pady=(6, 0))
        self.password_table_frame.columnconfigure(1, weight=1)
        self.password_table_title_label = ttk.Label(self.password_table_frame, text="密码表", style="Hint.TLabel")
        self.password_table_title_label.grid(row=0, column=0, padx=(0, 8))
        self.password_table_entry = ttk.Entry(
            self.password_table_frame,
            textvariable=self.password_table_input_var,
            font=("Consolas", 9),
        )
        self.password_table_entry.grid(row=0, column=1, sticky="ew")
        self.password_table_select_button = ttk.Button(
            self.password_table_frame,
            text="选择文件",
            command=self._browse_password_table,
            style="Secondary.TButton",
        )
        self.password_table_select_button.grid(row=0, column=2, padx=(8, 0))
        self.password_table_import_button = ttk.Button(
            self.password_table_frame,
            text="导入",
            command=self._import_password_table,
            style="Secondary.TButton",
        )
        self.password_table_import_button.grid(row=0, column=3, padx=(8, 0))
        self.password_table_export_button = ttk.Button(
            self.password_table_frame,
            text="导出加密模板",
            command=self._export_password_template,
            style="Secondary.TButton",
        )
        self.password_template_plain_button = ttk.Button(
            self.password_table_frame,
            text="高级: 明文模板",
            command=self._export_plaintext_template,
            style="Secondary.TButton",
        )
        self.password_table_hint = ttk.Label(
            self.password_table_frame,
            text="可先选择或拖入加密密码表；解压内部批量文件后可自动导入并继续解密。",
            style="Hint.TLabel",
        )
        self.password_table_hint.grid(row=1, column=0, columnspan=4, sticky="w", pady=(4, 0))
        self.template_scope_check = ttk.Checkbutton(
            self.password_table_frame,
            text="模板仅导出已标记单独加密的文件夹内文件",
            variable=self.template_marked_children_only_var,
        )
        self.template_scope_check.grid(row=2, column=0, columnspan=6, sticky="w", pady=(4, 0))
        self.password_table_entry.drop_target_register(DND_FILES)
        self.password_table_entry.dnd_bind("<<Drop>>", self._handle_password_table_drop)
        self.file_entry.drop_target_register(DND_FILES)
        self.file_entry.dnd_bind("<<Drop>>", self._handle_drop)

        self.quick_hint = ttk.Label(
            container,
            text="先选择模式，再输入密码和内容，最后点击左侧主按钮。",
            style="Hint.TLabel",
        )
        self.quick_hint.grid(row=6, column=0, columnspan=2, sticky="w", pady=(6, 0))

        self.input_frame = ttk.LabelFrame(container, text="输入", padding=8, style="Panel.TLabelframe")
        self.input_frame.grid(row=7, column=0, sticky="nsew", pady=(8, 0), padx=(0, 6))
        self.input_frame.rowconfigure(0, weight=1)
        self.input_frame.columnconfigure(0, weight=1)

        self.input_text = tk.Text(
            self.input_frame,
            wrap="word",
            font=("Consolas", 11),
            undo=True,
            height=20,
            bg="#fffdf9",
            fg="#1f2933",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.input_text.grid(row=0, column=0, sticky="nsew")

        self.output_frame = ttk.LabelFrame(container, text="输出", padding=8, style="Panel.TLabelframe")
        self.output_frame.grid(row=7, column=1, sticky="nsew", pady=(8, 0), padx=(6, 0))
        self.output_frame.rowconfigure(0, weight=1)
        self.output_frame.columnconfigure(0, weight=1)

        self.output_text = tk.Text(
            self.output_frame,
            wrap="word",
            font=("Consolas", 10),
            height=12,
            bg="#fffdf9",
            fg="#1f2933",
            relief="flat",
            padx=10,
            pady=10,
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")

        self.file_progress_frame = ttk.LabelFrame(container, text="文件处理进度", padding=12, style="Panel.TLabelframe")
        self.file_progress_frame.columnconfigure(0, weight=1)
        self.file_progress_frame.rowconfigure(4, weight=1)
        self.file_progress_label = ttk.Label(
            self.file_progress_frame,
            text="选择文件并点击上方主按钮后，这里会显示处理进度。",
            style="Info.TLabel",
        )
        self.file_progress_label.grid(row=0, column=0, sticky="w")
        self.file_progress_bar = ttk.Progressbar(
            self.file_progress_frame,
            mode="determinate",
            maximum=100,
            variable=self.progress_var,
            style="Accent.Horizontal.TProgressbar",
        )
        self.file_progress_bar.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        self.file_result_label = ttk.Label(self.file_progress_frame, text="输出路径", style="Hint.TLabel")
        self.file_result_label.grid(row=2, column=0, sticky="w", pady=(6, 0))
        result_row = ttk.Frame(self.file_progress_frame, style="App.TFrame")
        result_row.grid(row=3, column=0, sticky="ew", pady=(4, 0))
        result_row.columnconfigure(0, weight=1)
        self.file_result_entry = ttk.Entry(
            result_row,
            textvariable=self.file_result_var,
            font=("Consolas", 10),
            state="readonly",
        )
        self.file_result_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(
            result_row,
            text="打开所在目录",
            command=self._open_result_folder,
            style="Secondary.TButton",
        ).grid(row=0, column=1, padx=(10, 0))
        password_table_row = ttk.Frame(self.file_progress_frame, style="App.TFrame")
        password_table_row.grid(row=4, column=0, sticky="ew", pady=(6, 0))
        password_table_row.columnconfigure(1, weight=1)
        ttk.Label(password_table_row, text="密码表", style="Hint.TLabel").grid(row=0, column=0, padx=(0, 8))
        self.password_table_result_entry = ttk.Entry(
            password_table_row,
            textvariable=self.password_table_var,
            font=("Consolas", 9),
            state="readonly",
        )
        self.password_table_result_entry.grid(row=0, column=1, sticky="ew")
        ttk.Button(
            password_table_row,
            text="打开密码表",
            command=self._open_password_table,
            style="Secondary.TButton",
        ).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(
            password_table_row,
            text="复制密码表路径",
            command=self._copy_password_table_path,
            style="Secondary.TButton",
        ).grid(row=0, column=3, padx=(8, 0))

        progress_frame = ttk.Frame(container, style="App.TFrame")
        progress_frame.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        progress_frame.columnconfigure(0, weight=1)

        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode="determinate",
            maximum=100,
            variable=self.progress_var,
            style="Accent.Horizontal.TProgressbar",
        )
        self.progress_bar.grid(row=0, column=0, sticky="ew")

        status_bar = ttk.Label(container, textvariable=self.status_var, style="Info.TLabel")
        status_bar.grid(row=9, column=0, columnspan=2, sticky="w", pady=(6, 0))

        container.rowconfigure(7, weight=1)

    def _toggle_password(self) -> None:
        current = self.password_entry.cget("show")
        self.password_entry.configure(show="" if current == "*" else "*")

    def _toggle_bundle_password(self) -> None:
        current = self.bundle_password_entry.cget("show")
        self.bundle_password_entry.configure(show="" if current == "*" else "*")

    def _generate_password(self) -> None:
        password = generate_random_password()
        self.password_var.set(password)
        self.password_entry.configure(show="")
        messagebox.showinfo(
            "已生成随机密码",
            "系统已生成一个随机高强度密码。\n\n如需复制，请点击“复制密码”。请妥善保存，否则后续将无法解密。",
        )
        self.status_var.set("已生成随机密码")

    def _generate_bundle_password(self) -> None:
        password = generate_random_password()
        self.bundle_password_var.set(password)
        self.bundle_password_entry.configure(show="")
        messagebox.showinfo(
            "已生成打包密码",
            "系统已生成打包层随机密码。\n\n如需复制，请点击“复制密码”。请妥善保存，否则后续将无法解开最终打包密文。",
        )
        self.status_var.set("已生成打包密码")

    def _copy_main_password(self) -> None:
        password = self.password_var.get()
        if not password:
            messagebox.showinfo("提示", "当前没有可复制的主密码")
            return
        self._copy_sensitive_to_clipboard(password, "主密码已复制到剪贴板，30 秒后将自动清空")

    def _copy_bundle_password(self) -> None:
        password = self.bundle_password_var.get()
        if not password:
            messagebox.showinfo("提示", "当前没有可复制的打包密码")
            return
        self._copy_sensitive_to_clipboard(password, "打包密码已复制到剪贴板，30 秒后将自动清空")

    def _copy_sensitive_to_clipboard(self, value: str, status_message: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self._schedule_clipboard_clear()
        self.status_var.set(status_message)

    def _schedule_clipboard_clear(self, delay_ms: int = 30000) -> None:
        if self.clipboard_clear_job is not None:
            self.root.after_cancel(self.clipboard_clear_job)
        self.clipboard_clear_job = self.root.after(delay_ms, self._clear_clipboard_if_possible)

    def _clear_clipboard_if_possible(self) -> None:
        self.clipboard_clear_job = None
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            return
        if "剪贴板" in self.status_var.get():
            self.status_var.set("剪贴板已自动清空")

    def _clear_sensitive_state(self) -> None:
        self.password_var.set("")
        self.bundle_password_var.set("")
        self.file_password_overrides = {}
        self.file_password_sources = {path: "main" for path in self.selected_files}
        self.folder_child_password_overrides = {}
        self.folder_child_password_sources = {}
        self.password_table_imported = False

    def _on_close(self) -> None:
        existing_plaintext = sorted(path for path in self.plaintext_template_paths if os.path.exists(path))
        if existing_plaintext:
            preview = "\n".join(existing_plaintext[:3])
            suffix = "\n..." if len(existing_plaintext) > 3 else ""
            confirmed = messagebox.askyesno(
                "发现明文模板",
                f"退出前发现仍未清理的明文模板：\n{preview}{suffix}\n\n这些文件可能直接包含密码。是否仍然退出？",
            )
            if not confirmed:
                return
        self.root.destroy()

    def _browse_file(self) -> None:
        mode = self.mode_var.get()
        if mode == "file_decrypt":
            paths = filedialog.askopenfilenames(
                title="选择 .gcm 文件",
                filetypes=[("GCM Files", "*.gcm"), ("All Files", "*.*")],
            )
        else:
            paths = filedialog.askopenfilenames(title="选择文件")
        if paths:
            self._set_selected_files(list(paths))

    def _browse_folder(self) -> None:
        if self.mode_var.get() == "file_decrypt":
            messagebox.showinfo("提示", "文件夹选择仅用于加密模式")
            return
        path = filedialog.askdirectory(title="选择文件夹")
        if path:
            self._set_selected_files(self.selected_files + [path])

    def _browse_password_table(self) -> None:
        if self.mode_var.get() == "file_encrypt":
            path = filedialog.askopenfilename(
                title="选择加密模板、明文模板或密码表",
                filetypes=[("CSV Files", "*.csv"), ("Encrypted CSV", "*.csv.gcm"), ("All Files", "*.*")],
            )
        else:
            path = filedialog.askopenfilename(
                title="选择加密密码表",
                filetypes=[("Encrypted CSV", "*.csv.gcm"), ("GCM Files", "*.gcm"), ("All Files", "*.*")],
            )
        if path:
            self.password_table_input_var.set(path)

    def _export_password_template(self) -> None:
        if not self.selected_files:
            messagebox.showinfo("提示", "请先选择文件")
            return
        main_password = self.password_var.get().strip()
        if not main_password:
            messagebox.showerror("错误", "导出加密模板前请先输入主文件密码")
            return
        password_map = self._build_encryption_password_map(main_password)
        rows = build_template_password_rows(
            self.selected_files,
            password_map,
            self.batch_mode_var.get(),
            folder_individual_encrypt_map=self.folder_individual_encrypt_files,
            folder_child_password_map=self.folder_child_password_overrides,
            export_marked_folder_children_only=self.template_marked_children_only_var.get(),
        )
        path = export_encrypted_password_template(rows, main_password)
        refresh_explorer(path)
        self.password_table_input_var.set(path)
        self.status_var.set("已导出加密模板")
        messagebox.showinfo("已导出加密模板", f"加密模板已生成：\n{path}")

    def _export_plaintext_template(self) -> None:
        if not self.selected_files:
            messagebox.showinfo("提示", "请先选择文件")
            return
        confirmed = messagebox.askyesno(
            "导出明文模板",
            "明文模板会直接包含文件密码，存在明显隐私风险。\n\n是否继续导出高级明文模板？",
        )
        if not confirmed:
            return
        rows = build_template_password_rows(
            self.selected_files,
            self._build_encryption_password_map(self.password_var.get()),
            self.batch_mode_var.get(),
            folder_individual_encrypt_map=self.folder_individual_encrypt_files,
            folder_child_password_map=self.folder_child_password_overrides,
            export_marked_folder_children_only=self.template_marked_children_only_var.get(),
        )
        path = export_password_template(rows)
        self.plaintext_template_paths.add(path)
        refresh_explorer(path)
        self.password_table_input_var.set(path)
        self.status_var.set("已导出明文模板，请尽快填写并导回")
        messagebox.showinfo("已导出明文模板", f"明文模板已生成：\n{path}\n\n系统不会自动打开该文件，请在编辑后尽快导回并清理。")

    def _handle_drop(self, event) -> None:
        paths = self.root.tk.splitlist(event.data)
        if not paths:
            return
        self._set_selected_files(list(paths))
        self.status_var.set(f"已接收 {len(self.selected_files)} 个拖拽文件")

    def _handle_password_table_drop(self, event) -> None:
        paths = self.root.tk.splitlist(event.data)
        if not paths:
            return
        self.password_table_input_var.set(paths[0].strip().strip('"'))
        self.status_var.set("已接收密码表/模板文件")

    def _set_selected_files(self, paths: list[str]) -> None:
        normalized = []
        for path in paths:
            cleaned = path.strip().strip('"')
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)
        self.selected_files = normalized
        self.file_password_overrides = {path: self.file_password_overrides.get(path, "") for path in normalized}
        self.file_password_sources = {path: self.file_password_sources.get(path, "main") for path in normalized}
        self.folder_individual_encrypt_files = {
            path: {item for item in self.folder_individual_encrypt_files.get(path, set()) if os.path.isfile(item)}
            for path in normalized
            if os.path.isdir(path)
        }
        valid_children = {
            item
            for folder, items in self.folder_individual_encrypt_files.items()
            for item in items
        }
        self.folder_child_password_overrides = {
            path: self.folder_child_password_overrides.get(path, "")
            for path in valid_children
            if self.folder_child_password_overrides.get(path, "")
        }
        self.folder_child_password_sources = {
            path: self.folder_child_password_sources.get(path, "manual")
            for path in valid_children
            if path in self.folder_child_password_sources
        }
        self.file_group_labels = {}
        self.current_manifest_path = None
        self.password_table_imported = False
        self.pending_template_delete_path = None
        self.template_encrypted_copy_path = None
        first_path = normalized[0] if normalized else ""
        self.file_path_var.set(first_path)
        self.file_summary_var.set(summarize_paths(normalized))
        self._refresh_mode()

    def _remove_selected_indices(self, indices: list[int]) -> None:
        if not indices:
            return
        remaining = [path for idx, path in enumerate(self.selected_files) if idx not in set(indices)]
        self._set_selected_files(remaining)

    def _is_folder_child_item(self, item_id: str) -> bool:
        return item_id.startswith("folder-child::")

    def _folder_child_item_id(self, path: str) -> str:
        return f"folder-child::{path}"

    def _folder_child_path(self, item_id: str) -> str:
        return item_id.split("::", 1)[1]

    def _find_parent_folder_for_child(self, child_path: str) -> str | None:
        normalized_child = os.path.normpath(child_path)
        for folder in self.selected_files:
            if os.path.isdir(folder):
                normalized_folder = os.path.normpath(folder)
                try:
                    common = os.path.commonpath([normalized_folder, normalized_child])
                except ValueError:
                    continue
                if common == normalized_folder:
                    return folder
        return None

    def _build_selected_folder_child_lookup(self) -> dict[tuple[str, str], str]:
        lookup = {}
        for folder in self.selected_files:
            if not os.path.isdir(folder):
                continue
            scope = folder_child_scope(folder)
            for child_path in iter_folder_files(folder):
                lookup[(scope, folder_child_relative_path(folder, child_path))] = child_path
        return lookup

    def _child_password_for(self, child_path: str, folder_path: str | None = None) -> str:
        if child_path in self.folder_child_password_overrides:
            return self.folder_child_password_overrides[child_path]
        if folder_path is None:
            folder_path = self._find_parent_folder_for_child(child_path)
        if folder_path:
            return self.file_password_overrides.get(folder_path) or self.password_var.get()
        return self.password_var.get()

    def _load_manifest_for_selected_files(self) -> dict | None:
        password = self.password_var.get().strip() or None
        manifest_path = self.current_manifest_path or find_manifest_for_files(self.selected_files, password=password)
        if not manifest_path:
            self.current_manifest_path = None
            self.file_group_labels = {}
            return None
        try:
            manifest = load_manifest(manifest_path, password=password)
        except Exception:
            self.current_manifest_path = None
            self.file_group_labels = {}
            return None
        self.current_manifest_path = manifest_path
        entry_map = manifest_entry_map(manifest)
        group_map = manifest_group_map(manifest)
        self.file_group_labels = {}
        common_dir = get_common_directory(self.selected_files)
        for path in self.selected_files:
            relative_name = to_posix_path(os.path.relpath(path, common_dir)) if common_dir else os.path.basename(path)
            entry = entry_map.get(relative_name) or entry_map.get(os.path.basename(path))
            if entry:
                group = group_map.get(entry["group_id"], {})
                self.file_group_labels[path] = group.get("label", entry["group_id"])
        return manifest

    def _build_encryption_password_map(self, default_password: str) -> dict[str, str]:
        return {
            path: self.file_password_overrides.get(path) or default_password
            for path in self.selected_files
        }

    def _build_decryption_password_map(self, default_password: str) -> tuple[dict[str, str], dict | None]:
        manifest = self._load_manifest_for_selected_files()
        if not manifest:
            return {path: self.file_password_overrides.get(path) or default_password for path in self.selected_files}, None

        entry_map = manifest_entry_map(manifest)
        group_map = manifest_group_map(manifest)
        resolved = {}
        common_dir = get_common_directory(self.selected_files)
        for path in self.selected_files:
            relative_name = to_posix_path(os.path.relpath(path, common_dir)) if common_dir else os.path.basename(path)
            entry = entry_map.get(relative_name) or entry_map.get(os.path.basename(path))
            if not entry:
                resolved[path] = self.file_password_overrides.get(path) or default_password
                continue
            group = group_map.get(entry["group_id"], {})
            password = self.file_password_overrides.get(path) or default_password
            if not password or not verify_password_verifier(password, group["verifier"]):
                raise ValueError(f"文件 {os.path.basename(path)} 的密码未设置或不正确")
            resolved[path] = password
        return resolved, manifest

    def _select_mode(self, mode: str) -> None:
        self.mode_var.set(mode)
        self._refresh_mode()

    def _open_result_folder(self) -> None:
        path = self.file_result_var.get().strip()
        if not path:
            messagebox.showinfo("提示", "当前没有结果路径")
            return
        target = path if os.path.isdir(path) else os.path.dirname(path)
        if not target or not os.path.isdir(target):
            messagebox.showerror("错误", "结果目录不存在")
            return
        os.startfile(target)

    def _open_password_table(self) -> None:
        path = self.password_table_var.get().strip()
        if not path:
            messagebox.showinfo("提示", "当前没有密码表路径")
            return
        if not os.path.exists(path):
            messagebox.showerror("错误", "密码表文件不存在")
            return
        os.startfile(path)

    def _copy_password_table_path(self) -> None:
        path = self.password_table_var.get().strip()
        if not path:
            messagebox.showinfo("提示", "当前没有密码表路径")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        self.status_var.set("密码表路径已复制到剪贴板")

    def _import_password_table_file(self, path: str, main_password: str) -> int:
        with open(path, "rb") as file_obj:
            blob = file_obj.read()
        try:
            csv_text = decrypt_bytes(blob, main_password).decode("utf-8")
        except Exception:
            password = simpledialog.askstring(
                "密码表密码",
                "当前密码表不是由主文件密码加密。\n请输入密码表密码：",
                show="*",
                parent=self.root,
            )
            if not password:
                raise ValueError("未提供密码表密码")
            csv_text = decrypt_bytes(blob, password).decode("utf-8")

        reader = csv.DictReader(io.StringIO(csv_text))
        imported = 0
        by_name = {os.path.basename(file_path): file_path for file_path in self.selected_files}
        common_dir = get_common_directory(self.selected_files)
        by_relative_name = {
            to_posix_path(os.path.relpath(file_path, common_dir)): file_path
            for file_path in self.selected_files
            if common_dir and os.path.exists(file_path)
        }
        folder_child_lookup = self._build_selected_folder_child_lookup()
        for row in reader:
            file_name = row.get("source_file", "").strip()
            source_scope = row.get("source_scope", "").strip()
            source_type = row.get("source_type", "").strip()
            encrypted_name = row.get("encrypted_name", "").strip()
            password = row.get("password", "")
            matched_path = (
                by_relative_name.get(to_posix_path(encrypted_name))
                or by_name.get(encrypted_name)
                or by_name.get(file_name)
            )
            if matched_path:
                self.file_password_overrides[matched_path] = password
                self.file_password_sources[matched_path] = "manual"
                imported += 1
                continue
            if source_type == "folder_child":
                child_path = folder_child_lookup.get((source_scope, to_posix_path(file_name)))
                if child_path and password:
                    folder = self._find_parent_folder_for_child(child_path)
                    if folder:
                        self.folder_individual_encrypt_files.setdefault(folder, set()).add(child_path)
                    self.folder_child_password_overrides[child_path] = password
                    self.folder_child_password_sources[child_path] = "manual"
                    imported += 1
        if imported:
            self.password_table_imported = True
            self.password_table_input_var.set(path)
        return imported

    def _maybe_encrypt_imported_template(self, path: str) -> None:
        if not path.lower().endswith(".csv"):
            return
        self.plaintext_template_paths.add(path)
        self.pending_template_delete_path = None
        self.template_encrypted_copy_path = None
        template_password = self.password_var.get().strip()
        if not template_password:
            template_password = simpledialog.askstring(
                "模板密码",
                "检测到导入的是明文模板。\n\n请输入用于转换加密模板的密码；若留空将取消自动转换。",
                show="*",
                parent=self.root,
            )
            if not template_password:
                messagebox.showwarning("提示", "未提供模板密码，明文模板仍保留在磁盘，请手动清理。")
                return

        password_map = self._build_encryption_password_map(self.password_var.get())
        rows = build_template_password_rows(
            self.selected_files,
            password_map,
            self.batch_mode_var.get(),
            folder_individual_encrypt_map=self.folder_individual_encrypt_files,
            folder_child_password_map=self.folder_child_password_overrides,
            export_marked_folder_children_only=self.template_marked_children_only_var.get(),
        )
        encrypted_path = export_encrypted_password_template(rows, template_password, output_path=path + ".gcm")
        refresh_explorer(encrypted_path)
        self.template_encrypted_copy_path = encrypted_path
        self.password_table_input_var.set(encrypted_path)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            messagebox.showwarning("明文模板未删除", f"已生成加密模板，但未能删除原明文模板：\n{path}\n\n请尽快手动清理。")
        else:
            self.plaintext_template_paths.discard(path)
        messagebox.showinfo("模板已加密", f"已生成加密模板：\n{encrypted_path}\n\n系统已默认尝试删除原明文模板。")

    def _import_password_template_file(self, path: str) -> int:
        with open(path, "r", encoding="utf-8-sig") as file_obj:
            csv_text = file_obj.read()

        reader = csv.DictReader(io.StringIO(csv_text))
        imported = 0
        by_name = {os.path.basename(file_path): file_path for file_path in self.selected_files}
        folder_child_lookup = self._build_selected_folder_child_lookup()
        for row in reader:
            file_name = row.get("source_file", "").strip()
            source_scope = row.get("source_scope", "").strip()
            source_type = row.get("source_type", "").strip()
            password = row.get("password", "")
            matched_path = by_name.get(file_name) if not source_scope else None
            if matched_path and password:
                self.file_password_overrides[matched_path] = password
                self.file_password_sources[matched_path] = "manual"
                imported += 1
            elif source_type == "folder_child":
                child_path = folder_child_lookup.get((source_scope, to_posix_path(file_name)))
                if child_path:
                    folder = self._find_parent_folder_for_child(child_path)
                    if password:
                        if folder:
                            self.folder_individual_encrypt_files.setdefault(folder, set()).add(child_path)
                        self.folder_child_password_overrides[child_path] = password
                        self.folder_child_password_sources[child_path] = "manual"
                        imported += 1
                    else:
                        if folder:
                            self.folder_individual_encrypt_files.setdefault(folder, set()).discard(child_path)
                        self.folder_child_password_overrides.pop(child_path, None)
                        self.folder_child_password_sources.pop(child_path, None)
        return imported

    def _import_password_table(self) -> None:
        path = self.password_table_input_var.get().strip()
        if not path:
            messagebox.showinfo("提示", "请先选择密码表文件")
            return
        if not os.path.exists(path):
            messagebox.showerror("错误", "密码表文件不存在")
            return
        if self.mode_var.get() == "file_encrypt" and path.lower().endswith(".csv"):
            try:
                imported = self._import_password_template_file(path)
            except Exception as exc:
                messagebox.showerror("错误", f"密码模板导入失败：{exc}")
                return
            self._maybe_encrypt_imported_template(path)
            if imported:
                self.status_var.set(f"已从模板导入 {imported} 个文件的密码")
                messagebox.showinfo("导入完成", f"已从密码模板导入 {imported} 个文件的密码。")
            else:
                messagebox.showinfo("导入完成", "模板已读取，但没有匹配到带密码的当前文件；系统仍已尝试转存为加密模板并清理原明文文件。")
            return
        if self.mode_var.get() == "file_decrypt" and path.lower().endswith(".csv"):
            messagebox.showerror("错误", "文件解密模式不能导入明文模板，请导入加密后的密码表。")
            return
        main_password = self.password_var.get()
        if not main_password:
            messagebox.showerror("错误", "导入密码表前请先输入主文件密码")
            return
        try:
            imported = self._import_password_table_file(path, main_password)
        except Exception as exc:
            messagebox.showerror("错误", f"密码表解密失败：{exc}")
            return

        if imported:
            self.status_var.set(f"已导入 {imported} 个文件的密码")
            messagebox.showinfo("导入完成", f"已从密码表导入 {imported} 个文件的密码。")
        else:
            messagebox.showinfo("导入完成", "密码表已解密，但没有匹配到当前已选文件。")

    def _show_selected_files(self) -> None:
        if not self.selected_files:
            messagebox.showinfo("提示", "当前还没有选择内容")
            return

        if self.mode_var.get() == "file_decrypt":
            self._load_manifest_for_selected_files()

        dialog = tk.Toplevel(self.root)
        dialog.title("已选文件列表")
        dialog.geometry("900x480")
        dialog.minsize(620, 320)
        dialog.transient(self.root)

        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        ttk.Label(
            frame,
            text=f"当前共选择 {len(self.selected_files)} 个项目",
            style="Info.TLabel",
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        if self.password_table_imported:
            ttk.Label(
                frame,
                text="已从密码表导入",
                style="Hint.TLabel",
            ).grid(row=0, column=0, sticky="e", pady=(0, 8))

        list_frame = ttk.Frame(frame)
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        tree = ttk.Treeview(
            list_frame,
            columns=("type", "group", "password", "source"),
            show="tree headings",
            selectmode="extended",
        )
        tree.heading("#0", text="路径")
        tree.heading("type", text="类型")
        tree.heading("group", text="密码组")
        tree.heading("password", text="处理状态")
        tree.heading("source", text="来源")
        tree.column("#0", width=500, anchor="w")
        tree.column("type", width=90, anchor="center")
        tree.column("group", width=100, anchor="center")
        tree.column("password", width=120, anchor="center")
        tree.column("source", width=120, anchor="center")
        tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=scrollbar.set)

        def refresh_tree() -> None:
            for item in tree.get_children():
                tree.delete(item)
            for path in self.selected_files:
                is_folder = os.path.isdir(path)
                password_set = bool(self.file_password_overrides.get(path))
                state = "已单独设置" if password_set else "使用主密码"
                group_label = self.file_group_labels.get(path, "-")
                source_map = {
                    "main": "主文件密码",
                    "manual": "手动单独设置",
                    "auto": "自动生成",
                }
                source_label = source_map.get(self.file_password_sources.get(path, "main"), "主文件密码")
                node = tree.insert(
                    "",
                    "end",
                    iid=path,
                    text=path,
                    values=("文件夹" if is_folder else "文件", group_label, state, source_label),
                    open=is_folder,
                )
                if is_folder and self.mode_var.get() == "file_encrypt":
                    individually_encrypted = self.folder_individual_encrypt_files.get(path, set())
                    for child_path in iter_folder_files(path):
                        relative = os.path.relpath(child_path, path)
                        if child_path in individually_encrypted:
                            child_state = "单独加密"
                            child_source = self.folder_child_password_sources.get(child_path, "manual")
                            source_label = {"manual": "子文件独立密码", "auto": "子文件自动生成"}.get(child_source, "子文件独立密码")
                        else:
                            child_state = "随包保留"
                            source_label = "文件夹默认策略"
                        tree.insert(
                            node,
                            "end",
                            iid=self._folder_child_item_id(child_path),
                            text=relative,
                            values=("文件夹内文件", "-", child_state, source_label),
                        )

        refresh_tree()

        controls = ttk.Frame(frame)
        controls.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(2, weight=3)

        ttk.Label(controls, text="选中项目密码", style="Hint.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        password_var = tk.StringVar(value=self.password_var.get())
        password_entry = ttk.Entry(controls, textvariable=password_var, show="*", font=("Consolas", 10))
        password_entry.grid(row=0, column=1, columnspan=2, sticky="ew")
        default_hint = ttk.Label(
            controls,
            text="根项目未单独设置时默认使用主密码；文件夹内文件默认随包保留，可单独标记为额外加密。",
            style="Hint.TLabel",
        )
        default_hint.grid(row=1, column=0, columnspan=8, sticky="w", pady=(6, 0))

        folder_hint = ttk.Label(
            controls,
            text="提示：文件夹里的“单独加密”会在打包前先转换成包内独立 .gcm 文件，其余内容原样打包。",
            style="Hint.TLabel",
        )
        folder_hint.grid(row=2, column=0, columnspan=10, sticky="w", pady=(4, 0))

        def sync_password_entry(*_args) -> None:
            selection = list(tree.selection())
            selected_roots = [item for item in selection if not self._is_folder_child_item(item)]
            selected_children = [item for item in selection if self._is_folder_child_item(item)]
            if len(selected_children) == 1 and not selected_roots:
                child_path = self._folder_child_path(selected_children[0])
                password_var.set(self._child_password_for(child_path))
            elif len(selected_roots) == 1 and not selected_children:
                path = selected_roots[0]
                password_var.set(self.file_password_overrides.get(path) or self.password_var.get())
            else:
                password_var.set(self.password_var.get())

        tree.bind("<<TreeviewSelect>>", sync_password_entry)

        def apply_password_to_selection(auto_generate: bool = False) -> None:
            selected_roots = [item for item in tree.selection() if not self._is_folder_child_item(item)]
            selected_children = [item for item in tree.selection() if self._is_folder_child_item(item)]
            if not selected_roots and not selected_children:
                messagebox.showinfo("提示", "请先选择要设置密码的项目", parent=dialog)
                return
            if auto_generate:
                for path in selected_roots:
                    self.file_password_overrides[path] = generate_random_password()
                    self.file_password_sources[path] = "auto"
                for item in selected_children:
                    child_path = self._folder_child_path(item)
                    folder = self._find_parent_folder_for_child(child_path)
                    if folder:
                        self.folder_individual_encrypt_files.setdefault(folder, set()).add(child_path)
                    self.folder_child_password_overrides[child_path] = generate_random_password()
                    self.folder_child_password_sources[child_path] = "auto"
                self.status_var.set(f"已为 {len(selected_roots) + len(selected_children)} 个项目生成独立密码")
            else:
                password = password_var.get()
                if not password:
                    messagebox.showinfo("提示", "请先输入密码", parent=dialog)
                    return
                for path in selected_roots:
                    self.file_password_overrides[path] = password
                    self.file_password_sources[path] = "manual"
                for item in selected_children:
                    child_path = self._folder_child_path(item)
                    folder = self._find_parent_folder_for_child(child_path)
                    if folder:
                        self.folder_individual_encrypt_files.setdefault(folder, set()).add(child_path)
                    self.folder_child_password_overrides[child_path] = password
                    self.folder_child_password_sources[child_path] = "manual"
                self.status_var.set(f"已为 {len(selected_roots) + len(selected_children)} 个项目设置密码")
            refresh_tree()
            sync_password_entry()

        def reset_to_default() -> None:
            selected_roots = [item for item in tree.selection() if not self._is_folder_child_item(item)]
            selected_children = [item for item in tree.selection() if self._is_folder_child_item(item)]
            if not selected_roots and not selected_children:
                messagebox.showinfo("提示", "请先选择要恢复默认密码的项目", parent=dialog)
                return
            for path in selected_roots:
                self.file_password_overrides[path] = ""
                self.file_password_sources[path] = "main"
            for item in selected_children:
                child_path = self._folder_child_path(item)
                self.folder_child_password_overrides.pop(child_path, None)
                self.folder_child_password_sources.pop(child_path, None)
            refresh_tree()
            sync_password_entry()

        def mark_folder_children(individually_encrypt: bool) -> None:
            selected = [item for item in tree.selection() if self._is_folder_child_item(item)]
            if not selected:
                messagebox.showinfo("提示", "请先选择文件夹内文件", parent=dialog)
                return
            changed = 0
            for item in selected:
                child_path = self._folder_child_path(item)
                folder = self._find_parent_folder_for_child(child_path)
                if not folder:
                    continue
                bucket = self.folder_individual_encrypt_files.setdefault(folder, set())
                if individually_encrypt:
                    if child_path not in bucket:
                        bucket.add(child_path)
                        changed += 1
                else:
                    if child_path in bucket:
                        bucket.remove(child_path)
                        self.folder_child_password_overrides.pop(child_path, None)
                        self.folder_child_password_sources.pop(child_path, None)
                        changed += 1
            if changed:
                self.status_var.set("已更新文件夹内文件的单独加密标记")
            refresh_tree()

        ttk.Button(controls, text="应用到选中", command=apply_password_to_selection, style="Secondary.TButton").grid(
            row=0, column=3, padx=(8, 0)
        )
        ttk.Button(
            controls,
            text="为选中项自动生成",
            command=lambda: apply_password_to_selection(auto_generate=True),
            style="Secondary.TButton",
        ).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(
            controls,
            text="恢复主密码",
            command=reset_to_default,
            style="Secondary.TButton",
        ).grid(row=0, column=5, padx=(8, 0))
        folder_controls_hint = ttk.Label(
            controls,
            text="以下两项仅对文件夹内文件生效：用于决定该文件是随包保留，还是先单独加密后再放入压缩包。",
            style="Hint.TLabel",
        )
        folder_controls_hint.grid(row=3, column=0, columnspan=10, sticky="w", pady=(8, 0))
        ttk.Button(
            controls,
            text="标记单独加密",
            command=lambda: mark_folder_children(individually_encrypt=True),
            style="Secondary.TButton",
        ).grid(row=4, column=0, padx=(0, 8), pady=(4, 0), sticky="w")
        ttk.Button(
            controls,
            text="恢复随包",
            command=lambda: mark_folder_children(individually_encrypt=False),
            style="Secondary.TButton",
        ).grid(row=4, column=1, padx=(0, 8), pady=(4, 0), sticky="w")
        if self.mode_var.get() == "file_encrypt":
            ttk.Button(
                controls,
                text="导出加密模板",
                command=self._export_password_template,
                style="Secondary.TButton",
            ).grid(row=0, column=6, padx=(8, 0))
            ttk.Button(
                controls,
                text="高级: 明文模板",
                command=self._export_plaintext_template,
                style="Secondary.TButton",
            ).grid(row=0, column=7, padx=(8, 0))
            ttk.Button(
                controls,
                text="导入模板",
                command=self._import_password_table,
                style="Secondary.TButton",
            ).grid(row=0, column=8, padx=(8, 0))

        button_row = ttk.Frame(frame)
        button_row.grid(row=3, column=0, sticky="ew", pady=(10, 0))

        def remove_selected() -> None:
            selected_root_items = [item for item in tree.selection() if not self._is_folder_child_item(item)]
            selected = [self.selected_files.index(path) for path in selected_root_items]
            if not selected:
                messagebox.showinfo("提示", "请先选择要移除的根项目", parent=dialog)
                return
            self._remove_selected_indices(selected)
            refresh_tree()
            if not self.selected_files:
                dialog.destroy()

        def remove_all() -> None:
            if not self.selected_files:
                dialog.destroy()
                return
            confirmed = messagebox.askyesno("确认", "是否移除当前全部已选内容？", parent=dialog)
            if not confirmed:
                return
            self._set_selected_files([])
            dialog.destroy()

        ttk.Button(button_row, text="关闭", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
        ttk.Button(button_row, text="移除全部", command=remove_all, style="Secondary.TButton").pack(side="right", padx=(8, 0))
        ttk.Button(button_row, text="移除选中", command=remove_selected, style="Secondary.TButton").pack(side="right", padx=(8, 0))

    def _update_mode_buttons(self) -> None:
        active_mode = self.mode_var.get()
        colors = {
            "text_encrypt": ("#157f5b", "#ffffff"),
            "text_decrypt": ("#1d4ed8", "#ffffff"),
            "file_encrypt": ("#b45309", "#ffffff"),
            "file_decrypt": ("#7c3f00", "#ffffff"),
        }
        for mode, button in self.mode_buttons.items():
            if mode == active_mode:
                bg, fg = colors[mode]
                button.configure(bg=bg, fg=fg, activebackground=bg, activeforeground=fg)
            else:
                button.configure(
                    bg="#efe8dc",
                    fg="#2b2118",
                    activebackground="#e5dccd",
                    activeforeground="#2b2118",
                )

    def _refresh_mode(self) -> None:
        mode = self.mode_var.get()
        is_file_mode = mode.startswith("file_")
        is_text_encrypt = mode == "text_encrypt"
        is_text_decrypt = mode == "text_decrypt"
        is_encrypt_mode = mode.endswith("encrypt")
        decrypting_bundle_package = (
            mode == "file_decrypt"
            and len(self.selected_files) == 1
            and self.selected_files[0].lower().endswith(".zip.gcm")
        )
        needs_bundle_password = (
            mode == "file_encrypt"
            and self.batch_mode_var.get() == "bundle_encrypt"
            and len(self.selected_files) > 1
        ) or decrypting_bundle_package

        self._update_mode_buttons()
        self.action_var.set("开始加密" if is_encrypt_mode else "开始解密")

        self.password_box.grid_configure(row=4, column=0, columnspan=1, padx=(0, 0), sticky="ew")
        self.action_box.grid_configure(row=4, column=1, columnspan=1, padx=(12, 0), pady=(8, 0), sticky="nsew")
        if is_file_mode:
            self.password_entry.grid_configure(row=0, column=1, columnspan=2, pady=(0, 0))
            self.password_show_button.grid_configure(row=0, column=3, padx=(8, 0), pady=(0, 0), sticky="")
            self.password_generate_button.grid_configure(row=0, column=4, padx=(8, 0), pady=(0, 0), sticky="")
            self.password_copy_button.grid_configure(row=0, column=5, padx=(8, 0), pady=(0, 0), sticky="")
        else:
            self.password_entry.grid_configure(row=0, column=1, columnspan=5, pady=(0, 0))
            self.password_show_button.grid_configure(row=1, column=1, padx=(0, 8), pady=(6, 0), sticky="w")
            self.password_generate_button.grid_configure(row=1, column=2, padx=(0, 8), pady=(6, 0), sticky="w")
            self.password_copy_button.grid_configure(row=1, column=3, padx=(0, 0), pady=(6, 0), sticky="w")

        if is_file_mode:
            self.file_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(8, 0))
            if mode == "file_encrypt":
                self.batch_mode_frame.grid()
                self.password_table_frame.grid()
                self.password_table_title_label.configure(text="模板/密码表")
                self.password_table_select_button.configure(text="选择模板")
                self.password_table_import_button.configure(text="导入模板")
                self.password_table_export_button.grid(row=0, column=4, padx=(8, 0))
                self.password_template_plain_button.grid(row=0, column=5, padx=(8, 0))
                self.template_scope_check.grid()
                self.password_table_hint.configure(text="默认导出加密模板；如需手工编辑，可通过“高级: 明文模板”临时导出 CSV，导入后系统会尝试自动转加密并删除原文件。")
            else:
                self.batch_mode_frame.grid_remove()
                self.password_table_frame.grid()
                self.password_table_title_label.configure(text="密码表")
                self.password_table_select_button.configure(text="选择密码表")
                self.password_table_import_button.configure(text="导入密码表")
                self.password_table_export_button.grid_remove()
                self.password_template_plain_button.grid_remove()
                self.template_scope_check.grid_remove()
                self.password_table_hint.configure(text="只能导入加密密码表；若不是主文件密码加密，系统会要求输入密码表密码。")
        else:
            self.file_frame.grid_remove()

        input_label = "输入明文" if is_text_encrypt else "输入 Base64 密文" if is_text_decrypt else "文件说明"
        output_label = "输出 Base64 密文" if is_text_encrypt else "输出明文" if is_text_decrypt else "输出路径"

        self.input_frame.configure(text=input_label)
        self.output_frame.configure(text=output_label)

        if mode == "text_encrypt":
            self.password_label.configure(text="密码")
            self.mode_hint.configure(text="当前模式：文本加密。输入明文和密码后，点击“开始加密”。")
            self.quick_hint.configure(text="输入明文和密码后，点击左侧绿色主按钮。")
        elif mode == "text_decrypt":
            self.password_label.configure(text="密码")
            self.mode_hint.configure(text="当前模式：文本解密。输入 Base64 密文和密码后，点击“开始解密”。")
            self.quick_hint.configure(text="输入 Base64 密文和密码后，点击左侧蓝色主按钮。")
        elif mode == "file_encrypt":
            self.password_label.configure(text="文件密码")
            self.mode_hint.configure(text="当前模式：文件/文件夹加密。文件夹会先打包再加密。")
            if needs_bundle_password:
                has_overrides = any(bool(self.file_password_overrides.get(path)) for path in self.selected_files)
                if has_overrides:
                    self.quick_hint.configure(text="已为部分文件单独设置密码；主文件密码用于未单独设置文件，并用于加密密码表。压缩包密码用于最终压缩包。")
                else:
                    self.quick_hint.configure(text="文件密码用于每个文件，压缩包密码用于最终压缩包；若后续单独设置文件密码，主文件密码将用于密码表。")
            else:
                self.quick_hint.configure(text="可多选或拖入文件/文件夹；文件夹默认整包加密，也可在“查看已选内容”中标记其中部分文件单独加密。")
        else:
            self.password_label.configure(text="文件密码")
            if decrypting_bundle_package:
                self.mode_hint.configure(text="当前模式：加密压缩包解密。压缩包密码用于外层压缩包，文件密码用于后续密码表和内部文件。")
                self.quick_hint.configure(text="先输入压缩包密码解开外层包；若已提前提供密码表，解压后会自动导入密码并继续批量解密。")
            else:
                self.mode_hint.configure(text="当前模式：文件解密。支持单个或多个 .gcm 文件逐个解密。")
                self.quick_hint.configure(text="可多选或拖入多个 .gcm 文件；这里的“文件密码”用于逐个解密和密码表导入。")

        if needs_bundle_password:
            self.bundle_password_label.configure(text="压缩包密码")
            self.bundle_password_label.grid(row=1, column=0, padx=(0, 8), pady=(6, 0), sticky="w")
            self.bundle_password_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(6, 0))
            self.bundle_password_show_button.grid(row=1, column=3, padx=(8, 0), pady=(6, 0))
            self.bundle_password_generate_button.grid(row=1, column=4, padx=(8, 0), pady=(6, 0))
            self.bundle_password_copy_button.grid(row=1, column=5, padx=(8, 0), pady=(6, 0))
        else:
            self.bundle_password_label.grid_remove()
            self.bundle_password_entry.grid_remove()
            self.bundle_password_show_button.grid_remove()
            self.bundle_password_generate_button.grid_remove()
            self.bundle_password_copy_button.grid_remove()

        self.input_text.configure(state="normal")
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.file_result_var.set("")
        self.password_table_var.set("")
        self.progress_var.set(0)

        if is_file_mode:
            self.input_frame.grid_remove()
            self.output_frame.grid_remove()
            self.file_progress_frame.grid(row=7, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
            self.file_progress_label.configure(text="选择或拖拽文件后，点击上方主按钮开始处理。")
        else:
            self.file_progress_frame.grid_remove()
            self.input_frame.grid()
            self.output_frame.grid()
        self.status_var.set("就绪")

    def _execute(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showinfo("提示", "当前任务仍在执行")
            return

        password = self.password_var.get()
        if not password:
            messagebox.showerror("错误", "请先输入密码，或点击“自动生成”创建随机密码。")
            self.status_var.set("未设置密码")
            return
        bundle_password = self.bundle_password_var.get()
        mode = self.mode_var.get()
        payload = {
            "input_text": self._get_input_text(),
            "file_path": self.file_path_var.get().strip(),
            "file_paths": list(self.selected_files),
            "folder_individual_encrypt_map": {key: set(value) for key, value in self.folder_individual_encrypt_files.items()},
            "folder_child_password_map": dict(self.folder_child_password_overrides),
            "keep_source": self.keep_source_var.get(),
            "overwrite": False,
            "batch_mode": self.batch_mode_var.get(),
            "bundle_password": bundle_password,
        }

        if mode.startswith("file_") and not payload["file_paths"]:
            messagebox.showerror("错误", "请先选择至少一个文件或文件夹")
            self.status_var.set("未选择内容")
            return

        if mode == "file_encrypt":
            if payload["batch_mode"] == "bundle_encrypt" and len(payload["file_paths"]) > 1 and not bundle_password:
                messagebox.showerror("错误", "打包再加密模式需要单独设置打包密码。")
                self.status_var.set("未设置打包密码")
                return
            payload["file_password_map"] = self._build_encryption_password_map(password)
            if payload["batch_mode"] == "bundle_encrypt" and len(payload["file_paths"]) > 1:
                target_path = build_bundle_output_path(payload["file_paths"])
                payload["bundle_output_path"] = target_path
                if os.path.exists(target_path):
                    confirmed = messagebox.askyesno(
                        "确认覆盖",
                        f"打包加密文件已存在：\n{target_path}\n\n是否覆盖？",
                    )
                    if not confirmed:
                        self.status_var.set("已取消")
                        return
                    payload["overwrite"] = True
            else:
                target_paths = [get_source_encrypted_output_path(path) for path in payload["file_paths"]]
                existing = collect_existing_paths(target_paths)
                if existing:
                    preview = "\n".join(existing[:3])
                    suffix = "\n..." if len(existing) > 3 else ""
                    confirmed = messagebox.askyesno(
                        "确认覆盖",
                        f"以下加密输出已存在：\n{preview}{suffix}\n\n是否全部覆盖？",
                    )
                    if not confirmed:
                        self.status_var.set("已取消")
                        return
                    payload["overwrite"] = True
        elif mode == "file_decrypt":
            payload["decrypting_bundle_package"] = (
                len(payload["file_paths"]) == 1 and payload["file_paths"][0].lower().endswith(".zip.gcm")
            )
            if payload["decrypting_bundle_package"] and not bundle_password:
                messagebox.showerror("错误", "解密加密压缩包时，请先输入压缩包密码。")
                self.status_var.set("未设置压缩包密码")
                return
            try:
                payload["file_password_map"], payload["manifest"] = self._build_decryption_password_map(password)
            except ValueError as exc:
                if not payload["decrypting_bundle_package"]:
                    messagebox.showerror("错误", f"{exc}\n\n请在“查看已选文件”中输入对应密码。")
                    self.status_var.set("缺少文件密码")
                    return
                payload["file_password_map"] = {}
            target_paths = [get_decrypted_output_path(path) for path in payload["file_paths"]]
            existing = collect_existing_paths(target_paths)
            if existing:
                preview = "\n".join(existing[:3])
                suffix = "\n..." if len(existing) > 3 else ""
                confirmed = messagebox.askyesno(
                    "确认覆盖",
                    f"以下解密输出已存在：\n{preview}{suffix}\n\n是否全部覆盖？",
                )
                if not confirmed:
                    self.status_var.set("已取消")
                    return

        self.run_button.configure(state="disabled")
        self.progress_var.set(0)
        self.status_var.set("正在处理")

        self._worker = threading.Thread(
            target=self._execute_task,
            args=(mode, password, payload),
            daemon=True,
        )
        self._worker.start()

    def _execute_task(self, mode: str, password: str, payload: dict) -> None:
        try:
            if mode == "text_encrypt":
                self._queue_progress(35, "正在加密文本")
                result = encrypt_text(payload["input_text"], password)
                self._queue_success(result, "文本加密完成")
            elif mode == "text_decrypt":
                self._queue_progress(35, "正在解密文本")
                result = decrypt_text(payload["input_text"].strip(), password)
                self._queue_success(result, "文本解密完成")
            elif mode == "file_encrypt":
                if payload["batch_mode"] == "bundle_encrypt" and len(payload["file_paths"]) > 1:
                    result, password_table_path = encrypt_files_bundle(
                        payload["file_paths"],
                        payload["file_password_map"],
                        payload["bundle_password"],
                        password,
                        folder_individual_encrypt_map=payload["folder_individual_encrypt_map"],
                        folder_child_password_map=payload["folder_child_password_map"],
                        keep_source=payload["keep_source"],
                        overwrite=payload["overwrite"],
                        output_path=payload["bundle_output_path"],
                        progress_callback=self._queue_progress,
                    )
                    status = "批量打包加密完成"
                    if password_table_path:
                        status = f"{status}，已生成加密密码表"
                    self._queue_success(result, status, password_table_path)
                elif len(payload["file_paths"]) > 1:
                    output_paths, manifest_path, password_table_path = encrypt_files_individually(
                        payload["file_paths"],
                        payload["file_password_map"],
                        password,
                        folder_individual_encrypt_map=payload["folder_individual_encrypt_map"],
                        folder_child_password_map=payload["folder_child_password_map"],
                        keep_source=payload["keep_source"],
                        overwrite=payload["overwrite"],
                        progress_callback=self._queue_progress,
                    )
                    status = f"批量加密完成，共 {len(output_paths)} 个文件"
                    if password_table_path:
                        status = f"{status}，已生成加密密码表"
                    self._queue_success(get_common_directory(output_paths), status, password_table_path)
                else:
                    source_path = payload["file_paths"][0]
                    if os.path.isdir(source_path):
                        result = encrypt_folder(
                            source_path,
                            payload["file_password_map"][source_path],
                            individually_encrypt_files=payload["folder_individual_encrypt_map"].get(source_path, set()),
                            child_password_map=payload["folder_child_password_map"],
                            progress_callback=self._queue_progress,
                            keep_source=payload["keep_source"],
                            overwrite=payload["overwrite"],
                        )
                        password_rows = build_folder_child_password_rows(
                            source_path,
                            payload["file_password_map"][source_path],
                            folder_individual_encrypt_map=payload["folder_individual_encrypt_map"],
                            folder_child_password_map=payload["folder_child_password_map"],
                        )
                        password_table_path = export_password_table(password_rows, password) if password_rows else None
                    else:
                        result = encrypt_file(
                            source_path,
                            payload["file_password_map"][source_path],
                            progress_callback=self._queue_progress,
                            keep_source=payload["keep_source"],
                            overwrite=payload["overwrite"],
                        )
                        password_table_path = None
                    self._queue_success(result, "文件加密完成", password_table_path)
            else:
                if len(payload["file_paths"]) > 1:
                    results = decrypt_files_individually(
                        payload["file_paths"],
                        payload["file_password_map"],
                        keep_source=payload["keep_source"],
                        progress_callback=self._queue_progress,
                    )
                    self._queue_success(get_common_directory(results), f"批量解密完成，共 {len(results)} 个文件")
                else:
                    result = decrypt_file(
                        payload["file_paths"][0],
                        payload["bundle_password"] if payload.get("decrypting_bundle_package") else payload["file_password_map"][payload["file_paths"][0]],
                        progress_callback=self._queue_progress,
                        keep_source=payload["keep_source"],
                    )
                    self._queue_success(result, "文件解密完成")
        except Exception as exc:
            self.root.after(0, self._finish_error, str(exc))

    def _queue_progress(self, value: int, message: str) -> None:
        self.root.after(0, self._update_progress, value, message)

    def _update_progress(self, value: int, message: str) -> None:
        self.progress_var.set(value)
        self.status_var.set(message)
        if self.mode_var.get().startswith("file_"):
            self.file_progress_label.configure(text=message)

    def _queue_success(self, result: str, status: str, password_table_path: str | None = None) -> None:
        self.root.after(0, self._finish_success, result, status, password_table_path)

    def _finish_success(self, result: str, status: str, password_table_path: str | None = None) -> None:
        if self.mode_var.get().startswith("file_"):
            self.file_result_var.set(result)
            self.password_table_var.set(password_table_path or "")
            self.file_progress_label.configure(text=status)
            refresh_explorer(result)
            if password_table_path:
                refresh_explorer(password_table_path)
            if self.mode_var.get() == "file_encrypt" and self.pending_template_delete_path:
                try:
                    if os.path.exists(self.pending_template_delete_path):
                        confirmed = messagebox.askyesno(
                            "删除明文模板",
                            f"文件加密已完成。\n\n是否立即永久删除明文模板？\n{self.pending_template_delete_path}",
                        )
                        if confirmed:
                            os.remove(self.pending_template_delete_path)
                finally:
                    self.pending_template_delete_path = None
            should_preserve_sensitive_state = self._handle_post_file_success(result, status)
        else:
            self._set_output_text(result)
            should_preserve_sensitive_state = False
        if should_preserve_sensitive_state:
            self.defer_sensitive_clear = False
        else:
            self._clear_sensitive_state()
        self.progress_var.set(100)
        self.status_var.set(status)
        self.run_button.configure(state="normal")
        self._worker = None

    def _handle_post_file_success(self, result: str, status: str) -> bool:
        if self.mode_var.get() != "file_decrypt":
            return False
        if not result.lower().endswith(".zip"):
            return False

        unzip_now = messagebox.askyesno(
            "解压缩",
            f"已生成压缩包：\n{result}\n\n是否立即自动解压？",
        )
        if not unzip_now:
            return False

        try:
            extract_dir = extract_zip_to_directory(result)
            refresh_explorer(extract_dir)
        except Exception as exc:
            messagebox.showerror("错误", f"自动解压失败：{exc}")
            return False

        decrypt_now = messagebox.askyesno(
            "批量解密",
            f"已解压到：\n{extract_dir}\n\n是否载入内部加密文件并进入批量解密流程？",
        )
        if not decrypt_now:
            self.file_result_var.set(extract_dir)
            self.file_progress_label.configure(text="压缩包已解压")
            return False

        inner_manifest = discover_manifest_in_directory(extract_dir)
        inner_files = discover_inner_gcm_files(extract_dir)
        if not inner_files:
            messagebox.showinfo("提示", "解压目录中没有找到可继续解密的 .gcm 文件。")
            self.file_result_var.set(extract_dir)
            return False

        self.mode_var.set("file_decrypt")
        self._set_selected_files(inner_files)
        self.current_manifest_path = inner_manifest
        if inner_manifest:
            try:
                manifest = load_manifest(inner_manifest, password=self.password_var.get().strip() or None)
            except Exception:
                self.current_manifest_path = None
                self.file_group_labels = {}
            else:
                entry_map = manifest_entry_map(manifest)
                groups = manifest_group_map(manifest)
                self.file_group_labels = {}
                for path in inner_files:
                    entry = entry_map.get(os.path.basename(path))
                    if entry:
                        self.file_group_labels[path] = groups.get(entry["group_id"], {}).get("label", entry["group_id"])
        self.file_result_var.set(extract_dir)
        preset_password_table = self.password_table_input_var.get().strip()
        if preset_password_table and os.path.exists(preset_password_table):
            try:
                imported = self._import_password_table_file(preset_password_table, self.password_var.get())
            except Exception as exc:
                self.file_progress_label.configure(text="内部文件已载入，但预设密码表导入失败。")
                messagebox.showerror("错误", f"预设密码表导入失败：{exc}")
                return True
            self.file_result_var.set(f"{extract_dir} | 已自动导入密码表并继续内部批量解密")
            self.file_progress_label.configure(text="已自动导入密码表，正在继续内部批量解密。")
            self.status_var.set(f"已自动导入 {imported} 个文件密码，正在继续内部批量解密")
            self.root.after(100, self._execute)
            return True

        self.file_progress_label.configure(text="已载入内部加密文件，请检查密码后继续批量解密。")
        messagebox.showinfo(
            "已载入批量解密",
            "内部加密文件已经载入。\n\n如果各文件密码不同，请先打开“查看已选文件”分别输入对应密码，或先导入密码表，再点击“开始解密”。",
        )
        return True

    def _finish_error(self, message: str) -> None:
        self.status_var.set("执行失败")
        if self.mode_var.get().startswith("file_"):
            self.file_progress_label.configure(text="处理失败，请检查文件路径和密码。")
        self.run_button.configure(state="normal")
        self._worker = None
        messagebox.showerror("错误", message)

    def _get_input_text(self) -> str:
        return self.input_text.get("1.0", "end-1c")

    def _set_output_text(self, value: str) -> None:
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", value)

    def _copy_output(self) -> None:
        if self.mode_var.get().startswith("file_"):
            value = self.file_result_var.get().strip()
        else:
            value = self.output_text.get("1.0", "end-1c")
        if not value:
            messagebox.showinfo("提示", "当前没有可复制的输出")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status_var.set("输出已复制到剪贴板")

    def _clear_all(self) -> None:
        if self.clipboard_clear_job is not None:
            self.root.after_cancel(self.clipboard_clear_job)
            self.clipboard_clear_job = None
        self._clear_clipboard_if_possible()
        self._clear_sensitive_state()
        self.selected_files = []
        self.folder_individual_encrypt_files = {}
        self.file_path_var.set("")
        self.file_summary_var.set("")
        self.file_group_labels = {}
        self.current_manifest_path = None
        self.password_table_input_var.set("")
        self.password_table_var.set("")
        self.pending_template_delete_path = None
        self.template_encrypted_copy_path = None
        self.input_text.configure(state="normal")
        self.input_text.delete("1.0", "end")
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.file_result_var.set("")
        self._refresh_mode()


def run_gui() -> None:
    root = TkinterDnD.Tk()
    try:
        root.call("tk", "scaling", 1.15)
    except tk.TclError:
        pass
    AESGCMApp(root)
    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        run_cli()
    else:
        run_gui()
