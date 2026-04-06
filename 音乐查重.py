import os
import re
import csv
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, Set

# =======================
DEFAULT_REMOVE_TOKENS = ["河图"]

DEFAULT_IGNORE_EXTS = {
    ".lrc",  # 歌词不参与（强制）
    ".srt", ".ass", ".ssa", ".vtt",
    ".txt", ".nfo", ".log", ".cue",
    ".jpg", ".jpeg", ".png", ".webp", ".gif",
    ".url", ".lnk"
}

TRASH_DIR_NAME = "_Trash_Dedupe"
MANIFEST_NAME = "manifest.csv"
RESTORE_BAT_NAME = "restore_from_trash.bat"
REPORT_NAME = "report.csv"
DUPLICATES_NAME = "duplicates.csv"
KEEP_PLAN_NAME = "keep_plan.csv"

# 冲突策略
# RENAME: 自动改名保留两份（回收站同名 -> (1)(2)）
# SKIP:   跳过冲突项
# OVERWRITE: 覆盖回收站旧文件
CONFLICT_RENAME = "RENAME"
CONFLICT_SKIP = "SKIP"
CONFLICT_OVERWRITE = "OVERWRITE"

# =======================


@dataclass(frozen=True)
class FileRec:
    path: str
    side: str  # 'A' or 'B'
    name: str
    ext: str
    size: int


@dataclass
class GroupRec:
    key: str
    a_files: List[FileRec]
    b_files: List[FileRec]

    @property
    def a_count(self) -> int:
        return len(self.a_files)

    @property
    def b_count(self) -> int:
        return len(self.b_files)


def safe_relpath(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base)
    except Exception:
        return path


def build_normalizer(remove_tokens: List[str], remove_numbers: bool, remove_symbols: bool, casefold: bool):
    token_pattern = None
    if remove_tokens:
        escaped = [re.escape(t) for t in remove_tokens if t]
        if escaped:
            token_pattern = re.compile("|".join(escaped), re.IGNORECASE)

    re_numbers = re.compile(r"[0-9０-９]+")
    # remove_symbols=True：只保留中文+英文字母（符号如 - _ . 空格 等会被去掉）
    re_keep_cn_en = re.compile(r"[^\u4e00-\u9fffA-Za-z]+")

    def normalize(filename: str) -> str:
        base, _ = os.path.splitext(filename)
        s = base
        if casefold:
            s = s.lower()
        if token_pattern:
            s = token_pattern.sub("", s)
        if remove_numbers:
            s = re_numbers.sub("", s)
        if remove_symbols:
            s = re_keep_cn_en.sub("", s)
        else:
            s = re.sub(r"\s+", " ", s).strip()
        return s.strip()

    return normalize


def scan_folder(folder: str, side: str, normalize, ignore_exts: set, progress_cb=None, log_cb=None) -> Dict[str, List[FileRec]]:
    total = 0
    for _, _, files in os.walk(folder):
        total += len(files)

    scanned = 0
    m: Dict[str, List[FileRec]] = defaultdict(list)

    for root, _, files in os.walk(folder):
        for fn in files:
            scanned += 1
            if progress_cb:
                progress_cb(scanned, total)

            ext = os.path.splitext(fn)[1].lower()
            if ext in ignore_exts:
                continue

            full = os.path.join(root, fn)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = -1

            key = normalize(fn)
            if not key:
                continue

            m[key].append(FileRec(path=full, side=side, name=fn, ext=ext, size=size))

    if log_cb:
        log_cb(f"[{side}] keys={len(m)} (after normalize & ignore-ext)")
    return m


def write_csv(path: str, header: List[str], rows: List[List[str]]):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def unique_path(dst_path: str, reserved: Optional[Set[str]] = None) -> str:
    """
    若目标已存在或已被本批次占用(reserved)，则追加 (1)(2)...
    """
    reserved = reserved or set()
    if (not os.path.exists(dst_path)) and (dst_path not in reserved):
        return dst_path

    base, ext = os.path.splitext(dst_path)
    i = 1
    while True:
        cand = f"{base}({i}){ext}"
        if (not os.path.exists(cand)) and (cand not in reserved):
            return cand
        i += 1


def planned_trash_path_for_b(file_rec: FileRec, base_folder_b: str, trash_root: str) -> str:

    #计算B文件在回收站的“原始目标路径”（不含改名逻辑）：trash_root\B\<相对B路径>

    rel = safe_relpath(file_rec.path, base_folder_b)
    return os.path.join(trash_root, "B", rel)


def make_restore_bat(path: str, moves: List[Tuple[str, str]]):
    lines = [
        "@echo off",
        "chcp 65001 >nul",
        "echo Restoring files from _Trash_Dedupe ...",
        "echo If you see errors, check paths and permissions.",
        "",
    ]
    for trash_path, original_path in moves:
        orig_dir = os.path.dirname(original_path)
        lines.append(f'if not exist "{orig_dir}" mkdir "{orig_dir}"')
        lines.append(f'move /Y "{trash_path}" "{original_path}" >nul')
    lines.append("")
    lines.append("echo Done.")
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write("\n".join(lines))


class ConflictDialog(tk.Toplevel):
    """
    冲突预检弹窗：展示冲突概况 + 让用户选择策略
    """
    def __init__(self, parent: tk.Tk, conflict_count: int, total_count: int, examples: List[str]):
        super().__init__(parent)
        self.title("回收站同名冲突检查")
        self.resizable(True, True)
        self.choice: Optional[str] = None

        self.transient(parent)
        self.grab_set()

        pad = {"padx": 10, "pady": 8}

        ttk.Label(
            self,
            text=f"检测到回收站存在同路径文件冲突：{conflict_count}/{total_count}\n请选择本次移动的冲突处理策略："
        ).pack(anchor="w", **pad)

        self.var = tk.StringVar(value=CONFLICT_RENAME)

        box = ttk.Frame(self)
        box.pack(fill="x", **pad)

        ttk.Radiobutton(
            box, text="自动改名（保留两份，推荐）", value=CONFLICT_RENAME, variable=self.var
        ).pack(anchor="w")
        ttk.Radiobutton(
            box, text="跳过冲突项（只移动不冲突的）", value=CONFLICT_SKIP, variable=self.var
        ).pack(anchor="w")
        ttk.Radiobutton(
            box, text="覆盖回收站旧文件（删除旧的，用新的替换）", value=CONFLICT_OVERWRITE, variable=self.var
        ).pack(anchor="w")

        ex_box = ttk.LabelFrame(self, text="冲突样例（回收站目标路径）")
        ex_box.pack(fill="both", expand=True, **pad)
        txt = tk.Text(ex_box, height=10)
        txt.pack(fill="both", expand=True, padx=10, pady=8)
        txt.insert("end", "\n".join(examples) if examples else "(无样例)")
        txt.config(state="disabled")

        btns = ttk.Frame(self)
        btns.pack(fill="x", **pad)

        ttk.Button(btns, text="取消", command=self._cancel).pack(side="right")
        ttk.Button(btns, text="继续", command=self._ok).pack(side="right", padx=8)

        self.geometry("760x420")

    def _ok(self):
        self.choice = self.var.get()
        self.destroy()

    def _cancel(self):
        self.choice = None
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DedupePro（永远保留A，只移动B到回收站 + 冲突预检）")

        self.folder_a = tk.StringVar()
        self.folder_b = tk.StringVar()
        self.out_dir = tk.StringVar(value=os.path.abspath("out_dedupe"))

        self.remove_tokens = tk.StringVar(value="河图")
        self.ignore_exts = tk.StringVar(
            value=".lrc,.srt,.ass,.ssa,.vtt,.txt,.nfo,.log,.cue,.jpg,.jpeg,.png,.webp,.gif,.url,.lnk"
        )

        self.remove_numbers = tk.BooleanVar(value=True)
        self.remove_symbols = tk.BooleanVar(value=True)
        self.casefold = tk.BooleanVar(value=True)

        self.enable_trash = tk.BooleanVar(value=True)

        self.groups: List[GroupRec] = []
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True)

        row = ttk.Frame(frm); row.pack(fill="x", **pad)
        ttk.Label(row, text="Folder A（永远保留）").pack(side="left")
        ttk.Entry(row, textvariable=self.folder_a).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row, text="选择…", command=self.pick_a).pack(side="left")

        row = ttk.Frame(frm); row.pack(fill="x", **pad)
        ttk.Label(row, text="Folder B（重复项将移走）").pack(side="left")
        ttk.Entry(row, textvariable=self.folder_b).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row, text="选择…", command=self.pick_b).pack(side="left")

        row = ttk.Frame(frm); row.pack(fill="x", **pad)
        ttk.Label(row, text="输出目录").pack(side="left")
        ttk.Entry(row, textvariable=self.out_dir).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row, text="选择…", command=self.pick_out).pack(side="left")

        rule_box = ttk.LabelFrame(frm, text="判重规则（标准化Key）")
        rule_box.pack(fill="x", **pad)

        row = ttk.Frame(rule_box); row.pack(fill="x", padx=10, pady=6)
        ttk.Label(row, text="过滤字段（逗号分隔）").pack(side="left")
        ttk.Entry(row, textvariable=self.remove_tokens).pack(side="left", fill="x", expand=True, padx=8)

        row = ttk.Frame(rule_box); row.pack(fill="x", padx=10, pady=6)
        ttk.Checkbutton(row, text="去掉数字（含全角）", variable=self.remove_numbers).pack(side="left")
        ttk.Checkbutton(row, text="去掉符号（如 - _ . 空格 等）", variable=self.remove_symbols).pack(side="left", padx=12)
        ttk.Checkbutton(row, text="大小写统一（英文）", variable=self.casefold).pack(side="left")

        ign_box = ttk.LabelFrame(frm, text="不参与比对的扩展名（逗号分隔，含点号；强制包含 .lrc）")
        ign_box.pack(fill="x", **pad)
        row = ttk.Frame(ign_box); row.pack(fill="x", padx=10, pady=6)
        ttk.Entry(row, textvariable=self.ignore_exts).pack(side="left", fill="x", expand=True)

        opt_box = ttk.LabelFrame(frm, text="安全回收站")
        opt_box.pack(fill="x", **pad)
        row = ttk.Frame(opt_box); row.pack(fill="x", padx=10, pady=6)
        ttk.Checkbutton(
            row,
            text=f"将 B 中与 A 重复的文件移动到输出目录/{TRASH_DIR_NAME}（可恢复）",
            variable=self.enable_trash
        ).pack(side="left")

        run_row = ttk.Frame(frm); run_row.pack(fill="x", **pad)
        self.btn_scan = ttk.Button(run_row, text="扫描并生成报告/分组", command=self.scan_and_report)
        self.btn_scan.pack(side="left")
        self.btn_select_all = ttk.Button(run_row, text="全选组", command=lambda: self._select_all(True), state="disabled")
        self.btn_select_all.pack(side="left", padx=8)
        self.btn_select_none = ttk.Button(run_row, text="全不选", command=lambda: self._select_all(False), state="disabled")
        self.btn_select_none.pack(side="left")
        self.btn_move = ttk.Button(run_row, text="把已选组的 B 文件移动到回收站", command=self.move_selected, state="disabled")
        self.btn_move.pack(side="left", padx=8)

        self.pbar = ttk.Progressbar(run_row, length=240, mode="determinate")
        self.pbar.pack(side="left", padx=12, fill="x", expand=True)

        grp_box = ttk.LabelFrame(frm, text="可处理分组：Key 在 A 存在，且 B 也存在（将移动 B 全部）")
        grp_box.pack(fill="both", expand=True, **pad)

        cols = ("key", "a_sample", "b_move_count", "a_count", "b_count")
        self.tree = ttk.Treeview(grp_box, columns=cols, show="headings", height=10)
        self.tree.pack(fill="both", expand=True, padx=10, pady=8)

        self.tree.heading("key", text="标准化Key")
        self.tree.heading("a_sample", text="A样本(相对路径，第一条)")
        self.tree.heading("b_move_count", text="B将移走数量")
        self.tree.heading("a_count", text="A文件数")
        self.tree.heading("b_count", text="B文件数")

        self.tree.column("key", width=220, anchor="w")
        self.tree.column("a_sample", width=520, anchor="w")
        self.tree.column("b_move_count", width=90, anchor="center")
        self.tree.column("a_count", width=70, anchor="center")
        self.tree.column("b_count", width=70, anchor="center")

        self.tree.bind("<Double-1>", self._toggle_selection)

        log_box = ttk.LabelFrame(frm, text="日志")
        log_box.pack(fill="both", expand=True, **pad)
        self.txt = tk.Text(log_box, height=10)
        self.txt.pack(fill="both", expand=True, padx=10, pady=8)

    # ---- helpers ----
    def log(self, msg: str):
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")
        self.update_idletasks()

    def pick_a(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_a.set(d)

    def pick_b(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_b.set(d)

    def pick_out(self):
        d = filedialog.askdirectory()
        if d:
            self.out_dir.set(d)

    def _parse_csv_list(self, s: str) -> List[str]:
        items = [x.strip() for x in s.split(",")]
        return [x for x in items if x]

    def _parse_exts(self, s: str) -> set:
        exts = set()
        for x in self._parse_csv_list(s):
            x = x.lower()
            if not x.startswith("."):
                x = "." + x
            exts.add(x)
        return exts

    def _set_progress(self, cur: int, total: int):
        def _():
            if total <= 0:
                self.pbar.config(mode="indeterminate")
                self.pbar.start(10)
                return
            self.pbar.config(mode="determinate", maximum=total, value=cur)
        self.after(0, _)

    def _threadsafe_log(self, msg: str):
        self.after(0, lambda: self.log(msg))

    def _threadsafe_done(self, title="完成", msg="操作完成"):
        def _():
            self.btn_scan.config(state="normal")
            st = "normal" if self.groups else "disabled"
            self.btn_move.config(state=st)
            self.btn_select_all.config(state=st)
            self.btn_select_none.config(state=st)
            self.pbar["value"] = 0
            messagebox.showinfo(title, msg)
        self.after(0, _)

    def _threadsafe_error(self, msg: str):
        def _():
            self.btn_scan.config(state="normal")
            self.btn_move.config(state="disabled")
            self.btn_select_all.config(state="disabled")
            self.btn_select_none.config(state="disabled")
            self.pbar["value"] = 0
            messagebox.showerror("出错", msg)
        self.after(0, _)

    def _clear_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _toggle_selection(self, _event=None):
        sel = set(self.tree.selection())
        item = self.tree.focus()
        if not item:
            return
        if item in sel:
            self.tree.selection_remove(item)
        else:
            self.tree.selection_add(item)

    def _select_all(self, yes: bool):
        items = self.tree.get_children()
        if yes:
            self.tree.selection_set(items)
        else:
            self.tree.selection_remove(items)

    # ---- scan + report ----
    def scan_and_report(self):
        a = self.folder_a.get().strip()
        b = self.folder_b.get().strip()
        out_dir = self.out_dir.get().strip()
        if not a or not os.path.isdir(a):
            messagebox.showerror("错误", "Folder A 无效")
            return
        if not b or not os.path.isdir(b):
            messagebox.showerror("错误", "Folder B 无效")
            return
        os.makedirs(out_dir, exist_ok=True)

        remove_tokens = self._parse_csv_list(self.remove_tokens.get())
        ignore_exts = self._parse_exts(self.ignore_exts.get())
        ignore_exts.add(".lrc")

        normalize = build_normalizer(
            remove_tokens=remove_tokens,
            remove_numbers=self.remove_numbers.get(),
            remove_symbols=self.remove_symbols.get(),
            casefold=self.casefold.get(),
        )

        self.btn_scan.config(state="disabled")
        self.btn_move.config(state="disabled")
        self.btn_select_all.config(state="disabled")
        self.btn_select_none.config(state="disabled")
        self.pbar["value"] = 0
        self.groups = []
        self._clear_tree()

        self.log("== Scan & Report (Keep A, Move B) ==")
        self.log(f"Folder A: {a} (keep)")
        self.log(f"Folder B: {b} (move duplicates)")
        self.log(f"Out dir : {out_dir}")
        self.log(f"Remove tokens: {remove_tokens}")
        self.log(f"Ignore exts  : {sorted(ignore_exts)}")
        self.log("")

        def worker():
            try:
                self._threadsafe_log("[1/3] 扫描 A ...")
                map_a = scan_folder(a, "A", normalize, ignore_exts, progress_cb=self._set_progress, log_cb=self._threadsafe_log)

                self._threadsafe_log("[2/3] 扫描 B ...")
                map_b = scan_folder(b, "B", normalize, ignore_exts, progress_cb=self._set_progress, log_cb=self._threadsafe_log)

                self._threadsafe_log("[3/3] 生成报告 & 分组 ...")
                all_keys = sorted(set(map_a.keys()) | set(map_b.keys()))

                report_rows = []
                dup_rows = []
                plan_rows = []

                groups: List[GroupRec] = []

                for key in all_keys:
                    a_list = map_a.get(key, [])
                    b_list = map_b.get(key, [])

                    status = "重复(两边都有)" if (a_list and b_list) else ("仅A存在" if a_list else "仅B存在")
                    report_rows.append([
                        status, key,
                        " ; ".join([safe_relpath(x.path, a) for x in a_list]),
                        " ; ".join([safe_relpath(x.path, b) for x in b_list]),
                    ])

                    group_files = a_list + b_list
                    if len(group_files) >= 2:
                        for rec in group_files:
                            base = a if rec.side == "A" else b
                            dup_rows.append([key, rec.side, safe_relpath(rec.path, base), rec.ext, str(rec.size)])

                    if a_list and b_list:
                        keep_a = a_list[0]  # A永远保留；这里仅展示样本
                        plan_rows.append([
                            key,
                            f"A:{safe_relpath(keep_a.path, a)}",
                            keep_a.ext,
                            str(keep_a.size),
                            " | ".join([f"B:{safe_relpath(x.path, b)}" for x in b_list]),
                            "MOVE_B"
                        ])
                        groups.append(GroupRec(key=key, a_files=a_list, b_files=b_list))
                    else:
                        if a_list and not b_list:
                            keep_a = a_list[0]
                            plan_rows.append([key, f"A:{safe_relpath(keep_a.path, a)}", keep_a.ext, str(keep_a.size), "", "KEEP_ONLY"])
                        elif b_list and not a_list:
                            plan_rows.append([key, "", "", "", " | ".join([f"B:{safe_relpath(x.path, b)}" for x in b_list]), "B_ONLY_NO_ACTION"])

                report_path = os.path.join(out_dir, REPORT_NAME)
                dups_path = os.path.join(out_dir, DUPLICATES_NAME)
                plan_path = os.path.join(out_dir, KEEP_PLAN_NAME)

                write_csv(report_path, ["状态", "标准化Key", "FolderA文件(相对路径)", "FolderB文件(相对路径)"], report_rows)
                write_csv(dups_path, ["标准化Key", "来源(A/B)", "相对路径", "扩展名", "大小(bytes)"], dup_rows)
                write_csv(plan_path, ["标准化Key", "建议保留(A固定)", "保留扩展名", "保留大小(bytes)", "B建议移动列表", "动作"], plan_rows)

                self.after(0, lambda: self._populate_groups(groups, a, b))

                self._threadsafe_log("")
                self._threadsafe_log("导出完成 ✅")
                self._threadsafe_log(f"  {REPORT_NAME}     : {report_path}")
                self._threadsafe_log(f"  {DUPLICATES_NAME} : {dups_path}")
                self._threadsafe_log(f"  {KEEP_PLAN_NAME}  : {plan_path}")
                self._threadsafe_log("")
                self._threadsafe_log("提示：移动操作只会影响 B。移动前会做回收站同名冲突预检。")
                self._threadsafe_done("完成", f"扫描完成：可处理分组 {len(groups)} 组（Key 在 A 且 B 也存在）。")

            except Exception as e:
                self._threadsafe_error(str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _populate_groups(self, groups: List[GroupRec], a: str, b: str):
        self.groups = groups
        self._clear_tree()

        for idx, g in enumerate(groups):
            a_first = safe_relpath(g.a_files[0].path, a) if g.a_files else ""
            iid = f"g{idx}"
            self.tree.insert("", "end", iid=iid, values=(g.key, a_first, len(g.b_files), len(g.a_files), len(g.b_files)))

        self._select_all(True)

        st = "normal" if self.groups else "disabled"
        self.btn_move.config(state=st)
        self.btn_select_all.config(state=st)
        self.btn_select_none.config(state=st)

    # ---- conflict preflight ----
    def _preflight_conflicts(self, b_files: List[FileRec], b_base: str, trash_root: str) -> Tuple[int, List[str], Set[str]]:
        """
        返回：
          conflict_count, examples(list), existing_or_planned_conflict_set
        其中 existing_or_planned_conflict_set 是 “原始目标路径 planned_dst” 的集合（用于 SKIP/OVERWRITE 判断）
        """
        conflicts = 0
        examples: List[str] = []
        conflict_planned_set: Set[str] = set()

        planned_seen: Set[str] = set()
        for bf in b_files:
            planned_dst = planned_trash_path_for_b(bf, b_base, trash_root)
            # 1) 回收站已存在
            exist_conflict = os.path.exists(planned_dst)
            # 2) 本批次内部重复写同一路径（相对路径一致）
            batch_conflict = planned_dst in planned_seen

            if exist_conflict or batch_conflict:
                conflicts += 1
                conflict_planned_set.add(planned_dst)
                if len(examples) < 20:
                    tag = []
                    if exist_conflict:
                        tag.append("exists")
                    if batch_conflict:
                        tag.append("batch")
                    examples.append(f"{planned_dst}    [{'/'.join(tag)}]")
            planned_seen.add(planned_dst)

        return conflicts, examples, conflict_planned_set

    # ---- move selected ----
    def move_selected(self):
        if not self.groups:
            messagebox.showwarning("提示", "没有可处理分组。请先扫描。")
            return
        if not self.enable_trash.get():
            messagebox.showwarning("提示", "你未勾选安全回收站选项。")
            return

        a = os.path.abspath(self.folder_a.get().strip())
        b = os.path.abspath(self.folder_b.get().strip())
        out_dir = os.path.abspath(self.out_dir.get().strip())

        trash_root = os.path.join(out_dir, TRASH_DIR_NAME)
        ensure_dir(trash_root)

        sel = list(self.tree.selection())
        if not sel:
            messagebox.showwarning("提示", "未选择任何分组。")
            return

        sel_indices = []
        for iid in sel:
            if iid.startswith("g"):
                try:
                    sel_indices.append(int(iid[1:]))
                except ValueError:
                    pass
        sel_indices = sorted(set(sel_indices))
        selected_groups = [self.groups[i] for i in sel_indices if 0 <= i < len(self.groups)]
        if not selected_groups:
            messagebox.showwarning("提示", "选择无效。")
            return

        # 本次要移动的 B 文件
        b_files_to_move: List[FileRec] = []
        for g in selected_groups:
            b_files_to_move.extend(g.b_files)

        total_move = len(b_files_to_move)
        if total_move <= 0:
            messagebox.showinfo("提示", "选中的分组没有 B 文件可移动。")
            return

        # 预检冲突
        conflict_count, examples, conflict_planned_set = self._preflight_conflicts(b_files_to_move, b, trash_root)

        # 冲突策略默认：RENAME（最安全）
        strategy = CONFLICT_RENAME
        if conflict_count > 0:
            # 弹窗让用户选策略
            dlg = ConflictDialog(self, conflict_count, total_move, examples)
            self.wait_window(dlg)
            if dlg.choice is None:
                return  # 用户取消
            strategy = dlg.choice

        # 总体确认
        if not messagebox.askyesno(
            "确认",
            f"将选中的 {len(selected_groups)} 组里，B 的 {total_move} 个文件移动到回收站？\n"
            f"A 不会被修改；冲突策略：{strategy}"
        ):
            return

        self.btn_scan.config(state="disabled")
        self.btn_move.config(state="disabled")
        self.btn_select_all.config(state="disabled")
        self.btn_select_none.config(state="disabled")
        self.pbar["value"] = 0

        self.log("")
        self.log(f"== Move B to Trash == 目标：{trash_root}")
        self.log(f"冲突策略：{strategy}（冲突数 {conflict_count}/{total_move}）")

        def worker():
            try:
                moves: List[Tuple[str, str]] = []
                manifest_rows: List[List[str]] = []

                # 批次保留集合：避免 RENAME 时同批次撞到同名后缀
                reserved: Set[str] = set()

                self._set_progress(0, total_move)
                done = 0
                failed = 0
                skipped = 0
                overwritten = 0
                renamed = 0

                # 为 manifest 记录 A 样本
                # key -> "A:xxx"
                keep_map: Dict[str, str] = {}
                for g in selected_groups:
                    keep_map[g.key] = f"A:{safe_relpath(g.a_files[0].path, a)}" if g.a_files else "A:(missing?)"

                for g in selected_groups:
                    keep_show = keep_map.get(g.key, "A:(missing?)")

                    for bf in g.b_files:
                        done += 1
                        self._set_progress(done, total_move)

                        planned_dst = planned_trash_path_for_b(bf, b, trash_root)
                        is_conflict = os.path.exists(planned_dst) or (planned_dst in reserved)

                        # SKIP：冲突则跳过
                        if is_conflict and strategy == CONFLICT_SKIP:
                            skipped += 1
                            continue

                        # 确保目录存在
                        ensure_dir(os.path.dirname(planned_dst))

                        try:
                            # OVERWRITE：冲突则删除旧的
                            if is_conflict and strategy == CONFLICT_OVERWRITE:
                                if os.path.exists(planned_dst):
                                    try:
                                        os.remove(planned_dst)
                                    except Exception:
                                        # 可能是只读/占用/权限，后面 move 会失败，这里让它抛出更明确
                                        pass
                                overwritten += 1
                                dst = planned_dst
                            elif strategy == CONFLICT_RENAME:
                                # RENAME：永远用 unique_path 生成最终 dst（不冲突则原路径）
                                dst = unique_path(planned_dst, reserved=reserved)
                                if dst != planned_dst:
                                    renamed += 1
                            else:
                                # 非冲突 or OVERWRITE 已处理
                                dst = planned_dst

                            # 预占用
                            reserved.add(dst)

                            # 执行 move
                            shutil.move(bf.path, dst)
                            moves.append((dst, bf.path))

                            b_rel = safe_relpath(bf.path, b)
                            t_rel = safe_relpath(dst, trash_root)
                            manifest_rows.append([
                                g.key,
                                keep_show,
                                f"B:{b_rel}",
                                t_rel,
                                bf.ext,
                                str(bf.size),
                                bf.path,
                                dst,
                                strategy
                            ])
                        except Exception as e:
                            failed += 1
                            self._threadsafe_log(f"[FAIL] {bf.path} -> {e}")

                manifest_path = os.path.join(out_dir, MANIFEST_NAME)
                write_csv(
                    manifest_path,
                    ["标准化Key", "保留A样本", "移动的B文件(相对B)", "回收站相对路径", "扩展名", "大小(bytes)", "原绝对路径", "回收站绝对路径", "冲突策略"],
                    manifest_rows
                )

                restore_path = os.path.join(out_dir, RESTORE_BAT_NAME)
                make_restore_bat(restore_path, moves)

                self._threadsafe_log("")
                self._threadsafe_log("移动完成 ✅（只移动B）")
                self._threadsafe_log(f"  moved      : {len(moves)}")
                self._threadsafe_log(f"  skipped    : {skipped} (strategy=SKIP)")
                self._threadsafe_log(f"  overwritten: {overwritten} (strategy=OVERWRITE)")
                self._threadsafe_log(f"  renamed    : {renamed} (strategy=RENAME)")
                self._threadsafe_log(f"  failed     : {failed}")
                self._threadsafe_log(f"  manifest   : {manifest_path}")
                self._threadsafe_log(f"  restore    : {restore_path}")
                self._threadsafe_log(f"  trash      : {trash_root}")
                self._threadsafe_log("")
                self._threadsafe_log("提示：确认无误后，可手动清空回收站目录；如需回滚，运行 restore_from_trash.bat。")

                self._threadsafe_done("完成", f"移动完成：moved={len(moves)} skipped={skipped} failed={failed}。")

            except Exception as e:
                self._threadsafe_error(str(e))

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = App()
    app.geometry("1060x780")
    app.mainloop()