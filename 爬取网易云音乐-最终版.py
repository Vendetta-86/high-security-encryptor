import os
import re
import json
import time
import threading
import queue
import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urljoin, urlparse
import subprocess
import shutil

# ==========================
# 默认配置
# ==========================
DEFAULT_BASE_URL = "http://localhost:3000"
DEFAULT_HEALTH_PATH = "/"          # 通用健康检测：不绑定业务API；留空=只测BaseURL
LIMIT_DEFAULT = 20
MAX_WORKERS = 3
APP_NAME = "NCMDownloader"
# ==========================

# ========= mutagen（ID3） =========
MUTAGEN_OK = True
try:
    from mutagen.mp3 import MP3
    from mutagen.id3 import ID3, APIC, USLT, ID3NoHeaderError
    from mutagen.easyid3 import EasyID3
except Exception:
    MUTAGEN_OK = False


# ========= 路径（全 AppData，稳） =========
def get_app_paths(app_name: str = APP_NAME):
    appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
    base_dir = os.path.join(appdata, app_name)
    download_root = os.path.join(base_dir, "downloads")
    os.makedirs(base_dir, exist_ok=True)
    os.makedirs(download_root, exist_ok=True)
    return {
        "base_dir": base_dir,
        "state_file": os.path.join(base_dir, "state.json"),
        "cache_file": os.path.join(base_dir, "download_cache.txt"),
        "default_download_dir": download_root,
        "api_log_file": os.path.join(base_dir, "api_process.log"),
    }


PATHS = get_app_paths(APP_NAME)
STATE_FILE = PATHS["state_file"]
CACHE_FILE = PATHS["cache_file"]
DEFAULT_DOWNLOAD_DIR = PATHS["default_download_dir"]
API_LOG_FILE = PATHS["api_log_file"]


# ========= 工具 =========
def safe_filename(name: str) -> str:
    name = (name or "").strip() or "未知"
    return re.sub(r'[\\/:*?"<>|]', "_", name)


def guess_ext_from_url(url: str) -> str:
    m = re.search(r'\.([a-zA-Z0-9]{2,5})(?:\?|$)', url or "")
    return m.group(1).lower() if m else "mp3"


def with_retry(fn, tries=3, base_sleep=0.8):
    last = None
    for i in range(tries):
        try:
            return fn()
        except Exception as e:
            last = e
            if i == tries - 1:
                raise
            time.sleep(base_sleep * (2 ** i))
    raise last


def normalize_song_fields(song: dict):
    name = song.get("name") or "未知歌曲"
    artist_list = song.get("artists") or song.get("ar") or []
    artists = " / ".join([a.get("name", "") for a in artist_list]).strip() or "未知歌手"
    album_obj = song.get("album") or song.get("al") or {}
    album = album_obj.get("name", "") or ""
    fee = song.get("fee", 0)
    song_id = str(song.get("id", ""))
    return song_id, name, artists, album, fee


def compact_song_for_state(song: dict) -> dict:
    sid, name, artists, album, fee = normalize_song_fields(song)
    al = song.get("al") or song.get("album") or {}
    pic = al.get("picUrl") or al.get("pic_url") or ""
    return {"id": sid, "name": name, "artists": artists, "album": album, "fee": fee, "picUrl": pic}


# ========= LRC 双语合并 =========
def parse_lrc_lines(lrc_text: str) -> dict[int, str]:
    if not lrc_text:
        return {}
    out = {}
    for raw in lrc_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.match(r'^\[(ti|ar|al|by|offset):', line, re.I):
            continue
        times = re.findall(r'\[(\d{1,2}):(\d{2})(?:\.(\d{1,3}))?\]', line)
        if not times:
            continue
        text = re.sub(r'(\[\d{1,2}:\d{2}(?:\.\d{1,3})?\])', '', line).strip()
        if text == "":
            continue
        for mm, ss, xx in times:
            mm_i = int(mm)
            ss_i = int(ss)
            ms = int(xx.ljust(3, '0')) if xx else 0
            t = (mm_i * 60 + ss_i) * 1000 + ms
            out[t] = text
    return out


def ms_to_lrc_ts(ms: int) -> str:
    mm = ms // 60000
    ss = (ms % 60000) // 1000
    xx = (ms % 1000) // 10
    return f"[{mm:02d}:{ss:02d}.{xx:02d}]"


def merge_bilingual_lrc(orig: str, trans: str) -> str:
    o = parse_lrc_lines(orig)
    t = parse_lrc_lines(trans)
    if not o and not t:
        return ""
    keys = sorted(set(o.keys()) | set(t.keys()))
    lines = []
    for k in keys:
        ts = ms_to_lrc_ts(k)
        if k in o:
            lines.append(f"{ts}{o[k]}")
        if k in t:
            lines.append(f"{ts}{t[k]}")
    return "\n".join(lines).strip() + "\n"


def strip_lrc_timestamps(lrc_text: str) -> str:
    if not lrc_text:
        return ""
    out_lines = []
    for raw in lrc_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.match(r'^\[(ti|ar|al|by|offset):', line, re.I):
            continue
        line2 = re.sub(r'\[(\d{1,2}):(\d{2})(?:\.(\d{1,3}))?\]', '', line).strip()
        if line2:
            out_lines.append(line2)
    return "\n".join(out_lines).strip()


# ========= ID3 写入（mp3） =========
def write_id3_mp3(file_path: str, title: str, artist: str, album: str,
                  cover_bytes: bytes | None, cover_mime: str | None,
                  lyric_plain: str | None):
    if not MUTAGEN_OK:
        return False, "未安装 mutagen（pip install mutagen）"
    if not file_path.lower().endswith(".mp3"):
        return False, "非 mp3：跳过 ID3（目前仅写 mp3）"
    try:
        try:
            audio = MP3(file_path, ID3=ID3)
            if audio.tags is None:
                audio.add_tags()
        except ID3NoHeaderError:
            audio = MP3(file_path, ID3=ID3)
            audio.add_tags()

        try:
            tags = EasyID3(file_path)
        except Exception:
            tags = EasyID3()
        tags["title"] = [title]
        tags["artist"] = [artist]
        if album:
            tags["album"] = [album]
        tags.save(file_path)

        audio = MP3(file_path, ID3=ID3)

        if cover_bytes and cover_mime:
            audio.tags.delall("APIC")
            audio.tags.add(APIC(encoding=3, mime=cover_mime, type=3, desc="Cover", data=cover_bytes))

        if lyric_plain:
            audio.tags.delall("USLT")
            audio.tags.add(USLT(encoding=3, lang="chi", desc="Lyrics", text=lyric_plain))

        audio.save(v2_version=3)
        return True, "ID3 写入完成"
    except Exception as e:
        return False, str(e)


# ========= API 自启动（通用启动器，不绑定业务接口） =========
def parse_host_port(base_url: str):
    u = urlparse(base_url.strip())
    host = u.hostname or ""
    port = u.port
    if port is None:
        port = 443 if (u.scheme == "https") else 80
    return host.lower(), int(port)


def is_localhost(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "0.0.0.0")


def list_candidate_api_dirs(preferred_dir: str | None = None):
    dirs = []
    if preferred_dir:
        dirs.append(preferred_dir)

    try:
        here = os.path.dirname(os.path.abspath(__file__))
        dirs.append(here)
        dirs.append(os.path.dirname(here))
    except Exception:
        pass

    try:
        dirs.append(os.getcwd())
        dirs.append(os.path.dirname(os.getcwd()))
    except Exception:
        pass

    dirs.append(PATHS["base_dir"])

    subnames = ["api-enhanced", "api", "server", "netease_api", "NeteaseCloudMusicApiEnhanced", "music-api"]

    expanded = []
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        expanded.append(d)
        for sn in subnames:
            expanded.append(os.path.join(d, sn))

    seen = set()
    out = []
    for d in expanded:
        d2 = os.path.normpath(d)
        if d2 in seen:
            continue
        seen.add(d2)
        if os.path.isdir(d2):
            out.append(d2)
    return out


def find_api_project_dir(preferred_dir: str | None = None) -> str | None:
    for d in list_candidate_api_dirs(preferred_dir):
        app_js = os.path.join(d, "app.js")
        pkg = os.path.join(d, "package.json")
        if os.path.isfile(app_js) and os.path.isfile(pkg):
            return d
    return None


def start_node_api(project_dir: str, port: int) -> subprocess.Popen | None:
    node = shutil.which("node")
    if not node:
        return None

    env = os.environ.copy()
    env["PORT"] = str(port)

    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

    try:
        logf = open(API_LOG_FILE, "a", encoding="utf-8", errors="ignore")
        logf.write(f"\n[{datetime.now().isoformat(timespec='seconds')}] starting: node app.js (PORT={port}) in {project_dir}\n")
        logf.flush()

        p = subprocess.Popen(
            [node, "app.js"],
            cwd=project_dir,
            env=env,
            stdout=logf,
            stderr=logf,
            creationflags=creationflags
        )
        return p
    except Exception:
        return None


# ========= App =========
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("专业下载器（自启API + 结果内搜索 + 聚合N页 + limit可调 + 自选下载目录 + 落盘 + 断点续传 + 双语歌词 + ID3）")
        self.root.geometry("1280x980")

        # 状态
        self.keyword = ""
        self.current_page = 1
        self.downloaded_ids = set()
        self.selected_by_id: dict[str, bool] = {}
        self.song_cache: dict[str, dict] = {}
        self.ui_rows: dict[str, dict] = {}

        # API 配置
        self.base_url = DEFAULT_BASE_URL
        self.health_path = DEFAULT_HEALTH_PATH

        # API 自启动配置
        self.auto_start_api = True
        self.api_dir_hint = ""
        self.api_process: subprocess.Popen | None = None

        # 下载目录
        self.download_dir = DEFAULT_DOWNLOAD_DIR

        # B路线：limit 可调；A路线：聚合页数可调
        self.search_limit = LIMIT_DEFAULT
        self.agg_pages = 5

        # 结果内搜索（过滤）相关
        self.last_render_source_items: list[dict] = []   # 当前“结果集合”（未过滤）
        self.filter_query = ""                           # 当前过滤关键字（小写）

        # 聚合控制（中止聚合）
        self.aggregate_cancel_event = threading.Event()
        self.is_aggregated_view = False
        self.unaggregated_snapshot_items: list[dict] | None = None

        # 并发
        self.ui_q = queue.Queue()
        self.search_lock = threading.Lock()
        self.down_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.session = requests.Session()

        self._build_ui()
        self._load_cache()
        self._load_state()
        self._drain_ui_queue()

        self.root.after(300, self.ensure_api_ready_async)

    # ---------- UI ----------

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        # API 设置行
        api_row = ttk.Frame(top)
        api_row.pack(fill="x", pady=(0, 8))

        ttk.Label(api_row, text="API Base URL：").pack(side="left")
        self.base_url_var = tk.StringVar(value=self.base_url)
        self.base_url_entry = ttk.Entry(api_row, width=38, textvariable=self.base_url_var)
        self.base_url_entry.pack(side="left", padx=(0, 10))

        ttk.Label(api_row, text="健康检测 Path：").pack(side="left")
        self.health_path_var = tk.StringVar(value=self.health_path)
        self.health_entry = ttk.Entry(api_row, width=10, textvariable=self.health_path_var)
        self.health_entry.pack(side="left", padx=(0, 10))
        ttk.Label(api_row, text="（留空=只测BaseURL）", foreground="gray").pack(side="left")

        self.auto_start_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(api_row, text="自动启动API（本机）", variable=self.auto_start_var).pack(side="left", padx=10)

        ttk.Button(api_row, text="选择 API 目录（可选）", command=self.pick_api_dir).pack(side="right")
        ttk.Button(api_row, text="测试/确保 API 可用", command=self.ensure_api_ready_async).pack(side="right", padx=8)

        # 下载目录行
        dl_row = ttk.Frame(top)
        dl_row.pack(fill="x", pady=(0, 8))

        ttk.Label(dl_row, text="下载目录：").pack(side="left")
        self.download_dir_var = tk.StringVar(value=self.download_dir)
        self.download_dir_entry = ttk.Entry(dl_row, width=72, textvariable=self.download_dir_var)
        self.download_dir_entry.pack(side="left", padx=(0, 10), fill="x", expand=True)

        ttk.Button(dl_row, text="选择下载目录", command=self.pick_download_dir).pack(side="left")
        ttk.Button(dl_row, text="打开下载目录", command=self.open_download_dir).pack(side="left", padx=6)

        # 搜索行
        search_row = ttk.Frame(top)
        search_row.pack(fill="x")

        ttk.Label(search_row, text="关键词：").pack(side="left")
        self.entry = ttk.Entry(search_row, width=45)
        self.entry.pack(side="left", padx=(0, 8))
        self.entry.bind("<Return>", lambda e: self.search(1))

        self.btn_search = ttk.Button(search_row, text="搜索", command=lambda: self.search(1))
        self.btn_search.pack(side="left")

        if not MUTAGEN_OK:
            ttk.Label(search_row, text="（未安装 mutagen：将跳过 ID3）", foreground="gray").pack(side="left", padx=10)

        # 参数行：limit + 聚合页数 + 聚合/中止
        param_row = ttk.Frame(top)
        param_row.pack(fill="x", pady=(6, 0))

        ttk.Label(param_row, text="limit（一次返回条数）：").pack(side="left")
        self.limit_var = tk.StringVar(value=str(self.search_limit))
        self.limit_entry = ttk.Entry(param_row, width=6, textvariable=self.limit_var)
        self.limit_entry.pack(side="left", padx=(0, 12))
        ttk.Label(param_row, text="（B路线：调大=一次拿更多）", foreground="gray").pack(side="left")

        ttk.Label(param_row, text="  聚合页数：").pack(side="left", padx=(12, 0))
        self.agg_var = tk.StringVar(value=str(self.agg_pages))
        self.agg_entry = ttk.Entry(param_row, width=6, textvariable=self.agg_var)
        self.agg_entry.pack(side="left", padx=(0, 8))
        ttk.Label(param_row, text="（A路线：聚合N页再二次筛选）", foreground="gray").pack(side="left", padx=(0, 8))

        self.btn_aggregate = ttk.Button(param_row, text="聚合并显示", command=self.aggregate_current_query_async)
        self.btn_aggregate.pack(side="left", padx=6)

        self.btn_cancel_aggregate = ttk.Button(param_row, text="中止聚合并还原", command=self.cancel_aggregate_and_restore)
        self.btn_cancel_aggregate.pack(side="left", padx=6)

        ttk.Button(param_row, text="恢复为当前页结果", command=self.restore_current_page_result).pack(side="left", padx=6)

        # 结果内搜索（过滤）
        filter_row = ttk.Frame(top)
        filter_row.pack(fill="x", pady=(6, 0))

        ttk.Label(filter_row, text="结果内搜索：").pack(side="left")
        self.filter_var = tk.StringVar(value="")
        self.filter_entry = ttk.Entry(filter_row, width=40, textvariable=self.filter_var)
        self.filter_entry.pack(side="left", padx=(0, 8))
        self.filter_entry.bind("<Return>", lambda e: self.apply_filter())

        ttk.Button(filter_row, text="过滤", command=self.apply_filter).pack(side="left")
        ttk.Button(filter_row, text="清除过滤", command=self.clear_filter).pack(side="left", padx=6)
        ttk.Label(filter_row, text="（在当前结果集合内模糊匹配：歌名/歌手/专辑）", foreground="gray").pack(side="left", padx=10)

        # 分页
        pager = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        pager.pack(fill="x")

        self.btn_prev = ttk.Button(pager, text="上一页", command=self.prev_page)
        self.btn_prev.pack(side="left")

        self.btn_next = ttk.Button(pager, text="下一页", command=self.next_page)
        self.btn_next.pack(side="left", padx=6)

        self.page_label = ttk.Label(pager, text="第 1 页")
        self.page_label.pack(side="left", padx=12)

        ttk.Label(pager, text="跳转到页：").pack(side="left")
        self.jump_entry = ttk.Entry(pager, width=6)
        self.jump_entry.pack(side="left", padx=(0, 6))
        self.btn_jump = ttk.Button(pager, text="跳转", command=self.jump_page)
        self.btn_jump.pack(side="left")

        # 操作区
        action = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        action.pack(fill="x")

        ttk.Button(action, text="全选（当前页）", command=self.select_all_current_page).pack(side="left")
        ttk.Button(action, text="取消全选（当前页）", command=self.unselect_all_current_page).pack(side="left", padx=6)

        self.force_redownload = tk.BooleanVar(value=False)
        ttk.Checkbutton(action, text="强制重新下载音频（忽略缓存）", variable=self.force_redownload).pack(side="left", padx=10)

        self.btn_download = ttk.Button(action, text="下载选中（所有页）", command=self.download_selected_all_pages)
        self.btn_download.pack(side="left", padx=12)

        self.api_status_label = ttk.Label(action, text="API：未检测", foreground="gray")
        self.api_status_label.pack(side="right")

        # 列表滚动区
        list_wrap = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        list_wrap.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(list_wrap, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(list_wrap, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.list_frame = ttk.Frame(self.canvas)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.list_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_window, width=e.width))

        # 日志
        log_wrap = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        log_wrap.pack(fill="both")
        ttk.Label(log_wrap, text=f"日志（状态/缓存：{PATHS['base_dir']} | API日志：{API_LOG_FILE}）：").pack(anchor="w")
        self.log = tk.Text(log_wrap, height=11)
        self.log.pack(fill="both", expand=False)

    # ---------- 选择目录 ----------

    def pick_download_dir(self):
        d = filedialog.askdirectory(title="选择下载目录")
        if d:
            self.download_dir = os.path.normpath(d)
            self.download_dir_var.set(self.download_dir)
            try:
                os.makedirs(self.download_dir, exist_ok=True)
            except Exception as e:
                self.ui_message("错误", f"创建下载目录失败：{e}", "error")
            self._save_state()

    def open_download_dir(self):
        d = (self.download_dir_var.get() or "").strip()
        if not d:
            return
        try:
            os.makedirs(d, exist_ok=True)
            if os.name == "nt":
                os.startfile(d)
        except Exception as e:
            self.ui_message("错误", f"打开目录失败：{e}", "error")

    def pick_api_dir(self):
        d = filedialog.askdirectory(title="选择 API 项目目录（包含 app.js & package.json）")
        if d:
            self.api_dir_hint = os.path.normpath(d)
            self.ui_log(f"已选择 API 目录：{self.api_dir_hint}\n")
            self._save_state()

    # ---------- 线程安全 UI ----------

    def ui_log(self, text: str):
        self.ui_q.put(("log", text))

    def ui_set_busy(self, busy: bool):
        self.ui_q.put(("busy", busy))

    def ui_set_page_label(self, page: int):
        self.ui_q.put(("page_label", page))

    def ui_row_status(self, song_id: str, text: str):
        self.ui_q.put(("row_status", song_id, text))

    def ui_row_progress(self, song_id: str, value: int | None, maximum: int | None, mode: str | None = None):
        self.ui_q.put(("row_progress", song_id, value, maximum, mode))

    def ui_message(self, title: str, msg: str, kind: str = "info"):
        self.ui_q.put(("message", title, msg, kind))

    def ui_api_status(self, ok: bool, text: str):
        self.ui_q.put(("api_status", ok, text))

    def _drain_ui_queue(self):
        try:
            while True:
                item = self.ui_q.get_nowait()
                typ = item[0]

                if typ == "log":
                    self.log.insert(tk.END, item[1])
                    self.log.see(tk.END)

                elif typ == "busy":
                    state = "disabled" if item[1] else "normal"
                    for b in (self.btn_search, self.btn_prev, self.btn_next, self.btn_jump,
                              self.btn_aggregate, self.btn_cancel_aggregate):
                        b.config(state=state)

                elif typ == "page_label":
                    self.page_label.config(text=f"第 {item[1]} 页")

                elif typ == "row_status":
                    sid, text = item[1], item[2]
                    row = self.ui_rows.get(sid)
                    if row:
                        row["status"].config(text=text)

                elif typ == "row_progress":
                    sid, value, maximum, mode = item[1], item[2], item[3], item[4]
                    row = self.ui_rows.get(sid)
                    if row:
                        pb: ttk.Progressbar = row["progress"]
                        if mode:
                            pb.config(mode=mode)
                            if mode == "indeterminate":
                                pb.start(10)
                            else:
                                pb.stop()
                        if maximum is not None and maximum > 0:
                            pb.config(maximum=maximum)
                        if value is not None:
                            pb.config(value=value)

                elif typ == "message":
                    title, msg, kind = item[1], item[2], item[3]
                    if kind == "info":
                        messagebox.showinfo(title, msg)
                    elif kind == "warning":
                        messagebox.showwarning(title, msg)
                    else:
                        messagebox.showerror(title, msg)

                elif typ == "api_status":
                    ok, text = item[1], item[2]
                    self.api_status_label.config(text=f"API：{text}", foreground=("green" if ok else "red"))

                elif typ == "render_list":
                    self._render_list(item[1])

        except queue.Empty:
            pass

        self.root.after(30, self._drain_ui_queue)

    # ---------- 落盘：cache/state ----------

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        self.downloaded_ids.add(s)

    def _save_cache(self, song_id: str):
        with open(CACHE_FILE, "a", encoding="utf-8") as f:
            f.write(song_id + "\n")
        self.downloaded_ids.add(song_id)

    def rewrite_download_cache_file(self):
        try:
            tmp = CACHE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for sid in sorted(self.downloaded_ids):
                    f.write(sid + "\n")
            os.replace(tmp, CACHE_FILE)
        except Exception as e:
            self.ui_log(f"重写 {CACHE_FILE} 失败：{e}\n")

    def _load_state(self):
        if not os.path.exists(STATE_FILE):
            self._save_state()
            return
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.selected_by_id = {str(k): bool(v) for k, v in (data.get("selected_by_id") or {}).items()}
            self.song_cache = {str(k): v for k, v in (data.get("song_cache") or {}).items()}
            self.keyword = data.get("keyword") or ""
            self.current_page = int(data.get("current_page") or 1)

            self.base_url = data.get("base_url") or DEFAULT_BASE_URL
            self.health_path = data.get("health_path", DEFAULT_HEALTH_PATH)

            self.auto_start_api = bool(data.get("auto_start_api", True))
            self.api_dir_hint = data.get("api_dir_hint", "") or ""

            self.download_dir = data.get("download_dir") or DEFAULT_DOWNLOAD_DIR
            os.makedirs(self.download_dir, exist_ok=True)

            self.search_limit = int(data.get("search_limit", LIMIT_DEFAULT))
            self.agg_pages = int(data.get("agg_pages", 5))

            # UI 回填
            self.base_url_var.set(self.base_url)
            self.health_path_var.set(self.health_path)
            self.auto_start_var.set(self.auto_start_api)
            self.download_dir_var.set(self.download_dir)
            self.limit_var.set(str(self.search_limit))
            self.agg_var.set(str(self.agg_pages))

            if self.keyword:
                self.entry.insert(0, self.keyword)
                self.page_label.config(text=f"第 {self.current_page} 页")

            self.ui_log(
                f"已载入状态：选中 {sum(1 for v in self.selected_by_id.values() if v)} 首，缓存 {len(self.song_cache)} 首\n"
            )
        except Exception as e:
            self.ui_log(f"载入 {STATE_FILE} 失败：{e}\n")

    def _save_state(self):
        try:
            data = {
                "version": 4,
                "saved_at": datetime.now().isoformat(timespec="seconds"),

                "keyword": self.keyword,
                "current_page": self.current_page,
                "selected_by_id": self.selected_by_id,
                "song_cache": self.song_cache,

                "base_url": self.base_url,
                "health_path": self.health_path,

                "auto_start_api": bool(self.auto_start_var.get()) if hasattr(self, "auto_start_var") else self.auto_start_api,
                "api_dir_hint": self.api_dir_hint,

                "download_dir": self.download_dir_var.get().strip() if hasattr(self, "download_dir_var") else self.download_dir,

                "search_limit": self.search_limit,
                "agg_pages": self.agg_pages,
            }

            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, STATE_FILE)
        except Exception as e:
            self.ui_log(f"保存状态失败：{e}\n")

    # ---------- 配置刷新 ----------

    def _refresh_config_from_ui(self):
        base = (self.base_url_var.get() or "").strip()
        if base.endswith("/"):
            base = base[:-1]
        self.base_url = base or DEFAULT_BASE_URL

        hp = (self.health_path_var.get() or "").strip()
        if hp and not hp.startswith("/"):
            hp = "/" + hp
        self.health_path = hp

        self.auto_start_api = bool(self.auto_start_var.get())

        dd = (self.download_dir_var.get() or "").strip()
        if dd:
            self.download_dir = os.path.normpath(dd)
            os.makedirs(self.download_dir, exist_ok=True)

        self._read_limit_and_agg_from_ui()

        self._save_state()

    def _read_limit_and_agg_from_ui(self):
        # limit
        s = (self.limit_var.get() or "").strip()
        try:
            v = int(s)
            if v <= 0:
                v = LIMIT_DEFAULT
        except Exception:
            v = LIMIT_DEFAULT
        if v > 200:
            v = 200
        self.search_limit = v
        self.limit_var.set(str(v))

        # agg pages
        s2 = (self.agg_var.get() or "").strip()
        try:
            p = int(s2)
            if p <= 0:
                p = 1
        except Exception:
            p = 1
        if p > 50:
            p = 50
        self.agg_pages = p
        self.agg_var.set(str(p))

    # ---------- API 健康检测 & 自启 ----------

    def _health_url(self) -> str:
        if not self.health_path:
            return self.base_url
        return urljoin(self.base_url + "/", self.health_path.lstrip("/"))

    def check_api_reachable(self) -> tuple[bool, str]:
        try:
            url = self._health_url()
            r = self.session.get(url, timeout=(2.5, 6), allow_redirects=True)
            ok = (200 <= r.status_code < 500)
            return ok, f"{'可达' if ok else '异常'}（HTTP {r.status_code}）"
        except Exception as e:
            return False, f"不可达（{type(e).__name__}）"

    def ensure_api_ready_async(self):
        self._refresh_config_from_ui()
        threading.Thread(target=self._ensure_api_ready_worker, daemon=True).start()

    def _ensure_api_ready_worker(self):
        ok, msg = self.check_api_reachable()
        self.ui_api_status(ok, msg)
        if ok:
            return

        host, port = parse_host_port(self.base_url)
        if not (self.auto_start_api and is_localhost(host)):
            self.ui_log("API 不可达：未启用自动启动或非本机地址，跳过自启。\n")
            return

        if shutil.which("node") is None:
            self.ui_log("API 不可达：检测到系统没有 node，无法自动启动 API。\n")
            return

        proj = find_api_project_dir(self.api_dir_hint or None)
        if not proj:
            self.ui_log("API 不可达：未找到可启动的 API 项目目录（需包含 app.js 与 package.json）。\n")
            self.ui_log("你可以点“选择 API 目录（可选）”指定一次，之后会记住。\n")
            return

        self.ui_log(f"尝试自动启动 API：{proj}\n")
        p = start_node_api(proj, port)
        if not p:
            self.ui_log("自动启动失败：无法创建进程。\n")
            return

        self.api_process = p
        for _ in range(24):
            time.sleep(0.5)
            ok2, msg2 = self.check_api_reachable()
            self.ui_api_status(ok2, msg2)
            if ok2:
                self.ui_log("API 已自动启动并可达。\n")
                return

        self.ui_log("API 启动后仍不可达：请查看 API 日志。\n")
        self.ui_log(f"API 日志：{API_LOG_FILE}\n")

    # ---------- API 请求 ----------

    def api_get_json(self, path: str, params: dict | None = None):
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        r = self.session.get(url, params=params, timeout=(3, 20))
        r.raise_for_status()
        return r.json()

    # ---------- 勾选/持久化 ----------

    def _persist_current_page_selection(self):
        for sid, row in self.ui_rows.items():
            self.selected_by_id[sid] = bool(row["var"].get())
        self._save_state()

    def select_all_current_page(self):
        for row in self.ui_rows.values():
            row["var"].set(True)
        self._persist_current_page_selection()

    def unselect_all_current_page(self):
        for row in self.ui_rows.values():
            row["var"].set(False)
        self._persist_current_page_selection()

    # ---------- 结果内搜索（过滤） ----------

    def _item_to_search_blob(self, obj: dict) -> str:
        sid, name, artists, album, fee = normalize_song_fields(obj)
        return f"{name} {artists} {album}".lower()

    def apply_filter(self):
        q = (self.filter_var.get() or "").strip().lower()
        self.filter_query = q

        if not self.last_render_source_items:
            self.ui_message("提示", "当前没有可过滤的结果，请先搜索/聚合一次。", "warning")
            return

        if not q:
            self.clear_filter()
            return

        base = self.last_render_source_items
        matched = [it for it in base if q in self._item_to_search_blob(it)]

        self.ui_log(f"结果内过滤：'{q}' | {len(matched)}/{len(base)}\n")
        self.ui_q.put(("render_list", matched))

    def clear_filter(self):
        self.filter_var.set("")
        self.filter_query = ""
        if self.last_render_source_items:
            self.ui_log("已清除过滤，恢复显示当前结果集合\n")
            self.ui_q.put(("render_list", self.last_render_source_items))

    def _set_and_render_result_set(self, items: list[dict], log_prefix: str = ""):
        self.last_render_source_items = list(items)

        q = (self.filter_query or "").strip().lower()
        if q:
            matched = [it for it in self.last_render_source_items if q in self._item_to_search_blob(it)]
            if log_prefix:
                self.ui_log(f"{log_prefix}套用过滤 '{q}'：{len(matched)}/{len(items)}\n")
            self.ui_q.put(("render_list", matched))
        else:
            self.ui_q.put(("render_list", self.last_render_source_items))

    # ---------- 搜索/分页（B路线：limit可调） ----------

    def search(self, page: int):
        self._refresh_config_from_ui()

        kw = self.entry.get().strip()
        if not kw:
            self.ui_message("提示", "请输入关键词", "warning")
            return

        # 聚合状态切回“非聚合”
        self.is_aggregated_view = False
        self.unaggregated_snapshot_items = None
        self.aggregate_cancel_event.clear()

        ok, _ = self.check_api_reachable()
        if not ok:
            self.ensure_api_ready_async()
            self.ui_message("提示", "正在确保 API 可用（可能会自动启动）。稍后再点一次搜索即可。", "info")
            return

        self._persist_current_page_selection()
        self.keyword = kw
        self.current_page = page
        self.ui_set_page_label(page)
        self._save_state()

        threading.Thread(target=self._search_worker, args=(kw, page), daemon=True).start()

    def _search_worker(self, kw: str, page: int):
        with self.search_lock:
            self.ui_set_busy(True)
            try:
                limit = self.search_limit
                offset = (page - 1) * limit
                data = with_retry(lambda: self.api_get_json("/search", {"keywords": kw, "limit": limit, "offset": offset}), tries=3)
                songs = data.get("result", {}).get("songs", []) or []

                for song in songs:
                    c = compact_song_for_state(song)
                    sid = c["id"]
                    if sid:
                        self.song_cache[sid] = c

                self._save_state()
                self.ui_log(f"搜索：{kw} | 第 {page} 页 | limit={limit} | 返回 {len(songs)} 条\n")

                # 保存“未聚合快照”
                self.unaggregated_snapshot_items = list(songs)
                self._set_and_render_result_set(songs)

            except Exception as e:
                self.ui_message("错误", f"搜索失败：{e}", "error")
            finally:
                self.ui_set_busy(False)

    def next_page(self):
        if not self.keyword:
            self.ui_message("提示", "请先搜索", "warning")
            return
        self.search(self.current_page + 1)

    def prev_page(self):
        if not self.keyword:
            self.ui_message("提示", "请先搜索", "warning")
            return
        if self.current_page > 1:
            self.search(self.current_page - 1)

    def jump_page(self):
        if not self.keyword:
            self.ui_message("提示", "请先搜索", "warning")
            return
        s = self.jump_entry.get().strip()
        if not s.isdigit() or int(s) <= 0:
            self.ui_message("提示", "请输入有效页码（>=1）", "warning")
            return
        self.search(int(s))

    def restore_current_page_result(self):
        if not self.keyword:
            kw = self.entry.get().strip()
            if kw:
                self.keyword = kw
        if not self.keyword:
            self.ui_message("提示", "请先搜索一次", "warning")
            return
        self.search(self.current_page)

    # ---------- A路线：聚合 N 页 + 中止聚合 ----------

    def _dedup_key(self, item: dict) -> str:
        sid = str(item.get("id") or "").strip()
        if sid:
            return "id:" + sid
        sid2, name, artists, album, fee = normalize_song_fields(item)
        return "k:" + f"{name}|{artists}|{album}".lower()

    def aggregate_current_query_async(self):
        self._refresh_config_from_ui()

        kw = self.entry.get().strip()
        if not kw:
            self.ui_message("提示", "请先输入关键词（可先搜索再聚合，也可以直接聚合）", "warning")
            return

        ok, _ = self.check_api_reachable()
        if not ok:
            self.ensure_api_ready_async()
            self.ui_message("提示", "API 不可达，正在尝试自动启动。等 API 变为可达后再点聚合。", "warning")
            return

        # 记录聚合前的“未聚合快照”（用于中止/还原）
        if not self.unaggregated_snapshot_items:
            # 如果用户直接点聚合且没搜过，就先把当前页搜一次作为快照
            # 这里不阻塞：直接拉 page=1
            pass

        self.aggregate_cancel_event.clear()
        threading.Thread(target=self._aggregate_worker, args=(kw, self.agg_pages), daemon=True).start()

    def cancel_aggregate_and_restore(self):
        # 触发中止
        self.aggregate_cancel_event.set()
        self.ui_log("已请求中止聚合：正在还原未聚合视图…\n")

        # 还原视图：优先恢复聚合前快照；没有快照就回到当前页重新搜索
        if self.unaggregated_snapshot_items is not None:
            self.is_aggregated_view = False
            self._set_and_render_result_set(self.unaggregated_snapshot_items, log_prefix="还原")
            self.ui_log("已还原为未聚合结果集合。\n")
        else:
            self.restore_current_page_result()

    def _aggregate_worker(self, kw: str, pages: int):
        """
        A路线：聚合 page1..pageN 合并去重，然后展示为一个“结果集合”。
        支持中止：aggregate_cancel_event 置位后会尽快停止，并还原未聚合状态。
        """
        self.ui_set_busy(True)
        try:
            limit = self.search_limit
            if pages <= 0:
                pages = 1

            # 如果没有未聚合快照，先拉当前页作为快照（用于中止还原）
            if self.unaggregated_snapshot_items is None:
                try:
                    offset = (self.current_page - 1) * limit
                    data0 = with_retry(lambda: self.api_get_json("/search", {"keywords": kw, "limit": limit, "offset": offset}), tries=2)
                    snap = data0.get("result", {}).get("songs", []) or []
                    self.unaggregated_snapshot_items = list(snap)
                except Exception:
                    self.unaggregated_snapshot_items = []

            merged: list[dict] = []
            seen = set()

            self.ui_log(f"开始聚合：关键词='{kw}' | N={pages} 页 | limit={limit}\n")

            for p in range(1, pages + 1):
                if self.aggregate_cancel_event.is_set():
                    self.ui_log("聚合已中止（用户请求）。\n")
                    # 中止后还原
                    if self.unaggregated_snapshot_items is not None:
                        self.is_aggregated_view = False
                        self._set_and_render_result_set(self.unaggregated_snapshot_items, log_prefix="中止后还原")
                    return

                offset = (p - 1) * limit
                data = with_retry(lambda: self.api_get_json("/search", {"keywords": kw, "limit": limit, "offset": offset}), tries=3)
                songs = data.get("result", {}).get("songs", []) or []
                self.ui_log(f"聚合：API 第 {p}/{pages} 页，返回 {len(songs)} 条\n")

                for s in songs:
                    if self.aggregate_cancel_event.is_set():
                        self.ui_log("聚合已中止（用户请求）。\n")
                        if self.unaggregated_snapshot_items is not None:
                            self.is_aggregated_view = False
                            self._set_and_render_result_set(self.unaggregated_snapshot_items, log_prefix="中止后还原")
                        return

                    k = self._dedup_key(s)
                    if k in seen:
                        continue
                    seen.add(k)
                    merged.append(s)

                    c = compact_song_for_state(s)
                    sid = c.get("id")
                    if sid:
                        self.song_cache[sid] = c

                if not songs:
                    break

            self._save_state()
            self.is_aggregated_view = True
            self.ui_log(f"聚合完成：共 {len(merged)} 条（N={pages}, limit={limit}）\n")
            self._set_and_render_result_set(merged, log_prefix="聚合")

        except Exception as e:
            self.ui_message("错误", f"聚合失败：{e}", "error")
        finally:
            self.ui_set_busy(False)

    # ---------- 渲染列表 ----------

    def _render_list(self, songs: list[dict]):
        for w in self.list_frame.winfo_children():
            w.destroy()
        self.ui_rows.clear()

        if not songs:
            ttk.Label(self.list_frame, text="无结果或该集合为空").pack(anchor="w", pady=6)
            return

        for song in songs:
            sid, name, artists, album, fee = normalize_song_fields(song)
            vip = " [VIP]" if fee == 1 else ""
            text = f"{name} - {artists} ({album}){vip}"

            row = ttk.Frame(self.list_frame, padding=(6, 4))
            row.pack(fill="x", expand=True)

            var = tk.BooleanVar(value=self.selected_by_id.get(sid, False))

            def on_toggle(_sid=sid, _var=var):
                self.selected_by_id[_sid] = bool(_var.get())
                self._save_state()

            ttk.Checkbutton(row, variable=var, command=on_toggle).pack(side="left")
            ttk.Label(row, text=text).pack(side="left", padx=(6, 10), fill="x", expand=True)

            pb = ttk.Progressbar(row, length=320, mode="determinate")
            pb.pack(side="left", padx=(0, 10))

            st = ttk.Label(row, text="")
            st.pack(side="left")

            self.ui_rows[sid] = {"var": var, "progress": pb, "status": st}

    # ---------- 下载（跨页） ----------

    def download_selected_all_pages(self):
        self._refresh_config_from_ui()

        ok, _ = self.check_api_reachable()
        if not ok:
            self.ensure_api_ready_async()
            self.ui_message("提示", "正在确保 API 可用（可能会自动启动）。稍后再点一次下载即可。", "info")
            return

        self._persist_current_page_selection()

        selected_ids = [sid for sid, ok_ in self.selected_by_id.items() if ok_]
        if not selected_ids:
            self.ui_message("提示", "请先勾选歌曲（可跨页，重启不丢）", "warning")
            return

        jobs = []
        missing = 0
        for sid in selected_ids:
            c = self.song_cache.get(sid)
            if c:
                jobs.append(c)
            else:
                missing += 1

        if missing:
            self.ui_log(f"注意：有 {missing} 首歌缺少元数据缓存（请至少搜索到它所在页一次）\n")
        if not jobs:
            self.ui_message("提示", "没有可下载的歌曲（可能都缺少元数据）", "warning")
            return

        self.ui_log(f"开始下载：{len(jobs)} 首（并发 {MAX_WORKERS}）\n")
        for c in jobs:
            self.down_executor.submit(self._download_one_by_compact, c)

    # ---------- 下载辅助 ----------

    def find_audio_file(self, folder: str, base_name: str) -> str | None:
        cand = os.path.join(folder, f"{base_name}.mp3")
        if os.path.exists(cand) and os.path.getsize(cand) > 0:
            return cand
        if os.path.isdir(folder):
            prefix = base_name + "."
            for fn in os.listdir(folder):
                if fn.startswith(prefix):
                    p = os.path.join(folder, fn)
                    if os.path.isfile(p) and os.path.getsize(p) > 0:
                        return p
        return None

    def _fetch_song_detail(self, song_id: str) -> dict:
        data = with_retry(lambda: self.api_get_json("/song/detail", {"ids": song_id}), tries=3)
        songs = data.get("songs") or []
        if not songs:
            return {}
        s = songs[0]
        al = s.get("al") or {}
        ar = s.get("ar") or []
        return {
            "name": s.get("name") or "",
            "album": (al.get("name") or ""),
            "artists": " / ".join([a.get("name", "") for a in ar]).strip(),
            "picUrl": al.get("picUrl") or "",
        }

    def _download_cover_bytes(self, pic_url: str) -> tuple[bytes | None, str | None]:
        if not pic_url:
            return None, None
        try:
            r = with_retry(lambda: self.session.get(pic_url, timeout=(5, 20)), tries=2)
            r.raise_for_status()
            ct = (r.headers.get("content-type") or "").lower()
            if "png" in ct:
                return r.content, "image/png"
            return r.content, "image/jpeg"
        except Exception:
            return None, None

    def _download_lyric_bilingual(self, song_id: str) -> tuple[str, str]:
        try:
            data = with_retry(lambda: self.api_get_json("/lyric", {"id": song_id}), tries=2)
            orig = (data.get("lrc") or {}).get("lyric") or ""
            trans = (data.get("tlyric") or {}).get("lyric") or ""
            merged = merge_bilingual_lrc(orig, trans)
            plain = strip_lrc_timestamps(merged)
            return merged, plain
        except Exception:
            return "", ""

    # ---------- 单曲下载（.part + Range 续传 + 校验 + ID3） ----------

    def _download_one_by_compact(self, c: dict):
        song_id = str(c.get("id") or "")
        if not song_id:
            return

        title = c.get("name") or "未知歌曲"
        artist = c.get("artists") or "未知歌手"
        album = c.get("album") or ""
        pic_url = c.get("picUrl") or ""

        # detail 补全
        try:
            detail = self._fetch_song_detail(song_id)
            if detail:
                title = detail.get("name") or title
                album = detail.get("album") or album
                artist = detail.get("artists") or artist
                pic_url = detail.get("picUrl") or pic_url
        except Exception:
            pass

        safe_title = safe_filename(title)
        artist_folder = safe_filename(artist)
        folder = os.path.join(self.download_dir, artist_folder)
        os.makedirs(folder, exist_ok=True)

        # 1) 歌词
        self.ui_row_status(song_id, "获取歌词…")
        bilingual_lrc, uslt_plain = self._download_lyric_bilingual(song_id)
        if bilingual_lrc:
            lrc_path = os.path.join(folder, f"{safe_title}.lrc")
            try:
                with open(lrc_path, "w", encoding="utf-8") as f:
                    f.write(bilingual_lrc)
                self.ui_log(f"{safe_title} 歌词保存：{lrc_path}\n")
            except Exception as e:
                self.ui_log(f"{safe_title} 歌词写入失败：{e}\n")
        else:
            self.ui_log(f"{safe_title} 无歌词或获取失败\n")

        # 2) 缓存命中先检查文件存在
        audio_path_existing = self.find_audio_file(folder, safe_title)
        if (not self.force_redownload.get()) and (song_id in self.downloaded_ids):
            if audio_path_existing:
                self.ui_row_status(song_id, "已下载，补标签…")
                cover_bytes, cover_mime = self._download_cover_bytes(pic_url)
                _, info = write_id3_mp3(audio_path_existing, title, artist, album, cover_bytes, cover_mime, uslt_plain)
                self.ui_log(f"{safe_title} 标签更新：{info}\n")
                self.ui_row_status(song_id, "完成")
                return
            else:
                self.ui_log(f"{safe_title} 缓存命中但音频不存在，已自动修复缓存并重新下载\n")
                self.downloaded_ids.discard(song_id)
                self.rewrite_download_cache_file()

        # 强制重下：删旧文件
        if self.force_redownload.get() and audio_path_existing:
            try:
                os.remove(audio_path_existing)
            except Exception:
                pass

        # 3) 获取音频 URL
        self.ui_row_status(song_id, "获取链接…")
        try:
            url_json = with_retry(lambda: self.api_get_json("/song/url", {"id": song_id}), tries=3)
        except Exception as e:
            self.ui_row_status(song_id, "失败")
            self.ui_log(f"{safe_title} 获取链接失败：{e}\n")
            return

        d = url_json.get("data")
        item = d[0] if isinstance(d, list) and d else None
        music_url = item.get("url") if item else None
        if not music_url:
            self.ui_row_status(song_id, "无链接（VIP/无版权）")
            self.ui_log(f"{safe_title} 音频失败：VIP/无版权/无链接\n")
            return

        ext = guess_ext_from_url(music_url)
        audio_path = os.path.join(folder, f"{safe_title}.{ext}")
        part_path = audio_path + ".part"

        # 4) 断点续传 Range
        self.ui_row_status(song_id, "下载中…")
        resume_from = 0
        headers = {}
        if os.path.exists(part_path):
            try:
                resume_from = os.path.getsize(part_path)
                if resume_from > 0:
                    headers["Range"] = f"bytes={resume_from}-"
            except Exception:
                resume_from = 0
                headers = {}

        try:
            r = with_retry(lambda: self.session.get(music_url, stream=True, timeout=(5, 60), headers=headers), tries=3)
            r.raise_for_status()
        except Exception as e:
            self.ui_row_status(song_id, "失败")
            self.ui_log(f"{safe_title} 音频请求失败：{e}\n")
            return

        if headers.get("Range") and r.status_code != 206:
            try:
                if os.path.exists(part_path):
                    os.remove(part_path)
            except Exception:
                pass
            resume_from = 0
            try:
                r = with_retry(lambda: self.session.get(music_url, stream=True, timeout=(5, 60)), tries=2)
                r.raise_for_status()
            except Exception as e:
                self.ui_row_status(song_id, "失败")
                self.ui_log(f"{safe_title} 音频重试失败：{e}\n")
                return

        total_size = 0
        cr = r.headers.get("content-range")
        if cr:
            m = re.search(r"/(\d+)$", cr)
            if m:
                total_size = int(m.group(1))
        else:
            total_size = int(r.headers.get("content-length") or 0)
            if resume_from > 0 and total_size > 0 and r.status_code == 206:
                total_size = resume_from + total_size

        if total_size > 0:
            self.ui_row_progress(song_id, resume_from, total_size, mode="determinate")
        else:
            self.ui_row_progress(song_id, None, None, mode="indeterminate")

        mode = "ab" if resume_from > 0 else "wb"
        downloaded = resume_from

        try:
            with open(part_path, mode) as f:
                for chunk in r.iter_content(chunk_size=1024 * 32):
                    if not chunk:
                        continue
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        self.ui_row_progress(song_id, downloaded, None)
        except Exception as e:
            self.ui_row_status(song_id, "失败")
            self.ui_log(f"{safe_title} 写文件失败：{e}\n")
            return

        if total_size > 0 and downloaded != total_size:
            try:
                os.remove(part_path)
            except Exception:
                pass
            self.ui_row_status(song_id, "失败（不完整）")
            self.ui_log(f"{safe_title} 音频失败：下载不完整 {downloaded}/{total_size}\n")
            return

        try:
            os.replace(part_path, audio_path)
        except Exception as e:
            self.ui_row_status(song_id, "失败")
            self.ui_log(f"{safe_title} 文件替换失败：{e}\n")
            return

        self._save_cache(song_id)

        # 5) 写 ID3
        self.ui_row_status(song_id, "写入标签…")
        cover_bytes, cover_mime = self._download_cover_bytes(pic_url)
        _, info = write_id3_mp3(audio_path, title, artist, album, cover_bytes, cover_mime, uslt_plain)

        if total_size > 0:
            self.ui_row_progress(song_id, total_size, None, mode="determinate")
        else:
            self.ui_row_progress(song_id, 0, None, mode="determinate")

        self.ui_log(f"{safe_title} 完成：{audio_path} | {info}\n")
        self.ui_row_status(song_id, "完成")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()