import os
import re
import json
import time
import threading
import queue
import requests
import tkinter as tk
from tkinter import ttk, messagebox
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ====== 可配置 ======
BASE_URL = "http://localhost:3000"
LIMIT = 20
DOWNLOAD_DIR = "downloads"
CACHE_FILE = "download_cache.txt"
STATE_FILE = "state.json"
MAX_WORKERS = 3
# ===================

# ========= mutagen（ID3） =========
MUTAGEN_OK = True
try:
    from mutagen.mp3 import MP3
    from mutagen.id3 import ID3, APIC, USLT, ID3NoHeaderError
    from mutagen.easyid3 import EasyID3
except Exception:
    MUTAGEN_OK = False

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

def api_get_json(session: requests.Session, path: str, params: dict | None = None):
    url = f"{BASE_URL}{path}"
    r = session.get(url, params=params, timeout=(3, 20))
    r.raise_for_status()
    return r.json()

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

        # 基础字段
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

        # 封面
        if cover_bytes and cover_mime:
            audio.tags.delall("APIC")
            audio.tags.add(APIC(
                encoding=3, mime=cover_mime, type=3,
                desc="Cover", data=cover_bytes
            ))

        # 歌词（纯文本）
        if lyric_plain:
            audio.tags.delall("USLT")
            audio.tags.add(USLT(
                encoding=3, lang="chi", desc="Lyrics",
                text=lyric_plain
            ))

        audio.save(v2_version=3)
        return True, "ID3 写入完成"
    except Exception as e:
        return False, str(e)

# ========= App =========

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("网易云音乐增强版专业下载器（最终整合版）")
        self.root.geometry("1050x820")

        # 状态
        self.keyword = ""
        self.current_page = 1
        self.downloaded_ids = set()
        self.selected_by_id: dict[str, bool] = {}
        self.song_cache: dict[str, dict] = {}   # compact cache
        self.ui_rows: dict[str, dict] = {}

        # 并发
        self.ui_q = queue.Queue()
        self.search_lock = threading.Lock()
        self.down_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self.session = requests.Session()

        self._build_ui()
        self._load_cache()
        self._load_state()
        self._drain_ui_queue()

    # ---------- UI ----------

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="关键词：").pack(side="left")
        self.entry = ttk.Entry(top, width=45)
        self.entry.pack(side="left", padx=(0, 8))
        self.entry.bind("<Return>", lambda e: self.search(1))

        self.btn_search = ttk.Button(top, text="搜索", command=lambda: self.search(1))
        self.btn_search.pack(side="left")

        if not MUTAGEN_OK:
            ttk.Label(top, text="（未安装 mutagen：将跳过 ID3）", foreground="gray").pack(side="left", padx=10)

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

        action = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        action.pack(fill="x")

        ttk.Button(action, text="全选（当前页）", command=self.select_all_current_page).pack(side="left")
        ttk.Button(action, text="取消全选（当前页）", command=self.unselect_all_current_page).pack(side="left", padx=6)

        self.force_redownload = tk.BooleanVar(value=False)
        ttk.Checkbutton(action, text="强制重新下载音频（忽略缓存）", variable=self.force_redownload).pack(side="left", padx=10)

        self.btn_download = ttk.Button(action, text="下载选中（所有页）", command=self.download_selected_all_pages)
        self.btn_download.pack(side="left", padx=12)

        self.info_label = ttk.Label(action, text=f"并发:{MAX_WORKERS} | 状态:{STATE_FILE} | 缓存:{CACHE_FILE}")
        self.info_label.pack(side="right")

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
        ttk.Label(log_wrap, text="日志：").pack(anchor="w")
        self.log = tk.Text(log_wrap, height=10)
        self.log.pack(fill="both", expand=False)

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
                    for b in (self.btn_search, self.btn_prev, self.btn_next, self.btn_jump):
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
            return
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.selected_by_id = {str(k): bool(v) for k, v in (data.get("selected_by_id") or {}).items()}
            self.song_cache = {str(k): v for k, v in (data.get("song_cache") or {}).items()}
            self.keyword = data.get("keyword") or ""
            self.current_page = int(data.get("current_page") or 1)

            if self.keyword:
                self.entry.insert(0, self.keyword)
                self.page_label.config(text=f"第 {self.current_page} 页")

            self.ui_log(f"已载入状态：选中 {sum(1 for v in self.selected_by_id.values() if v)} 首，缓存 {len(self.song_cache)} 首\n")
        except Exception as e:
            self.ui_log(f"载入 {STATE_FILE} 失败：{e}\n")

    def _save_state(self):
        try:
            data = {
                "version": 1,
                "saved_at": datetime.now().isoformat(timespec="seconds"),
                "keyword": self.keyword,
                "current_page": self.current_page,
                "selected_by_id": self.selected_by_id,
                "song_cache": self.song_cache,
            }
            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, STATE_FILE)
        except Exception as e:
            self.ui_log(f"保存状态失败：{e}\n")

    # ---------- 缓存命中检查文件是否存在 ----------

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

    # ---------- 勾选 ----------

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

    # ---------- 搜索/分页 ----------

    def search(self, page: int):
        kw = self.entry.get().strip()
        if not kw:
            self.ui_message("提示", "请输入关键词", "warning")
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
                offset = (page - 1) * LIMIT
                data = with_retry(lambda: api_get_json(self.session, "/search", {"keywords": kw, "limit": LIMIT, "offset": offset}), tries=3)
                songs = data.get("result", {}).get("songs", []) or []

                for song in songs:
                    c = compact_song_for_state(song)
                    sid = c["id"]
                    if sid:
                        self.song_cache[sid] = c
                self._save_state()

                self.ui_log(f"搜索：{kw} | 第 {page} 页 | 返回 {len(songs)} 条 | 缓存 {len(self.song_cache)}\n")
                self.ui_q.put(("render_list", songs))

            except requests.exceptions.ConnectionError:
                self.ui_message("错误", "连接失败：请确认 API 已启动（http://localhost:3000）", "error")
            except Exception as e:
                self.ui_message("错误", f"搜索失败：{e}", "error")
            finally:
                self.ui_set_busy(False)

    def _render_list(self, songs: list[dict]):
        for w in self.list_frame.winfo_children():
            w.destroy()
        self.ui_rows.clear()

        if not songs:
            ttk.Label(self.list_frame, text="无结果或该页为空").pack(anchor="w", pady=6)
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

            pb = ttk.Progressbar(row, length=260, mode="determinate")
            pb.pack(side="left", padx=(0, 10))

            st = ttk.Label(row, text="")
            st.pack(side="left")

            self.ui_rows[sid] = {"var": var, "progress": pb, "status": st}

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

    # ---------- 下载（跨页） ----------

    def download_selected_all_pages(self):
        self._persist_current_page_selection()

        selected_ids = [sid for sid, ok in self.selected_by_id.items() if ok]
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

        self.ui_log(f"开始下载：{len(jobs)} 首（并发 {MAX_WORKERS}，断点续传 + .part + 双语歌词 + ID3）\n")
        for c in jobs:
            self.down_executor.submit(self._download_one_by_compact, c)

    # ---------- 下载辅助：detail/cover/lyric ----------

    def _fetch_song_detail(self, song_id: str) -> dict:
        data = with_retry(lambda: api_get_json(self.session, "/song/detail", {"ids": song_id}), tries=3)
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
            data = with_retry(lambda: api_get_json(self.session, "/lyric", {"id": song_id}), tries=2)
            orig = (data.get("lrc") or {}).get("lyric") or ""
            trans = (data.get("tlyric") or {}).get("lyric") or ""
            merged = merge_bilingual_lrc(orig, trans)
            plain = strip_lrc_timestamps(merged)
            return merged, plain
        except Exception:
            return "", ""

    # ---------- 核心：单曲下载（.part + Range 续传 + 校验 + ID3） ----------

    def _download_one_by_compact(self, c: dict):
        song_id = str(c.get("id") or "")
        if not song_id:
            return

        title = c.get("name") or "未知歌曲"
        artist = c.get("artists") or "未知歌手"
        album = c.get("album") or ""
        pic_url = c.get("picUrl") or ""

        # 用 detail 补充更可靠的元数据
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
        folder = os.path.join(DOWNLOAD_DIR, artist_folder)
        os.makedirs(folder, exist_ok=True)

        # 1) 歌词：双语合并写 .lrc（即便音频失败也尽量保存）
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

        # 2) 缓存命中：先确认文件存在，否则修缓存继续下
        audio_path_existing = self.find_audio_file(folder, safe_title)

        if (not self.force_redownload.get()) and (song_id in self.downloaded_ids):
            if audio_path_existing:
                self.ui_row_status(song_id, "已下载，补标签…")
                cover_bytes, cover_mime = self._download_cover_bytes(pic_url)
                ok, info = write_id3_mp3(audio_path_existing, title, artist, album, cover_bytes, cover_mime, uslt_plain)
                self.ui_log(f"{safe_title} 标签更新：{info}\n")
                self.ui_row_status(song_id, "完成")
                return
            else:
                # 缓存脏：修复并继续走下载
                self.ui_log(f"{safe_title} 缓存命中但音频不存在，已自动修复缓存并重新下载\n")
                self.downloaded_ids.discard(song_id)
                self.rewrite_download_cache_file()

        # 若强制重下且存在旧文件：可选择覆盖（这里直接覆盖）
        # 为避免覆盖错误：若存在旧文件，先删掉
        if self.force_redownload.get() and audio_path_existing:
            try:
                os.remove(audio_path_existing)
            except Exception:
                pass

        # 3) 获取音频 URL
        self.ui_row_status(song_id, "获取链接…")
        try:
            url_json = with_retry(lambda: api_get_json(self.session, "/song/url", {"id": song_id}), tries=3)
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

        # 4) 断点续传：Range
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

        # 发请求（可能 200 或 206）
        try:
            r = with_retry(lambda: self.session.get(music_url, stream=True, timeout=(5, 60), headers=headers), tries=3)
            r.raise_for_status()
        except Exception as e:
            self.ui_row_status(song_id, "失败")
            self.ui_log(f"{safe_title} 音频请求失败：{e}\n")
            return

        # 如果请求了 Range 但返回不是 206：说明不支持续传，删 part 从头下
        if headers.get("Range") and r.status_code != 206:
            try:
                if os.path.exists(part_path):
                    os.remove(part_path)
            except Exception:
                pass
            resume_from = 0

            # 重新从头请求一次
            try:
                r = with_retry(lambda: self.session.get(music_url, stream=True, timeout=(5, 60)), tries=2)
                r.raise_for_status()
            except Exception as e:
                self.ui_row_status(song_id, "失败")
                self.ui_log(f"{safe_title} 音频重试失败：{e}\n")
                return

        # total_size：优先 Content-Range 的总长度
        total_size = 0
        cr = r.headers.get("content-range")
        if cr:
            m = re.search(r"/(\d+)$", cr)
            if m:
                total_size = int(m.group(1))
        else:
            # 若非续传：content-length 是总长度；续传时可能只是剩余长度
            total_size = int(r.headers.get("content-length") or 0)
            if resume_from > 0 and total_size > 0 and r.status_code == 206:
                # 理论上 206 应该有 content-range；这里兜底
                total_size = resume_from + total_size

        # 进度条设置
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

        # 完整性校验（仅在 total_size 已知时）
        if total_size > 0 and downloaded != total_size:
            try:
                os.remove(part_path)
            except Exception:
                pass
            self.ui_row_status(song_id, "失败（不完整）")
            self.ui_log(f"{safe_title} 音频失败：下载不完整 {downloaded}/{total_size}\n")
            return

        # 原子替换
        try:
            os.replace(part_path, audio_path)
        except Exception as e:
            self.ui_row_status(song_id, "失败")
            self.ui_log(f"{safe_title} 文件替换失败：{e}\n")
            return

        # 下载成功：写缓存（关键：只有成功才写）
        self._save_cache(song_id)

        # 5) 写 ID3（封面/歌词/标签）
        self.ui_row_status(song_id, "写入标签…")
        cover_bytes, cover_mime = self._download_cover_bytes(pic_url)
        ok, info = write_id3_mp3(audio_path, title, artist, album, cover_bytes, cover_mime, uslt_plain)

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