import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import yt_dlp
import os
import re
import json
import shutil
import subprocess
import platform
import glob
import time
from typing import Optional, List, Dict, Tuple

CONFIG_FILE = "downloader_config.json"


class UserStop(Exception):
    pass


def create_no_window_flags() -> int:
    return subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


class AdvancedDownloader:
    def __init__(self, root):
        self.root = root
        self.root.title("Gemini 视频下载专家 - 稳定重构版")
        self.root.geometry("930x760")

        self.is_running = False
        self.stop_requested = False
        self.typing_timer = None

        self.lock = threading.Lock()
        self.current_urls: List[str] = []
        self.url_to_title: Dict[str, str] = {}
        self.fetch_thread_token = 0

        self.env_info = {"ffmpeg": None, "ffprobe": None, "js_runtime": None}
        self.current_ffmpeg_process = None
        self.current_ffmpeg_target: Optional[str] = None
        self.last_success_media: Optional[str] = None

        self._build_ui()
        self.root.after(150, self.bootstrap)

    # =========================
    # UI
    # =========================
    def _build_ui(self):
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=15, pady=10)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill="both", expand=True)

        tk.Label(left_frame, text="1. 粘贴链接 (自动过滤播放列表):", font=("Arial", 10, "bold")).pack(anchor="w")

        self.url_input = tk.Text(left_frame, height=12, width=40, font=("Consolas", 10))
        self.url_input.pack(pady=5, padx=5, fill="both", expand=True)
        self.url_input.bind("<KeyRelease>", self.on_url_input_change)

        input_btn_frame = tk.Frame(left_frame)
        input_btn_frame.pack(fill="x", padx=5, pady=(0, 5))

        self.clear_all_btn = tk.Button(input_btn_frame, text="🧹 一键清除", command=self.clear_all_urls)
        self.clear_all_btn.pack(side=tk.LEFT)

        self.clear_selected_btn = tk.Button(input_btn_frame, text="✂️ 清除选定", command=self.clear_selected_urls)
        self.clear_selected_btn.pack(side=tk.LEFT, padx=8)

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill="both", padx=10)

        tk.Label(right_frame, text="2. 待下载清单:", font=("Arial", 10, "bold")).pack(anchor="w")
        self.title_list = tk.Listbox(right_frame, height=12, width=58, bg="#f8f8f8", selectmode=tk.EXTENDED)
        self.title_list.pack(pady=5, fill="both", expand=True)

        self.title_list.bind("<Delete>", self.delete_selected_from_title_list)
        self.title_list.bind("<BackSpace>", self.delete_selected_from_title_list)
        self.title_list.bind("<Double-Button-1>", self.delete_selected_from_title_list)

        config_frame = tk.LabelFrame(self.root, text="设置与控制", padx=10, pady=10)
        config_frame.pack(fill="x", padx=15, pady=5)

        saved_path = self.load_config().get("path", os.path.join(os.getcwd(), "downloads"))
        self.path_var = tk.StringVar(value=saved_path)
        tk.Entry(config_frame, textvariable=self.path_var, width=60).grid(row=0, column=1)

        tk.Button(config_frame, text="更改位置", command=self.select_path).grid(row=0, column=2, padx=5)
        tk.Button(config_frame, text="📂 打开下载文件夹", command=self.open_download_folder).grid(row=0, column=3, padx=5)

        self.quality_var = tk.StringVar(value="最高画质")
        ttk.Combobox(
            config_frame,
            textvariable=self.quality_var,
            values=("最高画质", "1080P", "720P", "兼容模式(MP4 H264+AAC)", "仅音频(MP3)"),
            state="readonly",
            width=22
        ).grid(row=1, column=1, sticky="w", pady=5)

        self.thumb_var = tk.BooleanVar(value=True)
        tk.Checkbutton(config_frame, text="下载并嵌入封面", variable=self.thumb_var).grid(
            row=1, column=1, padx=220, sticky="w"
        )

        ctrl_frame = tk.Frame(self.root)
        ctrl_frame.pack(fill="x", padx=15, pady=5)

        self.start_btn = tk.Button(
            ctrl_frame, text="🚀 开始/恢复下载", command=self.start_task,
            bg="#4CAF50", fg="white", font=("Arial", 11, "bold"), width=20, height=2
        )
        self.start_btn.pack(side=tk.LEFT, padx=5, expand=True, fill="x")

        self.stop_btn = tk.Button(
            ctrl_frame, text="🛑 停止下载", command=self.stop_task,
            bg="#f44336", fg="white", font=("Arial", 11, "bold"), width=20, height=2, state="disabled"
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5, expand=True, fill="x")

        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", padx=15, pady=5)

        self.status_label = tk.Label(self.root, text="就绪", fg="blue")
        self.status_label.pack()

        self.log_box = tk.Text(
            self.root, height=10, state="disabled", bg="#1e1e1e",
            fg="#00ff00", font=("Consolas", 9)
        )
        self.log_box.pack(fill="both", padx=15, pady=5)

    # =========================
    # Logger
    # =========================
    def _make_logger(self):
        app = self

        class _Logger:
            def debug(self, msg):
                pass

            def info(self, msg):
                pass

            def warning(self, msg):
                s = str(msg)
                if ("PO Token" in s) or ("po_token=" in s) or ("gvs PO Token" in s):
                    return
                app._safe_log(f"⚠️ {s}")

            def error(self, msg):
                app._safe_log(f"❌ {msg}")

        return _Logger()

    def _safe_log(self, text: str):
        self.root.after(0, lambda t=text: self.write_log(t))

    # =========================
    # 启动 / 环境
    # =========================
    def bootstrap(self):
        self.write_log("🔎 启动：环境自检中...")
        ok = self.check_environment()
        self.status_label.config(
            text=("就绪（环境正常）" if ok else "就绪（环境有缺失）"),
            fg=("blue" if ok else "orange")
        )
        self.schedule_preview_refresh(0)

    def _run_version(self, exe_path: str, args=("--version",), timeout=4) -> bool:
        try:
            cp = subprocess.run(
                [exe_path, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=create_no_window_flags()
            )
            return cp.returncode == 0
        except Exception:
            return False

    def _find_executable(self, names: List[str]) -> Optional[str]:
        for n in names:
            p = shutil.which(n)
            if p:
                return p
        return None

    def check_environment(self) -> bool:
        ffmpeg_path = self._find_executable(["ffmpeg"])
        ffprobe_path = self._find_executable(["ffprobe"])
        node_path = self._find_executable(["node"])
        deno_path = self._find_executable(["deno"])

        ffmpeg_ok = bool(ffmpeg_path) and self._run_version(ffmpeg_path, ("-version",))
        ffprobe_ok = bool(ffprobe_path) and self._run_version(ffprobe_path, ("-version",))

        js_runtime = None
        if node_path and self._run_version(node_path, ("-v",)):
            js_runtime = ("node", node_path)
        elif deno_path and self._run_version(deno_path, ("--version",)):
            js_runtime = ("deno", deno_path)

        with self.lock:
            self.env_info["ffmpeg"] = ffmpeg_path if ffmpeg_ok else None
            self.env_info["ffprobe"] = ffprobe_path if ffprobe_ok else None
            self.env_info["js_runtime"] = js_runtime

        self.write_log(f"  • ffmpeg : {'OK' if ffmpeg_ok else 'MISSING'}")
        self.write_log(f"  • ffprobe: {'OK' if ffprobe_ok else 'MISSING'}")
        self.write_log(f"  • JS runtime: {'OK' if js_runtime else 'MISSING'}")
        return ffmpeg_ok and ffprobe_ok and (js_runtime is not None)

    # =========================
    # URL / 清单同步
    # =========================
    def clean_url(self, url: str) -> str:
        url = url.strip()
        if not url:
            return ""
        if "youtube.com/watch?v=" in url or "youtu.be/" in url:
            url = re.sub(r'([&?])list=[^&]+', '', url)
            url = re.sub(r'([&?])index=[^&]+', '', url)
            url = re.sub(r'([&?])start_radio=[^&]+', '', url)
        return url.strip()

    def parse_urls_from_input(self) -> List[str]:
        raw_urls = self.url_input.get("1.0", tk.END).strip().split("\n")
        cleaned = [self.clean_url(u) for u in raw_urls if u.strip()]
        seen = set()
        result = []
        for u in cleaned:
            if u and u not in seen:
                seen.add(u)
                result.append(u)
        return result

    def on_url_input_change(self, event):
        self.schedule_preview_refresh(800)

    def schedule_preview_refresh(self, delay_ms: int):
        if self.typing_timer:
            self.root.after_cancel(self.typing_timer)
        self.typing_timer = self.root.after(delay_ms, self.refresh_preview_async)

    def refresh_preview_async(self):
        urls = self.parse_urls_from_input()
        with self.lock:
            self.current_urls = urls
            for u in list(self.url_to_title.keys()):
                if u not in urls:
                    self.url_to_title.pop(u, None)
            self.fetch_thread_token += 1
            token = self.fetch_thread_token

        self.root.after(0, self.render_title_list)

        with self.lock:
            need_fetch = [u for u in urls if u not in self.url_to_title]
        if need_fetch:
            threading.Thread(target=self.fetch_worker, args=(need_fetch, token), daemon=True).start()

    def render_title_list(self):
        with self.lock:
            urls = list(self.current_urls)
            cache = dict(self.url_to_title)

        self.title_list.delete(0, tk.END)
        for u in urls:
            t = cache.get(u)
            self.title_list.insert(tk.END, t if t else f"⏳ 获取标题中...  |  {u}")

    def clear_all_urls(self):
        self.url_input.delete("1.0", tk.END)
        with self.lock:
            self.current_urls = []
            self.url_to_title.clear()
            self.fetch_thread_token += 1
        self.render_title_list()
        self.write_log("🧹 已清空所有链接。")

    def clear_selected_urls(self):
        try:
            start = self.url_input.index("sel.first")
            end = self.url_input.index("sel.last")
            start_line = int(start.split(".")[0])
            end_line = int(end.split(".")[0])
            self.url_input.delete(f"{start_line}.0", f"{end_line}.0 lineend+1c")
            self.write_log(f"✂️ 已清除选定行：{start_line} - {end_line}")
        except tk.TclError:
            cur = self.url_input.index("insert")
            line = int(cur.split(".")[0])
            self.url_input.delete(f"{line}.0", f"{line}.0 lineend+1c")
            self.write_log(f"✂️ 已清除当前行：{line}")
        self.schedule_preview_refresh(0)

    def delete_selected_from_title_list(self, event=None):
        sel = list(self.title_list.curselection())
        if not sel:
            return
        with self.lock:
            urls = list(self.current_urls)
        to_remove = [urls[i] for i in sel if 0 <= i < len(urls)]
        if not to_remove:
            return

        lines = self.url_input.get("1.0", tk.END).splitlines()
        remove_set = set(self.clean_url(u) for u in to_remove)
        new_lines = []
        removed = 0
        for ln in lines:
            c = self.clean_url(ln)
            if c and c in remove_set:
                removed += 1
                continue
            new_lines.append(ln)

        self.url_input.delete("1.0", tk.END)
        kept = [ln for ln in new_lines if ln.strip()]
        self.url_input.insert("1.0", "\n".join(kept) + ("\n" if kept else ""))
        self.write_log(f"🗑️ 已从输入框删除 {removed} 条 URL（来自右侧清单选择）。")
        self.schedule_preview_refresh(0)

    # =========================
    # yt-dlp 参数
    # =========================
    def _inject_js_runtime_opts(self, ydl_opts: dict):
        with self.lock:
            js = self.env_info.get("js_runtime")
        if not js:
            return
        runtime_name, runtime_path = js
        ydl_opts["js_runtimes"] = {runtime_name: {"path": runtime_path}}

    def _inject_ejs_remote_components(self, ydl_opts: dict):
        ydl_opts["remote_components"] = {"ejs:github"}

    def _inject_youtube_extractor_args(self, ydl_opts: dict):
        ydl_opts.setdefault("extractor_args", {})
        ydl_opts["extractor_args"].setdefault("youtube", {})
        ydl_opts["extractor_args"]["youtube"]["player_client"] = ["default", "android", "ios", "web"]

    def _height_cap_from_ui(self) -> Optional[int]:
        q = self.quality_var.get().strip()
        if q == "1080P":
            return 1080
        if q == "720P":
            return 720
        return None

    def _mode(self) -> str:
        q = self.quality_var.get().strip()
        if q == "兼容模式(MP4 H264+AAC)":
            return "compat_accurate"
        if q == "仅音频(MP3)":
            return "audio"
        return "auto"

    def _fallback_format(self, cap: Optional[int]) -> str:
        if cap == 1080:
            return "bestvideo[height<=1080]+bestaudio/best[height<=1080]/best"
        if cap == 720:
            return "bestvideo[height<=720]+bestaudio/best[height<=720]/best"
        return "bestvideo+bestaudio/best"

    # =========================
    # 文件探测 / ffmpeg
    # =========================
    def _file_ready(self, path: Optional[str], stable_wait: float = 0.6) -> bool:
        if not path or not os.path.exists(path):
            return False
        try:
            s1 = os.path.getsize(path)
            if s1 <= 0:
                return False
            time.sleep(stable_wait)
            s2 = os.path.getsize(path)
            return s2 > 0 and s1 == s2
        except Exception:
            return False

    def _ffprobe_codec(self, file_path: str) -> Tuple[Optional[str], Optional[str]]:
        with self.lock:
            ffprobe = self.env_info.get("ffprobe") or "ffprobe"

        def run(stream_sel: str) -> Optional[str]:
            try:
                cp = subprocess.run(
                    [ffprobe, "-v", "error", "-select_streams", stream_sel,
                     "-show_entries", "stream=codec_name", "-of", "default=nk=1:nw=1", file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                    creationflags=create_no_window_flags()
                )
                out = (cp.stdout or "").strip().splitlines()
                return out[0].strip() if out else None
            except Exception:
                return None

        return run("v:0"), run("a:0")

    def _analyze_compatibility(self, vcodec: Optional[str], acodec: Optional[str]) -> Tuple[bool, bool]:
        v = (vcodec or "").lower()
        a = (acodec or "").lower()

        need_video_transcode = not (
            v in ("h264", "avc1") or v.startswith("h264") or v.startswith("avc1")
        )
        need_audio_transcode = not (
            a == "aac" or a.startswith("aac")
        )
        return need_video_transcode, need_audio_transcode

    def _run_ffmpeg(self, args: List[str], expected_output: Optional[str] = None, timeout: int = 3600) -> bool:
        with self.lock:
            ffmpeg = self.env_info.get("ffmpeg") or "ffmpeg"

        cmd = [ffmpeg, *args]
        self.current_ffmpeg_target = expected_output
        self._safe_log("🛠️ ffmpeg 开始执行...")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=create_no_window_flags()
            )
            self.current_ffmpeg_process = proc

            stdout, stderr = proc.communicate(timeout=timeout)
            self.current_ffmpeg_process = None

            if proc.returncode != 0:
                if self._file_ready(expected_output):
                    self.last_success_media = expected_output
                    self._safe_log("⚠️ ffmpeg 返回非零，但成品文件已存在，按成功处理")
                    return True

                err = (stderr or "").strip()
                self._safe_log("❌ ffmpeg 失败：" + (err[-800:] if err else "unknown error"))
                return False

            if self._file_ready(expected_output) or expected_output is None:
                if expected_output:
                    self.last_success_media = expected_output
                self._safe_log("✅ ffmpeg 执行完成")
                return True

            self._safe_log("⚠️ ffmpeg 已结束，但目标文件未稳定落盘")
            return False

        except subprocess.TimeoutExpired:
            try:
                if self.current_ffmpeg_process:
                    self.current_ffmpeg_process.kill()
            except Exception:
                pass
            self.current_ffmpeg_process = None

            if self._file_ready(expected_output):
                self.last_success_media = expected_output
                self._safe_log("⚠️ ffmpeg 等待超时，但成品文件已存在，按成功处理")
                return True

            self._safe_log("❌ ffmpeg 超时，已强制终止")
            return False

        except Exception as e:
            try:
                if self.current_ffmpeg_process:
                    self.current_ffmpeg_process.kill()
            except Exception:
                pass
            self.current_ffmpeg_process = None

            if self._file_ready(expected_output):
                self.last_success_media = expected_output
                self._safe_log(f"⚠️ ffmpeg 出现异常，但成品文件已存在，按成功处理：{e}")
                return True

            self._safe_log(f"❌ ffmpeg 异常：{e}")
            return False

        finally:
            self.current_ffmpeg_target = None

    def _safe_remove(self, path: str):
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def _find_thumbnail_jpg(self, base_no_ext: str) -> Optional[str]:
        jpgs = glob.glob(base_no_ext + "*.jpg")
        if jpgs:
            jpgs.sort(key=lambda p: len(p))
            return jpgs[0]
        return None

    def _attach_cover_if_possible(self, mp4_path: str, cover_jpg: str) -> bool:
        self.write_log("🖼️ 开始写入封面...")
        tmp = mp4_path + ".cover_tmp.mp4"
        ok = self._run_ffmpeg([
            "-y",
            "-i", mp4_path,
            "-i", cover_jpg,
            "-map", "0",
            "-map", "1",
            "-c", "copy",
            "-disposition:v:1", "attached_pic",
            "-movflags", "+faststart",
            tmp
        ], expected_output=tmp, timeout=600)
        if not ok:
            self._safe_remove(tmp)
            return False
        try:
            os.replace(tmp, mp4_path)
            self.last_success_media = mp4_path
            return True
        except Exception:
            self._safe_remove(tmp)
            return False

    def _find_existing_from_info(self, info: dict) -> Optional[str]:
        candidates = []

        for k in ("filepath", "_filename", "filename"):
            v = info.get(k)
            if v and isinstance(v, str):
                candidates.append(v)

        rds = info.get("requested_downloads") or []
        for rd in rds:
            for k in ("filepath", "filename", "_filename"):
                v = rd.get(k)
                if v and isinstance(v, str):
                    candidates.append(v)

        seen = set()
        ordered = []
        for c in candidates:
            if c and c not in seen:
                seen.add(c)
                ordered.append(c)

        for c in ordered:
            if os.path.exists(c) and not c.endswith(".part"):
                ext = os.path.splitext(c)[1].lower()
                if ext not in (".360seurl",):
                    return c
        return None

    def _find_actual_downloaded_file(self, info: dict, ydl: yt_dlp.YoutubeDL) -> Optional[str]:
        found = self._find_existing_from_info(info)
        if found:
            return found

        candidates = []
        try:
            guess = ydl.prepare_filename(info)
            candidates.extend([
                guess,
                os.path.splitext(guess)[0] + ".mkv",
                os.path.splitext(guess)[0] + ".mp4",
                os.path.splitext(guess)[0] + ".webm",
                os.path.splitext(guess)[0] + ".m4a",
                os.path.splitext(guess)[0] + ".mp3",
            ])
        except Exception:
            pass

        normalized = []
        for c in candidates:
            if c and c not in normalized:
                normalized.append(c)

        for c in normalized:
            if os.path.exists(c) and not c.endswith(".part"):
                ext = os.path.splitext(c)[1].lower()
                if ext not in (".360seurl",):
                    return c

        for c in normalized:
            base_no_ext, _ = os.path.splitext(c)
            parent = os.path.dirname(c) or "."
            pattern = base_no_ext + ".*"
            for p in glob.glob(pattern):
                if os.path.isfile(p) and not p.endswith(".part"):
                    ext = os.path.splitext(p)[1].lower()
                    if ext not in (".360seurl",):
                        return p
            try:
                name = os.path.basename(base_no_ext)
                for p in glob.glob(os.path.join(parent, name + ".*")):
                    if os.path.isfile(p) and not p.endswith(".part"):
                        ext = os.path.splitext(p)[1].lower()
                        if ext not in (".360seurl",):
                            return p
            except Exception:
                pass

        return None

    # =========================
    # 标题获取
    # =========================
    def fetch_worker(self, urls, token: int):
        ydl_opts = {
            "quiet": True,
            "skip_download": True,
            "noplaylist": True,
            "ignoreerrors": True,
            "logger": self._make_logger(),
        }
        self._inject_js_runtime_opts(ydl_opts)
        self._inject_ejs_remote_components(ydl_opts)
        self._inject_youtube_extractor_args(ydl_opts)

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            for url in urls:
                with self.lock:
                    if token != self.fetch_thread_token:
                        return
                try:
                    info = ydl.extract_info(url, download=False)
                    title = (info or {}).get("title") or "未知标题"
                    with self.lock:
                        if token == self.fetch_thread_token:
                            self.url_to_title[url] = f"📌 {title}"
                    self.root.after(0, self.render_title_list)
                except Exception as e:
                    msg = f"⚠️ 标题获取失败: {e}  |  {url}"
                    with self.lock:
                        if token == self.fetch_thread_token:
                            self.url_to_title[url] = msg
                    self.root.after(0, self.render_title_list)
                    self._safe_log(msg)

    # =========================
    # 下载主流程
    # =========================
    def start_task(self):
        if self.is_running:
            return
        urls = self.parse_urls_from_input()
        if not urls:
            messagebox.showwarning("提示", "请先粘贴至少一个链接。")
            return

        self.is_running = True
        self.stop_requested = False
        self.start_btn.config(state="disabled", text="正在下载...")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="准备开始下载...", fg="blue")
        self.progress_bar.configure(value=0)

        threading.Thread(target=self.download_thread, args=(urls,), daemon=True).start()

    def stop_task(self):
        self.write_log("🛑 正在请求停止，请稍候...")

        target = self.current_ffmpeg_target or self.last_success_media
        if self._file_ready(target):
            self.write_log(f"ℹ️ 检测到成品已生成：{os.path.basename(target)}，不再强制终止后处理。")
            self.status_label.config(text="文件已生成，正在完成收尾...", fg="green")
            return

        self.stop_requested = True
        self.status_label.config(text="正在停止...", fg="red")

        try:
            if self.current_ffmpeg_process and self.current_ffmpeg_process.poll() is None:
                self.current_ffmpeg_process.kill()
                self.write_log("🛑 已终止 ffmpeg 后处理进程")
        except Exception as e:
            self.write_log(f"⚠️ 终止 ffmpeg 失败: {e}")

    def _build_base_ydl_opts(self, save_path: str) -> dict:
        opts = {
            "outtmpl": os.path.join(save_path, "%(title)s.%(ext)s"),
            "progress_hooks": [self.p_hook],
            "postprocessor_hooks": [self.pp_hook],
            "logger": self._make_logger(),
            "ignoreerrors": True,
            "noplaylist": True,
            "continuedl": True,
            "concurrent_fragment_downloads": 8,
            "fragment_retries": 10,
            "retries": 10,
            "sleep_interval": 0,
            "sleep_interval_requests": 0,
        }
        self._inject_js_runtime_opts(opts)
        self._inject_ejs_remote_components(opts)
        self._inject_youtube_extractor_args(opts)

        with self.lock:
            ffmpeg_path = self.env_info.get("ffmpeg")
        if ffmpeg_path:
            opts["ffmpeg_location"] = ffmpeg_path

        return opts

    def _download_audio_mp3(self, ydl: yt_dlp.YoutubeDL, url: str):
        ydl.params["format"] = "bestaudio/best"
        pps = [
            {"key": "FFmpegExtractAudio", "preferredcodec": "mp3", "preferredquality": "192"},
            {"key": "FFmpegMetadata"},
        ]
        if self.thumb_var.get():
            ydl.params["writethumbnail"] = True
            pps.insert(1, {"key": "EmbedThumbnail"})
        else:
            ydl.params["writethumbnail"] = False

        ydl.params["postprocessors"] = pps
        self.write_log("🎯 模式=仅音频：bestaudio -> MP3")
        info = ydl.extract_info(url, download=True)

        if info:
            actual = self._find_actual_downloaded_file(info, ydl)
            if actual and os.path.exists(actual):
                self.last_success_media = actual
                self.write_log(f"✅ 音频完成：{os.path.basename(actual)}")
        return info

    def _download_auto_video(self, ydl: yt_dlp.YoutubeDL, url: str, cap: Optional[int]):
        ydl.params["format"] = self._fallback_format(cap)
        ydl.params["merge_output_format"] = "mp4"
        ydl.params.pop("postprocessors", None)
        ydl.params.pop("postprocessor_args", None)

        # 视频模式默认跳过封面嵌入，避免卡在最后一步
        ydl.params["writethumbnail"] = False
        ydl.params["postprocessors"] = [
            {"key": "FFmpegMetadata"},
        ]

        if self.thumb_var.get():
            self.write_log("ℹ️ 视频模式为避免卡在后处理，已跳过封面嵌入。")

        self.write_log(f"🎯 模式=自动：format={ydl.params['format']}")
        info = ydl.extract_info(url, download=True)

        if info:
            actual = self._find_actual_downloaded_file(info, ydl)
            if actual and os.path.exists(actual):
                self.last_success_media = actual
                self.write_log(f"✅ 视频完成：{os.path.basename(actual)}")
        return info

    def _download_compat_accurate(self, ydl: yt_dlp.YoutubeDL, url: str, cap: Optional[int]):
        ydl.params["format"] = self._fallback_format(cap)
        ydl.params["merge_output_format"] = "mkv"
        ydl.params.pop("postprocessors", None)
        ydl.params.pop("postprocessor_args", None)

        # 兼容模式直接跳过视频封面写入，优先稳定
        ydl.params["writethumbnail"] = False

        if self.thumb_var.get():
            self.write_log("ℹ️ 兼容模式为避免 MP4 收尾卡住，已跳过视频封面嵌入。")

        self.write_log(f"🎯 兼容模式(100%准确)：先下载中间文件 | format={ydl.params['format']}")
        info = ydl.extract_info(url, download=True)
        if not info:
            self.write_log("❌ 下载完成但未返回 info")
            return

        in_path = self._find_actual_downloaded_file(info, ydl)
        if not in_path or not os.path.exists(in_path):
            self.write_log("❌ 找不到实际下载文件，无法继续兼容处理")
            return

        ext = os.path.splitext(in_path)[1].lower()
        if ext in (".part", ".360seurl"):
            self.write_log(f"❌ 拿到的不是有效媒体文件：{in_path}")
            return

        self.write_log("🔬 开始探测实际编码...")
        vcodec, acodec = self._ffprobe_codec(in_path)
        self.write_log(f"🔬 实际落盘 codec：v={vcodec}  a={acodec}")

        need_v, need_a = self._analyze_compatibility(vcodec, acodec)

        base_no_ext, _ = os.path.splitext(in_path)
        out_mp4 = base_no_ext + ".mp4"
        if os.path.abspath(out_mp4).lower() == os.path.abspath(in_path).lower():
            out_mp4 = base_no_ext + ".compat.mp4"

        if not need_v and not need_a:
            self.write_log("⚡ 兼容模式：视频=H264，音频=AAC -> 直接 remux/copy 到 MP4")
            ok = self._run_ffmpeg([
                "-y",
                "-i", in_path,
                "-map", "0:v:0",
                "-map", "0:a:0?",
                "-c", "copy",
                "-movflags", "+faststart",
                out_mp4
            ], expected_output=out_mp4)
            if not ok:
                self.write_log("⚠️ remux/copy 失败，改为全量转码兜底")
                need_v, need_a = True, True

        if need_v or need_a:
            self.write_log("🔄 开始兼容处理...")
            if need_v and need_a:
                self.write_log(f"🐢 兼容模式：视频={vcodec}，音频={acodec} -> 视频音频都转码")
                ff_args = [
                    "-y",
                    "-i", in_path,
                    "-map", "0:v:0",
                    "-map", "0:a:0?",
                    "-c:v", "libx264",
                    "-preset", "medium",
                    "-crf", "20",
                    "-pix_fmt", "yuv420p",
                    "-c:a", "aac",
                    "-b:a", "192k",
                    "-movflags", "+faststart",
                    out_mp4
                ]
            elif need_v:
                self.write_log(f"🐢 兼容模式：视频={vcodec} 不兼容 -> 转码视频，音频统一转 AAC")
                ff_args = [
                    "-y",
                    "-i", in_path,
                    "-map", "0:v:0",
                    "-map", "0:a:0?",
                    "-c:v", "libx264",
                    "-preset", "medium",
                    "-crf", "20",
                    "-pix_fmt", "yuv420p",
                    "-c:a", "aac",
                    "-b:a", "192k",
                    "-movflags", "+faststart",
                    out_mp4
                ]
            else:
                self.write_log(f"🐢 兼容模式：音频={acodec} 不兼容 -> 仅转码音频为 AAC，视频直通")
                ff_args = [
                    "-y",
                    "-i", in_path,
                    "-map", "0:v:0",
                    "-map", "0:a:0?",
                    "-c:v", "copy",
                    "-c:a", "aac",
                    "-b:a", "192k",
                    "-movflags", "+faststart",
                    out_mp4
                ]

            ok = self._run_ffmpeg(ff_args, expected_output=out_mp4)
            if not ok:
                self.write_log("❌ 兼容处理失败，未生成最终 MP4")
                return

        if os.path.exists(out_mp4):
            final_v, final_a = self._ffprobe_codec(out_mp4)
            self.last_success_media = out_mp4
            self.write_log(f"✅ 最终成品：{os.path.basename(out_mp4)} | v={final_v} a={final_a}")
        else:
            self.write_log("❌ 最终 MP4 未生成")
            return

        if self.thumb_var.get():
            self.write_log("ℹ️ 当前稳定版已跳过视频封面嵌入，不影响播放。")

        if os.path.exists(out_mp4):
            if os.path.abspath(in_path).lower() != os.path.abspath(out_mp4).lower():
                self._safe_remove(in_path)
                self.write_log("🧹 已删除中间媒体文件")
            self._safe_remove(out_mp4 + ".part")
            self._safe_remove(base_no_ext + ".part")

    def download_thread(self, urls: List[str]):
        save_path = self.path_var.get().strip() or os.path.join(os.getcwd(), "downloads")
        os.makedirs(save_path, exist_ok=True)

        base_opts = self._build_base_ydl_opts(save_path)

        with yt_dlp.YoutubeDL(base_opts) as ydl:
            for idx, url in enumerate(urls, start=1):
                if self.stop_requested:
                    self.write_log("⚠️ 任务已中途中断。已保存当前进度（支持断点续传）。")
                    break

                self.current_ffmpeg_target = None
                self.last_success_media = None
                self.progress_bar.configure(value=0)

                self.write_log(f"▶️ [{idx}/{len(urls)}] 处理中: {url}")

                ydl.params.pop("postprocessors", None)
                ydl.params.pop("postprocessor_args", None)
                ydl.params.pop("merge_output_format", None)
                ydl.params.pop("writethumbnail", None)

                cap = self._height_cap_from_ui()
                mode = self._mode()

                try:
                    if mode == "audio":
                        self._download_audio_mp3(ydl, url)
                    elif mode == "compat_accurate":
                        self._download_compat_accurate(ydl, url, cap)
                    else:
                        self._download_auto_video(ydl, url, cap)
                except UserStop:
                    self.write_log("🛑 已停止：当前下载已中断（支持断点续传）。")
                    break
                except Exception as e:
                    target = self.current_ffmpeg_target or self.last_success_media
                    if self._file_ready(target):
                        self.write_log(f"⚠️ 流程返回异常，但成品已存在，按成功处理：{e}")
                    else:
                        self.write_log(f"❌ 错误: {e}")

        self.root.after(0, self.on_finished)

    def on_finished(self):
        self.is_running = False
        self.start_btn.config(state="normal", text="🚀 开始/恢复下载")
        self.stop_btn.config(state="disabled")
        self.current_ffmpeg_process = None
        self.current_ffmpeg_target = None

        if not self.stop_requested:
            self.status_label.config(text="所有任务完成", fg="green")
            messagebox.showinfo("成功", "任务已完成！")
        else:
            self.status_label.config(text="已停止 (支持断点续传)", fg="orange")

    def p_hook(self, d):
        if self.stop_requested:
            raise UserStop()

        status = d.get("status")
        if status == "downloading":
            p_str = str(d.get("_percent_str", "0%")).replace("%", "").strip()
            try:
                p = float(p_str)
                self.root.after(0, lambda v=p: self.progress_bar.configure(value=v))
                self.root.after(0, lambda v=p: self.status_label.config(text=f"下载进度: {v:.1f}%", fg="blue"))
            except Exception:
                pass
        elif status == "finished":
            self.root.after(0, lambda: self.status_label.config(text="下载完成，正在收尾...", fg="blue"))

    def pp_hook(self, d):
        status = d.get("status")
        pp = d.get("postprocessor", "postprocessor")
        info = d.get("info_dict") or {}

        actual = self._find_existing_from_info(info)
        if actual and os.path.exists(actual):
            self.last_success_media = actual

        if status in ("started", "processing"):
            self.root.after(0, lambda p=pp: self.status_label.config(text=f"后处理中: {p}", fg="blue"))
        elif status == "finished":
            self.root.after(0, lambda p=pp: self.status_label.config(text=f"后处理完成: {p}", fg="blue"))

    # =========================
    # 文件夹 / 配置 / 日志
    # =========================
    def open_download_folder(self):
        path = self.path_var.get().strip() or os.path.join(os.getcwd(), "downloads")
        os.makedirs(path, exist_ok=True)
        try:
            system = platform.system().lower()
            if system.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif system == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except Exception as e:
            messagebox.showerror("打开失败", f"无法打开下载文件夹：{e}")

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_config(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({"path": self.path_var.get()}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.write_log(f"⚠️ 配置保存失败: {e}")

    def select_path(self):
        p = filedialog.askdirectory()
        if p:
            self.path_var.set(p)
            self.save_config()

    def write_log(self, text):
        self.log_box.config(state="normal")
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)
        self.log_box.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    app = AdvancedDownloader(root)
    root.mainloop()