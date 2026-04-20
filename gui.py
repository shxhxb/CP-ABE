"""
CP-ABE 图形界面：所有密码学操作通过子进程调用 cp_abe_cli。
需先 init 状态目录，再为各用户 keygen，然后进行 encrypt / decrypt 等。
"""
import json
import locale
import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


def _run_subprocess(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


def _load_json_sidecar(path: str) -> tuple[dict | None, str | None]:
    """
    读取 .ct.json。CLI 在 Windows 上曾用 ANSI 写侧车，故依次尝试 UTF-8 / 中文代码页。
    文件不存在返回 (None, None)；失败返回 (None, 错误说明)。
    """
    if not os.path.isfile(path):
        return None, None
    encodings = ("utf-8-sig", "utf-8", "gbk", "cp936", "gb18030")
    last_err = None
    for enc in encodings:
        try:
            with open(path, encoding=enc) as f:
                return json.load(f), None
        except UnicodeDecodeError as e:
            last_err = e
            continue
        except json.JSONDecodeError as e:
            return None, f"JSON 无效: {e}"
    pref = locale.getpreferredencoding(False)
    if pref:
        try:
            with open(path, encoding=pref) as f:
                return json.load(f), None
        except (UnicodeDecodeError, json.JSONDecodeError, LookupError, OSError) as e:
            last_err = e
    try:
        with open(path, "rb") as f:
            blob = f.read()
        for enc in encodings:
            try:
                return json.loads(blob.decode(enc)), None
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
    except OSError as e:
        return None, str(e)
    return None, str(last_err) if last_err else "无法解码侧车 JSON"


class ABEGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("CP-ABE GUI（cp_abe_cli）")
        self.geometry("980x720")

        self._project_root = os.path.dirname(os.path.abspath(__file__))
        self.identities = ["user_alice", "user_bob", "user_carol"]
        self.exe_var = tk.StringVar(value=self.default_exe_path())
        # 与 cli 默认一致：工程根下 abe_state（init 会创建；勿指向需管理员权限的目录）
        self.state_var = tk.StringVar(value=os.path.join(self._project_root, "abe_state"))
        self.init_rbits = tk.StringVar(value="160")
        self.init_qbits = tk.StringVar(value="512")
        self.init_n_users = tk.StringVar(value="16")
        self.owner_var = tk.StringVar(value="user_alice")
        self.actor_var = tk.StringVar(value="user_alice")
        self.new_identity_var = tk.StringVar()
        self.input_file_var = tk.StringVar()
        self.out_ct_var = tk.StringVar()
        self.package_file_var = tk.StringVar()
        self.dec_out_var = tk.StringVar()
        self.source_name_var = tk.StringVar(value="plain.bin")
        self.keygen_uid_var = tk.StringVar(value="user_alice")
        self.keygen_idx_var = tk.StringVar(value="0")
        self.trace_sk_var = tk.StringVar()
        self.revoke_uid_var = tk.StringVar(value="user_alice")
        self.demo_user_var = tk.StringVar(value="user_alice")
        self.demo_msg_var = tk.StringVar(value="hello-cp-abe-guo2023")

        self._build()
        self._refresh_id_widgets()
        self._sync_trace_sk_default()

    @staticmethod
    def default_exe_path() -> str:
        """
        默认可执行文件路径：优先选已存在的文件，兼容
        - CMake 单配置（MinGW/Ninja/Linux）：build/cp_abe_cli[.exe]
        - Visual Studio 多配置：build/Release 或 build/Debug
        若尚未编译，仍显示 build/ 下主路径，便于用户对照 BUILD.txt 构建。
        """
        base = os.path.dirname(os.path.abspath(__file__))
        name = "cp_abe_cli.exe" if os.name == "nt" else "cp_abe_cli"
        candidates = [
            os.path.join(base, "build", name),
            os.path.join(base, "build", "Release", name),
            os.path.join(base, "build", "Debug", name),
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p
        return candidates[0]

    def _build_dir_for_dialog(self) -> str:
        """浏览对话框起始目录：优先已存在的 build / Release / Debug。"""
        base = self._project_root
        for sub in ("build", os.path.join("build", "Release"), os.path.join("build", "Debug")):
            d = os.path.join(base, sub)
            if os.path.isdir(d):
                return d
        return base

    def _exe(self) -> str:
        return self.exe_var.get().strip()

    def _state(self) -> str:
        return self.state_var.get().strip()

    def _build(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(root)
        top.pack(fill=tk.X)
        ttk.Label(top, text="cp_abe_cli").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.exe_var, width=62).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="浏览", command=self.pick_exe).pack(side=tk.LEFT)

        row2 = ttk.Frame(root)
        row2.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(row2, text="状态目录").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.state_var, width=62).pack(side=tk.LEFT, padx=6)
        ttk.Button(row2, text="浏览", command=self.pick_state_dir).pack(side=tk.LEFT)

        notebook = ttk.Notebook(root)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        tab_state = ttk.Frame(notebook, padding=10)
        tab_ops = ttk.Frame(notebook, padding=10)
        tab_track = ttk.Frame(notebook, padding=10)
        tab_log = ttk.Frame(notebook, padding=10)
        notebook.add(tab_state, text="状态与密钥")
        notebook.add(tab_ops, text="文件加解密")
        notebook.add(tab_track, text="追溯与撤销")
        notebook.add(tab_log, text="演示与日志")

        self._build_state_tab(tab_state)
        self._build_ops_tab(tab_ops)
        self._build_track_tab(tab_track)
        self._build_log_tab(tab_log)

    def _build_state_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        init = ttk.LabelFrame(parent, text="init（创建配对参数、MSK、KEK 树等）", padding=8)
        init.grid(row=0, column=0, columnspan=3, sticky="ew")
        ttk.Label(init, text="rbits").grid(row=0, column=0, sticky="w")
        ttk.Entry(init, textvariable=self.init_rbits, width=8).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(init, text="qbits").grid(row=0, column=2, sticky="w", padx=(12, 0))
        ttk.Entry(init, textvariable=self.init_qbits, width=8).grid(row=0, column=3, sticky="w", padx=6)
        ttk.Label(init, text="n_users").grid(row=0, column=4, sticky="w", padx=(12, 0))
        ttk.Entry(init, textvariable=self.init_n_users, width=6).grid(row=0, column=5, sticky="w", padx=6)
        ttk.Button(init, text="执行 init", command=self.do_init).grid(row=0, column=6, padx=(16, 0))

        idf = ttk.LabelFrame(parent, text="身份列表（用于下拉框；keygen 需指定 user_index）", padding=8)
        idf.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        ttk.Label(idf, text="新增身份").grid(row=0, column=0, sticky="w")
        ttk.Entry(idf, textvariable=self.new_identity_var, width=22).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Button(idf, text="添加", command=self.add_identity).grid(row=0, column=2, sticky="w")
        ttk.Button(idf, text="删除选中", command=self.remove_identity).grid(row=0, column=3, sticky="w", padx=6)
        self.id_list = tk.Listbox(idf, selectmode=tk.EXTENDED, height=5, exportselection=False)
        self.id_list.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(8, 0))

        kg = ttk.LabelFrame(parent, text="keygen（为某用户生成 sk/tk/ku）", padding=8)
        kg.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        ttk.Label(kg, text="user_id").grid(row=0, column=0, sticky="w")
        self.keygen_uid_combo = ttk.Combobox(kg, textvariable=self.keygen_uid_var, width=18, state="readonly")
        self.keygen_uid_combo.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(kg, text="user_index (0..n_users-1)").grid(row=0, column=2, sticky="w", padx=(12, 0))
        ttk.Entry(kg, textvariable=self.keygen_idx_var, width=6).grid(row=0, column=3, sticky="w", padx=6)
        ttk.Button(kg, text="执行 keygen", command=self.do_keygen).grid(row=0, column=4, padx=(12, 0))

        hint = ttk.Label(
            parent,
            text="说明：encrypt 使用固定策略 AND(attr0,attr1)，KEK 覆盖由 init 时的 n_users 与 keygen 的索引共同决定。",
            wraplength=900,
        )
        hint.grid(row=3, column=0, columnspan=3, sticky="w", pady=(12, 0))

    def _build_ops_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        enc = ttk.LabelFrame(parent, text="encrypt", padding=8)
        enc.grid(row=0, column=0, columnspan=2, sticky="ew")
        enc.columnconfigure(1, weight=1)
        ttk.Label(enc, text="明文文件").grid(row=0, column=0, sticky="w")
        ttk.Entry(enc, textvariable=self.input_file_var).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(enc, text="选择", command=self.pick_input_file).grid(row=0, column=2)
        ttk.Label(enc, text="输出 .ct").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(enc, textvariable=self.out_ct_var).grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        ttk.Button(enc, text="另存为", command=self.pick_out_ct).grid(row=1, column=2, pady=(8, 0))
        ttk.Label(enc, text="owner 标签").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(enc, textvariable=self.owner_var, width=20).grid(row=2, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(enc, text="source 名称").grid(row=3, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(enc, textvariable=self.source_name_var, width=28).grid(row=3, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Button(enc, text="执行 encrypt", command=self.do_encrypt).grid(row=4, column=2, sticky="e", pady=(10, 0))

        dec = ttk.LabelFrame(parent, text="decrypt", padding=8)
        dec.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        dec.columnconfigure(1, weight=1)
        ttk.Label(dec, text="密文 .ct").grid(row=0, column=0, sticky="w")
        ttk.Entry(dec, textvariable=self.package_file_var).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(dec, text="选择", command=self.pick_ct_file).grid(row=0, column=2)
        ttk.Label(dec, text="解密用户").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.actor_combo = ttk.Combobox(dec, textvariable=self.actor_var, state="readonly")
        self.actor_combo.grid(row=1, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Label(dec, text="输出文件").grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(dec, textvariable=self.dec_out_var).grid(row=2, column=1, sticky="ew", padx=6, pady=(8, 0))
        ttk.Button(dec, text="另存为", command=self.pick_dec_out).grid(row=2, column=2, pady=(8, 0))
        ttk.Button(dec, text="执行 decrypt", command=self.do_decrypt).grid(row=3, column=2, sticky="e", pady=(10, 0))

        ttk.Label(dec, text="侧车 JSON 摘要（若存在 .ct.json）").grid(row=4, column=0, sticky="nw", pady=(8, 0))
        self.package_info = tk.Text(dec, height=8)
        self.package_info.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(6, 0))
        dec.rowconfigure(5, weight=1)

    def _build_track_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        tr = ttk.LabelFrame(parent, text="trace（从泄露的 sk.bin 追溯身份）", padding=8)
        tr.grid(row=0, column=0, columnspan=2, sticky="ew")
        tr.columnconfigure(1, weight=1)
        ttk.Label(tr, text="sk.bin 路径").grid(row=0, column=0, sticky="w")
        ttk.Entry(tr, textvariable=self.trace_sk_var).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(tr, text="选择", command=self.pick_trace_sk).grid(row=0, column=2)
        ttk.Button(tr, text="填入当前用户默认路径", command=self._sync_trace_sk_default).grid(row=1, column=1, sticky="w", padx=6, pady=(6, 0))
        ttk.Button(tr, text="执行 trace", command=self.do_trace).grid(row=1, column=2, sticky="e", pady=(6, 0))

        rev = ttk.LabelFrame(parent, text="revoke（将 user_id 写入状态 revoked.txt，后续 decrypt 拒绝）", padding=8)
        rev.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        ttk.Label(rev, text="撤销对象").grid(row=0, column=0, sticky="w")
        self.revoke_combo = ttk.Combobox(rev, textvariable=self.revoke_uid_var, state="readonly")
        self.revoke_combo.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Button(rev, text="执行 revoke", command=self.do_revoke).grid(row=0, column=2, sticky="e")

        self.trace_output = tk.Text(parent)
        self.trace_output.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(12, 0))
        parent.rowconfigure(2, weight=1)

    def _build_log_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)
        row = ttk.Frame(parent)
        row.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(row, text="demo 用户").pack(side=tk.LEFT)
        self.demo_user_combo = ttk.Combobox(row, textvariable=self.demo_user_var, state="readonly", width=16)
        self.demo_user_combo.pack(side=tk.LEFT, padx=6)
        ttk.Label(row, text="消息").pack(side=tk.LEFT, padx=(12, 0))
        ttk.Entry(row, textvariable=self.demo_msg_var, width=40).pack(side=tk.LEFT, padx=6)
        ttk.Button(row, text="运行 demo", command=self.run_demo).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Button(row, text="roundtrip-bin 自检", command=self.run_roundtrip_bin).pack(side=tk.LEFT, padx=6)

        self.log_output = tk.Text(parent)
        self.log_output.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        parent.rowconfigure(1, weight=1)

    def _refresh_id_widgets(self) -> None:
        self.id_list.delete(0, tk.END)
        for uid in self.identities:
            self.id_list.insert(tk.END, uid)
        vals = self.identities
        for combo in (self.actor_combo, self.demo_user_combo, self.keygen_uid_combo, self.revoke_combo):
            combo["values"] = vals
        first = self.identities[0] if self.identities else "user_alice"
        for var in (self.actor_var, self.demo_user_var, self.keygen_uid_var, self.revoke_uid_var):
            if self.identities and var.get() not in self.identities:
                var.set(first)

    def _sync_trace_sk_default(self) -> None:
        st = self._state()
        uid = self.keygen_uid_var.get().strip() or "user_alice"
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in uid)
        self.trace_sk_var.set(os.path.join(st, "users", safe, "sk.bin"))

    def _append_log(self, title: str, cmd: list[str], proc: subprocess.CompletedProcess) -> None:
        self.log_output.insert(tk.END, f"=== {title} ===\n$ {' '.join(cmd)}\n\n")
        if proc.stdout:
            self.log_output.insert(tk.END, proc.stdout)
            if not proc.stdout.endswith("\n"):
                self.log_output.insert(tk.END, "\n")
        if proc.stderr:
            self.log_output.insert(tk.END, "[stderr]\n" + proc.stderr)
            if not proc.stderr.endswith("\n"):
                self.log_output.insert(tk.END, "\n")
        self.log_output.insert(tk.END, f"退出码: {proc.returncode}\n\n")
        self.log_output.see(tk.END)

    def _require_exe(self) -> bool:
        exe = self._exe()
        if not exe or not os.path.isfile(exe):
            messagebox.showerror("错误", "请填写有效的 cp_abe_cli 路径")
            return False
        return True

    def pick_exe(self) -> None:
        ft = [("可执行文件", "*.exe"), ("All", "*.*")] if os.name == "nt" else [("可执行文件", "cp_abe_cli"), ("All", "*.*")]
        p = filedialog.askopenfilename(
            title="选择 cp_abe_cli",
            initialdir=self._build_dir_for_dialog(),
            filetypes=ft,
        )
        if p:
            self.exe_var.set(p)

    def pick_state_dir(self) -> None:
        initial = self._state()
        if not initial or not os.path.isdir(initial):
            initial = self._project_root
        p = filedialog.askdirectory(title="选择状态目录", initialdir=initial)
        if p:
            self.state_var.set(p)
            self._sync_trace_sk_default()

    def pick_input_file(self) -> None:
        p = filedialog.askopenfilename(title="选择明文文件")
        if p:
            self.input_file_var.set(p)
            base = os.path.basename(p)
            if not self.out_ct_var.get().strip():
                self.out_ct_var.set(os.path.join(os.path.dirname(p), base + ".ct"))
            if not self.source_name_var.get().strip():
                self.source_name_var.set(base)

    def pick_out_ct(self) -> None:
        p = filedialog.asksaveasfilename(
            title="密文输出",
            defaultextension=".ct",
            filetypes=[("密文", "*.ct"), ("All", "*.*")],
        )
        if p:
            self.out_ct_var.set(p)

    def pick_ct_file(self) -> None:
        p = filedialog.askopenfilename(
            title="选择密文 .ct",
            filetypes=[("密文", "*.ct"), ("All", "*.*")],
        )
        if p:
            self.package_file_var.set(p)
            if not self.dec_out_var.get().strip():
                root, _ = os.path.splitext(p)
                self.dec_out_var.set(root + ".plain")
            self.preview_sidecar(p)

    def pick_dec_out(self) -> None:
        p = filedialog.asksaveasfilename(title="解密输出文件", filetypes=[("All", "*.*")])
        if p:
            self.dec_out_var.set(p)

    def pick_trace_sk(self) -> None:
        p = filedialog.askopenfilename(title="选择 sk.bin", filetypes=[("sk.bin", "*.bin"), ("All", "*.*")])
        if p:
            self.trace_sk_var.set(p)

    def add_identity(self) -> None:
        uid = self.new_identity_var.get().strip()
        if not uid:
            return
        if uid in self.identities:
            messagebox.showwarning("提示", "身份已存在")
            return
        self.identities.append(uid)
        self.new_identity_var.set("")
        self._refresh_id_widgets()

    def remove_identity(self) -> None:
        idxs = list(self.id_list.curselection())
        if not idxs:
            return
        for idx in reversed(idxs):
            uid = self.id_list.get(idx)
            self.identities.remove(uid)
        if not self.identities:
            self.identities = ["user_alice"]
        self._refresh_id_widgets()

    def preview_sidecar(self, ct_path: str) -> None:
        json_path = ct_path + ".json"
        self.package_info.delete("1.0", tk.END)
        data, err = _load_json_sidecar(json_path)
        if data is not None:
            self.package_info.insert("1.0", json.dumps(data, ensure_ascii=False, indent=2))
            return
        if err:
            self.package_info.insert("1.0", f"读取侧车失败: {err}\n路径: {json_path}")
            return
        self.package_info.insert("1.0", f"（无侧车文件）{json_path}")

    def do_init(self) -> None:
        if not self._require_exe():
            return
        st = self._state()
        if not st:
            messagebox.showerror("错误", "请填写状态目录")
            return
        cmd = [
            self._exe(),
            "init",
            st,
            self.init_rbits.get().strip() or "160",
            self.init_qbits.get().strip() or "512",
            self.init_n_users.get().strip() or "16",
        ]
        proc = _run_subprocess(cmd)
        self._append_log("init", cmd, proc)
        if proc.returncode == 0:
            messagebox.showinfo("成功", "init 完成")
        else:
            messagebox.showerror("init 失败", proc.stderr or proc.stdout or f"exit {proc.returncode}")

    def do_keygen(self) -> None:
        if not self._require_exe():
            return
        st = self._state()
        uid = self.keygen_uid_var.get().strip()
        idx_s = self.keygen_idx_var.get().strip()
        if not st or not uid or not idx_s.isdigit():
            messagebox.showerror("错误", "请填写状态目录、user_id 与数字 user_index")
            return
        cmd = [self._exe(), "keygen", st, uid, idx_s]
        proc = _run_subprocess(cmd)
        self._append_log("keygen", cmd, proc)
        if proc.returncode == 0:
            messagebox.showinfo("成功", "keygen 完成")
            self._sync_trace_sk_default()
        else:
            messagebox.showerror("keygen 失败", proc.stderr or proc.stdout or f"exit {proc.returncode}")

    def do_encrypt(self) -> None:
        if not self._require_exe():
            return
        st = self._state()
        inf = self.input_file_var.get().strip()
        out = self.out_ct_var.get().strip()
        owner = self.owner_var.get().strip()
        src = self.source_name_var.get().strip() or "file"
        if not st or not inf or not out:
            messagebox.showerror("错误", "请填写状态目录、明文与输出 .ct")
            return
        if not os.path.isfile(inf):
            messagebox.showerror("错误", "明文文件不存在")
            return
        cmd = [self._exe(), "encrypt", st, inf, out, owner, src]
        proc = _run_subprocess(cmd)
        self._append_log("encrypt", cmd, proc)
        if proc.returncode == 0:
            self.preview_sidecar(out)
            messagebox.showinfo("成功", f"encrypt 完成\n{out}")
        else:
            messagebox.showerror("encrypt 失败", proc.stderr or proc.stdout or f"exit {proc.returncode}")

    def do_decrypt(self) -> None:
        if not self._require_exe():
            return
        st = self._state()
        uid = self.actor_var.get().strip()
        ct = self.package_file_var.get().strip()
        out = self.dec_out_var.get().strip()
        if not st or not uid or not ct or not out:
            messagebox.showerror("错误", "请填写状态目录、用户、密文与输出路径")
            return
        if not os.path.isfile(ct):
            messagebox.showerror("错误", "密文文件不存在")
            return
        cmd = [self._exe(), "decrypt", st, uid, ct, out]
        proc = _run_subprocess(cmd)
        self._append_log("decrypt", cmd, proc)
        if proc.returncode == 0:
            messagebox.showinfo("成功", f"decrypt 完成\n{out}")
        else:
            hint = proc.stderr or proc.stdout or f"exit {proc.returncode}"
            detail = (
                hint
                + "\n\n常见原因：状态目录与加密时一致；该用户已 keygen；user_index 与 init 的 n_users 匹配；未被 revoke。"
            )
            messagebox.showerror("decrypt 失败", detail)

    def do_trace(self) -> None:
        if not self._require_exe():
            return
        st = self._state()
        skp = self.trace_sk_var.get().strip()
        if not st or not skp:
            messagebox.showerror("错误", "请填写状态目录与 sk.bin")
            return
        if not os.path.isfile(skp):
            messagebox.showerror("错误", "sk.bin 不存在")
            return
        cmd = [self._exe(), "trace", st, skp]
        proc = _run_subprocess(cmd)
        self._append_log("trace", cmd, proc)
        self.trace_output.insert(tk.END, proc.stdout or "")
        self.trace_output.insert(tk.END, proc.stderr or "")
        self.trace_output.see(tk.END)
        if proc.returncode == 0:
            messagebox.showinfo("trace", proc.stdout.strip() or "OK")
        else:
            messagebox.showerror("trace 失败", proc.stderr or proc.stdout or f"exit {proc.returncode}")

    def do_revoke(self) -> None:
        if not self._require_exe():
            return
        st = self._state()
        uid = self.revoke_uid_var.get().strip()
        if not st or not uid:
            messagebox.showerror("错误", "请填写状态目录与撤销对象")
            return
        cmd = [self._exe(), "revoke", st, uid]
        proc = _run_subprocess(cmd)
        self._append_log("revoke", cmd, proc)
        self.trace_output.insert(tk.END, proc.stdout or "")
        self.trace_output.see(tk.END)
        if proc.returncode == 0:
            messagebox.showinfo("成功", "revoke 已记录")
        else:
            messagebox.showerror("revoke 失败", proc.stderr or proc.stdout or f"exit {proc.returncode}")

    def run_demo(self) -> None:
        if not self._require_exe():
            return
        uid = self.demo_user_var.get().strip()
        msg = self.demo_msg_var.get().strip()
        if not uid:
            messagebox.showerror("错误", "请选择用户")
            return
        cmd = [self._exe(), "demo", uid, msg]
        proc = _run_subprocess(cmd)
        self._append_log("demo", cmd, proc)
        if proc.returncode != 0:
            messagebox.showerror("demo 失败", proc.stderr or proc.stdout or f"exit {proc.returncode}")

    def run_roundtrip_bin(self) -> None:
        if not self._require_exe():
            return
        cmd = [self._exe(), "roundtrip-bin"]
        proc = _run_subprocess(cmd)
        self._append_log("roundtrip-bin", cmd, proc)
        if proc.returncode != 0:
            messagebox.showerror("自检失败", proc.stderr or proc.stdout or f"exit {proc.returncode}")
        else:
            messagebox.showinfo("自检", "roundtrip-bin 通过")


if __name__ == "__main__":
    ABEGui().mainloop()
