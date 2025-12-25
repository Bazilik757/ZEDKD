
import os
import shutil
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Optional, Dict, Any, List

from ..crypto import (
    decrypt_file,
    encrypt_file,
    generate_keys,
    sign_document,
    verify_signature,
)
from ..documents import (
    DOC_TYPES,
    ORDER_WORKFLOW_STEPS,
    DocumentRecord,
    generate_doc_id,
    load_documents_db,
    save_documents_db,
)
from ..forms import (
    FORMS,
    append_form_row,
    load_form_rows,
    save_form_rows,
    update_form_rows,
    upsert_form_row,
)
from ..paths import ARCHIVE_DIR, DOCUMENTS_DIR
from ..utils import (
    calc_file_hash,
    load_audit_events,
    log_event,
    next_seq,
    now_iso,
    relpath_in_storage,
    safe_load_data,
    list_users,
    add_user,
)
from .dialogs import RowEditorDialog


class ZEDKDGApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ZEDKD | Центр управления документами")
        self.root.geometry("1280x820")
        self.root.minsize(1100, 720)

        self.current_user = None
        self.docs = load_documents_db()
        self.current_doc_id = None

        self.status_var = tk.StringVar(value="Готово")
        self.user_name_var = tk.StringVar(value="Пользователь: (не выбран)")
        self.active_view = tk.StringVar(value="flow")

        self.style = ttk.Style()
        self._init_style()

        self.build_ui()
        self.switch_view("flow")
        self.refresh_docs_list()
        self.refresh_forms_all()
        self.refresh_audit()

    # -------------------------
    # helpers
    # -------------------------

    def set_status(self, text: str):
        self.status_var.set(text)

    def _init_style(self):
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.root.configure(bg="#0f172a")
        accent = "#5eead4"
        surface = "#111827"
        muted = "#94a3b8"
        self.style.configure("TFrame", background=surface)
        self.style.configure("Title.TLabel", font=("Inter", 16, "bold"), foreground=accent, background=surface)
        self.style.configure("Muted.TLabel", foreground=muted, background=surface)
        self.style.configure("Card.TLabelframe", background=surface, relief="solid")
        self.style.configure("Card.TLabelframe.Label", background=surface, foreground=accent, font=("Inter", 11, "bold"))
        self.style.configure("Accent.TButton", padding=8, font=("Inter", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", accent)], foreground=[("!disabled", "#0f172a")])

    def require_user(self):
        if not self.current_user:
            messagebox.showwarning("Нет пользователя", "Сначала выберите/введите пользователя.")
            self.set_status("Операция отменена: пользователь не выбран")
            return False
        return True

    def get_doc(self) -> Optional[DocumentRecord]:
        if not self.current_doc_id:
            return None
        for d in self.docs:
            if d.doc_id == self.current_doc_id:
                return d
        return None

    def _resolve_signature_id(self, d: DocumentRecord) -> Optional[str]:
        """Return a persisted signature id for the document without prompting the user."""

        if d.sig_path:
            return d.sig_path

        if d.doc_id:
            sig_id = safe_load_data(f"signature_doc_index:{d.doc_id}", None)
            if sig_id:
                d.sig_path = sig_id
                self.save_all()
                return sig_id
        return None

    def save_all(self):
        save_documents_db(self.docs)

    def ensure_integrity_before_step(self, d: DocumentRecord) -> bool:
        """
        ВАЖНО: по-хорошему, на каждом шаге проверяем, что исходный файл не изменили.
        """
        try:
            current_hash = calc_file_hash(d.stored_path)
            if current_hash != d.hash_value:
                log_event(self.current_user or "system", "integrity_block", "fail", doc_id=d.doc_id, extra={
                    "expected": d.hash_value, "actual": current_hash
                })
                messagebox.showerror(
                    "Целостность нарушена",
                    "Документ был изменён после регистрации.\n"
                    "Прохождение маршрута заблокировано.\n\n"
                    f"Ожидалось: {d.hash_value}\n"
                    f"Фактически: {current_hash}"
                )
                self.set_status("Маршрут остановлен: целостность нарушена")
                self.refresh_audit()
                return False
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return False

    # -------------------------
    # UI layout
    # -------------------------

    def build_ui(self):
        shell = ttk.Frame(self.root, padding=14)
        shell.pack(fill="both", expand=True)

        header = ttk.Frame(shell)
        header.pack(fill="x")
        ttk.Label(header, text="ZEDKD · Центр работы с приказами", style="Title.TLabel").pack(side="left")
        self.user_label = ttk.Label(header, textvariable=self.user_name_var, style="Muted.TLabel")
        self.user_label.pack(side="right")

        sub = ttk.Frame(shell)
        sub.pack(fill="x", pady=(6, 10))
        ttk.Label(sub, text="Маршруты, криптография и учет в едином окне", style="Muted.TLabel").pack(side="left")
        ttk.Label(sub, textvariable=self.status_var, style="Muted.TLabel").pack(side="right")

        body = ttk.Frame(shell)
        body.pack(fill="both", expand=True)

        main_split = ttk.Panedwindow(body, orient="horizontal")
        main_split.pack(fill="both", expand=True)

        nav = ttk.Frame(main_split, width=260, padding=(10, 12))
        nav.configure(style="TFrame")
        main_split.add(nav, weight=0)

        self.content = ttk.Frame(main_split)
        main_split.add(self.content, weight=1)

        self.views: Dict[str, ttk.Frame] = {}
        self._build_nav(nav)
        self.build_flow_view()
        self.build_forms_view()
        self.build_audit_view()

        status_bar = ttk.Label(shell, textvariable=self.status_var, anchor="w", relief="sunken")
        status_bar.pack(fill="x", side="bottom", pady=(10, 0))

    def _build_nav(self, nav: ttk.Frame):
        ttk.Label(nav, text="Режимы", style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        for key, text in [("flow", "Маршрут приказа"), ("forms", "Журналы учета"), ("audit", "Мониторинг действий")]:
            btn = ttk.Radiobutton(nav, text=text, value=key, variable=self.active_view, command=lambda k=key: self.switch_view(k))
            btn.pack(fill="x", pady=4)

        ttk.Separator(nav, orient="horizontal").pack(fill="x", pady=10)
        quick = ttk.LabelFrame(nav, text="Быстрые действия", padding=10, style="Card.TLabelframe")
        quick.pack(fill="x")
        ttk.Button(quick, text="Сменить пользователя", command=self.change_user, style="Accent.TButton").pack(fill="x", pady=4)
        ttk.Button(quick, text="Сгенерировать ключи", command=self.handle_generate_keys).pack(fill="x", pady=4)
        ttk.Button(quick, text="Регистрация файла", command=self.register_document_dialog).pack(fill="x", pady=4)

    def switch_view(self, key: str):
        self.active_view.set(key)
        for name, frame in self.views.items():
            frame.pack_forget()
        if key in self.views:
            self.views[key].pack(fill="both", expand=True)

    def build_flow_view(self):
        frame = ttk.Frame(self.content, padding=10)
        self.views["flow"] = frame

        hero = ttk.LabelFrame(frame, text="Живая карточка приказа", padding=12, style="Card.TLabelframe")
        hero.pack(fill="x")

        top_row = ttk.Frame(hero)
        top_row.pack(fill="x", pady=(0, 4))
        self.loaded_file_label = ttk.Label(top_row, text="Файл не выбран", style="Muted.TLabel")
        self.loaded_file_label.pack(side="left")
        ttk.Button(top_row, text="Загрузить и зарегистрировать", command=self.register_document_dialog, style="Accent.TButton").pack(side="right", padx=4)
        ttk.Button(top_row, text="Следующий этап", command=self.run_next_step).pack(side="right", padx=4)
        ttk.Button(top_row, text="Автопроход", command=self.run_all_steps).pack(side="right", padx=4)

        cards = ttk.Frame(hero)
        cards.pack(fill="x", pady=(6, 0))

        user_card = ttk.LabelFrame(cards, text="Пользователь", padding=10, style="Card.TLabelframe")
        user_card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Label(user_card, textvariable=self.user_name_var, style="Muted.TLabel").pack(anchor="w")
        ttk.Label(user_card, textvariable=self.status_var, style="Muted.TLabel").pack(anchor="w")
        ttk.Button(user_card, text="Сменить", command=self.change_user).pack(anchor="w", pady=(6, 0))

        crypto_card = ttk.LabelFrame(cards, text="Криптооперации", padding=10, style="Card.TLabelframe")
        crypto_card.pack(side="left", fill="x", expand=True)
        ttk.Button(crypto_card, text="Проверка целостности", command=self.check_integrity_button).pack(anchor="w", pady=2)
        ttk.Button(crypto_card, text="Подписать документ", command=self.sign_now).pack(anchor="w", pady=2)
        ttk.Button(crypto_card, text="Проверить подпись", command=self.verify_now).pack(anchor="w", pady=2)
        ttk.Button(crypto_card, text="Зашифровать", command=self.encrypt_now).pack(anchor="w", pady=2)
        ttk.Button(crypto_card, text="Расшифровать", command=self.decrypt_now).pack(anchor="w", pady=2)

        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True, pady=(12, 0))

        list_wrap = ttk.LabelFrame(body, text="Активные документы", padding=10, style="Card.TLabelframe")
        list_wrap.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self.docs_tree = ttk.Treeview(list_wrap, columns=("id", "type", "title", "status"), show="headings", height=14)
        for col, w, label in [("id", 160, "ID"), ("type", 120, "Тип"), ("title", 340, "Заголовок"), ("status", 260, "Статус")]:
            self.docs_tree.heading(col, text=label)
            self.docs_tree.column(col, width=w, anchor="w")
        self.docs_tree.pack(fill="both", expand=True)
        self.docs_tree.bind("<<TreeviewSelect>>", self.on_select_doc)

        doc_actions = ttk.Frame(list_wrap)
        doc_actions.pack(fill="x", pady=(8, 0))
        ttk.Button(doc_actions, text="Открыть файл", command=self.open_doc_file).pack(side="left")
        ttk.Button(doc_actions, text="Удалить", command=self.delete_selected_doc).pack(side="left", padx=6)

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)

        card = ttk.LabelFrame(right, text="Карточка маршрута", padding=12, style="Card.TLabelframe")
        card.pack(fill="x")

        self.card_vars = {k: tk.StringVar(value="") for k in [
            "doc_id", "doc_type", "title", "author", "department", "conf",
            "created_at", "hash", "status", "step", "order_reg_no", "carrier_no"
        ]}

        grid = ttk.Frame(card)
        grid.pack(fill="x")
        labels = [
            ("ID", "doc_id"),
            ("Тип", "doc_type"),
            ("Заголовок", "title"),
            ("Автор", "author"),
            ("Отдел", "department"),
            ("Гриф/конф.", "conf"),
            ("Дата регистрации", "created_at"),
            ("Хэш", "hash"),
            ("Статус", "status"),
            ("Этап", "step"),
            ("Рег.№ приказа", "order_reg_no"),
            ("Носитель (Ф1)", "carrier_no"),
        ]
        for i, (label, key) in enumerate(labels):
            ttk.Label(grid, text=f"{label}:", style="Muted.TLabel").grid(row=i, column=0, sticky="w", pady=2, padx=(0, 6))
            ttk.Label(grid, textvariable=self.card_vars[key]).grid(row=i, column=1, sticky="w", pady=2)
        grid.grid_columnconfigure(1, weight=1)

        wf = ttk.LabelFrame(right, text="Дорожная карта", padding=10, style="Card.TLabelframe")
        wf.pack(fill="both", expand=True, pady=(10, 0))

        self.workflow_list = tk.Listbox(wf, height=12)
        self.workflow_list.pack(fill="both", expand=True)
        for s in ORDER_WORKFLOW_STEPS:
            self.workflow_list.insert("end", s)

        wf_btns = ttk.Frame(wf)
        wf_btns.pack(fill="x", pady=(8, 0))
        ttk.Button(wf_btns, text="Следующий шаг", command=self.run_next_step).pack(side="left")
        ttk.Button(wf_btns, text="Все шаги", command=self.run_all_steps).pack(side="left", padx=6)

    def build_forms_view(self):
        frame = ttk.Frame(self.content, padding=12)
        self.views["forms"] = frame

        header = ttk.LabelFrame(frame, text="Журналы учета", padding=10, style="Card.TLabelframe")
        header.pack(fill="x")
        ttk.Label(header, text="Работа с электронными журналами форм 1–9", style="Muted.TLabel").pack(anchor="w")

        self.forms_notebook = ttk.Notebook(frame)
        self.forms_notebook.pack(fill="both", expand=True, pady=(10, 0))

        self.form_views = {}

        for form_no in sorted(FORMS.keys()):
            frm = ttk.Frame(self.forms_notebook, padding=10)
            self.forms_notebook.add(frm, text=f"Форма {form_no}")
            self.build_form_tab(frm, form_no)

    def build_form_tab(self, parent, form_no: int):
        meta = FORMS[form_no]
        ttk.Label(parent, text=meta["title"], font=("Inter", 11, "bold")).pack(anchor="w", pady=(0, 6))

        columns = meta["columns"]

        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True)

        tree = ttk.Treeview(wrap, columns=[f"c{i}" for i in range(len(columns))], show="headings")
        for i, col_name in enumerate(columns):
            tree.heading(f"c{i}", text=col_name)
            tree.column(f"c{i}", width=220, anchor="w")

        ysb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        xsb = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)

        tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")

        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(0, weight=1)

        btns = ttk.Frame(parent)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="Добавить строку", command=lambda: self.form_add_row(form_no)).pack(side="left")
        ttk.Button(btns, text="Редактировать", command=lambda: self.form_edit_row(form_no)).pack(side="left", padx=6)
        ttk.Button(btns, text="Удалить", command=lambda: self.form_delete_row(form_no)).pack(side="left", padx=6)
        ttk.Button(btns, text="Обновить", command=lambda: self.refresh_form(form_no)).pack(side="right")

        self.form_views[form_no] = {"tree": tree, "columns": columns}

    def build_audit_view(self):
        frame = ttk.Frame(self.content, padding=12)
        self.views["audit"] = frame

        header = ttk.LabelFrame(frame, text="Мониторинг действий", padding=10, style="Card.TLabelframe")
        header.pack(fill="x")
        ttk.Label(header, text="Отслеживание регистраций, шагов маршрута и криптографии", style="Muted.TLabel").pack(anchor="w")
        ttk.Button(header, text="Обновить", command=self.refresh_audit).pack(anchor="e", pady=(6, 0))

        wrap = ttk.Frame(frame)
        wrap.pack(fill="both", expand=True, pady=(10, 0))

        self.audit_tree = ttk.Treeview(
            wrap,
            columns=("ts", "user", "action", "result", "doc"),
            show="headings"
        )
        for col, w, name in [
            ("ts", 180, "Дата/время"),
            ("user", 150, "Пользователь"),
            ("action", 260, "Действие"),
            ("result", 110, "Результат"),
            ("doc", 220, "Документ"),
        ]:
            self.audit_tree.heading(col, text=name)
            self.audit_tree.column(col, width=w, anchor="w")

        ysb = ttk.Scrollbar(wrap, orient="vertical", command=self.audit_tree.yview)
        xsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.audit_tree.xview)
        self.audit_tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)

        self.audit_tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")

        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(0, weight=1)

    # -------------------------
    # Пользователь / ключи
    # -------------------------

    def change_user(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Пользователи")
        dlg.geometry("520x420")
        dlg.transient(self.root)
        dlg.grab_set()

        wrap = ttk.Frame(dlg, padding=10)
        wrap.pack(fill="both", expand=True)

        ttk.Label(wrap, text="Выберите существующего пользователя или добавьте нового").pack(anchor="w", pady=(0, 8))

        columns = ("id", "username", "created", "keys")
        tree = ttk.Treeview(wrap, columns=columns, show="headings", height=10)
        tree.heading("id", text="ID")
        tree.heading("username", text="Имя")
        tree.heading("created", text="Создан")
        tree.heading("keys", text="Ключи")
        tree.column("id", width=60, anchor="center")
        tree.column("username", width=200, anchor="w")
        tree.column("created", width=180, anchor="w")
        tree.column("keys", width=120, anchor="center")
        tree.pack(fill="both", expand=True)

        entry_frame = ttk.Frame(wrap)
        entry_frame.pack(fill="x", pady=(8, 0))
        ttk.Label(entry_frame, text="Новый пользователь:").pack(side="left")
        name_var = tk.StringVar()
        name_entry = ttk.Entry(entry_frame, textvariable=name_var)
        name_entry.pack(side="left", fill="x", expand=True, padx=6)
        status_lbl = ttk.Label(wrap, text="", foreground="#64748b")
        status_lbl.pack(anchor="w", pady=(4, 0))

        btns = ttk.Frame(wrap)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Выбрать", command=lambda: finish_select(tree)).pack(side="left")
        ttk.Button(btns, text="Добавить", command=lambda: add_new()).pack(side="right")
        ttk.Button(btns, text="Закрыть", command=dlg.destroy).pack(side="right", padx=6)

        def refresh_users():
            for i in tree.get_children():
                tree.delete(i)
            for u in list_users():
                keys_note = "созданы" if u.get("has_keys") else "нет"
                tree.insert("", "end", values=(u["id"], u["username"], u["created_at"], keys_note))

        def finish_select(tv: ttk.Treeview):
            sel = tv.selection()
            if not sel:
                messagebox.showwarning("Выбор", "Выберите пользователя из списка")
                return
            vals = tv.item(sel[0], "values")
            username = vals[1]
            keys_note = vals[3] if len(vals) > 3 else "нет"
            self.current_user = username
            key_suffix = "— ключи уже созданы" if keys_note == "созданы" else "— ключи не созданы"
            self.user_name_var.set(f"Пользователь: {self.current_user} ({key_suffix})")
            self.set_status(f"Пользователь: {self.current_user} ({key_suffix})")
            dlg.destroy()

        def add_new():
            try:
                created = add_user(name_var.get())
                status_lbl.config(text=f"Добавлен: {created['username']}")
                name_var.set("")
                refresh_users()
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

        refresh_users()
        tree.bind("<Double-1>", lambda _: finish_select(tree))
        name_entry.focus_set()

    def handle_generate_keys(self):
        if not self.require_user():
            return
        try:
            key_id = generate_keys(self.current_user)
            messagebox.showinfo("Ключи созданы", f"Идентификатор ключей: {key_id}")
            self.set_status("Ключи успешно созданы")
            self.refresh_audit()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            self.set_status("Ошибка при генерации ключей")

    # -------------------------
    # Документы: регистрация + АВТОЗАПОЛНЕНИЕ ПО СХЕМЕ
    # -------------------------

    def register_document_dialog(self):
        if not self.require_user():
            return

        path = filedialog.askopenfilename(title="Выберите документ (файл извне)")
        if not path:
            return

        self.loaded_file_label.config(text=os.path.basename(path))

        dlg = tk.Toplevel(self.root)
        dlg.title("Форма регистрации документа")
        dlg.geometry("540x460")
        dlg.transient(self.root)
        dlg.grab_set()

        v_author = tk.StringVar(value=self.current_user)
        v_dep = tk.StringVar(value="Служба ИБ")
        v_type = tk.StringVar(value="Приказ")
        v_title = tk.StringVar(value=os.path.splitext(os.path.basename(path))[0])
        v_conf = tk.StringVar(value="КОНФ.")
        v_copies = tk.StringVar(value="2")
        v_pages = tk.StringVar(value="3")
        v_recipients = tk.StringVar(value="Петров П.П., Сидорова А.А., Иванов И.И.")

        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill="both", expand=True)

        def row(label, var, i, widget="entry"):
            ttk.Label(frm, text=label).grid(row=i, column=0, sticky="w", pady=4, padx=(0, 8))
            if widget == "combo":
                cb = ttk.Combobox(frm, textvariable=var, values=DOC_TYPES, state="readonly")
                cb.grid(row=i, column=1, sticky="we", pady=4)
            else:
                ttk.Entry(frm, textvariable=var).grid(row=i, column=1, sticky="we", pady=4)

        row("Автор:", v_author, 0)
        row("Отдел:", v_dep, 1)
        row("Тип документа:", v_type, 2, widget="combo")
        row("Заголовок:", v_title, 3)
        row("Гриф/отметка конф.:", v_conf, 4)
        row("Кол-во экземпляров:", v_copies, 5)
        row("Листов в экземпляре:", v_pages, 6)
        row("Получатели (через запятую):", v_recipients, 7)

        ttk.Label(frm, text=f"Файл: {os.path.basename(path)}", foreground="#555").grid(
            row=8, column=0, columnspan=2, sticky="w", pady=(10, 0)
        )
        frm.grid_columnconfigure(1, weight=1)

        def on_ok():
            try:
                doc_id = generate_doc_id()
                stored_name = f"{doc_id}_{os.path.basename(path)}"
                stored_path = os.path.join(DOCUMENTS_DIR, stored_name)
                shutil.copy2(path, stored_path)
                h = calc_file_hash(stored_path)

                order_reg_no = ""
                carrier_no = ""
                if v_type.get().strip() == "Приказ":
                    reg_seq = next_seq("order_reg_no")
                    order_reg_no = f"Р-{reg_seq:03d}"
                    car_seq = next_seq("carrier")
                    carrier_no = f"НКИ-{car_seq:04d}/{v_conf.get().strip()}"

                rec = DocumentRecord(
                    doc_id=doc_id,
                    doc_type=v_type.get().strip(),
                    title=v_title.get().strip(),
                    author=v_author.get().strip(),
                    department=v_dep.get().strip(),
                    confidentiality=v_conf.get().strip(),
                    created_at=now_iso(),
                    status="Зарегистрирован",
                    step_index=0,
                    file_name=os.path.basename(path),
                    stored_path=stored_path,
                    hash_value=h,
                    copies=v_copies.get().strip(),
                    pages_per_copy=v_pages.get().strip(),
                    recipients=v_recipients.get().strip(),
                    order_reg_no=order_reg_no,
                    carrier_no=carrier_no
                )

                self.docs.append(rec)
                self.save_all()

                log_event(self.current_user, "register_document", "ok", doc_id=doc_id, extra={
                    "stored_path": stored_path,
                    "hash": h,
                    "doc_type": rec.doc_type
                })

                # ВАЖНО: автозаполнение по схеме
                self.autofill_on_register(rec)

                dlg.destroy()
                self.refresh_docs_list()
                self.select_doc(doc_id)
                self.refresh_forms_all()
                self.refresh_audit()
                self.set_status(f"Документ зарегистрирован: {doc_id}")

            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

        btns = ttk.Frame(frm)
        btns.grid(row=9, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(btns, text="Зарегистрировать", command=on_ok).pack(side="right", padx=6)
        ttk.Button(btns, text="Отмена", command=dlg.destroy).pack(side="right")

    def autofill_on_register(self, rec: DocumentRecord):
        """
        ПО СХЕМЕ:
        - На старте: Форма 1 (1-7) — создаём запись носителя
        - + фиксируем документ в Ф2 (общий журнал)
        - + для приказа фиксируем в Ф3
        """
        # ---------- ФОРМА 1 (почему раньше не заполнялась):
        # раньше тут НЕ БЫЛО append_form_row(1, row1) — поэтому форма 1 пустая.
        row1 = {
            "__doc_id": rec.doc_id,
            "Учетный номер и отметка конфиденциальности носителя": rec.carrier_no or f"{rec.doc_id}/{rec.confidentiality}",
            "Дата регистрации": rec.created_at,
            "Вид носителя": "Электронный",
            "Тип носителя": "Внутреннее хранилище системы",
            "Наименование информации, наносимой на носитель": relpath_in_storage(rec.stored_path),
            "Отметка о переносе информации на другой носитель": "",
            "Отметка об отправлении носителя": f"Передан на согласование / {rec.created_at}",
            "Отметка о возврате носителя": "",
            "Отметка об уничтожении (стирании) информации": "",
            "Отметка об уничтожении носителя": "",
        }
        upsert_form_row(1, lambda r: r.get("__doc_id") == rec.doc_id, row1)

        # ---------- ФОРМА 2
        row2 = {
            "__doc_id": rec.doc_id,
            "Учетный номер и отметка конфиденциальности носителя": f"{rec.doc_id} / {rec.confidentiality}",
            "Дата документа": rec.created_at,
            "Вид и заголовок документа": f"{rec.doc_type}: {rec.title}",
            "Ф.И.О исполнителя": rec.author,
            "Номера носителя и листов черновика": rec.carrier_no or "",
            "Количество экземпляров документов": rec.copies,
            "Количество листов в экземпляре": rec.pages_per_copy,
            "Подпись за получение черновика и проекта документа": f"{rec.author} / {rec.created_at}",
            "Подпись за возврат, дата": "",
            "Отметка об уничтожении черновика": "",
            "Отметка об уничтожении проектов/лишних экземпляров документа": "",
            "Куда отправлен документ": "Юридический отдел; Финансовый отдел",
            "Номера экземпляров": "Экз.1; Экз.2",
            "Наименование, номер и дата сопроводительного документа": "",
            "Отметка о возврате": "",
            "Индекс (номер) дела, номера листов дела": "",
            "Номер по учету документов выделенного хранения, количество экземпляров": "",
        }
        upsert_form_row(2, lambda r: r.get("__doc_id") == rec.doc_id, row2)

        # ---------- ФОРМА 3 (только приказы)
        if rec.doc_type == "Приказ":
            row3 = {
                "__doc_id": rec.doc_id,
                "Порядковый регистрационный номер и отметка конфиденциальности": f"{rec.order_reg_no} / {rec.confidentiality}",
                "Дата": rec.created_at,
                "Учетный номер": rec.doc_id,
                "Заголовок": rec.title,
                "Количество экземпляров": rec.copies,
                "Количество листов в экземпляре": rec.pages_per_copy,
                "Отметка о местонахождении": "На согласовании",
                "Отметка о проверке наличия": ""
            }
            upsert_form_row(3, lambda r: r.get("__doc_id") == rec.doc_id, row3)

        log_event(self.current_user or "system", "autofill_register", "ok", doc_id=rec.doc_id)

    # -------------------------
    # Документы: список / выбор
    # -------------------------

    def refresh_docs_list(self):
        for i in self.docs_tree.get_children():
            self.docs_tree.delete(i)
        for d in self.docs:
            self.docs_tree.insert("", "end", values=(d.doc_id, d.doc_type, d.title, d.status))

    def select_doc(self, doc_id: str):
        self.current_doc_id = doc_id
        self.update_card()
        self.highlight_workflow()

    def on_select_doc(self, _evt=None):
        sel = self.docs_tree.selection()
        if not sel:
            return
        values = self.docs_tree.item(sel[0], "values")
        if not values:
            return
        self.select_doc(values[0])

    def update_card(self):
        d = self.get_doc()
        if not d:
            for v in self.card_vars.values():
                v.set("")
            return

        self.card_vars["doc_id"].set(d.doc_id)
        self.card_vars["doc_type"].set(d.doc_type)
        self.card_vars["title"].set(d.title)
        self.card_vars["author"].set(d.author)
        self.card_vars["department"].set(d.department)
        self.card_vars["conf"].set(d.confidentiality)
        self.card_vars["created_at"].set(d.created_at)
        self.card_vars["hash"].set(d.hash_value)
        self.card_vars["status"].set(d.status)

        step_text = ORDER_WORKFLOW_STEPS[d.step_index] if d.step_index < len(ORDER_WORKFLOW_STEPS) else "—"
        self.card_vars["step"].set(step_text)

        self.card_vars["order_reg_no"].set(d.order_reg_no or "—")
        self.card_vars["carrier_no"].set(d.carrier_no or "—")

    def highlight_workflow(self):
        d = self.get_doc()
        self.workflow_list.selection_clear(0, "end")
        if not d:
            return
        if 0 <= d.step_index < len(ORDER_WORKFLOW_STEPS):
            self.workflow_list.selection_set(d.step_index)
            self.workflow_list.see(d.step_index)

    def delete_selected_doc(self):
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        if messagebox.askyesno("Удаление", f"Удалить документ {d.doc_id}?"):
            self.docs = [x for x in self.docs if x.doc_id != d.doc_id]
            self.current_doc_id = None
            self.save_all()
            log_event(self.current_user or "system", "delete_document", "ok", doc_id=d.doc_id)
            self.refresh_docs_list()
            self.update_card()
            self.refresh_audit()
            self.set_status("Документ удалён из базы")

    def open_doc_file(self):
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        messagebox.showinfo("Путь", d.stored_path)

    # -------------------------
    # Формы учета: операции
    # -------------------------

    def refresh_form(self, form_no: int):
        view = self.form_views[form_no]
        tree = view["tree"]
        columns = view["columns"]

        for i in tree.get_children():
            tree.delete(i)

        rows = load_form_rows(form_no)
        for idx, row in enumerate(rows):
            values = [row.get(col, "") for col in columns]
            tree.insert("", "end", iid=str(idx), values=values)

    def refresh_forms_all(self):
        for form_no in self.form_views:
            self.refresh_form(form_no)

    def form_add_row(self, form_no: int):
        cols = self.form_views[form_no]["columns"]
        dlg = RowEditorDialog(self.root, f"Добавить строку — форма {form_no}", cols)
        if dlg.result is not None:
            append_form_row(form_no, dlg.result)
            self.refresh_form(form_no)

    def form_edit_row(self, form_no: int):
        view = self.form_views[form_no]
        tree = view["tree"]
        cols = view["columns"]

        sel = tree.selection()
        if not sel:
            messagebox.showwarning("Выбор", "Выберите строку.")
            return

        idx = int(sel[0])
        rows = load_form_rows(form_no)
        if idx < 0 or idx >= len(rows):
            return

        dlg = RowEditorDialog(self.root, f"Редактировать — форма {form_no}", cols, initial=rows[idx])
        if dlg.result is not None:
            # сохраняем мета-поля
            for k in list(rows[idx].keys()):
                if k.startswith("__") and k not in dlg.result:
                    dlg.result[k] = rows[idx][k]
            rows[idx] = dlg.result
            save_form_rows(form_no, rows)
            self.refresh_form(form_no)

    def form_delete_row(self, form_no: int):
        view = self.form_views[form_no]
        tree = view["tree"]
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("Выбор", "Выберите строку.")
            return
        idx = int(sel[0])
        rows = load_form_rows(form_no)
        if 0 <= idx < len(rows):
            rows.pop(idx)
            save_form_rows(form_no, rows)
            self.refresh_form(form_no)

    # -------------------------
    # Журнал действий
    # -------------------------

    def refresh_audit(self):
        for i in self.audit_tree.get_children():
            self.audit_tree.delete(i)

        data = load_audit_events(limit=2000)
        for e in data:
            self.audit_tree.insert(
                "",
                "end",
                values=(e.get("timestamp", ""), e.get("user", ""), e.get("action", ""),
                        e.get("result", ""), e.get("doc_id", ""))
            )

    # -------------------------
    # Целостность: кнопка
    # -------------------------

    def check_integrity_button(self):
        if not self.require_user():
            return
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        try:
            current_hash = calc_file_hash(d.stored_path)
            ok = (current_hash == d.hash_value)

            log_event(self.current_user, "integrity_check", "ok" if ok else "fail", doc_id=d.doc_id, extra={
                "expected": d.hash_value,
                "actual": current_hash
            })

            if ok:
                messagebox.showinfo("Целостность", "Целостность подтверждена: документ не изменён.")
                self.set_status("Целостность подтверждена")
            else:
                messagebox.showwarning("Целостность", "ВНИМАНИЕ: документ изменён (хэш не совпадает)!")
                self.set_status("Целостность нарушена")

            self.refresh_audit()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # -------------------------
    # Маршрут приказа (по схеме): шаги
    # -------------------------

    def run_next_step(self):
        if not self.require_user():
            return
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        if d.step_index >= len(ORDER_WORKFLOW_STEPS):
            messagebox.showinfo("Маршрут", "Все этапы уже пройдены.")
            return

        if not self.ensure_integrity_before_step(d):
            return

        self._execute_step(d, d.step_index)

        self.save_all()
        self.refresh_docs_list()
        self.update_card()
        self.highlight_workflow()
        self.refresh_forms_all()
        self.refresh_audit()

    def run_all_steps(self):
        if not self.require_user():
            return
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return

        while d.step_index < len(ORDER_WORKFLOW_STEPS):
            if not self.ensure_integrity_before_step(d):
                return
            self._execute_step(d, d.step_index)

        self.save_all()
        self.refresh_docs_list()
        self.update_card()
        self.highlight_workflow()
        self.refresh_forms_all()
        self.refresh_audit()
        self.set_status("Автопроход завершён")

    # ---------- обновления форм “по схеме” ----------
    def _update_form3_location(self, doc_id: str, location: str):
        update_form_rows(3,
                         lambda r: r.get("__doc_id") == doc_id,
                         lambda r: r.__setitem__("Отметка о местонахождении", location))

    def _update_form1_field(self, doc_id: str, field: str, value: str):
        update_form_rows(1,
                         lambda r: r.get("__doc_id") == doc_id,
                         lambda r: r.__setitem__(field, value))

    def _update_form2_fields(self, doc_id: str, patch: Dict[str, str]):
        def upd(r):
            for k, v in patch.items():
                r[k] = v
        update_form_rows(2, lambda r: r.get("__doc_id") == doc_id, upd)

    def _fill_form9_on_distribute(self, d: DocumentRecord, recipients_list: List[str]):
        pages = d.pages_per_copy or "?"
        for rcp in recipients_list:
            row9 = {
                "__doc_id": d.doc_id,
                "__recipient": rcp,
                "Номер документа": d.doc_id,
                "Количество листов": pages,
                "Подпись за получение и дата": f"{rcp} / {now_iso()}",
                "Подпись за возврат и дата": ""
            }
            append_form_row(9, row9)

    def _fill_form9_return(self, doc_id: str):
        # Заполняем колонку 4 (по схеме: 9 4) если пусто
        def upd(r):
            if not r.get("Подпись за возврат и дата"):
                rec = r.get("__recipient", "")
                r["Подпись за возврат и дата"] = f"{rec} / {now_iso()}" if rec else now_iso()
        update_form_rows(9, lambda r: r.get("__doc_id") == doc_id, upd)

    def _execute_step(self, d: DocumentRecord, step_idx: int):
        step_name = ORDER_WORKFLOW_STEPS[step_idx]
        try:
            # 0) Согласование: юр
            if step_idx == 0:
                d.status = "Согласование: юридическая проверка (OK)"
                log_event(self.current_user, "order_legal_check", "ok", doc_id=d.doc_id)
                self._update_form3_location(d.doc_id, "Юридическая проверка")
                self._update_form1_field(d.doc_id, "Отметка об отправлении носителя", f"Юр.проверка / {now_iso()}")

            # 1) Согласование: фин
            elif step_idx == 1:
                d.status = "Согласование: финансовая проверка (OK)"
                log_event(self.current_user, "order_fin_check", "ok", doc_id=d.doc_id)
                self._update_form3_location(d.doc_id, "Финансовая проверка")
                self._update_form1_field(d.doc_id, "Отметка об отправлении носителя", f"Фин.проверка / {now_iso()}")

            # 2) Утверждение: подпись (и по схеме: Ф1 колонка 8 можно заполнить как 'возврат после согласования')
            elif step_idx == 2:
                signer = simpledialog.askstring("Подписание", "Кто подписывает (директор)?", initialvalue=self.current_user)
                if not signer:
                    raise ValueError("Подписание отменено")

                sig_path = sign_document(signer.strip(), d.stored_path, doc_id=d.doc_id)
                d.sig_path = sig_path

                d.status = f"Утвержден: подписан ({signer.strip()})"
                log_event(self.current_user, "order_director_sign", "ok", doc_id=d.doc_id, extra={"sig_path": sig_path})

                self._update_form3_location(d.doc_id, "Подписан директором")
                # “Ф1: возврат” (как в схеме: 1 8)
                self._update_form1_field(d.doc_id, "Отметка о возврате носителя", f"После согласования / {now_iso()}")

                # “Ф2: 1-7” — у нас уже есть, но можно уточнить
                self._update_form2_fields(d.doc_id, {
                    "Подпись за возврат, дата": f"{d.author} / {now_iso()}",
                })

            # 3) Утверждение: шифрование (и отметка о переносе на другой носитель)
            elif step_idx == 3:
                enc_path = encrypt_file(self.current_user, d.stored_path, doc_id=d.doc_id)
                d.enc_path = enc_path

                d.status = "Утвержден: зашифрован"
                log_event(self.current_user, "order_encrypt", "ok", doc_id=d.doc_id, extra={"enc_path": enc_path})

                self._update_form3_location(d.doc_id, "Зашифрован (готов к рассылке)")
                self._update_form1_field(
                    d.doc_id,
                    "Отметка о переносе информации на другой носитель",
                    f"Создан шифропакет: {relpath_in_storage(enc_path)} / {now_iso()}"
                )

            # 4) Исполнение: доведение (по схеме: Ф9 1-3)
            elif step_idx == 4:
                recipients = (d.recipients or "").strip()
                if not recipients:
                    recipients = simpledialog.askstring("Получатели", "Введите получателей (через запятую):", initialvalue="")
                    recipients = (recipients or "").strip()
                    d.recipients = recipients

                rec_list = [x.strip() for x in recipients.split(",") if x.strip()]
                if not rec_list:
                    rec_list = ["(не указан)"]

                # Ф9: создаём строки (1-3)
                self._fill_form9_on_distribute(d, rec_list)

                d.status = f"Исполнение: доведен до {len(rec_list)} получ."
                log_event(self.current_user, "order_distribute", "ok", doc_id=d.doc_id, extra={"recipients": rec_list})

                self._update_form3_location(d.doc_id, "Разослан исполнителям")
                self._update_form1_field(d.doc_id, "Отметка об отправлении носителя",
                                         f"Передача исполнителям: {', '.join(rec_list)} / {now_iso()}")

                self._update_form2_fields(d.doc_id, {
                    "Куда отправлен документ": ", ".join(rec_list),
                })

            # 5) Исполнение: проверка подписи
            elif step_idx == 5:
                sig_id = self._resolve_signature_id(d)
                if not sig_id:
                    raise ValueError(
                        "Подпись для документа отсутствует. Сначала выполните этап подписания."
                    )

                sig_payload = safe_load_data(sig_id, None)
                if sig_payload is None:
                    raise ValueError(
                        "Сохранённая подпись не найдена в базе данных. Повторите подписание документа."
                    )

                ok = verify_signature(d.stored_path, sig_id)
                d.status = "Исполнение: подпись проверена (OK)" if ok else "Исполнение: подпись НЕ прошла"
                log_event(self.current_user, "order_verify_signature", "ok" if ok else "fail",
                          doc_id=d.doc_id, extra={"sig_path": sig_id})

                self._update_form3_location(d.doc_id, "Подпись проверена" if ok else "Проблема подписи")

            # 6) В дело: архивирование
            elif step_idx == 6:
                arch_name = f"{d.doc_id}_{os.path.basename(d.stored_path)}"
                arch_path = os.path.join(ARCHIVE_DIR, arch_name)
                shutil.copy2(d.stored_path, arch_path)
                d.archived_path = arch_path

                d.status = "В деле (архив)"
                log_event(self.current_user, "order_archive", "ok", doc_id=d.doc_id, extra={"archived_path": arch_path})

                self._update_form3_location(d.doc_id, f"Архив: {relpath_in_storage(arch_path)}")

                # Ф9: заполнить возврат (по схеме: 9 4)
                self._fill_form9_return(d.doc_id)

                # Ф2: колонка 16 “в дело”
                self._update_form2_fields(d.doc_id, {
                    "Индекс (номер) дела, номера листов дела": f"Дело {datetime.now().year}-ПР, л. 1–{d.pages_per_copy}",
                    "Отметка о возврате": f"Возврат/архив / {now_iso()}",
                })

                # Ф1: возврат носителя (логично при “в дело”)
                self._update_form1_field(d.doc_id, "Отметка о возврате носителя", f"Архивирование / {now_iso()}")

            # 7) ПДЭК: протокол
            elif step_idx == 7:
                proto_name = f"PDEK_PROTOCOL_{d.doc_id}.txt"
                proto_path = os.path.join(ARCHIVE_DIR, proto_name)
                text = (
                    "Протокол заседания ПДЭК\n"
                    f"Документ: {d.doc_id}\n"
                    f"Приказ: {d.title}\n"
                    f"Дата: {now_iso()}\n"
                    f"Решение: хранить до рассекречивания\n"
                )
                with open(proto_path, "w", encoding="utf-8") as f:
                    f.write(text)
                d.pdek_protocol_path = proto_path

                d.status = "ПДЭК: протокол сформирован"
                log_event(self.current_user, "pdek_protocol", "ok", doc_id=d.doc_id, extra={"protocol_path": proto_path})

                # Можно зафиксировать в Ф4 (как протокол)
                row4 = {
                    "__doc_id": d.doc_id,
                    "Порядковый регистрационный номер и отметка конфиденциальности": f"ПДЭК-{next_seq('pdek'):03d} / {d.confidentiality}",
                    "Дата": now_iso(),
                    "Учетный номер": d.doc_id,
                    "Заголовок": f"Протокол ПДЭК по приказу: {d.title}",
                    "Количество экземпляров": "1",
                    "Количество листов в экземпляре": "1",
                    "Отметка о местонахождении": relpath_in_storage(proto_path),
                    "Отметка о проверке наличия": ""
                }
                append_form_row(4, row4)

            # 8) “Через 1 год” — шаг-метка
            elif step_idx == 8:
                d.status = "Ожидание рассекречивания (через 1 год) — метка"
                log_event(self.current_user, "declass_wait_mark", "ok", doc_id=d.doc_id)

            # 9) Рассекретить: акт передачи
            elif step_idx == 9:
                act_name = f"ACT_DECLASS_{d.doc_id}.txt"
                act_path = os.path.join(ARCHIVE_DIR, act_name)
                content = (
                    "Акт передачи в открытое делопроизводство\n"
                    f"Документ: {d.doc_id}\n"
                    f"Тип: {d.doc_type}\n"
                    f"Заголовок: {d.title}\n"
                    f"Дата: {now_iso()}\n"
                    f"Ответственный: {self.current_user}\n"
                    f"Основание: решение ПДЭК\n"
                )
                with open(act_path, "w", encoding="utf-8") as f:
                    f.write(content)

                d.declass_act_path = act_path
                d.status = "Рассекречен (акт сформирован)"
                log_event(self.current_user, "order_declassify_act", "ok", doc_id=d.doc_id, extra={"act_path": act_path})

                self._update_form3_location(d.doc_id, "Открытое делопроизводство")
                # По схеме: “1 7” — отметка об отправлении носителя (передача в открытое делопроизводство)
                self._update_form1_field(d.doc_id, "Отметка об отправлении носителя",
                                         f"Передан в открытое делопроизводство (акт {os.path.basename(act_path)}) / {now_iso()}")
                # Логично: отметить стирание/уничтожение как пустое или по факту
                self._update_form1_field(d.doc_id, "Отметка об уничтожении (стирании) информации", "")

            d.step_index += 1
            self.set_status(f"Этап выполнен: {step_name}")

        except Exception as e:
            log_event(self.current_user, "order_step_error", "fail", doc_id=d.doc_id, extra={"step": step_name, "error": str(e)})
            messagebox.showerror("Ошибка этапа", f"{step_name}\n\n{e}")
            self.set_status("Ошибка на этапе маршрута")

    # -------------------------
    # Ручные крипто-операции
    # -------------------------

    def sign_now(self):
        if not self.require_user():
            return
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        if not self.ensure_integrity_before_step(d):
            return
        try:
            sig_path = sign_document(self.current_user, d.stored_path, doc_id=d.doc_id)
            d.sig_path = sig_path
            d.status = "Подписан (вручную)"
            self.save_all()
            log_event(self.current_user, "sign_manual", "ok", doc_id=d.doc_id, extra={"sig_path": sig_path})
            messagebox.showinfo("Подпись", f"Файл подписи:\n{sig_path}")
            self.refresh_docs_list()
            self.update_card()
            self.refresh_audit()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def verify_now(self):
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        try:
            sig_id = self._resolve_signature_id(d)
            if not sig_id:
                messagebox.showwarning(
                    "Подпись не найдена",
                    "Подписание документа не зафиксировано в базе. Подпишите его, после чего проверка выполнится автоматически.",
                )
                return

            ok = verify_signature(d.stored_path, sig_id)
            log_event(self.current_user or "system", "verify_manual", "ok" if ok else "fail",
                      doc_id=d.doc_id, extra={"sig_path": sig_id})
            messagebox.showinfo("Проверка подписи", "Подпись действительна." if ok else "Подпись недействительна / документ изменён.")
            self.refresh_audit()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def encrypt_now(self):
        if not self.require_user():
            return
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        if not self.ensure_integrity_before_step(d):
            return
        try:
            enc_path = encrypt_file(self.current_user, d.stored_path, doc_id=d.doc_id)
            d.enc_path = enc_path
            d.status = "Зашифрован (вручную)"
            self.save_all()
            log_event(self.current_user, "encrypt_manual", "ok", doc_id=d.doc_id, extra={"enc_path": enc_path})
            messagebox.showinfo("Шифрование", f"Зашифрованный файл:\n{enc_path}")
            self.refresh_docs_list()
            self.update_card()
            self.refresh_audit()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def decrypt_now(self):
        if not self.require_user():
            return
        d = self.get_doc()
        if not d:
            messagebox.showwarning("Нет документа", "Выберите документ.")
            return
        if not d.enc_path:
            messagebox.showwarning(
                "Нет шифропакета",
                "Для расшифровки нужно сначала зашифровать документ (этап маршрута или кнопка \"Зашифровать\").",
            )
            return
        try:
            out_path = decrypt_file(self.current_user, d.enc_path, doc_id=d.doc_id)
            log_event(self.current_user, "decrypt_manual", "ok", doc_id=d.doc_id, extra={"dec_path": out_path})
            messagebox.showinfo("Расшифровка", f"Файл сохранён:\n{out_path}")
            self.refresh_audit()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))


def main():
    root = tk.Tk()
    app = ZEDKDGApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
