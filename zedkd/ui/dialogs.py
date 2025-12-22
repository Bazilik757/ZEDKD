import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List


class RowEditorDialog(tk.Toplevel):
    def __init__(self, parent, title: str, columns: List[str], initial: Dict[str, Any] | None = None):
        super().__init__(parent)
        self.title(title)
        self.resizable(True, True)
        self.result: Dict[str, Any] | None = None
        self.columns = columns
        self.initial = initial or {}

        self.geometry("760x520")

        container = ttk.Frame(self, padding=10)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container)
        scroll_y = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        frame = ttk.Frame(canvas)

        frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll_y.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

        self.vars: Dict[str, tk.StringVar] = {}
        for idx, column in enumerate(columns):
            ttk.Label(frame, text=column).grid(row=idx, column=0, sticky="w", padx=5, pady=4)
            var = tk.StringVar(value=self.initial.get(column, ""))
            self.vars[column] = var
            entry = ttk.Entry(frame, textvariable=var, width=60)
            entry.grid(row=idx, column=1, sticky="we", padx=5, pady=4)

        frame.grid_columnconfigure(1, weight=1)

        btns = ttk.Frame(self, padding=10)
        btns.pack(fill="x")

        ttk.Button(btns, text="ОК", command=self.on_ok).pack(side="right", padx=6)
        ttk.Button(btns, text="Отмена", command=self.on_cancel).pack(side="right")

    def on_ok(self):
        self.result = {c: v.get().strip() for c, v in self.vars.items()}
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()
