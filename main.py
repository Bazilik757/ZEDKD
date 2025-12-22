import tkinter as tk

from zedkd.ui.app import ZEDKDGApp


def main():
    root = tk.Tk()
    ZEDKDGApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
