import ttkbootstrap as tb

from zedkd.ui.app import ZEDKDGApp


def main():
    root = tb.Window(themename="superhero")
    ZEDKDGApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
