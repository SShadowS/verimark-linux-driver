#!/usr/bin/env python3
"""
p3_gui.py — dead-simple live status window for fingerprint capture.

Polls prototype/images/status.json (written by p3_hostmatch.py running as root) and shows a
big color-coded state + the latest captured image. Run as the desktop user:

    DISPLAY=:0 python3 prototype/p3_gui.py

Colors: grey=idle/starting, AMBER=tap now, BLUE=reading, GREEN=captured, dark=done, red=error.
"""
import os, json, tkinter as tk

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS = os.path.join(HERE, "images", "status.json")

COLORS = {
    "STARTING": ("#444", "#ddd"), "WAITING": ("#b8860b", "#fff"),
    "READING": ("#1f4e79", "#fff"), "CAPTURED": ("#1e7d32", "#fff"),
    "DONE": ("#0b3d0b", "#cfc"), "ERROR": ("#7d1e1e", "#fff"),
    "IDLE": ("#333", "#aaa"),
}


class App:
    def __init__(self, root):
        self.root = root
        root.title("VeriMark capture")
        root.geometry("560x520+120+120")
        root.configure(bg="#333")
        self.state = tk.Label(root, text="waiting for capture…", font=("Sans", 30, "bold"),
                              bg="#333", fg="#aaa", wraplength=520, justify="center")
        self.state.pack(fill="x", pady=(24, 8))
        self.detail = tk.Label(root, text="", font=("Sans", 15), bg="#333", fg="#ccc",
                               wraplength=520, justify="center")
        self.detail.pack(fill="x")
        self.count = tk.Label(root, text="", font=("Sans", 40, "bold"), bg="#333", fg="#fff")
        self.count.pack(pady=6)
        self.imgpanel = tk.Label(root, bg="#222")
        self.imgpanel.pack(expand=True, fill="both", padx=16, pady=16)
        self._photo = None
        self._last_png = None
        self._last_mtime = 0
        self.poll()

    def poll(self):
        try:
            st = json.load(open(STATUS))
        except Exception:
            st = {"state": "IDLE", "detail": "no status yet — start the capture", "count": 0, "target": 0}
        s = st.get("state", "IDLE")
        bg, fg = COLORS.get(s, ("#333", "#aaa"))
        self.root.configure(bg=bg)
        for w in (self.state, self.detail, self.count):
            w.configure(bg=bg)
        self.state.configure(text=s.replace("_", " "), fg=fg)
        self.detail.configure(text=st.get("detail", ""), fg=fg)
        tgt = st.get("target", 0)
        self.count.configure(text=("%d / %d" % (st.get("count", 0), tgt)) if tgt else "", fg=fg)
        png = st.get("last_png")
        if png and os.path.exists(png):
            try:
                m = os.path.getmtime(png)
                if png != self._last_png or m != self._last_mtime:
                    ph = tk.PhotoImage(file=png)
                    z = max(1, min(360 // max(ph.width(), 1), 360 // max(ph.height(), 1)))
                    ph = ph.zoom(z)
                    self._photo = ph
                    self.imgpanel.configure(image=ph)
                    self._last_png, self._last_mtime = png, m
            except Exception:
                pass
        self.root.after(120, self.poll)


if __name__ == "__main__":
    r = tk.Tk()
    App(r)
    r.mainloop()
