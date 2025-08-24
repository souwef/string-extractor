import os
import datetime
import pefile
import tkinter as tk
from tkinter import filedialog, ttk


def extract_strings(pe_file: str) -> str:
    file_name = os.path.splitext(os.path.basename(pe_file))[0]
    txt_name = f"{file_name}-strings.txt"

    with open(txt_name, "w") as file:
        # file name & size
        file.write(f"File Name: {os.path.basename(pe_file)}\n")
        file.write(f"File Size: {os.path.getsize(pe_file)} bytes\n")

        pe = pefile.PE(pe_file)

        # pcasvc string
        pcasvc_string = hex(pe.OPTIONAL_HEADER.SizeOfImage)
        file.write(f"PcaSvc: {pcasvc_string}\n")

        # dps string
        timestamp = pe.FILE_HEADER.TimeDateStamp
        timestamp_dt = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
        timestamp_str = timestamp_dt.strftime("%Y/%m/%d:%H:%M:%S")
        file.write(f"DPS: !{timestamp_str}\n")

    return txt_name


class StringExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("String Extractor")

        width, height = 400, 200
        x_offset = (root.winfo_screenwidth() - width) // 2
        y_offset = (root.winfo_screenheight() - height) // 2
        root.geometry(f"{width}x{height}+{x_offset}+{y_offset}")
        root.minsize(width, height)
        root.maxsize(width, height)

        self.pe_file = None
        self.create_widgets()

    def create_widgets(self):
        file_frame = ttk.Frame(self.root)
        file_frame.pack(pady=10)

        self.file_label = ttk.Label(file_frame, text="No file selected")
        self.file_label.pack(side="left", padx=10)

        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side="left")

        extract_btn = ttk.Button(self.root, text="Extract Strings", command=self.run_extraction)
        extract_btn.pack(pady=10)

        self.result_label = ttk.Label(self.root, text="")
        self.result_label.pack()

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
        if file_path:
            self.pe_file = file_path
            self.file_label.config(text=f"Selected File: {os.path.basename(file_path)}")

    def run_extraction(self):
        if not self.pe_file:
            self.result_label.config(text="No file selected!", foreground="red")
            return

        try:
            output_file = extract_strings(self.pe_file)
            self.result_label.config(text=f"Strings saved to {output_file}", foreground="green")
        except Exception as e:
            self.result_label.config(text=f"Error: {e}", foreground="red")


if __name__ == "__main__":
    root = tk.Tk()
    app = StringExtractorApp(root)
    root.mainloop()
