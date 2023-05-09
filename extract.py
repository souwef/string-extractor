import pefile
import os
import hashlib
import datetime
import tkinter as tk
from tkinter import filedialog
from tkinter import ttk

def extract_strings():
    file_name = os.path.splitext(os.path.basename(pe_file))[0]
    txt_name = file_name + "-strings.txt"
    with open(txt_name, "w") as file:
        file_name2 = os.path.basename(pe_file)
        file.write("File Name: " + file_name2 + "\n")
        file_size = os.path.getsize(pe_file)
        file.write("File Size: " + str(file_size) + " bytes\n")
        pe = pefile.PE(pe_file)

        # md5 string

        md5_hash = hashlib.md5(pe.__data__).hexdigest()
        file.write("MD5: " + md5_hash + "\n")

        # pcasvc string

        pcasvc_string = (hex(pe.OPTIONAL_HEADER.SizeOfImage))
        file.write("PcaSvc: " + pcasvc_string + "\n")

        # dps string

        timestamp = pe.FILE_HEADER.TimeDateStamp
        timestamp_dt = datetime.datetime.utcfromtimestamp(timestamp)
        timestamp_str = timestamp_dt.strftime("%Y/%m/%d:%H:%M:%S")
        DPS_string = "!" + timestamp_str
        file.write("DPS: " + DPS_string + "\n")

def browse_file():
    global pe_file
    pe_file = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
    if pe_file:
        file_label.config(text=f"Selected File: {os.path.basename(pe_file)}")


def extract_button():
    if not pe_file:
        return
    extract_strings()
    result_label.config(text="Strings extracted successfully!", foreground="green")

# window setup
root = tk.Tk()
width = 400
height = 200
x_offset = (root.winfo_screenwidth() - width) // 2
y_offset = (root.winfo_screenheight() - height) // 2
root.geometry(f"{width}x{height}+{x_offset}+{y_offset}")

# lock the window size
root.minsize(width, height)
root.maxsize(width, height)

root.title("String Extractor")

# create elements

file_frame = ttk.Frame(root)
file_frame.pack(pady=10)
file_label = ttk.Label(file_frame, text="No file selected")
file_label.pack(side="left", padx=10)
browse_button = ttk.Button(file_frame, text="Browse", command=browse_file)
browse_button.pack(side="left")

extract_button = ttk.Button(root, text="Extract Strings", command=extract_button)
extract_button.pack(pady=10)

result_label = ttk.Label(root, text="")
result_label.pack()

# main loop
root.mainloop()