# 📖 Setup Guide

## 1. Install Python
1. Go to the official Python website:
   https://www.python.org/downloads/
2. Download the **latest stable release** (Python 3.12+ is recommended).
3. Run the installer:
   - Check **“Add Python to PATH”** during installation.
   - Choose **Install Now**.

---

## 2. Verify Python is Installed
Open a terminal (Command Prompt or PowerShell on Windows) and type:

    python --version

You should see something like:

    Python 3.12.4

---

## 3. Install Required Library
This script only needs **pefile**.  
Install it by running:

    pip install pefile

---

## 4. Run the Script
1. Save your Python script as `extract.py`.
2. Open a terminal in the same folder as `extract.py`.
3. Run:

    python extract.py

The GUI window should open.

- Click **Browse** → select a `.exe` file.
- Click **Extract Strings** → output text file will be created in the same folder.

---

Done!
