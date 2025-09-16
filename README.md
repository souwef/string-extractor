# String Extractor Tool

## Features

- **PE File Analysis**: Extract metadata from executable files
- **User-Friendly GUI**: Simple interface for file selection and processing
- **Output Generation**: Creates text files with extracted information

## Requirements

### For Running from Source
- Python 3.8 or higher
- Required Python packages:
  - `pefile`
  - `tkinter` (usually included with Python)

### For Standalone Executable
- No requirements - the executable is self-contained

## Installation & Usage

### Option 1: Running from Source

1. **Install Python**:
   - Go to https://www.python.org/downloads/
   - Download Python 3.8+ and install with "Add Python to PATH" checked

2. **Verify Installation**:
   ```powershell
   python --version
   ```

3. **Install Required Library**:
   ```powershell
   pip install pefile
   ```

4. **Run the Application**:
   ```powershell
   python extract.py
   ```

### Option 2: Use Standalone Executable

1. **Download or build** `extract.exe` from the `dist` folder
2. **Double-click** `extract.exe` to run
3. **No installation required** - completely portable

## How to Use the Tool

1. **Launch the application** (either `python extract.py` or `extract.exe`)
2. **Click "Browse"** to select a `.exe` file
3. **Click "Extract Strings"** to process the file
4. **Output file** will be created in the same directory with format: `filename-strings.txt`

### Output File Contents

The generated text file includes:
- **File Name**: Original filename
- **File Size**: Size in bytes  
- **SHA1**: SHA1 Hash of the file
- **PcaSvc String**: Size of image in hex format
- **DPS String**: Timestamp in `YYYY/MM/DD:HH:MM:SS` format

## Building to Standalone Executable

### Prerequisites

1. **Install PyInstaller**:
   ```powershell
   pip install pyinstaller
   ```

### Build Commands

1. **Navigate to project directory**:
   ```powershell
   cd "path\to\string extractor"
   ```

2. **Build executable**:
   ```powershell
   pyinstaller --onefile --windowed extract.py
   ```

3. **Find your executable**:
   - Built executable: `dist\extract.exe`
   - Completely standalone - no dependencies needed
