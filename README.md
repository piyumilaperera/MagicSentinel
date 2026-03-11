<div align="center">

# MagicSentinel


**File Signature & Magic Number Detector, A sentinel born by my passion for system security and the truth behind every file.**

![C](https://img.shields.io/badge/Language-C-blue?style=flat-square&logo=c)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-informational?style=flat-square)
![Security](https://img.shields.io/badge/Category-System%20Security-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0.0-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

*Detects file type spoofing by reading and validating magic numbers against declared file extensions.*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Compilation](#-compilation)
- [Usage](#-usage)
- [Issues & Limitations](#-issues--limitations)
- [Final Word & Future Expectations](#-final-word--future-expectations)

---

## 🔍 Overview

**MagicSentinel** is a cross platform, lightweight command line tool written in C that performs binary level file inspection, also it is a outcome of my learning journey. It opens a file in binary format, reads its **magic number** (the first few bytes that identify the true file type), and compares it against the file's declared extension, flagging any mismatch as a potential **spoofing attempt**.

### What is a Magic Number?

Every file format has a unique byte signature at its beginning, known as a **magic number** or **file signature**. For example:

| File Type | Magic Bytes (Hex)     | ASCII      |
|-----------|----------------------|------------|
| JPEG      | `FF D8 FF`           | `ÿØÿ`      |
| PNG       | `89 50 4E 47`        | `‰PNG`     |
| PDF       | `25 50 44 46`        | `%PDF`     |
| ZIP       | `50 4B 03 04`        | `PK..`     |
| ELF       | `7F 45 4C 46`        | `.ELF`     |
| EXE (PE)  | `4D 5A`              | `MZ`       |

When an attacker renames a malicious file (e.g., `malware.exe` → `document.pdf`), the extension changes but the magic bytes do not. MagicSentinel catches this discrepancy.

Note that some advanced attackers also spoof the magic number itself, which is beyond the scope of this tool.
### Why It Matters

- Prevents execution of disguised malicious files
- Helps identify corrupted or mislabeled files
- Educational tool for understanding binary file structure

---

## ⚙️ Compilation

### Prerequisites

- GCC compiler (`gcc`)
- A terminal (Linux/macOS) or cmd (Windows)

### Linux / macOS

```bash
gcc magic_number.c -o magic_sentinel
```

### Windows (cmd)

```bash
gcc magic_number.c -o magic_sentinel.exe
```

> **Note:** On Windows, the program automatically enables ANSI color support and UTF-8 output via the Windows Console API. No additional flags are needed.


<p align="center">
  <img src="https://github.com/piyumilaperera/MagicSentinel/blob/main/media/1.Compiling.png"></p>


---

## 🚀 Usage

Run the compiled binary from your terminal:

```bash
./magic_sentinel
```

You will be greeted by the MagicSentinel banner and a prompt. From there:

### Commands

| Input            | Action                                          |
|------------------|-------------------------------------------------|
| `/path/to/file`  | Analyze the file's magic number vs extension    |
| `{list}`         | List all files in the current directory         |
| `{exit}`         | Exit the program                                |

### Examples


<p align="center">
  <img src="https://github.com/piyumilaperera/MagicSentinel/blob/main/media/2.First_look.png"></p>

<div align="center">

The list command give informations about the files on the same path
</div>

<p align="center">
  <img src="https://github.com/piyumilaperera/MagicSentinel/blob/main/media/3.list.png"></p>

<div align="center">

It successfully detected the file type
</div>

<p align="center">
  <img src="https://github.com/piyumilaperera/MagicSentinel/blob/main/media/4.Success.png"></p>

<div align="center">

It successfully detected the spoofed one, and it gave a alert.
</div>

<p align="center">
  <img src="https://github.com/piyumilaperera/MagicSentinel/blob/main/media/7.detected_a_spoofed_file.png"></p>

<div align="center">

---

## ⚠️ Issues & Limitations

### Known Limitations

**1. Plain text files are not supported**
Files such as `.c`, `.py`, `.sh`, `.txt`, `.html`, `.js` and other source code or script files do not have magic numbers. They begin with plain ASCII/UTF-8 text, so MagicSentinel cannot determine their type through binary inspection alone. This is the biggest limitation of this tool.

**2. Limited signature database**
The current version supports a finite list of known magic numbers (701 file types). Obscure or uncommon file formats may not be recognized and will be reported as `UNKNOWN`.

**3. No deep inspection**
MagicSentinel only reads the first 65 bytes of the file. Some complex formats (e.g., certain container formats) may require deeper parsing to identify correctly. But the first 65 bytes are good enough for 99% cases. Also reading deeper consumes more resouses and slow down the system, so i think 65 bytes are the sweet spot.

**4. False positives possible**
In rare cases, a file's first bytes may coincidentally match a known magic number pattern without actually being that file type. This is common within plain text files, keep that in mind

**5. Encrypted or packed files**
Files encrypted or packed with tools like UPX may have their magic bytes overwritten, making detection unreliable.

6. I tested this on windows and debian linux, but not on mac. Because i dont have one, but i am pretty sure that it should be run on mac without any issuse. But dont 100% sure.

<div align="center">

In here it gives a false positive on a ASCII file
</div>

<p align="center">
  <img src="https://github.com/piyumilaperera/MagicSentinel/blob/main/media/5.False_positive.png"></p>

### Platform Notes

| Platform       | Status     | Notes                                              |
|----------------|------------|----------------------------------------------------|
| Linux          | ✅ Full     | Native ANSI + Unicode support                      |
| macOS          | ✅ Full     | Native ANSI + Unicode support                      |
| Windows 10+    | ✅ Full     | ANSI enabled via Windows Console API at runtime    |
| Windows 7/8    | ⚠️ Partial  | Colors may not render; Unicode may show as garbage |
| Windows CMD    | ⚠️ Partial  | Limited Unicode rendering                          |

---

## 💬 Final Word & Future Expectations

### Final Word

MagicSentinel was developed as part of my learning journey on cybersecurity. This is a project to demonstrate how file extension spoofing works at the binary level, and how it can be detected with a simple but effective approach. The tool is intentionally kept minimal and dependency free, written entirely in standard C to maximize portability and transparency.

Building this tool also gave me a solid understanding of how files work at the binary level. This project reinforces a simple but important security truth: **never trust a file extension alone.** 

Trusting this tool alone will not fully protect you. Advanced attackers can also spoof the magic number itself, and at that level, this tool becomes ineffective. But that is exactly what cybersecurity teaches us, it is never enough. It is an endless battle between attackers and security experts, where the defenses of today become the challenges of tomorrow.



### Future Expectations

The following features are planned or considered for future versions:

- [ ] **Expanded signature database** - add support for new file formats
- [ ] **Recursive directory scanning** - scan entire folders, not just single files
- [ ] **JSON / CSV report export** - output scan results to a structured file
- [ ] **Scan files on a entire system and give a full report** - this is the final goal

---

<div align="center">

Developed by **Piyumila Perera** &nbsp;|&nbsp; System Security Analysis &nbsp;|&nbsp; v1.0.0

*If you find this tool useful, consider giving it a ⭐ on GitHub!*

</div>
