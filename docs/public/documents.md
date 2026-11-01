# Documents and images

The files people are sent are the files scanners skip: a spreadsheet with macros, a PDF that runs JavaScript when it opens, a Word file whose template lives on someone else's server, a picture that is really a program. wpantry reads PDFs, Office documents (old and new), RTF and images in the repos it scans and, on a machine scan, the top of `~/Downloads` and `~/Desktop`, for the shapes document malware takes. Nothing is opened, rendered, executed or fetched: every parser is bounded (32 MiB a file, 16 MiB an inflated part) and says "can't be read" rather than guess. When ClamAV is installed, it runs over the same files.

**A clean result is not a clean file.** These checks find the shapes; ClamAV finds what it has signatures for. A document from someone you don't know still goes in a sandbox or a viewer with scripting off.

| Id | What | Fails | Warns |
|---|---|---|---|
| `DISGUISED-PROGRAM` | A file named like a document or image whose first bytes are a Windows, ELF or Mach-O executable, or a shebang script | always | — |
| `DOC-POLYGLOT` | A `.pdf` with no `%PDF-` header in its first KiB (HTML, a zip or something else wearing the name) | always | — |
| `DOC-LAUNCH` | A PDF `/Launch` action: the viewer is asked to start a program | always | — |
| `DOC-JS-ON-OPEN` | PDF JavaScript (`/JS`, `/JavaScript`) with an `/OpenAction` or `/AA`: it runs when the file opens | always | — |
| `DOC-JAVASCRIPT` | PDF JavaScript with no open action | — | always (forms use it; so do exploits) |
| `DOC-OBFUSCATED` | PDF action names written with `#xx` hex escapes (`/J#61vaScript`); an RTF with a malformed header (`{\rt` but not `{\rtf1`) or binary spliced into its object stream (`\bin`) | always | — |
| `DOC-EMBEDDED` | PDF embedded files | — | always |
| `DOC-FORM` | PDF XFA forms, rich media, submit, remote-goto or import actions | — | always |
| `DOC-TRAILER` | More than 1 KiB after the PDF's last `%%EOF` | — | always |
| `DOC-MACRO` | VBA macros (`vbaProject.bin`, or `VBA`/`Macros`/`_VBA_PROJECT` storages in a legacy file) | in a format meant to carry none (`.docx`, `.xlsx`, `.pptx`, or a legacy file named as one), or a content type that says macro-enabled under a plain extension | in a macro-enabled format (`.docm`, `.xlsm`, `.pptm`, `.doc`, `.xls`, `.ppt`) |
| `DOC-XL4-MACRO` | Excel 4.0 macro sheets (`xl/macrosheets/`) | always | — |
| `DOC-REMOTE-TEMPLATE` | An attached template or glossary fetched from a URL or UNC path when the document opens (the relationship's `TargetMode="External"`) | always | — |
| `DOC-REMOTE-OBJECT` | An embedded OLE object, package, frame or subdocument fetched from elsewhere when the document opens (the CVE-2017-0199 shape) | always | — |
| `DOC-REMOTE-CONTENT` | Other external content loaded on open (not hyperlinks) | — | always |
| `DOC-DDE` | A DDE field (`DDEAUTO`, `ddeLink`): Office is asked to run another program's command | always | — |
| `DOC-OLE-OBJECT` | Embedded OLE objects (`oleObject*.bin`, `Ole10Native`): another file or program packaged inside | — | always |
| `DOC-ACTIVEX` | ActiveX controls | — | always |
| `DOC-RTF-OBJECT` | An RTF embedded object (`\objdata`, `\objemb`), one set to update itself on open (`\objupdate`, `\objautlink`), or an Equation Editor object | always | — |
| `DOC-UNREADABLE` | Encrypted or zip64 containers, damaged files, files over 32 MiB, text files with a document's extension | — | always: not checked, not clean |
| `IMG-WRONG-TYPE` | The bytes aren't the format the extension says | a zip, HTML or a script wearing an image's name | a PNG named `.jpg`, or no recognizable format |
| `IMG-PAYLOAD` | A zip, executable, script, PHP, `eval(`, `base64_decode(` or PowerShell after the image's last byte, or PHP, `eval(`, a decoder or a script tag in its metadata (EXIF, text chunks): the web-shell-in-a-JPEG | always | — |
| `IMG-TRAILER` | More than 1 KiB after the image's last byte with nothing recognizable in it | — | always (steganography, or a container) |
| `IMG-SVG-SCRIPT` | SVG with `<script>`, an `on*` event handler, a `javascript:` URI or an XML entity declaration (XXE) | always | — |
| `IMG-SVG-EXTERNAL` | SVG with `foreignObject`, `iframe`, `embed`, `object`, or content loaded from another host | — | always |
| `MALWARE` | ClamAV named a signature | always | — |

## How the formats are read

- **PDF**: the whole file, as pdfid does it: names are counted after `#xx` escapes are decoded, so a hidden `/JavaScript` still counts and the hiding is itself a finding. `/ObjStm` is noted in the message: compressed object streams can hold more than the raw bytes show.
- **OOXML** (`.docx`, `.xlsx`, `.pptx` and the macro-enabled and template variants, OpenDocument): the zip's central directory gives the part names (macros, macro sheets, OLE objects, ActiveX); `[Content_Types].xml`, every `.rels` and the main part (`word/document.xml`, `xl/workbook.xml`, `ppt/presentation.xml`) are inflated with a bounded DEFLATE reader of our own (no new dependency) to find external relationships and DDE fields. Encrypted members and zip64 files are `DOC-UNREADABLE`.
- **Legacy Office** (`.doc`, `.xls`, `.ppt`, compound files starting `D0 CF 11 E0`): the directory's names are UTF-16 in the file, so macro and object storages are found without walking the FAT; nothing deeper is attempted.
- **RTF**: control words in the first 16 MiB, lowercased.
- **Images**: the magic bytes decide the real format; the trailer after `IEND`, `FF D9` or GIF's `;` is read for payloads; metadata is searched for code. SVG is XML that a browser runs, so it is read as text.
- **ClamAV**: `clamdscan --fdpass` when the daemon's client is installed, else `clamscan`, over the document and image files found, with a 10-minute cap, once per scan. wpantry never installs, updates or configures it; `wpantry tools` says whether it is there.

## What it is not

A verdict, a sandbox, or a replacement for the viewer's own protections (Protected View, scripting off, macros blocked from the internet zone). Password-protected files can't be read and say so. Windows-only formats that aren't listed (`.lnk`, `.hta`, `.chm`) are caught by name in the hidden-text checks (`HIDDEN-FILENAME`) when they pose as documents, not read here.
