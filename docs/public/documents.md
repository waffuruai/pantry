# Documents and images

Scanners skip the files people are sent: a spreadsheet with macros, a PDF that runs JavaScript on open, a Word file with a template on someone else's server, a picture that is really a program.

- **Read:** PDFs, Office documents (old and new), RTF and images in the scanned repos; on a machine scan, also the top of `~/Downloads`, `~/Desktop` and `~/Documents`, unless `--no-personal-files`.
- **Never** opened, rendered, executed or fetched. Every parser is bounded (32 MiB a file, 16 MiB an inflated part) and says "can't be read" rather than guess.
- [ClamAV](https://www.clamav.net/), when installed, runs over the same files.

**A clean result is not a clean file.** These checks find the shapes of document malware; ClamAV finds what it has signatures for. A document from a stranger should still be opened in a sandbox or a viewer with scripting off.

| Id | What | Fails | Warns |
|---|---|---|---|
| `DISGUISED-PROGRAM` | A file named like a document or image whose first bytes are a Windows, ELF or Mach-O executable, or a shebang script | always | — |
| `DOC-POLYGLOT` | A `.pdf` with no `%PDF-` header in its first KiB (HTML, a zip or something else wearing the name) | always | — |
| `DOC-LAUNCH` | A PDF `/Launch` action: the viewer is asked to start a program | always | — |
| `DOC-JS-ON-OPEN` | PDF JavaScript run on open (an `/OpenAction` JavaScript action, or the document-level `/Names` tree) that reaches outside the document: `app.launchURL`, `submitForm`, `exportDataObject`, `app.openDoc`, `getURL`, `Net.HTTP`, `app.mailMsg`, `Collab.`, `util.printf`, or `eval`/`unescape`/`String.fromCharCode` over a long escaped or hex payload; or an unreadable script (missing object, a filter other than FlateDecode). The note quotes its first line | always | — |
| `DOC-JAVASCRIPT` | PDF JavaScript that stays inside the document: on open but only printing, alerting, popping up a menu or formatting fields; on open but only defining functions for links and fields (KiCad's `ShM` pop-up launches a URL when the reader picks one; the note says so); or off the open path (field scripts, page-close actions). An empty on-open script (TCPDF writes one) is ignored. The note quotes the first script | — | always (forms use it; so do exploits) |
| `DOC-OBFUSCATED` | PDF action names written with `#xx` hex escapes (`/J#61vaScript`); an RTF with a malformed header (`{\rt` but not `{\rtf1`) or binary spliced into its object stream (`\bin`) | always | — |
| `DOC-EMBEDDED` | PDF embedded files, named from the file specification's `/UF` or `/F` (Acrobat Distiller adds `EI.joboptions`; a `.exe` is another matter) | — | always |
| `DOC-FORM` | PDF XFA forms, rich media, submit, remote-goto or import actions | — | always |
| `DOC-TRAILER` | More than 1 KiB after the PDF's last `%%EOF` | — | always |
| `DOC-MACRO` | VBA macros (`vbaProject.bin`, or `VBA`/`Macros`/`_VBA_PROJECT` storages in a legacy file) | in a format meant to carry none (`.docx`, `.xlsx`, `.pptx`, or a legacy file named as one), or a content type that says macro-enabled under a plain extension | in a macro-enabled format (`.docm`, `.xlsm`, `.pptm`, `.doc`, `.xls`, `.ppt`) |
| `DOC-XL4-MACRO` | Excel 4.0 macro sheets (`xl/macrosheets/`) | always | — |
| `DOC-REMOTE-TEMPLATE` | An attached template or glossary fetched from a URL or UNC path on open (`TargetMode="External"`) | always | — |
| `DOC-REMOTE-OBJECT` | An OLE object, package, frame or subdocument fetched from elsewhere on open (the CVE-2017-0199 shape) | always | — |
| `DOC-REMOTE-CONTENT` | Other external content loaded on open (not hyperlinks) | — | always |
| `DOC-DDE` | A DDE field (`DDEAUTO`, `ddeLink`): Office is asked to run another program's command | always | — |
| `DOC-OLE-OBJECT` | Embedded OLE objects (`oleObject*.bin`, `Ole10Native`): another file or program packaged inside | — | always |
| `DOC-ACTIVEX` | ActiveX controls | — | always |
| `DOC-RTF-OBJECT` | An RTF embedded object (`\objdata`, `\objemb`), one that updates itself on open (`\objupdate`, `\objautlink`), or an Equation Editor object | always | — |
| `DOC-UNREADABLE` | Encrypted or zip64 containers, damaged files, files over 32 MiB, text files with a document's extension | — | always: not checked, not clean |
| `IMG-WRONG-TYPE` | The bytes aren't the format the extension says | a zip, HTML or a script wearing an image's name | a PNG named `.jpg`, or no recognizable format |
| `IMG-PAYLOAD` | A zip, executable, script, PHP, `eval(`, `base64_decode(` or PowerShell after the image's last byte, or PHP, `eval(`, a decoder or a script tag in its metadata (EXIF, text chunks): the web-shell-in-a-JPEG | always | — |
| `IMG-TRAILER` | More than 1 KiB after the image's last byte with nothing recognizable in it | — | always (steganography, or a container) |
| `IMG-SVG-SCRIPT` | SVG with `<script>`, an `on*` event handler, a `javascript:` URI or an XML entity declaration (XXE) | always | — |
| `IMG-SVG-EXTERNAL` | SVG with `foreignObject`, `iframe`, `embed`, `object`, or content loaded from another host | — | always |
| `MALWARE` | ClamAV named a signature | always | — |

## How the formats are read

- **PDF**: the whole file, as pdfid reads it.
  - Names are counted after `#xx` escapes are decoded: a hidden `/JavaScript` still counts, and the hiding is a finding.
  - Compressed object streams (`/ObjStm`, FlateDecode) are inflated and read; the message says so.
  - An on-open script is followed from `/OpenAction`, the `/Names` tree (one level of `/Kids`) or a page's `/AA` open action to its `/JS` value: a literal string (escapes undone), a hex string, UTF-16 with a BOM, or a stream (inflated when FlateDecode, "could not be read" for any other filter). Up to 256 KiB, graded by what it calls; the finding quotes its first line.
- **OOXML** (`.docx`, `.xlsx`, `.pptx`, their macro-enabled and template variants, OpenDocument): the zip's central directory gives the part names (macros, macro sheets, OLE objects, ActiveX). `[Content_Types].xml`, every `.rels` and the main part (`word/document.xml`, `xl/workbook.xml`, `ppt/presentation.xml`) are inflated by our own bounded DEFLATE reader (no new dependency) to find external relationships and DDE fields. Encrypted members and zip64 files are `DOC-UNREADABLE`.
- **Legacy Office** (`.doc`, `.xls`, `.ppt`; compound files starting `D0 CF 11 E0`): the directory's UTF-16 names find macro and object storages without walking the FAT; nothing deeper.
- **RTF**: control words in the first 16 MiB, lowercased.
- **Images**: magic bytes decide the real format; the trailer after `IEND`, `FF D9` or GIF's `;` is read for payloads; metadata is searched for code. SVG is XML a browser runs, so it is read as text.
- **[ClamAV](https://www.clamav.net/)** ([source](https://github.com/Cisco-Talos/clamav)): `clamdscan --fdpass` when the daemon's client is installed, else `clamscan`, over the document and image files found, once a scan, capped at 10 minutes. Pantry never installs, updates or configures it; `wpantry tools` says whether it is there.

## What it is not

- Not a verdict, a sandbox, or a replacement for the viewer's protections (Protected View, scripting off, macros blocked from the internet zone).
- Password-protected files can't be read and say so.
- Unlisted Windows-only formats (`.lnk`, `.hta`, `.chm`) aren't read here; posing as documents, they are caught by name in the hidden-text checks (`HIDDEN-FILENAME`).
