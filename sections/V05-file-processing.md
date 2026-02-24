# V5: File Processing

**ASVS Version:** 5.0.0
**ASVS Source:** `0x14-V5-File-Handling.md` in the [OWASP ASVS v5.0.0 repo](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en/)

> **Note to skill maintainers:** The requirement tables in this file are transcribed directly from the ASVS v5.0.0 source. Do not paraphrase or summarize — keep requirement text verbatim. The "Audit Guidance" sections are skill-specific additions to help sub-agents perform static analysis.

---

## Control Objective

The use of files can present a variety of risks to the application, including denial of service, unauthorized access, and storage exhaustion. This chapter includes requirements to address these risks.

---

## V5.1: File Handling Documentation

This section includes a requirement to document the expected characteristics of files accepted by the application, as a necessary precondition for developing and verifying relevant security checks.

| # | Requirement | Level |
|---|-------------|-------|
| **5.1.1** | Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected. | 2 |

### Audit Guidance for V5.1

**5.1.1 — Documented file handling policy:**

What to look for:
- Documentation (README, architecture docs, API docs, wiki pages, code comments) that defines allowed file types, accepted extensions, and maximum file sizes for each upload feature.
- OpenAPI/Swagger specs with `requestBody` definitions that constrain file upload content types, sizes, or formats.
- Configuration files or environment variables that define upload constraints (e.g., `MAX_UPLOAD_SIZE`, `ALLOWED_EXTENSIONS`, `ALLOWED_CONTENT_TYPES`).
- Documentation describing how the application handles malicious file detections (quarantine, delete, reject, notify user, alert admin).
- Incident-response or operational docs explaining malware scanning integration and behavior on positive detection.

Language/framework-specific places to check:
- **Django:** `FILE_UPLOAD_MAX_MEMORY_SIZE`, `DATA_UPLOAD_MAX_MEMORY_SIZE` in `settings.py`; custom validators documented in docstrings.
- **Express/Node.js:** `multer` configuration (`limits.fileSize`, `fileFilter`), `busboy` limits, or `formidable` options — check whether these are documented beyond the code itself.
- **Spring Boot:** `spring.servlet.multipart.max-file-size`, `spring.servlet.multipart.max-request-size` in `application.properties`/`application.yml`.
- **Laravel:** `upload_max_filesize` and `post_max_size` in `php.ini`; validation rules in Form Requests (e.g., `'file' => 'mimes:jpg,png|max:2048'`).
- **Rails:** ActiveStorage configuration, custom validators on attachment size/content type.
- **ASP.NET:** `IFormFile` size limits in `Startup.cs` or `Program.cs`, Kestrel `MaxRequestBodySize`.

Red flags:
- Upload features exist in code but no documentation defines accepted file types or size limits.
- Documentation exists for some upload features but not all.
- No documentation of what happens when a malicious file is detected.

When to mark N/A:
- The application does not accept file uploads of any kind.

---

## V5.2: File Upload and Content

File upload functionality is a primary source of untrusted files. This section outlines the requirements for ensuring that the presence, volume, or content of these files cannot harm the application.

| # | Requirement | Level |
|---|-------------|-------|
| **5.2.1** | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | 1 |
| **5.2.2** | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | 1 |
| **5.2.3** | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | 2 |
| **5.2.4** | Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. | 3 |
| **5.2.5** | Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to). | 3 |
| **5.2.6** | Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks. | 3 |

### Audit Guidance for V5.2

**5.2.1 — File size limits:**

What to look for:
- Enforcement of maximum file size at the web server, framework, or application layer before the full file body is read into memory or written to disk.
- **Good patterns:** Streaming uploads with size checks that abort early when limits are exceeded; web server-level limits (nginx `client_max_body_size`, Apache `LimitRequestBody`); framework-level limits configured before processing begins.

Language/framework-specific patterns:
- **Express/Node.js:** `multer({ limits: { fileSize: ... } })`, `busboy` limits, `express-fileupload` with `limits.fileSize`. Check that `bodyParser` has a `limit` option set. Red flag: reading entire request body into memory with `Buffer.concat()` or `data += chunk` without size checks.
- **Django:** `FILE_UPLOAD_MAX_MEMORY_SIZE`, `DATA_UPLOAD_MAX_MEMORY_SIZE` in `settings.py`. Check for custom upload handlers. Red flag: reading `request.FILES` without size validation.
- **Spring Boot:** `spring.servlet.multipart.max-file-size` and `spring.servlet.multipart.max-request-size` in `application.properties` or `application.yml`. Red flag: default (unlimited or very large) values unchanged.
- **Flask:** Check for `MAX_CONTENT_LENGTH` in app config. Red flag: `request.files` accessed without `MAX_CONTENT_LENGTH` set.
- **Laravel:** Validation rules like `max:10240` on file fields; `upload_max_filesize` and `post_max_size` in `php.ini`. Red flag: file accepted via `$request->file()` without size validation.
- **Rails:** ActiveStorage `size` validators, Shrine `max_size` plugin, CarrierWave `size_range`. Red flag: `params[:file]` used directly without size check.
- **Go:** `http.MaxBytesReader()` wrapping `r.Body`, `r.ParseMultipartForm(maxMemory)`. Red flag: `io.ReadAll(r.Body)` with no size limit.
- **ASP.NET/C#:** `[RequestSizeLimit]` attribute, Kestrel `MaxRequestBodySize`, `IFormFile` length checks. Red flag: reading `IFormFile.OpenReadStream()` without checking `Length`.

Red flags:
- No file size limits configured at any layer (web server, framework, application code).
- Size checked only after the entire file is uploaded and stored.
- Client-side-only file size validation with no server-side enforcement.

When to mark N/A:
- The application does not accept file uploads.

**5.2.2 — File type validation (extension + content):**

What to look for:
- Extension allowlist checking: the uploaded file's extension is compared against a list of permitted extensions.
- Content validation: the file's actual content is inspected to confirm it matches the claimed type. This means checking magic bytes (file signatures), MIME sniffing, or using specialized validation libraries.
- Both checks must be present — extension-only checking is insufficient.

Language/framework-specific patterns:
- **Python:** `python-magic` (`magic.from_buffer()`, `magic.from_file()`), `filetype` library, `imghdr` (deprecated in 3.13), Pillow `Image.open().verify()` for images. Red flag: checking only `file.filename.endswith('.jpg')` or `file.content_type` from the HTTP header (user-controlled).
- **Node.js:** `file-type` package (reads magic bytes), `mmmagic`, `image-size`. For `multer`, a custom `fileFilter` checking both extension and magic bytes. Red flag: relying solely on `req.file.mimetype` (derived from client `Content-Type` header).
- **Java:** `Apache Tika` (`Tika.detect()`), `java.nio.file.Files.probeContentType()`, `javax.imageio.ImageIO.read()` for images, `URLConnection.guessContentTypeFromStream()`. Red flag: checking only file extension via `FilenameUtils.getExtension()`.
- **PHP:** `finfo_file()` / `finfo_buffer()` with `FILEINFO_MIME_TYPE`, `getimagesize()` for images, `mime_content_type()`. Red flag: trusting `$_FILES['file']['type']` (client-supplied).
- **Ruby:** `MimeMagic`, `marcel` gem (used by ActiveStorage), `filemagic`. Red flag: checking only `File.extname()`.
- **Go:** `http.DetectContentType()` (reads first 512 bytes), `gabriel-vasile/mimetype` library. Red flag: relying solely on the extension from the filename.
- **C#/.NET:** `System.IO.Path.GetExtension()` for extension checking (insufficient alone); use `Mime` NuGet package or read magic bytes manually. For images, `System.Drawing.Image.FromStream()` or `ImageSharp`. Red flag: trusting `IFormFile.ContentType`.

Red flags:
- Only checking the file extension (trivially spoofable).
- Only checking the `Content-Type` header from the HTTP request (client-controlled).
- No content-based validation at all — accepting any file that passes the extension check.
- Allowing dangerous file types (`.exe`, `.bat`, `.sh`, `.php`, `.jsp`, `.aspx`) without explicit business justification.

When to mark N/A:
- The application does not accept file uploads.

**5.2.3 — Compressed file bomb protection:**

What to look for:
- Before or during decompression, the application checks the uncompressed size and file count against defined limits.
- The application uses streaming decompression that tracks bytes written and aborts if thresholds are exceeded, rather than decompressing everything first and checking after.

Language/framework-specific patterns:
- **Python:** `zipfile.ZipFile` — check for reading `ZipInfo.file_size` before extraction; `tarfile` — check member sizes before extracting. Red flag: `zipfile.extractall()` or `tarfile.extractall()` without pre-checking member sizes. Good pattern: iterating members and summing `file_size` / `compress_size` ratios.
- **Node.js:** `adm-zip`, `yauzl`, `unzipper` — check for size/count limits before or during extraction. `tar-stream` with byte counting. Red flag: `extract()` called without any size tracking.
- **Java:** `java.util.zip.ZipInputStream` — track total bytes read during extraction; `ZipEntry.getSize()` (can be spoofed in malicious zips, so also track bytes during streaming). Red flag: `ZipInputStream` reading without cumulative size tracking.
- **PHP:** `ZipArchive` — check `statIndex()` for each entry's size before extraction. Red flag: `extractTo()` without pre-checking entry sizes.
- **Go:** `archive/zip` — inspect `FileHeader.UncompressedSize64` before extraction; limit `io.Copy` with `io.LimitReader`. Red flag: extracting all entries without size checks.

Red flags:
- Decompressing the entire archive into memory or disk before checking sizes.
- No limit on the number of files within an archive.
- Relying solely on the compressed size (ignoring high compression ratios).
- Not handling nested archives (zip within zip).

When to mark N/A:
- The application does not accept or process compressed/archive files.

**5.2.4 — Per-user file quotas:**

What to look for:
- Enforcement of a maximum total storage size per user and/or maximum number of files per user.
- Quota checks performed before accepting and storing a new file, not only after.
- Database or storage-level tracking of per-user usage (e.g., a `total_storage_used` column, counting files per user before insert).

Red flags:
- No per-user limits — a single user can upload an unlimited number of files or consume unlimited storage.
- Quota checked only client-side.
- Quota checks that are race-condition-prone (check-then-write without locking).

When to mark N/A:
- The application does not store files on a per-user basis (e.g., only admin uploads, no user-driven file storage).

**5.2.5 — Symlink protection in compressed files:**

What to look for:
- During archive extraction, the application checks whether entries are symbolic links and rejects them (or validates them against an allowlist).
- The extraction process resolves paths and verifies they stay within the intended target directory even after symlink resolution.

Language/framework-specific patterns:
- **Python:** `tarfile` — check `TarInfo.issym()` and `TarInfo.islnk()` before extraction. Python 3.12+ has `tarfile.data_filter` for safe extraction. `zipfile` — zip files can contain symlinks on Unix; check for external attributes indicating symlinks.
- **Node.js:** `tar` package has `filter` option to skip symlinks; `yauzl` / `unzipper` — check entry type. Red flag: `extractall()` without filtering.
- **Java:** `ZipEntry` — check if entries create symlinks; `TarArchiveEntry.isSymbolicLink()` in Apache Commons Compress.
- **Go:** `archive/zip`, `archive/tar` — check `FileHeader.Mode()` for symlink flags; `tar.Header.Typeflag == tar.TypeSymlink`.

Red flags:
- Extracting archives without checking for symlinks at all.
- Allowing symlinks but not validating their targets against an allowlist.

When to mark N/A:
- The application does not accept or extract compressed/archive files.

**5.2.6 — Pixel flood / image dimension limits:**

What to look for:
- Before processing (resizing, thumbnailing, rendering) an image, the application checks the declared pixel dimensions (width x height) and rejects images exceeding a maximum.
- This prevents decompression bombs where a small file (e.g., a highly compressed PNG) expands to enormous pixel buffers in memory.

Language/framework-specific patterns:
- **Python (Pillow/PIL):** `Image.open(f).size` returns `(width, height)` — check before calling `.load()`, `.resize()`, or `.save()`. Pillow has `Image.MAX_IMAGE_PIXELS` (default ~178 million) — check it is not set to `None` (disabled). `Image.DecompressionBombWarning` / `Image.DecompressionBombError`.
- **Node.js:** `sharp` — check `metadata()` for width/height before processing; `image-size` package for quick dimension reading without full decode. `jimp` — check dimensions before processing.
- **Java:** `ImageIO.read()` decodes fully — use `ImageIO.getImageReaders()` and read metadata first via `ImageReader.getWidth(0)` / `getHeight(0)` before decoding pixel data.
- **PHP:** `getimagesize()` returns dimensions without fully decoding; check before `imagecreatefromjpeg()` / `imagecreatefrompng()`. GD library can OOM on large images.
- **Go:** `image.DecodeConfig()` reads dimensions without full decode; check before `image.Decode()`.
- **C#/.NET:** `System.Drawing.Image.FromStream()` with validation; `ImageSharp` `Image.Identify()` for metadata-only reading.

Red flags:
- Processing images without checking dimensions first.
- `Image.MAX_IMAGE_PIXELS = None` in Pillow (disables decompression bomb protection).
- Using `ImageIO.read()` (Java) or `Image.FromStream()` (.NET) directly on untrusted input without dimension pre-checks.
- No maximum pixel limit configured or enforced.

When to mark N/A:
- The application does not accept or process image files.

---

## V5.3: File Storage

This section includes requirements to prevent files from being inappropriately executed after upload, to detect dangerous content, and to avoid untrusted data being used to control where files are being stored.

| # | Requirement | Level |
|---|-------------|-------|
| **5.3.1** | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | 1 |
| **5.3.2** | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | 1 |
| **5.3.3** | Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip. | 3 |

### Audit Guidance for V5.3

**5.3.1 — Preventing execution of uploaded files:**

What to look for:
- Uploaded files must not be stored in locations where the web server will interpret and execute them (e.g., within a webroot directory that processes `.php`, `.jsp`, `.aspx`, `.py`, `.cgi`, `.pl` files).
- The storage location should serve files as static content only, with server-side script execution disabled.

Patterns and mitigations to check:
- **Separate storage:** Files stored outside the webroot entirely (e.g., in a dedicated storage directory, cloud object storage like S3/GCS/Azure Blob).
- **Randomized filenames:** Uploaded files renamed to UUIDs or hashes, removing the original extension. Served via a download endpoint that sets `Content-Disposition: attachment` and an explicit safe `Content-Type`.
- **Web server configuration:** If files are served from a directory within the webroot, check that script execution is disabled for that directory:
  - **nginx:** `location /uploads/ { ... }` should not pass to PHP-FPM, should not have `autoindex`, should set `add_header Content-Disposition attachment;`.
  - **Apache:** `.htaccess` in upload directory with `php_flag engine off`, `RemoveHandler .php .phtml`, or `ForceType application/octet-stream`.
  - **IIS:** `web.config` removing script handlers for the upload directory.
- **Cloud storage:** Files in S3/GCS/Azure Blob are inherently not executed server-side. This is a PASS for this requirement (but still check access controls).

Red flags:
- Uploaded files stored in a directory served by the application server with script execution enabled (e.g., PHP files stored in a directory processed by `mod_php` or PHP-FPM).
- Original file extensions preserved and files accessible via a direct URL that the web server could interpret.
- Upload directory within the webroot with no explicit configuration to prevent execution.
- Serving uploaded files with `Content-Type` derived from the file extension without overriding to a safe type.

When to mark N/A:
- The application does not store uploaded files in any web-accessible location (e.g., files are only stored in a database or processed in memory and discarded).

**5.3.2 — Path traversal and file inclusion prevention:**

What to look for:
- The application should generate file paths using internal identifiers (UUIDs, database IDs, hashes) rather than user-supplied filenames.
- If user-supplied filenames must be used, they should be strictly sanitized: remove or reject path separators (`/`, `\`, `..`), null bytes, URL-encoded variants, and Unicode normalization tricks.
- File operations should be confined to an expected base directory (jail/chroot/sandbox).

Language/framework-specific patterns:
- **Python:** `os.path.join(base_dir, user_input)` is insufficient alone — must also call `os.path.realpath()` or `os.path.abspath()` and verify the result starts with the base directory. `pathlib.Path.resolve()` and checking `is_relative_to(base)` (Python 3.9+). Red flag: `open(user_input)` or `os.path.join(base, user_input)` without canonicalization and prefix check.
- **Node.js:** `path.join(baseDir, userInput)` followed by checking `resolvedPath.startsWith(baseDir)`. Red flag: `fs.readFile(req.query.file)` or `path.join(base, req.params.filename)` without verifying the resolved path stays within bounds. Use `path.resolve()` and prefix-check.
- **Java:** `Paths.get(baseDir).resolve(userInput).normalize()` and then `startsWith(baseDir)` check. `File.getCanonicalPath()` and prefix check. Red flag: `new File(baseDir, userInput)` without canonicalization. Spring `Resource` resolution with user-controlled paths.
- **PHP:** `realpath()` to canonicalize, then `strpos($resolved, $baseDir) === 0` check. `basename()` to strip directory components. Red flag: `include($userInput)`, `require($userInput)`, `file_get_contents($userInput)`, `fopen($userInput)` with user-controlled paths. LFI/RFI risk if `allow_url_include` is on.
- **Ruby:** `File.expand_path()` and prefix check against base directory. `Pathname.new(path).cleanpath`. Red flag: `File.read(params[:path])`, `send_file(params[:filename])` without sanitization.
- **Go:** `filepath.Clean()`, `filepath.Abs()`, then `strings.HasPrefix(cleaned, baseDir)`. Red flag: `os.Open(userInput)` without path validation. `filepath.Join(base, userInput)` without prefix check (Join resolves `..` but does not prevent escaping).
- **C#/.NET:** `Path.GetFullPath()` and check `StartsWith(basePath)`. `Path.Combine()` does NOT prevent traversal — `Path.Combine("C:\\uploads", "..\\..\\etc\\passwd")` resolves upward. Red flag: `System.IO.File.ReadAllBytes(userInput)`.

Red flags:
- File paths constructed by directly concatenating user input with a base path.
- No canonicalization (resolving `..`, symlinks, normalizing Unicode) before path validation.
- Path validation using string matching without resolving the path first.
- Null byte injection potential (older runtimes/languages).
- `include`, `require`, or dynamic loading functions using user-controlled paths (LFI/RFI).
- SSRF via user-controlled file URLs passed to server-side fetching functions (e.g., `urllib.request.urlopen(user_url)`, `fetch(user_url)` on the server).

When to mark N/A:
- The application does not perform file operations based on any user input (all file paths are hardcoded or derived entirely from internal state).

**5.3.3 — Zip slip prevention:**

What to look for:
- When extracting entries from archives, the application must validate that each extracted file's path resolves to within the intended destination directory.
- User-supplied path components within archive entries (e.g., `../../etc/cron.d/malicious`) must be detected and rejected.

Language/framework-specific patterns:
- **Python:** When using `zipfile` or `tarfile`, iterate entries and check that `os.path.realpath(os.path.join(dest_dir, entry_name))` starts with `os.path.realpath(dest_dir)`. Python 3.12+ `tarfile` has `data_filter` for safe extraction. Red flag: `zipfile.extractall(path)` without validating member names, `tarfile.extractall()` without filters.
- **Node.js:** `yauzl`, `unzipper`, `adm-zip` — before writing each entry, resolve the path and verify it stays within the target directory. `tar` package with `strip` and `filter` options. Red flag: `entry.pipe(fs.createWriteStream(entry.path))` without path validation.
- **Java:** Apache Commons Compress or `java.util.zip` — after getting `ZipEntry.getName()`, resolve against the destination and verify with `canonicalPath.startsWith(destinationDir)`. Red flag: `new File(destDir, zipEntry.getName())` used directly without canonicalization check. The well-known Zip Slip vulnerability (Snyk advisory).
- **Go:** `archive/zip` — check `filepath.Join(dest, f.Name)` resolves within `dest` using `strings.HasPrefix(filepath.Clean(path), filepath.Clean(dest))`. Red flag: `os.Create(filepath.Join(dest, f.Name))` without prefix validation.
- **PHP:** `ZipArchive::extractTo()` — check entry names for `..` before extraction or validate resolved paths. Red flag: `$zip->extractTo($dest)` without entry name validation.
- **Ruby:** `Zip::File.open` with `rubyzip` — validate `entry.name` does not contain `..` and resolved path stays within destination. Red flag: `entry.extract(File.join(dest, entry.name))` without path validation.

Red flags:
- Archive extraction using `extractall()` or equivalent without pre-validating entry paths.
- Path validation that does not resolve/canonicalize before prefix-checking.
- No check for `..` sequences or absolute paths in archive entry names.

When to mark N/A:
- The application does not extract or decompress archive files on the server side.

---

## V5.4: File Download

This section contains requirements to mitigate risks when serving files to be downloaded, including path traversal and injection attacks. This also includes making sure they don't contain dangerous content.

| # | Requirement | Level |
|---|-------------|-------|
| **5.4.1** | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | 2 |
| **5.4.2** | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | 2 |
| **5.4.3** | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | 2 |

### Audit Guidance for V5.4

**5.4.1 — Filename validation in downloads:**

What to look for:
- When a user requests a file download (e.g., via a file ID or filename in a URL parameter, JSON body, or query string), the application should not use the user-supplied filename directly to locate or serve the file.
- The `Content-Disposition` header in the response should specify a safe, server-determined filename rather than reflecting user input verbatim.

Language/framework-specific patterns:
- **Python (Django):** `FileResponse` or `HttpResponse` with `Content-Disposition` header set using a sanitized filename. `django.utils.encoding.escape_uri_path()` for RFC 5987 encoding. Red flag: `Content-Disposition: attachment; filename={user_input}` without sanitization.
- **Python (Flask):** `send_file()` or `send_from_directory()` — check that `download_name` is not directly from user input. `send_from_directory()` provides some path traversal protection but filename in the header should still be controlled.
- **Node.js (Express):** `res.download(filePath, sanitizedFilename)` — the second argument controls the `Content-Disposition` filename. Red flag: `res.download(path.join(uploadDir, req.query.file))` reflecting user input in both path lookup and download name.
- **Java (Spring):** `ResponseEntity` with `ContentDisposition.attachment().filename(sanitized).build()` in headers. Red flag: reflecting `@RequestParam` filename directly in `Content-Disposition`.
- **PHP:** `header("Content-Disposition: attachment; filename=\"$sanitized\"")` — ensure `$sanitized` is not raw user input. Check for header injection via newlines in filename.
- **Rails:** `send_file(path, filename: sanitized)` or `send_data` with explicit `:filename` option. Red flag: `send_file(params[:path])`.
- **Go:** Setting `Content-Disposition` header via `w.Header().Set()` — check that the filename value is not taken directly from request parameters. Use `mime.FormatMediaType()` for proper encoding.
- **C#/.NET:** `FileResult` / `PhysicalFileResult` with explicit `FileDownloadName`. `ContentDispositionHeaderValue` for proper encoding.

Red flags:
- User-submitted filenames reflected directly in `Content-Disposition` headers without sanitization.
- File lookup path constructed from user input without mapping through an internal identifier (database ID, hash).
- No `Content-Disposition` header set at all on file download responses (browser may try to render/execute the file inline).
- JSONP responses that include user-controlled filenames without escaping.

When to mark N/A:
- The application does not serve file downloads.

**5.4.2 — Filename encoding/sanitization in responses (RFC 6266):**

What to look for:
- Filenames in `Content-Disposition` headers and email attachment filenames should be properly encoded to prevent injection attacks and preserve document structure.
- For HTTP headers, filenames containing non-ASCII characters or special characters should use RFC 5987 / RFC 6266 encoding (`filename*=UTF-8''...`).
- Filenames must not contain characters that could break the header structure (e.g., newlines for header injection, quotes, semicolons).

Specific checks:
- Filenames are stripped of or escaped: `"`, `\`, `/`, `\r`, `\n`, null bytes.
- Non-ASCII filenames use `filename*=UTF-8''<percent-encoded>` in addition to a fallback ASCII `filename=` parameter.
- Email attachment filenames (MIME headers) are encoded with RFC 2047 or RFC 2231 encoding.

Language/framework-specific safe patterns:
- **Python:** `email.utils.encode_rfc2231()` for email; Django `FileResponse` handles encoding. `urllib.parse.quote()` for percent-encoding in HTTP headers.
- **Node.js:** `content-disposition` npm package (handles RFC 6266 encoding automatically). Red flag: manually constructing `Content-Disposition` headers with string concatenation.
- **Java:** `ContentDisposition.builder("attachment").filename(name, StandardCharsets.UTF_8).build()` (Spring).
- **PHP:** Libraries like `symfony/http-foundation` `HeaderUtils::makeDisposition()`. Red flag: manual `header()` construction with unsanitized filenames.
- **Go:** `mime.FormatMediaType("attachment", map[string]string{"filename": sanitized})`.
- **C#/.NET:** `ContentDispositionHeaderValue` with `FileNameStar` property for RFC 5987 encoding.

Red flags:
- Filenames containing special characters passed directly into headers without encoding.
- No RFC 5987/6266 `filename*` parameter for non-ASCII filenames.
- Header injection possible through unsanitized newline characters in filenames.
- Email attachments with unencoded non-ASCII filenames.

When to mark N/A:
- The application does not serve files for download and does not send email attachments.

**5.4.3 — Antivirus scanning of untrusted files:**

What to look for:
- Files uploaded by users or obtained from untrusted external sources are scanned for malware before being served to other users or made available for download.
- Scanning should occur before the file is made accessible, not asynchronously after it is already downloadable.

Integration patterns to look for:
- **ClamAV:** `clamd` daemon integration via client libraries. Python: `pyclamd` or `clamd` package. Node.js: `clamscan` or `clamav.js`. Java: `ClamAV` client. PHP: `php-clamav` or shell exec to `clamscan`. Ruby: `clamav-client` gem.
- **Cloud-based scanning:** AWS S3 event triggers to scanning services, Google Cloud DLP, Azure Defender for Storage, VirusTotal API integration.
- **Commercial AV APIs:** Scanii, Metadefender (OPSWAT), Sophos Intelix API.
- **Application logic:** Check that the scan result is evaluated before the file is stored/served — a scan that runs but whose result is ignored is not effective.

Red flags:
- No antivirus scanning integration at all for an application that accepts and serves user-uploaded files.
- Scanning occurs asynchronously and files are made available before scan results are processed.
- Scan failures (e.g., AV service unavailable) result in the file being accepted rather than rejected (fail-open instead of fail-closed).
- Only scanning certain file types while allowing others through unscanned.
- Using only file extension or MIME type checks as a substitute for actual malware scanning.

When to mark N/A:
- The application does not serve user-uploaded or externally-obtained files to other users. Files are only processed internally and never made available for download.

---

## References

For more information, see also:

* [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
* [Example of using symlinks for arbitrary file read](https://hackerone.com/reports/1439593)
* [Explanation of "Magic Bytes" from Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

---

## V5 Requirement Level Summary

| Level | Requirements | IDs |
|-------|-------------|-----|
| L1 | 4 | 5.2.1, 5.2.2, 5.3.1, 5.3.2 |
| L2 | 5 | 5.1.1, 5.2.3, 5.4.1, 5.4.2, 5.4.3 |
| L3 | 4 | 5.2.4, 5.2.5, 5.2.6, 5.3.3 |
| **Total** | **13** | |
