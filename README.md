# LogSentinel

A command-line tool that analyzes web-server access logs (Apache/Nginx common log format) and detects suspicious activity such as brute-force logins, path scanners, known attack signatures and server-error spikes.

**Problem it addresses:** manually reviewing access logs is repetitive and time-consuming. LogSentinel produces a prioritized list of suspicious patterns for a person to investigate. Its rules do not prove that an IP is an attacker. The CLI can be called from another script or a scheduler, but the project does not configure cron or CI itself.

COE203 - Advanced Programming with Python, Istinye University. Project 1: Personal Automation Tool. The input-processing and report-generation workflow automates a repeated task. Team contribution records must describe actual work, not inferred authorship.

## Requirements

Python 3.9 or newer. No third-party packages.

Extract the project ZIP, open a terminal in the project folder, and check `python --version`. No `pip install` step is needed. On Windows, use `py` instead of `python` if that is your Python launcher.

```console
python cli.py --help
python cli.py analyze --help
```

## Project structure

| Path | Purpose |
|---|---|
| `cli.py` | Command-line entry point (argparse with sub-commands, exit codes) |
| `logsentinel/models.py` | `LogEntry`, `Alert`, `ParseStats` dataclasses and custom exceptions |
| `logsentinel/__init__.py` | Package description and version |
| `logsentinel/parser.py` | Safe streaming parser: path validation, regex, size and line-length limits |
| `logsentinel/detectors.py` | Abstract `Detector` base class, four detectors, `@register` and `@timed` decorators, `analyze()` |
| `logsentinel/report.py` | Text, JSON and CSV output formatters |
| `sample_logs/access.log` | Demo log with injected attacks and deliberately malformed lines |
| `tests/test_logsentinel.py` | Unit tests, including malicious-input cases |
| `tests/test_detectors.py` | Detection-rule, time-boundary, and ordering tests |
| `tests/test_cli_integration.py` | Real CLI runs, JSON/CSV results, validation, and file safety |
| `tests/__init__.py` | Marks the test directory as a package |
| `contributions/` | One markdown file per team member describing their work |
| `contributions/STUDENT_NAME_STUDENT_ID_GITHUB_USERNAME.md` | Blank template for actual members |
| `contributions/Anir_N_T_Elhasairi_2309116564_eneerhs.md` | Anir's confirmed project-selection and review-preparation contribution |
| `.gitignore` | Excludes caches, local credentials, real logs, and generated reports while keeping the sample log |
| `README.md` | Setup, file map, commands, rule semantics, limits, and tests |

## Usage

```bash
python cli.py analyze --input sample_logs/access.log
python cli.py analyze -i sample_logs/access.log --format json --min-severity high
python cli.py analyze -i sample_logs/access.log -d bruteforce scanner -t 10 -w 120 -o report.csv -f csv
python cli.py list-detectors
```

| Option | Meaning | Default |
|---|---|---|
| `-i, --input` | Log file to analyze (required) | |
| `-d, --detectors` | Detectors to run | all |
| `-t, --threshold` | Threshold for bruteforce, scanner and errorspike; suspicious alerts on any match | 5 |
| `-w, --window` | Bruteforce sliding window only, in seconds | 60 |
| `-f, --format` | `text`, `json` or `csv` | text |
| `-m, --min-severity` | `low`, `medium` or `high` | low |
| `-o, --output` | Write the report to a file | stdout |

Exit codes: `0` no alerts remaining after the severity filter, `1` report contains alerts, `2` error (bad file, bad argument, ordering, or output failure). Exit code 1 is an expected detection result, not a crash. CSV contains alert rows only; JSON and text also contain parse statistics. Numeric arguments must be integers between 1 and 1,000,000.

Input paths are relative to the terminal's current directory unless absolute. Quote paths containing spaces. `--output` replaces an existing report, but it cannot replace the input log, including a symlink or hard-link alias. Output parent folders must already exist.

## Verified demonstration

```console
python cli.py analyze -i sample_logs/access.log
```

The synthetic sample has 342 lines: 339 parsed and 3 skipped. Default settings produce four alerts, sorted first by severity and then descending count:

| Rule | Severity | IP | Count |
| --- | --- | --- | --- |
| bruteforce | high | 203.0.113.9 | 12 failed-auth responses within 60 seconds |
| suspicious | high | 198.51.100.77 | 4 signature matches |
| errorspike | medium | `*` (server-wide) | 8 server errors in the 10:40 minute |
| scanner | medium | 198.51.100.23 | At least 5 distinct missing paths |

Analysis time varies on each run. Sample IPs and events are demonstration data, not evidence of real attacks.

## Detectors

- **bruteforce**: at least `threshold` 401/403 responses from one IP inside an inclusive `window` (uses a deque and reports the peak count). Failed-auth timestamps for each IP must arrive in non-decreasing order. Out-of-order events produce a clear error instead of an incorrect window count. Other requests need not be globally time-sorted.
- **scanner**: at least `threshold` distinct missing (404) paths from one IP across the whole file. The set stops growing at the threshold, so the report says `5+` rather than claiming an exact total. It does not use `--window`.
- **suspicious**: a case-insensitive regex looks for path traversal, SQL injection, XSS and selected secret-file paths (`.env`, `.git`). One match is enough for an alert regardless of `--threshold`. Signatures are limited and can produce false positives.
- **errorspike**: at least `threshold` 5xx responses within a calendar minute, grouped using the timestamp's recorded timezone. This is a server-wide alert and uses `*` as the IP label. It does not use `--window`.

## Design and Python techniques used

- **Generators**: the parser yields one valid entry at a time and never loads the entire input file. Detector state still grows with IPs, minutes, and active failed-auth events. Total memory is not constant.
- **Context managers**: `@contextmanager` guarantees the file handle is closed.
- **Decorators**: `@register` builds a plugin registry, `@timed` measures analysis time.
- **OOP**: the abstract `Detector` class requires `feed()` and `finish()`. Each registered subclass implements those methods.
- **Dataclasses and type hints** throughout.
- **Custom exception hierarchy** turned into clean error messages and exit codes.
- **Regular expressions** for parsing and attack signatures.

## Robustness

Malformed lines, invalid IPs/timestamps/status codes, and lines longer than 4096 characters are counted and skipped. Oversized lines are drained in limited chunks. Invalid UTF-8 bytes are replaced while decoding; lines that remain malformed are skipped. HTTP status values must be between 100 and 599.

Missing files, directories, inputs above 200 MiB (209,715,200 bytes), bad CLI arguments, out-of-order failed-auth events, and output failures return exit code 2. The file-size check runs before reading. Report creation is a direct write, not an atomic transaction. Empty or entirely malformed input can return 0 with zero parsed entries, so inspect the statistics before treating a report as useful.

The tool is a heuristic analyzer of local files. It does not block IPs, monitor a live server, decode every possible attack encoding, or identify proven attackers. It supports a common-log-style prefix, including sample lines with trailing combined-log fields. The sample file is synthetic. Keep real server logs and credentials out of GitHub.

## Running the tests

```bash
python -m unittest discover -s tests -t . -v
```

All 27 tests passed during review on October 13, 2026. The tests cover parser edge cases, all four detectors, inclusive/expired time windows, invalid chronology, real CLI commands, text/JSON/CSV behavior, severity filtering, and input-file preservation. A reduced file-size limit is mocked to test rejection without creating a 200 MiB test file. Tests use temporary output paths and work on Windows and Unix.

## Contributions and GitHub submission

Every actual team member must complete their own file using `STUDENT_NAME_STUDENT_ID_GITHUB_USERNAME.md`, with spaces replaced by underscores. The template contains no invented members or contribution claims. Anir's record describes only confirmed work in the project conversation; original source authorship remains for the team to document truthfully.

The intended repository is `eneerhs/logsentinel`. Keep it private until the owner approves public visibility. Submit the repository URL through the professor's specified channel once all actual contribution records are complete and the required visibility is set.
