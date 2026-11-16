# 🛡️ Scope-Validated Nmap Discovery CLI

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Nmap](https://img.shields.io/badge/Engine-Nmap-2E8B57?style=for-the-badge)](https://nmap.org/)
[![Tests](https://img.shields.io/badge/Tests-Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/Focus-Defensive%20Security%20Engineering-critical?style=for-the-badge)](#)

> 🌐 **Language / Мова:** [English](#-english) | [Українська](#-українська)

---

## 🇬🇧 English

### Overview
**Scope-Validated Nmap Discovery CLI** is a fault-tolerant reconnaissance and asset discovery pipeline built in Python. Designed for penetration testers, SOC analysts, and vulnerability management teams, it ingests messy target lists, enforces strict scope boundaries, executes concurrent Nmap service scans, and outputs structured JSON reports without crashing on malformed inputs or unresponsive hosts.

### Key Engineering Features
* **Strict Scope Enforcement & Quarantine (`ipaddress` / `ValueError`):** Expands CIDR blocks (`10.0.0.0/24`), removes excluded off-limits IPs, deduplicates targets, and quarantines malformed entries into `rejected_scope.log` instead of halting execution.
* **Granular Exception Hierarchy Handling:** Separates critical environmental failures (`FileNotFoundError`, `PermissionError` → fail fast) from per-target network anomalies (`subprocess.TimeoutExpired`, `CalledProcessError`, `OSError` → log and continue).
* **Structured XML-to-JSON Pipeline:** Captures Nmap XML output (`-oX -`) directly in memory via `xml.etree.ElementTree` and exports clean service/port metadata to JSON.
* **Concurrent Execution & Graceful Abort:** Uses `ThreadPoolExecutor` for parallel scanning and handles `KeyboardInterrupt` (`Ctrl+C`) cleanly to save partial results before exiting.
* **Deterministic Unit Testing:** Includes a `pytest` suite using `unittest.mock` to verify timeout, subprocess, and scope-parsing edge cases without requiring a live lab.

### Project Structure
```text
scope-nmap-scanner/
├── scanner/
│   ├── __init__.py
│   ├── cli.py          # CLI entry point, pre-flight checks, concurrency orchestration
│   ├── validator.py    # Scope ingestion, CIDR expansion, exclusion filtering
│   ├── runner.py       # Subprocess Nmap wrapper with granular exception handling
│   └── parser.py       # Nmap XML (-oX -) parser into structured JSON dicts
├── tests/
│   └── test_runner.py  # Mocked pytest unit tests for failure modes
├── targets.txt         # Sample target scope file
└── README.md
```

### Quick Start
**Prerequisites:** Ensure Python 3.10+ and Nmap are installed and available in your system PATH.

**Run a Scan:**
```bash
python -m scanner.cli -i targets.txt -o results.json -w 10 -t 30
```

**Optional Exclusions File:**
```bash
python -m scanner.cli -i targets.txt -e exclusions.txt -p 22,80,443,8080 -o results.json
```

**Run Unit Tests:**
```bash
pip install pytest
python -m pytest -v
```

### Sample Output (`results.json`)
```json
[
  {
    "target": "127.0.0.1",
    "status": "success",
    "error": null,
    "data": {
      "host_state": "up",
      "ports": [
        {
          "port": "80",
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "product": "nginx",
          "version": "1.24.0"
        }
      ]
    }
  }
]
```

> ⚠️ **Legal Disclaimer:** This tool is intended strictly for authorized security assessments, defensive monitoring, and educational purposes. Never scan networks or systems without explicit written permission.

---

## 🇺🇦 Українська

### Огляд проєкту
**Scope-Validated Nmap Discovery CLI** — це відмовостійкий інструмент командного рядка (CLI) на Python для автоматизованої розвідки та інвентаризації мережевих активів. Проєкт створений для пентестерів, SOC-аналітиків та інженерів безпеки: він приймає «брудні» списки цілей, суворо контролює межі дозволеного скоупу (scope), виконує багатопотокове сканування через Nmap та формує структуровані JSON-звіти без аварійного завершення при помилках у вхідних даних чи зависанні хостів.

### Ключові інженерні рішення
* **Валідація скоупу та карантин (`ipaddress` / `ValueError`):** Автоматично розгортає CIDR-підмережі (`10.0.0.0/24`), відфільтровує заборонені IP-адреси зі списку винятків, видаляє дублікати та ізолює некоректні рядки у файл `rejected_scope.log` без зупинки сканування.
* **Гранулярна обробка ієрархії винятків Python:** Розділяє критичні системні збої (`FileNotFoundError`, `PermissionError` → миттєва зупинка) та мережеві помилки окремих хостів (`subprocess.TimeoutExpired`, `CalledProcessError`, `OSError` → логування та перехід до наступної цілі).
* **Парсинг XML у структурований JSON:** Перехоплює XML-вивід Nmap (`-oX -`) у пам'яті за допомогою `xml.etree.ElementTree` та перетворює інформацію про порти й сервіси у чистий JSON.
* **Багатопотоковість та безпечне переривання:** Використовує `ThreadPoolExecutor` для паралельного сканування та коректно обробляє `KeyboardInterrupt` (`Ctrl+C`), зберігаючи вже зібрані результати перед виходом.
* **Модульне тестування (Unit Tests):** Містить набір тестів `pytest` із використанням `unittest.mock` для детермінованої перевірки таймаутів, помилок підпроцесів та валідації скоупу.

### Структура проєкту
```text
scope-nmap-scanner/
├── scanner/
│   ├── __init__.py
│   ├── cli.py          # Точка входу CLI, pre-flight перевірки, керування потоками
│   ├── validator.py    # Парсинг скоупу, розгортання CIDR, фільтрація винятків
│   ├── runner.py       # Обгортка над subprocess Nmap з обробкою винятків
│   └── parser.py       # Парсер Nmap XML (-oX -) у структурований JSON
├── tests/
│   └── test_runner.py  # Модульні тести pytest із моками помилок
├── targets.txt         # Приклад файлу зі списком цілей
└── README.md
```

### Швидкий старт
**Вимоги:** переконайтеся, що встановлені Python 3.10+ та Nmap (і додані до системної змінної `PATH`).

**Запуск сканування:**
```bash
python -m scanner.cli -i targets.txt -o results.json -w 10 -t 30
```

**Запуск зі списком винятків (exclusions):**
```bash
python -m scanner.cli -i targets.txt -e exclusions.txt -p 22,80,443,8080 -o results.json
```

**Запуск модульних тестів:**
```bash
pip install pytest
python -m pytest -v
```

> ⚠️ **Застереження:** Цей інструмент призначений виключно для авторизованого тестування безпеки, моніторингу власної інфраструктури та навчальних цілей. Заборонено сканувати мережі або системи без явного дозволу їхніх власників.