# SPOOFCALYPSE

[English](README.md)

Проверка почтовой защиты доменов: SPF, DMARC, DKIM и MX.
Работает со списком доменов и файлами `.eml`. Отчёты — Markdown, CSV и JSON.
API-ключи не нужны.

## Установка

Python 3.11+. Windows CMD:

```cmd
git clone https://github.com/filyovscky/SPOOFCALYPSE.git
cd SPOOFCALYPSE
python -m venv .venv
.venv\Scripts\python.exe -m pip install .
```

Linux / macOS:

```sh
git clone https://github.com/filyovscky/SPOOFCALYPSE.git
cd SPOOFCALYPSE
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/spoofcalypse --help
```

## Проверка доменов

Один домен на строку в `scope.txt`. Пример — [scope.example.txt](scope.example.txt).

```cmd
spoofcalypse.cmd --file scope.txt --dkim-api --workers 4 --csv report.csv --md report.md
```

Другие варианты:

```cmd
spoofcalypse.cmd example.com
spoofcalypse.cmd --file scope.txt --brief
spoofcalypse.cmd --file scope.txt --json > report.json
```

В Linux/macOS вместо `spoofcalypse.cmd` используйте `.venv/bin/spoofcalypse`.

## Проверка письма

```cmd
spoofcalypse.cmd --eml message.eml --md email_report.md
spoofcalypse.cmd --eml first.eml --eml second.eml --json > emails.json
```

Проверяются все DKIM-подписи. Ключи берутся из DNS по селекторам письма.
`PASS` означает, что хотя бы одна подпись верна. Проверка `.eml` не оценивает DMARC-выравнивание From.
Результаты писем входят в Markdown и JSON. CSV содержит только домены.

## Статусы

| Проверка | Статусы |
| --- | --- |
| Домен | `SPOOFABLE`, `POSSIBLE`, `NOT_SPOOFABLE`, `UNKNOWN` |
| Поиск DKIM | `FOUND`, `NOT_FOUND`, `PARTIAL`, `ERROR`, `SKIPPED` |
| DKIM-ключ | `VALID`, `INVALID`, `REVOKED`, `UNSUPPORTED` |
| Подпись письма | `PASS`, `FAIL`, `ERROR`, `UNSIGNED` |

`NOT_SPOOFABLE` — обход не выявлен по DNS. `UNKNOWN` — данных недостаточно.
Риск `0–100` — сумма факторов. `N/A` — оценка не рассчитана.
`NOT_FOUND` — ключ не найден среди проверенных селекторов.
`NXDOMAIN` — DNS-имя не существует, а не подтверждение доступности регистрации.

## Основные параметры

| Параметр | Назначение |
| --- | --- |
| `--file FILE` | Список доменов |
| `--md FILE` | Подробный Markdown-отчёт |
| `--csv FILE` | Таблица доменов |
| `--json` | JSON в stdout |
| `--eml FILE` | Проверка DKIM-подписей, можно повторять |
| `--dkim-api` | Дополнительные селекторы из публичного архива prove.email |
| `--selectors a,b` | Дополнительные DKIM-селекторы |
| `--no-dkim` | Пропустить поиск DKIM-селекторов |
| `--dns IP` | DNS-резолвер |
| `--workers N` | Потоки, по умолчанию 16 |
| `--timeout N` | DNS-таймаут в секундах, по умолчанию 10 |
| `--brief` | Только сводка в терминале |

Архив селекторов — дополнительный источник. При его недоступности продолжается обычная DNS-проверка.
DMARC обрабатывается по RFC 9989. Устаревшие `pct`, `rf`, `ri` отмечаются в диагностике.

## Тесты

```cmd
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m unittest discover -s . -v
spoofcalypse.cmd --selftest
```

## Лицензия и авторство

**CC BY-NC 4.0 — некоммерческое использование с указанием авторства.**
Матрица решений адаптирована из [Spoofy](https://github.com/MattKeeley/Spoofy), автор Matt Keeley.
Изменения и сторонние библиотеки перечислены в [THIRD_PARTY.md](THIRD_PARTY.md).
Полный текст лицензии — [LICENSE](LICENSE). Атрибуция — [NOTICE](NOTICE).
Для коммерческого использования заимствованной матрицы требуется отдельное разрешение правообладателя.
