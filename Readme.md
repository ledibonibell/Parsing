# Парсеры уязвимостей для Windows (Произвольной версии), Ubuntu 22.04.4, AltLinux Workstation 10.1

Этот репозиторий содержит три скрипта для парсинга информации об уязвимостях (CVE) из различных источников.

## 1. Парсер для Windows (`Windows.py`)

### Глобальные переменные:
- `START_DATE = datetime(2015, 1, 1, tzinfo=timezone.utc)` - Дата начала сбора статистики
- `PLATFORM_ID = "10049%27,%2710047"` - ID платформы для фильтрации
- `PRODUCT_FAMILY_ID = 100000013` - ID семейства продуктов
- `OS_NAME = "windows_7"` - Название ОС
- `OS_VERSION = "6.1.7601"` - Версия ОС
- `MAX_RETRIES = 5` - Максимальное количество попыток запроса
- `REQUEST_TIMEOUT = 5` - Таймаут запроса (секунды)

### Ссылки для парсинга:
- API Microsoft Security Response Center:  
  `https://api.msrc.microsoft.com/sug/v2.0/ru-RU/affectedProduct`

## 2. Парсер для Ubuntu 22.04.4 (`Ubuntu.py`)

### Глобальные переменные:
- `OS_VERSION = "22.04.4"` - Версия Ubuntu
- `OS_NAME_VERSION = f"ubuntu_{OS_VERSION}"` - Название ОС с версией
- `OUTPUT_FILENAME = f"{OS_NAME_VERSION}_bulletin.txt"` - Имя выходного файла
- `MAX_RETRIES = 5` - Максимальное количество попыток запроса
- `REQUEST_TIMEOUT = 5` - Таймаут запроса (секунды)
- `OVAL_NAMESPACE` - Пространство имен OVAL

### Ссылки для парсинга:
- CVE OVAL файл:  
  `https://security-metadata.canonical.com/oval/com.ubuntu.jammy.cve.oval.xml.bz2`
- USN OVAL файл:  
  `https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2`

## 3. Парсер для ALT Workstation 10.1 (`AltLinux.py`)

### Глобальные переменные:
- `OVAL_URL` - URL для скачивания OVAL данных в формате ZIP
- `MAX_RETRIES = 3` - Максимальное количество попыток запроса
- `REQUEST_TIMEOUT = 30` - Таймаут запроса (секунды)
- `OUTPUT_FILE = "ALT_Workstation_10.1_bulletin.txt"` - Имя выходного файла
- `NAMESPACES` - Пространство имен OVAL
- `START_DATE = datetime(2023, 1, 31)` - Начальная дата для фильтрации
- `END_DATE = datetime(2024, 3, 13)` - Конечная дата для фильтрации
- `TARGET_CPE = "cpe:/o:alt:workstation:10"` - Целевой CPE для фильтрации

### Ссылки для парсинга:
- OVAL данные для ALT Linux:  
  `https://rdb.altlinux.org/api/errata/export/oval/p10?one_file=true`