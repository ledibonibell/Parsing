import requests
import bz2
from datetime import datetime
from lxml import etree
from typing import Set
from requests.exceptions import Timeout

OVAL_NAMESPACE = {'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'}
MAX_RETRIES = 5
REQUEST_TIMEOUT = 5
OS_VERSION = "22.04.4"
OS_NAME_VERSION = f"ubuntu_{OS_VERSION}"
OUTPUT_FILENAME = f"{OS_NAME_VERSION}_bulletin.txt"
MIN_DATE = datetime(2024, 2, 22)  # Минимальная дата для фильтрации

# URL для скачивания OVAL файлов
USN_OVAL_URL = (
    "https://security-metadata.canonical.com/"
    "oval/com.ubuntu.jammy.usn.oval.xml.bz2"
)


def download_and_decompress(url: str) -> bytes:
    """
    Скачивает и распаковывает bz2 файл
    :param url: URL для скачивания
    :return: Распакованные данные
    :raises: Exception при неудачных попытках скачивания
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return bz2.decompress(response.content)
        except Timeout:
            if attempt == MAX_RETRIES - 1:
                print(f"Превышено время ожидания запроса к {url}")
                raise
            print(f"Таймаут запроса. Повторная попытка {attempt + 1}...")
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                print(f"Ошибка при загрузке {url}: {str(e)}")
                raise
            print(f"Ошибка загрузки. Повторная попытка {attempt + 1}...")


def parse_usn_oval(data: bytes) -> Set[str]:
    """
    Парсит USN OVAL файл и возвращает CVE с датой выпуска >= MIN_DATE
    :param data: XML данные
    :return: Множество CVE
    """
    root = etree.fromstring(data)
    usn_cves = set()

    for definition in root.xpath('.//oval:definition', namespaces=OVAL_NAMESPACE):
        metadata = definition.find('oval:metadata', namespaces=OVAL_NAMESPACE)
        if metadata is None:
            continue

        advisory = metadata.find('oval:advisory', namespaces=OVAL_NAMESPACE)
        if advisory is None:
            continue

        # Проверяем дату выпуска (issued date)
        issued = advisory.find('oval:issued', namespaces=OVAL_NAMESPACE)
        if issued is None or 'date' not in issued.attrib:
            continue

        try:
            advisory_date = datetime.strptime(issued.get('date'), "%Y-%m-%d")
            if advisory_date < MIN_DATE:
                continue
        except ValueError:
            continue

        # Добавляем все CVE из этого advisory
        for cve_elem in advisory.findall('oval:cve', namespaces=OVAL_NAMESPACE):
            if cve_elem.text:
                usn_cves.add(cve_elem.text.strip())

    return usn_cves


def save_result(data: Set[str]) -> None:
    """
    Сохраняет финальный результат в файл
    :param data: Множество строк для сохранения
    """
    with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as f:
        f.write("\n".join(sorted(data)) + "\n")
    print(f"Сохранено {len(data)} CVE в {OUTPUT_FILENAME}")


def main():
    start_time = datetime.now()

    try:
        # USN OVAL
        print("Загрузка и обработка USN OVAL файла...")
        usn_data = download_and_decompress(USN_OVAL_URL)
        filtered_cves = parse_usn_oval(usn_data)
        print(f"Найдено {len(filtered_cves)} CVE")
        save_result(filtered_cves)

    except Exception as e:
        print(f"Ошибка: {str(e)}")
    finally:
        print(f"Выполнение заняло: {datetime.now() - start_time}")


if __name__ == "__main__":
    main()
