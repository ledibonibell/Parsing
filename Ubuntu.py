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

# URL для скачивания OVAL файлов
CVE_OVAL_URL = (
    "https://security-metadata.canonical.com/"
    "oval/com.ubuntu.jammy.cve.oval.xml.bz2"
)
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


def parse_cve_oval(data: bytes) -> Set[str]:
    """
    Парсит CVE OVAL файл и возвращает CVE с фиксом для версии 22.04.4
    :param data: XML данные
    :return: Множество CVE
    :raises: etree.ParseError: Если возникает ошибка парсинга XML
    """
    root = etree.fromstring(data)
    filtered_cves = set()

    for definition in root.xpath('.//oval:definition', namespaces=OVAL_NAMESPACE):
        metadata = definition.find('oval:metadata', namespaces=OVAL_NAMESPACE)
        if metadata is None:
            continue

        advisory = metadata.find('oval:advisory', namespaces=OVAL_NAMESPACE)
        if advisory is None:
            continue

        criteria = definition.find('.//oval:criteria', namespaces=OVAL_NAMESPACE)
        found_fixed = False
        found_version = False

        if criteria is not None:
            for node in criteria.iter():
                comment = node.get('comment', '').lower()
                if 'has been fixed' in comment:
                    found_fixed = True
                if OS_VERSION in comment:
                    found_version = True

        if not (found_fixed and found_version):
            continue

        for cve_elem in advisory.findall('oval:cve', namespaces=OVAL_NAMESPACE):
            if cve_elem.text:
                filtered_cves.add(cve_elem.text.strip())

    return filtered_cves


def parse_usn_oval(data: bytes) -> Set[str]:
    """
    Парсит USN OVAL файл и возвращает все CVE
    :param data: XML данные
    :return: Множество CVE
    """
    root = etree.fromstring(data)
    usn_cves = set()

    for definition in root.xpath('.//oval:definition', namespaces=OVAL_NAMESPACE):
        metadata = definition.find('oval:metadata', namespaces=OVAL_NAMESPACE)
        if metadata is None:
            continue

        # CVE из <reference>
        for ref in metadata.findall('oval:reference', namespaces=OVAL_NAMESPACE):
            if ref.get("source") == "CVE" and ref.get("ref_id"):
                usn_cves.add(ref.get("ref_id").strip())

        # CVE из <advisory><cve>
        advisory = metadata.find('oval:advisory', namespaces=OVAL_NAMESPACE)
        if advisory is not None:
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
        # CVE OVAL
        print("Загрузка и обработка CVE OVAL файла...")
        cve_data = download_and_decompress(CVE_OVAL_URL)
        filtered_cves = parse_cve_oval(cve_data)
        print(f"[CVE] Найдено {len(filtered_cves)} CVE с фиксом для {OS_VERSION}")

        # USN OVAL
        print("Загрузка и обработка USN OVAL файла...")
        usn_data = download_and_decompress(USN_OVAL_URL)
        usn_cves = parse_usn_oval(usn_data)
        print(f"[USN] Найдено {len(usn_cves)} уникальных CVE")

        # Пересечение для поиска нужного
        intersection = filtered_cves.intersection(usn_cves)
        print(f"Найдено {len(intersection)} CVE в обоих файлах")
        save_result(intersection)

    except Exception as e:
        print(f"Ошибка: {str(e)}")
    finally:
        print(f"Выполнение заняло: {datetime.now() - start_time}")


if __name__ == "__main__":
    main()