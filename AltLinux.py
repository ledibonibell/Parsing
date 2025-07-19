import requests
import zipfile
import io
from lxml import etree
from datetime import datetime
from typing import List, Tuple
from requests.exceptions import Timeout

OVAL_URL = "https://rdb.altlinux.org/api/errata/export/oval/p10?one_file=true"
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
OUTPUT_FILE = "ALT_Workstation_10.1_bulletin.txt"
NAMESPACES = {'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'}

START_DATE = datetime(2023, 1, 31)
END_DATE = datetime(2024, 3, 13)
TARGET_CPE = "cpe:/o:alt:workstation:10"


def download_and_extract_zip(url: str) -> str:
    """
    Скачивает ZIP-архив и извлекает XML
    :param url: URL для скачивания
    :return: Содержимое XML файла
    :raises:
        ValueError: Если в ZIP-архиве нет XML файлов.
        requests.exceptions.RequestException: При ошибках запроса.
    """
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Скачивание ZIP-архива (попытка {attempt + 1})")
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()

            print("Извлечение XML из ZIP")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                xml_files = [f for f in zip_file.namelist() if f.endswith('.xml')]
                if not xml_files:
                    raise ValueError("В ZIP-архиве не найдено XML файлов")

                with zip_file.open(xml_files[0]) as xml_file:
                    return xml_file.read().decode('utf-8')

        except Timeout:
            if attempt == MAX_RETRIES - 1:
                raise
            print(f"Таймаут запроса. Повторная попытка {attempt + 1}")
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            print(f"Ошибка: {str(e)}. Повторная попытка {attempt + 1}")


def parse_date(date_str: str) -> datetime:
    """
    Парсит дату из строки формата YYYY-MM-DD
    :param date_str: Строка с датой
    :return: Объект datetime или None
    """
    try:
        return datetime.strptime(date_str, "%Y-%m-%d") if date_str else None
    except ValueError:
        return None


def is_cve_in_date_range(cve_date: str) -> bool:
    """
    Проверяет, находится ли дата CVE в заданном диапазоне
    :param cve_date: Строка с датой CVE
    :return: True если дата в диапазоне
    """
    date = parse_date(cve_date)
    return date is not None and START_DATE <= date <= END_DATE


def has_target_cpe(advisory) -> bool:
    """
    Проверяет наличие нужного CPE в advisory
    :param advisory: Элемент advisory из OVAL
    :return: True если CPE совпадает
    """
    if advisory is None:
        return False

    cpe_list = advisory.find('.//oval:affected_cpe_list', namespaces=NAMESPACES)
    if cpe_list is None:
        return False

    return any(cpe.text and cpe.text.strip() == TARGET_CPE
               for cpe in cpe_list.findall('.//oval:cpe', namespaces=NAMESPACES))


def get_cve_info(metadata, advisory) -> List[Tuple[str, str]]:
    """
    Извлекает информацию о CVE с учетом фильтров
    :param metadata: Элемент metadata из OVAL
    :param advisory: Элемент advisory из OVAL
    :return: Список кортежей (CVE_ID, дата)
    """
    cves = []

    # Обработка reference элементов
    for ref in metadata.findall('oval:reference', namespaces=NAMESPACES):
        if ref.get('source') == 'CVE' and ref.get('ref_id'):
            cve_id = ref.get('ref_id')
            issued_elem = advisory.find('oval:issued', namespaces=NAMESPACES) \
                if advisory is not None else None
            updated_elem = advisory.find('oval:updated', namespaces=NAMESPACES) \
                if advisory is not None else None

            issued_date = issued_elem.get('date') \
                if issued_elem is not None else None
            updated_date = updated_elem.get('date') \
                if updated_elem is not None else None

            if (is_cve_in_date_range(issued_date) or
                is_cve_in_date_range(updated_date)):
                cves.append((cve_id, issued_date or updated_date))

    # Обработка cve элементов в advisory
    if advisory is not None:
        for cve in advisory.findall('oval:cve', namespaces=NAMESPACES):
            if cve.text:
                cve_id = cve.text.strip()
                cve_date = cve.get('public')
                if is_cve_in_date_range(cve_date):
                    cves.append((cve_id, cve_date))

    return cves


def extract_filtered_cves(xml_content: str) -> List[Tuple[str, str]]:
    """
    Извлекает CVE с учётом фильтров
    :param xml_content: XML строка
    :return: Отсортированный список уникальных CVE
    """
    root = etree.fromstring(xml_content.encode('utf-8'))
    filtered_cves = []
    definition_count = 0

    for definition in root.xpath('//oval:definition', namespaces=NAMESPACES):
        definition_count += 1
        metadata = definition.find('oval:metadata', namespaces=NAMESPACES)
        if metadata is None:
            continue

        advisory = definition.find('.//oval:advisory', namespaces=NAMESPACES)
        if not has_target_cpe(advisory):
            continue

        filtered_cves.extend(get_cve_info(metadata, advisory))

    print(f"[Parse] Обработано {definition_count} definition элементов")
    print(f"[Parse] Найдено {len(filtered_cves)} CVE после первичной фильтрации")

    # Удаляем дубликаты и сортируем
    unique_cves = {cve_id: date for cve_id, date in filtered_cves}
    return sorted(unique_cves.items(),
                 key=lambda x: (parse_date(x[1]) or datetime.min, x[0]),
                 reverse=True)


def save_results(cves: List[Tuple[str, str]], filename: str) -> None:
    """
    Сохраняет результаты в файл
    :param cves: Список CVE
    :param filename: Имя файла для сохранения
    """
    with open(filename, 'w', encoding='utf-8') as f:
        for cve_id, date in cves:
            f.write(f"{cve_id}\n")
    print(f"[Save] Сохранено {len(cves)} CVE в {filename}")


def main():
    start_time = datetime.now()

    try:
        xml_content = download_and_extract_zip(OVAL_URL)
        filtered_cves = extract_filtered_cves(xml_content)
        save_results(filtered_cves, OUTPUT_FILE)

    except Exception as e:
        print(f"Ошибка запроса: {str(e)}")
    finally:
        print(f"Выполнение заняло: {datetime.now() - start_time}")


if __name__ == "__main__":
    main()