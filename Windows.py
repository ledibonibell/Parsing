import requests
from datetime import datetime, timezone
from typing import Set
from requests.exceptions import Timeout

START_DATE = datetime(2015, 1, 1, tzinfo=timezone.utc)  # Дата начала сбора статистики
PLATFORM_ID = "12099%27,%2712098%27,%2712097"
PRODUCT_FAMILY_ID = 100000010
OS_NAME = "windows_10"
OS_VERSION = "10.0.19045"
MAX_RETRIES = 5
REQUEST_TIMEOUT = 5


def get_vulnerabilities_page(
        start_date: datetime,
        end_date: datetime = datetime.now(timezone.utc),
        skip: int = 0
) -> list:
    """
    Получает одну страницу с уязвимостями (500 записей)
    :param start_date: дата с которой начинаются парситься уязвимости
    :param end_date: дата конца парсинга уязвимости (по умолчанию текущая дата)
    :param skip: пропуск полученных ранее значений
    """
    date_format = "%Y-%m-%dT%H:%M:%S.000Z"
    start_str = start_date.strftime(date_format)
    end_str = end_date.strftime(date_format)

    url = (
        f"https://api.msrc.microsoft.com/sug/v2.0/ru-RU/affectedProduct?"
        f"$orderBy=releaseDate%20desc&"
        f"$top=500&"
        f"$skip={skip}&"
        f"$filter=productFamilyId%20in%20(%27{PRODUCT_FAMILY_ID}%27)%20"
        f"and%20productId%20in%20(%27{PLATFORM_ID}%27)%20"
        f"and%20(releaseDate%20ge%20{start_str})%20"
        f"and%20(releaseDate%20le%20{end_str})"
    )

    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            return data.get('value', [])
        except Timeout:
            if attempt == MAX_RETRIES - 1:
                print(f"Превышено время ожидания запроса. Повторная попытка {attempt + 1}")
                return []
            print(f"Таймаут запроса. Повторная попытка {attempt + 1}...")
            continue
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                print(f"Ошибка при запросе. Попытка {attempt + 1}: {str(e)}")
                return []
            print(f"Ошибка запроса. Повторная попытка {attempt + 1}...")
            continue


def get_all_vulnerabilities(start_date: datetime, end_date: datetime) -> Set[str]:
    """
    Получает все уязвимости за период (с обработкой пагинации)
    start_date: Дата начала периода для поиска уязвимостей
    end_date: Дата конца периода для поиска уязвимостей
    """
    all_cves = set()
    skip = 0

    while True:
        vulnerabilities = get_vulnerabilities_page(start_date, end_date, skip)

        if not vulnerabilities:
            break

        page_cves = {
            vuln['cveNumber'] for vuln in vulnerabilities
            if vuln.get('cveNumber', '').startswith('CVE-')
        }

        all_cves.update(page_cves)

        if len(vulnerabilities) < 500:
            break

        skip += 500
        # Фильтруем только CVE (если значение не кратно 500, значит был мусор))
        print(f"Получено {len(all_cves)} уникальных CVE...")

    return all_cves


def save_cves_to_file(cves: Set[str]) -> None:
    """
    Сохраняет CVE в файл
    cves: Множество идентификаторов CVE для сохранения
    """
    filename = f"{OS_NAME}_{OS_VERSION}_bulletin.txt"
    sorted_cves = sorted(cves, reverse=True)

    with open(filename, 'w') as f:
        f.write("\n".join(sorted_cves))

    print(f"\nСохранено {len(sorted_cves)} CVE в файл {filename}")


def main():
    # start_time = datetime.now()

    try:

        end_date = datetime.now(timezone.utc)
        cves = get_all_vulnerabilities(START_DATE, end_date)

        if not cves:
            print("Уязвимостей не найдено :(")
        else:
            save_cves_to_file(cves)

    except Exception as e:
        print(f"Ошибка запроса: {str(e)}")
    # finally:
    #     print(f"Выполнение заняло: {datetime.now() - start_time}")


if __name__ == "__main__":
    main()