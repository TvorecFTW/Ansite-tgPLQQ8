from flask import Flask, request, jsonify, render_template, send_file
import requests
import whois
import socket
import dns.resolver
import ssl
import os
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
import hashlib
import html2text
from bs4 import BeautifulSoup
import re
import csv
import io
import time
from flask_cors import CORS
from functools import lru_cache
import concurrent.futures

app = Flask(__name__)
CORS(app)

# База данных уязвимостей портов
PORT_VULNERABILITIES = {
    21: {
        "name": "FTP",
        "vulnerabilities": ["Слабые учетные данные", "Передача данных в открытом виде", "Анонимный доступ"],
        "attacks": ["Брутфорс-атака", "Перехват трафика", "Несанкционированный доступ"],
        "risk": "high"
    },
    22: {
        "name": "SSH",
        "vulnerabilities": ["Уязвимости в реализации SSH", "Слабые пароли", "Устаревшие версии"],
        "attacks": ["Брутфорс-атака", "RCE атаки", "Перехват сессий"],
        "risk": "medium"
    },
    23: {
        "name": "Telnet",
        "vulnerabilities": ["Полное отсутствие шифрования", "Аутентификация в открытом виде"],
        "attacks": ["Перехват трафика", "MITM атака", "Брутфорс-атака"],
        "risk": "critical"
    },
    25: {
        "name": "SMTP",
        "vulnerabilities": ["Неправильная конфигурация", "Ретрансляция спама"],
        "attacks": ["Спам-рассылки", "Фишинг", "Перебор пользователей"],
        "risk": "medium"
    },
    53: {
        "name": "DNS",
        "vulnerabilities": ["Слабая конфигурация", "Открытый резолвер"],
        "attacks": ["DNS-спуфинг", "DDoS амплификация", "Отравление кэша"],
        "risk": "high"
    },
    80: {
        "name": "HTTP",
        "vulnerabilities": ["Уязвимости веб-сервера", "Небезопасные приложения"],
        "attacks": ["SQL-инъекция", "XSS", "CSRF", "Path Traversal"],
        "risk": "medium"
    },
    110: {
        "name": "POP3",
        "vulnerabilities": ["Передача данных в открытом виде"],
        "attacks": ["Перехват учетных данных", "Брутфорс-атака"],
        "risk": "high"
    },
    135: {
        "name": "RPC",
        "vulnerabilities": ["Уязвимости в RPC службах"],
        "attacks": ["Удаленное выполнение кода", "Перечисление служб"],
        "risk": "high"
    },
    139: {
        "name": "NetBIOS",
        "vulnerabilities": ["Уязвимости SMB", "Небезопасные настройки"],
        "attacks": ["Распространение ransomware", "RCE", "Перехват NTLM-хешей"],
        "risk": "critical"
    },
    143: {
        "name": "IMAP",
        "vulnerabilities": ["Передача данных в открытом виде"],
        "attacks": ["Перехват писем", "Перехват учетных данных"],
        "risk": "high"
    },
    443: {
        "name": "HTTPS",
        "vulnerabilities": ["Устаревшие SSL/TLS", "Слабые шифры"],
        "attacks": ["MITM атака", "Downgrade атака", "Уязвимости приложений"],
        "risk": "medium"
    },
    445: {
        "name": "SMB",
        "vulnerabilities": ["Уязвимости реализации SMB"],
        "attacks": ["EternalBlue", "Удаленное выполнение кода"],
        "risk": "critical"
    },
    1433: {
        "name": "MSSQL",
        "vulnerabilities": ["Уязвимости СУБД", "Слабые пароли sa"],
        "attacks": ["SQL-инъекция", "Брутфорс-атака"],
        "risk": "high"
    },
    3306: {
        "name": "MySQL",
        "vulnerabilities": ["Уязвимости СУБД", "Стандартные учетные записи"],
        "attacks": ["Брутфорс-атака", "SQL-инъекция"],
        "risk": "high"
    },
    3389: {
        "name": "RDP",
        "vulnerabilities": ["Уязвимости реализации RDP", "Слабые пароли"],
        "attacks": ["Брутфорс-атака", "Удаленное выполнение кода"],
        "risk": "critical"
    },
    5432: {
        "name": "PostgreSQL",
        "vulnerabilities": ["Небезопасная конфигурация"],
        "attacks": ["Брутфорс-атака", "Выполнение команд"],
        "risk": "high"
    },
    5900: {
        "name": "VNC",
        "vulnerabilities": ["Слабые пароли", "Передача данных в открытом виде"],
        "attacks": ["Брутфорс-атака", "Перехват сессий"],
        "risk": "critical"
    },
    6379: {
        "name": "Redis",
        "vulnerabilities": ["Работа без аутентификации"],
        "attacks": ["Запись файлов (RCE)", "Несанкционированный доступ"],
        "risk": "critical"
    },
    27017: {
        "name": "MongoDB",
        "vulnerabilities": ["Работа без аутентификации"],
        "attacks": ["Несанкционированный доступ", "Шифрование данных"],
        "risk": "high"
    }
}

# Конфигурация
DEFAULT_VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', "YOUR_API_KEY")
MAX_DEPTH = 2
TIMEOUT = 8  # Уменьшил таймаут для Vercel
MAX_URL_LENGTH = 2048
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Валидация URL
def validate_url(url):
    if not url:
        return False, "URL не может быть пустым"
    
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL слишком длинный (максимум {MAX_URL_LENGTH} символов)"
    
    try:
        parsed = urlparse(url)
        if not parsed.scheme in ('http', 'https'):
            return False, "URL должен начинаться с http:// или https://"
        
        if not parsed.netloc:
            return False, "Некорректный домен"
            
        # Проверка на локальные адреса и приватные сети
        domain = extract_domain(url)
        try:
            ip = socket.gethostbyname(domain)
            if ip.startswith(('127.', '10.', '172.16.', '192.168.')):
                return False, "Локальные и приватные IP адреса не разрешены"
        except:
            pass
            
        return True, "OK"
    except Exception as e:
        return False, f"Некорректный URL: {str(e)}"

# Безопасное извлечение домена
def extract_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.split(':')[0].split('/')[0]
        
        # Базовая проверка домена
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            raise ValueError("Некорректный домен")
            
        return domain
    except Exception as e:
        raise ValueError(f"Не удалось извлечь домен: {str(e)}")

# Функции анализа
def get_html(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=True)
        response.raise_for_status()
        return response.text
    except requests.exceptions.SSLError:
        try:
            response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            return response.text
        except Exception as e:
            raise Exception(f"Ошибка при получении HTML (SSL): {str(e)}")
    except Exception as e:
        raise Exception(f"Ошибка при получении HTML: {str(e)}")

@lru_cache(maxsize=100)
def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        
        # Проверка на приватные IP
        if ip.startswith(('127.', '10.', '172.16.', '192.168.')):
            return {"info": "Приватный IP адрес"}
        
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
        except socket.herror:
            hostname, aliases = ip, []
        
        # Упрощаем для Vercel (убираем параллельные запросы которые могут падать)
        geolocation = get_geo_info(ip)
        open_ports = scan_ports(ip, [80, 443])  # Только основные порты
        
        return {
            "ip_address": ip,
            "hostname": hostname,
            "aliases": aliases,
            "open_ports": open_ports,
            "geolocation": geolocation
        }
    except Exception as e:
        return {"error": f"Ошибка при получении IP информации: {str(e)}"}

def scan_ports(ip, ports_to_scan=None):
    if ports_to_scan is None:
        # Сканируем все порты из базы уязвимостей
        ports_to_scan = list(PORT_VULNERABILITIES.keys())
    
    open_ports = {}
    
    for port in ports_to_scan:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # Порт открыт, добавляем информацию об уязвимостях
                    port_info = PORT_VULNERABILITIES.get(port, {
                        "name": "Unknown",
                        "vulnerabilities": ["Неизвестная служба"],
                        "attacks": ["Рекомендуется дальнейшее исследование"],
                        "risk": "unknown"
                    })
                    
                    open_ports[port] = {
                        "status": "open",
                        "service": port_info["name"],
                        "risk_level": port_info["risk"],
                        "vulnerabilities": port_info["vulnerabilities"],
                        "possible_attacks": port_info["attacks"],
                        "recommendations": generate_recommendations(port, port_info["risk"])
                    }
        except:
            continue
    
    return open_ports

def generate_recommendations(port, risk_level):
    recommendations = []
    
    if risk_level == "critical":
        recommendations.append("НЕМЕДЛЕННО ЗАКРОЙТЕ порт или настройте строгую аутентификацию")
        recommendations.append("Используйте VPN для доступа вместо открытого порта")
    elif risk_level == "high":
        recommendations.append("Рекомендуется закрыть порт или использовать брандмауэр")
        recommendations.append("Обновите ПО до последней версии")
    elif risk_level == "medium":
        recommendations.append("Настройте корректную аутентификацию")
        recommendations.append("Ограничьте доступ по IP адресам")
    else:
        recommendations.append("Мониторьте активность на порту")
    
    if port in [21, 22, 23, 110, 143, 5900]:
        recommendations.append("Используйте SSH туннелирование или VPN")
    if port in [3389, 5900]:
        recommendations.append("Рассмотрите альтернативные решения для удаленного доступа")
    
    return recommendations

def get_geo_info(ip):
    try:
        # Проверяем на приватные IP
        if ip.startswith(('127.', '10.', '172.16.', '192.168.')):
            return {"error": "Приватный IP адрес"}
            
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data['status'] == 'success':
            return {
                "country": data.get('country', 'N/A'),
                "region": data.get('regionName', 'N/A'),
                "city": data.get('city', 'N/A'),
                "isp": data.get('isp', 'N/A'),
                "org": data.get('org', 'N/A'),
                "lat": data.get('lat', 'N/A'),
                "lon": data.get('lon', 'N/A')
            }
        return {"error": "Геоданные не найдены"}
    except Exception as e:
        return {"error": f"Не удалось получить геоданные: {str(e)}"}

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        if not w:
            return {"error": "Информация WHOIS не найдена"}
        
        result = {}
        for key, value in w.items():
            if not key.startswith('_') and value:
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value if v)
                result[key] = str(value)
        
        # Если результат пустой, возвращаем ошибку
        if not result:
            return {"error": "WHOIS информация недоступна для этого домена"}
            
        return result
    except Exception as e:
        return {"error": f"Ошибка WHOIS: {str(e)}"}

def check_virustotal(domain, api_key=None):
    # Если API ключ не передан, используем дефолтный
    if not api_key:
        api_key = DEFAULT_VIRUSTOTAL_API_KEY
        
    if not api_key or api_key == "YOUR_API_KEY":
        return {"error": "Необходимо указать API ключ VirusTotal"}
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            return {
                "reputation": data.get('data', {}).get('attributes', {}).get('reputation', 'N/A'),
                "stats": data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}),
                "categories": data.get('data', {}).get('attributes', {}).get('categories', {}),
                "last_analysis_date": data.get('data', {}).get('attributes', {}).get('last_analysis_date', 'N/A')
            }
        elif response.status_code == 404:
            return {"error": "Домен не найден в базе VirusTotal"}
        else:
            return {"error": f"Ошибка запроса к VirusTotal: {response.status_code}"}
    except Exception as e:
        return {"error": f"Ошибка VirusTotal: {str(e)}"}

def save_web_snapshot(url):
    try:
        html = get_html(url)
        domain = extract_domain(url)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Безопасное имя файла
        safe_domain = re.sub(r'[^a-zA-Z0-9]', '_', domain)
        filename = f"{safe_domain}_{timestamp}.html"
        
        # Сохраняем во временную директорию Vercel
        os.makedirs("/tmp/snapshots", exist_ok=True)
        filepath = f"/tmp/snapshots/{filename}"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
            
        text = html2text.html2text(html)
        text_filename = f"{safe_domain}_{timestamp}.txt"
        text_filepath = f"/tmp/snapshots/{text_filename}"
        
        with open(text_filepath, "w", encoding="utf-8") as f:
            f.write(text)
            
        return {
            "html_file": filename,
            "text_file": text_filename,
            "html_size": f"{len(html)/1024:.2f} KB",
            "md5_hash": hashlib.md5(html.encode()).hexdigest()
        }
    except Exception as e:
        return {"error": f"Ошибка при сохранении снимка: {str(e)}"}

def recursive_parse(url, visited=None, depth=0):
    if visited is None:
        visited = set()
    
    if depth > MAX_DEPTH or url in visited:
        return []
    
    visited.add(url)
    results = []
    
    try:
        html = get_html(url)
        soup = BeautifulSoup(html, 'html.parser')
        
        page_data = {
            "url": url,
            "title": soup.title.string if soup.title else "Без заголовка",
            "meta_description": get_meta_description(soup),
            "links_count": len(soup.find_all('a')),
            "images_count": len(soup.find_all('img')),
            "forms_count": len(soup.find_all('form')),
            "js_files": get_js_files(soup),
            "css_files": get_css_files(soup),
            "headers": get_headers_info(html)
        }
        
        links = set()
        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(url, link['href'])
            if absolute_url.startswith(('http://', 'https://')):
                links.add(absolute_url)
        
        page_data["sample_links"] = list(links)[:5]
        results.append(page_data)
        
        if depth < MAX_DEPTH:
            for link in list(links)[:2]:  # Уменьшил количество ссылок для анализа
                sub_results = recursive_parse(link, visited, depth+1)
                results.extend(sub_results)
        
    except Exception as e:
        results.append({"url": url, "error": str(e)})
    
    return results

def get_meta_description(soup):
    meta = soup.find('meta', attrs={'name': 'description'})
    return meta['content'] if meta and 'content' in meta.attrs else "Не найдено"

def get_js_files(soup):
    scripts = soup.find_all('script', src=True)
    return [script['src'] for script in scripts if script['src']]

def get_css_files(soup):
    links = soup.find_all('link', rel='stylesheet')
    return [link['href'] for link in links if link['href']]

def get_headers_info(html):
    try:
        soup = BeautifulSoup(html, 'html.parser')
        headers = {}
        meta_tags = soup.find_all('meta')
        
        for meta in meta_tags:
            if meta.get('name'):
                headers[f"meta_{meta.get('name')}"] = meta.get('content', '')
            elif meta.get('property'):
                headers[f"og_{meta.get('property')}"] = meta.get('content', '')
        
        for i in range(1, 7):
            h_tags = soup.find_all(f'h{i}')
            headers[f'h{i}_count'] = len(h_tags)
            if h_tags:
                headers[f'h{i}_sample'] = h_tags[0].get_text()[:100]
        
        return headers
    except:
        return {}

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')
                
                def parse_name(name):
                    if isinstance(name, str):
                        return name
                    if isinstance(name, tuple):
                        return dict(x[0] for x in name)
                    return str(name)
                
                return {
                    "issuer": parse_name(cert.get('issuer', 'N/A')),
                    "subject": parse_name(cert.get('subject', 'N/A')),
                    "version": cert.get('version', 'N/A'),
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "serial_number": cert.get('serialNumber', 'N/A'),
                    "signature_algorithm": cert.get('signatureAlgorithm', 'N/A'),
                    "san": get_san(cert)
                }
    except Exception as e:
        return {"error": f"Ошибка SSL: {str(e)}"}

def get_san(cert):
    if not cert:
        return []
    
    san = []
    for field in cert.get('subjectAltName', []):
        if field[0].lower() == 'dns':
            san.append(field[1])
    return san or ["Не найдены"]

def get_dns_records(domain):
    try:
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                # ИСПОЛЬЗУЕМ ПРАВИЛЬНОЕ ИМЯ - dns.resolver
                answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
                if answers.rrset:
                    records[record_type] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception as e:
                records[record_type] = f"Ошибка: {str(e)}"
                
        return records if records else {"info": "DNS записи не найдены"}
    except Exception as e:
        return {"error": f"Ошибка DNS: {str(e)}"}
    
def get_ip_neighbors(domain):
    try:
        ip = socket.gethostbyname(domain)
        
        # Не проверяем соседей для приватных IP
        if ip.startswith(('127.', '10.', '172.16.', '192.168.')):
            return {"error": "Приватные IP адреса не поддерживаются"}
        
        base_ip = '.'.join(ip.split('.')[:3])
        neighbors = []
        
        # Проверяем только несколько соседей для производительности
        ranges_to_check = [-2, -1, 1, 2]
        
        for i in ranges_to_check:
            last_octet = int(ip.split('.')[-1]) + i
            if 1 <= last_octet <= 254:
                neighbor_ip = f"{base_ip}.{last_octet}"
                if neighbor_ip != ip:
                    try:
                        host = socket.gethostbyaddr(neighbor_ip)[0]
                        neighbors.append({
                            "ip": neighbor_ip,
                            "hostname": host,
                            "ports": scan_ports(neighbor_ip, [80, 443])
                        })
                    except:
                        continue
        
        return neighbors if neighbors else {"error": "Соседние IP не найдены"}
    except Exception as e:
        return {"error": f"Ошибка поиска соседей: {str(e)}"}

def get_website_metrics(url):
    try:
        start_time = time.time()
        html = get_html(url)
        load_time = time.time() - start_time
        
        soup = BeautifulSoup(html, 'html.parser')
        text_content = soup.get_text()
        word_count = len(text_content.split())
        char_count = len(text_content)
        
        return {
            "load_time": f"{load_time:.3f} секунд",
            "word_count": word_count,
            "char_count": char_count,
            "page_size": f"{len(html)/1024:.2f} KB",
            "encoding": soup.original_encoding or "unknown"
        }
    except Exception as e:
        return {"error": f"Ошибка анализа метрик: {str(e)}"}

# Обертка для всех API функций с обработкой ошибок
def safe_api_call(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as e:
        return {"error": f"Внутренняя ошибка сервера: {str(e)}"}

# Маршруты API
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/quick_scan', methods=['GET'])
def quick_scan():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        
        # Параллельное выполнение запросов
        with concurrent.futures.ThreadPoolExecutor() as executor:
            whois_future = executor.submit(safe_api_call, get_whois_info, domain)
            ip_future = executor.submit(safe_api_call, get_ip_info, domain)
            dns_future = executor.submit(safe_api_call, get_dns_records, domain)
            ssl_future = executor.submit(safe_api_call, get_ssl_info, domain)
            vt_future = executor.submit(safe_api_call, check_virustotal, domain, DEFAULT_VIRUSTOTAL_API_KEY)
            metrics_future = executor.submit(safe_api_call, get_website_metrics, url)
            security_future = executor.submit(safe_api_call, security_scan, domain)
            
            results = {
                'whois': whois_future.result(timeout=TIMEOUT),
                'ip_info': ip_future.result(timeout=TIMEOUT),
                'dns_records': dns_future.result(timeout=TIMEOUT),
                'ssl_certificate': ssl_future.result(timeout=TIMEOUT),
                'virustotal': vt_future.result(timeout=TIMEOUT),
                'metrics': metrics_future.result(timeout=TIMEOUT),
                'security_scan': security_future.result(timeout=TIMEOUT)
            }
        
        return jsonify(results)
    except concurrent.futures.TimeoutError:
        return jsonify({'error': 'Таймаут при выполнении анализа'}), 408
    except Exception as e:
        return jsonify({'error': f'Ошибка при выполнении анализа: {str(e)}'}), 500

@app.route('/api/whois', methods=['GET'])
def whois_route():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        return jsonify({'whois': safe_api_call(get_whois_info, domain)})
    except Exception as e:
        return jsonify({'error': f'Ошибка WHOIS: {str(e)}'}), 500

@app.route('/api/ip_info', methods=['GET'])
def ip_info():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        return jsonify({'ip_info': safe_api_call(get_ip_info, domain)})
    except Exception as e:
        return jsonify({'error': f'Ошибка IP информации: {str(e)}'}), 500



@app.route('/api/security_scan', methods=['GET'])
def security_scan_route():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        return jsonify({'security_scan': safe_api_call(security_scan, domain)})
    except Exception as e:
        return jsonify({'error': f'Ошибка сканирования безопасности: {str(e)}'}), 500

def security_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
        
        # Проверка на приватные IP
        if ip.startswith(('127.', '10.', '172.16.', '192.168.')):
            return {"error": "Приватные IP адреса не поддерживаются для сканирования"}
        
        # Сканируем все опасные порты
        open_ports = scan_ports(ip)
        
        # Получаем дополнительную информацию
        geo_info = get_geo_info(ip)
        ssl_info = get_ssl_info(domain)
        
        # Анализ безопасности
        security_analysis = analyze_security(open_ports, ssl_info)
        
        return {
            "target_ip": ip,
            "target_domain": domain,
            "open_ports": open_ports,
            "geolocation": geo_info,
            "ssl_security": ssl_info,
            "security_analysis": security_analysis,
            "scan_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {"error": f"Ошибка сканирования безопасности: {str(e)}"}
@app.route('/api/virustotal', methods=['GET'])
def analyze_security(open_ports, ssl_info):
    analysis = {
        "critical_issues": 0,
        "high_issues": 0,
        "medium_issues": 0,
        "total_ports_open": len(open_ports),
        "recommendations": []
    }
    
    # Анализ открытых портов
    for port, info in open_ports.items():
        if info["risk_level"] == "critical":
            analysis["critical_issues"] += 1
            analysis["recommendations"].append(f"КРИТИЧЕСКИЙ: Закройте порт {port} ({info['service']})")
        elif info["risk_level"] == "high":
            analysis["high_issues"] += 1
            analysis["recommendations"].append(f"ВЫСОКИЙ РИСК: Проверьте порт {port} ({info['service']})")
        elif info["risk_level"] == "medium":
            analysis["medium_issues"] += 1
    
    # Анализ SSL
    if isinstance(ssl_info, dict) and not ssl_info.get("error"):
        # Проверяем срок действия SSL
        if "valid_until" in ssl_info:
            try:
                valid_until = datetime.strptime(ssl_info["valid_until"], "%b %d %H:%M:%S %Y GMT")
                if valid_until < datetime.now():
                    analysis["critical_issues"] += 1
                    analysis["recommendations"].append("КРИТИЧЕСКИЙ: SSL сертификат просрочен")
            except:
                pass
    
    # Общая оценка безопасности
    if analysis["critical_issues"] > 0:
        analysis["security_level"] = "CRITICAL"
        analysis["summary"] = "Обнаружены критические уязвимости!"
    elif analysis["high_issues"] > 0:
        analysis["security_level"] = "HIGH"
        analysis["summary"] = "Высокий уровень риска"
    elif analysis["medium_issues"] > 0:
        analysis["security_level"] = "MEDIUM"
        analysis["summary"] = "Средний уровень риска"
    else:
        analysis["security_level"] = "LOW"
        analysis["summary"] = "Низкий уровень риска"
    
    return analysis
    
def virustotal():
    url = request.args.get('url')
    api_key = request.args.get('api_key', DEFAULT_VIRUSTOTAL_API_KEY)
    
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        return jsonify({'virustotal': safe_api_call(check_virustotal, domain, api_key)})
    except Exception as e:
        return jsonify({'error': f'Ошибка VirusTotal: {str(e)}'}), 500

@app.route('/api/dns', methods=['GET'])
def dns():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        return jsonify({'dns_records': safe_api_call(get_dns_records, domain)})
    except Exception as e:
        return jsonify({'error': f'Ошибка DNS: {str(e)}'}), 500

@app.route('/api/ssl', methods=['GET'])
def ssl_route():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        return jsonify({'ssl_certificate': safe_api_call(get_ssl_info, domain)})
    except Exception as e:
        return jsonify({'error': f'Ошибка SSL: {str(e)}'}), 500

@app.route('/api/ip_neighbors', methods=['GET'])
def ip_neighbors():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        return jsonify({'ip_neighbors': safe_api_call(get_ip_neighbors, domain)})
    except Exception as e:
        return jsonify({'error': f'Ошибка поиска соседей: {str(e)}'}), 500

@app.route('/api/snapshot', methods=['GET'])
def snapshot():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        return jsonify({'snapshot': safe_api_call(save_web_snapshot, url)})
    except Exception as e:
        return jsonify({'error': f'Ошибка создания снимка: {str(e)}'}), 500

@app.route('/api/deep_analysis', methods=['GET'])
def deep_analysis():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        return jsonify({'deep_analysis': safe_api_call(recursive_parse, url)})
    except Exception as e:
        return jsonify({'error': f'Ошибка глубокого анализа: {str(e)}'}), 500

@app.route('/api/metrics', methods=['GET'])
def metrics():
    url = request.args.get('url')
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        return jsonify({'metrics': safe_api_call(get_website_metrics, url)})
    except Exception as e:
        return jsonify({'error': f'Ошибка метрик: {str(e)}'}), 500

@app.route('/api/export', methods=['GET'])
def export_report():
    url = request.args.get('url')
    format_type = request.args.get('format', 'json')
    
    is_valid, message = validate_url(url)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    try:
        domain = extract_domain(url)
        data = {
            'url': url,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'whois': safe_api_call(get_whois_info, domain),
            'ip_info': safe_api_call(get_ip_info, domain),
            'dns_records': safe_api_call(get_dns_records, domain),
            'ssl_certificate': safe_api_call(get_ssl_info, domain),
            'metrics': safe_api_call(get_website_metrics, url)
        }
        
        if format_type == 'json':
            return jsonify(data)
        elif format_type == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            
            for key, value in data.items():
                if isinstance(value, dict):
                    writer.writerow([key])
                    for sub_key, sub_value in value.items():
                        writer.writerow([sub_key, str(sub_value)])
                    writer.writerow([])
                else:
                    writer.writerow([key, str(value)])
            
            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode()),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'{domain}_report.csv'
            )
        
        return jsonify({'error': 'Неподдерживаемый формат'}), 400
    except Exception as e:
        return jsonify({'error': f'Ошибка экспорта: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

# Добавьте в конец app.py перед запуском
if __name__ == '__main__':
    # Для Vercel timeout configuration
    from flask import Flask
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # Для локальной разработки
    app.run(debug=True)
