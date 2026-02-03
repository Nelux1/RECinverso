#!/usr/bin/env python3
"""
Herramienta de Reconocimiento Inverso
Encuentra subdominios, dominios, ASN e infraestructura EC2 de una empresa
"""

import argparse
import sys
import json
import subprocess
import socket
import ipaddress
import re
from collections import defaultdict
from typing import List, Set, Dict
import dns.resolver
import dns.reversename
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import urllib.parse
import threading
from itertools import cycle

class Spinner:
    """Spinner para mostrar progreso"""
    def __init__(self, message="Procesando", delay=0.1):
        self.spinner_chars = cycle(['|', '/', '-', '\\'])
        self.message = message
        self.delay = delay
        self.busy = False
        self.spinner_thread = None
    
    def spin(self):
        while self.busy:
            sys.stdout.write(f'\r{next(self.spinner_chars)} {self.message}...')
            sys.stdout.flush()
            time.sleep(self.delay)
    
    def start(self, message=None):
        if message:
            self.message = message
        self.busy = True
        self.spinner_thread = threading.Thread(target=self.spin)
        self.spinner_thread.daemon = True
        self.spinner_thread.start()
    
    def stop(self, final_message=""):
        self.busy = False
        if self.spinner_thread:
            self.spinner_thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 10) + '\r')
        if final_message:
            sys.stdout.write(final_message + '\n')
        sys.stdout.flush()

class ReconInverso:
    def __init__(self, empresa: str, verbose: bool = False, random_agent: bool = False, 
                 threads: int = 20, output_file: str = None, max_ips: int = 1000,
                 max_ips_reverse: int = 200, max_domains_sub: int = 10,
                 max_ips_ec2: int = 100, skip_ownership_check: bool = False,
                 aws_cache_ttl: int = 3600):
        self.empresa = empresa.lower()
        self.verbose = verbose
        self.random_agent = random_agent
        self.threads = threads
        self.output_file = output_file
        self.max_ips = max_ips
        self.max_ips_reverse = max_ips_reverse
        self.max_domains_sub = max_domains_sub
        self.max_ips_ec2 = max_ips_ec2
        self.skip_ownership_check = skip_ownership_check
        self.aws_cache_ttl = aws_cache_ttl
        self.dominios_encontrados: Set[str] = set()
        self.subdominios_encontrados: Set[str] = set()
        self.ips_encontradas: Set[str] = set()
        self.asns_encontrados: Set[int] = set()
        self.ec2_instances: List[Dict] = []
        self.dominios_filtrados: int = 0  # Contador de dominios filtrados
        self.registrante_info: Dict[str, str] = {}  # Info del registrante del dominio principal
        self.counter_lock = threading.Lock()
        self.aws_ranges_cache = None
        self.aws_cache_time = 0.0
        
        # User agents para random
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
    def log(self, message: str):
        """Imprime mensajes con formato"""
        if self.verbose:
            print(f"[*] {message}")
    
    def print_progress(self, current: int, total: int, prefix: str = "Progreso"):
        """Imprime progreso con porcentaje"""
        if total > 0:
            percent = (current / total) * 100
            print(f"\r[{prefix}] {current}/{total} ({percent:.1f}%)", end='', flush=True)
            if current == total:
                print()  # Nueva línea al completar
    
    def print_result(self, message: str):
        """Imprime resultados"""
        print(f"[+] {message}")
    
    def print_error(self, message: str):
        """Imprime errores"""
        print(f"[-] {message}", file=sys.stderr)
    
    def get_headers(self) -> Dict[str, str]:
        """Obtiene headers HTTP con o sin random user agent"""
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        if self.random_agent:
            headers['User-Agent'] = random.choice(self.user_agents)
        else:
            headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        return headers
    
    def buscar_asn_por_empresa(self) -> Set[int]:
        """Busca ASNs asociados a la empresa"""
        self.log(f"Buscando ASNs para {self.empresa}...")
        asns = set()
        
        try:
            # Usar whois para buscar ASN
            cmd = ["whois", "-h", "whois.radb.net", f"!gAS{self.empresa}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Buscar números ASN en la salida
            asn_pattern = r'AS(\d+)'
            matches = re.findall(asn_pattern, result.stdout, re.IGNORECASE)
            for match in matches:
                asns.add(int(match))
            
            # También buscar en RIPE
            cmd2 = f"whois -h whois.ripe.net '{self.empresa}'"
            result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True, timeout=10)
            matches2 = re.findall(asn_pattern, result2.stdout, re.IGNORECASE)
            for match in matches2:
                asns.add(int(match))
                
        except Exception as e:
            self.log(f"Error buscando ASN: {e}")
        
        # Búsqueda alternativa usando APIs públicas
        try:
            # Usar API de BGPView (pública, sin API key)
            url = f"https://api.bgpview.io/search?query_term={self.empresa}"
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    for item in data['data'].get('asns', []):
                        if 'asn' in item:
                            asns.add(item['asn'])
        except Exception as e:
            self.log(f"Error en API BGPView: {e}")
        
        for asn in asns:
            self.asns_encontrados.add(asn)
            self.print_result(f"ASN encontrado: AS{asn}")
        
        return asns
    
    def obtener_ips_por_asn(self, asn: int) -> Set[str]:
        """Obtiene rangos de IP asociados a un ASN"""
        self.log(f"Obteniendo IPs para AS{asn}...")
        ips = set()
        
        try:
            # Usar whois para obtener rangos de IP del ASN
            cmd = ["whois", "-h", "whois.radb.net", f"!gAS{asn}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            # Buscar rangos CIDR
            cidr_pattern = r'(\d+\.\d+\.\d+\.\d+/\d+)'
            matches = re.findall(cidr_pattern, result.stdout)
            for cidr in matches:
                try:
                    # Expandir el rango CIDR a IPs individuales (muestrear)
                    network = ipaddress.ip_network(cidr, strict=False)
                    # Tomar algunas IPs del rango (no todas para no saturar)
                    if network.num_addresses <= 256:
                        for ip in network.hosts():
                            ips.add(str(ip))
                    else:
                        # Para rangos grandes, muestrear
                        sample_size = min(100, network.num_addresses)
                        step = max(1, network.num_addresses // sample_size)
                        for i, ip in enumerate(network.hosts()):
                            if i % step == 0:
                                ips.add(str(ip))
                except:
                    pass
            
            # También usar API de BGPView
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            response = requests.get(url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    for prefix in data['data'].get('ipv4_prefixes', []):
                        try:
                            network = ipaddress.ip_network(prefix['prefix'], strict=False)
                            # Muestrear IPs del rango
                            if network.num_addresses <= 256:
                                for ip in network.hosts():
                                    ips.add(str(ip))
                            else:
                                step = max(1, network.num_addresses // 100)
                                for i, ip in enumerate(network.hosts()):
                                    if i % step == 0:
                                        ips.add(str(ip))
                        except:
                            pass
                            
        except Exception as e:
            self.log(f"Error obteniendo IPs para AS{asn}: {e}")
        
        return ips
    
    def busqueda_inversa_dns(self, ip: str) -> Set[str]:
        """Realiza búsqueda DNS inversa de una IP"""
        dominios = set()
        
        try:
            # DNS reverso
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, 'PTR', lifetime=5)
            for rdata in answers:
                dominio = str(rdata).rstrip('.')
                dominios.add(dominio)
        except:
            pass
        
        # También usar herramientas del sistema
        try:
            result = subprocess.run(['dig', '+short', '-x', ip], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.strip().split('\n'):
                if line and not line.startswith(';'):
                    dominio = line.rstrip('.')
                    if dominio:
                        dominios.add(dominio)
        except:
            pass
        
        return dominios
    
    def buscar_subdominios_crt_sh(self, dominio: str) -> Set[str]:
        """Busca subdominios usando crt.sh (certificados SSL)"""
        subdominios = set()
        try:
            # Limpiar el dominio base para evitar dobles TLDs
            dominio_base = self.limpiar_dominio(dominio)
            url = f"https://crt.sh/?q=%.{dominio_base}&output=json"
            response = requests.get(url, headers=self.get_headers(), timeout=30)
            if response.status_code == 200:
                data = response.json()
                total = len(data)
                for idx, entry in enumerate(data, 1):
                    name_value = entry.get('name_value', '')
                    # Puede contener múltiples dominios separados por \n
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name and dominio_base in name:
                            # Limpiar wildcards
                            name = name.replace('*.', '')
                            if name.startswith('.'):
                                name = name[1:]
                            
                            # Limpiar dominio de dobles TLDs
                            name = self.limpiar_dominio(name)
                            
                            # Solo agregar si es válido y no tiene doble TLD
                            if name and self.es_dominio_valido(name):
                                # Verificar que realmente pertenece al dominio base
                                if dominio_base in name or name.endswith(f'.{dominio_base}'):
                                    subdominios.add(name)
                    if idx % 100 == 0 and total > 100:
                        sys.stdout.write(f'\r[+] crt.sh: Procesando {idx}/{total} certificados... ({len(subdominios)} subdominios)')
                        sys.stdout.flush()
                if total > 100:
                    sys.stdout.write('\r' + ' ' * 60 + '\r')
                    sys.stdout.flush()
        except Exception as e:
            self.log(f"Error en crt.sh: {e}")
        return subdominios
    
    def buscar_subdominios(self, dominio: str) -> Set[str]:
        """Busca subdominios de un dominio"""
        self.log(f"Buscando subdominios para {dominio}...")
        subdominios = set()
        
        # 1. Búsqueda en crt.sh (certificados SSL)
        crt_subdomains = self.buscar_subdominios_crt_sh(dominio)
        # Filtrar subdominios válidos y relevantes
        for sub in crt_subdomains:
            # Limpiar dominio de dobles TLDs
            sub_limpio = self.limpiar_dominio(sub)
            if self.es_dominio_valido(sub_limpio) and self.es_dominio_relevante(sub_limpio):
                subdominios.add(sub_limpio)
                if self.verbose:
                    self.print_result(f"Subdominio encontrado (crt.sh): {sub_limpio}")
        
        # 2. Lista de subdominios comunes
        subdominios_comunes = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 
            'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 
            'exchange', 'owa', 'www1', 'beta', 'webhost', 'ns3', 'www3', 'api', 
            'cdn', 'stats', 'dns1', 'webmail', 'server', 'mx1', 'chat', 'wap', 
            'microsoft', 'portal', 'ns4', 'www4', 'mail2', 'sip', 'dns2', 'api1', 
            'www5', 'whm1', 'host', 'support', 'email', 'smtp2', 'crm', 'dns', 
            'owa1', 'www6', 'admin1', 'mx2', 'old', 'mysql', 'ns5', 'mail1', 
            'smtp1', 'panel', 'wiki', 'blog1', 'backup', 'mx', 'new', 'mysql1', 
            'mail2', 'test1', 'ns6', 'www7', 'info', 'apps', 'rec', 'www8', 
            'ns7', 'www9', 'ns8', 'www10', 'smtp3', 'demo', 'mailserver', 
            'ns9', 'pop1', 'ns10', 'www11', 'www12', 'ns11', 'www13', 'www14', 
            'www15', 'ns12', 'www16', 'www17', 'ns13', 'www18', 'www19', 'www20',
            'staging', 'prod', 'production', 'dev1', 'test2', 'qa', 'uat', 'preprod'
        ]
        
        # Intentar resolver subdominios comunes
        def verificar_subdominio(sub):
            try:
                full_domain = f"{sub}.{dominio}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        total_comunes = len(subdominios_comunes)
        encontrados_comunes = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(verificar_subdominio, sub): sub 
                      for sub in subdominios_comunes}
            
            for future in as_completed(futures):
                try:
                    resultado = future.result(timeout=2)
                    if resultado:
                        subdominios.add(resultado)
                        encontrados_comunes += 1
                        if self.verbose:
                            self.print_result(f"Subdominio encontrado: {resultado}")
                except:
                    pass
        
        # 3. Usar herramientas externas si están disponibles
        herramientas = {
            'subfinder': ['subfinder', '-d', dominio, '-silent'],
            'amass': ['amass', 'enum', '-passive', '-d', dominio, '-silent'],
            'dnsx': ['dnsx', '-l', '-', '-a', '-aaaa', '-cname', '-ns', '-mx', '-txt', '-soa', '-resp'],
        }
        
        for herramienta, cmd_base in herramientas.items():
            try:
                if herramienta == 'dnsx':
                    # dnsx necesita leer desde stdin
                    cmd = cmd_base
                    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, 
                                              stdout=subprocess.PIPE, 
                                              stderr=subprocess.PIPE, 
                                              text=True)
                    stdout, stderr = process.communicate(input=f"{dominio}\n", timeout=60)
                    for line in stdout.strip().split('\n'):
                        if line and '.' in line:
                            # dnsx puede devolver múltiples formatos
                            parts = line.split()
                            if len(parts) > 0:
                                domain = parts[0].strip()
                                if domain:
                                    subdominios.add(domain)
                else:
                    result = subprocess.run(cmd_base, capture_output=True, text=True, timeout=120)
                    for line in result.stdout.strip().split('\n'):
                        if line and '.' in line:
                            dominio_limpio = self.limpiar_dominio(line.strip())
                            if self.es_dominio_valido(dominio_limpio):
                                subdominios.add(dominio_limpio)
                    if herramienta == 'amass' and result.stderr:
                        # amass también puede escribir en stderr
                        for line in result.stderr.strip().split('\n'):
                            if line and '.' in line and '[' not in line:
                                dominio_limpio = self.limpiar_dominio(line.strip())
                                if self.es_dominio_valido(dominio_limpio):
                                    subdominios.add(dominio_limpio)
            except FileNotFoundError:
                self.log(f"{herramienta} no encontrado, saltando...")
                continue
            except subprocess.TimeoutExpired:
                self.log(f"{herramienta} excedió el tiempo límite")
                continue
            except Exception as e:
                self.log(f"Error con {herramienta}: {e}")
        
        return subdominios
    
    def detectar_ec2(self, ip: str) -> bool:
        """Detecta si una IP pertenece a EC2/AWS"""
        try:
            # Verificar si la IP está en rangos conocidos de AWS
            data = self.obtener_rangos_aws()
            if not data:
                return False
            ip_obj = ipaddress.ip_address(ip)
            
            for prefix in data.get('prefixes', []):
                try:
                    network = ipaddress.ip_network(prefix['ip_prefix'], strict=False)
                    if ip_obj in network:
                        servicio = prefix.get('service', '')
                        region = prefix.get('region', '')
                        
                        if 'EC2' in servicio or 'ec2' in servicio.lower():
                            self.ec2_instances.append({
                                'ip': ip,
                                'region': region,
                                'service': servicio,
                                'network': prefix['ip_prefix']
                            })
                            return True
                except:
                    continue
        except Exception as e:
            self.log(f"Error detectando EC2: {e}")
        
        return False

    def obtener_rangos_aws(self) -> Dict:
        """Obtiene y cachea rangos de AWS para evitar descargas repetidas"""
        ahora = time.time()
        if self.aws_ranges_cache and (ahora - self.aws_cache_time) < self.aws_cache_ttl:
            return self.aws_ranges_cache
        
        try:
            aws_ranges_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
            response = requests.get(aws_ranges_url, headers=self.get_headers(), timeout=10)
            if response.status_code == 200:
                self.aws_ranges_cache = response.json()
                self.aws_cache_time = ahora
                return self.aws_ranges_cache
        except Exception as e:
            self.log(f"Error obteniendo rangos AWS: {e}")
        
        return {}
    
    def extraer_registrante_whois(self, dominio: str) -> Dict[str, str]:
        """Extrae información del registrante de un dominio"""
        registrante_info = {}
        try:
            cmd = ["whois", dominio]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout.lower()
            
            # Buscar organización, registrant, owner
            org_patterns = [
                r'organization:\s*(.+)',
                r'org:\s*(.+)',
                r'registrant organization:\s*(.+)',
                r'owner:\s*(.+)',
                r'registrant name:\s*(.+)',
            ]
            
            for pattern in org_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    org = match.group(1).strip()
                    if org and len(org) > 2:
                        registrante_info['organization'] = org
                        break
            
            # Buscar email del registrante
            email_patterns = [
                r'registrant email:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                r'email:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            ]
            
            for pattern in email_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    registrante_info['email'] = match.group(1).strip()
                    break
            
        except Exception as e:
            self.log(f"Error extrayendo registrante de {dominio}: {e}")
        
        return registrante_info
    
    def verificar_propiedad_dominio(self, dominio: str, registrante_info: Dict[str, str]) -> bool:
        """Verifica si un dominio pertenece a la empresa comparando registrante"""
        if not registrante_info.get('organization'):
            return False
        
        try:
            dominio_info = self.extraer_registrante_whois(dominio)
            if not dominio_info.get('organization'):
                return False
            
            # Comparar organizaciones (case insensitive, normalizado)
            org_original = registrante_info['organization'].lower().strip()
            org_dominio = dominio_info['organization'].lower().strip()
            
            # Comparación exacta
            if org_original == org_dominio:
                return True
            
            # Comparación parcial (si una contiene a la otra)
            if org_original in org_dominio or org_dominio in org_original:
                # Verificar que no sea demasiado genérico
                palabras_genéricas = ['inc', 'llc', 'corp', 'ltd', 'limited', 'company', 'co']
                org_original_words = set(org_original.split())
                org_dominio_words = set(org_dominio.split())
                
                # Si tienen palabras significativas en común (excluyendo genéricas)
                palabras_comunes = (org_original_words & org_dominio_words) - set(palabras_genéricas)
                if len(palabras_comunes) > 0:
                    return True
            
            return False
        except Exception as e:
            self.log(f"Error verificando propiedad de {dominio}: {e}")
            return False
    
    def buscar_dominios_por_registrante(self, registrante_info: Dict[str, str]) -> Set[str]:
        """Busca dominios por registrante usando APIs públicas"""
        dominios = set()
        
        if not registrante_info.get('organization'):
            return dominios
        
        org = registrante_info['organization']
        self.log(f"Buscando dominios del registrante: {org}")
        
        # Buscar en crt.sh por organización (limitado pero útil)
        try:
            # Nota: crt.sh no tiene búsqueda directa por org, pero podemos intentar
            # buscar por el dominio principal y luego verificar ownership
            pass
        except:
            pass
        
        return dominios
    
    def limpiar_dominio(self, dominio: str) -> str:
        """Limpia un dominio de caracteres inválidos y dobles TLDs"""
        dominio = dominio.strip().lower()
        
        # Remover espacios y caracteres especiales al inicio/fin
        dominio = dominio.rstrip('.')
        
        # Detectar y corregir dobles TLDs (ej: paypal.com.com -> paypal.com)
        # Patrón: dominio.com.com, dominio.net.net, etc.
        patron_doble_tld = r'^(.+\.(com|net|org|io|co|info|biz|us|uk|de|fr|es|it|jp|cn|ru|au|ca|mx|br|in|nl|se|no|dk|fi|pl|cz|gr|pt|ie|at|ch|be|nz|sg|hk|tw|kr|tr|za|ae|il|ar|cl|co|pe|ve|ec|uy|py|bo|cr|pa|do|gt|hn|ni|sv|cu|jm|tt|bb|bs|bz|gy|sr|fk|ai|vg|ky|bm|tc|ms|ag|dm|lc|vc|gd|kn|aw|cw|sx|bq|mf|bl|pm|wf|pf|nc|re|yt|tf|mq|gp|gf|as|gu|mp|pr|vi|um|eh|sh|ac|io|cx|cc|nf|hm|gs|pn|tk|nu|sj|bv|aq|tf))\.\2$'
        match = re.match(patron_doble_tld, dominio, re.IGNORECASE)
        if match:
            # Extraer el dominio sin el TLD duplicado
            dominio_base = match.group(1)
            self.log(f"Corregido dominio con doble TLD: {dominio} -> {dominio_base}")
            return dominio_base
        
        return dominio
    
    def es_dominio_valido(self, dominio: str) -> bool:
        """Verifica si un dominio parece ser válido (no typosquatting)"""
        dominio = dominio.lower().strip()
        
        # Filtrar dominios con doble TLD (ej: .com.com, .net.net)
        patrones_sospechosos = [
            r'\.(com|net|org|io|co|info|biz|us|uk|de|fr|es|it|jp|cn|ru|au|ca|mx|br|in|nl|se|no|dk|fi|pl|cz|gr|pt|ie|at|ch|be|nz|sg|hk|tw|kr|tr|za|ae|il|ar|cl|co|pe|ve|ec|uy|py|bo|cr|pa|do|gt|hn|ni|sv|cu|jm|tt|bb|bs|bz|gy|sr|fk|ai|vg|ky|bm|tc|ms|ag|dm|lc|vc|gd|kn|aw|cw|sx|bq|mf|bl|pm|wf|pf|nc|re|yt|tf|mq|gp|gf|as|gu|mp|pr|vi|um|eh|sh|ac|io|cx|cc|nf|hm|gs|pn|tk|nu|sj|bv|aq|tf)\.\1$',  # .com.com, .net.net, etc
            r'\.(co|com|net|org|io)\.(co|com|net|org|io)$',  # .com.co, .net.com, etc (typosquatting)
            r'^[0-9]+\.',  # Dominios que empiezan con números
            r'-[0-9]+\.',  # Dominios con guiones y números al inicio
        ]
        
        for patron in patrones_sospechosos:
            if re.search(patron, dominio, re.IGNORECASE):
                return False
        
        # Verificar que el dominio tenga estructura válida
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', dominio):
            return False
        
        return True
    
    def es_dominio_relevante(self, dominio: str) -> bool:
        """Verifica si un dominio es relevante para la empresa"""
        dominio_lower = dominio.lower()
        empresa_limpia = self.empresa.lower()
        
        # Si el dominio contiene el nombre de la empresa, es relevante
        if empresa_limpia in dominio_lower:
            return True
        
        # Si el dominio contiene parte del nombre (mínimo 4 caracteres)
        if '.' in empresa_limpia:
            empresa_base = empresa_limpia.split('.')[0]
            if len(empresa_base) >= 4 and empresa_base in dominio_lower:
                return True
        
        # Filtrar dominios genéricos que no son relevantes
        dominios_no_relevantes = [
            'cloudflare', 'akamai', 'amazonaws', 'google', 'microsoft',
            'staticip', 'dynamicip', 'cable', 'public', 'red-', 'rima-tde',
            't-mobile', 'upcbusiness', 'surfer', 'chello', 'telering'
        ]
        
        for no_relevante in dominios_no_relevantes:
            if no_relevante in dominio_lower:
                return False
        
        # Si no podemos determinar relevancia, lo incluimos (será filtrado después)
        return True
    
    def buscar_dominios_por_empresa(self) -> Set[str]:
        """Busca dominios relacionados con la empresa"""
        self.log(f"Buscando dominios para {self.empresa}...")
        dominios = set()
        registrante_info = {}
        
        # Limpiar el nombre de la empresa (remover TLD si existe)
        empresa_limpia = self.empresa
        if '.' in empresa_limpia:
            empresa_limpia = empresa_limpia.split('.')[0]
        
        # Intentar resolver el dominio principal
        dominios_principales = [
            self.empresa,
            f"www.{self.empresa}",
            f"{empresa_limpia}.com",
            f"{empresa_limpia}.net",
            f"{empresa_limpia}.org",
            f"{empresa_limpia}.io",
            f"{empresa_limpia}.co",
            f"{empresa_limpia}.info",
            f"{empresa_limpia}.biz",
            f"{empresa_limpia}.us",
            f"{empresa_limpia}.uk",
        ]
        
        dominio_principal_encontrado = None
        for dominio in dominios_principales:
            try:
                ip = socket.gethostbyname(dominio)
                if self.es_dominio_valido(dominio):
                    dominios.add(dominio)
                    self.ips_encontradas.add(ip)
                    self.print_result(f"Dominio encontrado: {dominio} -> {ip}")
                    if not dominio_principal_encontrado and '.' in dominio:
                        dominio_principal_encontrado = dominio
            except:
                pass
        
        # Si encontramos un dominio principal, extraer info del registrante
        if dominio_principal_encontrado:
            self.log(f"Extrayendo información del registrante de {dominio_principal_encontrado}...")
            registrante_info = self.extraer_registrante_whois(dominio_principal_encontrado)
            if registrante_info:
                self.registrante_info = registrante_info
                self.log(f"Registrante encontrado: {registrante_info.get('organization', 'N/A')}")
        
        # Buscar dominios adicionales por nameservers
        try:
            dominio_base = dominio_principal_encontrado or f"{empresa_limpia}.com"
            cmd = ["whois", dominio_base]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            # Extraer dominios de nameservers
            ns_pattern = r'name server:\s*([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
            matches = re.findall(ns_pattern, result.stdout, re.IGNORECASE)
            for match in matches:
                if match[0]:
                    ns_domain = match[0].strip().lower()
                    if self.es_dominio_valido(ns_domain):
                        dominios.add(ns_domain)
                        self.log(f"Nameserver encontrado: {ns_domain}")
        except Exception as e:
            self.log(f"Error en búsqueda WHOIS: {e}")
        
        # Buscar en APIs adicionales (sin API key, limitado)
        try:
            # Intentar buscar en SecurityTrails (puede requerir API key)
            # Por ahora solo intentamos con el dominio principal
            pass
        except:
            pass
        
        return dominios
    
    def ejecutar_reconocimiento(self):
        """Ejecuta el reconocimiento completo"""
        print(f"\n{'='*60}")
        print(f"Reconocimiento Inverso para: {self.empresa.upper()}")
        print(f"{'='*60}\n")
        
        # 1. Buscar dominios principales
        spinner = Spinner("Fase 1: Búsqueda de dominios principales")
        spinner.start()
        dominios = self.buscar_dominios_por_empresa()
        self.dominios_encontrados.update(dominios)
        spinner.stop(f"[✓] Fase 1 completada: {len(dominios)} dominios encontrados")
        
        # 2. Buscar ASNs
        spinner = Spinner("Fase 2: Búsqueda de ASNs")
        spinner.start()
        asns = self.buscar_asn_por_empresa()
        spinner.stop(f"[✓] Fase 2 completada: {len(asns)} ASNs encontrados")
        
        # 3. Obtener IPs por ASN
        spinner = Spinner("Fase 3: Obteniendo IPs por ASN")
        spinner.start()
        todas_las_ips = set()
        total_asns = len(asns)
        for idx, asn in enumerate(asns, 1):
            if total_asns > 1:
                spinner.message = f"Fase 3: Procesando ASN {idx}/{total_asns} (AS{asn})"
            ips = self.obtener_ips_por_asn(asn)
            todas_las_ips.update(ips)
            time.sleep(0.5)
        
        # Limitar el número de IPs para no saturar
        if len(todas_las_ips) > self.max_ips:
            todas_las_ips = set(list(todas_las_ips)[:self.max_ips])
        
        self.ips_encontradas.update(todas_las_ips)
        spinner.stop(f"[✓] Fase 3 completada: {len(self.ips_encontradas)} IPs encontradas")
        
        # 4. Búsqueda DNS inversa
        print(f"\n[*] Fase 4: Búsqueda DNS inversa...")
        dominios_por_ip = defaultdict(set)
        ips_a_procesar = list(self.ips_encontradas)[:self.max_ips_reverse]
        total_ips = len(ips_a_procesar)
        procesadas = 0
        encontrados = 0
        
        def procesar_ip(ip):
            nonlocal procesadas, encontrados
            dominios = self.busqueda_inversa_dns(ip)
            with self.counter_lock:
                procesadas += 1
            if dominios:
                with self.counter_lock:
                    dominios_por_ip[ip] = dominios
                for dominio in dominios:
                    # Limpiar dominio de dobles TLDs
                    dominio_limpio = self.limpiar_dominio(dominio)
                    
                    # Filtrar dominios válidos y relevantes
                    if not self.es_dominio_valido(dominio_limpio):
                        with self.counter_lock:
                            self.dominios_filtrados += 1
                        continue
                    
                    if not self.es_dominio_relevante(dominio_limpio):
                        with self.counter_lock:
                            self.dominios_filtrados += 1
                        continue
                    
                    # Verificar propiedad si tenemos info del registrante
                    if (not self.skip_ownership_check and
                        self.registrante_info and self.registrante_info.get('organization')):
                        if not self.verificar_propiedad_dominio(dominio_limpio, self.registrante_info):
                            self.log(f"Dominio {dominio_limpio} no pertenece a la empresa (filtrado)")
                            with self.counter_lock:
                                self.dominios_filtrados += 1
                            continue
                    
                    with self.counter_lock:
                        self.dominios_encontrados.add(dominio_limpio)
                        encontrados += 1
                    if self.verbose:
                        self.print_result(f"Dominio encontrado por IP {ip}: {dominio_limpio}")
        
        # Procesar IPs en paralelo con progreso
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(procesar_ip, ip): ip for ip in ips_a_procesar}
            spinner = Spinner("Procesando IPs")
            spinner.start()
            
            for future in as_completed(futures):
                try:
                    future.result(timeout=10)
                    if procesadas % 10 == 0 or procesadas == total_ips:
                        spinner.message = f"Fase 4: Procesadas {procesadas}/{total_ips} IPs ({encontrados} dominios encontrados)"
                except:
                    procesadas += 1
                    if procesadas % 10 == 0:
                        spinner.message = f"Fase 4: Procesadas {procesadas}/{total_ips} IPs"
            
            spinner.stop(f"[✓] Fase 4 completada: {procesadas} IPs procesadas, {encontrados} dominios encontrados")
        
        # 5. Buscar subdominios
        print(f"\n[*] Fase 5: Búsqueda de subdominios...")
        dominios_a_procesar = list(self.dominios_encontrados)[:self.max_domains_sub]
        total_dominios = len(dominios_a_procesar)
        
        for idx, dominio in enumerate(dominios_a_procesar, 1):
            spinner = Spinner(f"Buscando subdominios para {dominio} ({idx}/{total_dominios})")
            spinner.start()
            subdominios = self.buscar_subdominios(dominio)
            self.subdominios_encontrados.update(subdominios)
            spinner.stop(f"[✓] {dominio}: {len(subdominios)} subdominios encontrados")
            time.sleep(0.5)
        
        print(f"[✓] Fase 5 completada: {len(self.subdominios_encontrados)} subdominios totales encontrados")
        
        # 6. Detectar EC2
        print(f"\n[*] Fase 6: Detección de infraestructura EC2...")
        ips_ec2 = list(self.ips_encontradas)[:self.max_ips_ec2]
        total_ec2 = len(ips_ec2)
        ec2_encontradas = 0
        
        spinner = Spinner("Verificando IPs en rangos AWS")
        spinner.start()
        
        for idx, ip in enumerate(ips_ec2, 1):
            if self.detectar_ec2(ip):
                ec2_encontradas += 1
            if idx % 10 == 0 or idx == total_ec2:
                spinner.message = f"Verificando IPs AWS: {idx}/{total_ec2} ({ec2_encontradas} EC2 encontradas)"
        
        spinner.stop(f"[✓] Fase 6 completada: {ec2_encontradas} instancias EC2 detectadas")
        
        # Mostrar resultados finales
        self.mostrar_resultados()
    
    def mostrar_resultados(self):
        """Muestra los resultados finales"""
        print(f"\n{'='*60}")
        print("RESULTADOS DEL RECONOCIMIENTO")
        print(f"{'='*60}\n")
        
        print(f"[+] ASNs encontrados: {len(self.asns_encontrados)}")
        for asn in sorted(self.asns_encontrados):
            print(f"    AS{asn}")
        
        print(f"\n[+] IPs encontradas: {len(self.ips_encontradas)}")
        if self.verbose:
            for ip in sorted(self.ips_encontradas):
                print(f"    {ip}")
        
        print(f"\n[+] Dominios encontrados: {len(self.dominios_encontrados)}")
        for dominio in sorted(self.dominios_encontrados):
            print(f"    {dominio}")
        
        print(f"\n[+] Subdominios encontrados: {len(self.subdominios_encontrados)}")
        for subdominio in sorted(self.subdominios_encontrados):
            print(f"    {subdominio}")
        
        print(f"\n[+] Instancias EC2 detectadas: {len(self.ec2_instances)}")
        for ec2 in self.ec2_instances:
            print(f"    IP: {ec2['ip']} | Región: {ec2['region']} | Servicio: {ec2['service']}")
        
        if self.dominios_filtrados > 0:
            print(f"\n[!] Dominios filtrados (falsos positivos): {self.dominios_filtrados}")
        
        # Guardar resultados en JSON
        resultados = {
            'empresa': self.empresa,
            'asns': sorted(list(self.asns_encontrados)),
            'ips': sorted(list(self.ips_encontradas)),
            'dominios': sorted(list(self.dominios_encontrados)),
            'subdominios': sorted(list(self.subdominios_encontrados)),
            'ec2_instances': self.ec2_instances
        }
        
        output_file_json = f"recon_{self.empresa}.json"
        with open(output_file_json, 'w') as f:
            json.dump(resultados, f, indent=2)
        
        print(f"\n[+] Resultados JSON guardados en: {output_file_json}")
        
        # Guardar dominios y subdominios en archivo de texto si se especificó -o
        if self.output_file:
            todos_dominios = sorted(list(self.dominios_encontrados | self.subdominios_encontrados))
            with open(self.output_file, 'w') as f:
                for dominio in todos_dominios:
                    f.write(f"{dominio}\n")
            print(f"[+] Dominios y subdominios guardados en: {self.output_file}")
            print(f"[+] Total de dominios/subdominios guardados: {len(todos_dominios)}")


def main():
    parser = argparse.ArgumentParser(
        description='Herramienta de Reconocimiento Inverso - Encuentra dominios, subdominios y infraestructura por empresa',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -u logitech
  %(prog)s -u microsoft -v -ra
  %(prog)s -u google -t 50 -o resultados.txt --max-ips 500
  %(prog)s -u amazon -v -ra -t 30 -o amazon_domains.txt --skip-ownership-check
        """
    )
    
    parser.add_argument('-u', '--empresa', required=True,
                       help='Nombre de la empresa a investigar')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Modo verbose (muestra más información)')
    parser.add_argument('-ra', '--random-agent', action='store_true',
                       help='Usar User-Agent aleatorio en las peticiones HTTP')
    parser.add_argument('-t', '--threads', type=int, default=20,
                       help='Número de hilos para operaciones paralelas (default: 20)')
    parser.add_argument('-o', '--output', type=str, default=None,
                       help='Archivo de salida para guardar todos los dominios y subdominios encontrados')
    parser.add_argument('--max-ips', type=int, default=1000,
                       help='Máximo de IPs a procesar desde ASN (default: 1000)')
    parser.add_argument('--max-ips-reverse', type=int, default=200,
                       help='Máximo de IPs para DNS inverso (default: 200)')
    parser.add_argument('--max-domains-sub', type=int, default=10,
                       help='Máximo de dominios para buscar subdominios (default: 10)')
    parser.add_argument('--max-ips-ec2', type=int, default=100,
                       help='Máximo de IPs para detectar EC2 (default: 100)')
    parser.add_argument('--skip-ownership-check', action='store_true',
                       help='No verificar propiedad por WHOIS (más rápido, menos precisión)')
    parser.add_argument('--aws-cache-ttl', type=int, default=3600,
                       help='TTL del cache de rangos AWS en segundos (default: 3600)')
    
    args = parser.parse_args()
    
    recon = ReconInverso(args.empresa, args.verbose, args.random_agent, 
                        args.threads, args.output, args.max_ips,
                        args.max_ips_reverse, args.max_domains_sub,
                        args.max_ips_ec2, args.skip_ownership_check,
                        args.aws_cache_ttl)
    recon.ejecutar_reconocimiento()


if __name__ == '__main__':
    main()
