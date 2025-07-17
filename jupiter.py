#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import requests
from datetime import datetime
from urllib.parse import urlparse

# Cores para output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
ENDC = "\033[0m"
BOLD = "\033[1m"

def display_banner():
    print(f"""{BOLD}{MAGENTA}
     ▄▄▄       ██▓     ██▓ ▄████▄   ██░ ██ 
    ▒████▄    ▓██▒    ▓██▒▒██▀ ▀█  ▓██░ ██▒
    ▒██  ▀█▄  ▒██░    ▒██▒▒▓█    ▄ ▒██▀▀██░
    ░██▄▄▄▄██ ▒██░    ░██░▒▓▓▄ ▄██▒░▓█ ░██ 
     ▓█   ▓██▒░██████▒░██░▒ ▓███▀ ░░▓█▒░██▓
     ▒▒   ▓▒█░░ ▒░▓  ░░▓  ░ ░▒ ▒  ░ ▒ ░░▒░▒
      ▒   ▒▒ ░░ ░ ▒  ░ ▒ ░  ░  ▒    ▒ ░▒░ ░
      ░   ▒     ░ ░    ▒ ░░         ░  ░░ ░
          ░  ░    ░  ░ ░  ░ ░       ░  ░  ░
                         ░                 
{ENDC}{CYAN}
       Advanced API Key Validator v2.2
     Developed for Security Professionals
     by GOUD3REN
{ENDC}""")
    print(f"{YELLOW}⚠️  Use apenas para testes autorizados ⚠️{ENDC}\n")

class Jupiter:
    def __init__(self, args):
        self.args = args
        self.endpoints = self.load_endpoints()
        self.keys = self.load_keys()
        self.valid_keys = []
        self.stats = {
            'start_time': datetime.now(),
            'keys_tested': 0,
            'valid_keys': 0,
            'endpoints_tested': 0
        }
        
        # Configurar sessão HTTP
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Jupiter/2.2",
            "Accept": "application/json"
        })
        
        # Configurar proxy se especificado
        if getattr(self.args, 'proxy', None):
            self.session.proxies = {
                'http': self.args.proxy,
                'https': self.args.proxy
            }
            print(f"{CYAN}[*] Proxy configurado: {self.args.proxy}{ENDC}")
        
        # Configurações de autenticação
        self.auth_config = {
            'type': self.args.auth_type,
            'param': getattr(self.args, 'key_param', None)
        }
        
        # Configurações de requisição
        self.request_config = {
            'method': getattr(self.args, 'method', 'GET'),
            'data': getattr(self.args, 'data', None),
            'headers': self.parse_custom_headers()
        }

    def parse_custom_headers(self):
        """Analisa cabeçalhos personalizados fornecidos"""
        headers = {}
        if getattr(self.args, 'header', None):
            for header in self.args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        return headers

    def load_endpoints(self):
        """Carrega endpoints de um arquivo ou usa o endpoint único"""
        endpoints = []
        if self.args.endpoint:
            if os.path.isfile(self.args.endpoint):
                with open(self.args.endpoint, 'r') as f:
                    endpoints = [line.strip() for line in f if line.strip()]
                print(f"{CYAN}[*] Carregados {len(endpoints)} endpoints do arquivo{ENDC}")
            else:
                endpoints = [self.args.endpoint]
        elif self.args.domain:
            endpoints = self.detect_endpoints()
        else:
            print(f"{RED}[!] Nenhum endpoint ou domínio fornecido{ENDC}")
            sys.exit(1)
        return endpoints

    def load_keys(self):
        """Carrega chaves do arquivo especificado"""
        if not os.path.isfile(self.args.keys):
            print(f"{RED}[!] Arquivo de chaves não encontrado: {self.args.keys}{ENDC}")
            sys.exit(1)
            
        with open(self.args.keys, 'r') as f:
            keys = [line.strip() for line in f if line.strip()]
            print(f"{CYAN}[*] Carregadas {len(keys)} chaves para teste{ENDC}")
            return keys

    def detect_endpoints(self):
        """Detecção aprimorada de endpoints"""
        if not self.args.domain:
            print(f"{RED}[!] Domínio necessário para detecção de endpoints{ENDC}")
            sys.exit(1)
            
        print(f"{CYAN}[*] Detectando endpoints para {self.args.domain}{ENDC}")
        
        # Lista expandida de endpoints comuns
        common_endpoints = [
            "/api/v1/auth", "/oauth/token", "/graphql", "/rest/v1/auth",
            "/api/auth", "/v1/authenticate", "/auth", "/token", "/login",
            "/api/login", "/api/token", "/v2/auth", "/identity/connect/token",
            "/authentication", "/session", "/oauth2/token", "/user/login",
            "/account/login", "/api/v2/auth", "/connect/token"
        ]
        
        # Endpoints específicos baseados no domínio
        domain_endpoints = [
            "/_api/auth", "/_api/login", "/api/graphql", "/backend/auth",
            "/admin-api", "/console/auth", "/v3/auth", "/internal/auth"
        ]
        
        detected = []
        for endpoint in set(common_endpoints + domain_endpoints):
            for scheme in ["https", "http"]:
                # Construir URL completa
                domain = self.args.domain
                if not domain.startswith("http"):
                    domain = f"https://{domain}"
                
                netloc = urlparse(domain).netloc
                if not netloc:
                    netloc = domain
                
                url = f"{scheme}://{netloc}{endpoint}"
                try:
                    response = self.session.head(
                        url, 
                        timeout=3,
                        allow_redirects=False
                    )
                    if response.status_code < 400:
                        detected.append(url)
                        print(f"{GREEN}[+] Endpoint detectado: {url}{ENDC}")
                    # Verificar redirecionamentos
                    elif 300 <= response.status_code < 400:
                        redirect_url = response.headers.get('Location', '')
                        if redirect_url and urlparse(redirect_url).netloc == urlparse(url).netloc:
                            detected.append(redirect_url)
                            print(f"{YELLOW}[+] Endpoint via redirecionamento: {redirect_url}{ENDC}")
                except Exception as e:
                    if self.args.verbose:
                        print(f"{YELLOW}[!] Erro testando {url}: {str(e)}{ENDC}")
                    continue
        
        if not detected:
            print(f"{YELLOW}[!] Usando endpoints padrão como fallback{ENDC}")
            netloc = urlparse(self.args.domain).netloc or self.args.domain
            detected = [
                f"https://{netloc}/api/auth",
                f"https://{netloc}/auth",
                f"https://{netloc}/login"
            ]
        
        return detected

    def prepare_request(self, key, endpoint):
        """Prepara a requisição HTTP com base na configuração"""
        # Configurar autenticação
        headers = self.request_config['headers'].copy()
        params = {}
        data = self.request_config['data']
        
        if self.auth_config['type'] == "bearer":
            headers["Authorization"] = f"Bearer {key}"
        elif self.auth_config['type'] == "basic":
            headers["Authorization"] = f"Basic {key}"
        elif self.auth_config['type'] == "header":
            header_name = self.auth_config['param'] or "X-API-Key"
            headers[header_name] = key
        elif self.auth_config['type'] == "param":
            param_name = self.auth_config['param'] or "key"
            params[param_name] = key
        
        return {
            'method': self.request_config['method'],
            'url': endpoint,
            'headers': headers,
            'params': params,
            'data': data,
            'timeout': getattr(self.args, 'timeout', 7.0)
        }

    def test_key(self, key, endpoint):
        """Testa uma única chave de API em um endpoint específico"""
        try:
            request_args = self.prepare_request(key, endpoint)
            start_time = time.time()
            
            response = self.session.request(**request_args)
            response_time = time.time() - start_time
            
            # Verificar resposta
            valid = response.status_code in self.args.success_codes
            
            # Verificação de conteúdo adicional
            if valid and getattr(self.args, 'content_check', None):
                valid = self.args.content_check.lower() in response.text.lower()
            
            # Verificação de padrão JSON para respostas bem formadas
            if valid and getattr(self.args, 'json_check', False):
                try:
                    json.loads(response.text)
                except ValueError:
                    valid = False
            
            # Log de requisição bem-sucedida
            if valid:
                return True, key, endpoint, response_time, response
            
            return False, key, endpoint, response_time, response
            
        except Exception as e:
            return False, key, endpoint, 0, str(e)

    def run_tests(self):
        """Executa todos os testes com paralelização"""
        if not self.endpoints:
            print(f"{RED}[!] Nenhum endpoint disponível para teste{ENDC}")
            return
            
        total_keys = len(self.keys)
        total_endpoints = len(self.endpoints)
        total_tests = total_keys * total_endpoints
        
        print(f"\n{CYAN}[*] Configuração:{ENDC}")
        print(f"  Chaves: {total_keys}")
        print(f"  Endpoints: {total_endpoints}")
        print(f"  Testes: {total_tests}")
        print(f"  Threads: {getattr(self.args, 'threads', 15)}")
        print(f"  Autenticação: {self.auth_config['type'].upper()}")
        
        if self.auth_config['param']:
            print(f"  Parâmetro: {self.auth_config['param']}")
        
        print(f"\n{YELLOW}[*] Iniciando testes...{ENDC}")
        print(f"{YELLOW}[!] Pressione Ctrl+C para interromper a qualquer momento{ENDC}")
        
        test_counter = 0
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self.args, 'threads', 15)) as executor:
                # Criar todas as combinações de chaves e endpoints
                tasks = []
                for key in self.keys:
                    for endpoint in self.endpoints:
                        tasks.append((key, endpoint))
                
                # Submeter tarefas
                futures = {executor.submit(self.test_key, key, endpoint): (key, endpoint) for key, endpoint in tasks}
                
                for future in concurrent.futures.as_completed(futures):
                    key, endpoint = futures[future]
                    test_counter += 1
                    
                    try:
                        valid, key_value, ep, response_time, response = future.result()
                        self.stats['keys_tested'] += 1
                        
                        if valid:
                            self.stats['valid_keys'] += 1
                            self.valid_keys.append((key_value, ep))
                            print(f"\n{GREEN}{BOLD}[+] CHAVE VÁLIDA ENCONTRADA!{ENDC}")
                            print(f"{GREEN}    Chave: {key_value[:15]}...{key_value[-15:]}{ENDC}")
                            print(f"{GREEN}    Endpoint: {ep}{ENDC}")
                            print(f"{GREEN}    Status: {response.status_code if response else 'N/A'} | Tempo: {response_time:.2f}s{ENDC}")
                            if response and response.text:
                                print(f"{CYAN}    Resposta: {response.text[:100]}{'...' if len(response.text) > 100 else ''}{ENDC}")
                    
                    except Exception as e:
                        if getattr(self.args, 'verbose', False):
                            print(f"{RED}[!] Erro testando chave: {e}{ENDC}")
                    
                    # Atualizar progresso
                    if test_counter % 10 == 0 or test_counter == total_tests:
                        percent = (test_counter / total_tests) * 100
                        print(f"\r{CYAN}[>] Progresso: {test_counter}/{total_tests} ({percent:.1f}%) | "
                              f"Válidas: {self.stats['valid_keys']}{ENDC}", end='', flush=True)
                    
                    # Delay entre requisições
                    if getattr(self.args, 'delay', 0.1) > 0:
                        time.sleep(self.args.delay)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Teste interrompido pelo usuário{ENDC}")
        
        # Salvar resultados
        if getattr(self.args, 'output', None) and self.valid_keys:
            with open(self.args.output, 'w') as f:
                for key, endpoint in self.valid_keys:
                    f.write(f"{key} | {endpoint}\n")
            print(f"\n{GREEN}[+] Chaves válidas salvas em: {self.args.output}{ENDC}")
        
        # Exibir relatório final
        self.generate_report()

    def generate_report(self):
        """Gera um relatório detalhado após os testes"""
        duration = datetime.now() - self.stats['start_time']
        print(f"\n{BOLD}{MAGENTA}=== RELATÓRIO FINAL JUPITER ==={ENDC}")
        print(f"{CYAN}• Tempo total: {duration}{ENDC}")
        print(f"{CYAN}• Chaves testadas: {self.stats['keys_tested']}{ENDC}")
        print(f"{CYAN}• Endpoints testados: {len(self.endpoints)}{ENDC}")
        print(f"{CYAN}• Combinações testadas: {self.stats['keys_tested']}{ENDC}")
        print(f"{GREEN}• Chaves válidas encontradas: {self.stats['valid_keys']}{ENDC}")
        
        if self.stats['keys_tested'] > 0:
            success_rate = (self.stats['valid_keys'] / self.stats['keys_tested']) * 100
            print(f"{CYAN}• Taxa de sucesso: {success_rate:.2f}%{ENDC}")
        
        # Exibir endpoints com chaves válidas
        if self.valid_keys:
            print(f"\n{YELLOW}[+] Endpoints com chaves válidas:{ENDC}")
            unique_endpoints = set(ep for _, ep in self.valid_keys)
            for endpoint in unique_endpoints:
                print(f"  - {endpoint}")
        else:
            print(f"\n{YELLOW}[!] Nenhuma chave válida encontrada{ENDC}")

if __name__ == "__main__":
    display_banner()
    
    parser = argparse.ArgumentParser(description='Jupiter - Advanced API Key Validator', 
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    # Argumentos principais
    parser.add_argument('-d', '--domain', help='Domínio base para detecção automática de endpoints')
    parser.add_argument('-e', '--endpoint', help='Endpoint único ou arquivo com endpoints')
    parser.add_argument('-k', '--keys', required=True, help='Arquivo com chaves (uma por linha)')
    
    # Configuração de autenticação
    parser.add_argument('-a', '--auth-type', choices=['bearer', 'header', 'param', 'basic'], 
                        default='bearer', help='Tipo de autenticação')
    parser.add_argument('-p', '--key-param', help='Nome do parâmetro/cabeçalho para a chave')
    
    # Configuração de requisição
    parser.add_argument('-X', '--method', default='GET', help='Método HTTP')
    parser.add_argument('-H', '--header', action='append', help='Header customizado (ex: "Content-Type: application/json")')
    parser.add_argument('-b', '--data', help='Dados para enviar no corpo da requisição (POST)')
    
    # Configuração de validação
    parser.add_argument('-s', '--success-codes', type=int, nargs='+', default=[200],
                        help='Códigos HTTP considerados sucesso')
    parser.add_argument('-c', '--content-check', help='Texto que deve estar na resposta para validar')
    parser.add_argument('-j', '--json-check', action='store_true', help='Verificar se a resposta é JSON válido')
    
    # Configuração avançada
    parser.add_argument('-P', '--proxy', help='Proxy a ser usado (ex: http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output', help='Arquivo para salvar chaves válidas')
    parser.add_argument('-t', '--threads', type=int, default=15, 
                        help='Número de threads paralelas')
    parser.add_argument('-D', '--delay', type=float, default=0.1,
                        help='Delay entre requisições em segundos')
    parser.add_argument('-to', '--timeout', type=float, default=7.0,
                        help='Timeout das requisições em segundos')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verboso')
    
    args = parser.parse_args()
    
    # Verificação básica de parâmetros
    if not args.endpoint and not args.domain:
        parser.error("Pelo menos um dos seguintes é necessário: --endpoint ou --domain")
    
    jupiter = Jupiter(args)
    jupiter.run_tests()
