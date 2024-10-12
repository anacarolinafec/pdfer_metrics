import requests
import time
import threading
import random
import string
import os
from prometheus_client import start_http_server, Summary, Counter, Gauge

# Definir métricas para a latência do GET e POST
POST_LATENCY = Summary('post_request_latency_seconds', 'Latência de requisições POST ao servidor')
GET_LATENCY = Summary('get_request_latency_seconds', 'Latência de requisições GET ao servidor')

# Contadores para requisições GET e POST bem-sucedidas e com erro
POST_SUCCESS = Counter('post_request_success_total', 'Total de requisições POST bem-sucedidas')
POST_FAILURE = Counter('post_request_failure_total', 'Total de requisições POST com erro')
GET_SUCCESS = Counter('get_request_success_total', 'Total de requisições GET bem-sucedidas')
GET_FAILURE = Counter('get_request_failure_total', 'Total de requisições GET com erro')

# Gauge para contar o número de clientes ativos
ACTIVE_CLIENTS = Gauge('active_clients', 'Número de clientes ativos')

# URL base do servidor
base_url = "http://pdfer:8080"

# Conjuntos para rastrear chaves e nomes de arquivos
used_keys = set()
used_file_names = set()

# Função para gerar uma chave aleatória de 16 caracteres
def generate_random_key(length=16):
    while True:
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        if key not in used_keys:  # Garante que a chave é única
            used_keys.add(key)  # Adiciona a chave ao conjunto
            return key

# Função para gerar um comprimento aleatório
def generate_random_length(min_length=1, max_length=1000):
    return random.randint(min_length, max_length)

# Função para gerar um nome de arquivo único
def generate_unique_file_name():
    while True:
        file_name = f"arquivo_{generate_random_key()}.txt"  # Nome do arquivo baseado na chave
        if file_name not in used_file_names:  # Garante que o nome do arquivo é único
            used_file_names.add(file_name)  # Adiciona o nome ao conjunto
            return file_name

# Função para fazer um pedido POST
@POST_LATENCY.time()
def make_post_request(key, length, file_name):
    url = f"{base_url}/files"
    headers = {"Content-Type": "application/json"}
    data = {
        "key": key,
        "length": length,
        "fileName": file_name
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 201:
            POST_SUCCESS.inc()  # Incrementa o contador de sucessos
        else:
            POST_FAILURE.inc()  # Incrementa o contador de falhas
        print(f"Resposta do POST ({file_name}): {response.status_code}")
        return response.status_code
    except Exception as e:
        POST_FAILURE.inc()  # Incrementa o contador de falhas
        print(f"Erro no POST: {e}")
        return None

# Função para fazer um pedido GET
@GET_LATENCY.time()
def make_get_request():
    url = f"{base_url}/files"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            GET_SUCCESS.inc()  # Incrementa o contador de sucessos
        else:
            GET_FAILURE.inc()  # Incrementa o contador de falhas
        print(f"Resposta do GET: {response.status_code}")
        return response.status_code
    except Exception as e:
        GET_FAILURE.inc()  # Incrementa o contador de falhas
        print(f"Erro no GET: {e}")
        return None

# Função para fazer um pedido GET para recuperar um arquivo específico
@GET_LATENCY.time()
def make_get_file_request(file_name, key):
    url = f"{base_url}/files/{file_name}"
    headers = {"Content-Type": "application/json"}
    data = {"key": key}  # Chave de criptografia
    try:
        response = requests.get(url, headers=headers, json=data)
        if response.status_code == 200:
            GET_SUCCESS.inc()  # Incrementa o contador de sucessos
        else:
            GET_FAILURE.inc()  # Incrementa o contador de falhas
        print(f"Resposta do GET do arquivo ({file_name}): {response.status_code}")
        return response.status_code
    except Exception as e:
        GET_FAILURE.inc()  # Incrementa o contador de falhas
        print(f"Erro no GET do arquivo: {e}")
        return None

# Função para criar e executar múltiplos clientes
def client_thread():
    ACTIVE_CLIENTS.inc()  # Incrementa o número de clientes ativos
    try:
        while True:
            key = generate_random_key()  # Gera uma chave aleatória e única
            length = generate_random_length()  # Gera um comprimento aleatório
            file_name = generate_unique_file_name()  # Gera um nome de arquivo único

            print("Fazendo pedido POST...")
            make_post_request(key, length, file_name)

            print("Fazendo pedido GET para listar arquivos...")
            make_get_request()

            print("Fazendo pedido GET para recuperar arquivo...")
            make_get_file_request(file_name, key)

            time.sleep(10)  # Espera 10 segundos antes de fazer novos pedidos
    finally:
        ACTIVE_CLIENTS.dec()  # Decrementa o número de clientes ativos quando o thread termina

if __name__ == '__main__':
    # Inicia o servidor de métricas na porta 8000 para expor as métricas ao Prometheus
    start_http_server(8000)

    # Interface do usuário para configurar a execução
    num_clients = 5# Padrão para 1 se não estiver definido

    # Cria e inicia as threads de clientes
    threads = []
    for i in range(num_clients):
        thread = threading.Thread(target=client_thread)
        thread.start()
        threads.append(thread)

    # Mantém o programa em execução
    for thread in threads:
        thread.join()