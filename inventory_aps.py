import os
import json
import requests
import logging
import psycopg2
from fastapi import FastAPI
from threading import Thread
from contextlib import asynccontextmanager
from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway
from dotenv import load_dotenv
import time
from datetime import datetime, timedelta
import re

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Configuración básica de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ============================================
# GESTIÓN DE TOKENS
# ============================================
class TokenManager:
    def __init__(self):
        self.connection = psycopg2.connect(
            dbname="aruba",
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            host=os.getenv("POSTGRES_HOST"),
            port=os.getenv("POSTGRES_PORT")
        )
        self.connection.autocommit = True
        self.cursor = self.connection.cursor()
        self.central_info = self.get_token_from_db()
        self.client_id = os.getenv("ARUBA_INVENTORY_ID")
        self.client_secret = os.getenv("ARUBA_INVENTORY_SECRET")
        self.base_url = "https://apigw-uswest4.central.arubanetworks.com"

    def get_token_from_db(self):
        query = "SELECT access_token, refresh_token, expires_at FROM token_inventory WHERE id = 1;"
        self.cursor.execute(query)
        result = self.cursor.fetchone()

        if result:
            access_token, refresh_token, expires_at = result
            return {
                "token": {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_at": expires_at
                }
            }
        else:
            logging.error("No se encontró información del token en la base de datos.")
            return None

    def verify_and_refresh_token(self, force_refresh=False):
        if not self.central_info:
            logging.error("No se puede verificar el token. No hay información del token disponible.")
            return False

        expires_at = self.central_info['token']['expires_at']
        current_time = datetime.now()

        if force_refresh or current_time >= expires_at:
            logging.info("El token ha expirado o se ha forzado la renovación. Intentando renovar el token...")
            return self.refresh_token()
        else:
            logging.info("El token sigue siendo válido.")
            return True

    def refresh_token(self):
        refresh_token = self.central_info['token']['refresh_token']
        url = f"{self.base_url}/oauth2/token"
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }

        response = requests.post(url, params=params)

        if response.status_code == 200:
            new_token_data = response.json()
            self.update_token_in_db(new_token_data)
            logging.info("El token ha sido renovado correctamente.")
            return True
        else:
            logging.error(f"Error al renovar el token: {response.status_code} - {response.text}")
            return False

    def update_token_in_db(self, new_token_data):
        expires_in = new_token_data['expires_in']
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        last_updated = datetime.now()

        query = """
        INSERT INTO token_inventory (id, access_token, refresh_token, expires_in, expires_at, last_updated)
        VALUES (1, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            access_token = EXCLUDED.access_token,
            refresh_token = EXCLUDED.refresh_token,
            expires_in = EXCLUDED.expires_in,
            expires_at = EXCLUDED.expires_at,
            last_updated = EXCLUDED.last_updated;
        """

        self.cursor.execute(query, (
            new_token_data['access_token'],
            new_token_data['refresh_token'],
            new_token_data['expires_in'],
            expires_at,
            last_updated
        ))

        self.central_info['token']['access_token'] = new_token_data['access_token']
        self.central_info['token']['refresh_token'] = new_token_data['refresh_token']
        self.central_info['token']['expires_at'] = expires_at

        logging.info(f"Información del token actualizada en la base de datos. El token expira en: {expires_at}")

# Inicializar el TokenManager
token_manager = TokenManager()

# ============================================
# MÉTRICAS ADICIONALES PARA LA API
# ============================================

# Definir las métricas de rendimiento de la API fuera de las funciones, para que se registren una vez
api_metrics_registry = CollectorRegistry()

# Métricas de la API con etiquetas adicionales
api_requests_counter = Counter(
    'api_requests_total', 
    'Total number of API requests made', 
    ['endpoint'],  # Añadir etiqueta 'endpoint'
    registry=api_metrics_registry
)
api_requests_success_counter = Counter(
    'api_requests_success_total', 
    'Total number of successful API requests', 
    ['endpoint'],  # Añadir etiqueta 'endpoint'
    registry=api_metrics_registry
)
api_requests_failure_counter = Counter(
    'api_requests_failure_total', 
    'Total number of failed API requests', 
    ['endpoint'],  # Añadir etiqueta 'endpoint'
    registry=api_metrics_registry
)
api_request_duration_gauge = Gauge(
    'api_request_duration_milliseconds',
    'Duration of API requests in milliseconds',
    ['endpoint'],  # Añadir etiqueta 'endpoint'
    registry=api_metrics_registry
)

# ============================================
# CONSULTA A LA API /monitoring/v2/aps
# ============================================

# Función para realizar solicitudes a la API
def make_api_request(api_path, params=None, retry=False):
    if not token_manager.verify_and_refresh_token():
        return {"error": "No se pudo renovar el token"}

    headers = {
        'Authorization': f"Bearer {token_manager.central_info['token']['access_token']}",
        'Content-Type': 'application/json'
    }

    url = f"{token_manager.base_url}{api_path}"
    logging.info(f"Haciendo solicitud a {url}")

    start_time = time.time()
    try:
        response = requests.get(url, headers=headers, params=params)

        duration_ms = (time.time() - start_time) * 1000  # Convertir a milisegundos
        api_request_duration_gauge.labels(endpoint='inventory_aps').set(duration_ms)

        if response.status_code == 401 and not retry:
            logging.info("Token expirado durante la solicitud. Intentando renovar y reintentar la solicitud...")
            if token_manager.verify_and_refresh_token(force_refresh=True):
                return make_api_request(api_path, params, retry=True)
            else:
                logging.error("Error al renovar el token después de recibir un 401.")
                api_requests_failure_counter.labels(endpoint='inventory_aps').inc()
                return {"error": "Error al renovar el token"}

        if response.status_code == 200:
            logging.info("Solicitud a la API exitosa.")
            api_requests_success_counter.labels(endpoint='inventory_aps').inc()
            return response.json()
        else:
            logging.error(f"Error en la petición: {response.status_code}, {response.text}")
            api_requests_failure_counter.labels(endpoint='inventory_aps').inc()
            return {"error": f"Error en la petición: {response.status_code}, {response.text}"}

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000  # Convertir a milisegundos
        api_request_duration_gauge.labels(endpoint='inventory_aps').set(duration_ms)
        api_requests_failure_counter.labels(endpoint='inventory_aps').inc()
        logging.error(f"Excepción al realizar la solicitud a la API: {e}")
        return {"error": f"Excepción al realizar la solicitud: {e}"}

# Función para recolectar los datos de inventario de APs
def collect_inventory_aps():
    logging.info("Iniciando la recolección de datos de inventario de APs...")
    params = {
        "calculate_total": "true",
        "calculate_client_count": "true",
        "calculate_ssid_count": "true",
        "show_resource_details": "true",
        "limit": 500
    }

    # Incrementar el contador de solicitudes
    api_requests_counter.labels(endpoint='inventory_aps').inc()

    inventory_result = make_api_request("/monitoring/v2/aps", params=params)

    return inventory_result

# Función para enviar los datos a Prometheus Pushgateway
def push_inventory_aps_to_gateway(inventory_result):
    # Crear un nuevo registro para las métricas del inventario de APs
    inventory_registry = CollectorRegistry()
    
    # Definir las etiquetas comunes para todas las métricas
    labels = ['ap_name', 'serial', 'site', 'group_name', 'ip_address', 'macaddr', 'model']
    
    # Definir las métricas con las etiquetas adicionales
    ap_status_gauge = Gauge('ap_status', 'Status of the AP (1=Up, 0=Down)', labels, registry=inventory_registry)
    ap_uptime_gauge = Gauge('ap_uptime_seconds', 'Uptime of the AP in seconds', labels, registry=inventory_registry)
    ap_client_count_gauge = Gauge('ap_client_count', 'Number of clients connected to the AP', labels, registry=inventory_registry)
    ap_cpu_utilization_gauge = Gauge('ap_cpu_utilization_percent', 'CPU utilization of the AP in percent', labels, registry=inventory_registry)
    ap_memory_free_gauge = Gauge('ap_memory_free_bytes', 'Free memory of the AP in bytes', labels, registry=inventory_registry)
    ap_memory_total_gauge = Gauge('ap_memory_total_bytes', 'Total memory of the AP in bytes', labels, registry=inventory_registry)
    ap_ssid_count_gauge = Gauge('ap_ssid_count', 'Number of SSIDs on the AP', labels, registry=inventory_registry)
    ap_last_modified_gauge = Gauge('ap_last_modified_timestamp', 'Last modified timestamp of the AP', labels, registry=inventory_registry)
    
    # Extraer y enviar datos para cada AP
    for ap in inventory_result.get('aps', []):
        # Extraer los campos requeridos y normalizar los nombres
        ap_name = ap.get('name', 'unknown').replace(" ", "_")
        serial = ap.get('serial', 'unknown')
        site = (ap.get('site') or 'unknown').replace(" ", "_")
        group_name = ap.get('group_name', 'unknown').replace(" ", "_")
        ip_address = ap.get('ip_address', 'unknown')
        macaddr = ap.get('macaddr', 'unknown')
        model = ap.get('model', 'unknown').replace(" ", "_")
        
        # Etiquetas para las métricas
        metric_labels = [ap_name, serial, site, group_name, ip_address, macaddr, model]
        
        # Establecer valores para las métricas
        status = 1 if ap.get('status', '').lower() == 'up' else 0
        ap_status_gauge.labels(*metric_labels).set(status)
    
        uptime = ap.get('uptime', 0)
        ap_uptime_gauge.labels(*metric_labels).set(uptime)
    
        client_count = ap.get('client_count', 0)
        ap_client_count_gauge.labels(*metric_labels).set(client_count)
    
        cpu_utilization = ap.get('cpu_utilization', 0)
        ap_cpu_utilization_gauge.labels(*metric_labels).set(cpu_utilization)
    
        mem_free = ap.get('mem_free', 0)
        ap_memory_free_gauge.labels(*metric_labels).set(mem_free)
    
        mem_total = ap.get('mem_total', 0)
        ap_memory_total_gauge.labels(*metric_labels).set(mem_total)
    
        ssid_count = ap.get('ssid_count', 0)
        ap_ssid_count_gauge.labels(*metric_labels).set(ssid_count)
    
        last_modified = ap.get('last_modified', 0)
        ap_last_modified_gauge.labels(*metric_labels).set(last_modified)
    
    # Enviar métricas al Pushgateway
    push_to_gateway('pushgateway_aruba:9091', job='inventory_aps', registry=inventory_registry)
    logging.info("Métricas de inventario de APs enviadas al Pushgateway")
    
    # Enviar métricas de la API al Pushgateway
    push_to_gateway('pushgateway_aruba:9091', job='inventory_aps_api_metrics', registry=api_metrics_registry)
    logging.info("Métricas de rendimiento de la API enviadas al Pushgateway")

# Función para recolectar y exportar las métricas cada 5 minutos
def collect_and_push_inventory_aps_periodically():
    while True:
        logging.info("Recolectando y enviando datos de inventario de APs a Prometheus...")
        # Colectar datos de inventario
        inventory_result = collect_inventory_aps()

        if "error" not in inventory_result:
            push_inventory_aps_to_gateway(inventory_result)

        # Esperar 5 minutos antes de la próxima recolección
        time.sleep(600)

# Iniciar FastAPI con el manejador de ciclo de vida
@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Iniciando FastAPI y recolección de datos de inventario de APs.")
    thread = Thread(target=collect_and_push_inventory_aps_periodically, daemon=True)
    thread.start()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/inventory_aps")
def get_inventory_aps():
    return collect_inventory_aps()
