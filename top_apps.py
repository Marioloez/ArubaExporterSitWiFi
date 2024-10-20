import os
import json
import requests
import logging
import psycopg2
from psycopg2 import sql
from fastapi import FastAPI
from threading import Thread
from contextlib import asynccontextmanager
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, push_to_gateway
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
        self.client_id = os.getenv("ARUBA_APPLICATIONS_ID")
        self.client_secret = os.getenv("ARUBA_APPLICATIONS_SECRET")
        self.base_url = "https://apigw-uswest4.central.arubanetworks.com"

        

    def get_token_from_db(self):
        query = "SELECT access_token, refresh_token, expires_at FROM token_applications WHERE id = 1;"
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
        INSERT INTO token_applications (id, access_token, refresh_token, expires_in, expires_at, last_updated)
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
    ['app'],  # Añadir etiqueta 'app'
    registry=api_metrics_registry
)
api_requests_success_counter = Counter(
    'api_requests_success_total', 
    'Total number of successful API requests', 
    ['app'],  # Añadir etiqueta 'app'
    registry=api_metrics_registry
)
api_requests_failure_counter = Counter(
    'api_requests_failure_total', 
    'Total number of failed API requests', 
    ['app'],  # Añadir etiqueta 'app'
    registry=api_metrics_registry
)
api_request_duration_gauge = Gauge(
    'api_request_duration_milliseconds',
    'Duration of API requests in milliseconds',
    ['app'],  # Añadir etiqueta 'app'
    registry=api_metrics_registry
)

# ============================================
# CONSULTA A LA API /apprf/datapoints/v2/topn_stats
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
        api_request_duration_gauge.labels(app='apps').set(duration_ms)

        if response.status_code == 401 and not retry:
            logging.info("Token expirado durante la solicitud. Intentando renovar y reintentar la solicitud...")
            if token_manager.verify_and_refresh_token(force_refresh=True):
                return make_api_request(api_path, params, retry=True)
            else:
                logging.error("Error al renovar el token después de recibir un 401.")
                api_requests_failure_counter.labels(app='apps').inc()
                return {"error": "Error al renovar el token"}

        if response.status_code == 200:
            logging.info("Solicitud a la API exitosa.")
            api_requests_success_counter.labels(app='apps').inc()
            return response.json()
        else:
            logging.error(f"Error en la petición: {response.status_code}, {response.text}")
            api_requests_failure_counter.labels(app='apps').inc()
            return {"error": f"Error en la petición: {response.status_code}, {response.text}"}

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000  # Convertir a milisegundos
        api_request_duration_gauge.labels(app='apps').set(duration_ms)
        api_requests_failure_counter.labels(app='apps').inc()
        logging.error(f"Excepción al realizar la solicitud a la API: {e}")
        return {"error": f"Excepción al realizar la solicitud: {e}"}

# Función para recolectar los datos de Top N stats
def collect_topn_stats():
    logging.info("Iniciando la recolección de Top N stats...")
    topn_params = {
        "count": 10,
        "metrics": "app_id"
    }

    # Incrementar el contador de solicitudes
    api_requests_counter.labels(app='apps').inc()

    topn_stats_result = make_api_request("/apprf/datapoints/v2/topn_stats", params=topn_params)

    return topn_stats_result
#mantonio
# Función para enviar los datos a Prometheus Pushgateway
def push_topn_stats_to_gateway(topn_stats_result):
    # Crear un nuevo registro para las métricas de las aplicaciones
    app_registry = CollectorRegistry()

    # Crear métricas tipo Gauge con etiquetas
    data_gauge = Gauge('app_data_bytes', 'Total data for applications (bytes)', ['app_name'], registry=app_registry)
    percent_usage_gauge = Gauge('app_percent_usage', 'Percent usage for applications', ['app_name'], registry=app_registry)
    rx_gauge = Gauge('app_rx_bytes', 'Received data for applications (bytes)', ['app_name'], registry=app_registry)
    tx_gauge = Gauge('app_tx_bytes', 'Transmitted data for applications (bytes)', ['app_name'], registry=app_registry)

    # Asignar valores a las métricas para cada aplicación
    for app in topn_stats_result['result']['app_id']:
        # Normalizar el nombre de la app para las etiquetas
        app_name = app['name'].replace(" ", "_").lower()
        app_name = re.sub(r'[^a-zA-Z0-9_]', '_', app_name)

        data_gauge.labels(app_name=app_name).set(app['data'])
        percent_usage = float(app['percent_usage'].strip('%'))
        percent_usage_gauge.labels(app_name=app_name).set(percent_usage)
        rx_gauge.labels(app_name=app_name).set(app['rx'])
        tx_gauge.labels(app_name=app_name).set(app['tx'])

    # Enviar métricas de las aplicaciones al Pushgateway
    push_to_gateway('172.18.0.4:9091', job='topn_stats_job', registry=app_registry)
    logging.info("Métricas de Top N stats enviadas al Pushgateway")

    # Enviar métricas de la API al Pushgateway
    push_to_gateway('172.18.0.4:9091', job='topn_stats_api_metrics', registry=api_metrics_registry)
    logging.info("Métricas de rendimiento de la API enviadas al Pushgateway")



# Función para recolectar y exportar las métricas cada 5 minutos
def collect_and_push_topn_stats_periodically():
    while True:
        logging.info("Recolectando y enviando datos de Top N stats a Prometheus...")

        # Realiza la llamada a la API para obtener los datos
        topn_stats_result = collect_topn_stats()

        if "error" not in topn_stats_result:
            push_topn_stats_to_gateway(topn_stats_result)

        # Esperar 5 minutos antes de la próxima recolección
        time.sleep(300)

# Iniciar FastAPI con el manejador de ciclo de vida
@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Iniciando FastAPI y recolección de Top N stats.")
    thread = Thread(target=collect_and_push_topn_stats_periodically, daemon=True)
    thread.start()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/topn_stats")
def get_topn_stats():
    return collect_topn_stats()

#ajustado