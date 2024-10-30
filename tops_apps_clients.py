import os
import json
import requests
import logging
import psycopg2
from psycopg2 import sql
from fastapi import FastAPI
from prometheus_client import CollectorRegistry, Counter, Gauge, push_to_gateway
from dotenv import load_dotenv
from datetime import datetime, timedelta

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
        self.client_id = os.getenv("ARUBA_APPLICATIONS_PER_CLIENT_ID")
        self.client_secret = os.getenv("ARUBA_APPLICATIONS_PER_CLIENT_SECRET")
        self.base_url = "https://apigw-uswest4.central.arubanetworks.com"

    def get_token_from_db(self):
        query = "SELECT access_token, refresh_token, expires_at FROM token_apps_client WHERE id = 1;"
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
        INSERT INTO token_apps_client (id, access_token, refresh_token, expires_in, expires_at, last_updated)
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
    logging.info(f"Haciendo solicitud a {url} con parámetros {params}")

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            logging.info("Solicitud a la API exitosa.")
            return response.json()
        else:
            logging.error(f"Error en la petición: {response.status_code}, {response.text}")
            return {"error": f"Error en la petición: {response.status_code}, {response.text}"}

    except Exception as e:
        logging.error(f"Excepción al realizar la solicitud a la API: {e}")
        return {"error": f"Excepción al realizar la solicitud: {e}"}

# Función para desglosar los datos de Top N stats
def desglosar_topn_stats(topn_stats_result):
    desglosado = []

    # Verificar si 'app_id' está en los resultados
    if 'result' in topn_stats_result and 'app_id' in topn_stats_result['result']:
        for app in topn_stats_result['result']['app_id']:
            desglosado.append({
                'app_name': app['name'],
                'app_category': app['app_cat']['name'],
                'data_bytes': app['data'],
                'rx_bytes': app['rx'],
                'tx_bytes': app['tx'],
                'percent_usage': app['percent_usage'],
                'timestamp': app['timestamp']
            })

    return desglosado

# Iniciar FastAPI
app = FastAPI()

@app.get("/topn_stats")
def get_topn_stats(macaddr: str):
    # Realizar la consulta a la API
    topn_stats_result = make_api_request("/apprf/datapoints/v2/topn_stats", params={"count": 10, "metrics": "app_id", "macaddr": macaddr})

    if "error" in topn_stats_result:
        return topn_stats_result

    # Desglosar los resultados de la API
    desglosado = desglosar_topn_stats(topn_stats_result)

    return desglosado
