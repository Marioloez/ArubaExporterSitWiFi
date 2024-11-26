import os
import json
import requests
import threading
import time
import logging
import psycopg2
from psycopg2 import sql
from threading import Thread
from datetime import datetime, timedelta
import re
from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway
from dotenv import load_dotenv

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
        self.client_id = os.getenv("ARUBA_CLIENT_ID")
        self.client_secret = os.getenv("ARUBA_CLIENT_SECRET")
        self.base_url = "https://apigw-uswest4.central.arubanetworks.com"

    def get_token_from_db(self):
        query = "SELECT access_token, refresh_token, expires_at FROM token_info WHERE id = 1;"
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

        query = """
        UPDATE token_info 
        SET access_token = %s, refresh_token = %s, expires_in = %s, expires_at = %s, last_updated = %s 
        WHERE id = 1;
        """

        self.cursor.execute(query, (
            new_token_data['access_token'],
            new_token_data['refresh_token'],
            new_token_data['expires_in'],
            expires_at,
            datetime.now()
        ))

        self.central_info['token']['access_token'] = new_token_data['access_token']
        self.central_info['token']['refresh_token'] = new_token_data['refresh_token']
        self.central_info['token']['expires_at'] = expires_at

        logging.info(f"Información del token actualizada en la base de datos. El token expira en: {expires_at}")

# Inicializar el TokenManager
token_manager = TokenManager()
print(f"POSTGRES_DB: {os.getenv('POSTGRES_DB')}")
print(f"POSTGRES_USER: {os.getenv('POSTGRES_USER')}")

# ============================================
# CONSULTA A LA API Y GUARDADO EN POSTGRESQL
# ============================================

# Conectar a PostgreSQL
try:
    conn = psycopg2.connect(
        dbname="aruba",
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        host=os.getenv("POSTGRES_HOST"),
        port=os.getenv("POSTGRES_PORT")
    )
    conn.autocommit = True
    cursor = conn.cursor()
    logging.info("Conexión a PostgreSQL exitosa.")
except Exception as e:
    logging.error(f"Error al conectar a PostgreSQL: {e}")

# Verificar si la tabla 'clients' existe y crearla si no
def verify_or_create_clients_table():
    create_table_query = """
    CREATE TABLE IF NOT EXISTS clients (
        macaddr VARCHAR(50) PRIMARY KEY,
        maxspeed INTEGER,
        name VARCHAR(255),
        network VARCHAR(255),
        os_type VARCHAR(50),
        ip_address VARCHAR(50),
        signal_db INTEGER,
        site VARCHAR(255),
        snr INTEGER,
        band VARCHAR(50),
        channel INTEGER,
        speed INTEGER,
        usage INTEGER,
        vlan VARCHAR(50),
        associated_device_mac VARCHAR(50),
        associated_device_name VARCHAR(255),
        last_seen TIMESTAMP
    );
    """
    try:
        cursor.execute(create_table_query)
        logging.info("Tabla 'clients' verificada o creada exitosamente.")
    except Exception as e:
        logging.error(f"Error al crear la tabla 'clients': {e}")

def verify_or_create_client_history_table():
    create_table_query = """
    CREATE TABLE IF NOT EXISTS client_history (
        id SERIAL PRIMARY KEY,
        batch_id BIGINT,
        macaddr VARCHAR(50),
        maxspeed BIGINT,
        name VARCHAR(255),
        network VARCHAR(255),
        os_type VARCHAR(50),
        ip_address VARCHAR(50),
        signal_db BIGINT,
        site VARCHAR(255),
        snr BIGINT,
        band VARCHAR(50),
        channel BIGINT,
        speed BIGINT,
        usage BIGINT,
        vlan VARCHAR(50),
        associated_device_mac VARCHAR(50),
        associated_device_name VARCHAR(255),
        timestamp TIMESTAMP NOT NULL
    );
    """
    try:
        cursor.execute(create_table_query)
        logging.info("Tabla 'client_history' verificada o creada exitosamente.")
    except Exception as e:
        logging.error(f"Error al crear la tabla 'client_history': {e}")

def verify_or_create_aruba_ilusion_aggregations_table():
    create_table_query = """
    CREATE TABLE IF NOT EXISTS aruba_ilusion_aggregations (
        batch_id BIGINT PRIMARY KEY,
        total_clients BIGINT,
        timestamp TIMESTAMP NOT NULL
    );
    """
    try:
        cursor.execute(create_table_query)
        logging.info("Tabla 'aruba_ilusion_aggregations' verificada o creada exitosamente.")
    except Exception as e:
        logging.error(f"Error al crear la tabla 'aruba_ilusion_aggregations': {e}")

# Verificar si las columnas existen en la tabla
def verify_or_create_columns():
    columns_to_check = [
        ("macaddr", "VARCHAR(50) PRIMARY KEY"),
        ("maxspeed", "INTEGER"),
        ("name", "VARCHAR(255)"),
        ("network", "VARCHAR(255)"),
        ("os_type", "VARCHAR(50)"),
        ("ip_address", "VARCHAR(50)"),
        ("signal_db", "INTEGER"),
        ("site", "VARCHAR(255)"),
        ("snr", "INTEGER"),
        ("band", "VARCHAR(50)"),
        ("channel", "INTEGER"),
        ("speed", "INTEGER"),
        ("usage", "INTEGER"),
        ("vlan", "VARCHAR(50)"),
        ("associated_device_mac", "VARCHAR(50)"),
        ("associated_device_name", "VARCHAR(255)"),
        ("last_seen", "TIMESTAMP")
    ]

    for column, column_type in columns_to_check:
        try:
            cursor.execute(f"ALTER TABLE clients ADD COLUMN IF NOT EXISTS {column} {column_type};")
            logging.info(f"Columna '{column}' verificada o creada exitosamente.")
        except Exception as e:
            logging.error(f"Error al verificar o crear la columna '{column}': {e}")

# Llamar a las funciones de verificación y creación al iniciar
def setup_database():
    verify_or_create_clients_table()
    verify_or_create_columns()
    verify_or_create_client_history_table()
    verify_or_create_aruba_ilusion_aggregations_table()

# Definir las métricas de rendimiento de la API
def setup_api_metrics():
    registry = CollectorRegistry()

    # Métricas de la API con etiquetas adicionales
    api_requests_counter = Counter(
        'api_requests_total', 
        'Total number of API requests made', 
        ['user_experience'],
        registry=registry
    )
    api_requests_success_counter = Counter(
        'api_requests_success_total', 
        'Total number of successful API requests', 
        ['user_experience'],
        registry=registry
    )
    api_requests_failure_counter = Counter(
        'api_requests_failure_total', 
        'Total number of failed API requests', 
        ['user_experience'],
        registry=registry
    )
    api_request_duration_gauge = Gauge(
        'api_request_duration_milliseconds',
        'Duration of API requests in milliseconds',
        ['user_experience'],
        registry=registry
    )

    # Métricas de clientes inalámbricos
    avg_signal_db_gauge = Gauge('average_signal_db', 'Average signal strength of wireless clients', registry=registry)
    avg_snr_gauge = Gauge('average_snr', 'Average signal-to-noise ratio of wireless clients', registry=registry)
    avg_usage_gauge = Gauge('average_usage', 'Average data usage of wireless clients', registry=registry)

    max_signal_db_gauge = Gauge('max_signal_db', 'Max signal strength of wireless clients', registry=registry)
    min_signal_db_gauge = Gauge('min_signal_db', 'Min signal strength of wireless clients', registry=registry)
    max_snr_gauge = Gauge('max_snr', 'Max SNR of wireless clients', registry=registry)
    min_snr_gauge = Gauge('min_snr', 'Min SNR of wireless clients', registry=registry)

    max_usage_gauge = Gauge('max_usage', 'Max data usage of wireless clients', registry=registry)
    min_usage_gauge = Gauge('min_usage', 'Min data usage of wireless clients', registry=registry)

    total_clients_gauge = Gauge('total_wireless_clients', 'Total number of wireless clients', registry=registry)

    return {
        'registry': registry,
        'api_requests_counter': api_requests_counter,
        'api_requests_success_counter': api_requests_success_counter,
        'api_requests_failure_counter': api_requests_failure_counter,
        'api_request_duration_gauge': api_request_duration_gauge,
        'avg_signal_db_gauge': avg_signal_db_gauge,
        'avg_snr_gauge': avg_snr_gauge,
        'avg_usage_gauge': avg_usage_gauge,
        'max_signal_db_gauge': max_signal_db_gauge,
        'min_signal_db_gauge': min_signal_db_gauge,
        'max_snr_gauge': max_snr_gauge,
        'min_snr_gauge': min_snr_gauge,
        'max_usage_gauge': max_usage_gauge,
        'min_usage_gauge': min_usage_gauge,
        'total_clients_gauge': total_clients_gauge
    }

def make_api_request(api_path, method="GET", params=None, retry=False, metrics=None):
    if not token_manager.verify_and_refresh_token():
        return {"error": "No se pudo renovar el token"}

    headers = {
        'Authorization': f"Bearer {token_manager.central_info['token']['access_token']}",
        'Content-Type': 'application/json'
    }

    url = f"{token_manager.base_url}{api_path}"
    logging.info(f"Haciendo solicitud a {url}")

    # Valor de la etiqueta
    user_experience_label = 'true'

    # Incrementar el contador de solicitudes totales
    if metrics:
        metrics['api_requests_counter'].labels(user_experience=user_experience_label).inc()

    start_time = time.time()
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=params)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=params)
        else:
            logging.error("Método HTTP no soportado")
            return {"error": "Método HTTP no soportado"}

        duration_ms = (time.time() - start_time) * 1000  # Convertir a milisegundos
        if metrics:
            metrics['api_request_duration_gauge'].labels(user_experience=user_experience_label).set(duration_ms)

        if response.status_code == 401 and not retry:
            logging.info("Token expirado durante la solicitud. Intentando renovar y reintentar la solicitud...")
            if token_manager.verify_and_refresh_token(force_refresh=True):
                return make_api_request(api_path, method, params, retry=True, metrics=metrics)
            else:
                logging.error("Error al renovar el token después de recibir un 401.")
                if metrics:
                    metrics['api_requests_failure_counter'].labels(user_experience=user_experience_label).inc()
                return {"error": "Error al renovar el token"}

        if response.status_code == 200:
            logging.info("Solicitud a la API exitosa.")
            if metrics:
                metrics['api_requests_success_counter'].labels(user_experience=user_experience_label).inc()
            return response.json()
        else:
            logging.error(f"Error en la petición: {response.status_code}, {response.text}")
            if metrics:
                metrics['api_requests_failure_counter'].labels(user_experience=user_experience_label).inc()
            return {"error": f"Error en la petición: {response.status_code}, {response.text}"}

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000  # Convertir a milisegundos
        if metrics:
            metrics['api_request_duration_gauge'].labels(user_experience=user_experience_label).set(duration_ms)
            metrics['api_requests_failure_counter'].labels(user_experience=user_experience_label).inc()
        logging.error(f"Excepción al realizar la solicitud a la API: {e}")
        return {"error": f"Excepción al realizar la solicitud: {e}"}

# Función para limpiar el valor de `channel`
def extract_channel(channel_value):
    try:
        match = re.match(r"(\d+)", str(channel_value))
        if match:
            return int(match.group(1))
        else:
            return 0
    except:
        return 0

# Función para limpiar los valores de texto de caracteres NUL
def clean_text(value):
    if isinstance(value, str):
        return value.replace('\x00', '')
    return value

# ============================================
# PARA ALMACENAMIENTO ACTUAL DE CLIENTES
# ============================================

# Función para almacenar los clientes en PostgreSQL
def store_clients_in_postgresql(all_clients):
    logging.info("Almacenando clientes en PostgreSQL...")

    now = datetime.now()

    for client in all_clients:
        client_mac = client.get('macaddr', 'unknown')
        if client_mac == 'unknown':
            continue

        client_cleaned = {
            'macaddr': clean_text(client.get('macaddr', 'unknown')),
            'maxspeed': client.get('maxspeed', 0),
            'name': clean_text(client.get('name', 'unknown')),
            'network': clean_text(client.get('network', 'unknown')),
            'os_type': clean_text(client.get('os_type', 'unknown')),
            'ip_address': clean_text(client.get('ip_address', 'unknown')),
            'signal_db': client.get('signal_db', 0),
            'site': clean_text(client.get('site', 'unknown')),
            'snr': client.get('snr', 0),
            'band': clean_text(client.get('band', 'unknown')),
            'channel': extract_channel(client.get('channel', 0)),
            'speed': client.get('speed', 0),
            'usage': client.get('usage', 0),
            'vlan': clean_text(client.get('vlan', 'unknown')),
            'associated_device_mac': clean_text(client.get('associated_device_mac', 'unknown')),
            'associated_device_name': clean_text(client.get('associated_device_name', 'unknown'))
        }

        query = sql.SQL("""
            INSERT INTO clients (macaddr, maxspeed, name, network, os_type, ip_address, signal_db, site, snr, band, 
                channel, speed, usage, vlan, associated_device_mac, associated_device_name, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (macaddr) 
            DO UPDATE SET maxspeed = EXCLUDED.maxspeed, name = EXCLUDED.name, network = EXCLUDED.network, 
                os_type = EXCLUDED.os_type, ip_address = EXCLUDED.ip_address, signal_db = EXCLUDED.signal_db, 
                site = EXCLUDED.site, snr = EXCLUDED.snr, band = EXCLUDED.band, channel = EXCLUDED.channel, 
                speed = EXCLUDED.speed, usage = EXCLUDED.usage, vlan = EXCLUDED.vlan, 
                associated_device_mac = EXCLUDED.associated_device_mac, 
                associated_device_name = EXCLUDED.associated_device_name, last_seen = EXCLUDED.last_seen;
        """)

        cursor.execute(query, (
            client_cleaned['macaddr'], client_cleaned['maxspeed'], client_cleaned['name'],
            client_cleaned['network'], client_cleaned['os_type'], client_cleaned['ip_address'],
            client_cleaned['signal_db'], client_cleaned['site'], client_cleaned['snr'],
            client_cleaned['band'], client_cleaned['channel'], client_cleaned['speed'],
            client_cleaned['usage'], client_cleaned['vlan'], client_cleaned['associated_device_mac'],
            client_cleaned['associated_device_name'], now
        ))

    logging.info(f"{len(all_clients)} clientes almacenados y actualizados en PostgreSQL correctamente.")

# ============================================
# PARA ALMACENAMIENTO HISTÓRICO DE CLIENTES
# ============================================

def store_clients_history(all_clients, batch_id):
    logging.info("Almacenando historial de clientes en PostgreSQL...")

    now = datetime.now()

    insert_query = sql.SQL("""
        INSERT INTO client_history (batch_id, macaddr, maxspeed, name, network, os_type, ip_address, signal_db, site, snr, band,
            channel, speed, usage, vlan, associated_device_mac, associated_device_name, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """)

    for client in all_clients:
        client_mac = client.get('macaddr', 'unknown')
        if client_mac == 'unknown':
            continue

        client_cleaned = {
            'batch_id': batch_id,
            'macaddr': clean_text(client.get('macaddr', 'unknown')),
            'maxspeed': client.get('maxspeed', 0),
            'name': clean_text(client.get('name', 'unknown')),
            'network': clean_text(client.get('network', 'unknown')),
            'os_type': clean_text(client.get('os_type', 'unknown')),
            'ip_address': clean_text(client.get('ip_address', 'unknown')),
            'signal_db': client.get('signal_db', 0),
            'site': clean_text(client.get('site', 'unknown')),
            'snr': client.get('snr', 0),
            'band': clean_text(client.get('band', 'unknown')),
            'channel': extract_channel(client.get('channel', 0)),
            'speed': client.get('speed', 0),
            'usage': client.get('usage', 0),
            'vlan': clean_text(client.get('vlan', 'unknown')),
            'associated_device_mac': clean_text(client.get('associated_device_mac', 'unknown')),
            'associated_device_name': clean_text(client.get('associated_device_name', 'unknown')),
            'timestamp': now
        }

        try:
            cursor.execute(insert_query, (
                client_cleaned['batch_id'], client_cleaned['macaddr'], client_cleaned['maxspeed'], client_cleaned['name'],
                client_cleaned['network'], client_cleaned['os_type'], client_cleaned['ip_address'],
                client_cleaned['signal_db'], client_cleaned['site'], client_cleaned['snr'],
                client_cleaned['band'], client_cleaned['channel'], client_cleaned['speed'],
                client_cleaned['usage'], client_cleaned['vlan'], client_cleaned['associated_device_mac'],
                client_cleaned['associated_device_name'], client_cleaned['timestamp']
            ))
        except Exception as e:
            logging.error(f"Error al insertar el historial del cliente {client_mac}: {e}")
            conn.rollback()
    conn.commit()
    logging.info(f"Historial de {len(all_clients)} clientes almacenado correctamente.")

def store_batch_info(batch_id, total_clients):
    logging.info("Almacenando información del lote en 'aruba_ilusion_aggregations'...")

    now = datetime.now()

    insert_query = sql.SQL("""
        INSERT INTO aruba_ilusion_aggregations (batch_id, total_clients, timestamp)
        VALUES (%s, %s, %s);
    """)

    try:
        cursor.execute(insert_query, (batch_id, total_clients, now))
        conn.commit()
        logging.info(f"Información del lote {batch_id} almacenada correctamente en 'aruba_ilusion_aggregations'.")
    except Exception as e:
        logging.error(f"Error al insertar información del lote {batch_id}: {e}")
        conn.rollback()

def calculate_metrics(all_clients):
    logging.info(f"Calculando métricas para {len(all_clients)} clientes.")

    valid_clients_signal = [client for client in all_clients if 'signal_db' in client and client['signal_db'] is not None]
    valid_clients_snr = [client for client in all_clients if 'snr' in client and client['snr'] is not None]
    valid_clients_usage = [client for client in all_clients if 'usage' in client and client['usage'] is not None]

    if valid_clients_signal:
        avg_signal_db = sum(client['signal_db'] for client in valid_clients_signal) / len(valid_clients_signal)
        max_signal_db = max(client['signal_db'] for client in valid_clients_signal)
        min_signal_db = min(client['signal_db'] for client in valid_clients_signal)
    else:
        avg_signal_db = max_signal_db = min_signal_db = 0
        logging.warning("No se encontraron clientes con 'signal_db' disponible.")

    if valid_clients_snr:
        avg_snr = sum(client['snr'] for client in valid_clients_snr) / len(valid_clients_snr)
        max_snr = max(client['snr'] for client in valid_clients_snr)
        min_snr = min(client['snr'] for client in valid_clients_snr)
    else:
        avg_snr = max_snr = min_snr = 0
        logging.warning("No se encontraron clientes con 'snr' disponible.")

    if valid_clients_usage:
        avg_usage = sum(client['usage'] for client in valid_clients_usage) / len(valid_clients_usage)
        max_usage = max(client['usage'] for client in valid_clients_usage)
        min_usage = min(client['usage'] for client in valid_clients_usage)
    else:
        avg_usage = max_usage = min_usage = 0
        logging.warning("No se encontraron clientes con 'usage' disponible.")

    logging.info(f"Métricas calculadas: avg_signal_db={avg_signal_db}, avg_snr={avg_snr}, avg_usage={avg_usage}")

    return {
        'avg_signal_db': avg_signal_db,
        'avg_snr': avg_snr,
        'avg_usage': avg_usage,
        'max_signal_db': max_signal_db,
        'min_signal_db': min_signal_db,
        'max_snr': max_snr,
        'min_snr': min_snr,
        'max_usage': max_usage,
        'min_usage': min_usage
    }

def push_metrics_to_gateway(metrics, total_clients, api_metrics):
    logging.info("Enviando métricas al Pushgateway...")

    # Usar el registry de las métricas de la API
    registry = api_metrics['registry']

    # Obtener las métricas existentes del api_metrics
    avg_signal_db_gauge = api_metrics['avg_signal_db_gauge']
    avg_snr_gauge = api_metrics['avg_snr_gauge']
    avg_usage_gauge = api_metrics['avg_usage_gauge']

    max_signal_db_gauge = api_metrics['max_signal_db_gauge']
    min_signal_db_gauge = api_metrics['min_signal_db_gauge']
    max_snr_gauge = api_metrics['max_snr_gauge']
    min_snr_gauge = api_metrics['min_snr_gauge']

    max_usage_gauge = api_metrics['max_usage_gauge']
    min_usage_gauge = api_metrics['min_usage_gauge']

    total_clients_gauge = api_metrics['total_clients_gauge']

    # Establecer los valores de las métricas
    avg_signal_db_gauge.set(metrics['avg_signal_db'])
    avg_snr_gauge.set(metrics['avg_snr'])
    avg_usage_gauge.set(metrics['avg_usage'])

    max_signal_db_gauge.set(metrics['max_signal_db'])
    min_signal_db_gauge.set(metrics['min_signal_db'])
    max_snr_gauge.set(metrics['max_snr'])
    min_snr_gauge.set(metrics['min_snr'])

    max_usage_gauge.set(metrics['max_usage'])
    min_usage_gauge.set(metrics['min_usage'])

    total_clients_gauge.set(total_clients)

    # Enviar todas las métricas al Pushgateway
    push_to_gateway('pushgateway_aruba:9091', job='wireless_clients_statistics', registry=registry)
    logging.info("Métricas enviadas al Pushgateway exitosamente.")

# Recolectar los datos de clientes inalámbricos y calcular las métricas
def collect_wireless_clients():
    # Inicializar las métricas de la API
    api_metrics = setup_api_metrics()

    while True:
        logging.info("Iniciando la recolección de clientes inalámbricos...")

        # Generar un batch_id único (puede ser un timestamp o un incremental)
        batch_id = int(time.time())
        logging.info(f"Batch ID generado: {batch_id}")

        wireless_clients_params = {
            "limit": 1000,
            "offset": 0,
            "client_type": "WIRELESS",
            "client_status": "CONNECTED",
            "show_usage": "true",
            "show_signal_db": "true",
            "timerange": "3H"
        }

        all_clients = []
        while True:
            wireless_clients_result = make_api_request("/monitoring/v2/clients", params=wireless_clients_params, metrics=api_metrics)
            if "error" in wireless_clients_result:
                logging.error("Error al obtener los datos de los clientes inalámbricos.")
                break

            clients = wireless_clients_result.get('clients', [])
            all_clients.extend(clients)

            if len(clients) < wireless_clients_params['limit']:
                break

            wireless_clients_params['offset'] += wireless_clients_params['limit']

        if all_clients:
            total_clients = len(all_clients)
            logging.info(f"Total de clientes recolectados: {total_clients}")
            # Llamada a la función para almacenar los clientes en PostgreSQL
            store_clients_history(all_clients, batch_id)
            store_clients_in_postgresql(all_clients)
            # Almacenar información del lote en 'aruba_ilusion_aggregations'
            store_batch_info(batch_id, total_clients)
            metrics = calculate_metrics(all_clients)
            push_metrics_to_gateway(metrics, total_clients, api_metrics)
        else:
            logging.info("No se encontraron clientes inalámbricos conectados.")

        time.sleep(600)

if __name__ == "__main__":
    # Código de inicio
    logging.info("Iniciando la recolección de clientes inalámbricos.")
    setup_database()  # Verifica la base de datos al iniciar
    thread = Thread(target=collect_wireless_clients, daemon=True)
    thread.start()

    # Mantener el programa en ejecución
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Programa detenido por el usuario.")
