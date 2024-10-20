import psycopg2
import requests
import json
from datetime import datetime, timedelta

# Función para obtener la información del token desde PostgreSQL
def get_token_info():
    try:
        print("Conectando a la base de datos para obtener información del token...")
        connection = psycopg2.connect(
            user="aruba_user", password="maral9", host="localhost", port="5432", database="aruba"
        )
        cursor = connection.cursor()
        cursor.execute("SELECT client_id, client_secret, base_url, refresh_token, access_token, expires_in, last_updated FROM token_info WHERE id = 1;")
        token_info = cursor.fetchone()
        cursor.close()
        connection.close()

        if token_info:
            print("Información del token obtenida con éxito.")
            print(f"Access Token actual: {token_info[4]}")
            print(f"Refresh Token actual: {token_info[3]}")
            return {
                "client_id": token_info[0],
                "client_secret": token_info[1],
                "base_url": token_info[2],
                "refresh_token": token_info[3],
                "access_token": token_info[4],
                "expires_in": token_info[5],
                "last_updated": token_info[6]
            }
        else:
            print("No se encontró información del token en la base de datos.")
            return None
    except Exception as e:
        print(f"Error al obtener la información del token: {e}")
        return None

# Función para hacer el curl y obtener un nuevo token
def refresh_token(token_info):
    if not token_info:
        print("No se puede realizar el refresh sin información del token.")
        return None
    
    try:
        url = f"{token_info['base_url']}/oauth2/token"
        params = {
            'client_id': token_info['client_id'],
            'client_secret': token_info['client_secret'],
            'grant_type': 'refresh_token',
            'refresh_token': token_info['refresh_token']
        }
        
        print(f"Haciendo la solicitud de refresh a: {url}")
        response = requests.post(url, params=params)
        
        if response.status_code == 200:
            new_token_data = response.json()
            print("Nuevo token obtenido con éxito.")
            print(f"Nuevo Access Token: {new_token_data['access_token']}")
            print(f"Nuevo Refresh Token: {new_token_data['refresh_token']}")
            return new_token_data
        else:
            print(f"Error al hacer el refresh del token: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error en la solicitud de refresh del token: {e}")
        return None

# Función para calcular expires_at
def calculate_expires_at(expires_in):
    expires_at = datetime.now() + timedelta(seconds=expires_in)
    return expires_at

# Función para actualizar la información del token en PostgreSQL
def update_token_info(new_token_data):
    try:
        print("Actualizando la información del token en la base de datos...")
        connection = psycopg2.connect(
            user="aruba_user", password="maral9", host="localhost", port="5432", database="aruba"
        )
        cursor = connection.cursor()

        # Calcula el tiempo de expiración exacto
        expires_at = calculate_expires_at(new_token_data['expires_in'])
        
        query = """
        UPDATE token_info 
        SET access_token = %s, refresh_token = %s, expires_in = %s, expires_at = %s, last_updated = %s 
        WHERE id = 1;
        """
        
        cursor.execute(query, (
            new_token_data['access_token'], 
            new_token_data['refresh_token'], 
            new_token_data['expires_in'], 
            expires_at,
            datetime.now()
        ))
        
        connection.commit()
        cursor.close()
        connection.close()
        print(f"Información del token actualizada con éxito en la base de datos. El token expira en: {expires_at}")
    except Exception as e:
        print(f"Error al actualizar la información del token en la base de datos: {e}")

# Main function
if __name__ == "__main__":
    print("Iniciando proceso de refresh del token...")
    token_info = get_token_info()
    
    if token_info:
        print("Información del token obtenida. Procediendo a hacer el refresh...")
        new_token_data = refresh_token(token_info)
        
        if new_token_data:
            print("Actualizando la base de datos con el nuevo token...")
            update_token_info(new_token_data)
            print("Proceso completado con éxito.")
        else:
            print("No se pudo obtener el nuevo token.")
    else:
        print("No se pudo obtener la información del token.")
