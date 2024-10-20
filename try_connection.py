import psycopg2
import os

try:
    connection = psycopg2.connect(
        dbname="aruba",
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        host='172.18.0.2',
        port=os.getenv("POSTGRES_PORT")
    )
    cursor = connection.cursor()
    cursor.execute("SELECT 1;")
    print("Conexión exitosa a la base de datos.")
except Exception as e:
    print(f"Error al conectar a la base de datos: {e}")
