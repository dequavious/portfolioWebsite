import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import sys


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Incorrect number of arguments used.\n USAGE: python3 setupdb.py <username> [password]\nNB: MAKE SURE "
              "THAT YOUR POSTGRESQL SUPERUSER HAS A PASSWORD SETUP")
        exit(1)

    postgres_user = sys.argv[1]
    postgres_password = sys.argv[2]

    conn = psycopg2.connect(
        host='localhost',
        user=postgres_user,
        password=postgres_password)
    print('CONNECTED ...')

    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

    cur = conn.cursor()
    cur.execute("CREATE USER webadmin WITH PASSWORD 'Mongool2001!';")
    cur.execute(sql.SQL("DROP DATABASE IF EXISTS {};").format(sql.Identifier("portfolio_website")))
    cur.execute(sql.SQL("CREATE DATABASE {} OWNER pay1;").format(sql.Identifier("portfolio")))
