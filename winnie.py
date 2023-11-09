#!/usr/bin/env python
import sys
import os
import traceback
import paramiko
import logging
import redis
import requests
import urllib3
import hashlib
import zipfile
from time import sleep
from urllib.parse import urlparse
import argparse
import threading
import socket
import asyncio
import signal
from datetime import datetime
from binascii import hexlify
from paramiko.py3compat import u, decodebytes
import rapidjson
import uvicorn
import aiopg

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    filename='combined_honeypot.log'
)

# Inhiber les avertissements InsecureRequestWarnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Lire les détails de connexion à Redis depuis les variables d'environnement
REDIS_HOST = os.environ.get("REDIS_HOST")
REDIS_PORT = os.environ.get("REDIS_PORT")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, decode_responses=True)

# Configuration PostgreSQL
PG_CONFIG = "host=localhost port=5432 dbname=mydatabase user=user password=password"

# Clé RSA pour le serveur SSH
HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

# Touches de contrôle pour les commandes SSH
UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

# Configuration du serveur SSH
async def handle_connection(reader, writer):
    data = await reader.read()
    decoded_data = data.decode('utf-16')

    try:
        sanitized_data = rapidjson.loads(decoded_data)
        sanitized_data = rapidjson.dumps(sanitized_data)
    except ValueError:
        logging.warning("Données invalides reçues du client : %s", decoded_data)
        return

    async with aiopg.create_pool("host=localhost port=5432 dbname=mydatabase user=user password=password") as pool:
        async with pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "INSERT INTO connections (data) VALUES (%s)",
                    (sanitized_data,)
                )
                await conn.commit()

    logging.info("Données reçues du client : %s", decoded_data)

    message = "Merci de vous connecter"
    encoded_message = message.encode('utf-16')
    writer.write(encoded_message)
    await writer.drain()
    writer.close()

async def main():
    semaphore = asyncio.Semaphore(10)
    server = await uvicorn.serve(handle_connection, '0.0.0.0', 8000)

    loop = asyncio.get_running_loop()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, server.close)

    async def log_activity():
        while True:
            logging.info("Nombre de connexions actives : %s", server.sockets_count)
            await asyncio.sleep(30)
    loop.create_task(log_activity())

    async with semaphore:
        await server.serve_forever()

# Fonction pour télécharger une URL
def downloadURL(url):
    if not r.hexists("checked_urls", url):
        a = urlparse(url)
        file_name = os.path.basename(a.path)
        logging.info('Téléchargement de l\'URL : {}'.format(url))
        m_sha256 = hashlib.sha256()
        file_digest = ''
        chunks = []

        try:
            response = requests.get(url, verify=False, timeout=10)

            if response.status_code == 200:
                for data in response.iter_content(8192):
                    m_sha256.update(data)
                    chunks.append(data)

                file_digest = m_sha256.hexdigest()
                directory = "uploaded_files"
                if not os.path.exists(directory):
                    os.makedirs(directory)

                zip_filename = directory + "/" + file_digest + '.zip'

                if not os.path.isfile(zip_filename):
                    file_contents = b''.join(chunks)
                    with zipfile.ZipFile(zip_filename, mode='w') as myzip:
                        myzip.writestr(file_name, file_contents)

            else:
                print("Pas de réponse http 200 pour l'URL demandée. Reçu : ", response.status_code)
                logging.info("Pas de réponse http 200 pour l'URL demandée. Reçu {}".format(response.status_code))

        except Exception as err:
            print('*** Échec du téléchargement de l\'URL : {}'.format(err))
            logging.info('*** Échec du téléchargement de l\'URL : {}'.format(err))
            traceback.print_exc()

        r.hset("checked_urls", url, file_digest)

print("En attente d'URL à télécharger...")
while True:
    try:
        url_to_download = r.lpop("download_queue")
        if url_to_download:
            downloadURL(url_to_download)
    except Exception as err:
        print('*** Échec du téléchargement de l\'URL : {}'.format(err))
        logging.info('*** Échec du téléchargement de l\'URL : {}'.format(err))
        traceback.print_exc()
    sleep(1)

# Fonction pour gérer les commandes SSH
def handle_cmd(cmd, chan, ip):
    response = ""
    if cmd.startswith("ls"):
        response = "users.txt"
    elif cmd.startswith("pwd"):
        response = "/home/root"

    if response != '':
        logging.info('Réponse du piège ({}): '.format(ip, response))
        response = response + "\r\n"
    chan.send(response)

# Classe pour le piège SSH de base
class BasicSshHoneypot(paramiko.ServerInterface):
    client_ip = None
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logging.info('Le client a appelé check_channel_request ({}): {}'.format(
                    self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        logging.info('Le client a appelé get_allowed_auths ({}) avec le nom d\'utilisateur {}'.format(
                    self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        logging.info('Clé publique du client ({}): nom d\'utilisateur : {}, nom de la clé : {}, empreinte MD5 : {}, base64 : {}, bits : {}'.format(
                    self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_password(self, username, password):
        logging.info('Nouvelles informations d\'authentification du client ({}): nom d\'utilisateur : {}, mot de passe : {}'.format(
                    self.client_ip, username, password))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command_text = str(command.decode("utf-8"))

        logging.info('Le client a envoyé une commande via check_channel_exec_request ({}): {}'.format(
                    self.client_ip, username, command))
        return True

# Fonction pour gérer la connexion SSH
def handle_connection(client, addr):
    client_ip = addr[0]
    logging.info('Nouvelle connexion depuis : {}'.format(client_ip))

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER

        server = BasicSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)

        except paramiko.SSHException:
            print('*** Échec de la négociation SSH.')
            raise Exception("Échec de la négociation SSH")

        chan = transport.accept(10)
        if chan is None:
            print('*** Aucun canal (de '+client_ip+').')
            raise Exception("Aucun canal")

        chan.settimeout(10)

        if transport.remote_mac != '':
            logging.info('Mac du client ({}): {}'.format(client_ip, transport.remote_mac))

        if transport.remote_compression != '':
            logging.info('Compression du client ({}): {}'.format(client_ip, transport.remote_compression))

        if transport.remote_version != '':
            logging.info('Version SSH du client ({}): {}'.format(client_ip, transport.remote_version))

        if transport.remote_cipher != '':
            logging.info('Chiffrement SSH du client ({}): {}'.format(client_ip, transport.remote_cipher))

        server.event.wait(10)
        if not server.event.is_set():
            logging.info('** Client ({}): n\'a jamais demandé de shell'.format(client_ip))
            raise Exception("Aucune demande de shell")

        try:
            chan.send("Bienvenue sur Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
            run = True
            while run:
                chan.send("$ ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip+"- reçu :", transport)
                    if(
                        transport != UP_KEY
                        and transport != DOWN_KEY
                        and transport != LEFT_KEY
                        and transport != RIGHT_KEY
                        and transport != BACK_KEY
                    ):
                        chan.send(transport)
                        command += transport.decode("utf-8")

                chan.send("\r\n")
                command = command.rstrip()
                logging.info('Commande reçue ({}): {}'.format(client_ip, command))
                detect_url(command, client_ip)

                if command == "exit":
                    settings.addLogEntry("Connexion fermée (via la commande exit) : " + client_ip + "\n")
                    run = False

                else:
                    handle_cmd(command, chan, client_ip)

        except Exception as err:
            print('!!! Exception : {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('!!! Exception : {}: {}'.format(err.__class__, err))
        try:
            transport.close()
        except Exception:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exécute un serveur SSH honeypot')
    parser.add_argument("--port", "-p", help="Le port auquel lier le serveur SSH (par défaut 22)", default=2222, type=int, action="store")
    parser.add_argument("--bind", "-b", help="L'adresse à laquelle lier le serveur SSH", default="", type=str, action="store")
    args = parser.parse_args()
    asyncio.run(main())

