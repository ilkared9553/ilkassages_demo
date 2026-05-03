import flet as ft
import socket
import threading
import os
import struct
import sqlite3
import ssl
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime

# Отключаем проверку SSL
ssl._create_default_https_context = ssl._create_unverified_context

# Цвета стиля
TG_BG = "#0e1621"
TG_SIDEBAR = "#17212b"
TG_ACCENT = "#242f3d"
TG_BLUE = "#5288c1"
TG_RED = "#e53935"
TEXT_WHITE = "#ffffff"


def main(page: ft.Page):
    page.title = "P2P Secure Bridge"
    page.bgcolor = TG_BG
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0

    state = {"conn": None, "server_socket": None, "connected": False}
    db_lock = threading.Lock()

    # Инициализация и авто-миграция базы данных
    db_path = os.path.join(os.getcwd(), "p2p_vault.db")
    db_conn = sqlite3.connect(db_path, check_same_thread=False)
    cursor = db_conn.cursor()
    with db_lock:
        # Создаем таблицу, если её нет
        cursor.execute('''CREATE TABLE IF NOT EXISTS messages 
                          (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, 
                           sender TEXT, content TEXT)''')

        # ПРОВЕРКА И ДОБАВЛЕНИЕ КОЛОНКИ ts (чтобы не было ошибки)
        cursor.execute("PRAGMA table_info(messages)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'ts' not in columns:
            cursor.execute("ALTER TABLE messages ADD COLUMN ts TEXT")

        db_conn.commit()

    # --- ИНТЕРФЕЙС ---
    chat_view = ft.ListView(expand=True, spacing=10, auto_scroll=True, padding=15)

    def on_send_click(e):
        send_logic()

    msg_entry = ft.TextField(
        hint_text="Сообщение...",
        expand=True,
        bgcolor=TG_ACCENT,
        border_radius=25,
        border_color=ft.Colors.TRANSPARENT,
        on_submit=on_send_click
    )

    key_input = ft.TextField(label="Ключ шифрования", password=True, can_reveal_password=True)
    ip_input = ft.TextField(label="IP Адрес", value="127.0.0.1")
    port_input = ft.TextField(label="Порт", value="5000")
    history_column = ft.Column(scroll=ft.ScrollMode.AUTO)

    def append_message(text, sender="sys", save=True):
        clean_key = key_input.value.strip() if key_input.value else ""
        if save and clean_key:
            ts = datetime.now().strftime("%H:%M")
            try:
                with db_lock:
                    cursor.execute("INSERT INTO messages (session_id, sender, content, ts) VALUES (?, ?, ?, ?)",
                                   (clean_key, sender, text, ts))
                    db_conn.commit()
                update_sidebar_list()
            except Exception as e:
                print(f"Ошибка сохранения в БД: {e}")

        align = ft.MainAxisAlignment.END if sender == "me" else ft.MainAxisAlignment.START if sender == "peer" else ft.MainAxisAlignment.CENTER
        bubble_color = "#2b5278" if sender == "me" else "#182533" if sender == "peer" else TG_ACCENT

        chat_view.controls.append(
            ft.Row([
                ft.Container(
                    content=ft.Text(text, color=TEXT_WHITE, selectable=True),
                    bgcolor=bubble_color,
                    padding=12,
                    border_radius=15,
                    width=min(page.width * 0.75, 450) if page.width > 0 else 300,
                )
            ], alignment=align)
        )
        page.update()

    # --- СЕТЬ ---
    def recvall(sock, n):
        data = bytearray()
        while len(data) < n:
            try:
                packet = sock.recv(n - len(data))
                if not packet: return None
                data.extend(packet)
            except:
                return None
        return bytes(data)

    def socket_receiver():
        while state["connected"]:
            try:
                conn = state["conn"]
                if not conn: break

                clean_key = key_input.value.strip()
                cipher = Fernet(clean_key.encode('utf-8'))

                header = recvall(conn, 4)
                if not header: break

                msg_len = struct.unpack('>I', header)[0]
                payload = recvall(conn, msg_len)
                if not payload: break

                decoded = cipher.decrypt(payload).decode('utf-8')
                if decoded.startswith("T:"):
                    append_message(decoded[2:], "peer")
            except Exception:
                break
        disconnect_logic()

    def disconnect_logic(e=None):
        if state["connected"]:
            append_message("Связь прервана", "sys", save=False)
        state["connected"] = False
        if state["conn"]:
            try:
                state["conn"].close()
            except:
                pass
            state["conn"] = None
        if state.get("server_socket"):
            try:
                state["server_socket"].close()
            except:
                pass
            state["server_socket"] = None
        page.update()

    def connect_action(mode):
        clean_key = key_input.value.strip() if key_input.value else ""
        if not clean_key:
            append_message("ОШИБКА: Нет ключа!", "sys", save=False)
            return

        def thread_task():
            try:
                disconnect_logic()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                p = int(port_input.value.strip())
                if mode == "host":
                    state["server_socket"] = s
                    s.bind(('', p))
                    s.listen(1)
                    append_message(f"Ожидание на порту {p}...", "sys", save=False)
                    conn, addr = s.accept()
                    state["conn"] = conn
                else:
                    target_ip = ip_input.value.strip()
                    append_message(f"Подключение к {target_ip}...", "sys", save=False)
                    s.connect((target_ip, p))
                    state["conn"] = s

                state["connected"] = True
                append_message("Связь установлена!", "sys", save=False)
                settings_dlg.open = False
                page.update()
                socket_receiver()
            except Exception as ex:
                append_message(f"Ошибка: {ex}", "sys", save=False)
                disconnect_logic()

        threading.Thread(target=thread_task, daemon=True).start()

    def send_logic():
        if not msg_entry.value or not state["connected"]:
            return
        try:
            clean_key = key_input.value.strip()
            cipher = Fernet(clean_key.encode('utf-8'))
            data = cipher.encrypt(f"T:{msg_entry.value}".encode('utf-8'))
            state["conn"].sendall(struct.pack('>I', len(data)) + data)
            append_message(msg_entry.value, "me")
            msg_entry.value = ""
            page.update()
        except Exception as ex:
            append_message(f"Ошибка отправки: {ex}", "sys", save=False)

    # --- ИНТЕРФЕЙСНЫЕ МЕНЕДЖЕРЫ ---
    def generate_key_handler(e):
        key_input.value = Fernet.generate_key().decode()
        page.update()

    settings_dlg = ft.AlertDialog(
        title=ft.Text("Настройки"),
        content=ft.Column([
            key_input,
            ft.TextButton("Создать ключ", on_click=generate_key_handler),
            ip_input, port_input,
            ft.Row([
                ft.FilledButton("ХОСТ", on_click=lambda _: connect_action("host"), bgcolor=TG_BLUE),
                ft.FilledButton("ВХОД", on_click=lambda _: connect_action("cli"), bgcolor=TG_BLUE),
            ], alignment=ft.MainAxisAlignment.CENTER),
            ft.TextButton("Отключиться", on_click=disconnect_logic, style=ft.ButtonStyle(color=TG_RED))
        ], tight=True, spacing=15)
    )

    def update_sidebar_list():
        history_column.controls.clear()
        try:
            with db_lock:
                cursor.execute("SELECT DISTINCT session_id FROM messages")
                rows = cursor.fetchall()
            for res in rows:
                sid = res[0]
                history_column.controls.append(
                    ft.ListTile(
                        leading=ft.Icon(ft.Icons.LOCK, color=TG_BLUE),
                        title=ft.Text(f"Сессия: {sid[:10]}...", size=14),
                        on_click=lambda e, k=sid: load_history_session(k)
                    )
                )
        except:
            pass
        page.update()

    def load_history_session(key):
        key_input.value = key
        chat_view.controls.clear()
        with db_lock:
            cursor.execute("SELECT sender, content FROM messages WHERE session_id = ? ORDER BY id ASC", (key,))
            rows = cursor.fetchall()
        for row in rows:
            append_message(row[1], row[0], save=False)
        page.drawer.open = False
        page.update()

    page.drawer = ft.NavigationDrawer(
        bgcolor=TG_SIDEBAR,
        controls=[
            ft.Container(padding=25, content=ft.Text("Архив", size=22, weight="bold")),
            history_column
        ]
    )

    page.appbar = ft.AppBar(
        leading=ft.IconButton(ft.Icons.MENU, on_click=lambda _: setattr(page.drawer, "open", True) or page.update()),
        title=ft.Text("Secure Bridge"),
        bgcolor=TG_SIDEBAR,
        actions=[
            ft.IconButton(ft.Icons.SETTINGS, on_click=lambda _: setattr(settings_dlg, "open", True) or page.update())]
    )

    page.overlay.append(settings_dlg)
    page.add(ft.Column([chat_view, ft.Container(bgcolor=TG_SIDEBAR, padding=10, content=ft.Row(
        [msg_entry, ft.IconButton(ft.Icons.SEND, on_click=on_send_click, icon_color=TG_BLUE)]))], expand=True))
    update_sidebar_list()


if __name__ == "__main__":
    ft.run(main)