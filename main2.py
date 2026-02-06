# main_app.py
import os
import json
import threading
import traceback
import socket
import time
import customtkinter as ctk
from customtkinter import CTkImage
from tkinter import filedialog, messagebox
from PIL import Image
import io
import hashlib
import base64
import secrets
import sys
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32api
import threading

# try to import AESGCM
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_AESGCM = True
except Exception:
    HAVE_AESGCM = False

# Fixed key for mapping file encryption (32 bytes for AES256)
MAPPING_ENCRYPTION_KEY = b'fixed_key_for_mapping_32_bytes!!'  # 32 bytes

# -----------------------------
# Configuration & helpers
# -----------------------------
DEVICES_FILE = "devices.json"
MAPPING_FILE = "mapping.json"
SENDER_PORT_DEFAULT = 9003
CHUNK_HEADER_SEP = b'||'
ACK_TIMEOUT = 2.0  # seconds

local_ip = socket.gethostbyname(socket.gethostname())
stored_parts = {}  # part_id -> {"payload": bytes, "sender_ip": str, "device_name": str}
OP_SEP = b'|OP_SEP|'
CLIENT_STORED_PARTS_FILE = "client_stored_parts.json"
stop_event = threading.Event()

# load stored_parts from file on startup
def load_stored_parts():
    global stored_parts
    if os.path.exists(CLIENT_STORED_PARTS_FILE):
        try:
            with open(CLIENT_STORED_PARTS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for pid, meta in data.items():
                    stored_parts[int(pid)] = {
                        "payload": base64.b64decode(meta["payload_b64"]),
                        "sender_ip": meta["sender_ip"],
                        "device_name": meta["device_name"]
                    }
        except Exception as e:
            print(f"Error loading stored parts: {e}")

# save stored_parts to file
def save_stored_parts():
    data = {}
    for pid, meta in stored_parts.items():
        data[str(pid)] = {
            "payload_b64": base64.b64encode(meta["payload"]).decode("utf-8"),
            "sender_ip": meta["sender_ip"],
            "device_name": meta["device_name"]
        }
    try:
        with open(CLIENT_STORED_PARTS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving stored parts: {e}")

# Server code
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((local_ip, SENDER_PORT_DEFAULT))
    server_socket.listen(5)
    server_socket.settimeout(1.0)  # timeout to allow checking stop_event
    print(f"Server started on {local_ip}:{SENDER_PORT_DEFAULT}")
    while not stop_event.is_set():
        try:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Server error: {e}")
            break
    server_socket.close()

def handle_client(client_socket, addr):
    try:
        len_bytes = client_socket.recv(8)
        if not len_bytes:
            client_socket.close()
            return
        length = int.from_bytes(len_bytes, "big")
        data = b""
        while len(data) < length:
            chunk = client_socket.recv(min(4096, length - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) != length:
            client_socket.close()
            return
        if OP_SEP in data:
            op_part, body = data.split(OP_SEP, 1)
            op = json.loads(op_part.decode("utf-8"))
            operation = op.get("operation")
            if operation == "RETRIEVE":
                segment_id = op.get("segment_id")
                if segment_id in stored_parts:
                    requester_ip = addr[0]
                    sender_ip = stored_parts[segment_id]["sender_ip"]
                    if requester_ip == sender_ip:
                        part_data = stored_parts[segment_id]["payload"]
                        client_socket.sendall(len(part_data).to_bytes(8, "big"))
                        client_socket.sendall(part_data)
                    else:
                        error = json.dumps({"error": "access denied"}).encode("utf-8")
                        client_socket.sendall(len(error).to_bytes(8, "big"))
                        client_socket.sendall(error)
                else:
                    error = json.dumps({"error": "part not found"}).encode("utf-8")
                    client_socket.sendall(len(error).to_bytes(8, "big"))
                    client_socket.sendall(error)
            else:
                error = json.dumps({"error": "unknown operation"}).encode("utf-8")
                client_socket.sendall(len(error).to_bytes(8, "big"))
                client_socket.sendall(error)
        else:
            # assume batch SEND
            offset = 0
            while offset < len(data):
                if offset + 8 > len(data):
                    break
                part_len_bytes = data[offset:offset+8]
                part_len = int.from_bytes(part_len_bytes, "big")
                offset += 8
                if offset + part_len > len(data):
                    break
                part_data = data[offset:offset+part_len]
                offset += part_len
                # parse part_data
                header_end = part_data.find(CHUNK_HEADER_SEP)
                if header_end == -1:
                    continue
                header_raw = part_data[:header_end]
                payload = part_data[header_end + len(CHUNK_HEADER_SEP):]
                header = json.loads(header_raw.decode("utf-8"))
                part_id = header.get("part_id")
                stored_parts[part_id] = {
                    "payload": payload,
                    "sender_ip": header.get("sender_ip"),
                    "device_name": header.get("device_name")
                }
                ack = json.dumps({"ack": part_id}).encode("utf-8")
                client_socket.sendall(len(ack).to_bytes(8, "big"))
                client_socket.sendall(ack)
            # save after batch
            save_stored_parts()
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def load_devices():
    if os.path.exists(DEVICES_FILE):
        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_devices(devmap):
    with open(DEVICES_FILE, "w", encoding="utf-8") as f:
        json.dump(devmap, f, indent=2)

def load_mapping_file():
    if os.path.exists(MAPPING_FILE):
        try:
            with open(MAPPING_FILE, "r", encoding="utf-8") as f:
                new_mapping = json.load(f)
            mapping = {}
            for image_name, encrypted_b64 in new_mapping.items():
                encrypted_data = base64.b64decode(encrypted_b64)
                if HAVE_AESGCM and len(encrypted_data) > 12:
                    aesgcm = AESGCM(MAPPING_ENCRYPTION_KEY)
                    nonce = encrypted_data[:12]
                    ct = encrypted_data[12:]
                    decrypted = aesgcm.decrypt(nonce, ct, None)
                    sensitive_data = json.loads(decrypted.decode('utf-8'))
                else:
                    sensitive_data = json.loads(encrypted_data.decode('utf-8'))
                entry = sensitive_data
                entry['image_name'] = image_name
                mapping[entry['original_hash']] = entry
            return mapping
        except Exception as e:
            print(f"Error loading mapping: {e}")
            return {}
    return {}

def save_mapping_file(mapping):
    new_mapping = {}
    for image_key, entry in mapping.items():
        image_name = entry.get('image_name', image_key)
        sensitive_data = {
            'total_parts': entry['total_parts'],
            'encryption_key': entry['encryption_key'],
            'enc_scheme': entry['enc_scheme'],
            'original_hash': entry['original_hash'],
            'thumbnail_b64': entry['thumbnail_b64'],
            'original_width': entry['original_width'],
            'original_height': entry['original_height'],
            'devices': entry['devices']
        }
        json_str = json.dumps(sensitive_data, indent=2)
        if HAVE_AESGCM:
            aesgcm = AESGCM(MAPPING_ENCRYPTION_KEY)
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, json_str.encode('utf-8'), None)
            data_to_save = nonce + encrypted
        else:
            data_to_save = json_str.encode('utf-8')
        new_mapping[image_name] = base64.b64encode(data_to_save).decode('utf-8')
    with open(MAPPING_FILE, "w", encoding="utf-8") as f:
        json.dump(new_mapping, f, indent=2)

class MyService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ImageClientService"
    _svc_display_name_ = "Image Client Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_event = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):
        global stop_event
        stop_event = self.stop_event
        load_stored_parts()
        start_server()

# split helper (9x9 fixed)
def split_image_9x9(image_path):
    img = Image.open(image_path).convert("RGB")
    w, h = img.size
    cols = 9
    rows = 9
    seg_w = w // cols
    seg_h = h // rows
    segments = []
    part_id = 0
    for r in range(rows):
        for c in range(cols):
            left = c * seg_w
            top = r * seg_h
            right = left + seg_w if (c < cols-1) else w
            bottom = top + seg_h if (r < rows-1) else h
            seg = img.crop((left, top, right, bottom))
            buf = io.BytesIO()
            seg.save(buf, format="PNG")
            segments.append((part_id, buf.getvalue()))
            part_id += 1
    total = len(segments)
    return segments, total

# legacy: split parts equally by contiguous ranges (NOT used for round-robin)
def split_parts_equally(parts, device_names):
    total_parts = len(parts)
    num_devices = len(device_names)
    per_device_base = total_parts // num_devices
    remainder = total_parts % num_devices

    assigned = {}
    idx = 0
    for i, dev in enumerate(device_names):
        take = per_device_base + (1 if i < remainder else 0)
        assigned[dev] = parts[idx: idx + take]
        idx += take
    return assigned

# NEW: Round-Robin assignment (part_index % num_devices)
def split_parts_round_robin(parts, device_names):
    """
    parts: list of (part_id, bytes)
    device_names: list of device names in selection order
    returns: dict device_name -> list of (part_id, bytes)
    """
    assigned = {name: [] for name in device_names}
    n = len(device_names)
    if n == 0:
        return assigned
    for idx, part in enumerate(parts):
        dev = device_names[idx % n]
        assigned[dev].append(part)
    return assigned

# build payload
def build_payload(part_id, total_parts, device_name, sender_ip, payload_bytes, image_hash=None):
    header = {"part_id": part_id, "total_parts": total_parts, "device_name": device_name, "sender_ip": sender_ip}
    if image_hash:
        header["image_hash"] = image_hash
    header_raw = json.dumps(header).encode("utf-8")
    body = header_raw + CHUNK_HEADER_SEP + payload_bytes
    length = len(body)
    return length.to_bytes(8, "big") + body

# send to single device, return set of acked part_ids and failures
# note: 'segments' is a list of (part_id, bytes) assigned to this device
def send_to_device(host_ip, port, device_name, segments, sender_ip, total_parts, image_hash=None):
    acked = set()
    failed = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host_ip, port))
        # Build batch payload: concatenate all part payloads directly
        batch_payloads = []
        for part_id, data in segments:
            payload = build_payload(part_id, total_parts, device_name, sender_ip, data, image_hash)
            batch_payloads.append(payload)
        batch_data = b''.join(batch_payloads)
        batch_length = len(batch_data)
        s.sendall(batch_length.to_bytes(8, "big"))
        s.sendall(batch_data)
        # Now receive ACKs for each part in the batch
        for part_id, _ in segments:
            try:
                # wait ack length (8 bytes)
                len_bytes = s.recv(8)
                if not len_bytes or len(len_bytes) < 8:
                    failed.append(part_id)
                    continue
                ack_len = int.from_bytes(len_bytes, "big")
                ack_raw = b""
                while len(ack_raw) < ack_len:
                    chunk = s.recv(min(4096, ack_len - len(ack_raw)))
                    if not chunk:
                        break
                    ack_raw += chunk
                try:
                    ack_j = json.loads(ack_raw.decode("utf-8"))
                    if ack_j.get("ack") == part_id:
                        acked.add(part_id)
                    else:
                        failed.append(part_id)
                except:
                    failed.append(part_id)
            except socket.timeout:
                failed.append(part_id)
            except Exception:
                failed.append(part_id)
        s.close()
    except Exception as e:
        # connection failed => mark all as failed
        failed = [pid for pid, _ in segments]
    return acked, failed

# -----------------------------
# App UI
# -----------------------------
app = ctk.CTk()
app.title("Image Splitting and Secure Share Distribution over High-speed LAN")
app.state("zoomed")
app.resizable(False, False)

screen_w = app.winfo_screenwidth()
screen_h = app.winfo_screenheight()

bg_photo = None
if os.path.exists("background.PNG"):
    try:
        bg_img = Image.open("background.PNG").resize((screen_w, screen_h))
        bg_photo = CTkImage(light_image=bg_img, dark_image=bg_img, size=(screen_w, screen_h))
    except:
        pass

def show_frame(frame):
    frame.tkraise()

main_frame = ctk.CTkFrame(app)
encrypt_frame = ctk.CTkFrame(app)
reassemble_frame = ctk.CTkFrame(app)

for fr in (main_frame, encrypt_frame, reassemble_frame):
    fr.place(x=0, y=0, relwidth=1, relheight=1)
    if bg_photo:
        ctk.CTkLabel(fr, image=bg_photo, text="").place(x=0, y=0, relwidth=1, relheight=1)

devices = load_devices()
selected_image_path = None
last_distribution_report = {}  # device -> {"acked":set(), "failed":list(), "assigned_count":int}

# ---- Settings window as before (simpler) ----
def open_settings_window():
    win = ctk.CTkToplevel(app)
    win.title("Settings — Devices")
    win.geometry("640x420")
    win.grab_set()
    ctk.CTkLabel(win, text="Device Settings", font=("Arial", 18, "bold")).pack(pady=8)
    frame = ctk.CTkFrame(win)
    frame.pack(padx=10, pady=6, fill="x")
    name_entry = ctk.CTkEntry(frame, placeholder_text="Device Name", width=220)
    name_entry.grid(row=0, column=0, padx=6, pady=6)
    ip_entry = ctk.CTkEntry(frame, placeholder_text="IP (port will be 9004)", width=320)
    ip_entry.grid(row=0, column=1, padx=6, pady=6)

    def add_device_action():
        n = name_entry.get().strip()
        ip = ip_entry.get().strip()
        if not n or not ip:
            return
        # Parse host (ignore any port specified, always use 9004)
        if ":" in ip:
            parts = ip.split(":")
            host = parts[0]
        else:
            host = ip
        port = 9004
        # Check if device is reachable on port 9004
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            s.close()
        except Exception as e:
            messagebox.showerror("Device not reachable", f"Cannot connect to {host}:{port}. Error: {str(e)}")
            return
        devices[n] = f"{host}:9004"
        save_devices(devices)
        refresh()
        name_entry.delete(0, "end")
        ip_entry.delete(0, "end")

    ctk.CTkButton(frame, text="Add", width=100, command=add_device_action, fg_color="#4169E1").grid(row=0, column=2, padx=6)
    listbox = ctk.CTkTextbox(win, height=220)
    listbox.pack(fill="both", expand=True, padx=12, pady=8)

    def refresh():
        listbox.delete("0.0", "end")
        for i,(n,ip) in enumerate(devices.items(), start=1):
            listbox.insert("end", f"{i}. {n} — {ip}\n")
    def remove_action():
        txt = listbox.get("0.0", "end").strip().splitlines()
        if not txt:
            return
        # ask index
        idx_dlg = ctk.CTkInputDialog(text="Enter index to remove", title="Remove")
        res = idx_dlg.get_input()
        if not res or not res.isdigit():
            return
        idxn = int(res)
        if idxn < 1 or idxn > len(txt):
            return
        key = list(devices.keys())[idxn-1]
        devices.pop(key, None)
        save_devices(devices)
        refresh()
    refresh()
    ctk.CTkButton(win, text="Remove", fg_color="#ff4d4d", command=remove_action).pack(pady=6)

# ---- Encrypt frame UI ----
ctk.CTkButton(main_frame, text="⚙️", width=50, height=40, fg_color="#1E90FF", command=open_settings_window).place(relx=0.97, rely=0.03, anchor="ne")
ctk.CTkButton(main_frame, text="🔐 Encrypt & Split Image", width=420, height=110, fg_color="#4169E1", command=lambda: show_frame(encrypt_frame)).place(relx=0.5, rely=0.45, anchor="center")
ctk.CTkButton(main_frame, text="🧩 Reassemble Image", width=420, height=110, fg_color="#4169E1", command=lambda: show_frame(reassemble_frame)).place(relx=0.5, rely=0.7, anchor="center")


ctk.CTkButton(encrypt_frame, text="Select Image", command=lambda: choose_image_action(), width=360, height=70, fg_color="#4169E1").place(relx=0.28, rely=0.26, anchor="center")
selected_label = ctk.CTkLabel(encrypt_frame, text="No image selected", font=("Arial", 14))
selected_label.place(relx=0.28, rely=0.33, anchor="center")

ctk.CTkButton(encrypt_frame, text="Select Devices & Start Distribution", command=lambda: open_device_selection_and_start(), width=360, height=70, fg_color="#4169E1").place(relx=0.28, rely=0.5, anchor="center")

# result box + resend controls
result_box = ctk.CTkTextbox(encrypt_frame, width=450, height=450, state="disabled")
result_box.place(relx=0.72, rely=0.5, anchor="center")

# helper UI buttons for resend
def refresh_result_box():
    result_box.configure(state="normal")
    result_box.delete("0.0", "end")
    for dev, rpt in last_distribution_report.items():
        ack_ct = len(rpt.get("acked", []))
        failed_ct = len(rpt.get("failed", []))
        assigned_ct = rpt.get("assigned_count", 0)
        result_box.insert("end", f"{dev}: ACKed {ack_ct} / {assigned_ct} ; Missing {failed_ct}\n")
        if failed_ct:
            result_box.insert("end", " Missing parts: " + ", ".join(map(str, rpt['failed'])) + "\n")
        result_box.insert("end", "\n")
    result_box.configure(state="disabled")

def choose_image_action():
    global selected_image_path
    fp = filedialog.askopenfilename(title="Select image", filetypes=[("Images","*.png;*.jpg;*.jpeg;*.bmp")])
    if fp:
        selected_image_path = fp
        selected_label.configure(text=os.path.basename(fp))

def open_device_selection_and_start():
    global devices
    if not selected_image_path:
        return
    if not devices:
        messagebox.showwarning("No devices", "No devices saved in settings.")
        return
    if not HAVE_AESGCM:
        messagebox.showerror("Missing dependency", "cryptography AESGCM not available. Install 'cryptography' package.")
        return
    sel_win = ctk.CTkToplevel(app)
    sel_win.title("Select target devices")
    sel_win.geometry("480x520")
    sel_win.grab_set()
    ctk.CTkLabel(sel_win, text="Select devices to send parts to:", font=("Arial", 14, "bold")).pack(pady=10)
    scroll = ctk.CTkScrollableFrame(sel_win)
    scroll.pack(fill="both", expand=True, padx=12, pady=8)
    var_map = {}
    for name, ip in devices.items():
        v = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(scroll, text=f"{name} — {ip}", variable=v).pack(anchor="w", pady=6, padx=6)
        var_map[name] = v
    def confirm():
        sel = [n for n,v in var_map.items() if v.get()]
        if not sel:
            messagebox.showwarning("No selection", "Select at least one device.")
            return
        peers = []
        for n in sel:
            ip = devices[n]
            if ":" in ip:
                peers.append((n, ip.split(":")[0], int(ip.split(":")[1])))
            else:
                peers.append((n, ip, SENDER_PORT_DEFAULT))
        sel_win.destroy()
        threading.Thread(target=distribution_flow, args=(selected_image_path, peers), daemon=True).start()
    ctk.CTkButton(sel_win, text="Confirm & Start", command=confirm, fg_color="#4169E1").pack(pady=8)

# distribution flow (batch mode + collect missing)
def distribution_flow(image_path, peers):
    global last_distribution_report
    last_distribution_report = {}
    # split once
    try:
        segments, total = split_image_9x9(image_path)
    except Exception as e:
        app.after(0, lambda: result_box.configure(state="normal")); app.after(0, lambda: result_box.insert("end", f"Split error: {e}\n")); app.after(0, lambda: result_box.configure(state="disabled"))
        return

    # create thumbnail for missing parts fallback
    img = Image.open(image_path).convert("RGB")
    orig_w, orig_h = img.size
    thumb = img.resize((324, 324))
    buf = io.BytesIO()
    thumb.save(buf, format="PNG")
    thumb_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    # compute original file hash
    try:
        with open(image_path, "rb") as f:
            orig_bytes = f.read()
            orig_hash = hashlib.sha256(orig_bytes).hexdigest()
    except:
        orig_hash = None

    # generate AES-GCM key (256-bit)
    if not HAVE_AESGCM:
        app.after(0, lambda: result_box.configure(state="normal"))
        result_box.insert("end", "Error: AESGCM not available (cryptography missing).\n")
        result_box.configure(state="disabled")
        return
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    b64_key = base64.b64encode(aes_key).decode("utf-8")

    # encrypt each segment with AES-GCM (nonce per segment)
    encrypted_segments = []
    for pid, data in segments:
        nonce = secrets.token_bytes(12)  # 96-bit nonce
        ct = aesgcm.encrypt(nonce, data, None)  # ciphertext + tag included
        payload = nonce + ct  # store nonce prefix
        encrypted_segments.append((pid, payload))

    # prepare assignment: Round-robin distribution of parts to devices
    device_names = [p[0] for p in peers]
    assigned = split_parts_round_robin(encrypted_segments, device_names)  # dict: device_name -> list of (part_id, bytes)

    # create mapping entry for this image and save mapping.json
    mapping = load_mapping_file()
    image_key = orig_hash
    mapping_entry = {
        "total_parts": total,
        "encryption_key": b64_key,
        "enc_scheme": "AESGCM",
        "original_hash": orig_hash,
        "image_name": os.path.basename(image_path),
        "thumbnail_b64": thumb_b64,
        "original_width": orig_w,
        "original_height": orig_h,
        "devices": {}
    }
    # fill devices info with parts and ip/port
    for name, host, port in peers:
        parts_for_device = assigned.get(name, [])
        # store sorted part ids for readability
        mapping_entry["devices"][name] = {
            "ip": host,
            "port": port,
            "parts": [pid for pid, _ in parts_for_device]
        }
    mapping[image_key] = mapping_entry
    try:
        save_mapping_file(mapping)
    except Exception:
        pass

    sender_ip = socket.gethostbyname(socket.gethostname())
    app.after(0, lambda: result_box.configure(state="normal"))
    app.after(0, lambda: result_box.delete("0.0", "end"))
    app.after(0, lambda lp=len(peers): result_box.insert("end", f"Starting distribution to {lp} devices...\n\n"))
    app.after(0, lambda: result_box.configure(state="disabled"))

    # send only assigned parts to each peer
    for name, host, port in peers:
        parts_for_device = assigned.get(name, [])
        assigned_count = len(parts_for_device)
        # immediate update report for UI even before sending
        last_distribution_report[name] = {"acked": set(), "failed": [], "assigned_count": assigned_count}
        app.after(0, refresh_result_box)

        app.after(0, lambda n=name, h=host, p=port, a=assigned_count: result_box.configure(state="normal"))
        app.after(0, lambda n=name, h=host, p=port, a=assigned_count: result_box.insert("end", f"Sending to {n} ({h}:{p})... assigned {a} parts\n"))
        app.after(0, lambda: result_box.configure(state="disabled"))

        # send assigned parts to this device
        acked, failed = send_to_device(host, port, name, parts_for_device, sender_ip, total, image_hash=orig_hash)
        last_distribution_report[name]["acked"] = sorted(list(acked))
        last_distribution_report[name]["failed"] = sorted(list(failed))
        app.after(0, refresh_result_box)

    # final message
    app.after(0, lambda: result_box.configure(state="normal"))
    result_box.insert("end", "Distribution flow finished. Mapping saved to mapping.json\n")
    result_box.configure(state="disabled")

# Resend missing parts UI (kept for compatibility)
def open_resend_window():
    if not last_distribution_report:
        messagebox.showinfo("Info", "No distribution report available (send first).")
        return
    win = ctk.CTkToplevel(app)
    win.title("Resend Missing Parts")
    win.geometry("600x420")
    win.grab_set()
    ctk.CTkLabel(win, text="Select a failed device and a target device to resend missing parts", font=("Arial", 14)).pack(pady=8)
    # list failed devices
    failed_names = [n for n,r in last_distribution_report.items() if r.get("failed")]
    if not failed_names:
        ctk.CTkLabel(win, text="No failed devices in last run.", font=("Arial", 12)).pack(pady=10)
        return
    ctk.CTkLabel(win, text="Failed devices:").pack(anchor="w", padx=12)
    fail_box = ctk.CTkComboBox(win, values=failed_names, width=400)
    fail_box.pack(padx=12, pady=6)
    # target devices (all available)
    ctk.CTkLabel(win, text="Resend target device (choose different device):").pack(anchor="w", padx=12)
    targets = [n for n in devices.keys()]
    target_box = ctk.CTkComboBox(win, values=targets, width=400)
    target_box.pack(padx=12, pady=6)
    def do_resend_action():
        src = fail_box.get()
        dst = target_box.get()
        if not src or not dst or src == dst:
            messagebox.showwarning("Invalid", "Choose a failed source and a different target.")
            return
        missing_parts = last_distribution_report[src]["failed"]
        if not missing_parts:
            messagebox.showinfo("No missing", "Selected device has no missing parts.")
            return
        # prepare segments map to resend
        try:
            segments, total = split_image_9x9(selected_image_path)
        except Exception as e:
            messagebox.showerror("Error", f"Split error: {e}")
            return
        # we need to re-encrypt the segments using mapping key if mapping exists
        mapping = load_mapping_file()
        # compute hash of selected_image_path
        with open(selected_image_path, "rb") as f:
            orig_bytes = f.read()
            image_key = hashlib.sha256(orig_bytes).hexdigest()
        entry = mapping.get(image_key)
        if not entry:
            messagebox.showerror("Error", "No mapping found for this image; cannot determine encryption key.")
            return
        enc_scheme = entry.get("enc_scheme")
        b64_key = entry.get("encryption_key")
        if enc_scheme != "AESGCM" or not b64_key:
            messagebox.showerror("Error", "Unsupported or missing encryption scheme/key in mapping.")
            return
        key = base64.b64decode(b64_key)
        aesgcm = AESGCM(key)
        # map part_id -> encrypted bytes
        seg_map = {}
        for pid, data in segments:
            nonce = secrets.token_bytes(12)
            ct = aesgcm.encrypt(nonce, data, None)
            seg_map[pid] = nonce + ct
        dst_ip_raw = devices.get(dst)
        if ":" in dst_ip_raw:
            host = dst_ip_raw.split(":")[0]; port = int(dst_ip_raw.split(":")[1])
        else:
            host = dst_ip_raw; port = SENDER_PORT_DEFAULT
        # build list of parts to resend
        to_send = [(pid, seg_map[pid]) for pid in missing_parts]
        # send
        def resend_thread():
            acked, failed = send_to_device(host, port, dst, to_send, socket.gethostbyname(socket.gethostname()), total)
            # update report (we consider successful ack moves those parts)
            if acked:
                # remove those acked from original src failed list
                remaining = [p for p in missing_parts if p not in acked]
                last_distribution_report[src]["failed"] = remaining
                # add to dst acked set
                last_distribution_report.setdefault(dst, {"acked":[], "failed":[], "assigned_count": len(last_distribution_report.get(dst,{}).get("acked",[]))})
                last_distribution_report[dst]["acked"].extend(list(acked))
            app.after(0, refresh_result_box)
        threading.Thread(target=resend_thread, daemon=True).start()
        win.destroy()
    ctk.CTkButton(win, text="Resend Missing", command=do_resend_action, fg_color="#4169E1").pack(pady=12)

# small button to open resend UI
ctk.CTkButton(encrypt_frame, text="Resend Missing Parts", command=open_resend_window, width=360, height=70, fg_color="#4169E1").place(relx=0.28, rely=0.7, anchor="center")
ctk.CTkButton(encrypt_frame, text="Back", command=lambda: show_frame(main_frame), width=220, height=50, fg_color="#4169E1").place(relx=0.15, rely=0.92, anchor="center")

# -----------------------------
# Reassemble UI (redesigned)
# -----------------------------
ctk.CTkLabel(reassemble_frame, text="", font=("Arial", 24, "bold")).place(relx=0.5, rely=0.02, anchor="n")

# Left column: mapping controls + notes + device parts
left_panel = ctk.CTkFrame(reassemble_frame)
left_panel.place(relx=0.02, rely=0.08, relwidth=0.46, relheight=0.84)

ctk.CTkLabel(left_panel, text="Mapping & Retrieval", font=("Arial", 16, "bold")).pack(anchor="nw", padx=12, pady=(8,4))

# image select / entry
images_entry = ctk.CTkEntry(left_panel, placeholder_text="Type image name or select from list...", width=360)
images_entry.pack(anchor="nw", padx=12, pady=(2,6))

# combobox of mapping images
images_combo = ctk.CTkComboBox(left_panel, values=[], width=360, command=lambda value: on_load_mapping_button() if value else None)
images_combo.pack(anchor="nw", padx=12, pady=(0,6))

# load mapping button
def on_load_mapping_button():
    # if combo has selection use it; else read entry
    sel = images_combo.get()
    entry_name = images_entry.get().strip()
    name = entry_name if entry_name else sel
    if not name:
        notes_box.configure(state="normal")
        notes_box.delete("0.0", "end")
        notes_box.insert("end", "Please provide image name (type or choose).\n")
        notes_box.configure(state="disabled")
        return
    mapping, path = load_mapping()
    if not mapping:
        notes_box.configure(state="normal")
        notes_box.delete("0.0", "end")
        notes_box.insert("end", "Mapping file not found.\n")
        notes_box.configure(state="disabled")
        # clear device parts box
        devices_parts_box.configure(state="normal")
        devices_parts_box.delete("0.0", "end")
        devices_parts_box.configure(state="disabled")
        return
    # find the key by image_name
    image_key = None
    for key, entry in mapping.items():
        if entry.get("image_name") == name:
            image_key = key
            break
    if image_key is None:
        notes_box.configure(state="normal")
        notes_box.delete("0.0", "end")
        notes_box.insert("end", f"NOT FOUND in mapping: {name}\n")
        notes_box.configure(state="disabled")
        # clear device parts box
        devices_parts_box.configure(state="normal")
        devices_parts_box.delete("0.0", "end")
        devices_parts_box.configure(state="disabled")
        return
    # populate devices parts box
    entry = mapping[image_key]
    devs = entry.get("devices", {})
    devices_parts_box.configure(state="normal")
    devices_parts_box.delete("0.0", "end")
    devices_parts_box.insert("end", f"Mapping loaded: {name}\n")
    devices_parts_box.insert("end", f"Total parts: {entry.get('total_parts')}\n\n")
    for d, info in devs.items():
        parts = info.get("parts", [])
        devices_parts_box.insert("end", f"{d} ({info.get('ip')}:{info.get('port', SENDER_PORT_DEFAULT)}) -> parts: {parts}\n")
    devices_parts_box.configure(state="disabled")
    # notes
    notes_box.configure(state="normal")
    notes_box.delete("0.0", "end")
    notes_box.insert("end", f"Found mapping for '{name}'. Ready to start retrieval.\n")
    notes_box.configure(state="disabled")
    # save selected key (hash) in a variable for later retrieval
    app.selected_mapping_image = image_key
    app.current_mapping_entry = entry

load_map_btn = ctk.CTkButton(left_panel, text="Load mapping / Select image", command=on_load_mapping_button, width=220, fg_color="#4169E1")
load_map_btn.pack(anchor="nw", padx=12, pady=(4,8))

# Notes box
ctk.CTkLabel(left_panel, text="Notes / Status", font=("Arial", 12, "bold")).pack(anchor="nw", padx=12)
notes_box = ctk.CTkTextbox(left_panel, height=100, width=400, state="disabled")
notes_box.pack(anchor="nw", padx=12, pady=(4,8))

# Devices & parts box (shows plan and failures)
ctk.CTkLabel(left_panel, text="Devices & Parts", font=("Arial", 12, "bold")).pack(anchor="nw", padx=12)
devices_parts_box = ctk.CTkTextbox(left_panel, height=200, width=400, state="disabled")
devices_parts_box.pack(anchor="nw", padx=12, pady=(4,8))

# Buttons: start retrieval and retry missing
def start_retrieval_action():
    # check selected mapping image
    name = getattr(app, "selected_mapping_image", None)
    if not name:
        notes_box.configure(state="normal")
        notes_box.delete("0.0", "end")
        notes_box.insert("end", "No image mapping selected. Load mapping first.\n")
        notes_box.configure(state="disabled")
        return
    # run retrieval in background
    threading.Thread(target=ui_retrieve_worker, args=(name,), daemon=True).start()

def retry_missing_action():
    name = getattr(app, "selected_mapping_image", None)
    if not name:
        notes_box.configure(state="normal")
        notes_box.delete("0.0", "end")
        notes_box.insert("end", "No image mapping selected. Load mapping first.\n")
        notes_box.configure(state="disabled")
        return
    # retry only missing parts (already stored in app.missing_by_device)
    threading.Thread(target=ui_retry_missing_worker, args=(name,), daemon=True).start()

btn_frame = ctk.CTkFrame(left_panel)
btn_frame.pack(anchor="nw", padx=12, pady=(6,12))
start_btn = ctk.CTkButton(btn_frame, text="Start Retrieval", command=start_retrieval_action, width=160, fg_color="#4169E1")
start_btn.grid(row=0, column=0, padx=6, pady=6)
retry_btn = ctk.CTkButton(btn_frame, text="Retry Missing", command=retry_missing_action, width=160, fg_color="#4169E1")
retry_btn.grid(row=0, column=1, padx=6, pady=6)

# Right column: preview + save
right_panel = ctk.CTkFrame(reassemble_frame)
right_panel.place(relx=0.50, rely=0.08, relwidth=0.48, relheight=0.84)

ctk.CTkLabel(right_panel, text="Preview (after reassembly)", font=("Arial", 16, "bold")).pack(anchor="n", pady=(6,8))

preview_container = ctk.CTkFrame(right_panel, width=400, height=400)
preview_container.pack(pady=(4,8))
preview_container.pack_propagate(False)

# placeholder label for image preview
preview_label = ctk.CTkLabel(preview_container, text="No image reconstructed yet", width=400, height=400, anchor="center")
preview_label.pack(expand=True, fill="both")

# Save button
def on_save_reconstructed():
    img = getattr(app, "reconstructed_image", None)
    if img is None:
        messagebox.showinfo("No image", "No reconstructed image to save.")
        return
    fp = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image","*.png")])
    if not fp:
        return
    try:
        img.save(fp)
        messagebox.showinfo("Saved", f"Image saved to {fp}")
    except Exception as e:
        messagebox.showerror("Save error", str(e))

save_btn = ctk.CTkButton(right_panel, text="Save reconstructed image", command=on_save_reconstructed, width=220, fg_color="#4169E1")
save_btn.pack(pady=(6,12))

# Back button
ctk.CTkButton(reassemble_frame, text="Back", command=lambda: show_frame(main_frame), width=220, height=50, fg_color="#4169E1").place(relx=0.5, rely=0.94, anchor="center")

# load mapping on startup for convenience
def load_mapping_and_populate():
    mapping, path = load_mapping()
    images_combo.configure(values=[])
    if not mapping:
        mapping_label_text = "Mapping file: not found"
        images_combo.configure(values=[])
        return
    # populate combo with image_names
    image_names = [entry.get("image_name", key) for key, entry in mapping.items()]
    images_combo.configure(values=image_names)
    if image_names:
        images_combo.set(image_names[0])

# Call initial populate
app.after(200, load_mapping_and_populate)

# -----------------------------
# Retrieval worker functions (UI-driven)
# -----------------------------
OP_SEP = b'|OP_SEP|'

def retrieve_segment_from_peer(peer_ip: str, peer_port: int, segment_id: int, image_hash: str, timeout=6.0):
    """
    Connect to peer and request segment_id for specific image_hash. Returns bytes or (None, error_str)
    Protocol: send 8-byte length then JSON op + OP_SEP (no body needed)
    Peer expected to respond with 8-byte length then payload bytes.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((peer_ip, peer_port))
            op = json.dumps({"operation": "RETRIEVE", "segment_id": segment_id, "image_hash": image_hash}).encode("utf-8")
            full = op + OP_SEP
            s.sendall(len(full).to_bytes(8, "big"))
            s.sendall(full)
            len_bytes = s.recv(8)
            if not len_bytes or len(len_bytes) < 8:
                return None, "No length from peer"
            resp_len = int.from_bytes(len_bytes, "big")
            data = b""
            while len(data) < resp_len:
                chunk = s.recv(min(4096, resp_len - len(data)))
                if not chunk:
                    break
                data += chunk
            if len(data) != resp_len:
                return None, "Incomplete read"
            return data, None
    except Exception as e:
        return None, str(e)

def try_decrypt(data_bytes: bytes, b64_key: str, scheme: str):
    if not b64_key:
        return None, "no key"
    if scheme == "AESGCM":
        if not HAVE_AESGCM:
            return None, "AESGCM not available"
        try:
            key = base64.b64decode(b64_key)
            aesgcm = AESGCM(key)
            if len(data_bytes) < 12:
                return None, "data too short for nonce"
            nonce = data_bytes[:12]
            ct = data_bytes[12:]
            dec = aesgcm.decrypt(nonce, ct, None)
            return dec, None
        except Exception as e:
            return None, str(e)
    else:
        return None, f"unsupported_scheme:{scheme}"

def ui_retrieve_worker(image_key):
    """
    1) Read mapping for image_key
    2) Show plan in devices_parts_box and notes_box
    3) Start parallel retrieval of all parts
    4) Update notes with progress, mark failed parts per-device
    5) Reconstruct available parts into image and show in preview_label
    6) Store missing parts in app.missing_by_device for retry
    """
    # ensure mapping loaded
    mapping, path = load_mapping()
    if not mapping or image_key not in mapping:
        app.after(0, lambda: notes_box.configure(state="normal"))
        app.after(0, lambda: notes_box.delete("0.0", "end"))
        app.after(0, lambda: notes_box.insert("end", f"NOT FOUND in mapping: {image_key}\n"))
        app.after(0, lambda: notes_box.configure(state="disabled"))
        return

    entry = mapping[image_key]
    devices_info = entry.get("devices", {})
    enc_key = entry.get("encryption_key")
    enc_scheme = entry.get("enc_scheme")
    total_parts = entry.get("total_parts", 81)

    # show planned parts
    def show_plan():
        devices_parts_box.configure(state="normal")
        devices_parts_box.delete("0.0", "end")
        devices_parts_box.insert("end", f"Planned retrieval for {image_key}\nTotal parts: {total_parts}\n\n")
        for dev, info in devices_info.items():
            devices_parts_box.insert("end", f"{dev} -> {info.get('parts', [])}\n")
        devices_parts_box.configure(state="disabled")
        notes_box.configure(state="normal")
        notes_box.delete("0.0", "end")
        notes_box.insert("end", f"Starting retrieval of {total_parts} parts from {len(devices_info)} devices...\n")
        notes_box.configure(state="disabled")
    app.after(0, show_plan)

    # Build segment_map: part_id -> {ip, port, device}
    segment_map = {}
    for dev_name, info in devices_info.items():
        ip = info.get("ip")
        port = int(info.get("port", SENDER_PORT_DEFAULT))
        for p in info.get("parts", []):
            try:
                pid = int(p)
            except:
                continue
            segment_map[pid] = {"ip": ip, "port": port, "device": dev_name}

    fetched = {}
    errors = {}
    missing_by_device = {}  # device -> list of missing parts (failed)
    lock = threading.Lock()

    def worker(pid, info):
        ip = info.get("ip")
        port = int(info.get("port", SENDER_PORT_DEFAULT))
        dev = info.get("device")
        app.after(0, lambda: notes_box.configure(state="normal"))
        app.after(0, lambda: notes_box.insert("end", f"[Fetch] part {pid} from {dev or ip}:{port} ... "))
        app.after(0, lambda: notes_box.configure(state="disabled"))
        data, err = retrieve_segment_from_peer(ip, port, pid, image_key, timeout=6.0)
        if data:
            # decrypt if needed
            if enc_key:
                dec, derr = try_decrypt(data, enc_key, enc_scheme)
                if dec is None:
                    with lock:
                        errors[pid] = f"decrypt_error:{derr}"
                        fetched[pid] = None
                        missing_by_device.setdefault(dev, []).append(pid)
                    app.after(0, lambda: notes_box.configure(state="normal"))
                    app.after(0, lambda: notes_box.insert("end", f"RETRIEVED (decrypt failed: {derr})\n"))
                    app.after(0, lambda: notes_box.configure(state="disabled"))
                else:
                    with lock:
                        fetched[pid] = dec
                    app.after(0, lambda: notes_box.configure(state="normal"))
                    app.after(0, lambda: notes_box.insert("end", "RETRIEVED + DECRYPTED\n"))
                    app.after(0, lambda: notes_box.configure(state="disabled"))
            else:
                with lock:
                    fetched[pid] = data
                app.after(0, lambda: notes_box.configure(state="normal"))
                app.after(0, lambda: notes_box.insert("end", "RETRIEVED\n"))
                app.after(0, lambda: notes_box.configure(state="disabled"))
        else:
            with lock:
                errors[pid] = err or "unknown"
                fetched[pid] = None
                missing_by_device.setdefault(dev, []).append(pid)
            app.after(0, lambda: notes_box.configure(state="normal"))
            app.after(0, lambda: notes_box.insert("end", f"FAILED ({err})\n"))
            app.after(0, lambda: notes_box.configure(state="disabled"))

    # start threads for all parts in segment_map
    threads = []
    for pid, info in segment_map.items():
        t = threading.Thread(target=worker, args=(pid, info), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    # after fetching, show summary in devices_parts_box
    def show_summary():
        devices_parts_box.configure(state="normal")
        devices_parts_box.delete("0.0", "end")
        devices_parts_box.insert("end", f"Retrieval summary for {image_key}\n\n")
        for dev, info in devices_info.items():
            parts = [int(p) for p in info.get("parts", [])]
            failed = missing_by_device.get(dev, [])
            ok = sorted([p for p in parts if p not in failed])
            devices_parts_box.insert("end", f"{dev} -> OK: {ok}\n")
            if failed:
                devices_parts_box.insert("end", f"  FAILED: {failed}\n")
        devices_parts_box.configure(state="disabled")

        notes_box.configure(state="normal")
        notes_box.insert("end", "\nRetrieval finished. See summary above.\n")
        notes_box.configure(state="disabled")

    app.after(0, show_summary)

    # attempt reconstruction with the successfully fetched parts
    images_list = []
    for pid, data in fetched.items():
        if not data:
            continue
        try:
            img = Image.open(io.BytesIO(data)).convert("RGB")
            images_list.append((pid, img))
        except Exception as e:
            errors[pid] = f"open_error:{e}"

    # Load thumbnail for missing parts fallback
    thumb_img = None
    thumb_b64 = entry.get("thumbnail_b64")
    if thumb_b64:
        try:
            thumb_bytes = base64.b64decode(thumb_b64)
            thumb_img = Image.open(io.BytesIO(thumb_bytes)).convert("RGB")
        except Exception as e:
            notes_box.configure(state="normal")
            notes_box.insert("end", f"[Reassemble] Failed to load thumbnail: {e}\n")
            notes_box.configure(state="disabled")

    if not images_list:
        # Use thumbnail as full fallback, resized to original dimensions
        if thumb_img:
            orig_w = entry.get("original_width", thumb_img.size[0])
            orig_h = entry.get("original_height", thumb_img.size[1])
            resized_thumb = thumb_img.resize((orig_w, orig_h))
            app.reconstructed_image = resized_thumb
            def update_preview_thumb():
                try:
                    thumb_copy = resized_thumb.copy()
                    max_w = int(preview_container.winfo_width() or 400)
                    max_h = int(preview_container.winfo_height() or 400)
                    thumb_copy.thumbnail((max_w, max_h))
                    preview_img = CTkImage(light_image=thumb_copy, dark_image=thumb_copy, size=(thumb_copy.width, thumb_copy.height))
                    preview_label.configure(image=preview_img, text="")
                    preview_label.image = preview_img
                except Exception:
                    preview_label.configure(text="Thumbnail (could not preview)", image=None)
                notes_box.configure(state="normal")
                notes_box.insert("end", "[Reassemble] Used thumbnail as fallback since no parts retrieved, resized to original dimensions.\n")
                notes_box.configure(state="disabled")
            app.after(0, update_preview_thumb)
        else:
            notes_box.configure(state="normal")
            notes_box.insert("end", "[Reassemble] No thumbnail available as fallback.\n")
            notes_box.configure(state="disabled")
        # store missing_by_device for retry
        app.missing_by_device = missing_by_device
        return

    # determine tile size (use min)
    widths = [im.size[0] for _, im in images_list]
    heights = [im.size[1] for _, im in images_list]
    tile_w = min(widths)
    tile_h = min(heights)
    final_w = tile_w * 9
    final_h = tile_h * 9
    reconstructed = Image.new("RGB", (final_w, final_h))

    placed = set()
    for pid, img in images_list:
        if pid >= 9*9:
            continue
        r = pid // 9
        c = pid % 9
        x = c * tile_w
        y = r * tile_h
        if img.size != (tile_w, tile_h):
            img = img.resize((tile_w, tile_h))
        reconstructed.paste(img, (x, y))
        placed.add(pid)

    # Fill missing parts with resized thumbnail parts
    if thumb_img and thumb_img.size == (324, 324):
        thumb_part_size = 36  # each part in thumbnail is 36x36
        for pid in range(81):
            if pid in placed:
                continue
            r = pid // 9
            c = pid % 9
            # crop from thumbnail
            thumb_x = c * thumb_part_size
            thumb_y = r * thumb_part_size
            thumb_part = thumb_img.crop((thumb_x, thumb_y, thumb_x + thumb_part_size, thumb_y + thumb_part_size))
            # resize to match tile size
            resized_part = thumb_part.resize((tile_w, tile_h))
            # place in reconstructed
            x = c * tile_w
            y = r * tile_h
            reconstructed.paste(resized_part, (x, y))
            placed.add(pid)

    # save reconstructed image in memory and update preview
    app.reconstructed_image = reconstructed
    def update_preview():
        # convert to CTkImage and set to preview_label
        try:
            # create a thumbnail to fit preview container nicely
            thumb = reconstructed.copy()
            max_w = int(preview_container.winfo_width() or 400)
            max_h = int(preview_container.winfo_height() or 400)
            thumb.thumbnail((max_w, max_h))
            preview_img = CTkImage(light_image=thumb, dark_image=thumb, size=(thumb.width, thumb.height))
            preview_label.configure(image=preview_img, text="")
            preview_label.image = preview_img
        except Exception:
            preview_label.configure(text="Reconstructed (could not preview)", image=None)
        notes_box.configure(state="normal")
        notes_box.insert("end", f"[Reassemble] Reconstructed image with {len(placed)} parts placed.\n")
        if errors:
            notes_box.insert("end", "[Reassemble] Some errors:\n")
            for pid, err in errors.items():
                notes_box.insert("end", f" - Part {pid}: {err}\n")
        notes_box.configure(state="disabled")
    app.after(0, update_preview)

    # store missing_by_device for retry attempts
    app.missing_by_device = missing_by_device

    # Discard decrypted mapping after use to preserve confidentiality
    app.selected_mapping_image = None
    app.current_mapping_entry = None

def ui_retry_missing_worker(image_key):
    """
    Attempt to re-retrieve only missing parts stored in app.missing_by_device.
    Update UI boxes and then try to reconstruct again with newly fetched parts.
    """
    missing_by_device = getattr(app, "missing_by_device", None)
    if not missing_by_device:
        app.after(0, lambda: notes_box.configure(state="normal"))
        app.after(0, lambda: notes_box.insert("end", "No missing parts recorded (nothing to retry).\n"))
        app.after(0, lambda: notes_box.configure(state="disabled"))
        return

    mapping, path = load_mapping()
    if not mapping or image_key not in mapping:
        app.after(0, lambda: notes_box.configure(state="normal"))
        app.after(0, lambda: notes_box.insert("end", "Mapping not found; cannot retry.\n"))
        app.after(0, lambda: notes_box.configure(state="disabled"))
        return

    entry = mapping[image_key]
    devices_info = entry.get("devices", {})
    enc_key = entry.get("encryption_key")
    enc_scheme = entry.get("enc_scheme")

    notes_box.configure(state="normal")
    notes_box.insert("end", f"Retrying missing parts for {image_key}...\n")
    notes_box.configure(state="disabled")

    # we will collect newly fetched bytes in fetched_new
    fetched_new = {}
    errors = {}
    lock = threading.Lock()

    def worker(dev, parts):
        ip = devices_info.get(dev, {}).get("ip")
        port = int(devices_info.get(dev, {}).get("port", SENDER_PORT_DEFAULT))
        for pid in parts:
            app.after(0, lambda p=pid, d=dev: notes_box.configure(state="normal"))
            app.after(0, lambda p=pid, d=dev: notes_box.insert("end", f"[Retry] part {p} from {dev}... "))
            app.after(0, lambda: notes_box.configure(state="disabled"))
            data, err = retrieve_segment_from_peer(ip, port, pid, timeout=6.0)
            if data:
                if enc_key:
                    dec, derr = try_decrypt(data, enc_key, enc_scheme)
                    if dec is None:
                        with lock:
                            errors[pid] = f"decrypt_error:{derr}"
                        app.after(0, lambda: notes_box.configure(state="normal"))
                        app.after(0, lambda: notes_box.insert("end", f"RETRIEVED (decrypt failed: {derr})\n"))
                        app.after(0, lambda: notes_box.configure(state="disabled"))
                    else:
                        with lock:
                            fetched_new[pid] = dec
                        app.after(0, lambda: notes_box.configure(state="normal"))
                        app.after(0, lambda: notes_box.insert("end", "RETRIEVED + DECRYPTED\n"))
                        app.after(0, lambda: notes_box.configure(state="disabled"))
                else:
                    with lock:
                        fetched_new[pid] = data
                    app.after(0, lambda: notes_box.configure(state="normal"))
                    app.after(0, lambda: notes_box.insert("end", "RETRIEVED\n"))
                    app.after(0, lambda: notes_box.configure(state="disabled"))
            else:
                with lock:
                    errors[pid] = err or "unknown"
                app.after(0, lambda: notes_box.configure(state="normal"))
                app.after(0, lambda: notes_box.insert("end", f"FAILED ({err})\n"))
                app.after(0, lambda: notes_box.configure(state="disabled"))

    # spawn workers per device
    threads = []
    for dev, parts in list(missing_by_device.items()):
        if not parts:
            continue
        t = threading.Thread(target=worker, args=(dev, parts), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    # merge newly fetched data into existing reconstructed image attempt
    # fetch previously successful parts from app.reconstructed_image if exist
    existing_fetched = {}
    # Ideally we would keep the previously fetched bytes; for simplicity, re-run full ui_retrieve_worker merging newly fetched:
    # Build a temporary fetched dict by combining previously fetched (if any) with fetched_new.
    # To keep simple: save fetched_new into a temporary file-based reconstruction by calling a modified reconstruct routine.
    # For now, we update app.missing_by_device removing retried successes:
    for pid in list(missing_by_device.keys()):
        # if pid got fetched_new -> remove from missing list
        # but missing_by_device is device -> list, so iterate accordingly
        pass

    # Re-run ui_retrieve_worker but prefer to use new fetched parts: easiest approach is to call ui_retrieve_worker again;
    # this will re-attempt to fetch all parts and update app.missing_by_device accordingly.
    # (This keeps logic simpler and robust.)
    app.after(0, lambda: notes_box.configure(state="normal"))
    app.after(0, lambda: notes_box.insert("end", "\nRetry phase finished; re-running full retrieval summary to rebuild image.\n"))
    app.after(0, lambda: notes_box.configure(state="disabled"))

    # Call ui_retrieve_worker again to refresh fetching/reconstruction (it will attempt all parts but many are already retrieved)
    ui_retrieve_worker(image_key)

# helper to load mapping
def load_mapping():
    path = None
    for name in [MAPPING_FILE, "segment_map.json", "segment-map.json"]:
        if os.path.exists(name):
            path = name
            break
    if not path:
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            new_mapping = json.load(f)
        mapping = {}
        for image_name, encrypted_b64 in new_mapping.items():
            encrypted_data = base64.b64decode(encrypted_b64)
            if HAVE_AESGCM and len(encrypted_data) > 12:
                aesgcm = AESGCM(MAPPING_ENCRYPTION_KEY)
                nonce = encrypted_data[:12]
                ct = encrypted_data[12:]
                decrypted = aesgcm.decrypt(nonce, ct, None)
                sensitive_data = json.loads(decrypted.decode('utf-8'))
            else:
                sensitive_data = json.loads(encrypted_data.decode('utf-8'))
            sensitive_data['image_name'] = image_name
            mapping[sensitive_data['original_hash']] = sensitive_data
        return mapping, path
    except Exception as e:
        print(f"Error loading mapping: {e}")
        return None, None

# start server in background
threading.Thread(target=start_server, daemon=True).start()

# show frame
show_frame(main_frame)
app.mainloop()
