import os
import json
import threading
import socket
import base64
import sys
import time
import win32serviceutil
import win32service
import win32event
import servicemanager

# Configuration
CLIENT_PORT = 9004  # Port for the client to listen on
CHUNK_HEADER_SEP = b'||'
PART_SEP = b'|PART_SEP|'
OP_SEP = b'|OP_SEP|'
CLIENT_STORED_PARTS_FILE = "client_stored_parts.json"

local_ip = socket.gethostbyname(socket.gethostname())
stored_parts = {}  # part_id -> {"payload": bytes, "sender_ip": str, "device_name": str, "image_hash": str}

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

def start_client_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((local_ip, CLIENT_PORT))
    server_socket.listen(5)
    print(f"Client server started on {local_ip}:{CLIENT_PORT}")
    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=handle_client_request, args=(client_socket, addr), daemon=True).start()

def handle_client_request(client_socket, addr):
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
                    part_data = stored_parts[segment_id]["payload"]
                    client_socket.sendall(len(part_data).to_bytes(8, "big"))
                    client_socket.sendall(part_data)
                else:
                    error = json.dumps({"error": "part not found"}).encode("utf-8")
                    client_socket.sendall(len(error).to_bytes(8, "big"))
                    client_socket.sendall(error)
            else:
                error = json.dumps({"error": "unknown operation"}).encode("utf-8")
                client_socket.sendall(len(error).to_bytes(8, "big"))
                client_socket.sendall(error)
        else:
            # assume SEND batch
            batch_data = data
            offset = 0
            while offset < len(batch_data):
                if offset + 8 > len(batch_data):
                    break
                part_length = int.from_bytes(batch_data[offset:offset+8], "big")
                offset += 8
                if offset + part_length > len(batch_data):
                    break
                part_data = batch_data[offset:offset + part_length]
                offset += part_length
                # process part
                header_end = part_data.find(CHUNK_HEADER_SEP)
                if header_end == -1:
                    continue
                header_raw = part_data[:header_end]
                payload = part_data[header_end + len(CHUNK_HEADER_SEP):]
                try:
                header = json.loads(header_raw.decode("utf-8"))
                part_id = header.get("part_id")
                device_name = header.get("device_name")
                sender_ip = header.get("sender_ip")
                image_hash = header.get("image_hash")
                stored_parts[part_id] = {"payload": payload, "sender_ip": sender_ip, "device_name": device_name}
                if image_hash:
                    stored_parts[part_id]["image_hash"] = image_hash
                save_stored_parts()  # save after storing
                ack = json.dumps({"ack": part_id}).encode("utf-8")
                client_socket.sendall(len(ack).to_bytes(8, "big"))
                client_socket.sendall(ack)
                print(f"Received and stored part {part_id} from {device_name}" + (f" (image_hash: {image_hash})" if image_hash else ""))
                except Exception as e:
                    print(f"Error processing part: {e}")
                    continue
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

class ClientService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ClientService"
    _svc_display_name_ = "Client File Parts Service"
    _svc_description_ = "Service to receive and store file parts from clients"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.server_thread = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        if self.server_thread and self.server_thread.is_alive():
            # Note: In a real service, you might need a better way to stop the server thread
            pass  # For simplicity, we'll let it terminate naturally

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.EVENTLOG_INFORMATION_TYPE,
                              (self._svc_name_, "Service is starting"))
        load_stored_parts()
        self.server_thread = threading.Thread(target=start_client_server)
        self.server_thread.start()
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.EVENTLOG_INFORMATION_TYPE,
                              (self._svc_name_, "Service started successfully"))
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Run as console application
        load_stored_parts()
        threading.Thread(target=start_client_server, daemon=True).start()
        print("Client is running and listening for parts...")
        # Keep the main thread alive
        while True:
            import time
            time.sleep(1)
    else:
        # Run as service
        win32serviceutil.HandleCommandLine(ClientService)
