# Image Splitting and Secure Share Distribution over High-speed LAN

## Project Overview
This project implements a secure and distributed image storage and reconstruction system over a Local Area Network (LAN). The system splits an image into encrypted segments and distributes them across multiple devices to enhance security, fault tolerance, and data confidentiality.

---

## System Requirements

### Operating System
- Windows 10 or later  
- Linux (tested on Ubuntu-based systems)  

### Python Version
- Python 3.9 or higher  

> Make sure Python is added to PATH.

---

## Required Python Libraries

The following Python libraries must be installed before running the project:

- `cryptography`
- `Pillow`
- `customtkinter`
- `socket` (built-in)
- `threading` (built-in)
- `hashlib` (built-in)
- `json` (built-in)
- `base64` (built-in)
- `secrets` (built-in)

---

## Installing Dependencies

Run the following command in the project directory:

pip install cryptography pillow customtkinter

Built-in libraries do not require installation.


System Requirements and Security Design
---------------------------------------

## Network Requirements:
- All devices must be connected to the same Local Area Network (LAN)
- TCP socket communication must be allowed through the firewall
- Required ports must be open to enable reliable client-server communication

## Security Requirements:
- AES-GCM encryption is used to encrypt each image segment independently
- Mapping files are stored in encrypted form and decrypted only at runtime
- SHA-256 hashing is used to uniquely identify images and verify data integrity
  during the reassembly process

## System Notes:
- Each client device runs a background service to receive and store encrypted segments
- No single device stores the complete image, reducing the risk of data exposure
- Proper key management is essential for successful image reconstruction
- Mapping files must be correctly decrypted and available during the reassembly phase
"""

## How to Run

Start client services on all participating devices

Run the main application on the sender device

Select an image and distribute encrypted segments

Request reassembly to reconstruct the original image

