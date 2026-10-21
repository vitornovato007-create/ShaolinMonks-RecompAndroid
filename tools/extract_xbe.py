import struct
import sys

def parse_xbe_header(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)
        if magic != b'XBE1':
            print("[-] Erro: O arquivo nao e um executavel XBE valido de Xbox Clássico!")
            return None
        
        f.seek(0x0104)
        base_address = struct.unpack("<I", f.read(4))[0]
        header_size = struct.unpack("<I", f.read(4))[0]
        code_size = struct.unpack("<I", f.read(4))[0]

        f.seek(0x0118)
        entry_point = struct.unpack("<I", f.read(4))[0]

        print("=== Informacoes do XBE (MK: Shaolin Monks) ===")
        print(f"[+] Magic: {magic.decode('ascii')}")
        print(f"[+] Base Address: {hex(base_address)}")
        print(f"[+] Header Size: {hex(header_size)}")
        print(f"[+] Image Size: {hex(code_size)}")
        print(f"[+] Entry Point: {hex(entry_point)}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_xbe_header(sys.argv[1])
    else:
        print("Uso: python extract_xbe.py default.xbe")
