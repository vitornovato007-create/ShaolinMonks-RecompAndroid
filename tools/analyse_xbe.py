import struct
import os
import sys
import json

# Constantes do formato XBE (Xbox Executable)
XBE_MAGIC = b'XBE1'
EP_XOR_KEY = 0xA8FC57AB    # Chave XOR oficial para Entry Point de varejo (Retail)
EP_DEBUG_KEY = 0x5B6D40B6  # Chave XOR para imagens de Debug/Devkit

def parse_xbe(xbe_path):
    if not os.path.exists(xbe_path):
        print(f"[-] Erro: Arquivo nao encontrado em '{xbe_path}'")
        return None

    with open(xbe_path, 'rb') as f:
        # 1. Leitura do Cabeçalho Principal (Header)
        header_data = f.read(0x180)
        if len(header_data) < 0x180:
            print("[-] Erro: Arquivo XBE muito curto ou corrompido.")
            return None

        magic = header_data[0:4]
        if magic != XBE_MAGIC:
            print(f"[-] Erro: Assinatura invalida '{magic}'. Esperado 'XBE1'.")
            return None

        # Desempacota campos-chave do XBE Header
        # Offsets conforme especificação do Xbox SDK:
        # 0x004: Digital Signature (256 bytes)
        # 0x104: Base Address (4 bytes)
        # 0x108: Size of Headers (4 bytes)
        # 0x10C: Size of Image (4 bytes)
        # 0x110: Size of Image Header (4 bytes)
        # 0x114: Time Date Stamp (4 bytes)
        # 0x118: Certificate Address (4 bytes)
        # 0x11C: Number of Sections (4 bytes)
        # 0x120: Section Headers Address (4 bytes)
        # 0x124: Init Flags (4 bytes)
        # 0x128: Entry Point (4 bytes XORed)
        
        base_address, size_of_headers, size_of_image, _, timestamp, cert_addr, \
        num_sections, section_headers_addr, init_flags, raw_entry_point = \
            struct.unpack('<IIIIIIIIII', header_data[0x104:0x12C])

        # Decodifica o Entry Point (tenta Retail primeiro, depois Debug)
        entry_point = raw_entry_point ^ EP_XOR_KEY
        ep_type = "Retail"
        if entry_point < base_address or entry_point >= (base_address + size_of_image):
            entry_point = raw_entry_point ^ EP_DEBUG_KEY
            ep_type = "Debug/Devkit"

        xbe_info = {
            "magic": magic.decode('ascii'),
            "base_address": f"0x{base_address:08X}",
            "entry_point_raw": f"0x{raw_entry_point:08X}",
            "entry_point_decoded": f"0x{entry_point:08X}",
            "entry_point_type": ep_type,
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "num_sections": num_sections,
            "sections": []
        }

        print("=" * 60)
        print("         XBOX EXECUTABLE (XBE) HEADER ANALYSIS")
        print("=" * 60)
        print(f"[+] Assinatura Magic    : {magic.decode('ascii')} (OK)")
        print(f"[+] Endereco Base (Image): 0x{base_address:08X}")
        print(f"[+] Entry Point Decod.  : 0x{entry_point:08X} ({ep_type})")
        print(f"[+] Tamanho da Imagem   : {size_of_image} bytes ({size_of_image / (1024*1024):.2f} MB)")
        print(f"[+] Numero de Secoes    : {num_sections}")
        print("-" * 60)

        # 2. Leitura dos Section Headers
        # Mapeia offset virtual do Section Header para offset físico dentro do arquivo
        sec_header_raw_offset = section_headers_addr - base_address
        f.seek(sec_header_raw_offset)

        print(f"\n{'Nome da Secao':<15} {'Endr. Virtual':<15} {'Tam. Virtual':<15} {'Offset Fisico':<15} {'Tam. Fisico'}")
        print("-" * 75)

        for i in range(num_sections):
            sec_data = f.read(56) # Cada cabeçalho de seção tem 56 bytes (0x38)
            if len(sec_data) < 56:
                break

            sec_flags, virtual_addr, virtual_size, raw_addr, raw_size, name_addr, _, _, _, _ = \
                struct.unpack('<IIIIIIIIII', sec_data[:40])

            # Lê o nome da seção a partir do ponteiro name_addr
            name_raw_offset = name_addr - base_address
            current_pos = f.tell()
            f.seek(name_raw_offset)
            sec_name_bytes = f.read(32)
            sec_name = sec_name_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')
            f.seek(current_pos)

            sec_info = {
                "name": sec_name,
                "virtual_address": f"0x{virtual_addr:08X}",
                "virtual_size": virtual_size,
                "raw_address": f"0x{raw_addr:08X}",
                "raw_size": raw_size,
                "flags": f"0x{sec_flags:08X}"
            }
            xbe_info["sections"].append(sec_info)

            print(f"{sec_name:<15} 0x{virtual_addr:08X}       {virtual_size:<15} 0x{raw_addr:08X}       {raw_size}")

        print("=" * 75)
        return xbe_info

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: python analyze_xbe.py /caminho/para/default.xbe [output_info.json]")
    else:
        target_xbe = sys.argv[1]
        data = parse_xbe(target_xbe)
        
        # Se for passado um segundo argumento, exporta os metadados para JSON
        if data and len(sys.argv) >= 3:
            json_out = sys.argv[2]
            with open(json_out, 'w') as jf:
                json.dump(data, jf, indent=4)
            print(f"\n[✓] Metadados exportados com sucesso para '{json_out}'")
