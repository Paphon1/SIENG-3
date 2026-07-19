#!/usr/bin/env python3
import sys
import argparse
from src.utils import load_yaml_config
from src.engine import run_embed, run_extract

def main():
    parser = argparse.ArgumentParser(description="Sieng-F5 Professional Steganography Core Engine")
    parser.add_argument('--mode', choices=['embed', 'extract'], required=True, help="Execution mode")
    parser.add_argument('--config', required=True, help="Path to the sender/receiver YAML config file")
    args = parser.parse_args()

    try:
        config = load_yaml_config(args.config)
        
        if args.mode == 'embed':
            print("[*] Initiating Embedding Process via Configuration...")
            s_set = config['stego_settings']
            i_o = config['input_output']
            secret = config['secret']
            
            message = secret['message_text']
            if secret.get('message_source') == 'file' and secret.get('message_file_path'):
                with open(secret['message_file_path'], 'r', encoding='utf-8') as f:
                    message = f.read()

            run_embed(
                cover_path=i_o['cover_image_path'],
                stego_path=i_o['stego_image_path'],
                message=message,
                password=secret['password'],
                k=s_set.get('hamming_k', 3),
                iters=s_set.get('pbkdf2_iterations', 200_000)
            )
            
        elif args.mode == 'extract':
            print("[*] Initiating Extraction Process via Configuration...")
            s_set = config['stego_settings']
            i_o = config['input_output']
            secret = config['secret']
            
            # ดึงค่าพารามิเตอร์ K และ Iteration จากฝั่งรับ (ต้องตรงกับฝั่งส่ง)
            iters = config.get('stego_settings', {}).get('pbkdf2_iterations', 200_000)
            
            decrypted_msg = run_extract(
                stego_path=i_o['stego_image_path'],
                password=secret['password'],
                k=s_set.get('hamming_k', 3),
                iters=iters
            )
            
            print("\n[+] --- Decrypted Secret Message ---")
            print(decrypted_msg)
            print("------------------------------------\n")
            
            # ถ้ามีการตั้งค่าให้เซฟไฟล์ขาออก
            if i_o.get('output_text_path'):
                with open(i_o['output_text_path'], 'w', encoding='utf-8') as f:
                    f.write(decrypted_msg)
                print(f"[*] Message successfully exported to {i_o['output_text_path']}")

    except Exception as e:
        print(f"[-] Critical Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()