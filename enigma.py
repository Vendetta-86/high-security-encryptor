import string
import random
import json
import os
from datetime import datetime, timedelta

ALPHABET = string.ascii_uppercase

# ----- 三转子历史配置（Enigma I） -----
ROTOR_WIRINGS = {
    "I":    "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II":   "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III":  "BDFHJLCPRTXVZNYEIWGAKMUSQO"
}
ROTOR_NOTCHES = {"I":"Q","II":"E","III":"V"}
REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

# ----- Enigma 类 -----
class Rotor:
    def __init__(self, wiring, notch, position=0):
        self.wiring = wiring
        self.notch = notch
        self.position = position
        self.forward_map = {ALPHABET[i]: wiring[i] for i in range(26)}
        self.backward_map = {wiring[i]: ALPHABET[i] for i in range(26)}
    def step(self):
        self.position = (self.position + 1) % 26
    def at_notch(self):
        return ALPHABET[self.position] == self.notch
    def encode_forward(self, ch):
        idx = (ALPHABET.index(ch) + self.position) % 26
        mapped = self.forward_map[ALPHABET[idx]]
        out = ALPHABET[(ALPHABET.index(mapped) - self.position) % 26]
        return out
    def encode_backward(self, ch):
        idx = (ALPHABET.index(ch) + self.position) % 26
        mapped = self.backward_map[ALPHABET[idx]]
        out = ALPHABET[(ALPHABET.index(mapped) - self.position) % 26]
        return out

class Reflector:
    def __init__(self, wiring):
        self.mapping = {ALPHABET[i]: wiring[i] for i in range(26)}
    def reflect(self, ch):
        return self.mapping[ch]

class EnigmaMachine:
    def __init__(self, rotor_names, rotor_positions=(0,0,0), plugboard_pairs=[]):
        self.rotors = [
            Rotor(ROTOR_WIRINGS[rotor_names[0]], ROTOR_NOTCHES[rotor_names[0]], rotor_positions[0]),
            Rotor(ROTOR_WIRINGS[rotor_names[1]], ROTOR_NOTCHES[rotor_names[1]], rotor_positions[1]),
            Rotor(ROTOR_WIRINGS[rotor_names[2]], ROTOR_NOTCHES[rotor_names[2]], rotor_positions[2])
        ]
        self.reflector = Reflector(REFLECTOR_B)
        self.plugboard = {ch: ch for ch in ALPHABET}
        for a,b in plugboard_pairs:
            self.plugboard[a.upper()] = b.upper()
            self.plugboard[b.upper()] = a.upper()

    def step_rotors(self):
        # 中转子双步机制
        if self.rotors[1].at_notch():
            self.rotors[0].step()
            self.rotors[1].step()
        elif self.rotors[2].at_notch():
            self.rotors[1].step()
        self.rotors[2].step()  # 最右边转子每次步进

    def process_char(self, ch):
        if ch not in ALPHABET:
            return ch
        self.step_rotors()
        ch = self.plugboard[ch]
        for rotor in reversed(self.rotors):
            ch = rotor.encode_forward(ch)
        ch = self.reflector.reflect(ch)
        for rotor in self.rotors:
            ch = rotor.encode_backward(ch)
        ch = self.plugboard[ch]
        return ch

    def encrypt(self, text):
        return "".join(self.process_char(ch.upper()) for ch in text)

# ----- 文件操作 -----
KEY_FILE = "daily_keys.json"
CIPHER_FILE = "daily_ciphers.json"

def load_json_file(filename):
    if os.path.exists(filename):
        with open(filename,"r") as f:
            return json.load(f)
    return {}

def save_json_file(filename, data):
    with open(filename,"w") as f:
        json.dump(data,f)

# ----- 每日密钥生成 -----
def generate_daily_keys(date_str, num_messages):
    keys = [tuple(random.randint(0,25) for _ in range(3)) for _ in range(num_messages)]
    key_records[date_str] = keys
    save_json_file(KEY_FILE, key_records)
    print(f"[{date_str}] 生成每日密钥表，共 {num_messages} 条消息。")
    for i,k in enumerate(keys,1):
        print(f"消息 {i}: {k}")

# ----- 批量加密 -----
def encrypt_batch(date_str, messages, rotor_names, plugboard_pairs=[]):
    if date_str not in key_records:
        print("该日期无密钥表，请先生成")
        return
    if len(messages) != len(key_records[date_str]):
        print("消息数量与密钥表条目数不一致")
        return
    ciphers = []
    for i,msg in enumerate(messages):
        key = tuple(key_records[date_str][i])
        enigma = EnigmaMachine(rotor_names, key, plugboard_pairs)
        cipher = enigma.encrypt(msg)
        print(f"消息 {i+1} 加密结果: {cipher}，密钥: {key}")
        ciphers.append(cipher)
    cipher_records[date_str] = ciphers
    save_json_file(CIPHER_FILE, cipher_records)

# ----- 批量解密 -----
def decrypt_batch(date_str, rotor_names, plugboard_pairs=[]):
    if date_str not in key_records or date_str not in cipher_records:
        print("该日期无完整密钥表或密文记录")
        return
    for i,cipher in enumerate(cipher_records[date_str]):
        key = tuple(key_records[date_str][i])
        enigma = EnigmaMachine(rotor_names, key, plugboard_pairs)
        msg = enigma.encrypt(cipher)
        print(f"消息 {i+1} 解密结果: {msg}")

# ----- 自动生成消息 -----
def auto_generate_messages(num_messages):
    messages = []
    for _ in range(num_messages):
        length = random.randint(5,15)
        msg = ''.join(random.choice(ALPHABET+' ') for _ in range(length))
        messages.append(msg)
    return messages

# ----- 手动解密 -----
def manual_decrypt():
    cipher = input("请输入密文：").upper()
    while True:
        rotor_names = input("请输入三转子型号(如 I II III): ").split()
        if len(rotor_names) == 3 and all(r in ROTOR_WIRINGS for r in rotor_names):
            break
        print("输入无效，请输入 3 个合法转子型号，例如 I II III")
    positions = tuple(int(x) for x in input("请输入转子初始位置(0-25，用空格分隔): ").split())
    plug_input = input("请输入插线板交换对 (如 AB CD EF，可空): ")
    plug_pairs = []
    if plug_input.strip():
        items = plug_input.strip().split()
        for item in items:
            if len(item)==2:
                plug_pairs.append((item[0].upper(), item[1].upper()))
    enigma = EnigmaMachine(rotor_names, positions, plug_pairs)
    plaintext = enigma.encrypt(cipher)
    print("手动解密结果：", plaintext)

# ----- 主程序 -----
if __name__=="__main__":
    print("=== 每日 Enigma 系统 + 手动解密 ===")
    key_records = load_json_file(KEY_FILE)
    cipher_records = load_json_file(CIPHER_FILE)

    # 转子型号输入验证
    while True:
        rotor_names_input = input("请输入三转子型号(如 I II III): ").split()
        if len(rotor_names_input) == 3 and all(r in ROTOR_WIRINGS for r in rotor_names_input):
            break
        print("输入无效，请输入 3 个合法转子型号，例如 I II III")

    # 插线板输入验证
    plug_input = input("请输入插线板交换对 (如 AB CD EF，可空)：")
    plug_pairs = []
    if plug_input.strip():
        items = plug_input.strip().split()
        for item in items:
            if len(item)==2 and item[0].isalpha() and item[1].isalpha():
                plug_pairs.append((item[0].upper(), item[1].upper()))

    start_date_str = input("请输入起始日期（如2025-12-30）：")
    num_messages = int(input("请输入每日消息数量："))
    start_date = datetime.strptime(start_date_str,"%Y-%m-%d")
    days = int(input("请输入连续运行天数："))

    for d in range(days):
        current_date = start_date + timedelta(days=d)
        date_str = current_date.strftime("%Y-%m-%d")
        print(f"\n=== 第 {d+1} 天 日期: {date_str} ===")
        generate_daily_keys(date_str, num_messages)

        # 消息输入方式
        messages = []
        choice = input("选择消息生成方式：1=自动生成 2=手动输入：").strip()
        if choice=='2':
            print(f"请输入 {num_messages} 条消息：")
            for i in range(num_messages):
                msg = input(f"消息 {i+1}：")
                messages.append(msg.upper())
        else:
            messages = auto_generate_messages(num_messages)
            print("自动生成消息：")
            for i,m in enumerate(messages,1):
                print(f"消息 {i}: {m}")

        encrypt_batch(date_str, messages, rotor_names_input, plug_pairs)
        print("自动解密验证：")
        decrypt_batch(date_str, rotor_names_input, plug_pairs)

    while True:
        manual = input("\n是否手动解密某条密文？(y/n)：").strip().lower()
        if manual=='y':
            manual_decrypt()
        else:
            print("程序结束")
            break
