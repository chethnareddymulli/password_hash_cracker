import hashlib
import sys
import os
import time

def hash_cracker(wordlists, hash_to_decrypt, hash_algorithm):
    total_passwords = 0
    for wordlist in wordlists:
        if os.path.isfile(wordlist):
            total_passwords += sum(1 for _ in open(wordlist))
        else:
            print(f"'{wordlist}' is not a valid file.")

    if total_passwords == 0:
        print("No valid wordlists provided.")
        return None

    passwords_tried = 0

    for wordlist_path in wordlists:
        if not os.path.isfile(wordlist_path):
            continue

        try:
            with open(wordlist_path, 'r') as file:
                for line in file:
                    password = line.strip()
                    if hash_algorithm == 'md5':
                        hash_object = hashlib.md5(password.encode())
                    elif hash_algorithm == 'sha1':
                        hash_object = hashlib.sha1(password.encode())
                    elif hash_algorithm == 'sha256':
                        hash_object = hashlib.sha256(password.encode())
                    elif hash_algorithm == 'sha512':
                        hash_object = hashlib.sha512(password.encode())
                    else:
                        print(f"Hashing algorithm '{hash_algorithm}' not supported.")
                        return None

                    hashed_word = hash_object.hexdigest()
                    passwords_tried += 1
                    progress = (passwords_tried / total_passwords) * 100
                    print(f"\rProgress: {progress:.2f}%", end='', flush=True)

                    if hashed_word == hash_to_decrypt:
                        return password
        except FileNotFoundError:
            print(f"Wordlist file '{wordlist_path}' not found.")
            continue
        except Exception as e:
            print(f"Error reading wordlist file '{wordlist_path}': {str(e)}")
            continue

    return None

def print_header():
    title = """
                (      (         )                                 
 )\ )   )\ )   ( /(                   (      *   )  
(()/(  (()/(   )\())     (    (       )\   ` )  /(  
 /(_))  /(_)) ((_)\      )\   )\    (((_)   ( )(_)) 
(_))   (_))     ((_)    ((_) ((_)   )\___  (_(_())  
| _ \  | _ \   / _ \   _ | | | __| ((/ __| |_   _|  
|  _/  |   /  | (_) | | || | | _|   | (__    | |    
|_|    |_|_\   \___/   \__/  |___|   \___|   |_|     
    """
    print("\033[1;31m" + title + "\033[0m")

def guess_hash_algorithm(hash_str):
    hash_length = len(hash_str)

    if hash_length == 32:
        return 'md5'
    elif hash_length == 40:
        return 'sha1'
    elif hash_length == 64:
        return 'sha256'
    elif hash_length == 128:
        return 'sha512'
    else:
        return 'Unknown or unsupported hash length'

# Example usage:
hash_to_decrypt = input("Enter the hash to analyze: ")
algorithm_guess = guess_hash_algorithm(hash_to_decrypt)
print(f"Guessed hash algorithm: {algorithm_guess}")


def print_menu():
    print("\n🔥🔓 Menu: 🔓🔥")
    print("1. 🔐 Crack Password")
    print("2. 🔴 Exit")

def main():
    attention_message = "⚠️🔒🛑 Ethical use only, please. Not for unauthorized access. 🛑🔒⚠️"
    print("\033[1;33m" + attention_message + "\033[0m")

    print_header()
    while True:
        print_menu()
        choice = input("\n🔫 Enter your choice: ")

        if choice == '1':
            print("\n🔐  Password Cracking Tool  🔐\n")
            hash_algorithm = input("🔥 Which type of Hash algorithm you want to use? (e.g., md5, sha1, sha256, sha512): ").lower()
            if hash_algorithm not in ['md5', 'sha1', 'sha256', 'sha512']:
                print("🚫 Invalid hash algorithm.")
                continue
            num_wordlists = input("🔫 Enter the number of wordlists you want to use: ")
            if not num_wordlists.isdigit() or int(num_wordlists) <= 0:
                print("❌ Invalid number of wordlists.")
                continue
            num_wordlists = int(num_wordlists)
            wordlists = []
            for i in range(num_wordlists):
                wordlist_path = input(f"💣 Enter path for wordlist {i+1}: ")
                if not os.path.exists(wordlist_path):
                    print(f"🔍 Wordlist file '{wordlist_path}' not found.")
                    continue
                wordlists.append(wordlist_path)
            hash_to_decrypt = input("💥 Enter Hash value to bruteforce: ")

            start_time = time.time()
            cracked_password = hash_cracker(wordlists, hash_to_decrypt, hash_algorithm)
            end_time = time.time()

            if cracked_password:
                print(f"\n\n\033[1;32m🔓 Found Password: {cracked_password}\033[0m\n")
            else:
                print("\n\033[1;31m🛑 Password not found in the wordlist.\033[0m\n")

            print(f"⏱️ Time taken: {end_time - start_time:.2f} seconds")

        elif choice == '2':
            print("\n🚪 Exiting...")
            sys.exit()
        else:
            print("\n⛔ Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()

