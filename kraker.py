import os
import pyzipper
import subprocess
import sys

# Path to unrar.exe (if not added to PATH)
UNRAR_PATH = "C:\\Program Files\\WinRAR\\unrar.exe"  # If WinRAR is installed
# UNRAR_PATH = "C:\\unrar\\unrar.exe"  # If UnRAR is manually installed

# Path to the password file
PASSWORD_FILE_PATH = "C:\\Users\\admin\\Downloads\\passwords.txt"

def check_password_file():
    """Check if the password file exists. If not, exit the program."""
    if not os.path.exists(PASSWORD_FILE_PATH):
        print(f"[-] Password file not found. Please ensure the file exists at: {PASSWORD_FILE_PATH}")
        sys.exit(1)  # Terminate the program

def check_zip_password_protection(file_path):
    """Check if a ZIP file is password protected."""
    try:
        with pyzipper.AESZipFile(file_path, 'r') as zf:
            for file_info in zf.infolist():
                if file_info.flag_bits & 0x1:  # Check the encryption flag
                    return True  # Password protected
            return False  # Not password protected
    except RuntimeError:
        return False

def check_rar_password_protection(file_path):
    """Check if a RAR file is password protected using unrar."""
    command = [UNRAR_PATH, 't', '-p-', file_path]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        return False  # Not password protected
    else:
        return True  # Password protected

def extract_zip(file_path, password):
    """Test if the password is correct for an AES-encrypted ZIP file."""
    try:
        with pyzipper.AESZipFile(file_path, 'r') as zf:
            zf.setpassword(password.encode('utf-8'))  # Set the password
            for file_info in zf.infolist():
                if file_info.flag_bits & 0x1:  # Check if the file is encrypted
                    try:
                        zf.read(file_info.filename)  # Attempt to read the file
                        return True  # Password is correct
                    except (RuntimeError, pyzipper.BadZipFile):
                        return False  # Wrong password
            return False  # No encrypted files found
    except (RuntimeError, pyzipper.BadZipFile, pyzipper.LargeZipFile):
        return False

def extract_rar(file_path, password):
    """Test if the password is correct for a RAR file."""
    try:
        # Use unrar.exe to test the RAR file
        command = [UNRAR_PATH, 't', '-p' + password, file_path]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode == 0:  # Password is correct
            return True
        else:  # Password is incorrect
            return False
    except Exception:
        return False

def create_extracted_folder(file_path):
    """Create a folder named 'extracted\<archive_name>' in the same directory as the file."""
    base_folder = os.path.join(os.path.dirname(file_path), "extracted")
    archive_name = os.path.splitext(os.path.basename(file_path))[0]  # Get archive name without extension
    extracted_folder = os.path.join(base_folder, archive_name)  # Example: \extracted\example
    if not os.path.exists(extracted_folder):
        os.makedirs(extracted_folder)
    return extracted_folder

def extract_zip_files(file_path, password=None):
    """Extract ZIP files to 'extracted\<archive_name>' folder."""
    try:
        extracted_folder = create_extracted_folder(file_path)
        with pyzipper.AESZipFile(file_path, 'r') as zf:
            if password:
                zf.setpassword(password.encode('utf-8'))  # Set the password if provided
            zf.extractall(extracted_folder)  # Extract to 'extracted\<archive_name>' folder
            print(f"[+] Files extracted to: {extracted_folder}")
    except Exception as e:
        print(f"[-] Failed to extract files: {e}")

def extract_rar_files(file_path, password=None):
    """Extract RAR files to 'extracted\<archive_name>' folder."""
    try:
        extracted_folder = create_extracted_folder(file_path)
        if password:
            # Use unrar.exe to extract the RAR file with password
            command = [UNRAR_PATH, 'x', '-p' + password, file_path, extracted_folder]
        else:
            # Use unrar.exe to extract the RAR file without password
            command = [UNRAR_PATH, 'x', file_path, extracted_folder]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode == 0:  # Extraction successful
            print(f"[+] Files extracted to: {extracted_folder}")
        else:
            print(f"[-] Failed to extract files: {result.stderr.decode('utf-8')}")
    except Exception as e:
        print(f"[-] Failed to extract files: {e}")

def ask_for_extraction(files_to_extract):
    """Ask the user if they want to extract all files."""
    while True:
        choice = input("Do you want to extract all files? (y/n): ").strip().lower()
        if choice in ['y', 'e']:  # y, e
            for file_path, password in files_to_extract.items():
                if file_path.endswith('.zip'):
                    extract_zip_files(file_path, password)
                elif file_path.endswith('.rar'):
                    extract_rar_files(file_path, password)
            break
        elif choice in ['n', 'h']:  # n, h
            print("[INFO] No files were extracted.")
            break
        else:
            print("[ERROR] Invalid choice. Please enter 'y' or 'n'.")

def crack_file(file_path, password_list):
    """Try each password in the list for the given file."""
    for password in password_list:
        password = password.strip()  # Remove leading/trailing whitespace
        if file_path.endswith('.zip') and extract_zip(file_path, password):
            return password
        elif file_path.endswith('.rar') and extract_rar(file_path, password):
            return password
    return None

def process_files(folder_path, password_list):
    """Process all files in a folder: Check if they are password protected and crack them."""
    files_to_extract = {}  # Store files and their passwords

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)

            try:
                # Check if the file exists and is readable
                if not os.path.exists(file_path):
                    raise FileNotFoundError(f"File not found: {file_path}")
                if not os.access(file_path, os.R_OK):
                    raise PermissionError(f"File is not readable: {file_path}")
            
                if file.endswith('.zip'):
                    if check_zip_password_protection(file_path):
                        result = crack_file(file_path, password_list)
                        if result:
                            print(f"[+] Success: Password found for {file_path}: {result}")
                            files_to_extract[file_path] = result  # Save file and password
                        else:
                            print(f"[-] Failed: No valid password found for {file_path}.")
                    else:
                        print(f"[INFO] {file_path} is not password protected.")
                        files_to_extract[file_path] = None  # Save file without password
                elif file.endswith('.rar'):
                    if check_rar_password_protection(file_path):
                        result = crack_file(file_path, password_list)
                        if result:
                            print(f"[+] Success: Password found for {file_path}: {result}")
                            files_to_extract[file_path] = result  # Save file and password
                        else:
                            print(f"[-] Failed: No valid password found for {file_path}.")
                    else:
                        print(f"[INFO] {file_path} is not password protected.")
                        files_to_extract[file_path] = None  # Save file without password
            except FileNotFoundError as e:
                print(f"[-] Error: {e}")
                continue # File not found, move to the next one
            except PermissionError as e:
                print(f"[-] Error: {e}")
                continue  # File not readable, move to the next one  
            except Exception as e:
                print(f"[-] Unexpected error: {e}")
                continue 
             
    if files_to_extract:
        ask_for_extraction(files_to_extract)
    else:
        print("[INFO] No files to extract.")

def load_password_list():
    """Load the password list from the specified file."""
    try:
        with open(PASSWORD_FILE_PATH, 'r', encoding='utf-8') as pf:
            return pf.readlines()
    except Exception as e:
        print(f"[-] Error reading password file: {e}")
        return None

def main():
    # Check if the password file exists before proceeding
    check_password_file()

    print("Select an option:")
    print("1. Check and crack a single archive file")
    print("2. Check and crack all archive files in a folder")
    choice = input("Enter your choice (1 or 2): ")

    # Load the password list
    password_list = load_password_list()
    if not password_list:
        return  # Exit if password list cannot be loaded

    if choice == '1':
        file_path = input("Enter the full path of the archive file: ").strip()
        if os.path.isfile(file_path):
            if file_path.endswith('.zip'):
                if check_zip_password_protection(file_path):
                    result = crack_file(file_path, password_list)
                    if result:
                        print(f"[+] Success: Password found for {file_path}: {result}")
                        ask_for_extraction({file_path: result})  # Ask for extraction
                    else:
                        print(f"[-] Failed: No valid password found for {file_path}.")
                else:
                    print(f"[INFO] {file_path} is not password protected.")
                    ask_for_extraction({file_path: None})  # Ask for extraction without password
            elif file_path.endswith('.rar'):
                if check_rar_password_protection(file_path):
                    result = crack_file(file_path, password_list)
                    if result:
                        print(f"[+] Success: Password found for {file_path}: {result}")
                        ask_for_extraction({file_path: result})  # Ask for extraction
                    else:
                        print(f"[-] Failed: No valid password found for {file_path}.")
                else:
                    print(f"[INFO] {file_path} is not password protected.")
                    ask_for_extraction({file_path: None})  # Ask for extraction without password
            else:
                print("[ERROR] Unsupported file format.")
        else:
            print("[ERROR] File not found. Please check the path.")
    elif choice == '2':
        folder_path = input("Enter the folder path containing archive files: ").strip()
        if os.path.isdir(folder_path):
            process_files(folder_path, password_list)
        else:
            print("[ERROR] Folder not found. Please check the path.")
    else:
        print("[ERROR] Invalid choice. Please select 1 or 2.")

if __name__ == "__main__":
    main()
