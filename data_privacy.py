import mysql.connector
import hashlib
import sys
from cryptography.fernet import Fernet

# Generate an encryption key (Store this securely for decryption)
read_key = open("key.key", 'r')
data = read_key.read()
data = data.replace("\n", "")

encryption_key = bytes(data, 'utf-8')
cipher = Fernet(encryption_key)

# Database connection details
db_config = {
    "host": "localhost",          # Change to your MySQL host
    "user": "test",               # Change to your MySQL username
    "password": "test",           # Change to your MySQL password
    "database": "healthcare_db"   # Change to your database name
}

# Function to hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to decrypt a value
def decrypt_value(encrypted_value):
    return cipher.decrypt(encrypted_value.encode()).decode()

def generate_row_hash(row):
    row_data = "|".join(map(str, row))  # Concatenate all non-sensitive fields with '|'
    return hashlib.sha256(row_data.encode()).hexdigest()

def check_modification(cursor):
    query = "select *from healthcare_info"
    cursor.execute(query)
    results = cursor.fetchall()
    for row in results:
        row_hash = generate_row_hash((row[1], row[2], row[5], row[6], row[7]))
        if row_hash == row[8]:
            pass
        else:
            print("some modification detect in line ",row[0])
            exit()

# Function to execute SQL queries with access restrictions
def execute_query(user_group):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    
    while True:
        print("\n--- SQL Query Input ---")
        query = input("Enter an SQL query (or type 'exit' to logout): ").strip()
        
        if query.lower() == "exit":
            print("Exiting query prompt.")
            break

        if user_group == "R":
            # Restrict R users to SELECT queries only
            if not query.strip().lower().startswith("select"):
                print("Error: You do not have permission to run non-SELECT queries (INSERT, UPDATE, DELETE).")
                continue
            
            # Remove first_name and last_name from output
            if "first_name" in query.lower() or "last_name" in query.lower():
                print("Error: You do not have permission to access 'first_name' or 'last_name'.")
                continue
            
            # Modify query to exclude first_name and last_name
            query = query.replace("*", "gender_encrypted, age_encrypted, weight, height, health_history ")
        

        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
            check_modification(cursor)
            if user_group == "R":
                # Display decrypted data for R users
                for row in results:
                    for i in row:
                        
                        try:
                            print(" ", decrypt_value(i), end="")
                        except:
                            print(" ", i, end="")
                    print()
            else:
                # Display full data for H users
                for row in results:
                    if len(row) == 9:
                        row_data = row[:-1]
                    else:
                        row_data = row
                    for i in row_data:
                        try:
                            print(" ", decrypt_value(i), end="")
                        except:
                            print(" ", i, end="")
                    print()
        except mysql.connector.Error as err:
            print(f"Error: {err}")
    
    conn.close()

# Login functionality
def login():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    print("\n--- Login ---")
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    # Retrieve user from the database
    cursor.execute("SELECT username, password_hash, user_group FROM admin_auth WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user or hash_password(password) != user[1]:
        print("Invalid username or password!")
        conn.close()
        return None

    print(f"Login successful! Welcome, {user[0]} (Group: {user[2]})")
    conn.close()
    return user

# Signup functionality
def signup():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    print("\n--- Signup ---")
    username = input("Enter a username: ").strip()
    password = input("Enter a password: ").strip()
    group = input("Enter user group (H for full access, R for restricted): ").strip().upper()

    if group not in ["H", "R"]:
        print("Invalid group! Please choose 'H' or 'R'.")
        conn.close()
        return

    # Check if username already exists
    cursor.execute("SELECT * FROM admin_auth WHERE username = %s", (username,))
    if cursor.fetchone():
        print("Username already exists! Please try another username.")
        conn.close()
        return

    # Insert new user into the database
    password_hash = hash_password(password)
    cursor.execute("INSERT INTO admin_auth (username, password_hash, user_group) VALUES (%s, %s, %s)", 
                   (username, password_hash, group))
    conn.commit()
    conn.close()
    print("Signup successful! You can now log in.")

# Main menu
def main_menu():
    while True:
        print("\n--- Main Menu ---")
        print("1. Login")
        print("2. Signup")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            user = login()
            if user:
                _, _, user_group = user
                execute_query(user_group)  # Open query prompt after successful login
        elif choice == "2":
            signup()
        elif choice == "3":
            print("Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice! Please select 1, 2, or 3.")

# Entry point of the program
if __name__ == "__main__":
    main_menu()
