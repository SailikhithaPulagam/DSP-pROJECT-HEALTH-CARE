import mysql.connector
import csv
import hashlib
from cryptography.fernet import Fernet

# Generate an encryption key (Store this securely for decryption)
encryption_key = Fernet.generate_key()
enc_str = str(encryption_key, 'utf-8')
ff = open("key.key", 'w')
ff.write(enc_str)
ff.close()
cipher = Fernet(encryption_key)

# Database connection details
db_config = {
    "host": "localhost",          # Change to your MySQL host
    "user": "test",               # Change to your MySQL username
    "password": "test",           # Change to your MySQL password
    "database": "healthcare_db"   # Change to your database name
}

# Establish connection to MySQL
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

# Create the healthcare information table with encrypted 'gender' and 'age'
cursor.execute("""
CREATE TABLE IF NOT EXISTS healthcare_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    gender_encrypted TEXT,       -- Encrypted gender
    age_encrypted TEXT,          -- Encrypted age
    weight FLOAT,
    height FLOAT,
    health_history TEXT,
    data_hash VARCHAR(64)
)
""")

# Create the admin authentication table
cursor.execute("""
CREATE TABLE IF NOT EXISTS admin_auth (
    username VARCHAR(50) PRIMARY KEY,
    password_hash VARCHAR(64),  -- SHA-256 hash
    user_group CHAR(1)          -- 'H' for full access, 'R' for restricted
)
""")

# Function to generate hash for a row (excluding sensitive fields)
def generate_row_hash(row):
    row_data = "|".join(map(str, row))  # Concatenate all non-sensitive fields with '|'
    return hashlib.sha256(row_data.encode()).hexdigest()

# Function to hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to encrypt a value
def encrypt_value(value):
    return cipher.encrypt(str(value).encode()).decode()

# Read data from the CSV file
csv_filename = "healthcare_data.csv"
with open(csv_filename, mode="r") as file:
    csv_reader = csv.DictReader(file)
    data = []
    for row in csv_reader:
        # Encrypt sensitive fields
        gender_encrypted = encrypt_value(row["Gender"])
        age_encrypted = encrypt_value(row["Age"])

        # Prepare row data for insertion (exclude sensitive fields from hash)
        row_data = (
            row["First Name"],
            row["Last Name"],
            gender_encrypted,
            age_encrypted,
            float(row["Weight"]),
            float(row["Height"]),
            row["Health History"]
        )

        # Generate hash for the row (exclude encrypted fields)
        row_hash = generate_row_hash((row["First Name"], row["Last Name"], row["Weight"], row["Height"], row["Health History"]))
        
        # Append data with hash
        data.append(row_data + (row_hash,))

# Insert data into the healthcare_info table with hash
insert_query_healthcare = """
INSERT INTO healthcare_info (
    first_name, last_name, gender_encrypted, age_encrypted, weight, height, health_history, data_hash
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
"""
cursor.executemany(insert_query_healthcare, data)

# Add admin users to the admin_auth table
admins = [
    ("admin1", hash_password("admin123"), "H"),  # Full access admin
    ("admin2", hash_password("securePass1"), "R"),  # Restricted access admin
    ("admin3", hash_password("pass456"), "R")   # Restricted access admin
]

insert_query_admin = """
INSERT INTO admin_auth (username, password_hash, user_group)
VALUES (%s, %s, %s)
"""
cursor.executemany(insert_query_admin, admins)

# Commit changes and close the connection
conn.commit()
cursor.close()
conn.close()

# Print a note about the encryption key
print(f"Encryption key (store this securely for decryption): {encryption_key.decode()}")
print(f"Data from '{csv_filename}' has been successfully inserted into the database with encrypted fields and hashes.")
print("Admin authentication table created, and users added successfully.")
