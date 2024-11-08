<h1 align="center"> 🐻 Project Winnie 🍟 </h1>

### SSH Honeypot with URL Download Functionality

## 🛠️ Prerequisites

- **Install Python**: Make sure [Python](https://www.python.org/downloads/) is installed on your system.
  
- **Install PostgreSQL**: Download and install PostgreSQL from the [official PostgreSQL website](https://www.postgresql.org/download/).
  
- **Install Python dependencies**:
  - Run the following command in the script directory to install the required dependencies:

    ```bash
    pip install paramiko requests aiopg uvicorn rapidjson
    ```

## ⚙️ Configuration

### 1. Create a PostgreSQL Database:
   - Use psql or pgAdmin to execute these SQL commands and create the database and user:

     ```sql
     CREATE DATABASE mydatabase;
     CREATE USER user WITH PASSWORD 'password';
     ALTER ROLE user SET client_encoding TO 'utf8';
     ALTER ROLE user SET default_transaction_isolation TO 'read committed';
     ALTER ROLE user SET timezone TO 'UTC';
     GRANT ALL PRIVILEGES ON DATABASE mydatabase TO user;
     ```

### 2. Update Connection Information in the Script
   - Open the Python script and update the `PG_CONFIG` variable:

     ```python
     PG_CONFIG = "host=localhost port=5432 dbname=mydatabase user=user password=password"
     ```

### 3. Install and Configure Redis (if needed)
   - Download and install Redis from the official Redis website: https://redis.io/
   - Start the Redis server.

### 4. Manage SSH Keys

- **Generate an SSH key pair**: Generate a key pair with the following command:

    ```bash
    ssh-keygen -t rsa -f server.key
    ```

## 🚀 Run

- **Build the Docker image**

  ```bash
    docker build -t winnie .
  ```

- **Run the Docker container**

    ```bash
    docker run -v ${PWD}:/usr/src/app -p 2222:2222 basic_honeypot
    ```

### Environment Configuration

- **Set environment variables for Redis (if needed)**
  
  In the terminal, execute the following commands:

    ```bash
    export REDIS_HOST=127.0.0.1
    export REDIS_PORT=6379
    export REDIS_PASSWORD=your_redis_password
    ```

  Or in Windows PowerShell:

    ```powershell
    $env:REDIS_HOST="127.0.0.1"
    $env:REDIS_PORT="6379"
    $env:REDIS_PASSWORD="your_redis_password"
    ```

### Running the Script

- **Run the script**: Navigate to the script directory in the terminal and start it:

    ```bash
    python script_name.py
    ```

- **Check functionality**: Review the logs (`combined_honeypot.log`) for information on connections and activities.

- **Test with an SSH client**: Use an SSH client to connect to the server with the IP address and port specified in the script.

- **Send URLs to download**: Add URLs to the Redis queue to test the URL download functionality.

- **Stop the script**: Use `Ctrl + C` in the terminal where it is running.

