# Installation (Without using VM)

## Install MySQL

1. install the following package :	

   ```console
   sudo apt-get install mysql-server
   ```

   You will be prompted to choose a root password

2. Install the CoreCA database (empty) :

   ```console
   sh scripts/setup_mysql.sh <DB Root Password>
   ```

   

## Install Python dependencies

1. Ensure __pip__ and __python3.*__ are installed.

2. Install a virtual environment : 

   ```console
   sudo apt-get install python3.*-venv 
   ```

3. Setup virtual environment :

   ```console
   python3.* -m venv venv 
   source venv/bin/activate
   ```

4. Install dependencies :

   ```console
   pip install -r requirements.txt
   ```

   This is not guaranteed to work on all systems, other python dependencies might need to be installed

# Running the Server

## Default run

```console
./run
```

Default values for parameters :

- port : 5001
- ip : 127.0.0.1
- __user__ : root
- __host__ : localhost
- __db__ : coreCA
- pwd : toor
- cap12 : p12/ca.p12
- crl : crl/crl.pem
- empfolder : p12 (must be in directoy _ca_core_)
- p12pass : default_password
- cert : keys/server_certificate.crt
- sk : keys/server_private_key.key
- newkeys : specify if a new CA signing key pair is needed.
- newcrl : specify if a new CRL must be generated

Parameters in bold characters should not be tweaked. In most cases a new server key (!= CA p12 key) will have to be generated :

```console
cd keys/
./genkeyscert.sh
```

When prompted a common name, the ip address of the server must be specified. if the ip is different than 127.0.0.1, then the ip parameter must be specified when running the server.

## VM

A VM is available at : <vm is not uploaded yet>

Everything should be already installed on it hence should follow instructions above to run the server. 

