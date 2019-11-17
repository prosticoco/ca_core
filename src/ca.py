import argparse
from server import *
from db_manager import * 
from ca_crypto import * 

def main(args):

	port = args.port
	ip = args.ip
	db_username = args.user
	db_host = args.host
	db_pwd = args.pwd
	db_name = args.db
	cert_path = args.cert
	key_path = args.sk
	ca_path = args.cap12
	crl_path = args.crl
	ca_passphrase = args.p12pass
	employee_folder = args.empfolder
	load_p12 = not args.newkeys
	load_crl = not args.newcrl


	db_manager = DBManager(db_host,db_username,db_pwd,db_name)
	ca_crypto = CACrypto(ca_path,crl_path,employee_folder,ca_passphrase,load_p12=load_p12,load_crl=load_crl)
	ca_server = CACoreServer('CA Core server',ip,port,db_manager,ca_crypto,
		cert_path=cert_path,key_path=key_path)
	print("Server IP : {} Server Port : {}".format(ip,port))
	ca_server.run_server()


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('--port', default=5001,help='server port')
	parser.add_argument('--ip',default='127.0.0.1',help='server ip')
	parser.add_argument('--user', default='root',help='database username')
	parser.add_argument('--host', default='localhost',help='db username host ip')
	parser.add_argument('--db', default='imovies',help='database name')
	parser.add_argument('--pwd', default='toor',help='db user password')
	parser.add_argument('--cap12',default='p12/ca.p12',help='location of the servers p12 file')
	parser.add_argument('--crl',default='crl/crl.pem',help='location of the certificate revocation list file')
	parser.add_argument('--empfolder',default='p12',help='name of the folder to contain employees saved certificates and keys')
	parser.add_argument('--p12pass',default='default_password',help='password to open and save all p12 files')
	parser.add_argument('--cert',default='keys/server_certificate.crt',help='server certificate path')
	parser.add_argument('--sk',default='keys/server_private_key.key',help='server private key path')
	parser.add_argument('--newkeys', action= 'store_true',help='if present then a new p12 will be generated at the ca p12 path')
	parser.add_argument('--newcrl',action='store_true',help='if present then a new crl will be generated at the crl path')
	arguments = parser.parse_args()
	main(arguments)

