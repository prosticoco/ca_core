import requests
import json
import argparse
import sys
import os
import traceback
import time
import base64
from OpenSSL import crypto





class Client :


	def __init__(self,ip,port,cert):


		self.ip = ip
		self.port = port
		self.cert = cert
		urlbase = 'https://' + str(ip) + ":" + str(port) + "/"
		self.url_new_certificate = urlbase + "new_certificate"
		self.url_current_state = urlbase + "current_state"
		self.url_revocation_list = urlbase + "revocation_list"
		self.url_revoke_certificate = urlbase + "revoke_certificate"
		self.function_dict = {'0' : self.new_certificate,'1' : self.current_state, '2' : self.revocation_list,'3' : self.revoke_certificate}


	def run(self):

		while True :

			try :

				os.system('clear')

				print("What do you want to do ?")
				action = input("0 : new cert, 1 : get state, 2 : revocation_list, 3 : revoke_certificate \n")

				function = self.function_dict.get(action,None)

				if function is None :
					print("Invalid choice")

				else :
					function()

			except KeyboardInterrupt :

				self.exit()

			except requests.exceptions.ConnectionError :

				print("Server unreachable")
				self.exit()


	def exit(self):

		print("\nGoodbye my friend\n")
		sys.exit(0)


	def revoke_certificate(self):

		req = dict()
		req['uid'] = input("Username?\n")
		r = requests.post(self.url_revoke_certificate,verify=self.cert,json=json.dumps(req))
		self.answer(r)


	def new_certificate(self):

		check = dict()
		check['uid'] = input("Username ?\n")
		check['lastname'] = input("lastname ?\n")
		check['firstname'] = input("firstname ?\n")
		check['email'] = input("email ?\n")
		r = requests.post(self.url_new_certificate,verify=self.cert,json=json.dumps(check))	
		self.answer(r)
		



	def answer(self,r):
		print("Answer from server:")
		try :
			print(r.json())

		except :
			print("Server unexpected answer")
		print("(Press Enter for new request)")
		i = input("")



	
	def current_state(self):

		r = requests.get(self.url_current_state,verify=self.cert)
		self.answer(r)

	
	def revocation_list(self):

		r = requests.get(self.url_revocation_list,verify=self.cert)
		print(r.json()['rlist'])
		self.answer(r)




def main(args):

	ip = args.ip
	port = args.port
	cert = args.cert
	client = Client(ip,port,cert)
	requests.packages.urllib3.disable_warnings()
	client.run()


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('--port', default=5001)
	parser.add_argument('--ip',default='127.0.0.1')
	parser.add_argument('--cert',default='keys/server_certificate.crt')
	arguments = parser.parse_args()
	main(arguments)