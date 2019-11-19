from flask import Flask, request, Response, jsonify, make_response
from cerberus import Validator
import json
import logging
import os
import traceback
from db_manager import *
from ca_crypto import *
from utils import *
import base64
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)



class Endpoint :

	def __init__(self,action,name,secret_hash):

		self.action = action
		self.name = name
		self.secret_hash = secret_hash

	def __call__(self, *args):

		self.log_before_action(request)


		pwd = request.headers.get('secret',None) or None
	
		if pwd is None :
			self.log_no_password()
			return self.error_response("Need to Provide a Password in Header field 'secret'",401)
		
		if not self.check_pwd(pwd):
			self.log_auth_failed()
			return self.error_response('Wrong Password in Header',401)

		answer = self.action()

		return answer

	def log_auth_failed(self):

		log_line = "A Wrong password has been entered"
		logging.critical(log_line)

	def log_no_password(self):

		log_line = "No Password Given"
		logging.warning(log_line)

	def log_before_action(self,request):

		try : 

			log_line = ""
			log_line += str(Utils.asn1_date())
			log_line += str(request.method) + " "
			log_line += str(self.name) + " "
			log_line += str(request.remote_addr) + " "
			logging.info(log_line)
			if request.method == 'POST':
				log_line = str(json.loads(request.get_json()))
				logging.info(log_line)

		except Exception as e:

			log_line = "EXCEPTION CAUGHT "
			log_line += str(e) + " "
			log_line += str(request.remote_addr)
			logging.info(log_line)

	def check_pwd(self,pwd):

		hashed = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
		return hashed == self.secret_hash

	def error_response(self,error_text,status_code):

		error_r = dict()
		error_r['description'] = error_text

		return make_response(jsonify(error_r),status_code) 



class Server :

	def __init__(self,name,ip,port,certificate=None,key=None,secret_file='keys/secret_password.txt'):

		logging.basicConfig(filename='logs/server_ca_core.log',level=logging.DEBUG)

		self.app = Flask(name)
		self.port = port
		self.ip = ip
		sec = open(secret_file,'r')
		self.secret_hash = sec.read()
		sec.close()
		self.certificate = certificate
		self.key = key


	def add_url(self,endpoint=None,endpoint_name=None,handler=None,methods=None):
		self.app.add_url_rule(endpoint,endpoint_name,Endpoint(handler,endpoint_name,self.secret_hash),methods = methods)


	def run_server(self):

		if (self.certificate is not None) and (self.key is not None):

			self.app.run(host=self.ip,port=self.port,debug=False,
				ssl_context=(self.certificate,self.key))

		else:
			self.app.run(host=self.ip,port=self.port,debug=False)


	

class CACoreServer(Server) :

	
	def __init__(self,name,ip,port,db_manager,ca_crypto,cert_path=None,key_path=None):

		Server.__init__(self,name,ip,port,certificate= cert_path, key = key_path)
		self.db = db_manager
		self.ca_crypto = ca_crypto
		self.add_url("/new_certificate","new_certificate",handler=self.new_certificate,methods=['POST'])
		self.add_url("/current_state","current_state",handler=self.current_state,methods=['GET'])
		self.add_url("/revocation_list","revocation_list",handler=self.revocation_list,methods=['GET'])
		self.add_url("/revoke_certificate","revoke_certificate",handler=self.revoke_certificate,methods=['POST'])

	
	def revoke(self,sn):

		self.db.revoke_cert(sn)
		self.ca_crypto.revoke_sn(sn)
		self.ca_crypto.write_crl()

	def new(self,uid,last,first,email):

		state = self.db.get_currentState()
		serial = state[2]
		p12_bytes = self.ca_crypto.new_employee_cert(uid,last,first,email,serial)
		self.db.add_cert(uid)
		p12_encoded = base64.b64encode(p12_bytes).decode('utf-8')
		return p12_encoded


	def new_certificate(self):

		try :

			error = self.validate_request(request,validator = JSONValidators.new_certificate)

			if error is not None :

				return error

			data = json.loads(request.get_json())
			response_json = dict()

			uid = data['uid']
			lastname = data['lastname']
			firstname = data['firstname']
			email = data['email']

			# check if certificate already exists
			(already_exists,serial_number) = self.db.check_validCertificate(uid)

			if already_exists :

				# revoke certificate from serial number
				self.revoke(serial_number[0])

			# Generate Certificate
			p12  = self.new(uid,lastname,firstname,email)

			response_json['p12'] = p12
			return make_response(jsonify(response_json),200)

		except :

			self.handle_error()
			return self.error_response("Server Error",400)


	def current_state(self):

		try :

			# get current state
			response_json = dict()
			# TODO Add
			(num_issued,num_revoked,serial_num) = self.db.get_currentState()
			response_json['issued'] = num_issued
			response_json['revoked'] = num_revoked
			response_json['serial'] = serial_num

			return make_response(jsonify(response_json),200)

		except :

			self.handle_error()
			return self.error_response("Server Error",400)


	def revoke_certificate(self):

		try :

			error = self.validate_request(request,validator = JSONValidators.revoke_certificate)

			if error is not None :

				return error

			data = json.loads(request.get_json())
			response_json = dict()
			uid = data['uid']

			# Check if certificate already exists TODO
			(already_exists,serial_number) = self.db.check_validCertificate(uid)
			if not already_exists :
				response_json['revoked'] = False
			else :
				#TODO revoke certificate
				self.revoke(serial_number[0])
				response_json['revoked'] = True

			return make_response(jsonify(response_json),200)

		except :

			self.handle_error()
			return self.error_response("Server Error",400)


	def revocation_list(self):

		try :

			# TODO
			rlist = self.ca_crypto.get_crl_bytes()
			response_json = dict()
			response_json['rlist'] = rlist

			return make_response(jsonify(response_json),200)

		except :

			self.handle_error()
			return self.error_response("Server Error",400)



	def error_response(self,error_text,status_code):

		error_r = dict()
		error_r['description'] = error_text

		return make_response(jsonify(error_r),status_code) 


	def json_validator(self,data):

		try :

			json.loads(data)
			return True

		except ValueError as error:

			return False


	def has_json(self,r):

		try :

			json_data = r.get_json()
			return True

		except Exception as e :

			return False


	def validate_request(self,r,validator = None):

		if not self.has_json(r):

			return self.error_response("Invalid HTTP Request : No JSON",400)

		json_data = r.get_json()

		if not self.json_validator(json_data):

			return self.error_response("Invalid JSON format",400)

		data = json.loads(json_data)

		if not validator.validate(data):

			return self.error_response("Invalid JSON Fields",400)

		return None

	
	def handle_error(self):

		traceback.print_exc()



class JSONValidators :

	new_certificate = Validator({
		"uid" : {
			"type" : "string",
			"required" : True
		},
		"lastname" : {
			"type" : "string",
			"required" : True
		},
		"firstname" : {
			"type" : "string",
			"required" : True
		},
		"email" : {
			"type" : "string",
			"required" : True
		},
		"pwd" : {
			"type" : "string",
			"required" : False
		}
		})

	revoke_certificate = Validator({
		"uid" : {
			"type" : "string",
			"required" : True
		}
		})


	

if __name__ == '__main__':
	main()
	



















