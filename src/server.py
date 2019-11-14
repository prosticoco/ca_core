from flask import Flask, request, Response, jsonify, make_response
from cerberus import Validator
import json
import logging
import os
import traceback
import hashlib
from user_db_manager import *

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


class Server :

	def __init__(self,name,ip,port,certificate=None,key=None):

		self.app = Flask(name)
		self.port = port
		self.ip = ip
		self.certificate = certificate
		self.key = key


	def add_url(self,endpoint=None,endpoint_name=None,handler=None,methods=None):
		self.app.add_url_rule(endpoint,endpoint_name,handler,methods = methods)



	def run_server(self):

		if (self.certificate is not None) and (self.key is not None):

			self.app.run(host=self.ip,port=self.port,debug=False,
				ssl_context=(self.certificate,self.key))

		else:
			self.app.run(host=self.ip,port=self.port,debug=False)


	

class CACoreServer(Server) :

	
	def __init__(self,name,ip,port,db_manager,cert_path=None,key_path=None):

		Server.__init__(self,name,ip,port,certificate= cert_path, key = key_path)
		self.user_db = db_manager
		self.add_url("/new_certificate","new_certificate",handler=self.new_certificate,methods=['POST'])
		self.add_url("/current_state","current_state",handler=self.current_state,methods=['GET'])
		self.add_url("/revocation_list","revocation_list",handler=self.revocation_list,methods=['GET'])
		self.add_url("/revoke_certificate","revoke_certificate",handler=self.revoke_certificate,methods=['POST'])

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
			(already_exists,serial_number) = self.db.check_if_exists()

			if already_exists :

				# revoke certificate from serial number
				self.db.revoke()

			# Generate Certificate
			certificate, pkcs  = self.db.gen_certificate

			response_json['certificate'] = certificate
			response_json['pkcs'] = pkcs
			return make_response(jsonify(response_json),200)

		except :

			self.handle_error()
			return self.error_response("Server Error",400)


	def current_state(self):

		try :

			# get current state
			response_json = dict()
			# TODO Add
			(num_issued,num_revoked,serial_num) = self.db
			response_json['issued'] = num_issued
			response_json['revoked'] = num_revoked
			response_json['serial'] = serial_num

			return make_response(jsonify(response_json),200)

		except :

			self.handle_error()
			return self.error_response("Server Error",400)


	def revoke_certificate(self):

		try :

			error = self.validate_request(request,validator = JSONValidators.new_certificate)

			if error is not None :

				return error

			data = json.loads(request.get_json())
			response_json = dict()
			uid = data['uid']

			# Check if certificate already exists TODO
			(already_exists,serial) = self.db.check_if_exists()
			if not already_exists :
				response_json['revoked'] = False
			else :
				#TODO revoke certificate
				self.db.revoke(uid)
				response_json['revoked'] = True

			return make_response(jsonify(response_json),200)

		except :

			self.handle_error()
			return self.error_response("Server Error",400)


	def revocation_list(self):

		try :

			# TODO
			rlist = self.db.get_revocation_list()
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

			print("Invalid json")
			return False


	def has_json(self,r):

		try :

			json_data = r.get_json()
			return True

		except Exception as e :

			print("Message has no JSON")
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


	


	



















