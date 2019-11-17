import mysql.connector 
from mysql.connector import Error
import traceback






class DBManager :

	insertQuery = """ INSERT INTO keyStore (uid,valid)
	VALUES (%s,'valid');"""

	checkQuery = """ SELECT valid FROM keyStore 
		WHERE uid = %s AND valid = 'valid';"""

	selectQuery = """ SELECT * FROM keyStore """

	getRowCount = """ SELECT COUNT(*) FROM keyStore"""

	updateQuery = """ UPDATE keyStore 
	SET 
	valid = 'revoked'
	WHERE
	sn = %s;"""

	getRovkedQuery = """
	SELECT sn FROM keyStore
		WHERE valid = 'revoked';"""

	checkRevokedCertificate = """
	SELECT * FROM keyStore
		WHERE uid=%s AND valid = 'valid';"""

	getSerial = """SELECT MAX(sn) FROM keyStore"""
	"""Summary
​
	Baseline class to connect to a mySQL database and execute 
	SQL queries
	
	Attributes:
	    connection (TYPE): connection to the DB
	    cursor (TYPE): DB Cursor to execute queries
	"""

	def __init__(self,host,user,passwd,database):
		"""Summary
		
		Args:
		    host (TYPE): IP address of user
		    user (TYPE): username
		    passwd (TYPE): password
		    database (TYPE): database name
		"""
		try:
			self.connection = mysql.connector.connect(host= host,user = user,
				passwd =passwd,database = database)
			
			

			self.cursor = self.connection.cursor(prepared=True)
		
		except Error as e:
			print("Error while connecting to MySQL", e)

		try:
			mySql_Create_Table_Query = """ CREATE TABLE IF NOT EXISTS keyStore
			(sn INT AUTO_INCREMENT PRIMARY KEY,
			uid VARCHAR(20) NOT NULL, valid VARCHAR(10) NOT NULL)
			"""
			self.cursor.execute(mySql_Create_Table_Query)

		except mysql.connector.Error as error:
			print("Failed to create table in MySQL: {}".format(error))

	
	def revoke_cert(self,sn):

		self.insert_query(self.updateQuery,(int(sn),))



	def add_cert(self,uid):

		self.insert_query(self.insertQuery,(uid,))


	def err_handler(self,exc):
		"""Summary
		
		Args:
		    exc (Exception, optional): Exception to print
		"""
		print("DBManager Error :")
		print(type(exc))
		traceback.print_exc()
		raise exc

	def insert_query(self,query,q_tuple):

		try:
			self.cursor.execute(query,q_tuple)
			self.connection.commit()


		except Exception as e :
			self.err_handler(e)
				
		

	def update_query(self,query,q_tuple):

		try:
			self.cursor.execute(query,q_tuple)
			self.connection.commit()


		except Exception as e :
			self.err_handler(e)
				
		

	def lookUp_query(self, query, q_tuple):
		result = None

		try:
			self.cursor.execute(query, q_tuple)
			result = self.cursor.fetchall()

		except Exception as e :
			self.err_handler(e)

		return result

	def get_currentState(self):
		revokedCertificatesNumber = 0
		currentSerialNumber = 0
		try:
			self.cursor.execute(self.getSerial)
			currentSerialNumber = self.cursor.fetchall()[0][0]
			if currentSerialNumber is None :
				currentSerialNumber = 1
			else :
				currentSerialNumber += 1

			self.cursor.execute(self.getRowCount)
			num_issued = self.cursor.fetchall()[0][0]
			
			self.cursor.execute(self.getRovkedQuery)
			revokedCertificatesNumber = self.cursor.fetchall()

		except Exception as e :
			self.err_handler(e)

		return [num_issued,len(revokedCertificatesNumber),currentSerialNumber]

	def get_revocationList(self):
		try:
			self.cursor.execute(self.getRovkedQuery)
			revocationList = self.cursor.fetchall()

		except Exception as e :
			self.err_handler(e)


		serialNumbers = []

		for revokedEntity in revocationList:
			serialNumbers.append(revokedEntity[0])
		return serialNumbers


	def check_validCertificate(self, name):
		nameTuple = (name, )
		try:
			self.cursor.execute(self.checkRevokedCertificate, nameTuple)
			validCertificateList = self.cursor.fetchall()

			if(len(validCertificateList)==0):
				return False, None

			else:
				validSerialNumbers = []
				for validCertificate in validCertificateList:
					validSerialNumbers.append(validCertificate[0])

				return True, validSerialNumbers

		except Exception as e:
			self.err_handler(e)

		

	def disconnectDB(self):
			try:
				if (self.connection.is_connected()):
					self.cursor.close()
					self.connection.close()
					print("MySQL connection is closed")

			except Exception as e:
				print('Can not close the connection to database')





if __name__ == '__main__':
	####	How to instantiate a DB on local host, user:root, passwd: toor, table: coreCA
	db_manager = DBManager('localhost','root','toor','coreCA')

	####	How to insert an entity
	db_manager.add_cert('pr')
	db_manager.add_cert('prost')
	db_manager.add_cert('prosty')

	####	How to revoke a certificate of a user
	db_manager.revoke_cert(1)
	db_manager.revoke_cert(4)

	print(db_manager.get_revocationList())
	
	####	How to get current state
	result = db_manager.get_currentState()
	print(result)

	####	How to get revocation list
	#result = db_manager.get_revocationList()

	####	How to check if a user has any valid certificates
	####	If yes, it reruns a list [True, [list of all valid certificates]]
	####	If no, it returns a list [False, []]
	result = db_manager.check_validCertificate('pr')
	print(result)
	####	How to disconnect from database
	db_manager.disconnectDB()

