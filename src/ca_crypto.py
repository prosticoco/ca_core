from OpenSSL.crypto import load_privatekey, load_publickey, FILETYPE_PEM,FILETYPE_TEXT
from OpenSSL import crypto
from OpenSSL.crypto import TYPE_RSA
from utils import Utils




class CACrypto :


	def __init__(self,ca_p12_path,crl_path,employee_folder,passphrase,load_p12=False,load_crl=False):

		self.ca_p12_path = ca_p12_path
		self.crl_path = crl_path
		self.p12_folder = employee_folder
		self.passphrase = passphrase

		if load_p12 :

			self.load_ca_p12()
			self.load_crl()

		else :

			self.gen_new_ca_key_cert()

		if load_crl :

			self.load_crl()

		else :

			self.new_crl()


	def load_crl(self):

		data = open(self.crl_path,"rb")
		self.crl = crypto.load_crl(FILETYPE_PEM,data.read())
		print(type(self.crl))
		data.close()


	def new_crl(self):

		self.crl = crypto.CRL()
		self.write_crl()



	def revoke_sn(self,sn):

		revoke = crypto.Revoked()
		revoke.set_serial(format(sn,'x').encode('UTF-8'))
		revoke.set_rev_date(Utils.asn1_date().encode('UTF-8'))
		self.crl.add_revoked(revoke)
		self.crl.set_lastUpdate(Utils.asn1_date().encode('UTF-8'))

	def write_crl(self):

		crl_bytes = self.crl.export(self.ca_cert,self.ca_key,
			type=FILETYPE_PEM,digest=b"sha256")
		file = open(self.crl_path,'wb')
		file.write(crl_bytes)
		file.close()
	
	def get_crl_bytes(self):

		return self.crl.export(self.ca_cert,self.ca_key,
			type=FILETYPE_PEM,digest=b"sha256").decode('utf-8')


	def generate_keys(self):
		key = crypto.PKey()
		key.generate_key(TYPE_RSA,4096)
		return key

	def gen_new_ca_key_cert(self):

		self.ca_key = self.generate_keys()
		self.ca_pkcs12 = crypto.PKCS12()
		self.ca_pkcs12.set_privatekey(self.ca_key)
		name = self.get_ca_name()
		cert = self.gen_unsigned_cert(name,name,69420,self.ca_key,1)
		cert.sign(self.ca_key,'sha256')
		self.ca_cert = cert
		self.ca_pkcs12.set_certificate(cert)
		self.write_ca_p12()

	def new_employee_cert(self,uid,lastname,firstname,email,serial_number):

		subject = self.get_employee_name(uid,lastname,firstname,email)
		subject_key = self.generate_keys()
		cert = self.gen_unsigned_cert(self.get_ca_name(),subject,serial_number,subject_key,1)
		cert.sign(self.ca_key,'sha256')
		pkcs12 = crypto.PKCS12()
		pkcs12.set_certificate(cert)
		pkcs12.set_privatekey(subject_key)
		p12bytes = pkcs12.export()
		p12bytes_encrypted = pkcs12.export(passphrase=self.passphrase.encode('utf-8'))
		path = self.p12_folder + "/" + "uid" + str(uid) + "sn" + str(serial_number) + ".p12"
		file = open(path,"wb")
		file.write(p12bytes_encrypted)
		file.close()
		return p12bytes


	def load_ca_p12(self):

		sk_bin = open(self.ca_p12_path,"rb")
		self.ca_pkcs12 = crypto.load_pkcs12(sk_bin.read(),passphrase=self.passphrase.encode('utf-8'))
		self.ca_key = self.ca_pkcs12.get_privatekey()
		self.ca_cert = self.ca_pkcs12.get_certificate()
		sk_bin.close()


	def write_ca_p12(self):

		p12file = open(self.ca_p12_path,"wb")
		pkcs_string = self.ca_pkcs12.export(passphrase=self.passphrase.encode('utf-8'))
		p12file.write(pkcs_string)
		p12file.close()


	def gen_unsigned_cert(self,issuer,subject,serial_number,key,num_years):

		cert = crypto.X509()
		cert.set_subject(subject)
		cert.set_issuer(issuer)
		cert.set_serial_number(serial_number)
		cert.gmtime_adj_notBefore(0)
		cert.gmtime_adj_notAfter(num_years*365*24*60*60)
		cert.set_pubkey(key)
		return cert


	def get_imovies_name(self):
		
		name = crypto.X509Name(crypto.X509().get_subject())
		name.O = "Imovies"
		return name 


	def get_ca_name(self):

		name = self.get_imovies_name()
		name.OU = "Certificate Authority"
		name.CN = "Imovies"
		return name


	def get_employee_name(self,uid,lastname,firstname,email):

		name = self.get_imovies_name()
		name.OU = "Employee"
		name.CN = lastname + " " + firstname + " " + uid
		name.emailAddress = email
		return name


if __name__ == '__main__':

	ca = CACrypto("../p12/ca.p12",load=True)
	ca.new_crl()
	ca.revoke_sn(18)
	ca.revoke_sn(421)
	ca.write_crl()
	employee = ca.new_employee_cert('pr','Prost','Adrien','aprost@eth.ch',69)
	certfile = open('../p12/prost.p12',"wb")
	certfile.write(employee)
	certfile.close()

	



