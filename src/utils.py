from datetime import datetime,timezone


class Utils : 


  def asn1_date():
  	return str(datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%z'))





if __name__ == '__main__':
	time = datetime.now(timezone.utc)
	print(time.strftime('%Y%m%d%H%M%S%Z'))
	print(time.year)
	print(time.month)
	print(time.day)
	print(time.hour)
	print(time.minute)
	print(datetime.now(None))

	