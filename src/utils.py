from datetime import datetime,timezone


class Utils : 


  def asn1_date():
  	return str(datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%z'))

