import MySQLdb
from config import dbname,dbhost,dbuser
def connection():
	conn=MySQLdb.connect(host=dbhost,user=dbuser,db=dbname)
	c=conn.cursor()
	return c, conn
