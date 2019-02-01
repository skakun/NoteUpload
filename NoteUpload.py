from flask import Flask,render_template,redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
from MySQLdb import escape_string as thwart

app = Flask(__name__)
app.config["SECRET_KEY"]="secret"

def crypt(passwd):
	return bcrypt.hashpw(passwd.encode('utf-8'),bcrypt.gensalt())
from dbconnect import connection
@app.route('/NoteUpload/')
def hello():
    return "Hello, Flask!"

@app.route('/NoteUpload/login/')
def on_login():
	return render_template('login.html')

@app.route('/NoteUpload/register/',methods=["GET"])
def reg_form():
	return render_template('register.html')

@app.route('/NoteUpload/register/',methods=["POST"])
def on_register():
	username=request.form['login']
	password=crypt(request.form['password'])

	c, conn=connection()
	c.execute("INSERT INTO  user(username,password) VALUES(%s,%s)",( thwart(username),thwart(password)))
	conn.commit()
	c.close()
	conn.close()
	return redirect((url_for('/NoteUpload/login')))

if __name__ == "__main__":
    app.run()
