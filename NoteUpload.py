from flask import Flask,render_template,redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
from config import secret
import bcrypt
from MySQLdb import escape_string as thwart

app = Flask(__name__)
app.config["SECRET_KEY"]=secret

def crypt(passwd):
	return bcrypt.hashpw(passwd.encode('utf-8'),bcrypt.gensalt())
from dbconnect import connection
@app.route('/')
def hello():
    return "Hello, Flask!"

@app.route('/login/')
def on_login():
	return render_template('login.html')

from wtforms import Form, BooleanField, StringField, PasswordField, validators
class RegistrationForm(Form):
	username=StringField('Username', [validators.Length(min=4,max=25)])
	email=StringField('Email Adress', [validators.Length(min=6,max=35)] )
	password = PasswordField('New Password', [
	 validators.DataRequired(),
	 validators.EqualTo('confirm', message='Passwords must match')
	])
	confirm = PasswordField('Repeat Password')
	accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])
	def validate(self):
		rv=Form.validate(self)
		flag=True
		if not rv:
			return False
		c, conn=connection()
		row_count=c.execute("select * from user where username in(%s)",[thwart(self.username.data)])
		if row_count >0:
			self.username.errors.append("Username already in use")
			flag=False
		row_count=c.execute("select * from user where email in(%s)",[thwart(self.email.data)])
		if row_count >0:
			self.email.errors.append("Email already in use")
			flag=False
		return flag



########@app.route('/NoteUpload/register/',methods=["GET"])
########def reg_form():
########	return render_template('register.html')

@app.route('/NoteUpload/register/',methods=["GET","POST"])
def on_register():
	form = RegistrationForm(request.form)
	if request.method == 'POST' and form.validate():
		username=form.username.data
		password=form.password.data
		password=crypt(password)
		email=form.email.data
		c, conn=connection()
		c.execute("INSERT INTO  user(username,password,email) VALUES(%s,%s,%s)",( thwart(username),thwart(password),thwart(email)))
		conn.commit()
		c.close()
		conn.close()
		return redirect((url_for('hello')))
	return render_template('register.html',form=form)

if __name__ == "__main__":
    app.run()
