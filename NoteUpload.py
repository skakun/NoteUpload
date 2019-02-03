from flask import Flask,render_template,redirect, url_for, request,Blueprint,flash,jsonify,session
from config import appsecret,appsalt, BaseConfig
import bcrypt
from MySQLdb import escape_string as thwart
from flask_mail import Mail
import sys
from util import fprint
import json
import shutil
import os
app = Flask(__name__)
_config=BaseConfig()
app.config.from_object(_config)
mail = Mail(app)
#sys.stdout = open('output.logs', 'w')
########app.config["SECRET_KEY"]=appsecret
########app.config["SECURITY_PASSWORD_SALT"]=appsalt


from mail_handler import generate_confirmation_token, confirm_token,send_email
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
		c.execute("INSERT INTO  user(username,password,email,checked) VALUES(%s,%s,%s,0)",( thwart(username),thwart(password),thwart(email)))
		conn.commit()
		c.close()
		conn.close()

		token = generate_confirmation_token(email)
		confirm_url = url_for('confirm_email', token=token, _external=True)
		html = render_template('reg_mail_template.html', confirm_url=confirm_url)
		subject = "Please confirm your email"
		send_email(email, subject, html)
		flash('A confirmation email has been sent via email.', 'success')

		return redirect((url_for('hello')))
	return render_template('register.html',form=form)
@app.route('/confirm/<token>')
def confirm_email(token):
	c,conn=connection()
	try:
		email = confirm_token(token)
	except:
		flash('The confirmation link is invalid or has expired.', 'danger')
	c.execute("select * from user where email=(%s)",[thwart(str(email))])
	user_checked=1
	resp=c.fetchall()
	user_checked=resp[0][4]
	username=resp[0][1]
	print(user_checked)
	if user_checked==1:
		flash('Account already confirmed. Please login.', 'success')
	else:
		c.execute(" update user set checked=1 where email=(%s)",[thwart(str(email))])
		flash('You have confirmed your account. Thanks!', 'success')
	conn.commit()
	c.close()
	conn.close()
	os.makedirs(app.config["WORKING_DIR"]+"notes/"+username+"/")
	os.makedirs(app.config["WORKING_DIR"]+"notes/"+username+"/recived")
	return redirect(url_for('hello'))

@app.route('/login/',methods=['POST','GET'])
def log_in():
	c,conn=connection()
	query=""
	if request.method=="GET":
		return render_template("login.html")
	if request.method=="POST":
		row_num=c.execute("select * from user where username=(%s)",[thwart(request.form['login'])])
		if row_num==0:
			return "Wrong passess"
		query=c.fetchall()[0]
		hashpass=query[2].encode('utf-8')
		checked=query[4]
		username=query[1]
		if  hashpass!=bcrypt.hashpw(request.form["password"].encode('utf-8'),hashpass) or checked!=1:
			return "Wrong passess"
		else:
			session['username']=username
			return redirect(url_for('render_main_view'))
	return "pozdro"
@app.route('/noteview/<file_to_preview>',methods=['POST','GET'])
@app.route('/noteview/',methods=['POST','GET'],defaults={'file_to_preview':None})
def render_main_view(file_to_preview):
	print(session['username'])
	if session['username'] is None or session['username']=="":
		return "You should log in first"
	filelist=os.listdir(app.config["WORKING_DIR"]+"notes/"+session["username"]+'/')
	filelist=[f for f in filelist if os.path.isfile(app.config["WORKING_DIR"]+"notes/"+session["username"]+'/'+f)]
	preview=""
	if not ( file_to_preview is None or file_to_preview==""):
		f=open(app.config["WORKING_DIR"]+"notes/"+session["username"]+'/'+file_to_preview,"r")
		preview=f.read()
		f.close()
	return render_template('notes.html',user=session['username'],filelist=filelist,previewed=preview)
@app.route('/logout/',methods=['POST','GET'])
def log_off():
	session['username']=""
	return redirect(url_for('hello'))
@app.route('/delaccount/',methods=['POST','GET'])
def remove_accout():
	shutil.rmtree(app.config['WORKING_DIR']+'notes/'+session['username']+'/')
	c,conn=connection()	
	c.execute("delete from user where username=(%s)",[thwart(session["username"])])
	conn.commit()
	c.close()
	conn.close()
	session['username']=""
	return redirect(url_for('hello'))
@app.route('/upload/',methods=["POST"])
def upload_note():
	if session['username'] is None or session['username']=="":
		return "You should have been signed up"
########c,conn=connection()
########row_num=c.execute("select * from user where username=(%s)",[thwart(session["username"])])
########if row_num==0:
########	return "pozdro"
########result=c.fetchall()[0]
	title=request.form["ntitle"]+".txt"
	note=request.form["note"]
	f=open(app.config["WORKING_DIR"]+"notes/"+session["username"]+'/'+title,"w+")
	f.write(note)
	f.close()
	return redirect(url_for('render_main_view'))
@app.route('/share/', methods=["POST","GET"])
def share_note():
	if session['username'] is None or session['username']=="":
		return "You should have been signed up"
	if request.method=="GET":
		filename=request.form["filename"]
		return render_template("share.html",filename=filename)
	if request.method=="POST":
		filename=request.form["filename"]+".txt"
		note_reciver=request.form["note_reciver"]
		sharer=session['username']
		c,conn=connection()
		row_count=c.execute("select * from user where username=(%s)",[thwart(note_reciver)])
		conn.commit()
		c.close()
		conn.close()
		if row_count==0:
			return "No such user"
		os.symlink(app.config["WORKING_DIR"]+"notes/"+sharer+"/"+filename,app.config["WORKING_DIR"]+"notes/"+reciver+"/recived/"+filename)
	return redirect(url_for('render_main_view'))

if __name__ == "__main__":
    app.run()
