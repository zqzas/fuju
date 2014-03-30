#Author: Mainri (mainri@live.com)

from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import login_user, logout_user, current_user, login_required
from werkzeug import generate_password_hash, check_password_hash, secure_filename

import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/zqzas/Dropbox/fuju/dev/test.db'
app.config['MAX_USER_LENGTH'] = 100
app.config['IMAGE_PATH'] = 'static/image/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(app.config['MAX_USER_LENGTH']), unique=True)
    email = db.Column(db.String(app.config['MAX_USER_LENGTH']), unique=True)
    password_hash = db.Column(db.String(app.config['MAX_USER_LENGTH']))
    major = db.Column(db.String(app.config['MAX_USER_LENGTH']))

    groups = db.relationship('Group', backref='user', lazy='dynamic')

    def __init__(self, username, email, password, major):
        self.username = username
        self.email = email
        sef.password_hash = generate_password_hash(password) 

    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return unicode(self.id)
 
    def __repr__(self):
        return '<User %r>' % (self.username)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    pic1 = db.Column(db.Text)
    pic2 = db.Column(db.Text)
    pic3 = db.Column(db.Text)

    des1 = db.Column(db.Text)
    des2 = db.Column(db.Text)
    des3 = db.Column(db.Text)

    def __init__(self, user_id, pic1, des1, pic2, des2, pic3, des3):
        self.user_id = user_id
        self.pic1 = pic1
        self.pic2 = pic2
        self.pic3 = pic3

        self.des1 = des1
        self.des2 = des2
        self.des3 = des3

    def __repr__(self):
        return '<Group of %d>' % (self.user_id)

@app.route('/register', method=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html') #TODO: consider if this is needed
    user = User(request.form['username'], request.form['email'], request.form['password'],  request.form['major'])
    db.session.add(user)
    db.session.commit()

    flash("You are in.")
    return redirect(url_for('login'))


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'GET':
        return render_template('login.html') #TODO: consider if needed

    username = request.form['username']
    password_hash = generate_password_hash(request.form['password'])
    registered_user = User.query.filter_by(username=username,password_hash=password_hash).first() 
    
    if registered_user is None:
        flash('Invalid.')
        return redirect(url_for('index')) #TODO: consider if this is the next page for a failed signin

    login_user(registered_user)
    flash("You've come in.")

    return redirect(request.args.get('next') or url_for('index'))

@app.route('/getgroup/<int:group_id>', method=['GET', 'POST'])
@login_required
def get_group(group_id):
    group = Group.query.filter_by(id=group_id).first()

    uri_pic1 = app.config['IMAGE_PATH'] + group.pic1
    uri_pic2 = app.config['IMAGE_PATH'] + group.pic2
    uri_pic3 = app.config['IMAGE_PATH'] + group.pic3

    uri_pics = [uri_pic1, uri_pic2, uri_pic3]
    dess = [des1, des2, des3]

    if group: #on succes
        return render_template('group.html', pics = uri_pics, dess = dess) #TODO: pass the parameters for group page.

    return redirect(url_for('index'))


def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1] in ['.jpg', '.jpeg', 'png', 'bmp', 'gif']

@app.route('/addgroup', method=['POST'])
@login_required
def add_group():
    user = current_user

    uploaded_files = request.files.getlist('file[]')
    dess = [request.form['des1'], request.form['des2'], request.form['des3']] #TODO: examine if 3 descriptions actually
    dess = [dess[i] if dess[i] else '']
    filenames = []

    for f in uploaded_files:
        if f and allowed_file(f.filename):
            filename = secure_filename(f.filename) #filename is secured here

            #it should be an image now
            f.save(os.path.join(app.config['IMAGE_PATH'], filename))
            filenames.append(filename)

    

    if len(filenames) > 3 or len(filenames) < 1:
        return redirect(url_for('index'), error = 'Upload fails.' )

    #save the group into db
    group = Group(user.id, filenames[0], dess[0], filenames[1], dess[1], filenames[2], dess[2])
    db.session.add(group)
    db.session.commit()

    flash('Upload finished.')


    return redirect(url_for('index'))

            




    group = Group(user.id, 









        

