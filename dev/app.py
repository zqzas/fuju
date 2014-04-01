#Author: Mainri (mainri@live.com)

from flask import Flask, url_for, render_template, redirect, request, flash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import login_user, logout_user, current_user, login_required, LoginManager
from werkzeug import generate_password_hash, check_password_hash, secure_filename

import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'FUD32'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/zqzas/Dropbox/fuju/dev/test.db'
app.config['MAX_USER_LENGTH'] = 100
app.config['IMAGE_PATH'] = 'static/image/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'signin'

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

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
        self.password_hash = generate_password_hash(password) 
        self.major = major

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

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group1_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    group2_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    message = db.Column(db.Text)
    status = db.Column(db.Integer)

    def __init__(self, group1_id, group2_id, message):
        self.group1_id = group1_id
        self.group2_id = group2_id
        self.message = message
        self.status = 0

    def __repr__(self):
        return '<Meeting between %d and %d with message %s>' % (self.group1_id, self.group2_id, self.message)









@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html') #TODO: consider if this is needed
    user = User(request.form['nickname'], request.form['email'], request.form['password'],  request.form['major'])
    db.session.add(user)
    db.session.commit()

    flash("You are in.")
    return redirect(url_for('signin'))


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'GET':
        return render_template('signin.html') #TODO: consider if needed

    email = request.form['email']
    password = request.form['password']
    registered_user = User.query.filter_by(email=email).first() 
    
    print registered_user.password_hash, password #debug
    if registered_user is None or not check_password_hash(registered_user.password_hash, password):
        print 'invalid' #debug
        flash('Invalid.')
        return redirect(url_for('index')) #TODO: consider if this is the next page for a failed signin
    print email, ' has signed in.'
    login_user(registered_user)
    flash("You've come in.")

    return redirect(request.args.get('next') or url_for('index'))

@app.route('/getgroup/<int:group_id>', methods=['GET', 'POST'])
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
            filename.rsplit('.', 1)[1] in ['jpg', 'jpeg', 'png', 'bmp', 'gif']

@app.route('/addgroup', methods=['POST'])
@login_required
def add_group():
    user = current_user

    print request.files

    uploaded_files = [request.files['pic1'], request.files['pic2'], request.files['pic3']]
    print 'ok'
    dess = [request.form['des1'], request.form['des2'], request.form['des3']] #TODO: examine if 3 descriptions actually
    print 'ok'
    dess = [des if des else '' for des in dess]
    filenames = []


    #TODO: WTForms and form validation are needed.

    for f in uploaded_files:
        if len(f.filename) and allowed_file(f.filename):
            filename = secure_filename(f.filename) #filename is secured here
            #it should be an image now
            f.save(os.path.join(app.config['IMAGE_PATH'], filename))
            filenames.append(filename)


        
    
    if len(filenames) > 3 or len(filenames) < 1:
        return redirect(url_for('index'), error = 'Upload fails.' ) #TODO: handle error

    #save the group into db
    group = Group(user.id, filenames[0], dess[0], filenames[1], dess[1], filenames[2], dess[2])
    db.session.add(group)
    db.session.commit()

    flash('Upload finished.')
    print 'Upload finished.' #debug


    return redirect(url_for('index'))

app.route('/static/<path:path>')
def static(path):
    # send_static_file will guess the correct MIME type
    return app.send_static_file(os.path.join('static', path))

            
@app.route('/')
def index():
    if (not current_user) or (not current_user.is_authenticated()):
        return redirect(url_for('signin'))

    #user has signed in
    user = current_user
    
    #TODO: add more main stuffs here

    groups = Group.query.all()
    return render_template('index.html', groups = groups, img_path = app.config['IMAGE_PATH'])
    


        

if __name__ == '__main__':
    app.run(debug=True)




        

