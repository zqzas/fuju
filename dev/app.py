#!/usr/bin/python
# -*- coding: utf-8 -*-

#Author: Mainri (mainri@live.com)

from flask import Flask, url_for, render_template, redirect, request, flash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import login_user, logout_user, current_user, LoginManager
from werkzeug import generate_password_hash, check_password_hash, secure_filename

from flask.ext.security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, url_for_security
from flask_security.forms import ConfirmRegisterForm, Required, _default_field_labels
from wtforms import TextField
from flask_wtf.html5 import IntegerField
from wtforms.fields import RadioField
    
from flask_mail import Mail

import os, datetime


app = Flask(__name__)

app.config['MY_DOMAIN'] = 'fdanke.com' #just to hold the place

app.config['CODE_PATH'] = os.path.dirname(os.path.abspath(__file__))
app.config['SECRET_KEY'] = 'FUD32'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////%s' % (os.path.join(app.config['CODE_PATH'], 'beta.db'))
app.config['MAX_USER_LENGTH'] = 255
app.config['IMAGE_PATH'] = 'static/image/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECURITY_TRACKABLE'] = True
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = '32'
app.config['SECURITY_EMAIL_SENDER'] = 'danke_fd@163.com'
app.config['SECURITY_CONFIRMABLE'] = True #Users are required to confirm their email when registering
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True

app.config['MAIL_SERVER'] = 'smtp.163.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'danke_fd'
app.config['MAIL_PASSWORD'] = 'u4HmMe8q'

db = SQLAlchemy(app)

#login_manager = LoginManager()
#login_manager.init_app(app)
#login_manager.login_view = 'signin'

#! The view for login: login, login.html


#
# Models
#

roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(app.config['MAX_USER_LENGTH']), unique=True)
    email = db.Column(db.String(app.config['MAX_USER_LENGTH']), unique=True)
    password = db.Column(db.String(app.config['MAX_USER_LENGTH']))
    major = db.Column(db.String(app.config['MAX_USER_LENGTH']))
    gender = db.Column(db.Integer) # 0 for male, 1 for female
    single = db.Column(db.Integer) # 1 for single
    info = db.Column(db.PickleType)
    
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    
    last_login_at = db.Column(db.String(app.config['MAX_USER_LENGTH']))
    current_login_at = db.Column(db.String(app.config['MAX_USER_LENGTH']))
    last_login_ip = db.Column(db.String(app.config['MAX_USER_LENGTH']))
    current_login_ip = db.Column(db.String(app.config['MAX_USER_LENGTH']))
    login_count = db.Column(db.Integer)

    groups = db.relationship('Group', backref='user', lazy='dynamic')
    roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))

    #def __init__(self, username, email, password, major, gender, single=1):
    #    self.username = username
    #    self.email = email
    #    self.password_hash = generate_password_hash(password) 
    #    self.major = major
    #    self.gender = gender
    #    self.single = single

    #def is_authenticated(self):
    #    return True
 
    #def is_active(self):
    #    return True
 
    #def is_anonymous(self):
    #    return False
 
    #def get_id(self):
    #    return unicode(self.id)
 
    #def __repr__(self):
    #    return '<User %r>' % (self.username)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    info = db.Column(db.PickleType)
    
    status = db.Column(db.Integer)
    
    pic1 = db.Column(db.Text)
    pic2 = db.Column(db.Text)
    pic3 = db.Column(db.Text)

    des1 = db.Column(db.Text)
    des2 = db.Column(db.Text)
    des3 = db.Column(db.Text)

    def __init__(self, user_id, pic1, des1, pic2, des2, pic3, des3):
        self.user_id = user_id
        self.status = 0 #normal status
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
    group1_id = db.Column(db.Integer, db.ForeignKey('group.id'), index=True)
    group2_id = db.Column(db.Integer, db.ForeignKey('group.id'), index=True)
    message = db.Column(db.Text)
    status = db.Column(db.Integer) #0 for initial, 1 for success
    info = db.Column(db.PickleType)


    def __init__(self, group1_id, group2_id, message):
        self.group1_id = group1_id
        self.group2_id = group2_id
        self.message = message
        self.status = 0

    def __repr__(self):
        return '<Meeting between %d and %d with message %s>' % (self.group1_id, self.group2_id, self.message)




#
# Customize forms
#

class ExtendedConfirmRegisterForm(ConfirmRegisterForm):    
    nickname = TextField('昵称', [Required()])
    major = TextField('专业年级', [Required()])
    gender = RadioField('gender', choices=[('0', '男'), ('1', '女')])
    
    
# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, confirm_register_form = ExtendedConfirmRegisterForm)

@security.login_context_processor
def security_login_processor():
    return dict( register_user_form=ExtendedConfirmRegisterForm() )

#Setup Mail
mail = Mail(app)

def debug_log(text):
    print text
    return ''

def get_time():
    return str(datetime.datetime.now().replace(microsecond=0))

def make_message(user, message):
    if message == None:
        message = ''
    return u'%s 说："%s"。 于%s。 \n\n' % ( user.nickname, message, get_time())

    

#@login_manager.user_loader
#def load_user(id):
#    return User.query.get(int(id))


@app.route('/register', methods=['POST'])
def register():
    user = User(request.form['nickname'], request.form['email'], request.form['password'], 
                request.form['major'], request.form['gender'])
    db.session.add(user)
    db.session.commit()

    flash("You are in.")
    return redirect(url_for('signin'))


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'GET':
        return render_template('signin.html', user=None) #TODO: consider if needed

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


@app.route('/signout')
@login_required
def signout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/getgroup/<int:group_id>', methods=['GET', 'POST'])
@login_required
def get_group(group_id):
    group = Group.query.filter_by(id=group_id).first()

    uri_pic1 = app.config['IMAGE_PATH'] + group.pic1
    uri_pic2 = app.config['IMAGE_PATH'] + group.pic2
    uri_pic3 = app.config['IMAGE_PATH'] + group.pic3

    uri_pics = [uri_pic1, uri_pic2, uri_pic3]
    dess = [des1, des2, des3]

    if group: #on success
        return render_template('group.html', pics = uri_pics, dess = dess) #TODO: pass the parameters for group page.

    return redirect(url_for('index'))


def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ['jpg', 'jpeg', 'png', 'bmp', 'gif']

@app.route('/addgroup', methods=['POST'])
@login_required
def add_or_update_group():
    user = current_user

    print request.files

    uploaded_files = [request.files['pic1'], request.files['pic2'], request.files['pic3']]
    print 'ok'
    dess = [request.form['des1'], request.form['des2'], request.form['des3']] #TODO: examine if 3 descriptions actually
    print 'ok'
    dess = [des if des else '' for des in dess]
    filenames = []


    #TODO: WTForms and form validation are needed.

    counter = 0

    for f in uploaded_files:
        if len(f.filename) and allowed_file(f.filename):
            filename = secure_filename(f.filename) #filename is secured here
            #it should be an image now
            f.save(os.path.join(app.config['IMAGE_PATH'], filename))
            filenames.append(filename)
            counter += 1
        else:
            filenames.append('')
    
    if counter > 3 or counter < 1:
        return redirect(url_for('index'), error = 'Upload fails.' ) #TODO: handle error

    #save the group into db
    if user.groups.count() == 0:
        group = Group(user.id, filenames[0], dess[0], filenames[1], dess[1], filenames[2], dess[2])
        db.session.add(group)
        db.session.commit()
    else:
        #User is already in group
        group = user.groups.first() #consider only first one
        (group.pic1, group.pic2, group.pic3) = tuple(filenames) # filenames should have no more than 3 elements
        (group.des1, group.des2, group.des3) = tuple(dess) # dess should have no more than 3 elements
        db.session.add(group)
        db.session.commit()

    flash('Upload finished.')
    print 'Upload finished.' #debug

    return redirect(url_for('index'))


@app.route('/requestmeeting/<int:group_id>', methods=['GET', 'POST'])
@login_required
def request_meeting(group_id):
    user = current_user
    group1 = user.groups.first() #assuming user's main group is the first one

    if (group1 is None): #no group for this user. need to add group.
        return redirect(url_for('index', group_id=group_id)) #TODO: add error info
        
    group2 = Group.query.filter_by(id=group_id).first()

    if (group2 is None or group1.id == group2.id): #can't invite None or himself
        return redirect(url_for('index', group_id=group_id))

    if find_meeting(group1.id, group2.id) is not None: #no duplicate
        return redirect(url_for('index', group_id=group_id))

    message = request.form['message'] 
    if message and len(message):
        message = make_message(user, message)

    meeting = Meeting(group1_id=group1.id, group2_id=group2.id, message=message)

    db.session.add(meeting)
    db.session.commit()

    return redirect(url_for('index', group_id=group_id))

def find_meeting(group1_id, group2_id):
    meetings = Meeting.query.filter_by(group1_id=group1_id) #to take advantage of the index on group1_id
    for meeting in meetings:
        if meeting.group2_id == group2_id:
            return meeting
    return None


    


@app.route('/modifymeeting/<int:group_id>', methods=['GET', 'POST'])
@login_required
def modify_meeting(group_id):
    user = current_user
    user_group = user.groups.first() #assuming user has only one group

    #consider both directions
    meeting = find_meeting(user_group.id, group_id) or find_meeting(group_id, user_group.id)

    if request.method == 'POST':
        action = request.form['action']
    else:
        action = request.args.get('action')

    if meeting and action:
        if action == 'accept':
            if user_group.id == meeting.group2_id: #should be the target group
                meeting.status = 1 #for success

        if action == 'addmessage':
            message = request.form['message']
            meeting.message += make_message(user, message)
        db.session.commit()

    print 'status: ', Meeting.query.first().status
    return redirect(url_for('index', group_id=group_id))



@app.route('/invitations')
@login_required
def invitations():
    user = current_user
    
    groups = user.groups
    #check every group belongs to current_user
    meetings_in = []
    meetings_out = []
    for group in groups:
        #requests that sent out from THE group
        meetings_out.append(Meeting.query.filter_by(group1_id=group.id))
        #requests that received from other group
        meetings_in.append(Meeting.query.filter_by(group2_id=group.id))

    return render_template('invitations.html',user=user, groups=groups, 
                            meetings_in=meetings_in, meetings_out=meetings_out)
        


@app.route('/getmodal')
@login_required
def get_modal():
    meeting_id = request.args.get('meeting_id')
    message = None
    print meeting_id #debug
    if meeting_id:
        meeting = Meeting.query.filter_by(id=meeting_id).first()
        if meeting:
            message = meeting.message
        
    target = request.args.get('target')
    return render_template('modal.html', message=message, target=target)
    
'''
@app.route('/static/<path:path>')
def static(path):
    # send_static_file will guess the correct MIME type
    return app.send_static_file(os.path.join('static', path))
'''


@app.route('/<int:group_id>')
@app.route('/')
def index(group_id = None):
    if not current_user or not current_user.is_authenticated():
        return redirect(url_for_security('login'))
    #user has signed in
    user = current_user
    user_group = user.groups.first() #assuming user has only one group
    
    #TODO: add more  stuffs here

    if group_id:
        groups = Group.query.filter_by(id=group_id).all()
    else:
        #no group_id
        gender = request.args.get('gender')
        if gender is None:
            groups = Group.query.all()
        else:
            #gender is not None and group_id is None (default)
            gender = 0 if gender == 'boys' else 1
            groups = Group.query.filter_by(gender=gender).all()

    #if user_group:
    #    meetings = get_all_meetings(user_group.id)
    #else:
    #    meeting = None


    return render_template('index.html', groups = groups, index_group_id = group_id, 
                            find_meeting=find_meeting, user_group=user_group,
                            user=user,
                            img_path = app.config['IMAGE_PATH'])



        

if __name__ == '__main__':
    app.run("0.0.0.0", debug=True)




        

