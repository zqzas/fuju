import sys, os
path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(path)

from app import app as application

activate_this = '/srv/www/fudanke.com/public_html/fuju/fuju/vir/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))


