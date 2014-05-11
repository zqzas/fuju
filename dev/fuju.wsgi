import sys, os
path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(path)

from app import app as application


print application
