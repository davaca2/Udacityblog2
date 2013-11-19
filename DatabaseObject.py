from google.appengine.ext import db


class BlogPost(db.Model):
  subject = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  createdtime = db.DateTimeProperty(auto_now_add = True) 

class User(db.Model):
	username = db.StringProperty(required = True)
	passwordhash = db.StringProperty(required = True)
	email = db.StringProperty()

