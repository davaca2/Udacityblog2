import os, re, random, string, datetime, json, time
import webapp2
import jinja2
import logging
from DatabaseObject import *
from google.appengine.ext import db
from google.appengine.api import memcache
import hmac, hashlib

SECRET = "banaan, baby"


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),\
                                autoescape = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.write(*a, **kw)

	def render_Str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_Str(template, **kw))

class FrontPageHandler(Handler):
	def get(self, js=None):
		posts, cache_time = self.getPosts()
		if js:
			self.response.headers['Content-Type'] = 'application/json'
			#json needs content and subject
			returnedJson = []
			for post in posts:
				content = post.content
				subject = post.subject
				toAppend = {"content":     content, "subject": subject}
				returnedJson.append(toAppend)

			returned = json.dumps(returnedJson)
				
			self.response.write(returned)
		else:
			cache_time = time.time() - cache_time
			self.render('main.html', blogposts = posts, cache_time = cache_time)

	def getPosts(self, update = False):
		key = 'top'
		timekey = 'top_time'
		topposts = memcache.get(key)
		cache_time = memcache.get(timekey)

		if topposts == None or update or cache_time == None:
			topposts = db.GqlQuery("select * from BlogPost order by createdtime desc")
			topposts = list(topposts)
			cache_time = time.time()
			memcache.set(key, topposts)
			memcache.set(timekey,cache_time)
		return topposts, cache_time


class SignupHandler(Handler):
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	PW_RE = re.compile(r"^.{3,20}$")
   	EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

	def get(self):
		self.render('signup.html')

	def post(self):
		foundError = False
		name = self.request.get('username')
		pw = self.request.get('password')
		confirm = self.request.get('verify')
		email = self.request.get('email')

		if name and self.valid_username(name):
			user = db.GqlQuery("select * from User where username='" + name + "'").get()
			if user:
				foundError = True
				nameError = "This name already exists"
			else:
				nameError = ""
		else: 
			logging.info(self.valid_username(name))
			user = None
			foundError = True
			nameError = "Put in a name"

		if pw == confirm:
			confirmError = ""
			if self.valid_password(pw): #is this a possible password
				if user:
					if self.valid_pw(name, pw, user.passwordhash): #is the password right?
						pwValidError = ""
					else:
						foundError = True
						pwValidError = "this password is wrong"
				else:
					pwValidError=""
					pwhash = self.make_pw_hash(name, pw)

			else:
				foundError = True
				pwValidError = "invalid password"
		else:
			foundError = True
			pwValidError = ""
			confirmError = "confirmation wasn't the same as password"

		if email: 
			if self.valid_email(email):
				emailError = ""
			else:
				foundError = True
				emailError = "invalid email"
		else:
			email = ""
			emailError = ""

		if foundError:
			self.render('signup.html', name= name, email=email, nameError = nameError, confirmError = confirmError,\
			 pwValidError= pwValidError, emailError=emailError)
		else:
			#self.render('signup.html')
			user = User(username= name, passwordhash = pwhash, email=email)
			user.put()
			namehash = hashlib.sha256(name).hexdigest()
			cookievalue = "name=" + str(name) + '|' + str(namehash)
			self.response.headers.add_header('Set-Cookie', cookievalue)
			self.redirect('/welcome')
			

	def make_salt(self):
		return ''.join(random.choice(string.letters) for x in xrange(5))

	def make_pw_hash(self, name, pw, salt=None):
		if not salt:
			salt = self.make_salt()
		h = hashlib.sha256(name + pw + salt).hexdigest()
		return '%s,%s' % (h, salt)

	def valid_pw(self, name, pw, h):
		salt = h.split(',')[1]
		logging.info("the salt: " + salt)
		return h == self.make_pw_hash(name, pw, salt)

	def valid_username(self, username):
		logging.info('username in valid_username: ' + username)
		return self.USER_RE.match(username)

	def valid_password(self, password):
	    return self.PW_RE.match(password)

	def valid_email(self, email):
	   	return self.EMAIL_RE.match(email)

class WelcomeHandler(Handler):
	def get(self):
		cookievalue = self.request.cookies.get("name", None)
		cookievalue = cookievalue.split('|')
		name = cookievalue[0]
		namehash = cookievalue[1]
		if namehash == hashlib.sha256(name).hexdigest():
			self.render('welcome.html', username=name)
		else:
			self.redirect('/signup')

class LoginHandler(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		user = db.GqlQuery("select * from User where username='" + username + "'").get()

		error = ''

		if not user:
			self.render('login.html',error ='invalid login')
		else:
			databaseHash = user.passwordhash
			if not self.valid_pw(username, password, databaseHash):
				self.render('login.html',error ='invalid login')
			else: #correct password
				namehash = hashlib.sha256(username).hexdigest()
				cookievalue = "name=" + str(username) + '|' + str(namehash)
				self.response.headers.add_header('Set-Cookie', cookievalue)
				self.redirect('/welcome')

	def make_salt(self):
		return ''.join(random.choice(string.letters) for x in xrange(5))

	def make_pw_hash(self, name, pw, salt=None):
		if not salt:
			salt = self.make_salt()
		h = hashlib.sha256(name + pw + salt).hexdigest()
		return '%s,%s' % (h, salt)

	def valid_pw(self, name, pw, h):
		salt = h.split(',')[1]
		logging.info("the salt: " + salt)
		return h == self.make_pw_hash(name, pw, salt)

class LogoutHandler(Handler):
	def get(self):
		#cookievalue = str(self.request.cookies.get("name", None))  + "name=deletes; Expires=Thu, 01-Jan-1970 00:00:00 GMT"
		
		self.response.headers.add_header('Set-Cookie', "name=; Path=/")
		self.redirect('signup')



class NewpostHandler(Handler):
	def get(self):
		self.render('newpost.html')

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			bp = BlogPost(subject = subject, content= content)
			bp.put()

			bp_id = bp.key().id()

			self.redirect('/blogpost/' + str(bp_id))
		else:
			self.render('newpost.html', subject = subject, content=content)


class ViewPostHandler(Handler):
	def get(self, post_id):
		key = 'single' + post_id
		timekey = 'time' + post_id
		cachepost = memcache.get(key)
		cachetime = memcache.get(timekey)
		if not cachepost or not cachetime:
			cachepost = BlogPost.get_by_id(int(post_id))
			memcache.set(key, cachepost)
			cachetime = time.time()
			memcache.set(timekey, cachetime)

		queriedtime = time.time() - cachetime

		self.render('viewpost.html', bp=cachepost, time = queriedtime)

class JsonSinglePostHandler(Handler):
	def get(self, post_id, js):
		logging.info('-------------------------------------------------------------------------------')
		self.response.headers['Content-Type'] = 'application/json'
		bp = BlogPost.get_by_id(int(post_id))
		theString = '[{"content": "'  +  str(bp.content) + '", "subject": "' + str(bp.subject) + '"}]'
		#logging.info('-------------------------------------------------------------------------------')
		#logging.info(theString)
		jsonToReturn = json.dumps([{"content": bp.content, "subject": bp.subject}])

		#jsonToReturn = json.loads(theString)

		self.response.write(jsonToReturn)

class FlushHandler(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect('/')