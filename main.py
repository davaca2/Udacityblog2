import webapp2
import jinja2
import os
import Handlers

application = webapp2.WSGIApplication([
	('/(.json)', Handlers.FrontPageHandler),
	('/', Handlers.FrontPageHandler),
	('/signup', Handlers.SignupHandler),
	('/newpost', Handlers.NewpostHandler),
	('/blogpost/([0-9]+)(.json)', Handlers.JsonSinglePostHandler),
	('/blogpost/([0-9]+)', Handlers.ViewPostHandler),
	('/welcome', Handlers.WelcomeHandler),
	('/login', Handlers.LoginHandler),
	('/logout', Handlers.LogoutHandler),
	('/flush', Handlers.FlushHandler)
	], debug = True)