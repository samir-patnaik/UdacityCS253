#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = 'n&Vr=KH)/r85[MdaK&w{E2P!]CQfy~Ky^+k3.=/j>Yq$32YqX#v.?/\zVW>Mer>V'

# Render Helper
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# ======= HASHING STUFF ==
import hmac

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest()) # cookie tip: no whitespace between strings

def check_secure_val(secure_val):
    val = secure_val.split('|')[0];
    if secure_val == make_secure_val(val):
        return val

# ======= MAIN TEMPLATE HANDLER ==
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Cookie Helper Functions
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Login/Logout Helper Functions
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')

    # Initialize Response by inspecting Cookies
    def initialize(self, *a, **kw):
        '''initialize() is called by appengine framework implicitly
           before a response is sent out everytime. Here we are checking
           if the user is logged in or not.'''
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        if self.user:
            self.response.write('<br>motherfucker!')
            self.response.write(self.user.name)


# ======= FRONT PAGE COOKIE STUFF ==

class MainPage(BlogHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_val = self.request.cookies.get('visits')
        if visit_cookie_val:
            cookie_val = check_secure_val(visit_cookie_val)
            if cookie_val:
                visits = int(cookie_val)


        visits += 1
        print visits
        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)

        if visits > 100 and visits < 105:
            self.write("You are the best ever!")
        else:
            self.write("You've been here %s times!" % visits)


# ======= BLOG STUFF ==

# Blog Helper Function
def render_post(response, post):
    ''' HTML Formatting for the blog post data
        retrieved from the DB '''
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# == Post Database Model Class ==
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>') #replaces new lines in the form with <br>
        return render_str("post.html", p = self)

# Blog Front Page Handler
class BlogFront(BlogHandler):
    def get(self):

        ''' Render 10 latest posts from Google Datastore'''

        posts = Post.all().order('-created')
        self.render("front.html", posts = posts)

# Blog Post Permalink Handler
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject = subject, content = content, error = error)


# ======= USER STUFF ==

import re

# Validate User Data Helper Functions
def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)

def validate_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return password and PASSWORD_RE.match(password)

def validate_email(email):
    EMAIL_RE= re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return not email or EMAIL_RE.match(email)

# User Security Helper Functions
import random
import hashlib
from string import letters

def make_salt(length = 5):
    '''In cryptography, a salt is random data
        that is used as an additional input to
        a one-way function that "hashes" a password
        or passphrase.

       - random.choice(letters) picks one character from
         string.letters i.e, from [a-z] and [A-Z].
       - for x in range(length) loop runs 'length' times and creates a list,
         'length' characters long.
       - ''.join() joins all characters within a '' to create
         one single string.

         For e.g.,
            ['x','L','q','Y','z'] -> xLqYz'''

    return ''.join(random.choice(letters) for x in range(length))

# Password Hashing Helper Functions
def make_password_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def validate_password_hash(name, password, h):
    salt = h.split(',')[0]
    return h == make_password_hash(name, password, salt)

# == User Database Model Class ==
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, password, email = None):
        password_hash = make_password_hash(name, password)
        return User(parent = users_key(),
                    name = name,
                    password_hash = password_hash,
                    email = email)
    @classmethod
    def login(cls, name, password):
        u = cls.by_name(name)
        if u and validate_password_hash(name, password, u.password_hash):
            return u

# == Sign Up Handler Class ==
class Signup(BlogHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
    # == Form Submission and Validation ==

        # Retrieve User Data
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # Validate Data
        params = dict(username = self.username,
                      email = self.email)

        if not validate_username(self.username):
            params['username_ERR'] = 'Sorry. We don\'t allow special characters barring _ (underscore) and - (hyphen)'
            have_error = True

        if not validate_password(self.password):
            params['password_ERR'] = '8-30 characters needed'
            have_error = True
        elif self.password != self.verify:
            params['password_match_ERR'] = 'passwords don\'t match'
            have_error = True

        if not validate_email(self.email):
            params['email_ERR'] = 'That email don\'t look valid to me'
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    # Raise Error
    def done(self, *a, **kw):
        raise NotImplementedError

# == Register User Handler ==
class Register(Signup):
    def done(self):
        # Duplicate User Error Check
        u = User.by_name(self.username)
        if u:
            message = 'Username not available.'
            self.render('signup.html', username_ERR = message)
        # Register New User
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

# == Login User Handler ==
class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            message = 'Invalid Login Credentials'
            self.render('login.html', error = message)

# == Logout User Handler ==
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/thanks')

# ======= WELCOME ==
class ThanksPage(BlogHandler):
    def get(self):
        if self.user:
            self.render('thanks.html', username = self.user.name)
        else:
            self.write("You are not logged in anynore but, Thanks for coming here!")



# ======= MAIN APP ROUTING ==
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/?', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/signup', Register),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/thanks', ThanksPage),
], debug=True)
