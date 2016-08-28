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
import webapp2
import cgi
import re

def escape_html(s):
    return cgi.escape(s, quote = True)


rot13_form = """<!DOCTYPE html><title>Rot 13 Encoder</title><h2>Enter some text to ROT13:</h2><form method=post><label><textarea name=text style=height:100px;width:400px type=text>%(new_text)s</textarea></label><br><input type=submit></form>"""


def encoder_rot13(plaintext):
    cyphertext = plaintext.encode('rot13')
    return cyphertext


class MainHandler(webapp2.RequestHandler):

    def write_html(self, new_text=""):
        self.response.write(rot13_form % {"new_text":escape_html(new_text)})

    def get(self):
        self.write_html()

    def post(self):
        user_text = self.request.get('text')
        cypher_text = encoder_rot13(user_text)
        self.write_html(cypher_text)


signup_form="""<!DOCTYPE html><title>Just Sign Up</title><style>.label{text-align:right}.error{color:red}</style><h2>Sign Up</h2><form method=post><table><tr><td class=label>Usename:<td><input name=username value=%(username)s><td class=error>%(username_error)s<tr><td class=label>Password:<td><input name=password type=password value=%(password)s><td class=error>%(password_error)s<tr><td class=label>Verify Password:<td><input name=verify type=password><td class=error>%(password_mismatch_error)s<tr><td class=label>Email (optional):<td><input name=email type=email value=%(email)s><td class=error>%(email_error)s</table><input type=submit></form>"""


def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    if username:
        return USER_RE.match(username)

def validate_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    if password:
        return PASSWORD_RE.match(password)

def match_password(arg1, arg2):
    if arg1 == arg2:
        return True

def validate_email(email):
    EMAIL_RE= re.compile(r"^[\S]+@[\S]+.[\S]+$")
    if email == "":
        return True
    else:
        return EMAIL_RE.match(email)

class SignupHandler(webapp2.RequestHandler):
    def write_signup_form(self, username="", password="", email="", username_error="", password_error="", password_mismatch_error="", email_error=""):
        return self.response.write(signup_form % {"username": escape_html(username),
                                                  "email": escape_html(email),
                                                  "password": escape_html(password),
                                                  "username_error": escape_html(username_error),
                                                  "password_error": escape_html(password_error),
                                                  "password_mismatch_error": escape_html(password_mismatch_error),
                                                  "email_error": escape_html(email_error)})


    def get(self):
        self.write_signup_form()

    def post(self):

        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify_password = self.request.get('verify')
        user_email = self.request.get('email')

        valid_username = validate_username(user_username)
        valid_password = validate_password(user_password)
        matched_password = match_password(user_password, user_verify_password)
        valid_email = validate_email(user_email)

        username_error = ""
        password_error = ""
        password_mismatch_error = ""
        email_error = ""
        empty_password=""

        if not valid_username:
            username_error = 'except - and _ special chars are not supported'
        if not valid_password:
            password_error = 'min 3 - max 20 chars'
        if not matched_password:
            password_mismatch_error = 'password does not match'
        if not valid_email:
            email_error = 'That email doesn\'t look valid to us.'

        if valid_username and valid_password and matched_password and valid_email:
            self.redirect('/welcome?user=%s' % user_username)
        else:
            self.write_signup_form(user_username, user_email, empty_password, username_error,
                                        password_error, password_mismatch_error, email_error    )

welcome_html ="""<!DOCTYPE html><title> Welcome %(user)s</title><h2>Welcome, %(user)s!</h2>"""

class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        user = self.request.get('user')
        self.response.write(welcome_html % {"user":user})


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
