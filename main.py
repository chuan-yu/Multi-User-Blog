import webapp2
import os
import string
import random
import re
import hmac
import logging
import time
import jinja2
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                                autoescape=True)
MAIN_URL ='/'
SIGNUP_URL = '/signup'
LOGIN_URL = '/login'
LOGOUT_URL = '/logout'
WELCOME_PAGE_URL = '/welcome'
NEW_POST_URL = '/newpost'
SINGLE_POST_URL_HEAD = '/post'
SINGLE_POST_URL = SINGLE_POST_URL_HEAD + '/[0-9]+'
EDIT_POST_URL_HEAD = '/post/edit'
EDIT_POST_URL = EDIT_POST_URL_HEAD + '/[0-9]+'
EDIT_ERROR_URL = '/edit/error'
LIKE_URL_HEAD = '/like'
LIKE_URL = LIKE_URL_HEAD + '/[0-9]+'
LIKE_ERROR_URL = '/like/error'
NEW_COMMENT_URL_HEAD = '/newcomment'
NEW_COMMENT_URL = NEW_COMMENT_URL_HEAD + '/[0-9]+'
EDIT_COMMENT_URL_HEAD = '/editcomment'
EDIT_COMMENT_URL = EDIT_COMMENT_URL_HEAD + '/[0-9]+'

SECRET = 'l7"aXoV01o6A$#_B?8<@,13gF.#|S%'

# Fetch entity using key_name and store entity as attribute attr_name
# Example:
# prefetch(posts, author_key, author)
# For each post in posts, a query is made using author_key and the result
# is stored as an attribute name author of each post, i.e. post.author
def prefetch(entities, key_name, attr_name):
    # Asyncronously get author for each post
    for e in entities:
        if getattr(e, key_name):
           setattr(e, attr_name, getattr(e, key_name).get_async())

    # Replace Future objects with the real author
    for e in entities:
        if getattr(e, attr_name):
            setattr(e, attr_name, getattr(e, attr_name).get_result())

    return entities

# A generic handler that other handlers inherit.
# It includes functions used for rendering jinja template
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        # Make these parameters available on all templates
        params['user'] = self.user
        params['login_url'] = LOGIN_URL
        params['signup_url'] = SIGNUP_URL
        params['new_post_url'] = NEW_POST_URL
        params['logout_url'] = LOGOUT_URL
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookies(self, name, value):
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, value))

    # Get the secure user_id from Cookies.
    # If it is valid, return the normal user_id. Else return None
    def read_user_id(self):
        secure_user_id = self.request.cookies.get('user_id')
        if secure_user_id:
            if validate_cookie_user_id(secure_user_id):
                user_id = secure_user_id.split('|')[0]
            else:
                user_id = None
        else:
            user_id = None
        return user_id

    # Get integer after the last '/' in url as the post_id
    def get_id_from_url(self):
        url = self.request.url
        post_id = url.rsplit('/', 1)[-1]
        return post_id

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_user_id()
        if user_id:
            self.user = User.get_by_id(int(user_id))
        else:
            self.user = None



# Blog Part

# Create blog Post database entity model
class Post(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author_key = ndb.KeyProperty(kind='User', required=True)
    likes = ndb.IntegerProperty(default=0)
    liked_by = ndb.KeyProperty(kind='User', repeated=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)

    @staticmethod
    def prefetch_authors(posts):
        # Asyncronously get author for each post
        for post in posts:
            if post.author_key:
                post.author = post.author_key.get_async()

        # Replace Future objects with the real author
        for post in posts:
            if post.author:
                post.author = post.author.get_result()

        return posts

# Create post Comment database entity model
class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    post_key = ndb.KeyProperty(kind='Post', required=True)
    user_key = ndb.KeyProperty(kind='User', required=True)
    updated = ndb.DateTimeProperty(auto_now=True)

class MainPage(Handler):
    def get(self):
        posts = Post.query().order(-Post.created).fetch()
        posts = prefetch(posts, 'author_key', 'author')
        user = self.user
        self.render("blog.html", posts=posts,
                    single_post_url_head=SINGLE_POST_URL_HEAD,
                    logout_url=LOGOUT_URL,
                    edit_post_url_head=EDIT_POST_URL_HEAD,
                    like_url_head=LIKE_URL_HEAD,
                    new_comment_url_head=NEW_COMMENT_URL_HEAD)

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("post_form.html", heading="New Post")
        else:
            self.redirect(LOGIN_URL)

    def post(self):
        if not self.user:
            self.redirect(LOGIN_URL)
            return

        POST_FORM_ERROR_MESSAGE = "subject and content please"
        subject = self.request.get('subject')
        content = self.request.get('content')
        if not subject or not content:
            self.render("post_form.html",
                        heading="New Post",
                        error=POST_FORM_ERROR_MESSAGE)
        else:
            post = Post(subject=subject, content=content, author_key=self.user.key)
            post_key = post.put()
            self.redirect("/%s" % post_key.id())

class SinglePostPage(Handler):
    def get(self):
        # Get post_id from url
        post_id = self.get_id_from_url()
        # query post by id
        post = Post.get_by_id(int(post_id))
        comments = Comment.query(Comment.post_key==post.key).fetch()
        comments = prefetch(comments, 'user_key', 'user')
        current_user_key = None
        if self.user:
            current_user_key = self.user.key
        if not post:
            self.error(404)
            return
        else:
            self.render("post.html", post=post,
                        edit_post_url_head=EDIT_POST_URL_HEAD,
                        comments=comments, current_user_key=current_user_key,
                        edit_comment_url_head=EDIT_COMMENT_URL_HEAD)

class EditPost(Handler):
    def get(self):
        logging.info(self.user)
        # Check if user is logged in
        if not self.user:
            self.redirect(LOGIN_URL)
            return
        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id))
        if not post:
            self.error(404)
            return
        if post.author_key != self.user.key:
            self.redirect(EDIT_ERROR_URL)
        else:
            subject = post.subject
            logging.info('subject=' + subject)
            content = post.content
            self.render("post_form.html",
                        heading="Edit Post",
                        subject=subject,
                        content=content)

    def post(self):
        # check if user is logged in
        if not self.user:
            self.redirect(LOGIN_URL)
            return

        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id))
        # Get the subject and content on the Edit Form
        new_subject = self.request.get('subject')
        new_content = self.request.get('content')
        POST_FORM_ERROR_MESSAGE = "subject and content please"
        if not new_subject or not new_content:
            self.render("post_form.html",
                        heading="Edit Post",
                        subject=new_subject,
                        content=new_content,
                        error=POST_FORM_ERROR_MESSAGE)
            return
        # Track whether subject or content is updated
        updated = False
        if post.subject != new_subject:
            post.subject = new_subject
            updated = True
        if post.content != new_content:
            post.content = new_content
            updated = True
        # Only update database if either subject or content is updated
        if updated:
            post.put()
        self.redirect(SINGLE_POST_URL_HEAD + '/' + post_id)

class EditPostError(Handler):
    def get(self):
        EDIT_ERROR_MESSEAGE = "Sorry. You don't have the permission to edit the post"
        self.render("error.html", error_message=EDIT_ERROR_MESSEAGE, homepage_url=MAIN_URL)

class LikePost(Handler):
    def get(self):
        # check if logged in
        if not self.user:
            self.redirect(LOGIN_URL)
            return

        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id))
        if not post:
            error(404)
            return

        if self.user.key in post.liked_by:
            # If user already liked it, unlike
            self.unlike(post)
            # Wait for database likes to be updated before redirect
            time.sleep(0.5)
            self.redirect(MAIN_URL)
        else:
            # If it is user's own post, redirect to error page
            if post.author_key == self.user.key:
                self.redirect(LIKE_ERROR_URL)
            else:
                self.like(post)
                # Wait for database likes to be updated before redirect
                time.sleep(0.5)
                self.redirect(MAIN_URL)

    def unlike(self, post):
        # Remove the current user key from the liked_by list
        post.liked_by.remove(self.user.key)
        # Reduce likes by 1
        post.likes -= 1
        post.put()

    def like(self, post):
        # Add current user key to the liked_by list
        post.liked_by.append(self.user.key)
        # Increase likes by 1
        post.likes += 1
        post.put()

class LikeError(Handler):
    def get(self):
        LIKE_ERROR_MESSAGE = "You can't like your own post"
        self.render("error.html", error_message=LIKE_ERROR_MESSAGE, homepage_url=MAIN_URL)

class CommentPost(Handler):
    def get(self):
        # check if logged in
        if not self.user:
            self.redirect(LOGIN_URL)
            return
        self.render("comment.html")

    def post(self):
        # check if logged in
        if not self.user:
            self.redirect(LOGIN_URL)
            return

        # Query the post. If not found, redirect to the error page
        post_id = self.get_id_from_url()
        post = Post.get_by_id(int(post_id))
        if not post:
            COMMENT_POST_NOT_FOUND_MESSAGE = "No post was found"
            self.render("error.html", error=COMMENT_POST_NOT_FOUND_MESSAGE, homepage_url=MAIN_URL)
            return

        content = self.request.get('content')
        if not content:
            COMMENT_FORM_ERROR_MESSAGE = "Comments must not be blank"
            self.render("comment.html", error=COMMENT_FORM_ERROR_MESSAGE)
        else:
            comment = Comment(content=content, post_key=post.key, user_key=self.user.key)
            comment.put()
            self.redirect(SINGLE_POST_URL_HEAD + '/' + str(post.key.id()))

class EditComment(Handler):
    def get(self):
        if not self.user:
            self.redirect(LOGIN_URL)
            return
        comment_id = self.get_id_from_url()
        comment = Comment.get_by_id(int(comment_id))
        # Check if user is editing his own comment
        if comment:
            if comment.user_key != self.user.key:
                COMMENT_ERROR_MESSAGE = "You can only edit your own comment"
                self.render("error.html", error_message=COMMENT_ERROR_MESSAGE,
                            homepage_url=MAIN_URL)
                return
            content = comment.content
            self.render("comment.html", content=content)
        else:
            self.render("error.html", error_message="Comment not found",
                        homepage_url=MAIN_URL)

    def post(self):
        if not self.user:
            self.redirect(LOGIN_URL)

        comment_id = self.get_id_from_url()
        comment = Comment.get_by_id(int(comment_id))
        new_content = self.request.get('content')
        # Check whether there is any changes to the comment content
        updated = False
        if new_content != comment.content:
            updated = True
            comment.content = new_content
        # Write to database only when there are changes to the content
        if updated:
            comment.put()
        self.redirect(SINGLE_POST_URL_HEAD + '/' + str(comment.post_key.id()) )

# User Part

# helper functions for User part

def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

def validate_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password)

def compare_passwords(password, verify):
    if password:
        if password == verify:
            return True
        else:
            return False
    else:
        return False

def validate_email(email):
    if email:
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return EMAIL_RE.match(email)
    else:
        return True

def make_salt():
    return ''.join((random.choice(string.letters)) for i in range(5))

def make_secure_pw(username, password, salt=make_salt()):
    hash_value = hmac.new(SECRET, username + password + salt).hexdigest()
    return "%s,%s" % (hash_value, salt)

def make_secure_cookie_user_id(user_id):
    hash_value = hmac.new(SECRET, str(user_id)).hexdigest()
    return "%s|%s" % (user_id, hash_value)

def validate_cookie_user_id(secure_user_id):
    split_value = secure_user_id.split("|")
    if len(split_value) != 2:
        return False
    user_id = split_value[0]
    if hmac.new(SECRET, user_id).hexdigest() == split_value[1]:
        return True
    else:
        return False

# Create User database entity model
class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)

class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        USERNAME_ERROR_MESSAGE = "That's not a valid username"
        VERIFY_ERROR_MESSAGE = "Your passwords didn't match"
        PASSWORD_ERROR_MESSAGE = "That's not a valid password"
        EMAIL_ERROR_MESSAGE = "That's not a valid email"

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        # validate signup form inputs.
        # If OK, register user. Else, reload form with error message(s)
        if (validate_username(username)
            and validate_password(password)
            and compare_passwords(password, verify)
            and validate_email(email)):
            self.register(username, password, email)
        else:
            if not validate_username(username):
                username_error = USERNAME_ERROR_MESSAGE

            if not validate_password(password):
                password_error = PASSWORD_ERROR_MESSAGE
            elif not compare_passwords(password, verify):
                verify_error = VERIFY_ERROR_MESSAGE

            if not validate_email(email):
                email_error = EMAIL_ERROR_MESSAGE

            self.render("signup.html", username = username,
                username_error = username_error,
                password_error = password_error,
                verify_error = verify_error,
                email_error = email_error)

    def register(self, username, password, email):
        user = User.query(User.username == username).get()
        if user:
            self.render("signup.html", username_error = "That user already exists")
            return
        # Only stored the hashed password in the DB
        secure_password = make_secure_pw(username, password)
        user = User(username=username, password=secure_password, email=email)
        user_key = user.put()
        user_id = user_key.id()
        secure_user_id = make_secure_cookie_user_id(str(user_id))
        self.set_cookies('user_id', secure_user_id)
        self.redirect(WELCOME_PAGE_URL)


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        LOGIN_ERROR = "Invalid Login"
        LOGIN_FORM_ERROR = "username and password must not be empty"

        username = self.request.get('username')
        password = self.request.get('password')

        if username and password:
            user = User.query(User.username==username).get()
            if user:
                password_db = user.password
                if Login.check_password(username, password, password_db):
                    secure_user_id = make_secure_cookie_user_id(user.key.id())
                    self.set_cookies('user_id', secure_user_id)
                    self.redirect(WELCOME_PAGE_URL)
                else:
                    self.render("login.html", username=username, login_error=LOGIN_ERROR)
            else:
                self.render("login.html", username=username, login_error=LOGIN_ERROR)
        else:
            self.render("login.html", username=username, login_error=LOGIN_FORM_ERROR)

    @staticmethod
    def check_password(username, password, password_db):
        split_value = password_db.split(',')
        salt = split_value[1]
        secure_password = make_secure_pw(username, password, salt)
        if secure_password == password_db:
            return True
        else:
            return False

class Logout(Handler):
    def get(self):
        self.set_cookies('user_id', '')
        self.redirect(MAIN_URL)

class WelcomePage(Handler):
    def get(self):
        user_id = self.read_user_id()
        if user_id:
            username = User.get_by_id(int(user_id)).username
            if username:
                self.render("Welcome.html", username=username, homepage_url=MAIN_URL)
            else:
                self.redirect(SIGNUP_URL)
        else:
            self.redirect(SIGNUP_URL)


app = webapp2.WSGIApplication([
    (MAIN_URL, MainPage),
    (NEW_POST_URL, NewPost),
    (EDIT_POST_URL, EditPost),
    (EDIT_ERROR_URL, EditPostError),
    (SINGLE_POST_URL, SinglePostPage),
    (LOGIN_URL, Login),
    (SIGNUP_URL, Signup),
    (LOGOUT_URL, Logout),
    (WELCOME_PAGE_URL, WelcomePage),
    (LIKE_URL, LikePost),
    (LIKE_ERROR_URL, LikeError),
    (NEW_COMMENT_URL, CommentPost),
    (EDIT_COMMENT_URL, EditComment)
], debug=True)
