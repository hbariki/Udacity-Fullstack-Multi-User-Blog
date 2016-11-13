import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


secret = 'imo secret'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    """
    make_secure_val : creates a secure value using secret

    """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    """
    verifies secure value against secret
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val



class BlogHandler(webapp2.RequestHandler):
    """
      Blog Handler : This is blog handler class, inherits webapp2.RequestHandler,
      and provides helper methods
    """  
    def write(self, *a, **kw):
        """
          write : This method writes output to client browser
        """  
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """
         render_str :This method renders html using template
        """ 
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """
          set_secure_cookie: Sets cookie to the browser
        """  
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """
         read_secure_cookie :Read secure cookie to the browser
         
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """
         login : verifies user existence
        """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """
          logout: removes login information
          
        """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """
          This method gets executed for every page and verifies user login status,
          using cookie information
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


##### user stuff

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)



class User(db.Model):
    """
      User : create's User model for database - includes user model functions
    """  
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)



class Post(db.Model):
    """
     Post : This is Post Class, which holds blog post information. And helps
     to store/retrieve User data from database

    Attributes :
          subject(str) : This is subject line of the post
          content(txt) : This is content of the post.
          created(text) : This is date of the post.
          user_id : This is user_id, who wrote blog post.
          likes : show likes of the post

     """     
    
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.StringProperty(required = True)
    likes = db.StringListProperty()
    parent_post = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)




class BlogFront(BlogHandler):
    """
       Blog Front : Shows Blog Front page

    """   
    def get(self):
        posts = Post.all().filter('parent_post =', None).order('-created')
        uid = self.read_secure_cookie('user_id')

        self.render('front.html', posts = posts, uid=uid)



class PostPage(BlogHandler):
    """
      PostPage : shows individual post based on id in URL

    """  
      
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        uid = self.read_secure_cookie('user_id')

        if post.likes and uid in post.likes:
            likeText = 'unlike'
        else:
            likeText = 'like'

        totalLikes = len(post.likes)

        comments = Post.all().filter('parent_post =', post_id)


        for comment in comments:
            print(comments)    

        if not post:
            self.error(404)
            return
        post._render_text = post.content.replace('\n', '<br>')

        self.render("post.html", post = post, likeText = likeText, totalLikes = totalLikes, uid = uid, comments = comments)

    def post(self, post_id):
        if not self.user:
           return self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        uid = self.read_secure_cookie('user_id')

        if subject and content:
            post = Post(parent = blog_key(), subject = subject, content = content, user_id = uid, parent_post = post_id)
            post.put()
            return self.redirect('/post/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("post.html", subject=subject, content=content, error=error)



class LikePage(BlogHandler):
    """
      LikePage : Logs a like for the post with the id in url

    """  
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        uid = self.read_secure_cookie('user_id')

        if not post:
            self.error(404)
            return

        if post.user_id != uid:

            if post.likes and uid in post.likes:
                post.likes.remove(uid)
            else:
                post.likes.append(uid)

            post.put()
            print(post.likes)

            self.redirect('/post/%s' % str(post.key().id()))

        else:
            error = 'you can\'t like or unlike you own post'
            self.render("error.html", error = error)



class DeletePage(BlogHandler):
    """
      DeletePage : Delete's page based on id in url

    """  
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.redirect("/")
            return

        uid = self.read_secure_cookie('user_id')

        if post.user_id != uid:
            error = 'You don\'t have permission to delete this post'
        else:
            error = ''
            db.delete(key)

        self.render("delete.html", error = error)



class EditPage(BlogHandler):
    """
      EditPage : Allows the user of the post to edit page. If they are not the user, display warning

    """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        uid = self.read_secure_cookie('user_id')

        if post.user_id != uid:
            error = 'You don\'t have permission to edit this post'
        else:
            error = ''

        self.render("edit.html", post = post, error = error, uid=uid)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        uid = self.read_secure_cookie('user_id')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and post.user_id == uid:
            post.subject = subject
            post.content = content
            post.put()
            if post.parent_post:
                redirect_id = post.parent_post
            else:
                redirect_id = post.key().id()
            self.redirect('/post/%s' % str(redirect_id))
        else:
            error = "subject and content, please!"
            self.render("edit.html", post = post, error=error)


class NewPost(BlogHandler):
    """
      NewPost : If the user is signed in, allow for the creation of a new post

    """
    def get(self):
        uid = self.read_secure_cookie('user_id')
        # if self.user.email == "harshinibariki@gmail.com":
        #     self.render("newpost.html",  uid=uid)
        # elif self.user:
        if self.user:
            # error = "you do not have permission to create a post, but you may comment on existing posts"
            # posts = Post.all().filter('parent_post =', None).order('-created')
            # self.render('front.html', posts = posts, uid=uid, error=error)
            self.render("newpost.html",  uid=uid)
        else:
          return self.redirect("/login")

    def post(self):
        if not self.user:
           return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        uid = self.read_secure_cookie('user_id')

        if subject and content:
            post = Post(parent = blog_key(), subject = subject, content = content, user_id = uid)
            post.put()
            self.redirect('/post/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



class Signup(BlogHandler):
    """
     Signup : Handles the signup page, shows error if the fields do not match the validation's above.

    """
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """
       Register : creates new user for blog
    """  
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(BlogHandler):
    """
      Login : Handles login for log
    """  
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)



class Logout(BlogHandler):
    """
     Logout : Logouts the user
    """ 
    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(BlogHandler):
    """
    Welcome : welcome page after a user succesfully logs in
    """
    def get(self):
        if self.user:
            uid = self.read_secure_cookie('user_id')
            self.render('welcome.html', username = self.user.name, uid=uid)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/?', BlogFront),
                               ('/post/([0-9]+)', PostPage),
                               ('/delete/([0-9]+)', DeletePage),
                               ('/edit/([0-9]+)', EditPage),
                               ('/like/([0-9]+)', LikePage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
