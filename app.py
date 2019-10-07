import json
from base64 import b64encode
from datetime import datetime

from elasticsearch import Elasticsearch
from flask import Flask, render_template, flash, redirect, url_for, session, request, jsonify
import logging
from flask_socketio import SocketIO
from flask_mysqldb import MySQL
from requests_oauthlib import OAuth2Session
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from wtforms.fields.html5 import EmailField
import os
import ast
import redis

r = redis.Redis('localhost')
es = Elasticsearch([{"host": "localhost", "port": 9200}])

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

client_id = r"897862822843-jrh6lik38767q5f3r4gfuf45ac7f811j.apps.googleusercontent.com"
client_secret = "eIJuwsMoG6KiiNrkOhLPDpPi"
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://oauth2.googleapis.com/token'
redirect_uri = "http://localhost:5000/callback"
scope = ['https://www.googleapis.com/auth/userinfo.email',
         'https://www.googleapis.com/auth/userinfo.profile']
state = ''

app = Flask(__name__)
socketio = SocketIO(app)
app.secret_key = os.urandom(24)
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["JPEG", "JPG", "PNG"]

mysql = MySQL()
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'chat'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql.init_app(app)

logging.basicConfig(filename="logfile.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


@app.route("/callback")
def callback():
    global state

    github = OAuth2Session(client_id, state=state, redirect_uri=redirect_uri)
    token = github.fetch_token(token_url, client_secret=client_secret,
                               authorization_response=request.url)
    user_info = github.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    return redirect(url_for('register_with_google', user_info=user_info))


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'uid' in session:
            return f(*args, *kwargs)
        else:
            flash('Unauthorized, Please logged in', 'danger')
            return redirect(url_for('login'))

    return wrap


def not_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'uid' in session:
            flash('Unauthorized, You logged in', 'danger')
            return redirect(url_for('index'))
        else:
            return f(*args, *kwargs)

    return wrap


@app.route('/register_with_google', methods=['POST', 'GET'])
@not_logged_in
def register_with_google():
    user_info = request.args.get('user_info')
    user_info = ast.literal_eval(user_info)

    logging.debug("Logging with Google Id process started.")
    name = user_info['name']
    email = user_info['email']
    username = (user_info['email'].split('@'))[0]

    password = "google id"

    cur = mysql.connection.cursor()
    query = "select * from users where name=%s and email=%s"
    query_data = (name, email)
    cur.execute(query, query_data)
    result = cur.fetchone()

    if len(result) == 0:
        query = "INSERT INTO users(name, email, username, password) VALUES (%s,%s,%s,%s)"
        query_data = (name, email, username, password)
        cur.execute(query, query_data)
    query = "select id from users where name = %s and email = %s"
    query_data = (name, email)
    cur.execute(query, query_data)
    result = cur.fetchone()
    if len(result) != 0:
        uid = session['uid'] = result['id']
        session['s_name'] = user_info['name']
        session['username'] = (user_info['email'].split('@'))[0]
        x = '1'
        cur.execute("UPDATE users SET active=%s WHERE id=%s", (x, uid))
        mysql.connection.commit()
        cur.close()
        flash('You are now logged in  with Google Id', 'success')
        logging.debug("User logged in  with Google Id successfully.")
    else:
        flash('No user with Google Id', 'danger')
    return render_template('home.html')


@app.route('/')
def index():
    github = OAuth2Session(client_id, redirect_uri=redirect_uri,
                           scope=scope)
    authorization_url, state = github.authorization_url(authorization_base_url, access_type="offline",
                                                        prompt="select_account")
    session['oauth_state'] = state
    return render_template('home.html', authorization_url=authorization_url)


class LoginForm(Form):  # Create Message Form
    username = StringField('Username', [validators.length(min=1)], render_kw={'autofocus': True})


@app.route('/login/', methods=['GET', 'POST'])
@not_logged_in
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():

        logging.debug("Login process started.")
        username = form.username.data
        password_candidate = request.form['password']
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username=%s", [username])

        if result > 0:
            data = cur.fetchone()
            password = data['password']
            uid = data['id']
            name = data['name']

            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['uid'] = uid
                session['s_name'] = name
                session['username'] = username
                x = '1'
                cur.execute("UPDATE users SET active=%s WHERE id=%s", (x, uid))
                flash('You are now logged in', 'success')
                logging.debug("User logged in successfully.")

                return redirect(url_for('index'))

            else:
                flash('Incorrect password', 'danger')
                return render_template('login.html', form=form)

        else:
            flash('Username not found', 'danger')
            cur.close()
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)


@app.route('/out')
def logout():
    if 'uid' in session:
        cur = mysql.connection.cursor()
        uid = session['uid']
        x = '0'
        cur.execute("UPDATE users SET active=%s WHERE id=%s", (x, uid))
        mysql.connection.commit()
        cur.close()
        session.clear()
        flash('You are logged out', 'success')
        logging.debug("User logged out  successfully.")
        return redirect(url_for('index'))
    return redirect(url_for('login'))


class RegisterForm(Form):
    name = StringField('Name', [validators.length(min=3, max=50)], render_kw={'autofocus': True})
    username = StringField('Username', [validators.length(min=3, max=40)])
    email = EmailField('Email', [validators.DataRequired(), validators.Email(), validators.length(min=4, max=40)])
    password = PasswordField('Password',
                             [validators.length(min=3), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Re-enter Password')


@app.route('/register', methods=['GET', 'POST'])
@not_logged_in
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        logging.debug("Registration process started.")
        name = form.name.data
        email = form.email.data
        username = form.username.data

        password = sha256_crypt.encrypt(str(form.password.data))

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                    (name, email, username, password))
        cur.execute("select max(id) from users")
        max_id = cur.fetchone()
        dummy_user_data = {"id": max_id["max(id)"],
                           "name": name,
                           "email": email,
                           "username": username,
                           "password": password
                           }

        insert_obj = es.index(index="instagram-clone1", doc_type="users", body=dummy_user_data,
                              id=max_id["max(id)"])


        mysql.connection.commit()
        cur.close()

        flash('You are now registered and can login', 'success')
        logging.debug("User registered  successfully.")

        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/search', methods=["GET", "POST"])
@is_logged_in
def search():
    user_datas = []
    # if request.method == "POST":
    #     list_of_needed_data = []
    #
    #     data_to_be_searched = request.form['search_value'].lower()
    #     data_to_be_searched = ".*" + data_to_be_searched + ".*"
    #     # body = {
    #     #     "query": {
    #     #
    #     #         "regexp": {"name":
    #     #                        {"value": data_to_be_searched}
    #     #                    },
    #     #         "regexp": {"username":
    #     #                        {"value": data_to_be_searched}
    #     #                    }
    #     #     }
    #     # }
    #
    #     body = {
    #         "query": {
    #             "bool": {
    #                 "should": [
    #                     {"regexp": {
    #                         "username": {
    #                             "value": data_to_be_searched
    #                         }
    #                     }},
    #                     {"regexp":
    #                         {
    #                             "name": {
    #                                 "value": data_to_be_searched
    #                             }
    #                         }
    #                     }
    #                 ]
    #
    #             }
    #         }
    #     }
    #
    #     search_obj = es.search(index="instagram-clone1", body=body)
    #     for needed_data in search_obj['hits']['hits']:
    #         list_of_needed_data.append(needed_data['_source'])
    #     if len(list_of_needed_data) == 0:
    #         flash("No User found.", "info")
    #     return render_template('search.html', list_of_needed_data=list_of_needed_data)
    for key in r.scan_iter():
        x = r.hgetall(key)
        user_data = {y.decode('ascii'): x.get(y).decode('ascii') for y in x.keys() if y != b"profile_photo"}
        user_data["profile_photo"] = x[b"profile_photo"]
        user_datas.append(user_data)
    for index, user in enumerate(user_datas):
        user_datas[index]['profile_photo'] = b64encode(
            user_datas[index]['profile_photo']).decode("utf-8")
    return render_template('search.html', user_datas=user_datas)


class MessageForm(Form):  # Create Message Form
    body = StringField('', [validators.length(min=1)], render_kw={'autofocus': True})


@app.route('/chatting/<string:id>', methods=['GET', 'POST'])
def chatting(id):
    if 'uid' in session:
        form = MessageForm(request.form)
        cur = mysql.connection.cursor()

        get_result = cur.execute("SELECT * FROM users WHERE id=%s", [id])
        l_data = cur.fetchone()
        if get_result > 0:
            session['name'] = l_data['name']
            uid = session['uid']
            session['lid'] = id
            # cur.execute("select msg_time from messages where msg_by = %s and msg_to =%s",(id, uid))
            # last_message_read_time =cur.fetchall()
            # last_message_read_time = list(last_message_read_time)
            # last_message_read_time=[i["msg_time"] for i in last_message_read_time]
            # if last_message_read_time:
            #     last_message_read_time=max(last_message_read_time)
            #     print(last_message_read_time)
            # last_read_time = last_message_read_time or datetime(1900, 1, 1)

            # print(last_read_time)
            # print(type(last_read_time))
            # cursor = mysql.connection.cursor()
            # cursor.execute("select count(*) from messages where msg_time > %s and msg_to = %s", (last_read_time, uid))
            # triger = cursor.fetchone()
            #
            # triger=triger["count(*)"]
            msg_time = datetime.now().strftime(' %Y-%m-%d %H:%M:%S')
            if request.method == 'POST' and form.validate():
                txt_body = form.body.data
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO messages(body, msg_by, msg_to,msg_time) VALUES(%s, %s, %s,%s)",
                            (txt_body, id, uid, msg_time))
                mysql.connection.commit()
                cur.execute("select max(id) from messages")
                max_id = cur.fetchone()
                max_id = max_id["max(id)"]
                body = {
                    "body": txt_body,
                    "msg_by": id,
                    "msg_to": str(uid),
                    "id": max_id + 1,
                    "msg_time": msg_time
                }
                search_obj = es.index(index="instagram-chats", body=body)

            cur.execute(
                "select * from users where id in (select user2 from following where user1 = {0})".format(
                    session['uid']))
            users = cur.fetchall()

            if len(users) == 0:
                flash("No friends in your friend list.", "warning")
                cur.close()

            return render_template('chat_room.html', users=users, form=form, )
        else:
            flash('No permission!', 'danger')
            logging.debug("Unauthorized user.")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))


@app.route('/chats', methods=['GET', 'POST'])
@is_logged_in
def chats():
    if 'lid' in session:
        chats = []

        id = session['lid']
        uid = session['uid']
        # cur = mysql.connection.cursor()

        # cur.execute("SELECT * FROM messages WHERE (msg_by=%s AND msg_to=%s) OR (msg_by=%s AND msg_to=%s) "
        #             "ORDER BY id ASC", (id, uid, uid, id))
        #
        # chats = cur.fetchall()
        # print(chats)
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {
                            "msg_by": [id, uid]

                        }},
                        {"terms":
                            {
                                "msg_to": [id, uid]

                            }
                        }
                    ]

                }}}
        search_obj = es.search(index="instagram-chats", body=body, size=1000)
        for i in search_obj["hits"]["hits"]:
            chats.append(i["_source"])
        results_sorted = sorted(chats, key=lambda file: datetime.strptime(str(file["msg_time"]), ' %Y-%m-%d %H:%M:%S'))

        # results_sorted= [i  ]
        for i, j in enumerate(results_sorted):
            results_sorted[i]["msg_to"] = int(results_sorted[i]["msg_to"].strip())
            results_sorted[i]["msg_by"] = int(results_sorted[i]["msg_by"].strip())
        # cur.close()
        return render_template('chats.html', chats=results_sorted, )
    return redirect(url_for('login'))


@app.route('/suggestions', methods=['GET'])
@is_logged_in
def suggestions():
    suggestion_list = []

    # try:
    #     cursor = mysql.connection.cursor()
    # except Exception as e:
    #     logging.debug("Cant connect to database.")
    try:
        # cursor.execute(
        #     "select id from users where username not in (select username from users where id in (select user2 "
        #     "from following where user1 =%s )) limit 10;",
        #     (session['uid'],))
        # results = cursor.fetchall()
        # results = list(results)
        body = {
            "query":
                {
                    "match_phrase": {
                        "user1": session['uid']
                    }
                }
        }
        search_obj = es.search(index="instagram-following", body=body)
        results = []

        for i in search_obj["hits"]["hits"]:
            results.append(i["_source"]["user2"])

        results1 = []
        for i in results:
            body = {
                "query":
                    {
                        "match_phrase": {
                            "user1": i
                        }
                    }
            }
            search_obj = es.search(index="instagram-following", body=body)

            for j in search_obj["hits"]["hits"]:
                if j["_source"]["user2"] not in results1 and j["_source"]["user2"] not in results:
                    results1.append(j["_source"]["user2"])

        # all_user=[]
        # for key in r.scan_iter():
        #     all_user.append(key)
        #
        # all_user=[i.decode("utf-8") for i in all_user]

        # for i in all_user:
        #     if i not in results:
        #         res.append(i)

        results1 = [i for i in results1 if i != str(session["uid"])]

        for i in results1:
            x = r.hgetall(i)
            y = {y.decode('ascii'): x.get(y).decode('ascii') for y in x.keys() if y != b"profile_photo"}
            y["profile_photo"] = x[b"profile_photo"]
            suggestion_list.append(y)

        for index, user in enumerate(suggestion_list):
            suggestion_list[index]['profile_photo'] = b64encode(
                suggestion_list[index]['profile_photo']).decode("utf-8")

        if len(suggestion_list) == 0:
            flash("No more suggestion.", "danger")
            logging.debug("No suggestion found.")
    except KeyError as e:
        flash("Session Expired. Please login again.", "danger")
        return redirect(url_for('index'))
    return render_template('suggestions.html', suggestion_list=suggestion_list)


@app.route('/on_follow', methods=['GET', 'POST'])
def on_follow():
    uid = session.get('uid')
    for k, v in request.form.items():
        if v == "Follow":
            username_clicked = k
    try:
        cursor = mysql.connection.cursor()
    except Exception as e:
        logging.debug("Cant connect to database.")
    try:
        username_clicked = ast.literal_eval(username_clicked)
        cursor.execute("select id from users where username= %s", (username_clicked["username"],))
        user_clicked = cursor.fetchone()

        cursor.execute(
            "select 1 from following where user1={0} and user2={1}".format(session['uid'], user_clicked['id']))
        i_exists_follower = cursor.fetchall()
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {
                            "user1": session['uid']

                        }},
                        {"term":
                            {
                                "user2": user_clicked['id']

                            }
                        }
                    ]

                }}}
        search_obj = es.search(index="instagram-following", body=body)

        if user_clicked['id'] is not "" or user_clicked['id'] is not None:
            if not search_obj["hits"]["hits"]:
                cursor.execute("INSERT into following values ({0},{1})".format(session['uid'], user_clicked['id']))
                body = {
                    "user1": str(session['uid']),
                    "user2": str(user_clicked['id'])
                }
                mysql.connection.commit()
                cursor.close()

                insert_obj = es.index(index="instagram-following", body=body)
                flash("Successfully followed user \"{}\" ".format(username_clicked["username"]), 'info')

            else:
                flash("\"{}\" is already followed.".format(username_clicked["username"]), 'danger')

        # results = cursor.execute("INSERT into Following(user1,user2) select ?,? " \
        #                 "where not EXISTS()",(session['user_id'],user_clicked[:-1],session['user_id'],user_clicked[:-1]))
    except KeyError as e:
        flash("Session Expired. Please login again.", "danger")
        return redirect(url_for('index'))
    return redirect(url_for('suggestions'))


@app.route('/followers/', methods=['GET'])
@is_logged_in
def followers():
    list_of_followers_user = []
    try:
        # cursor.execute("select user1 from following where user2 = {0}".format(session['uid']))
        # res = cursor.fetchall()
        body = {
            "query":
                {
                    "match_phrase": {
                        "user2": session['uid']
                    }
                }
        }
        search_obj = es.search(index="instagram-following", body=body)
        res = []

        for i in search_obj["hits"]["hits"]:
            res.append(i["_source"])

        for i in res:

            x = r.hgetall(i['user1'])
            y = {y.decode('ascii'): x.get(y).decode('ascii') for y in x.keys() if y != b"profile_photo"}
            y["profile_photo"] = x[b"profile_photo"]
            list_of_followers_user.append(y)

        if len(list_of_followers_user) == 0:
            flash("No Followers found.", "danger")
            logging.debug("No Followers found.")
        for index, user in enumerate(list_of_followers_user):
            list_of_followers_user[index]['profile_photo'] = b64encode(
                list_of_followers_user[index]['profile_photo']).decode("utf-8")

    except KeyError as e:
        flash("Session Expired. Please login again.", "danger")
        return redirect(url_for('index'))
    return render_template('follower.html', list_of_followers_user=list_of_followers_user)


@app.route('/following/', methods=['GET'])
@is_logged_in
def following():
    list_of_following_user = []
    try:
        cursor = mysql.connection.cursor()
    except Exception as e:
        logging.debug("Cant connect to database.")

    # cursor.execute(
    #     "select username,name,profile_photo from users where id in (select user2 from following where user1 = {0})".format(
    #         session['uid']))
    body = {
        "query":
            {
                "match_phrase": {
                    "user1": session['uid']
                }
            }
    }
    search_obj = es.search(index="instagram-following", body=body)
    res = []
    for i in search_obj["hits"]["hits"]:
        res.append(i["_source"])
    # try:
    # cursor.execute(
    #     "select user2 from following where user1 = {0}".format(
    #         session['uid']))
    # res = cursor.fetchall()

    for i in res:
        x = r.hgetall(i['user2'])
        y = {y.decode('ascii'): x.get(y).decode('ascii') for y in x.keys() if y != b"profile_photo"}
        y["profile_photo"] = x[b"profile_photo"]
        list_of_following_user.append(y)

    if len(list_of_following_user) == 0:
        flash("No Following found.", "danger")
        logging.debug("No Following found.")
    for index, user in enumerate(list_of_following_user):
        list_of_following_user[index]['profile_photo'] = b64encode(
            list_of_following_user[index]['profile_photo']).decode("utf-8")
    cursor.close()

    return render_template('following.html', list_of_following_user=list_of_following_user)


@app.route('/posting_image', methods=['POST', 'GET'])
@is_logged_in
def posting_image():
    if request.method == "POST":
        file = request.files['file_name']
        timestamp = datetime.now()
        caption = request.form['caption']
        if allowed_image(file.filename):
            file_content = file.read()
            current_image = b64encode(file_content).decode("utf-8")

            try:
                cursor = mysql.connection.cursor()
            except Exception as e:
                logging.debug("Cant connect to database.")
            try:
                query = """insert into photoposted (posted_by,photo,times,caption) values (%s,%s,%s,%s)"""
                query_data = (session['uid'], file_content, timestamp, caption)
                cursor.execute(query, query_data)
                cursor.execute("select max(photo_id) from photoposted")
                max_photo_id = cursor.fetchone()

                body = {"photo_id": max_photo_id["max(photo_id)"],
                        "posted_by": session['uid'],
                        "photo": str(current_image),
                        "time": timestamp,
                        "caption": caption

                        }
                insert_obj = es.index("instagram-photoposted", body=body)

                mysql.connection.commit()
                cursor.close()
            except Exception as e:
                logging.debug("Database issue.\n", e)
            except KeyError as e:
                flash("Session Expired. Please login again.", "danger")
                return redirect(url_for('index'))

            flash('File uploaded to timeline successfully.', 'info')
            return render_template("timeline.html", current_image=current_image, caption=caption)
        else:
            flash("Invalid file type.\n\nOnly image type allowed.", 'info')
            return render_template('posting-image.html')
    else:
        return render_template('posting-image.html')


@app.route('/timeline/', methods=['GET'])
@is_logged_in
def timeline():
    try:
        cursor = mysql.connection.cursor()
    except Exception as e:

        logging.debug("Cant connect to database.")
    # cursor.execute('SELECT posted_by,photo FROM photoposted ORDER BY times DESC limit 10 ')
    # results = cursor.fetchall()
    body = {
        "query":
            {
                "match_phrase": {
                    "user1": session['uid']
                }
            }
    }
    search_obj = es.search(index="instagram-following", body=body)
    try:
        list_of_following = []
        for i in search_obj["hits"]["hits"]:
            list_of_following.append(i["_source"]["user2"])
        list_of_following.append(session["uid"])
        results = []
        s = []
        for i in list_of_following:

            body = {
                "query":
                    {
                        "match_phrase": {
                            "posted_by": i
                        }
                    }
            }
            search_obj = es.search(index="instagram-photoposted", body=body)

            for k in search_obj["hits"]["hits"]:
                if k["_source"] not in s and k["_source"]["photo"] is not "":
                    s.append(k["_source"])
        for j in s:
            result = {}
            result["posted_by"] = j["posted_by"]
            if j["photo"].startswith(r"b'"):
                result["photo"] = j["photo"][2:]
                result["photo"] = result["photo"][:-1]
            else:
                result["photo"] = j["photo"]

            if "." in j["time"]:
                j["time"] = j["time"].split(".")[0]
            if "T" in j["time"]:
                j["time"] = j["time"].replace("T", " ")
            date = datetime.strptime(j["time"], '%Y-%m-%d %H:%M:%S')
            result["time"] = date
            # datetime.strftime(date, "%d %B,%Y")

            result["caption"] = j["caption"]

            x = r.hgetall(j["posted_by"])
            y = {y.decode('ascii'): x.get(y).decode('ascii') for y in x.keys() if y != b"profile_photo"}
            result["profile_photo"] = x[b"profile_photo"]
            result["name"] = y["name"]

            results.append(result)
        for index, user in enumerate(results):
            results[index]['profile_photo'] = b64encode(
                results[index]['profile_photo']).decode("utf-8")
        results = list(results)

        results_sorted = sorted(results, key=lambda file: datetime.strptime(str(file["time"]), '%Y-%m-%d %H:%M:%S'),
                                reverse=True)
        for k, s in enumerate(results_sorted):
            results_sorted[k]["time"] = datetime.strftime(s["time"], "%d %B,%Y")
        # cursor.execute(
        #     "select u.name,p.photo,p.times,p.caption from users u,photoposted p where u.id = p.posted_by order by p.times desc limit 10 ")
        # results = cursor.fetchall()

        cursor.close()
    except KeyError as e:
        print(e)
        flash("Session Expired. Please login again.", "danger")
        return render_template('login.html')
    return render_template("timeline.html", list_of_image=results_sorted)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET'])
def invalid_urls(path):
    flash("This url doesnt exists.\nTry Logging in.", "danger")
    return render_template('home.html')


def allowed_image(filename):
    if not "." in filename:
        return False
    ext = filename.rsplit(".", 1)[1]
    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False


# def messageReceived(methods=['GET', 'POST']):
#     print('message was received!!!')
#
#
# @socketio.on('my event')
# def handle_my_custom_event(json, methods=['GET', 'POST']):
#     print('received my event: ' + str(json))
#     socketio.emit('my response', json, callback=messageReceived)


@app.route('/profile', methods=["GET", "POST"])
@is_logged_in
def my_profile():
    if request.method == "POST":
        x = r.hgetall(session["uid"])
        y = {y.decode('ascii'): x.get(y).decode('ascii') for y in x.keys() if y != b"profile_photo"}
        y["profile_photo"] = b64encode(x[b"profile_photo"]).decode("utf-8")
        return render_template('profile.html', change_profile="1",current_user=y)
    try:
        cursor = mysql.connection.cursor()
    except Exception as e:
        logging.debug("Cant connect to database.")
    query = "select active from users where id = %s"
    query_data = (session['uid'],)
    cursor.execute(query, query_data)
    active = cursor.fetchall()
    active = list(active)

    x = r.hgetall(session["uid"])
    y = {y.decode('ascii'): x.get(y).decode('ascii') for y in x.keys() if y != b"profile_photo"}
    y["profile_photo"] = b64encode(x[b"profile_photo"]).decode("utf-8")

    if len(active) == 0:
        flash("User not online.", "danger")
        logging.debug("User not online.")

    body = {
        "query":
            {
                "match_phrase": {
                    "user1": session['uid']
                }
            }
    }
    search_obj = es.search(index="instagram-following", body=body)
    no_of_following = len(search_obj["hits"]["hits"])
    # query = "select count(*) from following where user2 = %s"
    # query_data = (session['uid'],)
    # cursor.execute(query, query_data)
    # no_of_followers = cursor.fetchall()
    # no_of_followers = no_of_followers[0]["count(*)"]
    body = {
        "query":
            {
                "match_phrase": {
                    "user2": session['uid']
                }
            }
    }
    search_obj = es.search(index="instagram-following", body=body)
    no_of_followers = len(search_obj["hits"]["hits"])

    # query = "select count(*) from following where user1 = %s"
    # query_data = (session['uid'],)
    # cursor.execute(query, query_data)
    # no_of_following = cursor.fetchall()
    # no_of_following = no_of_following[0]["count(*)"]

    # body = {
    #     "query":
    #         {
    #             "match_phrase": {
    #                 "user2": session['uid']
    #             }
    #         }
    # }
    # search_obj = es.search(index="instagram-following", body=body)
    # no_of_posts = len(search_obj["hits"]["hits"])

    # query = "select count(*) from photoposted where posted_by= %s"
    # query_data = (session['uid'],)
    # cursor.execute(query, query_data)
    # no_of_posts = cursor.fetchall()
    # no_of_posts = no_of_posts[0]["count(*)"]

    list_of_post = []
    body = {"query": {
        "match_phrase": {'posted_by': str(session["uid"])}
    }}
    search_obj = es.search(index="instagram-photoposted", body=body, size=1000)

    no_of_posts = len(search_obj["hits"]["hits"])
    for i in search_obj["hits"]["hits"]:
        list_of_post.append(i["_source"])

    for i, j in enumerate(list_of_post):
        if j["photo"].startswith(r"b'"):
            j["photo"] = j["photo"][2:]
            j["photo"] = j["photo"][:-1]

    cursor.close()
    return render_template('profile.html', list_of_user=y, active=active, no_of_posts=no_of_posts,
                           no_of_following=no_of_following, no_of_followers=no_of_followers, list_of_post=list_of_post)


@app.route('/change_profile_photo', methods=["GET", "POST"])
def change_profile_photo():
    if request.method == "POST":
        file_content = request.files['new_profile'].read()
        bio = request.form["bio"]
        username = request.form["username"]
        name = request.form["name"]

        try:
            cursor = mysql.connection.cursor()
        except Exception as e:
            logging.debug("Cant connect to database.")

        query = "update users set profile_photo =%s where id = %s"

        # Redis code here
        # set_Obj = r.set(session['uid'], file_content)
        if file_content:
            set_Obj = r.hset(session['uid'], "profile_photo", file_content)
        if username:
            set_Obj = r.hset(session['uid'], "username", username)
        if name:
            set_Obj = r.hset(session['uid'], "name", name)
        if bio:
            set_Obj = r.hset(session['uid'], "bio", bio)


        query_data = (file_content, session['uid'])
        cursor.execute(query, query_data)
        return redirect(url_for('my_profile'))


if __name__ == '__main__':
    socketio.run(app, debug=True)
