from flask import Flask, request, render_template, url_for, flash,session,redirect
import sqlite3
import logging
from base64 import b64encode
from markupsafe import Markup

logging.basicConfig(filename="logfile.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

app = Flask(__name__,template_folder='template',static_folder=r'C:\Users\yashashri_naitam\PycharmProjects\Instagram2\image')
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["JPEG", "JPG", "PNG"]
app.config['UPLOAD_FOLDER']=r'C:\Users\yashashri_naitam\PycharmProjects\Instagram2'


@app.route('/')
def hello_world():
    if 'photo_id' not in session:
        session['photo_id'] = 2000
    return render_template('login.html')

@app.route('/logout/', methods=['GET', 'POST'])
def logout():
    session.pop('user_id',None)
    #session.pop('photo_id', None)
    return  "You successfully logged out."

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        user_id = request.form['user_id']
        password = request.form['password']
        session['user_id'] = user_id
        conn = sqlite3.connect('instagram1.db')
        cursor = conn.cursor()

        result = cursor.execute("select password from PersonalProfile where user_id =?",(session['user_id'],))
        result = result.fetchone()
        conn.commit()
        cursor.close()
        if result[0] == password:
            return render_template('home-page.html')
        else:
            flash( "Invalid UserName or Password.\nLogin Again..")
            return render_template('login.html')

@app.route('/post-image/', methods=['POST','GET'])
def post_image():
    if request.method =="POST" :
        session['photo_id'] +=1
        # print("after",session['photo_id'])
        file = request.files['file_name']
        file_content =file.read()
        current_image = b64encode(file_content).decode("utf-8")

        conn = sqlite3.connect('instagram1.db')
        cursor = conn.cursor()

        query="insert into PhotoPosted values (?,?,?)"
        cursor.execute(query, (session['photo_id'], session['user_id'], file_content))
        conn.commit()
        cursor.close()
        flash('File uploaded to timeline successfully.')
        return render_template("timeline.html",current_image=current_image)


@app.route('/timeline/', methods=['GET'])
def timeline():
    list_of_image = []
    conn = sqlite3.connect('instagram1.db')
    cursor = conn.cursor()
    results = cursor.execute('select posted_by,src from PhotoPosted limit 10 ').fetchall()
    cursor.close()

    for row in results:
        name = row[0]
        dict_of_userID_image = {}
        image_to_base64 = b64encode(row[1]).decode("utf-8")
        dict_of_userID_image[name] = image_to_base64
        list_of_image.append(dict_of_userID_image)
    return render_template("timeline.html", list_of_image=list_of_image)

@app.route('/login/<name>/', methods=['GET'])
def render_template_html(name):
    return render_template(name)

@app.route('/following/', methods=['GET','POST'])
def following():
    list_of_following_user=[]
    conn = sqlite3.connect('instagram1.db')
    cursor = conn.cursor()
    results =cursor.execute("select user1 from Following where user2 = ?",(session['user_id'],)).fetchall()
    # print("results",results)
    for result in results:
        user_name =cursor.execute("select name from PersonalProfile where user_id=?",(result[0],)).fetchone()
        list_of_following_user.append(user_name[0])
    list_of_following_user = set(list_of_following_user)
    # print(list_of_following_user)
    conn.commit()
    cursor.close()

    return render_template('following.html', list_of_following_user=list_of_following_user)

@app.route('/followers/', methods=['GET'])
def followers():
    list_of_followers_user=[]
    conn = sqlite3.connect('instagram1.db')
    cursor = conn.cursor()

    results =cursor.execute("select user2 from Following where user1 = ?",(session['user_id'],)).fetchall()
    # print(results)
    for result in results:
        user_name =cursor.execute("select name from PersonalProfile where user_id =?",(result[0],)).fetchone()
        # print(user_name)
        list_of_followers_user.append(user_name[0])
    list_of_followers_user = set(list_of_followers_user)
    # print(list_of_followers_user)
    conn.commit()
    cursor.close()
    return render_template('follower.html', list_of_followers_user=list_of_followers_user)

@app.route('/suggestion/',methods=['GET'])
def suggestion():
    suggestion_list=[]
    conn = sqlite3.connect('instagram1.db')
    cursor = conn.cursor()
    results =cursor.execute('''select user_id from PersonalProfile limit 10;''').fetchall()
    suggestion_list =[result[0] for result in results]
    return render_template('suggestion.html',suggestion_list=suggestion_list)

@app.route('/on_follow/',methods=['GET','POST'])
def on_follow():
    for k,v in request.form.items():
        if v =="Follow":
            user_clicked=k
    conn = sqlite3.connect('instagram1.db')
    cursor = conn.cursor()
    i_exists_follower = cursor.execute("select 1 from Following where user1=? and user2=?",(session['user_id'],user_clicked[:-1])).fetchall()
    print(list(i_exists_follower))

    if len(list(i_exists_follower)) == 0:
        results = cursor.execute("INSERT into Following values (?,?)",(session['user_id'],user_clicked[:-1])).fetchall()
        flash("Successfully followed user \"{}\" ".format(user_clicked))
        conn.commit()
        cursor.close()
    else:
        flash("\"{}\" is already followed.".format(user_clicked))

    # results = cursor.execute("INSERT into Following(user1,user2) select ?,? " \
    #                 "where not EXISTS()",(session['user_id'],user_clicked[:-1],session['user_id'],user_clicked[:-1]))

    return redirect(url_for('suggestion'))

@app.route('/register/',methods=['POST','GET'])
def register():
    if request.method == "POST":
        name=request.form['name']
        passwd = request.form['passwd']
        email= request.form['email']
        user_id= request.form['user_id']
        data = (user_id, email, name, passwd)
        conn = sqlite3.connect('instagram1.db')
        cursor = conn.cursor()
        cursor.execute("insert into PersonalProfile values (?,?,?,?)",data)
        conn.commit()
        cursor.close()
        flash(Markup("Registered Successfully.."))
        return render_template('login.html')
    return render_template('register.html')

if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.run(debug=True)
