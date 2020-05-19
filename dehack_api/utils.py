from flask_mail import Message

#urls determined by frontend
def activation_email(email, activation_key, mail):
    msg = Message("Hello",
                  sender="onileereo@gmail.com",
                  recipients=[email])
    msg.body = "View this message in html to activate"
    msg.html = f"""<p>User <b>account activation</b> <br> Use the link below to activate your account <br> <a href='http://localhost:5000/activate/{activation_key}'>http://localhost:5000/activate/{activation_key}</a>
                      <br> Have a great day</p>"""
    mail.send(msg)


def user_activated_email(email, mail):
    msg = Message("Hello",
                  sender="onileereo@gmail.com",
                  recipients=[email])
    msg.body = "View this message in html to activate"
    msg.html = f"""<p>User <b>account activated</b> <br> Thank you for using StreetCred
                      <br> Have a great day</p>"""
    mail.send(msg)


def reset_password_email(email, reset_key, mail):
    msg = Message("Hello",
                  sender="onileereo@gmail.com",
                  recipients=[email])
    msg.body = "View this message in html to activate"
    msg.html = f"""<p>User <b>account password reset</b> <br> Use the link below to reset your password <br> <a href='http://localhost:5000/resetpassword/{reset_key}'>http://localhost:5000/resetpassword/{reset_key}</a>
                      <br> Have a great day</p>"""
    mail.send(msg)      

