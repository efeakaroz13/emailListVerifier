from flask import Flask,request,render_template
from emailVerifier import verify
app = Flask(__name__)

@app.route("/",methods=["POST","GET"])
def index():
    if request.method == "POST":
        email = request.form.get("email")
        verifier = verify(email)
        return str(verifier)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True,port=3001)