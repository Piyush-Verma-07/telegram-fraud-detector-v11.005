from flask import Flask, render_template, request
from detector.scam_detector import analyze_message

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        message = request.form["message"]

        score, reasons, verdict = analyze_message(message)

        result = {
            "score": score,
            "reasons": reasons,
            "verdict": verdict
        }

    return render_template("index.html", result=result)



# ================= PRIVACY POLICY PAGE =================

@app.route("/privacy-policy")
def privacy_policy():

    return render_template("privacy_policy.html")


# ================= TERMS PAGE =================

@app.route("/terms")
def terms():

    return render_template("terms.html")


# ================= CONTACT PAGE =================

@app.route("/contact")
def contact():

    return render_template("contact.html")




if __name__ == "__main__":
    app.run(debug=True)