from flask import Flask, render_template, request, redirect, url_for, session
from detector.scam_detector import analyze_message

app = Flask(__name__)


@app.after_request
def add_header(response):

    response.cache_control.no_store = True
    response.cache_control.no_cache = True
    response.cache_control.must_revalidate = True
    response.cache_control.max_age = 0

    return response




app.secret_key = "fraud_detector_secret"
@app.route("/", methods=["GET", "POST"])
def home():

    # ================= POST =================

    if request.method == "POST":

        message = request.form["message"]

        score, reasons, verdict = analyze_message(message)

        session["result"] = {
            "score": score,
            "reasons": reasons,
            "verdict": verdict,
            "message": message
        }

        return redirect(url_for("home"))

    # ================= GET =================

    result = session.pop("result", None)

    return render_template(
        "index.html",
        result=result
    )


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