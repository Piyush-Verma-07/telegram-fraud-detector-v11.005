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


if __name__ == "__main__":
    app.run(debug=True)