from flask import Flask, render_template, request
import base64
import requests

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url:
            return render_template("index.html", error=True)

        try:
            res = requests.get(url)
            res.raise_for_status()

            encoded = base64.b64encode(res.content).decode("utf-8")

            content_type = res.headers.get("Content-Type", "image/png")

            data_uri = f"data:{content_type};base64,{encoded}"

            return render_template("index.html", success=True, img=data_uri)
        except Exception:
            return render_template("index.html", error=True)

    return render_template("index.html")

