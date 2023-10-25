from modules import api
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():    
    cves = api.get_all_cve()
    return render_template("index.html", cves = cves)

@app.route("/api/cves")
def list_cves():
    cves = api.get_all_cve()
    return jsonify(cves)

# GET route
@app.route("/get-user/<user_id>")
def get_user(user_id):
    user_data = {
        "user_id": user_id,
        "name": "Leong Yi Phang",
        "email": "ypleong@example.com"
    }

    extra = request.args.get("extra")
    if extra:
        user_data["extra"] = extra
    
    return jsonify(user_data), 200

# POST route
@app.route("/create-user", methods=["POST"])
def create_user():
    data = request.get_json()
    # add data into database
    return jsonify(data), 201

if __name__ == "__main__":
    app.run(debug=True)