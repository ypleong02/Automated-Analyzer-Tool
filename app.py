from modules import api
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    # exp_cve = [('CVE-2016-6301', 'ip camera')]
    # cve = api.get_rationale_cve_information(exp_cve, 1)
    # return cve
    # for key, value in cve[0].items():
    #     print(f"{key:18} : {value}")
    
    # cve = api.get_all_cve()
    # return 
    return "Home"

if __name__ == "__main__":
    app.run(debug=True)