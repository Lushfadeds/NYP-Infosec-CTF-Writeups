from flask import Flask, render_template, request, jsonify, session
import os
import time
import hashlib


app = Flask(__name__)

app.secret_key = os.urandom(24)  
salt = os.urandom(16)
game_db = {}
flag = open("flag.txt").read()

@app.route('/')
def index():
   
    if 'user_id' not in session:
        session['user_id'] = os.urandom(8).hex()
        game_db[session['user_id']] = {"horsey":0,"evil_horsey":0}
        
    user_id = session['user_id']
    
    return render_template("index.html",horsey_pos=game_db[session['user_id']]['horsey'],evil_horsey_pos=game_db[session['user_id']]['evil_horsey'])




@app.get('/api/run')
def run():
    user = session['user_id']

    try:
        game_db[user]['horsey'] += 30
        game_db[user]['evil_horsey'] += 40
    except KeyError:
        return jsonify({"status":"lose","message":"already lost"})


    #upcoming integrity feature please don't touch
    hashlib.pbkdf2_hmac('sha256', b'integrity_check', salt, 100000)
    
    

    #checks for which horse won
    if game_db[user]['horsey'] >= 100:
        return  jsonify({"status":"win","message":f"you win have a flag {flag}"})
    
    if game_db[user]['evil_horsey'] >= 100:
        game_db.pop(user)
        session['user_id'] = os.urandom(8).hex()
        game_db[session['user_id']] = {"horsey":0,"evil_horsey":0}
        return  jsonify({"status":"lose","message":"you lose"})

    #if no win yet then continue racing
    return jsonify({
        "status": "running",
        "horsey_pos": str(game_db[user]['horsey']) + "%",
        "evil_horsey_pos": str(game_db[user]['evil_horsey']) + "%"
    })
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)