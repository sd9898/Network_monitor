from flask import Flask, jsonify, render_template
import os

app = Flask(__name__)

# Stores visited sites and threat verification
visited_sites = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/visited_sites')
def get_visited_sites():
    return jsonify(visited_sites)

# Start the Flask server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
