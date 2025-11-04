from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/api/health', methods=['GET'])
def health():
    return {'status': 'ok', 'message': 'Vaunt API Dashboard Backend'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
