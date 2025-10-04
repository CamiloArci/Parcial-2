from flask import Flask, request, jsonify
from jose import jwt, JWTError
import requests

app = Flask(__name__)

KEYCLOAK_URL = "http://localhost:8080/realms/parcial2/protocol/openid-connect/certs"

def get_jwks():
    return requests.get(KEYCLOAK_URL).json()

def get_public_key(token, jwks):
    headers = jwt.get_unverified_header(token)
    kid = headers['kid']
    for key in jwks['keys']:
        if key['kid'] == kid:
            return key
    raise Exception("Public key not found")

def verify_token(token):
    jwks = get_jwks()
    jwk = get_public_key(token, jwks)
    return jwt.decode(token, jwk, algorithms=["RS256"], options={"verify_aud": False})

@app.route("/api/public")
def publico():
    return jsonify({"msg": "Endpoint público"})

@app.route("/api/service")
def service_endpoint():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return jsonify({"error": "Falta token"}), 401
    
    token = auth.split(" ")[1]
    try:
        decoded = verify_token(token)
        if "service-client" not in decoded.get("aud", []):
            return jsonify({"error": "Token no válido para servicios"}), 403
        return jsonify({"msg": "Acceso de servicio permitido", "client": decoded.get("azp")})
    except JWTError as e:
        return jsonify({"error": str(e)}), 401

@app.route("/api/user")
def user_endpoint():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return jsonify({"error": "Falta token"}), 401
    
    token = auth.split(" ")[1]
    try:
        decoded = verify_token(token)
        if "frontend-client" not in decoded.get("aud", []):
            return jsonify({"error": "Token no válido para usuarios"}), 403
        return jsonify({"msg": "Acceso de usuario permitido", "user": decoded.get("preferred_username")})
    except JWTError as e:
        return jsonify({"error": str(e)}), 401

if __name__ == "__main__":
    app.run(port=5000, debug=True, ssl_context='adhoc')