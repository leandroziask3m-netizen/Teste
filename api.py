"""
API do Sistema de Áreas
------------------------
Backend único e limpo (sem duplicações de rotas).
Persiste áreas em areas.json e usuários em usuarios.json.
Senhas são armazenadas como hash (sha256 + salt), nunca em texto puro.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import json
import os
import hashlib
import secrets

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AREAS_FILE = "areas.json"
USERS_FILE = "usuarios.json"


# ---------------------------------------------------------------------------
# Helpers de persistência
# ---------------------------------------------------------------------------

def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_areas():
    return load_json(AREAS_FILE, [])


def save_areas(data):
    save_json(AREAS_FILE, data)


def load_users():
    return load_json(USERS_FILE, {})


def save_users(data):
    save_json(USERS_FILE, data)


# ---------------------------------------------------------------------------
# Hash de senha (sha256 + salt, sem dependências externas)
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: str = None) -> str:
    """Retorna 'salt$hash'. Gera um salt novo se não for informado."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hash_password(password, salt) == stored


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------

class Area(BaseModel):
    nome: str
    img: str = ""
    lat: float
    lng: float


class Credenciais(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Rotas gerais
# ---------------------------------------------------------------------------

@app.get("/")
def home():
    return HTMLResponse("<h1>API rodando</h1>")


# ---------------------------------------------------------------------------
# Áreas
# ---------------------------------------------------------------------------

@app.get("/areas")
def get_areas():
    return load_areas()


@app.post("/areas")
def add_area(area: Area):
    areas = load_areas()

    next_id = (max((a["id"] for a in areas), default=0)) + 1

    new_area = {
        "id": next_id,
        "nome": area.nome,
        "img": area.img,
        "lat": area.lat,
        "lng": area.lng,
    }

    areas.append(new_area)
    save_areas(areas)

    return new_area


@app.delete("/areas/{area_id}")
def delete_area(area_id: int):
    areas = load_areas()

    if not any(a["id"] == area_id for a in areas):
        raise HTTPException(status_code=404, detail="área não encontrada")

    areas = [a for a in areas if a["id"] != area_id]
    save_areas(areas)

    return {"msg": "removido"}


# ---------------------------------------------------------------------------
# Autenticação
# ---------------------------------------------------------------------------

@app.post("/register")
def register(data: Credenciais):
    user = data.username.strip().lower()
    password = data.password

    if not user or not password:
        raise HTTPException(status_code=400, detail="usuário e senha são obrigatórios")

    usuarios = load_users()

    if user in usuarios:
        raise HTTPException(status_code=409, detail="usuário já existe")

    usuarios[user] = hash_password(password)
    save_users(usuarios)

    return {"msg": "usuario criado", "user": user}


@app.post("/login")
def login(data: Credenciais):
    user = data.username.strip().lower()
    password = data.password

    usuarios = load_users()
    stored = usuarios.get(user)

    if stored and verify_password(password, stored):
        return {"msg": "login ok", "user": user}

    raise HTTPException(status_code=401, detail="usuário ou senha inválidos")
