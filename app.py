from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from starlette.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
import logging, time

from schemas import LoginRequest, RegistrationRequest, RoleUpdateRequest
from security import create_access_token, verify_password
from auth import require_roles
from dependencies import success
from database import SessionLocal
from models import User
from registration import user_registration, update_user_role
app = FastAPI()
logging.basicConfig(level=logging.INFO)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    logging.info(f"{request.method} {request.url.path} {time.time()-start}")
    return response

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=63072000"
    return response


def verify_user_and_generate_token(email, password):
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.email})
    return token

@app.post("/generate_access_token")
@limiter.limit("5/minute")
def generate_access_token(request: Request, payload: LoginRequest):
    token = verify_user_and_generate_token(payload.email, payload.password)
    return success({"access_token": token})

@app.post("/registration")
@limiter.limit("5/minute")
def registration(request: Request, payload: RegistrationRequest):
    result = user_registration(payload)
    return success({"result": result})

@app.put("/admin/update-role")
def update_role(
    payload: RoleUpdateRequest,
    admin=Depends(require_roles("admin"))
):
    result = update_user_role(payload)
    return {"message": result}



@app.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    token = verify_user_and_generate_token(form_data.username, form_data.password)
    return {
        "access_token": token,
        "token_type": "bearer"
    }

# 🔐 ADMIN ONLY
@app.get("/admin")
def admin_dashboard(user=Depends(require_roles("admin"))):
    return {"message": "Admin access granted"}

# 🔐 MULTI-ROLE ACCESS (admin, manager, agent)
@app.post("/api/search")
@limiter.limit("30/minute")
async def search_properties(
    request: Request,
    user=Depends(require_roles("admin", "manager", "agent"))
):
    return {
        "message": "Search allowed",
        "user_role": user.role
    }

# 🔐 USER + ABOVE
@app.get("/profile")
def user_profile(user=Depends(require_roles("admin", "manager", "agent", "user"))):
    return {
        "email": user.email,
        "role": user.role
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8002, reload=True)
