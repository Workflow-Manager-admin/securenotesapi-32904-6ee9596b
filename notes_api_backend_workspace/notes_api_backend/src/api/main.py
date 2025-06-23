from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from sqlmodel import SQLModel, Field, Session, create_engine, select
from typing import Optional, List
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import time
import threading

# ---------------- Configuration ------------------

SECRET_KEY = "CHANGE_THIS_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = "sqlite:///./notes.sqlite"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

RATE_LIMIT = 10
RATE_PERIOD = 60


# ---------------- Rate Limiting -----------------

class RateLimiter:

    def __init__(self):
        self.clients = {}
        self.lock = threading.Lock()

    def check(self, key: str) -> bool:
        now = int(time.time())
        window = now // RATE_PERIOD
        with self.lock:
            if key not in self.clients:
                self.clients[key] = {}
            client_windows = self.clients[key]
            if window not in client_windows:
                client_windows.clear()
                client_windows[window] = 0
            if client_windows[window] >= RATE_LIMIT:
                return False
            client_windows[window] += 1
            return True


rate_limiter = RateLimiter()


def get_client_ip(request: Request):
    return request.client.host


async def rate_limit(request: Request):
    user = None
    try:
        token = await oauth2_scheme(request)
        user = decode_token(token).get("sub")
    except Exception:
        pass
    client_id = user or get_client_ip(request)
    if not rate_limiter.check(client_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


# ---------------- Database Models ----------------


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, nullable=False)
    email: EmailStr = Field(unique=True, nullable=False)
    hashed_password: str


class Note(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    content: str
    owner_id: int = Field(foreign_key="user.id", index=True)


class NoteCreate(BaseModel):
    title: str
    content: str


class NoteRead(BaseModel):
    id: int
    title: str
    content: str


class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# ---------------- Security Helpers ----------------


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


def get_db_session():
    with Session(engine) as session:
        yield session


# PUBLIC_INTERFACE
def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_db_session)
):
    """Gets the current user from the JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = decode_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None:
        raise credentials_exception
    return user


# ---------------- FastAPI App Setup ----------------


app = FastAPI(
    title="Secure Notes API",
    description="A RESTful API for notes CRUD with JWT authentication and rate limiting. "
                "Built with FastAPI, SQLModel, SQLite.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "User registration and authentication."},
        {"name": "Notes", "description": "CRUD operations on notes (protected)."}
    ]
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- Event Handlers -------------------


@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)


# ---------------- API Endpoints: Auth --------------


@app.post(
    "/api/register",
    response_model=Token,
    tags=["Auth"],
    summary="Register a new user"
)
async def register_user(
    user: UserCreate,
    session: Session = Depends(get_db_session)
):
    """Register a new user and return JWT access token."""
    existing = session.exec(
        select(User).where(
            (User.email == user.email) | (User.username == user.username)
        )
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Username or email already registered."
        )
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post(
    "/api/login",
    response_model=Token,
    tags=["Auth"],
    summary="Login and obtain JWT token"
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_db_session)
):
    """Authenticate user and return JWT token."""
    user = session.exec(
        select(User).where(User.username == form_data.username)
    ).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password"
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# ---------------- API Endpoints: Notes --------------


@app.post(
    "/api/notes/",
    response_model=NoteRead,
    tags=["Notes"],
    dependencies=[Depends(rate_limit)],
    summary="Create a new note"
)
async def create_note(
    note: NoteCreate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session)
):
    """Create a note for the authenticated user."""
    db_note = Note(title=note.title, content=note.content, owner_id=user.id)
    session.add(db_note)
    session.commit()
    session.refresh(db_note)
    return db_note


@app.get(
    "/api/notes/",
    response_model=List[NoteRead],
    tags=["Notes"],
    dependencies=[Depends(rate_limit)],
    summary="List all notes"
)
async def read_notes(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session)
):
    """Get all notes belonging to authenticated user."""
    notes = session.exec(
        select(Note).where(Note.owner_id == user.id)
    ).all()
    return notes


@app.get(
    "/api/notes/{note_id}",
    response_model=NoteRead,
    tags=["Notes"],
    dependencies=[Depends(rate_limit)],
    summary="Get a single note"
)
async def read_note(
    note_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session)
):
    """Get details of a single note for this user."""
    note = session.exec(
        select(Note).where(
            (Note.id == note_id) & (Note.owner_id == user.id)
        )
    ).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    return note


@app.put(
    "/api/notes/{note_id}",
    response_model=NoteRead,
    tags=["Notes"],
    dependencies=[Depends(rate_limit)],
    summary="Update a note"
)
async def update_note(
    note_id: int,
    note_update: NoteUpdate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session)
):
    """Update a note's title or content."""
    db_note = session.exec(
        select(Note).where(
            (Note.id == note_id) & (Note.owner_id == user.id)
        )
    ).first()
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")
    if note_update.title is not None:
        db_note.title = note_update.title
    if note_update.content is not None:
        db_note.content = note_update.content
    session.add(db_note)
    session.commit()
    session.refresh(db_note)
    return db_note


@app.delete(
    "/api/notes/{note_id}",
    response_model=dict,
    tags=["Notes"],
    dependencies=[Depends(rate_limit)],
    summary="Delete a note"
)
async def delete_note(
    note_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session)
):
    """Delete a note."""
    db_note = session.exec(
        select(Note).where(
            (Note.id == note_id) & (Note.owner_id == user.id)
        )
    ).first()
    if not db_note:
        raise HTTPException(status_code=404, detail="Note not found")
    session.delete(db_note)
    session.commit()
    return {"message": "Note deleted."}


@app.get("/", tags=["Root"], include_in_schema=False)
def health_check():
    return {"message": "Healthy"}


# ---------------- Swagger/OpenAPI enhancements --------------


@app.get("/api/docs/help", tags=["Root"], summary="Swagger usage help")
def swagger_usage_note():
    """
    Usage note for API and JWT security:
    - Register using /api/register to get a JWT token.
    - Authorize via the Authorize button in Swagger (lock icon) or send Bearer token in Authorization header.
    - All /api/notes routes require authentication.
    - Endpoints are rate limited to 10 requests per minute per user.
    """
    return {
        "details": [
            "Register through /api/register to receive a JWT token.",
            "Use the JWT as 'Bearer <token>' in the Authorization header.",
            "All /api/notes routes are protected and require authentication.",
            (
                "All endpoints are rate limited to 10 requests per minute per "
                "user or IP."
            ),
            "Swagger UI provided at /docs.",
        ]
    }


# ---------------- Custom Exception Handlers -------------------


@app.exception_handler(429)
async def ratelimit_exception_handler(request: Request, exc):
    return JSONResponse(
        status_code=429,
        content={"message": "Rate limit exceeded. Try again later."}
    )


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Secure Notes API",
        version="1.0.0",
        description=(
            "A RESTful API for notes CRUD with JWT authentication and rate "
            "limiting. Register and login to receive a JWT for "
            "/api/notes endpoints."
        ),
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
