import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
from database import FurCreate

logger = logging.getLogger(__name__)

# --- НАСТРОЙКИ БЕЗОПАСНОСТИ ---
SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

MANAGER_USERNAME = os.getenv("MANAGER_USERNAME")
MANAGER_PASSWORD = os.getenv("MANAGER_PASSWORD")

# Проверяем, что заданы ВСЕ переменные
if not all(
    [SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, MANAGER_USERNAME, MANAGER_PASSWORD]
):
    logger.critical(
        "КРИТИЧЕСКАЯ ОШИБКА: Не заданы переменные окружения SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, MANAGER_USERNAME или MANAGER_PASSWORD!"
    )
    logger.critical(
        "Создайте файл .env (или добавьте переменные на сервере Render) и перезапустите."
    )
    raise SystemExit(1)

ALGORITHM = "HS256"
templates = Jinja2Templates(directory="templates")


# --- ФУНКЦИИ JWT ---
def create_access_token(username: str):
    """
    Создание JWT-токена
    """
    expire = datetime.now(timezone.utc) + timedelta(hours=2)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_admin_token(access_token: str | None = Cookie(default=None)):
    """
    Проверка JWT-токена (пускает и админа, и менеджера)
    """
    if not access_token:
        raise HTTPException(status_code=401, detail="Вы не авторизованы")
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username not in [ADMIN_USERNAME, MANAGER_USERNAME]:
            raise HTTPException(status_code=401, detail="Неверный пользователь")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен истек")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Неверный токен")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Включается при запуске
    """
    await database.startup()
    yield  # сервер начал принятие запросов

    # отключение
    await database.shutdown()


# 2. Передача lifespan в FastAPI
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


@app.exception_handler(FastAPIHTTPException)
async def custom_http_exception_handler(request: Request, exc: FastAPIHTTPException):
    # Если ошибка 401 (нет доступа) И это запрос от браузера (ожидает HTML)
    if exc.status_code == 401 and "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # Для всех остальных случаев (ошибки API, 404 и т.д.) возвращаем стандартный JSON
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html(admin: str = Depends(verify_admin_token)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # <------------------------============
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/pets")
async def get_all_pets():
    async with database.pool.acquire() as conn:
        to_get = await conn.fetch("SELECT * FROM lost_pets;")
    return [dict(row) for row in to_get]


@app.post("/api/pets")
async def create_fur(fur: FurCreate):
    """
    Добавление нового блока с новым питомцем
    """
    async with database.pool.acquire() as conn:
        inf = """INSERT INTO lost_pets (name, species, street)
        VALUES ($1, $2, $3)
        RETURNING *;"""
        new_pet = await conn.fetchrow(inf, fur.name, fur.species, fur.street)
    return {"message": "Заявка добавлена", "data": dict(new_pet)}


@app.delete("/api/pets/{fur_id}")
async def dell_fur(fur_id: int, admin: str = Depends(verify_admin_token)):
    """
    Удаление блока с информации о выбранном питомце
    """
    async with database.pool.acquire() as conn:
        inf = "DELETE FROM lost_pets WHERE id = $1;"
        status_fur = await conn.execute(inf, fur_id)
    if status_fur == "DELETE 0":
        raise HTTPException(status_code=404, detail="Питомец с таким ID не найден")

    return {"message": f"Животное с id={fur_id} удалено"}


@app.patch("/api/pets/{fur_id}/found")
async def mark_as_found(fur_id: int, admin: str = Depends(verify_admin_token)):
    """
    обновление статуса питомца
    """
    async with database.pool.acquire() as conn:
        inf = """UPDATE lost_pets
            set status = 'found'
            WHERE id = $1
            RETURNING *;
        """
        updated_pet = await conn.fetchrow(inf, fur_id)

    if updated_pet is None:
        raise HTTPException(status_code=404, detail="Питомец с таким ID не найден")

    return {
        "message": "Статус питомца обновлён на found",
        "data": dict(updated_pet),
    }


# --- ЭНДПОИНТЫ АВТОРИЗАЦИИ ---
@app.get("/login")
async def login_page(request: Request):
    """
    Страница входа в админку
    """
    return templates.TemplateResponse(request=request, name="login.html", context={})


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """
    Обработка формы входа и выдача токена (для админа и менеджера)
    """
    # Проверка прав
    is_admin = username == ADMIN_USERNAME and password == ADMIN_PASSWORD
    is_manager = username == MANAGER_USERNAME and password == MANAGER_PASSWORD

    if is_admin or is_manager:
        token = create_access_token(username)
        response = RedirectResponse(url="/admin", status_code=303)
        response.set_cookie(key="access_token", value=token, httponly=True)
        return response
    else:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Неверный логин или пароль"},
        )


@app.get("/logout")
async def logout():
    """
    Выход из админки и удаление токена
    """
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.get("/admin")
async def admin_panel(request: Request, admin: str = Depends(verify_admin_token)):
    async with database.pool.acquire() as conn:
        inf = await conn.fetch("SELECT * FROM lost_pets ORDER BY id DESC;")

    return templates.TemplateResponse(
        request=request, name="admin.html", context={"pets": [dict(row) for row in inf]}
    )


@app.post("/admin/delete/{fur_id}")
async def admin_delete_pet(fur_id: int, admin: str = Depends(verify_admin_token)):
    async with database.pool.acquire() as conn:
        await conn.execute("DELETE FROM lost_pets WHERE id = $1;", fur_id)

    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/found/{fur_id}")
async def admin_found_pet(fur_id: int, admin: str = Depends(verify_admin_token)):
    async with database.pool.acquire() as conn:
        await conn.execute(
            "UPDATE lost_pets SET status = 'found' WHERE id = $1;", fur_id
        )

    return RedirectResponse(url="/admin", status_code=303)
