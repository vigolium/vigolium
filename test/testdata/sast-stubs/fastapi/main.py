from fastapi import FastAPI, Path, Query, Body, Form

app = FastAPI()


@app.get("/users")
def list_users(q: str = Query(None), page: int = Query(1)):
    return {"users": [], "q": q, "page": page}


@app.post("/users")
def create_user(name: str = Body(...), email: str = Body(...)):
    return {"name": name, "email": email}


@app.get("/users/{user_id}")
def get_user(user_id: int = Path(...)):
    return {"id": user_id}


@app.put("/users/{user_id}")
def update_user(user_id: int = Path(...), name: str = Body(None)):
    return {"id": user_id, "name": name}


@app.delete("/users/{user_id}")
def delete_user(user_id: int = Path(...)):
    return {"deleted": user_id}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/items")
def list_items(category: str = Query(None), limit: int = Query(10)):
    return {"items": []}


@app.post("/items")
def create_item(title: str = Body(...), price: float = Body(...)):
    return {"title": title}


@app.get("/items/{item_id}")
def get_item(item_id: int = Path(...)):
    return {"id": item_id}


@app.patch("/items/{item_id}")
def patch_item(item_id: int = Path(...), title: str = Body(None)):
    return {"id": item_id}


@app.options("/config")
def get_config():
    return {"debug": False}
