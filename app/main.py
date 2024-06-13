from time import time
import ulid
from fastapi import FastAPI, HTTPException, status, Query, Depends
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import Field, Relationship, SQLModel, Session, create_engine, select
from pydantic import Field as PydanticField
from sqlalchemy.exc import IntegrityError  # erro ao gerar dois usernames identicos


class User(SQLModel, table=True):  # Boa prática, ter classe SQLModel para tabela
    id: str = Field(primary_key=True)
    username: str = Field(
        unique=True, index=True
    )  # unique impede gerar dois usernames idênticos
    hashed_password: str
    enabled: bool

    posts: list["Post"] = Relationship(back_populates="user")


class Post(SQLModel, table=True):
    id: str = Field(primary_key=True)
    title: str
    created_at: int
    created_by: str = Field(foreign_key="user.id")

    user: User = Relationship(back_populates="posts")


class ShowPost(BaseModel):
    id: str
    title: str
    created_at: int
    created_by: str


class CreateUser(BaseModel):  # Boa prática ter classe para lidar com FastAPI
    id: str | None = PydanticField(default_factory=lambda: str(ulid.new()))
    username: str
    password: str
    enabled: bool | None = True


class ShowUser(BaseModel):
    id: str
    username: str
    enabled: bool


class Login(BaseModel):
    username: str
    password: str


class CreatePost(BaseModel):
    id: str | None = PydanticField(default_factory=lambda: str(ulid.new()))
    title: str
    created_at: int | None = PydanticField(default_factory=lambda: int(time()))
    username: str
    password: str


class UpdatePost(BaseModel):
    title: str | None
    edited_at: int | None = PydanticField(default_factory=lambda: int(time()))
    username: str
    password: str


class UpdateUser(BaseModel):
    password: str | None = None
    enabled: bool | None = None
    old_username: str
    old_password: str


pwd_context = CryptContext(
    schemes=["bcrypt"], deprecated="auto"
)  # contexto de criptografia


def verify_password(password, hashed_password):
    return pwd_context.verify(password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def validar_usuario(login, session):
    usuario = session.exec(select(User).where(User.username == login.username)).first()
    if usuario is None:
        return False
    return verify_password(login.password, usuario.hashed_password)


def get_login(username: str = Query(), password: str = Query()):
    return Login(username=username, password=password)


postgres_url = "postgresql://user:123@localhost:5432/postgres"

engine = create_engine(postgres_url)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


app = FastAPI()


@app.on_event("startup")  # liga o servidor, cria as tabelas
def on_startup():
    create_db_and_tables()


@app.post("/usuarios/", response_model=ShowUser)
def novo_usuario(novo_usu: CreateUser):
    try:
        with Session(
            engine
        ) as session:  # abre a conexão entre o banco de dados e o código
            usuario_criado = User(
                id=novo_usu.id,
                username=novo_usu.username,
                hashed_password=get_password_hash(novo_usu.password),
                enabled=novo_usu.enabled,
            )
            session.add(usuario_criado)  # adiciona o objeto a session
            session.commit()  # adiciona o objeto no banco, e marca o objeto como desatualizado
            session.refresh(usuario_criado)  # atualiza o objeto
            usuario_retorno = ShowUser(
                id=usuario_criado.id,
                username=usuario_criado.username,
                enabled=usuario_criado.enabled,
            )
            return usuario_retorno
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Usuário existente!"
        )


@app.get("/usuarios/", response_model=list[ShowUser])
def todos_usuarios(login: Login = Depends(get_login)):
    with Session(engine) as session:
        if validar_usuario(login, session):
            all_usuario = session.exec(select(User)).all()
            retorno = []
            for usuario in all_usuario:
                retorno.append(
                    ShowUser(
                        id=usuario.id,
                        username=usuario.username,
                        enabled=usuario.enabled,
                    )
                )
            return retorno
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Senha e/ou usuário incorretos!",
            )


@app.get("/usuarios/{id_usuario}", response_model=ShowUser)
def get_usuario(id_usuario: str, login: Login = Depends(get_login)):
    with Session(engine) as session:
        if validar_usuario(login, session):
            usuario = session.exec(select(User).where(User.id == id_usuario)).first()
            if usuario is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"usuário id ={id_usuario} não encontrado",
                )
            else:
                usuario_retornado = ShowUser(
                    id=usuario.id, username=usuario.username, enabled=usuario.enabled
                )
                return usuario_retornado
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário e/ou senha incorretos!",
            )


@app.patch("/usuarios/{id_usuario}", response_model=ShowUser)
def editar_usuario(id_usuario: str, usuario_editado: UpdateUser):
    with Session(engine) as session:
        login = Login(
            username=usuario_editado.old_username, password=usuario_editado.old_password
        )
        if validar_usuario(login, session):
            contato = session.exec(select(User).where(User.id == id_usuario)).first()

            if contato is None or contato.username != login.username:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Amongus!"
                )
            if usuario_editado.password is not None:
                contato.hashed_password = get_password_hash(usuario_editado.password)
            if usuario_editado.enabled is not None:
                contato.enabled = usuario_editado.enabled
            session.add(contato)
            session.commit()
            session.refresh(contato)
            contato_show = ShowUser(
                id=contato.id, username=contato.username, enabled=contato.enabled
            )
            return contato_show
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário e/ou senha inválidos!",
            )


@app.delete("/cadastros/{id_usuario}")
def deletar_usuario(id_usuario: str, login: Login = Depends(get_login)):
    with Session(engine) as session:
        if validar_usuario(login, session):
            contato = session.exec(select(User).where(User.id == id_usuario)).first()
            if contato is None or contato.username != login.username:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Usuário não mexe nos outros usuários!",
                )
            session.delete(contato)
            session.commit()
        else:
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Não pode"
            )


@app.post("/posts/", response_model=Post)
def criar_post(novo_post: CreatePost, login: Login = Depends(get_login)):
    with Session(engine) as session:
        if validar_usuario(login, session):
            criado_por = session.exec(
                select(User).where(User.username == novo_post.username)
            ).first()
            postagem = Post(
                id=novo_post.id,
                title=novo_post.title,
                created_at=novo_post.created_at,
                created_by=criado_por.id,
            )
            session.add(postagem)
            session.commit()
            session.refresh(postagem)
            return postagem
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário e/ou senha inválidos!",
            )


@app.patch("/posts/{id_post}", response_model=Post)
def editar_post(id_post: str, post_editado: UpdatePost):
    with Session(engine) as session:
        login = Login(username=post_editado.username, password=post_editado.password)
        if validar_usuario(login, session):
            post = session.exec(select(Post).where(Post.id == id_post)).first()

            if post is None or post.user.username != login.username:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Não pode!"
                )
            if post_editado.title is not None:
                post.title = post_editado.title
                post.created_at = post_editado.edited_at
            session.add(post)
            session.commit()
            session.refresh(post)
            return post
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário e/ou senha inválidos!",
            )


@app.delete("/posts/{id_post}")
def deletar_post(id_post: str, login=Depends(get_login)):
    with Session(engine) as session:
        if validar_usuario(login, session):
            post = session.exec(select(Post).where(Post.id == id_post)).first()
            if post is None or post.user.username != login.username:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Sai daqui!"
                )
            session.delete(post)
            session.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário e/ou senha inválidos!",
            )


@app.get("/usuarios/{id_usuario}/posts/", response_model=list[ShowPost])
def get_todos_posts(id_usuario: str, login: Login = Depends(get_login)):
    with Session(engine) as session:
        if validar_usuario(login, session):
            results = session.exec(select(Post, User).join(User))
            show_post = []
            for post, user in results:
                show_post.append(
                    ShowPost(
                        id=post.id,
                        title=post.title,
                        created_by=post.created_by,
                        created_at=post.created_at,
                    )
                )
            return show_post
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário e/ou senha inválidos!",
            )


@app.get("/usuarios/posts/", response_model=list[ShowPost])
def all_posts(login: Login = Depends(get_login)):
    with Session(engine) as session:
        if validar_usuario(login, session):
            results_all = session.exec(select(Post)).all()
            all_posts = []
            for post in results_all:
                all_posts.append(
                    ShowPost(
                        id=post.id,
                        title=post.title,
                        created_by=post.created_by,
                        created_at=post.created_at,
                    )
                )
            return all_posts
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Usuário e/ou senha incorretos!!",
            )
