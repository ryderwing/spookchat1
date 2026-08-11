import os
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps

import psycopg
from flask import Flask, jsonify, request, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpookChat</title>
<style>
:root{--bg:#09070e;--panel:#100c18;--line:#272033;--purple:#8b5cf6;--purple2:#a855f7;--text:#f5f3ff;--muted:#9b93aa}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#201035 0,transparent 35%),var(--bg);color:var(--text);font:14px system-ui,sans-serif;height:100vh;overflow:hidden}
button,input,textarea{font:inherit}button{cursor:pointer;border:0}.app{height:100vh;display:flex}.sidebar{width:260px;background:#0c0911;border-right:1px solid var(--line);display:flex;flex-direction:column}
.brand{height:64px;padding:0 18px;display:flex;align-items:center;font-size:20px;font-weight:800;border-bottom:1px solid var(--line)}.brand b{color:var(--purple2)}
.nav{padding:12px}.nav button,.server{width:100%;text-align:left;background:transparent;color:#bcb4ca;padding:11px 12px;border-radius:10px;margin-bottom:5px}.nav button:hover,.server:hover{background:#1b1426;color:white}
.section{padding:14px 14px 6px;color:#756b82;font-size:11px;font-weight:800;text-transform:uppercase}
.servers{padding:0 12px;overflow:auto}.server{display:flex;gap:9px;align-items:center}.serverIcon{width:30px;height:30px;border-radius:9px;background:#241536;display:grid;place-items:center}
.main{flex:1;min-width:0;display:flex;flex-direction:column}.top{height:64px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 18px}.messages{flex:1;overflow:auto;padding:18px}.msg{padding:8px 10px;border-radius:9px}.msg:hover{background:#ffffff05}.meta{display:flex;gap:8px;align-items:center}.name{font-weight:800}.role{font-size:10px;color:#c4b5fd;background:#25183b;padding:2px 6px;border-radius:6px}.time{font-size:10px;color:#686073}.body{white-space:pre-wrap;color:#d8d2df;margin-top:3px}
.composer{padding:14px 18px;border-top:1px solid var(--line);display:flex;gap:10px}.composer input,.modal input,.modal textarea{width:100%;background:#0d0a13;border:1px solid #2b2235;color:white;border-radius:10px;padding:12px;outline:none}
.send,.primary{background:linear-gradient(135deg,var(--purple),var(--purple2));color:white;border-radius:10px;padding:0 18px;font-weight:700}.ghost{background:#1a1422;color:#ddd;padding:9px 12px;border-radius:9px}
.login{height:100vh;display:grid;place-items:center;padding:20px}.loginCard{width:min(420px,95vw);background:#100c18;border:1px solid #30263b;border-radius:20px;padding:28px}.logo{font-size:32px;font-weight:900}.logo span{color:var(--purple2)}.form{display:grid;gap:10px}.tabs{display:flex;gap:6px;margin:16px 0}.tabs button{flex:1;padding:10px;border-radius:9px;background:#18121f;color:#aaa}.tabs button.active{background:#29183d;color:white}
.modalWrap{position:fixed;inset:0;background:#000b;display:grid;place-items:center;z-index:20}.modal{width:min(480px,92vw);background:#110d18;border:1px solid #30263b;border-radius:16px;padding:20px}.actions{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}.toast{position:fixed;right:18px;bottom:18px;background:#17111f;border:1px solid #392b4b;padding:12px 15px;border-radius:10px;z-index:99}
.mobilebar{display:none}@media(max-width:850px){.sidebar{display:none}.mobilebar{display:flex;height:62px;border-top:1px solid var(--line);justify-content:space-around;align-items:center}.mobilebar button{background:transparent;color:#aaa}.messages{padding:10px}.composer{padding:10px}}
</style>
</head>
<body>
<div id="root"></div><div id="modal"></div><div id="toast"></div>
<script>
let st={me:null,profile:null,view:"public",channel:"chat1",messages:[],servers:[],activeServer:null,activeChat:null,poll:null};
const esc=s=>String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
async function api(path,opts={}){let r=await fetch(path,{headers:{"Content-Type":"application/json"},...opts});let d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Request failed");return d}
function toastMsg(x){toast.textContent=x;toast.className="toast";setTimeout(()=>toast.className="",2200)}
function openModal(t,b){modal.innerHTML=`<div class="modalWrap" onclick="if(event.target===this)closeModal()"><div class="modal"><h2>${t}</h2>${b}</div></div>`}
function closeModal(){modal.innerHTML=""}
async function boot(){try{let d=await api("/api/me");st.me=d.user;st.profile=d.profile;st.servers=(await api("/api/servers")).servers;render()}catch(e){renderLogin()}}
function renderLogin(){root.innerHTML=`<div class="login"><div class="loginCard"><div class="logo">Spook<span>Chat</span></div><p style="color:#9b93aa">Login or create an account.</p><div class="tabs"><button id="lt" class="active" onclick="authForm('login')">Login</button><button id="rt" onclick="authForm('register')">Register</button></div><div id="auth"></div></div></div>`;authForm("login")}
function authForm(mode){lt.classList.toggle("active",mode==="login");rt.classList.toggle("active",mode==="register");auth.innerHTML=`<form class="form" onsubmit="doAuth(event,'${mode}')">${mode==="register"?'<input id="username" placeholder="Username" maxlength="32" required>':''}<input id="email" type="email" placeholder="Email" required><input id="password" type="password" minlength="8" placeholder="Password" required><button class="primary" style="height:44px">${mode==="register"?"Create account":"Login"}</button></form>`}
async function doAuth(e,mode){e.preventDefault();try{let b={email:email.value,password:password.value};if(mode==="register")b.username=username.value;await api("/api/"+mode,{method:"POST",body:JSON.stringify(b)});await boot()}catch(e){toastMsg(e.message)}}
function render(){clearInterval(st.poll);root.innerHTML=`<div class="app"><aside class="sidebar"><div class="brand">👻 Spook<b>Chat</b></div><div class="section">Public</div><div class="nav"><button onclick="openPublic('chat1')">💬 Chat 1</button><button onclick="openPublic('chat2')">💬 Chat 2</button></div><div class="section">Direct</div><div class="nav"><button onclick="friends()">👥 Friends</button><button onclick="groupCreate()">➕ Group Chat</button></div><div class="section">Servers <button style="float:right;background:none;color:#a78bfa" onclick="serverCreate()">＋</button></div><div class="servers">${st.servers.map(s=>`<button class="server" onclick="openServer(${s.id})"><span class="serverIcon">${esc(s.name[0].toUpperCase())}</span>${esc(s.name)}</button>`).join("")}</div><div style="margin-top:auto;padding:12px"><button class="ghost" style="width:100%" onclick="editProfile()">⚙ Profile</button><button class="ghost" style="width:100%;margin-top:6px" onclick="logout()">Log out</button></div></aside><main class="main"><div class="top"><b id="title">${st.view==="public"?(st.channel==="chat1"?"Chat 1":"Chat 2"):"Chat"}</b></div><div class="messages" id="messages"></div><div class="composer"><input id="messageInput" maxlength="4000" placeholder="Message..." onkeydown="if(event.key==='Enter'){event.preventDefault();sendMessage()}"><button class="send" onclick="sendMessage()">Send</button></div><div class="mobilebar"><button onclick="openPublic('chat1')">💬 Chat</button><button onclick="friends()">👥 Friends</button><button onclick="groupCreate()">➕ Group</button><button onclick="editProfile()">👤 Profile</button></div></main></div>`;loadMessages();st.poll=setInterval(loadMessages,1200)}
function openPublic(c){st.view="public";st.channel=c;st.activeServer=null;st.activeChat=null;render()}
function openServer(id){st.view="server";st.activeServer=id;st.channel="chat";render();let s=st.servers.find(x=>x.id===id);title.textContent=s?.name||"Server"}
async function loadMessages(){try{let q=st.view==="public"?`/api/messages?kind=public&channel=${st.channel}`:st.view==="server"?`/api/messages?kind=server&channel=chat&server_id=${st.activeServer}`:`/api/messages?kind=dm&chat_id=${st.activeChat}`;st.messages=(await api(q)).messages;draw()}catch(e){}}
function draw(){if(!messages)return;let near=messages.scrollHeight-messages.scrollTop-messages.clientHeight<100;messages.innerHTML=st.messages.map(m=>`<div class="msg"><div class="meta"><span class="name">${esc(m.username)}</span>${m.role&&m.role!=="user"&&m.role!=="member"?`<span class="role">${esc(m.role)}</span>`:""}<span class="time">${new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span></div><div class="body">${esc(m.content)}</div></div>`).join("")||"<div style='color:#777'>No messages yet.</div>";if(near)messages.scrollTop=messages.scrollHeight}
async function sendMessage(){let content=messageInput.value.trim();if(!content)return;let b={content};if(st.view==="public"){b.kind="public";b.channel=st.channel}else if(st.view==="server"){b.kind="server";b.channel="chat";b.server_id=st.activeServer}else{b.kind="dm";b.chat_id=st.activeChat}try{await api("/api/messages",{method:"POST",body:JSON.stringify(b)});messageInput.value="";loadMessages()}catch(e){toastMsg(e.message)}}
async function friends(){try{let d=await api("/api/friends");openModal("Friends",d.friends.map(f=>`<div style="display:flex;justify-content:space-between;padding:8px">${esc(f.username)}<button class="ghost" onclick="startDM(${f.id});closeModal()">Message</button></div>`).join("")||"<p>No friends yet.</p>")}catch(e){toastMsg(e.message)}}
async function startDM(id){let d=await api("/api/dms",{method:"POST",body:JSON.stringify({user_id:id})});st.view="dm";st.activeChat=d.chat_id;render()}
function groupCreate(){openModal("Create Group",`<form class="form" onsubmit="makeGroup(event)"><input id="gname" placeholder="Group name" required><input id="gmembers" placeholder="Usernames, comma separated"><button class="primary" style="height:42px">Create</button></form>`)}
async function makeGroup(e){e.preventDefault();let d=await api("/api/groups",{method:"POST",body:JSON.stringify({name:gname.value,usernames:gmembers.value.split(",").map(x=>x.trim()).filter(Boolean)})});closeModal();st.view="dm";st.activeChat=d.chat_id;render()}
function editProfile(){openModal("Edit Profile",`<form class="form" onsubmit="saveProfile(event)"><input id="pname" value="${esc(st.profile.username)}" placeholder="Name"><input id="pronouns" value="${esc(st.profile.pronouns||"")}" placeholder="Pronouns"><input id="company" value="${esc(st.profile.company||"")}" placeholder="Company"><textarea id="desc" placeholder="Description">${esc(st.profile.description||"")}</textarea><input id="avatar" value="${esc(st.profile.avatar||"")}" placeholder="Avatar URL"><button class="primary" style="height:42px">Save</button></form>`)}
async function saveProfile(e){e.preventDefault();let d=await api("/api/profile",{method:"PATCH",body:JSON.stringify({username:pname.value,pronouns:pronouns.value,company:company.value,description:desc.value,avatar:avatar.value})});st.profile=d.profile;closeModal();render()}
function serverCreate(){openModal("Create Server",`<form class="form" onsubmit="makeServer(event)"><input id="sname" placeholder="Server name" required><button class="primary" style="height:42px">Create</button></form>`)}
async function makeServer(e){e.preventDefault();await api("/api/servers",{method:"POST",body:JSON.stringify({name:sname.value})});closeModal();st.servers=(await api("/api/servers")).servers;render()}
async function logout(){await api("/api/logout",{method:"POST"});location.reload()}
boot();
</script>
</body>
</html>
"""

SCHEMA = """
create table if not exists users(
 id bigserial primary key,
 email text not null unique,
 username text not null unique,
 password_hash text not null,
 description text not null default '',
 avatar text not null default '',
 pronouns text not null default '',
 company text not null default '',
 global_role text not null default 'user',
 banned_until timestamptz,
 created_at timestamptz not null default now()
);
create table if not exists friends(
 user_a bigint references users(id) on delete cascade,
 user_b bigint references users(id) on delete cascade,
 primary key(user_a,user_b)
);
create table if not exists servers(
 id bigserial primary key,
 owner_id bigint not null references users(id) on delete cascade,
 name text not null,
 icon text not null default '',
 created_at timestamptz not null default now()
);
create table if not exists server_members(
 server_id bigint references servers(id) on delete cascade,
 user_id bigint references users(id) on delete cascade,
 role text not null default 'member',
 banned_until timestamptz,
 muted_until timestamptz,
 primary key(server_id,user_id)
);
create table if not exists chats(
 id bigserial primary key,
 kind text not null,
 name text not null default '',
 owner_id bigint references users(id) on delete set null,
 created_at timestamptz not null default now()
);
create table if not exists chat_members(
 chat_id bigint references chats(id) on delete cascade,
 user_id bigint references users(id) on delete cascade,
 role text not null default 'member',
 primary key(chat_id,user_id)
);
create table if not exists messages(
 id bigserial primary key,
 user_id bigint not null references users(id) on delete cascade,
 content text not null,
 kind text not null,
 channel text,
 server_id bigint references servers(id) on delete cascade,
 chat_id bigint references chats(id) on delete cascade,
 created_at timestamptz not null default now()
);
create table if not exists reports(
 id bigserial primary key,
 reporter_id bigint references users(id) on delete set null,
 message_id bigint references messages(id) on delete set null,
 message_snapshot text not null,
 reported_user_id bigint references users(id) on delete set null,
 status text not null default 'open',
 created_at timestamptz not null default now()
);
create table if not exists ip_bans(
 ip text primary key,
 banned_until timestamptz,
 reason text not null default ''
);
"""

def connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing. Add it in Vercel Settings > Environment Variables.")
    return psycopg.connect(DATABASE_URL)

def init_db():
    if not DATABASE_URL:
        return
    try:
        with connect() as c:
            c.execute(SCHEMA)
            c.commit()
    except Exception as e:
        print("DATABASE INITIALIZATION ERROR:", repr(e))

init_db()

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    with connect() as c:
        r = c.execute("""select id,email,username,description,avatar,pronouns,company,global_role,banned_until
                         from users where id=%s""",(uid,)).fetchone()
    if not r:
        return None
    keys=["id","email","username","description","avatar","pronouns","company","global_role","banned_until"]
    return dict(zip(keys,r))

def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        u=current_user()
        if not u:
            return jsonify(error="Not logged in"),401
        if u["banned_until"] and u["banned_until"] > datetime.now(timezone.utc):
            return jsonify(error="Account banned"),403
        request.me=u
        return fn(*args, **kwargs)
    return wrap

def server_member(sid, uid):
    with connect() as c:
        r=c.execute("select role,banned_until,muted_until from server_members where server_id=%s and user_id=%s",(sid,uid)).fetchone()
    return {"role":r[0],"banned_until":r[1],"muted_until":r[2]} if r else None

@app.get("/")
def home():
    return render_template_string(HTML)

@app.get("/api/health")
def health():
    try:
        with connect() as c:
            c.execute("select 1").fetchone()
        return jsonify(ok=True,database=True)
    except Exception as e:
        return jsonify(ok=False,database=False,error=str(e)),500

@app.post("/api/register")
def register():
    d=request.get_json(silent=True) or {}
    email=str(d.get("email","")).strip().lower()
    username=str(d.get("username","")).strip()
    password=str(d.get("password",""))

    if not email or len(username)<2 or len(username)>32 or len(password)<8:
        return jsonify(error="Use a valid email, username, and password of at least 8 characters."),400

    try:
        with connect() as c:
            count=c.execute("select count(*) from users").fetchone()[0]
            role="owner" if count==0 else "user"
            uid=c.execute(
                "insert into users(email,username,password_hash,global_role) values(%s,%s,%s,%s) returning id",
                (email,username,generate_password_hash(password),role)
            ).fetchone()[0]
            c.commit()
        session["uid"]=uid
        return jsonify(ok=True)
    except psycopg.errors.UniqueViolation:
        return jsonify(error="That email or username is already registered."),409
    except Exception as e:
        print("REGISTER ERROR:", repr(e))
        return jsonify(error="Database error while creating account. Check DATABASE_URL and Vercel logs."),500

@app.post("/api/login")
def login():
    d=request.get_json(silent=True) or {}
    try:
        with connect() as c:
            r=c.execute("select id,password_hash,banned_until from users where lower(email)=lower(%s)",(str(d.get("email","")).strip(),)).fetchone()
    except Exception as e:
        print("LOGIN ERROR:", repr(e))
        return jsonify(error="Database connection failed."),500
    if not r or not check_password_hash(r[1],str(d.get("password",""))):
        return jsonify(error="Invalid email or password"),401
    if r[2] and r[2] > datetime.now(timezone.utc):
        return jsonify(error="Account banned"),403
    session["uid"]=r[0]
    return jsonify(ok=True)

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
@login_required
def me():
    u=request.me
    return jsonify(user={"id":u["id"],"email":u["email"]},
                   profile={k:u[k] for k in ["id","username","description","avatar","pronouns","company","global_role"]})

@app.get("/api/profile/<int:uid>")
@login_required
def get_profile(uid):
    with connect() as c:
        r=c.execute("select id,username,description,avatar,pronouns,company,global_role from users where id=%s",(uid,)).fetchone()
    if not r:return jsonify(error="User not found"),404
    return jsonify(profile=dict(zip(["id","username","description","avatar","pronouns","company","global_role"],r)))

@app.patch("/api/profile")
@login_required
def edit_profile():
    d=request.get_json(silent=True) or {}
    username=str(d.get("username","")).strip()
    if not 2<=len(username)<=32:return jsonify(error="Invalid username"),400
    try:
        with connect() as c:
            c.execute("update users set username=%s,description=%s,avatar=%s,pronouns=%s,company=%s where id=%s",
                      (username,str(d.get("description",""))[:300],str(d.get("avatar",""))[:500],
                       str(d.get("pronouns",""))[:40],str(d.get("company",""))[:80],request.me["id"]))
            c.commit()
    except psycopg.errors.UniqueViolation:
        return jsonify(error="Username taken"),409
    u=current_user()
    return jsonify(profile={k:u[k] for k in ["id","username","description","avatar","pronouns","company","global_role"]})

@app.get("/api/servers")
@login_required
def get_servers():
    with connect() as c:
        rows=c.execute("""select s.id,s.name,s.icon,sm.role
                          from servers s join server_members sm on sm.server_id=s.id
                          where sm.user_id=%s order by s.created_at""",(request.me["id"],)).fetchall()
    return jsonify(servers=[{"id":r[0],"name":r[1],"icon":r[2],"role":r[3]} for r in rows])

@app.post("/api/servers")
@login_required
def create_server():
    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip()[:60]
    if not name:return jsonify(error="Server name required"),400
    with connect() as c:
        sid=c.execute("insert into servers(owner_id,name) values(%s,%s) returning id",(request.me["id"],name)).fetchone()[0]
        c.execute("insert into server_members(server_id,user_id,role) values(%s,%s,'owner')",(sid,request.me["id"]))
        c.commit()
    return jsonify(id=sid)

@app.get("/api/messages")
@login_required
def get_messages():
    kind=request.args.get("kind")
    channel=request.args.get("channel")
    sid=request.args.get("server_id")
    cid=request.args.get("chat_id")

    with connect() as c:
        if kind=="public":
            rows=c.execute("""select m.id,m.user_id,m.content,m.created_at,u.username,u.avatar,u.global_role
                              from messages m join users u on u.id=m.user_id
                              where m.kind='public' and m.channel=%s order by m.created_at desc limit 150""",(channel,)).fetchall()
        elif kind=="server":
            if not server_member(sid,request.me["id"]):return jsonify(error="Not a member"),403
            rows=c.execute("""select m.id,m.user_id,m.content,m.created_at,u.username,u.avatar,sm.role
                              from messages m join users u on u.id=m.user_id
                              left join server_members sm on sm.server_id=m.server_id and sm.user_id=m.user_id
                              where m.kind='server' and m.server_id=%s and m.channel=%s
                              order by m.created_at desc limit 150""",(sid,channel)).fetchall()
        else:
            ok=c.execute("select 1 from chat_members where chat_id=%s and user_id=%s",(cid,request.me["id"])).fetchone()
            if not ok:return jsonify(error="Not a chat member"),403
            rows=c.execute("""select m.id,m.user_id,m.content,m.created_at,u.username,u.avatar,u.global_role
                              from messages m join users u on u.id=m.user_id
                              where m.kind='dm' and m.chat_id=%s order by m.created_at desc limit 150""",(cid,)).fetchall()

    return jsonify(messages=[
        {"id":r[0],"user_id":r[1],"content":r[2],"created_at":r[3].isoformat(),"username":r[4],"avatar":r[5],"role":r[6]}
        for r in reversed(rows)
    ])

@app.post("/api/messages")
@login_required
def post_message():
    d=request.get_json(silent=True) or {}
    content=str(d.get("content","")).strip()
    kind=d.get("kind")
    if not content or len(content)>4000 or kind not in ("public","server","dm"):
        return jsonify(error="Invalid message"),400

    sid=d.get("server_id"); cid=d.get("chat_id"); channel=d.get("channel")

    if kind=="server":
        sm=server_member(sid,request.me["id"])
        now=datetime.now(timezone.utc)
        if not sm:return jsonify(error="Not a member"),403
        if sm["banned_until"] and sm["banned_until"]>now:return jsonify(error="Banned from server"),403
        if sm["muted_until"] and sm["muted_until"]>now:return jsonify(error="Restricted from talking"),403

    if kind=="dm":
        with connect() as c:
            if not c.execute("select 1 from chat_members where chat_id=%s and user_id=%s",(cid,request.me["id"])).fetchone():
                return jsonify(error="Not in chat"),403

    with connect() as c:
        mid=c.execute("""insert into messages(user_id,content,kind,channel,server_id,chat_id)
                         values(%s,%s,%s,%s,%s,%s) returning id""",
                      (request.me["id"],content,kind,channel,sid,cid)).fetchone()[0]
        c.commit()
    return jsonify(id=mid)

@app.get("/api/friends")
@login_required
def get_friends():
    with connect() as c:
        rows=c.execute("""select u.id,u.username,u.avatar
                          from friends f
                          join users u on u.id=(case when f.user_a=%s then f.user_b else f.user_a end)
                          where f.user_a=%s or f.user_b=%s order by u.username""",
                       (request.me["id"],request.me["id"],request.me["id"])).fetchall()
    return jsonify(friends=[{"id":r[0],"username":r[1],"avatar":r[2]} for r in rows])

@app.post("/api/friends")
@login_required
def add_friend():
    d=request.get_json(silent=True) or {}
    target=int(d.get("user_id") or 0)
    if not target or target==request.me["id"]:return jsonify(error="Invalid user"),400
    a,b=sorted([request.me["id"],target])
    with connect() as c:
        c.execute("insert into friends(user_a,user_b) values(%s,%s) on conflict do nothing",(a,b))
        c.commit()
    return jsonify(ok=True)

@app.post("/api/dms")
@login_required
def make_dm():
    target=int((request.get_json(silent=True) or {}).get("user_id") or 0)
    if not target or target==request.me["id"]:return jsonify(error="Invalid user"),400
    with connect() as c:
        r=c.execute("""select c.id from chats c
                       join chat_members a on a.chat_id=c.id
                       join chat_members b on b.chat_id=c.id
                       where c.kind='dm' and a.user_id=%s and b.user_id=%s limit 1""",
                    (request.me["id"],target)).fetchone()
        if r:return jsonify(chat_id=r[0])
        cid=c.execute("insert into chats(kind,owner_id) values('dm',%s) returning id",(request.me["id"],)).fetchone()[0]
        c.execute("insert into chat_members(chat_id,user_id) values(%s,%s),(%s,%s)",
                  (cid,request.me["id"],cid,target))
        c.commit()
    return jsonify(chat_id=cid)

@app.post("/api/groups")
@login_required
def make_group():
    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip()[:50]
    if not name:return jsonify(error="Group name required"),400
    with connect() as c:
        cid=c.execute("insert into chats(kind,name,owner_id) values('group',%s,%s) returning id",
                      (name,request.me["id"])).fetchone()[0]
        c.execute("insert into chat_members(chat_id,user_id,role) values(%s,%s,'owner')",(cid,request.me["id"]))
        for uname in (d.get("usernames") or [])[:50]:
            u=c.execute("select id from users where lower(username)=lower(%s)",(uname,)).fetchone()
            if u:c.execute("insert into chat_members(chat_id,user_id) values(%s,%s) on conflict do nothing",(cid,u[0]))
        c.commit()
    return jsonify(chat_id=cid)

@app.post("/api/reports")
@login_required
def report():
    mid=(request.get_json(silent=True) or {}).get("message_id")
    with connect() as c:
        m=c.execute("select content,user_id from messages where id=%s",(mid,)).fetchone()
        if not m:return jsonify(error="Message not found"),404
        c.execute("""insert into reports(reporter_id,message_id,message_snapshot,reported_user_id)
                     values(%s,%s,%s,%s)""",(request.me["id"],mid,m[0],m[1]))
        c.commit()
    return jsonify(ok=True)
