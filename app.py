import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests
import psycopg
from flask import Flask, jsonify, request, session, render_template_string
from flask_cors import CORS

# ============================================================
# SpookChat - 3-file Vercel/Supabase app
# Environment variables required on Vercel:
#
# SUPABASE_URL
# SUPABASE_ANON_KEY
# SUPABASE_SERVICE_ROLE_KEY
# SUPABASE_DB_URL
# FLASK_SECRET_KEY
#
# SUPABASE_DB_URL is the Supabase Postgres connection string.
# ============================================================

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CHANGE-ME-IN-PRODUCTION")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
CORS(app, supports_credentials=True)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
DB_URL = os.environ.get("SUPABASE_DB_URL", "")

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpookChat</title>
<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
<style>
:root{--bg:#09070e;--panel:#100c18;--panel2:#151020;--line:#272033;--purple:#8b5cf6;--purple2:#a855f7;--text:#f5f3ff;--muted:#9b93aa;--danger:#ef4444;--ok:#22c55e}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#201035 0,transparent 35%),var(--bg);color:var(--text);font:14px Inter,system-ui,sans-serif;height:100vh;overflow:hidden}
button,input,textarea{font:inherit}button{cursor:pointer;border:0}.hidden{display:none!important}
.app{height:100vh;display:flex}.sidebar{width:260px;background:rgba(12,9,17,.94);border-right:1px solid var(--line);display:flex;flex-direction:column}
.brand{height:64px;padding:0 18px;display:flex;align-items:center;font-size:20px;font-weight:800;border-bottom:1px solid var(--line)}.brand b{color:var(--purple2)}
.nav{padding:12px}.nav button,.server{width:100%;text-align:left;background:transparent;color:#bcb4ca;padding:11px 12px;border-radius:10px;margin-bottom:5px}.nav button:hover,.server:hover,.nav button.active{background:#1b1426;color:white}
.section{padding:14px 14px 6px;color:#756b82;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em}
.servers{padding:0 12px;overflow:auto}.server{display:flex;align-items:center;gap:9px}.serverIcon{width:30px;height:30px;border-radius:9px;background:#241536;display:grid;place-items:center;color:#c4b5fd;font-weight:800}
.main{flex:1;min-width:0;display:flex;flex-direction:column}.top{height:64px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 18px;background:rgba(10,7,15,.72);backdrop-filter:blur(12px)}.top h2{margin:0;font-size:16px}.top small{color:var(--muted);margin-left:10px}
.messages{flex:1;overflow:auto;padding:20px}.msg{display:flex;gap:11px;padding:8px 10px;border-radius:9px}.msg:hover{background:rgba(255,255,255,.025)}.avatar{width:38px;height:38px;border-radius:50%;object-fit:cover;background:#26153d;flex:none}.bubble{max-width:800px}.meta{display:flex;align-items:center;gap:8px}.name{font-weight:750}.role{font-size:10px;color:#c4b5fd;background:#25183b;padding:2px 6px;border-radius:6px}.time{font-size:10px;color:#686073}.body{white-space:pre-wrap;color:#d8d2df;line-height:1.5;margin-top:2px}
.composer{padding:14px 18px;border-top:1px solid var(--line);display:flex;gap:10px}.composer input,.modal input,.modal textarea{width:100%;background:#0d0a13;border:1px solid #2b2235;color:white;border-radius:10px;padding:12px;outline:none}.composer input:focus,.modal input:focus,.modal textarea:focus{border-color:var(--purple)}.send,.primary{background:linear-gradient(135deg,var(--purple),var(--purple2));color:white;border-radius:10px;padding:0 18px;font-weight:700}.danger{background:#32131a;color:#ff9ca6}.ghost{background:#1a1422;color:#ddd;padding:9px 12px;border-radius:9px}
.profile{width:300px;border-left:1px solid var(--line);background:#0d0a13;padding:18px;overflow:auto}.profile img{width:76px;height:76px;border-radius:50%;object-fit:cover;background:#241536}.profile h3{margin-bottom:4px}.muted{color:var(--muted)}
.mobilebar{display:none}.empty{height:100%;display:grid;place-items:center;color:#776d83;text-align:center}
.modalWrap{position:fixed;inset:0;background:rgba(0,0,0,.7);display:grid;place-items:center;z-index:20}.modal{width:min(480px,92vw);background:#110d18;border:1px solid #30263b;border-radius:16px;padding:20px;box-shadow:0 25px 100px #000}.modal h2{margin-top:0}.form{display:grid;gap:10px}.actions{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}
.login{height:100vh;display:grid;place-items:center;padding:20px}.loginCard{width:min(420px,95vw);background:rgba(16,12,24,.94);border:1px solid #30263b;border-radius:20px;padding:28px;box-shadow:0 30px 100px #000}.logo{font-size:32px;font-weight:900;margin-bottom:4px}.logo span{color:var(--purple2)}.loginCard p{color:var(--muted)}.tab{display:flex;gap:6px;margin-bottom:16px}.tab button{flex:1;padding:10px;border-radius:9px;background:#18121f;color:#aaa}.tab button.active{background:#29183d;color:#fff}.context{position:fixed;z-index:50;background:#17111f;border:1px solid #382b48;border-radius:10px;padding:6px;box-shadow:0 15px 50px #000;min-width:190px}.context button{display:block;width:100%;background:transparent;color:#ddd;text-align:left;padding:9px;border-radius:7px}.context button:hover{background:#271936}.toast{position:fixed;right:18px;bottom:18px;background:#17111f;border:1px solid #392b4b;padding:12px 15px;border-radius:10px;z-index:99}
@media(max-width:850px){.sidebar{display:none}.profile{display:none}.mobilebar{display:flex;height:62px;border-top:1px solid var(--line);background:#0d0a13;justify-content:space-around;align-items:center}.mobilebar button{background:transparent;color:#a59bb2;font-size:12px}.mobilebar button.active{color:#c4b5fd}.messages{padding:12px}.composer{padding:10px}.top{height:58px}.msg{padding:7px 3px}}
</style>
</head>
<body>
<div id="root"></div>
<div id="modal"></div>
<div id="toast"></div>
<script>
const SB_URL = {{ supabase_url|tojson }};
const SB_KEY = {{ anon_key|tojson }};
const sb = (SB_URL && SB_KEY) ? supabase.createClient(SB_URL, SB_KEY) : null;
let state={user:null,profile:null,view:"public",channel:"chat1",messages:[],servers:[],friends:[],activeServer:null,activeChat:null,people:[]};
let poll=null, realtime=null;

const esc=s=>String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
async function api(path,opts={}){let r=await fetch(path,{credentials:"include",headers:{"Content-Type":"application/json",...(opts.headers||{})},...opts});let d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Request failed");return d}
function toast(x){let e=document.getElementById("toast");e.textContent=x;e.className="toast";setTimeout(()=>e.className="",2600)}
function openModal(title,body){document.getElementById("modal").innerHTML=`<div class="modalWrap" onclick="if(event.target===this)closeModal()"><div class="modal"><h2>${title}</h2>${body}</div></div>`}
function closeModal(){document.getElementById("modal").innerHTML=""}

async function boot(){
 try{let d=await api("/api/me");state.user=d.user;state.profile=d.profile;await loadData();render();startRealtime();}catch(e){renderLogin()}
}
async function loadData(){state.servers=(await api("/api/servers")).servers;state.friends=(await api("/api/friends")).friends}
function renderLogin(){
 document.getElementById("root").innerHTML=`<div class="login"><div class="loginCard"><div class="logo">Spook<span>Chat</span></div><p>Real-time communities without the clutter.</p><div class="tab"><button id="lt" class="active" onclick="showAuth('login')">Login</button><button id="rt" onclick="showAuth('register')">Register</button></div><div id="auth"></div></div></div>`;showAuth("login")
}
function showAuth(mode){
 document.getElementById("lt").classList.toggle("active",mode==="login");document.getElementById("rt").classList.toggle("active",mode==="register");
 document.getElementById("auth").innerHTML=`<form class="form" onsubmit="auth(event,'${mode}')">${mode==="register"?'<input id="username" placeholder="Username" maxlength="32" required>':''}<input id="email" type="email" placeholder="Email" required><input id="password" type="password" minlength="8" placeholder="Password" required><button class="primary" style="height:44px">${mode==="register"?"Create account":"Login"}</button></form>`;
}
async function auth(ev,mode){ev.preventDefault();try{let body={email:email.value,password:password.value};if(mode==="register")body.username=username.value;await api("/api/"+mode,{method:"POST",body:JSON.stringify(body)});toast(mode==="register"?"Account created":"Welcome back");await boot()}catch(e){toast(e.message)}}

function render(){
 let canStaff=["owner","admin","moderator"].includes(state.profile?.global_role);
 document.getElementById("root").innerHTML=`<div class="app">
 <aside class="sidebar"><div class="brand">👻 Spook<b>Chat</b></div>
 <div class="section">Public</div><div class="nav"><button class="${state.view==='public'?'active':''}" onclick="publicChat('chat1')">💬 Chat 1</button><button onclick="publicChat('chat2')">💬 Chat 2</button></div>
 <div class="section">Direct</div><div class="nav"><button onclick="showFriends()">👥 Friends</button><button onclick="showGroupCreate()">➕ Group Chat</button></div>
 <div class="section">Servers <button style="float:right;background:transparent;color:#a78bfa" onclick="createServer()">＋</button></div><div class="servers">${state.servers.map(s=>`<button class="server" onclick="openServer('${s.id}','chat')"><span class="serverIcon">${esc((s.name||'S')[0].toUpperCase())}</span>${esc(s.name)}</button>`).join("")}</div>
 <div style="margin-top:auto;padding:12px"><button class="ghost" style="width:100%" onclick="editProfile()">⚙ Profile</button><button class="ghost" style="width:100%;margin-top:6px" onclick="logout()">Log out</button></div></aside>
 <main class="main"><div class="top"><h2 id="title">Chat 1</h2><small id="subtitle">Public</small></div><div class="messages" id="messages"></div><div class="composer"><input id="messageInput" maxlength="4000" placeholder="Message..." onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage()}"><button class="send" onclick="sendMessage()">Send</button></div><div class="mobilebar"><button onclick="publicChat('chat1')">💬<br>Chat</button><button onclick="showFriends()">👥<br>Friends</button><button onclick="showGroupCreate()">➕<br>Group</button><button onclick="editProfile()">👤<br>Profile</button></div></main>
 </div>`;
 loadMessages();
}
function publicChat(c){state.view="public";state.channel=c;state.activeServer=null;state.activeChat=null;render()}
function openServer(id,ch){state.view="server";state.channel=ch;state.activeServer=id;let s=state.servers.find(x=>x.id===id);render();document.getElementById("title").textContent=s?.name||"Server";document.getElementById("subtitle").textContent=ch==="announcement"?"Announcements":"Server chat"}
async function loadMessages(){
 try{let q=state.view==="public"?`/api/messages?kind=public&channel=${state.channel}`:state.view==="server"?`/api/messages?kind=server&channel=${state.channel}&server_id=${state.activeServer}`:`/api/messages?kind=dm&chat_id=${state.activeChat}`;state.messages=(await api(q)).messages;drawMessages()}catch(e){toast(e.message)}
}
function drawMessages(){
 let el=document.getElementById("messages");if(!el)return;
 if(!state.messages.length){el.innerHTML='<div class="empty">No messages yet.<br>Start the conversation.</div>';return}
 el.innerHTML=state.messages.map(m=>`<div class="msg" oncontextmenu="messageMenu(event,'${m.id}')"><img class="avatar" src="${esc(m.avatar||'')}" onerror="this.style.display='none'"><div class="bubble"><div class="meta"><span class="name">${esc(m.username)}</span>${m.role&&m.role!=="member"?`<span class="role">${esc(m.role)}</span>`:""}<span class="time">${new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span></div><div class="body">${esc(m.content)}</div></div></div>`).join("");el.scrollTop=el.scrollHeight}
async function sendMessage(){let inp=document.getElementById("messageInput"),content=inp.value.trim();if(!content)return;try{let b={content};if(state.view==="public"){b.kind="public";b.channel=state.channel}else if(state.view==="server"){b.kind="server";b.channel=state.channel;b.server_id=state.activeServer}else{b.kind="dm";b.chat_id=state.activeChat}await api("/api/messages",{method:"POST",body:JSON.stringify(b)});inp.value="";await loadMessages()}catch(e){toast(e.message)}}
function messageMenu(ev,id){ev.preventDefault();document.querySelectorAll(".context").forEach(x=>x.remove());let m=state.messages.find(x=>x.id===id),mine=m?.user_id===state.user.id,staff=["owner","admin","moderator"].includes(state.profile.global_role);let html=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-210)}px;top:${Math.min(ev.clientY,innerHeight-220)}px" onclick="event.stopPropagation()"><button onclick="viewProfile('${m.user_id}');this.parentElement.remove()">👤 View Profile</button><button onclick="navigator.clipboard.writeText(${JSON.stringify(m.content)});this.parentElement.remove()">📋 Copy Message</button><button onclick="reportMessage('${id}');this.parentElement.remove()">🚩 Report Message</button>${mine||staff?`<button class="danger" onclick="deleteMessage('${id}');this.parentElement.remove()">🗑 Delete Message</button>`:""}</div>`;document.body.insertAdjacentHTML("beforeend",html)}
document.addEventListener("click",()=>document.querySelectorAll(".context").forEach(x=>x.remove()));
async function deleteMessage(id){try{await api("/api/messages/"+id,{method:"DELETE"});await loadMessages()}catch(e){toast(e.message)}}
async function reportMessage(id){try{await api("/api/reports",{method:"POST",body:JSON.stringify({message_id:id})});toast("Report sent to staff")}catch(e){toast(e.message)}}
async function viewProfile(id){try{let d=await api("/api/profile/"+id);openModal("Profile",`<img class="avatar" style="width:90px;height:90px" src="${esc(d.profile.avatar||'')}" onerror="this.style.display='none'"><h3>${esc(d.profile.username)}</h3><p class="muted">${esc(d.profile.pronouns||"")}</p><p>${esc(d.profile.description||"No description.")}</p><p class="muted">${esc(d.profile.company||"")}</p><div class="actions"><button class="primary" onclick="addFriend('${id}');closeModal()">Add Friend</button><button class="ghost" onclick="closeModal()">Close</button></div>`)}catch(e){toast(e.message)}}
async function addFriend(id){try{await api("/api/friends",{method:"POST",body:JSON.stringify({user_id:id})});toast("Friend request sent")}catch(e){toast(e.message)}}
async function showFriends(){let d=await api("/api/friends");openModal("Friends",`<div>${d.friends.length?d.friends.map(f=>`<div style="display:flex;align-items:center;gap:10px;padding:9px"><img class="avatar" style="width:34px;height:34px" src="${esc(f.avatar||'')}" onerror="this.style.display='none'"><span>${esc(f.username)}</span><button class="ghost" style="margin-left:auto" onclick="startDM('${f.id}');closeModal()">Message</button></div>`).join(""):"<p class='muted'>No friends yet.</p>"}</div><div class="actions"><button class="ghost" onclick="closeModal()">Close</button></div>`)}
async function startDM(id){let d=await api("/api/dms",{method:"POST",body:JSON.stringify({user_id:id})});state.view="dm";state.activeChat=d.chat_id;render()}
function showGroupCreate(){openModal("Create group chat",`<form class="form" onsubmit="createGroup(event)"><input id="gname" maxlength="50" placeholder="Group name" required><input id="gmembers" placeholder="Friend usernames, comma separated"><div class="actions"><button type="button" class="ghost" onclick="closeModal()">Cancel</button><button class="primary">Create</button></div></form>`)}
async function createGroup(e){e.preventDefault();try{let d=await api("/api/groups",{method:"POST",body:JSON.stringify({name:gname.value,usernames:gmembers.value.split(",").map(x=>x.trim()).filter(Boolean)})});closeModal();state.view="dm";state.activeChat=d.chat_id;render()}catch(e){toast(e.message)}}
function editProfile(){openModal("Edit profile",`<form class="form" onsubmit="saveProfile(event)"><input id="pname" maxlength="32" value="${esc(state.profile.username)}" placeholder="Name"><input id="pronouns" maxlength="40" value="${esc(state.profile.pronouns||"")}" placeholder="Pronouns"><input id="company" maxlength="80" value="${esc(state.profile.company||"")}" placeholder="Company name"><textarea id="desc" maxlength="300" placeholder="Description">${esc(state.profile.description||"")}</textarea><input id="avatar" maxlength="500" value="${esc(state.profile.avatar||"")}" placeholder="Profile picture URL"><div class="actions"><button type="button" class="ghost" onclick="closeModal()">Cancel</button><button class="primary">Save</button></div></form>`)}
async function saveProfile(e){e.preventDefault();try{let d=await api("/api/profile",{method:"PATCH",body:JSON.stringify({username:pname.value,pronouns:pronouns.value,company:company.value,description:desc.value,avatar:avatar.value})});state.profile=d.profile;closeModal();render();toast("Profile saved")}catch(e){toast(e.message)}}
async function createServer(){openModal("Create server",`<form class="form" onsubmit="doCreateServer(event)"><input id="sname" maxlength="60" placeholder="Server name" required><input id="sicon" maxlength="500" placeholder="Icon URL (optional)"><div class="actions"><button type="button" class="ghost" onclick="closeModal()">Cancel</button><button class="primary">Create</button></div></form>`)}
async function doCreateServer(e){e.preventDefault();try{await api("/api/servers",{method:"POST",body:JSON.stringify({name:sname.value,icon:sicon.value})});closeModal();await loadData();render();toast("Server created")}catch(e){toast(e.message)}}
async function logout(){await api("/api/logout",{method:"POST"});location.reload()}
function startRealtime(){
 if(!sb)return;
 if(realtime)sb.removeChannel(realtime);
 realtime=sb.channel("spookchat-messages").on("postgres_changes",{event:"*",schema:"public",table:"messages"},()=>loadMessages()).subscribe();
}
window.addEventListener("beforeunload",()=>{if(sb&&realtime)sb.removeChannel(realtime)});
boot();
</script>
</body>
</html>
"""

SCHEMA = r"""
create table if not exists profiles(
 id uuid primary key,
 username text not null unique,
 description text not null default '',
 avatar text not null default '',
 pronouns text not null default '',
 company text not null default '',
 global_role text not null default 'user' check(global_role in ('user','moderator','admin','owner')),
 created_at timestamptz not null default now()
);

create table if not exists public_channels(
 id text primary key,
 name text not null
);
insert into public_channels(id,name) values('chat1','Chat 1'),('chat2','Chat 2') on conflict do nothing;

create table if not exists servers(
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references profiles(id) on delete cascade,
 name text not null,
 icon text not null default '',
 created_at timestamptz not null default now()
);

create table if not exists server_members(
 server_id uuid references servers(id) on delete cascade,
 user_id uuid references profiles(id) on delete cascade,
 role text not null default 'member' check(role in ('member','moderator','admin','owner')),
 banned_until timestamptz,
 muted_until timestamptz,
 primary key(server_id,user_id)
);

create table if not exists chats(
 id uuid primary key default gen_random_uuid(),
 kind text not null check(kind in ('dm','group')),
 name text not null default '',
 owner_id uuid references profiles(id) on delete set null,
 created_at timestamptz not null default now()
);

create table if not exists chat_members(
 chat_id uuid references chats(id) on delete cascade,
 user_id uuid references profiles(id) on delete cascade,
 role text not null default 'member',
 primary key(chat_id,user_id)
);

create table if not exists messages(
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references profiles(id) on delete cascade,
 content text not null check(char_length(content) between 1 and 4000),
 kind text not null check(kind in ('public','server','dm')),
 channel text,
 server_id uuid references servers(id) on delete cascade,
 chat_id uuid references chats(id) on delete cascade,
 created_at timestamptz not null default now()
);

create index if not exists messages_created_idx on messages(created_at);
create index if not exists messages_server_idx on messages(server_id,channel,created_at);
create index if not exists messages_chat_idx on messages(chat_id,created_at);

create table if not exists reports(
 id uuid primary key default gen_random_uuid(),
 reporter_id uuid references profiles(id) on delete set null,
 message_id uuid references messages(id) on delete set null,
 message_snapshot text not null default '',
 reported_user_id uuid references profiles(id) on delete set null,
 created_at timestamptz not null default now(),
 status text not null default 'open'
);

create table if not exists global_bans(
 user_id uuid primary key references profiles(id) on delete cascade,
 banned_until timestamptz,
 reason text not null default ''
);

create table if not exists ip_bans(
 ip text primary key,
 banned_until timestamptz,
 reason text not null default ''
);

alter table messages replica identity full;
do $$ begin
  alter publication supabase_realtime add table messages;
exception when duplicate_object then null;
end $$;

-- The browser only needs realtime SELECT visibility.
alter table messages enable row level security;
drop policy if exists "authenticated realtime read" on messages;
create policy "authenticated realtime read" on messages for select to authenticated using (true);
"""

def db():
    if not DB_URL:
        raise RuntimeError("SUPABASE_DB_URL is missing")
    return psycopg.connect(DB_URL)

def init_db():
    if not DB_URL:
        return
    try:
        with db() as c:
            with c.cursor() as cur:
                cur.execute(SCHEMA)
            c.commit()
    except Exception as e:
        print("Database initialization warning:", e)

init_db()

def supabase_headers():
    return {"apikey": SERVICE_KEY, "Authorization": "Bearer " + SERVICE_KEY, "Content-Type": "application/json"}

def auth_user():
    token = request.cookies.get("sb-access-token") or request.headers.get("Authorization","").replace("Bearer ","")
    if not token or not SUPABASE_URL or not ANON_KEY:
        return None
    r = requests.get(SUPABASE_URL + "/auth/v1/user", headers={"apikey":ANON_KEY,"Authorization":"Bearer "+token}, timeout=10)
    if r.status_code != 200:
        return None
    return r.json()

def profile(uid):
    with db() as c:
        row=c.execute("select * from profiles where id=%s",(uid,)).fetchone()
        if not row:return None
        cols=[x.name for x in c.execute("select * from profiles limit 0").description]
        return dict(zip(cols,row))

def require_auth(fn):
    @wraps(fn)
    def w(*a,**k):
        u=auth_user()
        if not u:return jsonify(error="Not authenticated"),401
        p=profile(u["id"])
        if not p:return jsonify(error="Profile not found"),403
        if is_global_banned(u["id"]):return jsonify(error="Your account is banned"),403
        request.current_user=u;request.current_profile=p
        return fn(*a,**k)
    return w

def is_global_banned(uid):
    with db() as c:
        r=c.execute("select banned_until from global_bans where user_id=%s",(uid,)).fetchone()
        if not r:return False
        return r[0] is None or r[0] > datetime.now(timezone.utc)

def global_staff(p, levels=("owner","admin","moderator")):
    return p["global_role"] in levels

def server_role(uid,sid):
    with db() as c:
        r=c.execute("select role,banned_until,muted_until from server_members where server_id=%s and user_id=%s",(sid,uid)).fetchone()
        return dict(role=r[0],banned_until=r[1],muted_until=r[2]) if r else None

def server_can(uid,sid,roles):
    r=server_role(uid,sid)
    return bool(r and r["role"] in roles and not (r["banned_until"] and r["banned_until"]>datetime.now(timezone.utc)))

@app.get("/")
def index():
    return render_template_string(HTML,supabase_url=SUPABASE_URL,anon_key=ANON_KEY)

@app.post("/api/register")
def register():
    data=request.json or {};email=str(data.get("email","")).strip().lower();password=str(data.get("password",""));username=str(data.get("username","")).strip()
    if len(username)<2 or len(username)>32 or len(password)<8:return jsonify(error="Username/password is invalid"),400
    r=requests.post(SUPABASE_URL+"/auth/v1/signup",headers={"apikey":ANON_KEY,"Content-Type":"application/json"},json={"email":email,"password":password},timeout=10)
    if r.status_code>=400:return jsonify(error=r.json().get("msg") or r.json().get("message") or "Registration failed"),400
    u=r.json().get("user")
    if not u:return jsonify(error="Check your email, then log in"),200
    with db() as c:
        try:c.execute("insert into profiles(id,username) values(%s,%s)",(u["id"],username));c.commit()
        except Exception:c.rollback();return jsonify(error="Username already exists"),400
    if r.json().get("access_token"):
        resp=jsonify(ok=True);resp.set_cookie("sb-access-token",r.json()["access_token"],httponly=True,samesite="Lax",secure=True,max_age=604800);return resp
    return jsonify(ok=True)

@app.post("/api/login")
def login():
    data=request.json or {}
    r=requests.post(SUPABASE_URL+"/auth/v1/token?grant_type=password",headers={"apikey":ANON_KEY,"Content-Type":"application/json"},json={"email":data.get("email",""),"password":data.get("password","")},timeout=10)
    if r.status_code>=400:return jsonify(error="Invalid email or password"),401
    u=r.json()["user"]
    if is_global_banned(u["id"]):return jsonify(error="Account is banned"),403
    resp=jsonify(ok=True);resp.set_cookie("sb-access-token",r.json()["access_token"],httponly=True,samesite="Lax",secure=True,max_age=604800);return resp

@app.post("/api/logout")
def logout():
    resp=jsonify(ok=True);resp.delete_cookie("sb-access-token");return resp

@app.get("/api/me")
@require_auth
def me():
    return jsonify(user={"id":request.current_user["id"],"email":request.current_user.get("email")},profile=request.current_profile)

@app.get("/api/profile/<uid>")
@require_auth
def get_profile(uid):
    p=profile(uid)
    if not p:return jsonify(error="User not found"),404
    return jsonify(profile=p)

@app.patch("/api/profile")
@require_auth
def edit_profile():
    d=request.json or {};allowed={"username":str(d.get("username","")).strip(),"description":str(d.get("description",""))[:300],"avatar":str(d.get("avatar",""))[:500],"pronouns":str(d.get("pronouns",""))[:40],"company":str(d.get("company",""))[:80]}
    if not 2<=len(allowed["username"])<=32:return jsonify(error="Invalid username"),400
    with db() as c:
        try:
            c.execute("update profiles set username=%s,description=%s,avatar=%s,pronouns=%s,company=%s where id=%s",(*allowed.values(),request.current_user["id"]));c.commit()
        except Exception:c.rollback();return jsonify(error="Username is already taken"),400
    return jsonify(profile=profile(request.current_user["id"]))

@app.get("/api/servers")
@require_auth
def servers():
    uid=request.current_user["id"]
    with db() as c:
        rows=c.execute("""select s.id,s.name,s.icon,sm.role from servers s join server_members sm on sm.server_id=s.id
                          where sm.user_id=%s and (sm.banned_until is null or sm.banned_until>now()) order by s.created_at""",(uid,)).fetchall()
    return jsonify(servers=[{"id":str(r[0]),"name":r[1],"icon":r[2],"role":r[3]} for r in rows])

@app.post("/api/servers")
@require_auth
def create_server():
    d=request.json or {};name=str(d.get("name","")).strip()[:60];icon=str(d.get("icon",""))[:500]
    if not name:return jsonify(error="Server name required"),400
    with db() as c:
        sid=c.execute("insert into servers(owner_id,name,icon) values(%s,%s,%s) returning id",(request.current_user["id"],name,icon)).fetchone()[0]
        c.execute("insert into server_members(server_id,user_id,role) values(%s,%s,'owner')",(sid,request.current_user["id"]));c.commit()
    return jsonify(id=str(sid))

@app.get("/api/messages")
@require_auth
def get_messages():
    kind=request.args.get("kind");channel=request.args.get("channel");sid=request.args.get("server_id");cid=request.args.get("chat_id");uid=request.current_user["id"]
    with db() as c:
        if kind=="public":
            rows=c.execute("""select m.id,m.user_id,m.content,m.created_at,p.username,p.avatar,p.global_role
                              from messages m join profiles p on p.id=m.user_id where m.kind='public' and m.channel=%s order by m.created_at desc limit 150""",(channel,)).fetchall()
        elif kind=="server":
            if not server_role(uid,sid):return jsonify(error="Not a server member"),403
            rows=c.execute("""select m.id,m.user_id,m.content,m.created_at,p.username,p.avatar,sm.role
                              from messages m join profiles p on p.id=m.user_id left join server_members sm on sm.server_id=m.server_id and sm.user_id=m.user_id
                              where m.kind='server' and m.channel=%s and m.server_id=%s order by m.created_at desc limit 150""",(channel,sid)).fetchall()
        else:
            with db() as cc:
                member=cc.execute("select 1 from chat_members where chat_id=%s and user_id=%s",(cid,uid)).fetchone()
            if not member:return jsonify(error="Not a chat member"),403
            rows=c.execute("""select m.id,m.user_id,m.content,m.created_at,p.username,p.avatar,p.global_role
                              from messages m join profiles p on p.id=m.user_id where m.kind='dm' and m.chat_id=%s order by m.created_at desc limit 150""",(cid,)).fetchall()
    out=[{"id":str(r[0]),"user_id":str(r[1]),"content":r[2],"created_at":r[3].isoformat(),"username":r[4],"avatar":r[5],"role":r[6]} for r in reversed(rows)]
    return jsonify(messages=out)

@app.post("/api/messages")
@require_auth
def post_message():
    d=request.json or {};kind=d.get("kind");content=str(d.get("content","")).strip()
    if kind not in ("public","server","dm") or not content or len(content)>4000:return jsonify(error="Invalid message"),400
    uid=request.current_user["id"];channel=d.get("channel");sid=d.get("server_id");cid=d.get("chat_id")
    if kind=="server":
        r=server_role(uid,sid)
        if not r:return jsonify(error="Not a member"),403
        now=datetime.now(timezone.utc)
        if r["banned_until"] and r["banned_until"]>now:return jsonify(error="Banned from server"),403
        if r["muted_until"] and r["muted_until"]>now:return jsonify(error="You are restricted from talking"),403
    if kind=="dm":
        with db() as c:
            if not c.execute("select 1 from chat_members where chat_id=%s and user_id=%s",(cid,uid)).fetchone():return jsonify(error="Not a chat member"),403
    with db() as c:
        m=c.execute("insert into messages(user_id,content,kind,channel,server_id,chat_id) values(%s,%s,%s,%s,%s,%s) returning id",(uid,content,kind,channel,sid,cid)).fetchone()[0];c.commit()
    return jsonify(id=str(m))

@app.delete("/api/messages/<mid>")
@require_auth
def delete_message(mid):
    uid=request.current_user["id"]
    with db() as c:
        m=c.execute("select user_id,server_id,kind from messages where id=%s",(mid,)).fetchone()
        if not m:return jsonify(error="Message not found"),404
        allowed=str(m[0])==uid or global_staff(request.current_profile)
        if m[2]=="server" and m[1] and server_can(uid,m[1],("owner","admin","moderator")):allowed=True
        if not allowed:return jsonify(error="No permission"),403
        c.execute("delete from messages where id=%s",(mid,));c.commit()
    return jsonify(ok=True)

@app.post("/api/reports")
@require_auth
def report():
    mid=(request.json or {}).get("message_id")
    with db() as c:
        m=c.execute("select content,user_id from messages where id=%s",(mid,)).fetchone()
        if not m:return jsonify(error="Message not found"),404
        c.execute("insert into reports(reporter_id,message_id,message_snapshot,reported_user_id) values(%s,%s,%s,%s)",(request.current_user["id"],mid,m[0],m[1]));c.commit()
    return jsonify(ok=True)

@app.post("/api/friends")
@require_auth
def friend():
    # Compact implementation: accepted friendships are represented by a tiny
    # table created lazily below.
    d=request.json or {};target=d.get("user_id")
    if not target or target==request.current_user["id"]:return jsonify(error="Invalid user"),400
    with db() as c:
        c.execute("""create table if not exists friendships(
          user_a uuid references profiles(id) on delete cascade,
          user_b uuid references profiles(id) on delete cascade,
          status text not null default 'accepted',
          primary key(user_a,user_b))""")
        a,b=sorted([request.current_user["id"],target])
        c.execute("insert into friendships(user_a,user_b) values(%s,%s) on conflict do nothing",(a,b));c.commit()
    return jsonify(ok=True)

@app.get("/api/friends")
@require_auth
def friends():
    with db() as c:
        c.execute("""create table if not exists friendships(
          user_a uuid references profiles(id) on delete cascade,
          user_b uuid references profiles(id) on delete cascade,
          status text not null default 'accepted', primary key(user_a,user_b))""")
        rows=c.execute("""select p.id,p.username,p.avatar from friendships f join profiles p on p.id=(case when f.user_a=%s then f.user_b else f.user_a end)
                         where f.user_a=%s or f.user_b=%s order by p.username""",(request.current_user["id"],request.current_user["id"],request.current_user["id"])).fetchall()
        c.commit()
    return jsonify(friends=[{"id":str(r[0]),"username":r[1],"avatar":r[2]} for r in rows])

@app.post("/api/dms")
@require_auth
def dms():
    target=(request.json or {}).get("user_id");uid=request.current_user["id"]
    if not target or target==uid:return jsonify(error="Invalid user"),400
    with db() as c:
        row=c.execute("""select c.id from chats c join chat_members a on a.chat_id=c.id join chat_members b on b.chat_id=c.id
                         where c.kind='dm' and a.user_id=%s and b.user_id=%s limit 1""",(uid,target)).fetchone()
        if row:return jsonify(chat_id=str(row[0]))
        cid=c.execute("insert into chats(kind,owner_id) values('dm',%s) returning id",(uid,)).fetchone()[0]
        c.execute("insert into chat_members(chat_id,user_id) values(%s,%s),(%s,%s)",(cid,uid,cid,target));c.commit()
    return jsonify(chat_id=str(cid))

@app.post("/api/groups")
@require_auth
def groups():
    d=request.json or {};name=str(d.get("name","")).strip()[:50];names=d.get("usernames") or [];uid=request.current_user["id"]
    if not name:return jsonify(error="Group name required"),400
    with db() as c:
        cid=c.execute("insert into chats(kind,name,owner_id) values('group',%s,%s) returning id",(name,uid)).fetchone()[0]
        c.execute("insert into chat_members(chat_id,user_id,role) values(%s,%s,'owner')",(cid,uid))
        for n in names[:50]:
            r=c.execute("select id from profiles where lower(username)=lower(%s)",(n,)).fetchone()
            if r:c.execute("insert into chat_members(chat_id,user_id) values(%s,%s) on conflict do nothing",(cid,r[0]))
        c.commit()
    return jsonify(chat_id=str(cid))

# ---------- Owner/global staff moderation ----------
@app.post("/api/staff/ban")
@require_auth
def staff_ban():
    if not global_staff(request.current_profile,("owner","admin")):return jsonify(error="Owner/Admin only"),403
    d=request.json or {};target=d.get("user_id");minutes=d.get("minutes")
    if not target:return jsonify(error="User required"),400
    until=None if not minutes else datetime.now(timezone.utc)+timedelta(minutes=max(1,min(int(minutes),525600)))
    with db() as c:c.execute("insert into global_bans(user_id,banned_until,reason) values(%s,%s,%s) on conflict(user_id) do update set banned_until=excluded.banned_until,reason=excluded.reason",(target,until,str(d.get("reason",""))[:300]));c.commit()
    return jsonify(ok=True)

@app.post("/api/staff/role")
@require_auth
def staff_role():
    if request.current_profile["global_role"]!="owner":return jsonify(error="Owner only"),403
    target=request.json.get("user_id");role=request.json.get("role")
    if role not in ("user","moderator","admin","owner"):return jsonify(error="Invalid role"),400
    with db() as c:c.execute("update profiles set global_role=%s where id=%s",(role,target));c.commit()
    return jsonify(ok=True)

@app.post("/api/server/member-action")
@require_auth
def server_action():
    d=request.json or {};sid=d.get("server_id");target=d.get("user_id");action=d.get("action");minutes=int(d.get("minutes") or 10)
    me=server_role(request.current_user["id"],sid)
    if not me:return jsonify(error="Not a member"),403
    if action in ("ban","unban") and me["role"] not in ("owner","admin"):return jsonify(error="Admin/Owner only"),403
    if action in ("mute","unmute") and me["role"] not in ("owner","admin","moderator"):return jsonify(error="Staff only"),403
    if action=="role" and me["role"]!="owner":return jsonify(error="Owner only"),403
    until=None if action in ("unban","unmute") else datetime.now(timezone.utc)+timedelta(minutes=max(1,min(minutes,525600)))
    with db() as c:
        if action in ("ban","unban"):c.execute("update server_members set banned_until=%s where server_id=%s and user_id=%s",(until,sid,target))
        elif action in ("mute","unmute"):c.execute("update server_members set muted_until=%s where server_id=%s and user_id=%s",(until,sid,target))
        elif action=="role":
            role=d.get("role")
            if role not in ("member","moderator","admin"):return jsonify(error="Invalid role"),400
            c.execute("update server_members set role=%s where server_id=%s and user_id=%s",(role,sid,target))
        c.commit()
    return jsonify(ok=True)

@app.post("/api/server/edit")
@require_auth
def server_edit():
    d=request.json or {};sid=d.get("server_id");r=server_role(request.current_user["id"],sid)
    if not r or r["role"]!="owner":return jsonify(error="Owner only"),403
    with db() as c:
        c.execute("update servers set name=%s,icon=%s where id=%s",(str(d.get("name","")).strip()[:60],str(d.get("icon",""))[:500],sid));c.commit()
    return jsonify(ok=True)

# Vercel imports `app`.
