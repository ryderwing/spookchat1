import os
import secrets
import hashlib
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

# ============================================================
# DATABASE
# ============================================================

SCHEMA = r"""
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
 account_info_password_hash text not null default '',
 banned_until timestamptz,
 last_ip text not null default '',
 last_seen timestamptz,
 device_type text not null default 'PC',
 theme text not null default 'original',
 show_staff_tag boolean not null default true,
 created_at timestamptz not null default now()
);

create table if not exists friends(
 user_a bigint references users(id) on delete cascade,
 user_b bigint references users(id) on delete cascade,
 status text not null default 'accepted',
 primary key(user_a,user_b)
);

create table if not exists servers(
 id bigserial primary key,
 owner_id bigint not null references users(id) on delete cascade,
 name text not null,
 icon text not null default '',
 privacy_mode text not null default 'public',
 created_at timestamptz not null default now()
);

create table if not exists server_members(
 server_id bigint references servers(id) on delete cascade,
 user_id bigint references users(id) on delete cascade,
 role text not null default 'member',
 banned_until timestamptz,
 muted_until timestamptz,
 joined_at timestamptz not null default now(),
 primary key(server_id,user_id)
);




create table if not exists server_join_requests(
 id bigserial primary key,
 server_id bigint not null references servers(id) on delete cascade,
 user_id bigint not null references users(id) on delete cascade,
 status text not null default 'pending',
 created_at timestamptz not null default now(),
 unique(server_id,user_id)
);

create index if not exists server_join_requests_server_idx
on server_join_requests(server_id,status,created_at);

create table if not exists server_invites(
 id bigserial primary key,
 server_id bigint not null references servers(id) on delete cascade,
 created_by bigint not null references users(id) on delete cascade,
 code text not null unique,
 uses integer not null default 0,
 created_at timestamptz not null default now()
);

create index if not exists server_invites_server_idx
on server_invites(server_id,created_at);

create table if not exists server_roles(
 id bigserial primary key,
 server_id bigint not null references servers(id) on delete cascade,
 name text not null,
 created_at timestamptz not null default now(),
 unique(server_id,name)
);

create table if not exists server_member_roles(
 server_id bigint not null references servers(id) on delete cascade,
 user_id bigint not null references users(id) on delete cascade,
 role_id bigint not null references server_roles(id) on delete cascade,
 primary key(server_id,user_id,role_id)
);

create table if not exists server_channels(
 id bigserial primary key,
 server_id bigint not null references servers(id) on delete cascade,
 name text not null,
 kind text not null default 'chat',
 view_roles jsonb not null default '["member","moderator","admin","owner"]'::jsonb,
 talk_roles jsonb not null default '["member","moderator","admin","owner"]'::jsonb,
 position integer not null default 0,
 created_at timestamptz not null default now(),
 unique(server_id,name)
);

create table if not exists spookhooks(
 id bigserial primary key,
 server_id bigint not null references servers(id) on delete cascade,
 channel_id bigint not null references server_channels(id) on delete cascade,
 created_by bigint not null references users(id) on delete cascade,
 name text not null default 'SpookHook',
 token_hash text not null unique,
 created_at timestamptz not null default now()
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
 edited_at timestamptz,
 is_spookhook boolean not null default false,
 hook_name text not null default '',
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
 reason text not null default '',
 created_at timestamptz not null default now()
);


create table if not exists notifications(
 id bigserial primary key,
 user_id bigint not null references users(id) on delete cascade,
 actor_id bigint references users(id) on delete set null,
 type text not null default 'message',
 title text not null default '',
 body text not null default '',
 chat_id bigint references chats(id) on delete cascade,
 read_at timestamptz,
 created_at timestamptz not null default now()
);

create index if not exists notifications_user_idx
on notifications(user_id,read_at,created_at);

create index if not exists messages_public_idx on messages(kind,channel,created_at);
create index if not exists messages_server_idx on messages(server_id,channel,created_at);
create index if not exists messages_chat_idx on messages(chat_id,created_at);
"""

def connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing")
    return psycopg.connect(DATABASE_URL)

def init_db():
    if not DATABASE_URL:
        return
    try:
        with connect() as c:
            # Create all base tables first.
            c.execute(SCHEMA)

            # Repair/upgrade databases created by older SpookChat versions.
            # PostgreSQL safely ignores these when the columns already exist.
            c.execute("alter table users add column if not exists last_ip text not null default ''")
            c.execute("alter table users add column if not exists description text not null default ''")
            c.execute("alter table users add column if not exists avatar text not null default ''")
            c.execute("alter table users add column if not exists pronouns text not null default ''")
            c.execute("alter table users add column if not exists company text not null default ''")
            c.execute("alter table users add column if not exists global_role text not null default 'user'")
            c.execute("alter table users add column if not exists banned_until timestamptz")
            c.execute("alter table users add column if not exists created_at timestamptz not null default now()")

            c.execute("alter table users add column if not exists device_type text not null default 'PC'")
            c.execute("alter table users add column if not exists theme text not null default 'original'")
            c.execute("alter table users add column if not exists show_staff_tag boolean not null default true")

            c.execute("alter table users add column if not exists account_info_password_hash text not null default ''")
            c.execute("alter table users add column if not exists last_seen timestamptz")
            c.execute("alter table servers add column if not exists privacy_mode text not null default 'public'")
            c.execute("""
                create table if not exists server_join_requests(
                 id bigserial primary key,
                 server_id bigint not null references servers(id) on delete cascade,
                 user_id bigint not null references users(id) on delete cascade,
                 status text not null default 'pending',
                 created_at timestamptz not null default now(),
                 unique(server_id,user_id)
                )
            """)
            c.execute("create index if not exists server_join_requests_server_idx on server_join_requests(server_id,status,created_at)")



            c.execute("alter table friends add column if not exists status text not null default 'accepted'")

            c.execute("alter table server_members add column if not exists banned_until timestamptz")
            c.execute("alter table server_members add column if not exists muted_until timestamptz")
            c.execute("alter table server_members add column if not exists joined_at timestamptz not null default now()")

            c.execute("alter table messages add column if not exists edited_at timestamptz")

            c.execute("alter table messages add column if not exists is_spookhook boolean not null default false")
            c.execute("alter table messages add column if not exists hook_name text not null default ''")

            # Seed the two original server channels for old and new servers.
            c.execute("""
                insert into server_channels(server_id,name,kind,view_roles,talk_roles,position)
                select s.id,'announcements','announcement',
                       '["member","moderator","admin","owner"]'::jsonb,
                       '["moderator","admin","owner"]'::jsonb,0
                from servers s
                where not exists(select 1 from server_channels c2 where c2.server_id=s.id and c2.name='announcements')
            """)
            c.execute("""
                insert into server_channels(server_id,name,kind,view_roles,talk_roles,position)
                select s.id,'chat','chat',
                       '["member","moderator","admin","owner"]'::jsonb,
                       '["member","moderator","admin","owner"]'::jsonb,1
                from servers s
                where not exists(select 1 from server_channels c2 where c2.server_id=s.id and c2.name='chat')
            """)
            # Move old server messages that used "chat"/"announcement" names onto channel IDs.
            c.execute("""
                update messages m set channel=sc.id::text
                from server_channels sc
                where m.kind='server' and m.server_id=sc.server_id
                  and ((m.channel='chat' and sc.name='chat')
                    or (m.channel='announcement' and sc.name='announcements'))
            """)


            c.execute("alter table reports add column if not exists status text not null default 'open'")
            c.execute("alter table reports add column if not exists created_at timestamptz not null default now()")

            c.execute("alter table ip_bans add column if not exists banned_until timestamptz")
            c.execute("alter table ip_bans add column if not exists reason text not null default ''")
            c.execute("alter table ip_bans add column if not exists created_at timestamptz not null default now()")

            c.execute("""
                create table if not exists notifications(
                 id bigserial primary key,
                 user_id bigint not null references users(id) on delete cascade,
                 actor_id bigint references users(id) on delete set null,
                 type text not null default 'message',
                 title text not null default '',
                 body text not null default '',
                 chat_id bigint references chats(id) on delete cascade,
                 read_at timestamptz,
                 created_at timestamptz not null default now()
                )
            """)
            c.execute("create index if not exists notifications_user_idx on notifications(user_id,read_at,created_at)")

            c.execute("""
                create table if not exists server_invites(
                 id bigserial primary key,
                 server_id bigint not null references servers(id) on delete cascade,
                 created_by bigint not null references users(id) on delete cascade,
                 code text not null unique,
                 uses integer not null default 0,
                 created_at timestamptz not null default now()
                )
            """)
            c.execute("create index if not exists server_invites_server_idx on server_invites(server_id,created_at)")



            c.commit()
            print("SpookChat database migration complete.")
    except Exception as e:
        print("DATABASE INITIALIZATION ERROR:", repr(e))

init_db()


def device_type():
    ua = (request.headers.get("user-agent") or "").lower()
    mobile_words = ("android","iphone","ipad","ipod","mobile","windows phone")
    return "Mobile" if any(x in ua for x in mobile_words) else "PC"

def client_ip():
    # Vercel supplies x-forwarded-for. We only use the first IP inserted by the edge.
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.remote_addr or "")[:64]

def row_user(uid):
    with connect() as c:
        r = c.execute("""
            select id,email,username,description,avatar,pronouns,company,
                   global_role,banned_until,last_ip,last_seen,device_type,theme,show_staff_tag,account_info_password_hash,created_at
            from users where id=%s
        """, (uid,)).fetchone()
    if not r:
        return None
    keys = ["id","email","username","description","avatar","pronouns","company",
            "global_role","banned_until","last_ip","last_seen","device_type","theme","show_staff_tag","account_info_password_hash","created_at"]
    return dict(zip(keys, r))

def current_user():
    uid = session.get("uid")
    return row_user(uid) if uid else None

def ip_is_banned(ip):
    if not ip:
        return False
    with connect() as c:
        r = c.execute("select banned_until from ip_bans where ip=%s", (ip,)).fetchone()
    if not r:
        return False
    return r[0] is None or r[0] > datetime.now(timezone.utc)

def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        if ip_is_banned(client_ip()):
            return jsonify(error="This IP address is banned from SpookChat."), 403
        u = current_user()
        if not u:
            return jsonify(error="Not logged in"), 401
        if u["banned_until"] and u["banned_until"] > datetime.now(timezone.utc):
            return jsonify(error="Your account is temporarily banned."), 403
        try:
            with connect() as c:
                c.execute("update users set last_ip=%s,device_type=%s,last_seen=now() where id=%s", (client_ip(), device_type(), u["id"]))
                c.commit()
        except Exception:
            pass
        request.me = u
        return fn(*args, **kwargs)
    return wrap

def staff_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrap(*args, **kwargs):
            if request.me["global_role"] not in roles:
                return jsonify(error="You do not have permission."), 403
            return fn(*args, **kwargs)
        return wrap
    return deco

def server_member(sid, uid):
    with connect() as c:
        r = c.execute("""
            select role,banned_until,muted_until,joined_at
            from server_members where server_id=%s and user_id=%s
        """, (sid, uid)).fetchone()
    if not r:
        return None
    return {"role": r[0], "banned_until": r[1], "muted_until": r[2], "joined_at": r[3]}

def server_level(role):
    return {"member":0, "moderator":1, "admin":2, "owner":3}.get(role, -1)


def server_custom_roles(sid, uid):
    with connect() as c:
        rows = c.execute("""
            select smr.role_id from server_member_roles smr
            where smr.server_id=%s and smr.user_id=%s
        """,(sid,uid)).fetchall()
    return {f"custom:{r[0]}" for r in rows}

def channel_access(sid, channel_id, uid, mode):
    sm = server_member(sid,uid)
    if not sm:
        return False
    if sm["role"] == "owner":
        return True
    with connect() as c:
        r = c.execute("""
            select view_roles,talk_roles from server_channels where id=%s and server_id=%s
        """,(channel_id,sid)).fetchone()
    if not r:
        return False
    allowed = set(r[0] if mode=="view" else r[1])
    if sm["role"] in allowed:
        return True
    return bool(server_custom_roles(sid,uid) & allowed)

def global_level(role):
    return {"user":0, "moderator":1, "admin":2, "owner":3}.get(role, -1)

def can_manage_global(actor, target):
    return global_level(actor["global_role"]) > global_level(target["global_role"])

# ============================================================
# FRONTEND
# ============================================================

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SpookChat</title>
<link rel="icon" type="image/png" href="/static/spookchat_pfp.png">
<style>
:root{
 --bg:#08070c;--side:#0d0a12;--panel:#110d18;--panel2:#17111f;
 --line:#2a2134;--purple:#8957ff;--purple2:#b14cff;
 --text:#f6f2ff;--muted:#9b93aa;--danger:#ff5368;--good:#35d07f;
}

body.theme-dark{--bg:#090909;--side:#0d0d0d;--panel:#121212;--panel2:#181818;--line:#292929;--purple:#777;--purple2:#aaa;--text:#f4f4f4;--muted:#999}
body.theme-light{--bg:#f5f3f8;--side:#ffffff;--panel:#ffffff;--panel2:#f0edf4;--line:#ded8e5;--purple:#7651d8;--purple2:#9a55d8;--text:#1d1822;--muted:#716b78;background:#f5f3f8}
body.theme-light .topbar,body.theme-light .composer,body.theme-light .meBox{background:#fff}
body.theme-light .field,body.theme-light .composer input{background:#fff;color:#1d1822}

*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font:14px Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
body{overflow:hidden;background:radial-gradient(circle at 15% -10%,#28123e 0,transparent 34%),var(--bg)}
button,input,textarea,select{font:inherit}
button{border:0;cursor:pointer}
input,textarea,select{outline:none}
.hidden{display:none!important}
.app{height:100vh;display:grid;grid-template-columns:270px minmax(0,1fr) 0;transition:.25s}
.app.with-members{grid-template-columns:270px minmax(0,1fr) 260px}
.sidebar{background:rgba(11,8,15,.96);border-right:1px solid var(--line);display:flex;flex-direction:column;min-width:0}
.brand{height:64px;display:flex;align-items:center;gap:10px;padding:0 17px;border-bottom:1px solid var(--line);font-weight:900;font-size:20px}
.brandLogo{width:34px;height:34px;border-radius:11px;background:linear-gradient(135deg,var(--purple),var(--purple2));display:grid;place-items:center;box-shadow:0 0 30px #8b5cf633}
.brand span{color:#c9a8ff}
.sideScroll{overflow:auto;padding:10px 10px 18px}
.sectionTitle{display:flex;align-items:center;justify-content:space-between;padding:12px 9px 7px;color:#746c7e;font-weight:800;font-size:10px;letter-spacing:.09em;text-transform:uppercase}
.sideBtn,.serverBtn,.channelBtn{width:100%;display:flex;align-items:center;gap:10px;background:transparent;color:#b9b1c4;padding:10px 11px;border-radius:10px;text-align:left;margin:2px 0;transition:.15s}
.sideBtn:hover,.serverBtn:hover,.channelBtn:hover,.sideBtn.active,.serverBtn.active,.channelBtn.active{background:#1a1423;color:#fff;transform:translateX(2px)}
.iconBox,.serverIcon{width:31px;height:31px;border-radius:9px;background:#241735;display:grid;place-items:center;flex:none;overflow:hidden}
.serverIcon img{width:100%;height:100%;object-fit:cover}
.badge{margin-left:auto;font-size:10px;padding:3px 6px;border-radius:20px;background:#26183b;color:#cdb7ff}
.meBox{margin-top:auto;padding:10px;border-top:1px solid var(--line);display:flex;align-items:center;gap:9px;background:#0b0910}
.meAvatar,.avatar{border-radius:50%;background:#261737;object-fit:cover}
.meAvatar{width:36px;height:36px}.avatar{width:40px;height:40px}
.meText{min-width:0;flex:1}.meName{font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.meRole{font-size:11px;color:#82798d}
.roundBtn{width:34px;height:34px;border-radius:9px;background:#18121f;color:#bfb6c9}
.roundBtn:hover{background:#281a38;color:white}
.main{min-width:0;display:flex;flex-direction:column}
.topbar{height:64px;border-bottom:1px solid var(--line);background:rgba(9,7,13,.75);backdrop-filter:blur(14px);display:flex;align-items:center;padding:0 18px;gap:12px}
.topTitle{font-weight:850;font-size:16px}.topSub{color:#7f7689;font-size:12px}
.topActions{margin-left:auto;display:flex;gap:7px}
.content{flex:1;min-height:0;position:relative;overflow:hidden}
.messages{height:100%;overflow:auto;padding:18px 20px}
.msg{display:flex;gap:11px;padding:8px 8px;border-radius:10px;position:relative}
.msg:hover{background:#ffffff05}
.msgBody{min-width:0;max-width:min(900px,90%)}.meta{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.name{font-weight:800}.roleTag{font-size:10px;padding:2px 6px;border-radius:6px;background:#26183b;color:#cdb7ff;text-transform:uppercase}
.time{font-size:10px;color:#655d6d}.edited{font-size:10px;color:#726978}.text{margin-top:2px;color:#d9d3e0;white-space:pre-wrap;word-break:break-word;line-height:1.45}
.composer{height:auto;min-height:70px;border-top:1px solid var(--line);padding:12px 16px;display:flex;gap:9px;background:#0a080e}
.composer input{flex:1;background:#15101d;border:1px solid #2b2236;color:white;border-radius:11px;padding:12px 13px}
.primary{background:linear-gradient(135deg,var(--purple),var(--purple2));color:white;padding:10px 15px;border-radius:10px;font-weight:800;box-shadow:0 7px 24px #8b5cf622}
.primary:hover{filter:brightness(1.08)}
.ghost{background:#19131f;color:#d7d0df;padding:9px 12px;border-radius:9px}
.ghost:hover{background:#261a33}.danger{background:#36131c;color:#ff9aaa;padding:9px 12px;border-radius:9px}
.good{background:#113123;color:#8eeeb8;padding:9px 12px;border-radius:9px}
.membersPane{border-left:1px solid var(--line);background:#0c0911;overflow:auto;display:none}
.app.with-members .membersPane{display:block}
.memberHead{height:64px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 15px;font-weight:800}
.memberRow{display:flex;align-items:center;gap:9px;padding:8px 12px;border-radius:9px;margin:2px 7px}.memberRow:hover{background:#17111f}
.memberRow .avatar{width:34px;height:34px}.memberInfo{min-width:0;flex:1}.memberName{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.memberRole{font-size:10px;color:#877e91;text-transform:uppercase}
.page{height:100%;overflow:auto;padding:22px}
.pageHero{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:20px}.pageHero h1{margin:0 0 5px;font-size:26px}.muted{color:var(--muted)}
.card{background:linear-gradient(180deg,#120e19,#0f0c15);border:1px solid var(--line);border-radius:15px;padding:16px;margin-bottom:13px}
.card h3{margin:0 0 12px}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}.row{display:flex;align-items:center;gap:10px}.between{justify-content:space-between}
.searchBox{display:flex;gap:8px;margin:13px 0}.searchBox input,.field{width:100%;background:#0d0a13;border:1px solid #30263b;color:white;border-radius:10px;padding:11px 12px}
.listItem{display:flex;align-items:center;gap:11px;border-bottom:1px solid #211a29;padding:11px 2px}.listItem:last-child{border-bottom:0}.listMain{min-width:0;flex:1}.listTitle{font-weight:800}.listSub{color:#82798d;font-size:11px;margin-top:2px}
.pill{font-size:10px;padding:3px 7px;border-radius:20px;background:#241735;color:#cbb6ff}
.formGrid{display:grid;gap:10px}.label{font-size:11px;font-weight:800;color:#8f869a;margin-bottom:-4px}
.modalWrap{position:fixed;inset:0;background:#000b;display:grid;place-items:center;padding:16px;z-index:100}.modal{width:min(520px,96vw);max-height:88vh;overflow:auto;background:#110d18;border:1px solid #392d46;border-radius:16px;padding:20px;box-shadow:0 30px 100px #000}.modal h2{margin:0 0 14px}.modalActions{display:flex;gap:8px;justify-content:flex-end;margin-top:15px}
.context{position:fixed;z-index:200;min-width:205px;background:#17111f;border:1px solid #3a2d47;border-radius:11px;padding:6px;box-shadow:0 22px 60px #000}.context button{display:flex;width:100%;gap:9px;align-items:center;background:transparent;color:#ddd;padding:9px;border-radius:8px;text-align:left}.context button:hover{background:#281a38}.context .red{color:#ff8d9d}
.toast{position:fixed;right:18px;bottom:18px;z-index:250;background:#17111f;border:1px solid #3b2c4c;color:white;padding:12px 14px;border-radius:10px;box-shadow:0 15px 50px #000;animation:pop .18s ease}
.login{height:100vh;display:grid;place-items:center;padding:20px}.loginCard{width:min(430px,95vw);padding:28px;border:1px solid #382b46;background:rgba(16,12,24,.96);border-radius:20px;box-shadow:0 30px 100px #000}.loginLogo{font-size:32px;font-weight:950}.loginLogo b{color:var(--purple2)}.tabs{display:flex;gap:6px;margin:18px 0}.tabs button{flex:1;background:#18121f;color:#aaa;padding:10px;border-radius:9px}.tabs button.active{background:#2b193f;color:white}
.mobilebar{display:none}
.empty{padding:50px 20px;text-align:center;color:#736a7d}
@keyframes pop{from{transform:translateY(5px);opacity:0}to{transform:none;opacity:1}}

/* ---------- SpookChat polish ---------- */
html{scroll-behavior:smooth}
*{scrollbar-width:thin;scrollbar-color:#49305f transparent}
*::-webkit-scrollbar{width:8px;height:8px}
*::-webkit-scrollbar-thumb{background:#49305f;border-radius:20px}
*::-webkit-scrollbar-track{background:transparent}
.brandLogo{overflow:hidden;padding:0;background:#0a0710!important;border:1px solid #6f39a9;box-shadow:0 0 28px #9b4dff3d}
.brandLogo img{width:100%;height:100%;object-fit:cover}
.sideBtn,.serverBtn,.channelBtn,.roundBtn,.ghost,.primary,.danger,.good,.card,.listItem,.msg,.memberRow{
 transition:transform .18s ease,background .18s ease,border-color .18s ease,box-shadow .18s ease,filter .18s ease,opacity .18s ease
}
.sideBtn:hover,.serverBtn:hover,.channelBtn:hover{transform:translateX(4px)}
.card:hover{border-color:#4d3760;box-shadow:0 12px 40px #0003}
.primary:hover{transform:translateY(-1px);box-shadow:0 10px 30px #8b5cf643}
.primary:active,.ghost:active,.roundBtn:active{transform:scale(.97)}
.msg{animation:messageIn .20s cubic-bezier(.2,.8,.2,1)}
.page,.content{animation:viewIn .22s ease}
.modal{animation:modalIn .18s cubic-bezier(.2,.8,.2,1)}
.serverIcon,.avatar,.meAvatar{box-shadow:0 0 0 1px #ffffff08}
.notifyBadge{
 margin-left:auto;min-width:20px;height:20px;padding:0 6px;border-radius:20px;
 display:inline-flex;align-items:center;justify-content:center;
 background:linear-gradient(135deg,#a855f7,#7c3aed);color:white;font-size:10px;font-weight:900;
 box-shadow:0 0 18px #9b4dff66;animation:badgePulse 1.8s ease-in-out infinite
}
.notifyDot{width:8px;height:8px;border-radius:50%;background:#b252ff;box-shadow:0 0 12px #b252ff}
.notificationPanelItem{cursor:pointer}
.notificationPanelItem.unread{background:linear-gradient(90deg,#21142eaa,transparent);border-left:2px solid #9b4dff;padding-left:10px}
.notificationBell{position:relative}
.notificationBell .notifyBadge{position:absolute;right:-7px;top:-7px;margin:0}
.typingGlow{box-shadow:0 0 0 1px #8b5cf633,0 0 30px #7c3aed12}
.loginCard{animation:loginFloat .45s cubic-bezier(.2,.8,.2,1)}
body::before{
 content:"";position:fixed;inset:-40%;pointer-events:none;z-index:-1;
 background:radial-gradient(circle at 75% 20%,#6d28d915 0,transparent 26%),
            radial-gradient(circle at 20% 80%,#a855f710 0,transparent 28%);
 animation:ambientDrift 15s ease-in-out infinite alternate
}
@keyframes messageIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
@keyframes viewIn{from{opacity:.55;transform:translateY(4px)}to{opacity:1;transform:none}}
@keyframes modalIn{from{opacity:0;transform:translateY(12px) scale(.985)}to{opacity:1;transform:none}}
@keyframes badgePulse{0%,100%{box-shadow:0 0 12px #9b4dff44}50%{box-shadow:0 0 23px #b252ff99}}
@keyframes loginFloat{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:none}}
@keyframes ambientDrift{from{transform:translate3d(-2%,0,0)}to{transform:translate3d(2%,2%,0)}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}

@media(max-width:1000px){.app,.app.with-members{grid-template-columns:240px minmax(0,1fr)}.membersPane{display:none!important}}
@media(max-width:720px){
 body{overflow:hidden}.app,.app.with-members{display:flex;flex-direction:column}.sidebar{display:none}.main{height:calc(100vh - 62px)}.topbar{height:58px}.messages{padding:10px}.composer{padding:9px;min-height:62px}.page{padding:14px}.grid2{grid-template-columns:1fr}.mobilebar{height:62px;display:flex;background:#0c0911;border-top:1px solid var(--line);justify-content:space-around;align-items:center}.mobilebar button{background:transparent;color:#9d94a7;font-size:11px}.mobilebar button b{display:block;font-size:18px;color:#c9b7ff}.pageHero{align-items:flex-start;flex-direction:column}.topSub{display:none}
}

/* ============================================================
   SPOOKCHAT CLEAN UI
   Less Discord-like, more original SpookChat identity
   ============================================================ */

:root{
  --sc-bg:#08070b;
  --sc-panel:#100d16;
  --sc-panel-soft:#15111d;
  --sc-border:#2a2134;
  --sc-accent:#9b4dff;
  --sc-accent-2:#6d28d9;
  --sc-text:#f5f2fb;
  --sc-muted:#9c94a6;
}

body{
  background:
    radial-gradient(circle at 10% 0%,rgba(155,77,255,.10),transparent 34%),
    radial-gradient(circle at 90% 100%,rgba(109,40,217,.08),transparent 30%),
    #08070b !important;
}

.sidebar{
  background:rgba(12,9,16,.96)!important;
  border-right:1px solid rgba(255,255,255,.06)!important;
  width:250px!important;
}

.brand{
  height:70px!important;
  padding:0 18px!important;
  border-bottom:1px solid rgba(255,255,255,.06)!important;
  letter-spacing:-.02em;
}

.brandLogo{
  width:38px!important;
  height:38px!important;
  border-radius:14px!important;
  border:1px solid rgba(155,77,255,.5)!important;
  box-shadow:0 0 24px rgba(155,77,255,.20)!important;
}

.sideBtn,.serverBtn,.channelBtn{
  border-radius:12px!important;
  margin:3px 0!important;
  padding:11px 12px!important;
}

.sideBtn:hover,.serverBtn:hover,.channelBtn:hover{
  transform:none!important;
  background:rgba(155,77,255,.08)!important;
}

.sideBtn.active,.serverBtn.active,.channelBtn.active{
  background:linear-gradient(90deg,rgba(155,77,255,.18),rgba(155,77,255,.05))!important;
  box-shadow:inset 3px 0 0 var(--sc-accent)!important;
}

.main{
  background:transparent!important;
}

.topbar{
  height:70px!important;
  background:rgba(8,7,11,.72)!important;
  border-bottom:1px solid rgba(255,255,255,.06)!important;
  backdrop-filter:blur(18px)!important;
}

.content{
  background:transparent!important;
}

.messages{
  padding:24px 28px!important;
}

.msg{
  border-radius:14px!important;
  padding:10px 12px!important;
  margin-bottom:3px!important;
}

.msg:hover{
  background:rgba(255,255,255,.025)!important;
}

.msgBody{
  max-width:min(900px,92%)!important;
}

.avatar,.meAvatar{
  border:1px solid rgba(255,255,255,.08);
  box-shadow:0 0 0 3px rgba(155,77,255,.04);
}

.composer{
  margin:0 18px 16px!important;
  border:1px solid rgba(255,255,255,.07)!important;
  border-radius:16px!important;
  background:rgba(18,14,24,.94)!important;
  min-height:64px!important;
  padding:10px 12px!important;
}

.composer input{
  background:transparent!important;
  border:0!important;
  box-shadow:none!important;
}

.primary{
  border-radius:11px!important;
  background:linear-gradient(135deg,#9b4dff,#7c3aed)!important;
}

.ghost,.danger,.good,.roundBtn{
  border-radius:10px!important;
}

.card{
  border-radius:16px!important;
  background:linear-gradient(180deg,rgba(19,15,26,.96),rgba(14,11,19,.96))!important;
  border:1px solid rgba(255,255,255,.07)!important;
  box-shadow:none!important;
}

.card:hover{
  box-shadow:0 12px 35px rgba(0,0,0,.18)!important;
}

.page{
  padding:26px!important;
  max-width:1180px;
  width:100%;
  margin:0 auto;
}

.pageHero h1{
  letter-spacing:-.03em;
}

.membersPane{
  background:#0c0911!important;
  border-left:1px solid rgba(255,255,255,.06)!important;
}

.memberRow{
  border-radius:12px!important;
}

.context{
  border-radius:13px!important;
  background:#15101d!important;
  border:1px solid rgba(255,255,255,.09)!important;
  box-shadow:0 20px 60px rgba(0,0,0,.5)!important;
}

.modal{
  border-radius:18px!important;
  background:#120e19!important;
  border:1px solid rgba(255,255,255,.09)!important;
}

.notifyBadge{
  background:linear-gradient(135deg,#a855f7,#7c3aed)!important;
  border:1px solid rgba(255,255,255,.14);
}

/* Original SpookChat identity: flatter server navigation, not Discord bubbles */
.serverIcon{
  border-radius:11px!important;
  background:#1b1326!important;
  border:1px solid rgba(155,77,255,.20);
}

.sectionTitle{
  letter-spacing:.13em!important;
  color:#746d7d!important;
}

/* Softer animations */
.msg{animation:scMessage .18s ease}
.page{animation:scFade .18s ease}
.modal{animation:scModal .16s ease}
@keyframes scMessage{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}
@keyframes scFade{from{opacity:.7}to{opacity:1}}
@keyframes scModal{from{opacity:0;transform:translateY(8px) scale(.99)}to{opacity:1;transform:none}}

body.theme-light{
  --sc-bg:#f5f3f8;
  --sc-panel:#fff;
  --sc-panel-soft:#f6f2fa;
  --sc-border:#ddd5e5;
  --sc-text:#1c1722;
  --sc-muted:#706878;
  background:#f5f3f8!important;
}

body.theme-light .sidebar,
body.theme-light .membersPane{
  background:#fff!important;
}

body.theme-light .topbar,
body.theme-light .composer{
  background:rgba(255,255,255,.94)!important;
}

body.theme-light .card,
body.theme-light .modal,
body.theme-light .context{
  background:#fff!important;
  color:#1c1722!important;
}

@media(max-width:720px){
  .main{height:calc(100vh - 64px)!important}
  .topbar{height:58px!important}
  .messages{padding:14px!important}
  .composer{margin:0 10px 10px!important}
  .page{padding:16px!important}
}


/* ============================================================
   UNIVERSAL SCROLLING FIX
   ============================================================ */

/* Allow flex/grid children to actually shrink and scroll */
html,body,#root{
  width:100%;
  height:100%;
}

.app{
  min-height:0!important;
  overflow:hidden!important;
}

.main{
  min-height:0!important;
  overflow:hidden!important;
}

#mainArea{
  min-height:0!important;
  overflow:hidden!important;
}

/* Pages such as Settings, Friends, Moderation and Discover */
.page{
  flex:1 1 auto!important;
  min-height:0!important;
  height:auto!important;
  overflow-y:auto!important;
  overflow-x:hidden!important;
  overscroll-behavior:contain;
  scrollbar-gutter:stable;
  padding-bottom:42px!important;
}

/* Chat/message areas */
.content{
  flex:1 1 auto!important;
  min-height:0!important;
  overflow:hidden!important;
}

.messages{
  height:100%!important;
  min-height:0!important;
  overflow-y:auto!important;
  overflow-x:hidden!important;
  overscroll-behavior:contain;
  scrollbar-gutter:stable;
}

/* Sidebars */
.sideScroll{
  flex:1 1 auto!important;
  min-height:0!important;
  overflow-y:auto!important;
  overflow-x:hidden!important;
  overscroll-behavior:contain;
}

.servers{
  min-height:0!important;
  overflow-y:auto!important;
  overflow-x:hidden!important;
}

.membersPane{
  min-height:0!important;
  overflow-y:auto!important;
  overflow-x:hidden!important;
  overscroll-behavior:contain;
}

/* Server channel column */
.main [style*="width:190px"]{
  min-height:0;
  overflow-y:auto;
  overflow-x:hidden;
}

/* Every modal can scroll when it becomes taller than the screen */
.modalWrap{
  overflow-y:auto!important;
  overflow-x:hidden!important;
  align-items:flex-start!important;
  padding-top:5vh!important;
  padding-bottom:5vh!important;
}

.modal{
  max-height:90vh!important;
  overflow-y:auto!important;
  overflow-x:hidden!important;
  overscroll-behavior:contain;
  scrollbar-gutter:stable;
}

/* Context menus should remain accessible on short screens */
.context{
  max-height:80vh!important;
  overflow-y:auto!important;
}

/* Long cards/lists should not force the whole app outside the viewport */
.card,
.grid2,
.listItem,
.formGrid{
  min-width:0;
}

/* Mobile */
@media(max-width:720px){
  .app,
  .main,
  #mainArea{
    min-height:0!important;
  }

  .page{
    padding-bottom:90px!important;
    -webkit-overflow-scrolling:touch;
  }

  .messages,
  .sideScroll,
  .membersPane,
  .modal{
    -webkit-overflow-scrolling:touch;
  }

  .modalWrap{
    padding-top:12px!important;
    padding-bottom:80px!important;
  }

  .modal{
    max-height:calc(100vh - 100px)!important;
  }
}


/* ============================================================
   SPOOKCHAT FULL VIEWPORT / SCROLL FIX
   Sidebar, pages, modals, server columns, mobile
   ============================================================ */

html, body, #root {
  height: 100%;
  min-height: 0;
  width: 100%;
  overflow: hidden;
}

body {
  min-width: 0;
}

/* Main application viewport */
.app {
  height: 100vh !important;
  height: 100dvh !important;
  max-height: 100vh !important;
  max-height: 100dvh !important;
  min-height: 0 !important;
  overflow: hidden !important;
}

/* LEFT SIDEBAR:
   header fixed, nav scrolls, account bar fixed */
.sidebar {
  height: 100% !important;
  max-height: 100% !important;
  min-height: 0 !important;
  overflow: hidden !important;
  display: flex !important;
  flex-direction: column !important;
}

.brand {
  flex: 0 0 auto !important;
}

.sideScroll {
  flex: 1 1 0 !important;
  min-height: 0 !important;
  max-height: none !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  overscroll-behavior-y: contain !important;
  scrollbar-gutter: stable;
  padding-bottom: 24px !important;
}

.meBox {
  flex: 0 0 auto !important;
  position: relative !important;
  bottom: auto !important;
  margin-top: 0 !important;
  z-index: 5;
}

/* Main content column */
.main {
  height: 100% !important;
  max-height: 100% !important;
  min-height: 0 !important;
  overflow: hidden !important;
  display: flex !important;
  flex-direction: column !important;
}

#mainArea {
  flex: 1 1 0 !important;
  height: 100% !important;
  max-height: 100% !important;
  min-height: 0 !important;
  overflow: hidden !important;
  display: flex !important;
  flex-direction: column !important;
}

/* Top bars never scroll away */
.topbar {
  flex: 0 0 auto !important;
}

/* Generic full pages: Settings, Friends, Moderation, Discover, etc. */
.page {
  flex: 1 1 0 !important;
  min-height: 0 !important;
  max-height: 100% !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  overscroll-behavior-y: contain !important;
  scrollbar-gutter: stable;
  padding-bottom: 48px !important;
}

/* Chat area */
.content {
  flex: 1 1 0 !important;
  min-height: 0 !important;
  max-height: 100% !important;
  overflow: hidden !important;
}

.messages {
  height: 100% !important;
  max-height: 100% !important;
  min-height: 0 !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  overscroll-behavior-y: contain !important;
  scrollbar-gutter: stable;
}

/* Composer always visible */
.composer {
  flex: 0 0 auto !important;
}

/* RIGHT MEMBER PANE */
.membersPane {
  height: 100% !important;
  max-height: 100% !important;
  min-height: 0 !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  overscroll-behavior-y: contain !important;
  scrollbar-gutter: stable;
}

/* Server internal flex containers */
.main > div,
#mainArea > div {
  min-height: 0;
}

/* Force the server's channel + message row to be allowed to shrink */
#mainArea > div[style*="display:flex"],
#mainArea > div[style*="display: flex"] {
  min-height: 0 !important;
}

/* Channel list column in servers */
#mainArea div[style*="width:190px"],
#mainArea div[style*="width: 190px"] {
  min-height: 0 !important;
  max-height: 100% !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  overscroll-behavior-y: contain !important;
}

/* Server message-side column */
#mainArea div[style*="flex-direction:column"],
#mainArea div[style*="flex-direction: column"] {
  min-height: 0 !important;
}

/* Lists inside tall cards should not force viewport overflow */
.card {
  min-height: 0;
}

.grid2 {
  min-height: 0;
}

/* Modals / popups */
.modalWrap {
  overflow-y: auto !important;
  overflow-x: hidden !important;
  align-items: flex-start !important;
  padding: 24px 16px !important;
}

.modal {
  max-height: calc(100dvh - 48px) !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
  overscroll-behavior-y: contain !important;
  scrollbar-gutter: stable;
}

/* Right-click context menus */
.context {
  max-height: min(520px, 80dvh) !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
}

/* Server list / any legacy scroll container */
.servers {
  min-height: 0 !important;
  overflow-y: auto !important;
  overflow-x: hidden !important;
}

/* Make scrollbars visible enough to notice */
.sideScroll::-webkit-scrollbar,
.page::-webkit-scrollbar,
.messages::-webkit-scrollbar,
.membersPane::-webkit-scrollbar,
.modal::-webkit-scrollbar,
.context::-webkit-scrollbar {
  width: 9px;
}

.sideScroll::-webkit-scrollbar-thumb,
.page::-webkit-scrollbar-thumb,
.messages::-webkit-scrollbar-thumb,
.membersPane::-webkit-scrollbar-thumb,
.modal::-webkit-scrollbar-thumb,
.context::-webkit-scrollbar-thumb {
  background: #4a345d;
  border-radius: 20px;
}

/* MOBILE */
@media (max-width: 720px) {
  html, body, #root {
    height: 100dvh !important;
    min-height: 0 !important;
    overflow: hidden !important;
  }

  .app {
    height: calc(100dvh - 62px) !important;
    max-height: calc(100dvh - 62px) !important;
    min-height: 0 !important;
  }

  .main,
  #mainArea {
    height: 100% !important;
    max-height: 100% !important;
    min-height: 0 !important;
  }

  .mobilebar {
    flex: 0 0 62px !important;
    height: 62px !important;
  }

  .page {
    padding-bottom: 100px !important;
    -webkit-overflow-scrolling: touch;
  }

  .messages,
  .sideScroll,
  .membersPane,
  .modal,
  .context {
    -webkit-overflow-scrolling: touch;
  }

  .modalWrap {
    padding: 12px 10px 80px !important;
  }

  .modal {
    max-height: calc(100dvh - 92px) !important;
  }
}

/* Short laptop windows / users at 100% zoom */
@media (max-height: 700px) and (min-width: 721px) {
  .brand {
    height: 56px !important;
  }

  .sideBtn,
  .serverBtn,
  .channelBtn {
    padding-top: 8px !important;
    padding-bottom: 8px !important;
  }

  .sectionTitle {
    padding-top: 8px !important;
  }

  .meBox {
    padding-top: 7px !important;
    padding-bottom: 7px !important;
  }

  .topbar {
    height: 56px !important;
  }
}

</style>
</head>
<body>
<div id="root"></div>
<div id="modal"></div>
<div id="overlay"></div>
<div id="toastWrap"></div>

<script>
const state={
 me:null, profile:null, view:"public", channel:"chat1", messages:[],
 servers:[], activeServer:null, serverInfo:null, serverMembers:[],serverChannels:[],serverRoles:[],
 activeChat:null, poll:null,notifPoll:null,notifications:[],unreadCount:0,lastSeenUnread:0
};
const esc=s=>String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
const avatarSrc=s=>esc(s||"/static/spookchat_pfp.png");
const roleRank=r=>({user:0,member:0,moderator:1,admin:2,owner:3}[r]??0);
async function api(path,opts={}){
 const r=await fetch(path,{headers:{"Content-Type":"application/json",...(opts.headers||{})},...opts});
 const d=await r.json().catch(()=>({}));
 if(!r.ok) throw Error(d.error||`Request failed (${r.status})`);
 return d;
}
function toast(msg){toastWrap.innerHTML=`<div class="toast">${esc(msg)}</div>`;setTimeout(()=>toastWrap.innerHTML="",2500)}
function applyTheme(theme){document.body.classList.remove("theme-dark","theme-light");if(theme==="dark")document.body.classList.add("theme-dark");if(theme==="light")document.body.classList.add("theme-light")}
function modalOpen(title,body){modal.innerHTML=`<div class="modalWrap" onclick="if(event.target===this)modalClose()"><div class="modal"><h2>${esc(title)}</h2>${body}</div></div>`}
function modalClose(){modal.innerHTML=""}
function closeContext(){overlay.innerHTML=""}
document.addEventListener("click",e=>{if(!e.target.closest(".context"))closeContext()});

async function boot(){
 try{
   const d=await api("/api/me");
   state.me=d.user;state.profile=d.profile;
   applyTheme(state.profile.theme||"original");
   state.servers=(await api("/api/servers")).servers;
   renderApp();
   startNotificationPolling();
   setTimeout(checkInviteFromURL,150);
 }catch(e){renderLogin()}
}

function renderLogin(){
 clearInterval(state.poll);
 root.innerHTML=`<div class="login"><div class="loginCard">
 <div class="row" style="gap:12px"><img src="/static/spookchat_pfp.png" style="width:58px;height:58px;border-radius:18px;box-shadow:0 0 30px #a855f744;border:1px solid #7c3aed66"><div class="loginLogo">Spook<b>Chat</b></div></div>
 <p class="muted">A private Discord-inspired chat app.</p>
 <div class="tabs"><button id="loginTab" class="active" onclick="authForm('login')">Login</button><button id="registerTab" onclick="authForm('register')">Register</button></div>
 <div id="authArea"></div></div></div>`;
 authForm("login");
}
function authForm(mode){
 loginTab.classList.toggle("active",mode==="login");
 registerTab.classList.toggle("active",mode==="register");
 authArea.innerHTML=`<form class="formGrid" onsubmit="doAuth(event,'${mode}')">
 ${mode==="register"?'<input class="field" id="regUsername" maxlength="32" placeholder="Username" required>':""}
 <input class="field" id="authEmail" type="email" placeholder="Email" required>
 <input class="field" id="authPassword" type="password" minlength="8" placeholder="Password" required>
 <button class="primary" style="height:44px">${mode==="register"?"Create account":"Login"}</button></form>`;
}
async function doAuth(e,mode){
 e.preventDefault();
 try{
   const body={email:authEmail.value,password:authPassword.value};
   if(mode==="register")body.username=regUsername.value;
   await api("/api/"+mode,{method:"POST",body:JSON.stringify(body)});
   await boot();
 }catch(e){toast(e.message)}
}

function sidebar(){
 const isStaff=["moderator","admin","owner"].includes(state.profile.global_role);
 return `<aside class="sidebar">
 <div class="brand"><div class="brandLogo"><img src="/static/spookchat_pfp.png"></div>Spook<span>Chat</span></div>
 <div class="sideScroll">
   <div class="sectionTitle">Home</div>
   <button class="sideBtn ${state.view==="public"&&state.channel==="chat1"?"active":""}" onclick="openPublic('chat1')"><span class="iconBox">#</span>Chat 1</button>
   <button class="sideBtn ${state.view==="public"&&state.channel==="chat2"?"active":""}" onclick="openPublic('chat2')"><span class="iconBox">#</span>Chat 2</button>
   <button class="sideBtn ${state.view==="friends"?"active":""}" onclick="showFriendsPage()"><span class="iconBox">👥</span>Friends <span id="friendsUnreadSide" class="notifyBadge ${state.unreadCount?"":"hidden"}">${state.unreadCount||""}</span></button>
   <button class="sideBtn" onclick="showNotifications()"><span class="iconBox">🔔</span>Notifications <span id="notificationsUnreadSide" class="notifyBadge ${state.unreadCount?"":"hidden"}">${state.unreadCount||""}</span></button>
   <button class="sideBtn" onclick="groupCreate()"><span class="iconBox">＋</span>New Group</button>
   ${isStaff?`<button class="sideBtn ${state.view==="staff"?"active":""}" onclick="showStaff()"><span class="iconBox">🛡</span>Moderation</button>`:""}
   <button class="sideBtn ${state.view==="settings"?"active":""}" onclick="showSettings()"><span class="iconBox">⚙</span>SpookChat Settings</button>
   <a class="sideBtn" href="/static/downloads/SpookChatPCSet-up.exe" download="SpookChatPCSet-up.exe" style="text-decoration:none"><span class="iconBox">⬇</span>Download Desktop App</a>
   <button class="sideBtn ${state.view==="discover"?"active":""}" onclick="showServerDiscovery()"><span class="iconBox">🔎</span>Discover Servers</button>

   <div class="sectionTitle"><span>Your Servers</span><button class="roundBtn" style="width:27px;height:27px" onclick="serverCreate()">＋</button></div>
   ${state.servers.map(s=>`<button class="serverBtn ${state.activeServer==s.id?"active":""}" onclick="openServer(${s.id},'chat')">
      <span class="serverIcon">${s.icon?`<img src="${esc(s.icon)}" onerror="this.remove()">`:esc((s.name||"S")[0].toUpperCase())}</span>
      <span style="min-width:0;overflow:hidden;text-overflow:ellipsis">${esc(s.name)}</span><span class="badge">${s.member_count}</span>
   </button>`).join("")}
 </div>
 <div class="meBox">
   <img class="meAvatar" src="${avatarSrc(state.profile.avatar)}" onerror="this.style.visibility='hidden'">
   <div class="meText"><div class="meName">${esc(state.profile.username)}</div><div class="meRole">${esc(state.profile.global_role)}</div></div>
   <button class="roundBtn" onclick="showSettings()">⚙</button>
   <button class="roundBtn" onclick="logout()">↪</button>
 </div></aside>`;
}

function mobilebar(){
 return `<nav class="mobilebar">
 <button onclick="openPublic('chat1')"><b>#</b>Chat</button>
 <button onclick="showFriendsPage()" style="position:relative"><b>👥</b>Friends<span id="friendsUnreadMobile" class="notifyBadge ${state.unreadCount?"":"hidden"}" style="position:absolute;top:0;right:2px">${state.unreadCount||""}</span></button>
 <button onclick="showNotifications()" style="position:relative"><b>🔔</b>Alerts<span id="notificationsUnreadMobile" class="notifyBadge ${state.unreadCount?"":"hidden"}" style="position:absolute;top:0;right:2px">${state.unreadCount||""}</span></button>
 <button onclick="showServersMobile()"><b>◈</b>Servers</button>
 <button onclick="showSettings()"><b>⚙</b>Settings</button>
 </nav>`;
}


function notificationBellButton(){
 return `<button class="roundBtn notificationBell" onclick="showNotifications()" title="Notifications">🔔<span class="notifyBadge ${state.unreadCount?"":"hidden"}">${state.unreadCount||""}</span></button>`;
}
function updateNotificationBadges(){
 const n=state.unreadCount||0;
 ["friendsUnreadSide","notificationsUnreadSide","friendsUnreadMobile","notificationsUnreadMobile"].forEach(id=>{
   const e=document.getElementById(id);if(!e)return;e.textContent=n||"";e.classList.toggle("hidden",!n);
 });
 document.querySelectorAll(".notificationBell .notifyBadge").forEach(e=>{e.textContent=n||"";e.classList.toggle("hidden",!n)});
}

function renderApp(){
 clearInterval(state.poll);
 root.innerHTML=`<div id="appShell" class="app">${sidebar()}<main class="main"><div id="mainArea" style="height:100%;display:flex;flex-direction:column"></div></main><aside id="membersPane" class="membersPane"></aside></div>${mobilebar()}`;
 if(state.view==="friends")renderFriendsPage();
 else if(state.view==="settings")renderSettings();
 else if(state.view==="staff")renderStaff();
 else if(state.view==="discover")renderServerDiscovery();
 else if(state.view==="server")renderServer();
 else renderChat();
 setTimeout(updateNotificationBadges,0);
}

function renderChat(){
 const title=state.view==="public"?(state.channel==="chat1"?"# Chat 1":"# Chat 2"):"Chat";
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">${esc(title)}</div><div class="topSub">Public SpookChat channel</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="content"><div id="messageList" class="messages"></div></div>
 <div class="composer"><input id="messageInput" maxlength="4000" placeholder="Message ${esc(title)}..." onkeydown="if(event.key==='Enter'){event.preventDefault();sendMessage()}"><button class="primary" onclick="sendMessage()">Send</button></div>`;
 appShell.classList.remove("with-members");
 loadMessages();
 state.poll=setInterval(loadMessages,1200);
}
function openPublic(c){state.view="public";state.channel=c;state.activeServer=null;state.serverInfo=null;renderApp()}

async function loadMessages(){
 try{
   let url;
   if(state.view==="public")url=`/api/messages?kind=public&channel=${encodeURIComponent(state.channel)}`;
   else if(state.view==="server")url=`/api/messages?kind=server&channel=${encodeURIComponent(state.channel)}&server_id=${state.activeServer}`;
   else if(state.view==="dm")url=`/api/messages?kind=dm&chat_id=${state.activeChat}`;
   else return;
   const d=await api(url);state.messages=d.messages;drawMessages();
 }catch(e){}
}
function drawMessages(){
 const el=document.getElementById("messageList");if(!el)return;
 const near=el.scrollHeight-el.scrollTop-el.clientHeight<130;
 if(!state.messages.length){el.innerHTML=`<div class="empty">No messages here yet.<br>Be the first to say something.</div>`;return}
 el.innerHTML=state.messages.map(m=>`<div class="msg" oncontextmenu="messageMenu(event,${m.id})">
   <img class="avatar" src="${avatarSrc(m.avatar)}" onerror="this.style.visibility='hidden'">
   <div class="msgBody"><div class="meta"><span class="name">${esc(m.username)}</span>
   ${m.is_spookhook?`<span class="roleTag">SPOOKHOOK</span>`:(m.role&&m.role!=="user"&&m.role!=="member"?`<span class="roleTag">${esc(m.role)}</span>`:"")}
   <span class="time">${new Date(m.created_at).toLocaleString([], {hour:'2-digit',minute:'2-digit'})}</span>
   ${m.edited_at?`<span class="edited">(edited)</span>`:""}</div><div class="text">${esc(m.content)}</div></div>
 </div>`).join("");
 if(near)el.scrollTop=el.scrollHeight;
}
async function sendMessage(){
 const inp=document.getElementById("messageInput");const content=inp.value.trim();if(!content)return;
 const b={content};
 if(state.view==="public"){b.kind="public";b.channel=state.channel}
 else if(state.view==="server"){b.kind="server";b.channel=state.channel;b.server_id=state.activeServer}
 else {b.kind="dm";b.chat_id=state.activeChat}
 try{await api("/api/messages",{method:"POST",body:JSON.stringify(b)});inp.value="";await loadMessages()}catch(e){toast(e.message)}
}
function messageMenu(ev,id){
 ev.preventDefault();ev.stopPropagation();
 const m=state.messages.find(x=>x.id===id);if(!m)return;
 const mine=Number(m.user_id)===Number(state.me.id);
 const globalStaff=["moderator","admin","owner"].includes(state.profile.global_role);
 const serverStaff=state.view==="server"&&state.serverInfo&&["moderator","admin","owner"].includes(state.serverInfo.my_role);
 const canDelete=mine||globalStaff||serverStaff;
 overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-220)}px;top:${Math.min(ev.clientY,innerHeight-260)}px" onclick="event.stopPropagation()">
 <button onclick="viewProfile(${m.user_id});closeContext()">👤 View profile</button>
 <button onclick="navigator.clipboard.writeText(${JSON.stringify(m.content)});toast('Copied');closeContext()">📋 Copy message</button>
 <button onclick="reportMessage(${m.id});closeContext()">🚩 Report message</button>
 ${mine?`<button onclick="editMessagePrompt(${m.id});closeContext()">✏️ Edit message</button>`:""}
 ${canDelete?`<button class="red" onclick="deleteMessage(${m.id});closeContext()">🗑 Delete message</button>`:""}
 </div>`;
}
async function reportMessage(id){try{await api("/api/reports",{method:"POST",body:JSON.stringify({message_id:id})});toast("Report sent to staff")}catch(e){toast(e.message)}}
async function deleteMessage(id){try{await api("/api/messages/"+id,{method:"DELETE"});loadMessages()}catch(e){toast(e.message)}}
function editMessagePrompt(id){
 const m=state.messages.find(x=>x.id===id);
 modalOpen("Edit message",`<form class="formGrid" onsubmit="saveEditedMessage(event,${id})"><textarea id="editText" class="field" rows="5" maxlength="4000">${esc(m.content)}</textarea><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Save</button></div></form>`);
}
async function saveEditedMessage(e,id){e.preventDefault();try{await api("/api/messages/"+id,{method:"PATCH",body:JSON.stringify({content:editText.value})});modalClose();loadMessages()}catch(e){toast(e.message)}}

async function viewProfile(uid){
 try{
   const d=await api("/api/profile/"+uid);
   const p=d.profile;
   modalOpen("User profile",`<div class="row"><img class="avatar" style="width:72px;height:72px" src="${avatarSrc(p.avatar)}" onerror="this.style.visibility='hidden'"><div><h2 style="margin:0">${esc(p.username)}</h2><span class="pill">${esc(p.global_role)}</span> <span class="pill">${p.device_type==="Mobile"?"📱 Mobile":"🖥 PC"}</span></div></div>
   <div class="card" style="margin-top:14px"><div class="listSub">Spook ID: #${p.id}</div><div class="muted" style="margin-top:8px">${esc(p.pronouns||"No pronouns set")}</div><p>${esc(p.description||"No description.")}</p><div class="muted">${esc(p.company||"")}</div></div>
   ${Number(uid)!==Number(state.me.id)?`<div class="modalActions"><button class="primary" onclick="addFriend(${uid});modalClose()">Add friend</button><button class="ghost" onclick="startDM(${uid});modalClose()">Message</button></div>`:""}`);
 }catch(e){toast(e.message)}
}

async function showFriendsPage(){state.view="friends";state.activeServer=null;renderApp()}
async function renderFriendsPage(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Friends</div><div class="topSub">Find people and manage conversations</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page"><div class="pageHero"><div><h1>Your friends</h1><div class="muted">Search SpookChat by username or open a DM.</div></div><button class="primary" onclick="groupCreate()">＋ New group chat</button></div>
 <div class="card"><h3>Find people</h3><div class="searchBox"><input id="userSearchInput" placeholder="Search username or Spook ID (#123)..." onkeydown="if(event.key==='Enter')searchUsers()"><button class="primary" onclick="searchUsers()">Search</button></div><div id="userSearchResults"></div></div>
 <div class="card"><h3>Friends list</h3><div id="friendsList">Loading...</div></div>
 <div class="card"><h3>Your direct & group chats</h3><div id="chatList">Loading...</div></div></div>`;
 const d=await api("/api/friends");drawFriends(d.friends);
 const chats=await api("/api/chats");drawChats(chats.chats);
}
function drawFriends(list){
 friendsList.innerHTML=list.length?list.map(f=>`<div class="listItem"><img class="avatar" src="${avatarSrc(f.avatar)}" onerror="this.style.visibility='hidden'"><div class="listMain"><div class="listTitle">${esc(f.username)}</div><div class="listSub">${esc(f.pronouns||"")}</div></div><button class="ghost" onclick="viewProfile(${f.id})">Profile</button><button class="primary" onclick="startDM(${f.id})">Message</button></div>`).join(""):`<div class="empty">You haven't added anyone yet.</div>`;
}
async function searchUsers(){
 const q=userSearchInput.value.trim();if(!q){userSearchResults.innerHTML="";return}
 try{
   const d=await api("/api/users/search?q="+encodeURIComponent(q));
   userSearchResults.innerHTML=d.users.length?d.users.map(u=>`<div class="listItem"><img class="avatar" src="${avatarSrc(u.avatar)}" onerror="this.style.visibility='hidden'"><div class="listMain"><div class="listTitle">${esc(u.username)}</div><div class="listSub">#${u.id}${u.company?` · ${esc(u.company)}`:""}</div></div>${u.is_friend?'<span class="pill">Friend</span>':`<button class="primary" onclick="addFriend(${u.id})">Add friend</button>`}<button class="ghost" onclick="viewProfile(${u.id})">Profile</button></div>`).join(""):`<div class="muted">No usernames found.</div>`;
 }catch(e){toast(e.message)}
}
async function addFriend(uid){try{await api("/api/friends",{method:"POST",body:JSON.stringify({user_id:uid})});toast("Friend added");if(state.view==="friends"){renderFriendsPage()}}catch(e){toast(e.message)}}
async function startDM(uid){try{const d=await api("/api/dms",{method:"POST",body:JSON.stringify({user_id:uid})});state.view="dm";state.activeChat=d.chat_id;state.activeServer=null;renderDM(d.chat_id)}catch(e){toast(e.message)}}
function drawChats(list){chatList.innerHTML=list.length?list.map(c=>`<button class="sideBtn" onclick="openChat(${c.id})"><span class="iconBox">${c.kind==="group"?"👥":"💬"}</span>${esc(c.display_name)}</button>`).join(""):`<div class="muted">No DMs or groups yet.</div>`}
async function openChat(id){state.view="dm";state.activeChat=id;state.activeServer=null;renderDM(id)}
async function renderDM(id){
 clearInterval(state.poll);
 root.innerHTML=`<div id="appShell" class="app">${sidebar()}<main class="main"><div id="mainArea" style="height:100%;display:flex;flex-direction:column"></div></main><aside id="membersPane" class="membersPane"></aside></div>${mobilebar()}`;
 let info=await api("/api/chats/"+id);
 await markChatNotificationsRead(id);
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">${esc(info.chat.display_name)}</div><div class="topSub">${info.chat.kind==="group"?"Group chat":"Direct message"}</div></div><div class="topActions">${notificationBellButton()}</div></header><div class="content"><div id="messageList" class="messages"></div></div><div class="composer"><input id="messageInput" maxlength="4000" placeholder="Message..." onkeydown="if(event.key==='Enter'){event.preventDefault();sendMessage()}"><button class="primary" onclick="sendMessage()">Send</button></div>`;
 loadMessages();state.poll=setInterval(loadMessages,1200);
}
function groupCreate(){modalOpen("Create group chat",`<form class="formGrid" onsubmit="makeGroup(event)"><div class="label">Group name</div><input id="groupName" class="field" maxlength="50" required><div class="label">Add usernames</div><input id="groupUsers" class="field" placeholder="alex, sam, jordan"><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Create</button></div></form>`)}
async function makeGroup(e){e.preventDefault();try{const d=await api("/api/groups",{method:"POST",body:JSON.stringify({name:groupName.value,usernames:groupUsers.value.split(",").map(x=>x.trim()).filter(Boolean)})});modalClose();openChat(d.chat_id)}catch(e){toast(e.message)}}


function showServerDiscovery(){state.view="discover";state.activeServer=null;state.serverInfo=null;renderApp()}
async function renderServerDiscovery(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Discover Servers</div><div class="topSub">Browse and join SpookChat communities</div></div><div class="topActions"><button class="primary" onclick="serverCreate()">＋ Create Server</button></div></header>
 <div class="page"><div class="pageHero"><div><h1>Server Discovery</h1><div class="muted">Every public SpookChat server appears here. Search by name and join instantly.</div></div></div>
 <div class="card"><div class="searchBox"><input id="serverDiscoverySearch" class="field" placeholder="Search servers..." oninput="searchServersDebounced()"><button class="primary" onclick="loadServerDiscovery()">Search</button></div></div>
 <div id="serverDiscoveryList" class="grid2"><div class="muted">Loading servers...</div></div></div>`;
 await loadServerDiscovery();
}
let serverSearchTimer=null;
function searchServersDebounced(){clearTimeout(serverSearchTimer);serverSearchTimer=setTimeout(loadServerDiscovery,250)}
async function loadServerDiscovery(){
 const list=document.getElementById("serverDiscoveryList");if(!list)return;
 const q=document.getElementById("serverDiscoverySearch")?.value.trim()||"";
 try{
   const d=await api("/api/servers/discover?q="+encodeURIComponent(q));
   list.innerHTML=d.servers.length?d.servers.map(s=>`<div class="card" style="margin:0">
     <div class="row" style="align-items:flex-start">
       <div class="serverIcon" style="width:58px;height:58px;border-radius:16px;font-size:20px">${s.icon?`<img src="${esc(s.icon)}" onerror="this.remove()">`:esc((s.name||"S")[0].toUpperCase())}</div>
       <div class="listMain"><div class="listTitle" style="font-size:17px">${esc(s.name)}</div><div class="listSub">${s.member_count} member${s.member_count===1?"":"s"} · Owner: ${esc(s.owner_username)}</div></div>
     </div>
     <div class="row" style="margin-top:14px">
       ${s.joined?`<button class="good" style="flex:1" onclick="openServer(${s.id},'chat')">Joined · Open Server</button>`:(s.request_pending?`<button class="ghost" style="flex:1" disabled>Join Request Pending</button>`:`<button class="primary" style="flex:1" onclick="joinServer(${s.id})">${s.privacy_mode==="public_approval"?"Request to Join":"Join Server"}</button>`)}
     </div>
   </div>`).join(""):`<div class="card" style="grid-column:1/-1"><div class="empty">No servers match your search.</div></div>`;
 }catch(e){list.innerHTML=`<div class="card"><div class="muted">${esc(e.message)}</div></div>`}
}
async function joinServer(id){
 try{
   const d=await api(`/api/servers/${id}/join`,{method:"POST"});
   if(d.join_request){
     toast("Join request sent to the server owner");
     await loadServerDiscovery();
     return;
   }
   state.servers=(await api("/api/servers")).servers;
   toast("Joined server");
   await loadServerDiscovery();
   const oldView=state.view;renderApp();state.view=oldView;
 }catch(e){toast(e.message)}
}

function serverCreate(){modalOpen("Create server",`<form class="formGrid" onsubmit="makeServer(event)"><div class="label">Server name</div><input id="newServerName" class="field" maxlength="60" required><div class="label">Server picture URL (optional)</div><input id="newServerIcon" class="field" maxlength="500"><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Create server</button></div></form>`)}
async function makeServer(e){e.preventDefault();try{await api("/api/servers",{method:"POST",body:JSON.stringify({name:newServerName.value,icon:newServerIcon.value})});modalClose();state.servers=(await api("/api/servers")).servers;renderApp()}catch(e){toast(e.message)}}
async function openServer(id,ch=null){
 state.view="server";state.activeServer=Number(id);
 try{
   state.serverInfo=(await api("/api/servers/"+id)).server;
   state.serverMembers=(await api("/api/servers/"+id+"/members")).members;
   state.serverChannels=(await api("/api/servers/"+id+"/channels")).channels;
   state.serverRoles=(await api("/api/servers/"+id+"/roles")).roles;
   if(ch && !Number.isNaN(Number(ch)))state.channel=Number(ch);
   else if(ch){const found=state.serverChannels.find(c=>c.name===ch||c.name===String(ch).replace("announcement","announcements"));state.channel=found?found.id:(state.serverChannels[0]?.id||null)}
   else if(!state.serverChannels.some(c=>Number(c.id)===Number(state.channel)))state.channel=state.serverChannels[0]?.id||null;
   renderApp()
 }catch(e){toast(e.message)}
}
function renderServer(){
 clearInterval(state.poll);
 const s=state.serverInfo; if(!s){openPublic("chat1");return}
 appShell.classList.add("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">${esc(s.name)}</div><div class="topSub">${s.member_count} member${s.member_count===1?"":"s"}</div></div><div class="topActions">${notificationBellButton()}<button class="ghost" onclick="showServerInvite(${s.id})">🔗 Invite</button>${s.my_role==="owner"?`<button class="ghost" onclick="showServerSettings(${s.id})">⚙ Server settings</button>`:""}<button class="ghost" onclick="toggleMembers()">👥 Members</button></div></header>
 <div style="display:flex;min-height:0;flex:1">
   <div style="width:190px;border-right:1px solid var(--line);padding:12px;background:#0d0a12">
     <div class="sectionTitle"><span>Channels</span>${s.my_role==="owner"?`<button class="roundBtn" style="width:25px;height:25px" onclick="createChannelPrompt()">＋</button>`:""}</div>
     ${state.serverChannels.map(c=>`<button class="channelBtn ${Number(state.channel)===Number(c.id)?"active":""}" onclick="openServer(${s.id},${c.id})" oncontextmenu="channelMenu(event,${c.id})">${c.kind==="announcement"?"📢":"#"} ${esc(c.name)}</button>`).join("")||'<div class="muted" style="padding:10px">No visible channels</div>'}
   </div>
   <div style="min-width:0;flex:1;display:flex;flex-direction:column"><div class="content"><div id="messageList" class="messages"></div></div><div class="composer"><input id="messageInput" maxlength="4000" placeholder="Message channel..." onkeydown="if(event.key==='Enter'){event.preventDefault();sendMessage()}"><button class="primary" onclick="sendMessage()">Send</button></div></div>
 </div>`;
 renderMembers();
 loadMessages();state.poll=setInterval(loadMessages,1200);
}
function renderMembers(){
 const p=document.getElementById("membersPane");if(!p)return;
 p.innerHTML=`<div class="memberHead">Members · ${state.serverMembers.length}</div><div style="padding-top:8px">${state.serverMembers.map(m=>`<div class="memberRow" ${["owner","admin","moderator"].includes(state.serverInfo.my_role)?`oncontextmenu="serverMemberMenu(event,${m.id})"`:""}><img class="avatar" src="${avatarSrc(m.avatar)}" onerror="this.style.visibility='hidden'"><div class="memberInfo"><div class="memberName">${esc(m.username)}</div><div class="memberRole">${esc(m.role)} · ${m.device_type==="Mobile"?"📱":"🖥"}${m.muted?" · muted":""}${m.banned?" · banned":""}</div></div></div>`).join("")}</div>`;
}
function toggleMembers(){appShell.classList.toggle("with-members")}
function serverMemberMenu(ev,uid){
 ev.preventDefault();ev.stopPropagation();
 const m=state.serverMembers.find(x=>x.id===uid);if(!m)return;
 const my=state.serverInfo.my_role;const canRole=my==="owner"&&m.role!=="owner";const canMute=["owner","admin","moderator"].includes(my)&&m.role!=="owner";const canBan=["owner","admin"].includes(my)&&m.role!=="owner";
 overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-220)}px;top:${Math.min(ev.clientY,innerHeight-290)}px" onclick="event.stopPropagation()">
 <button onclick="viewProfile(${uid});closeContext()">👤 View profile</button>
 ${canMute?`<button onclick="serverAction(${uid},'${m.muted?"unmute":"mute"}');closeContext()">🔇 ${m.muted?"Unrestrict":"Restrict from talking"}</button>`:""}
 ${canBan?`<button class="red" onclick="serverAction(${uid},'${m.banned?"unban":"ban"}');closeContext()">⛔ ${m.banned?"Unban":"Ban from server"}</button>`:""}
 ${canRole?`<button onclick="changeServerRole(${uid});closeContext()">🛡 Change server role</button>`:""}
 </div>`;
}
async function serverAction(uid,action){try{await api("/api/server/member-action",{method:"POST",body:JSON.stringify({server_id:state.activeServer,user_id:uid,action,minutes:60})});await openServer(state.activeServer,state.channel);toast("Member updated")}catch(e){toast(e.message)}}
function changeServerRole(uid){modalOpen("Change server role",`<form class="formGrid" onsubmit="saveServerRole(event,${uid})"><select id="serverRoleSelect" class="field"><option value="member">Member</option><option value="moderator">Moderator</option><option value="admin">Admin</option></select><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Save</button></div></form>`)}
async function saveServerRole(e,uid){e.preventDefault();try{await api("/api/server/member-action",{method:"POST",body:JSON.stringify({server_id:state.activeServer,user_id:uid,action:"role",role:serverRoleSelect.value})});modalClose();await openServer(state.activeServer,state.channel)}catch(e){toast(e.message)}}
async function showServerSettings(id){
 try{
   const d=await api("/api/servers/"+id+"/members");
   const s=state.serverInfo;
   modalOpen("Server settings",`<div class="formGrid"><div class="label">Server name</div><input id="serverSetName" class="field" value="${esc(s.name)}"><div class="label">Server picture URL</div><input id="serverSetIcon" class="field" value="${esc(s.icon||"")}"><div class="label">Server privacy</div><select id="serverPrivacyMode" class="field"><option value="public" ${s.privacy_mode==="public"?"selected":""}>Public — anyone can join</option><option value="public_approval" ${s.privacy_mode==="public_approval"?"selected":""}>Public + Owner Approval — join requests</option><option value="invite_only" ${s.privacy_mode==="invite_only"?"selected":""}>Invite Only — hidden from Discover</option><option value="private" ${s.privacy_mode==="private"?"selected":""}>Private — no joining</option></select><button class="primary" onclick="saveServerSettings(${id})">Save server settings</button></div>
   <div class="card" style="margin-top:16px"><h3>Joining</h3><div class="muted">Members can only join this server themselves from Discover Servers.</div></div><div class="card"><div class="row between"><div><h3 style="margin:0">Join Requests</h3><div class="muted">Used when Server Privacy is set to Public + Owner Approval.</div></div><button class="ghost" onclick="loadJoinRequests(${id})">Refresh</button></div><div id="joinRequestsList" style="margin-top:10px">Loading...</div></div>
   <div class="card"><div class="row between"><h3 style="margin:0">Custom Roles</h3><button class="primary" onclick="createCustomRole(${id})">＋ Role</button></div><div style="margin-top:10px">${state.serverRoles.length?state.serverRoles.map(r=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(r.name)}</div><div class="listSub">Custom access role</div></div><button class="danger" onclick="deleteCustomRole(${id},${r.id})">Delete</button></div>`).join(""):'<div class="muted">No custom roles yet.</div>'}</div>
   <div class="card"><h3>Members (${d.members.length})</h3>${d.members.map(m=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(m.username)}</div><div class="listSub">${esc(m.role)}</div></div>${m.role!=="owner"?`<button class="ghost" onclick="changeServerRoleFromSettings(${id},${m.id})">Staff Role</button><button class="ghost" onclick="manageMemberCustomRoles(${id},${m.id},'${esc(m.username)}')">Custom Roles</button><button class="danger" onclick="removeServerMember(${id},${m.id})">Remove</button>`:""}</div>`).join("")}</div>
   <div class="card"><h3>Danger zone</h3><button class="danger" onclick="deleteServer(${id})">Delete server</button></div>`);
   setTimeout(()=>loadJoinRequests(id),20);
 }catch(e){toast(e.message)}
}

async function loadJoinRequests(sid){
 const el=document.getElementById("joinRequestsList");if(!el)return;
 try{
   const d=await api(`/api/servers/${sid}/join-requests`);
   el.innerHTML=d.requests.length?d.requests.map(r=>`<div class="listItem"><img class="avatar" src="${avatarSrc(r.avatar)}"><div class="listMain"><div class="listTitle">${esc(r.username)}</div><div class="listSub">Spook ID #${r.user_id} · Requested ${new Date(r.created_at).toLocaleString()}</div></div><button class="good" onclick="decideJoinRequest(${sid},${r.request_id},'accept')">Accept</button><button class="danger" onclick="decideJoinRequest(${sid},${r.request_id},'deny')">Deny</button></div>`).join(""):`<div class="muted">No pending join requests.</div>`;
 }catch(e){el.innerHTML=`<div class="muted">${esc(e.message)}</div>`}
}
async function decideJoinRequest(sid,rid,decision){
 try{
   await api(`/api/servers/${sid}/join-requests/${rid}`,{method:"POST",body:JSON.stringify({decision})});
   toast(decision==="accept"?"Member accepted":"Join request denied");
   loadJoinRequests(sid);
 }catch(e){toast(e.message)}
}

async function saveServerSettings(id){try{await api("/api/servers/"+id,{method:"PATCH",body:JSON.stringify({name:serverSetName.value,icon:serverSetIcon.value,privacy_mode:serverPrivacyMode.value})});state.servers=(await api("/api/servers")).servers;state.serverInfo=(await api("/api/servers/"+id)).server;toast("Server updated");modalClose();renderApp()}catch(e){toast(e.message)}}
function changeServerRoleFromSettings(id,uid){changeServerRole(uid)}
async function removeServerMember(id,uid){if(!confirm("Remove this member from the server?"))return;try{await api(`/api/servers/${id}/members/${uid}`,{method:"DELETE"});modalClose();await openServer(id,state.channel);showServerSettings(id)}catch(e){toast(e.message)}}
async function deleteServer(id){if(!confirm("Permanently delete this server and all of its messages?"))return;try{await api("/api/servers/"+id,{method:"DELETE"});modalClose();state.activeServer=null;state.serverInfo=null;state.servers=(await api("/api/servers")).servers;openPublic("chat1")}catch(e){toast(e.message)}}
function showServersMobile(){modalOpen("Your servers",state.servers.map(s=>`<button class="serverBtn" onclick="modalClose();openServer(${s.id},'chat')"><span class="serverIcon">${s.icon?`<img src="${esc(s.icon)}">`:esc(s.name[0])}</span>${esc(s.name)}<span class="badge">${s.member_count}</span></button>`).join("")||"<div class='muted'>No servers yet.</div>")}

function showSettings(){state.view="settings";state.activeServer=null;renderApp()}
function renderSettings(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">SpookChat Settings</div><div class="topSub">Profile and account settings</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page"><div class="pageHero"><div><h1>Settings</h1><div class="muted">Control how your account appears across SpookChat.</div></div></div>
 <div class="grid2"><div class="card"><h3>Profile</h3><form class="formGrid" onsubmit="saveProfile(event)">
 <div class="label">Username</div><input id="setUsername" class="field" maxlength="32" value="${esc(state.profile.username)}">
 <div class="label">Pronouns</div><input id="setPronouns" class="field" maxlength="40" value="${esc(state.profile.pronouns||"")}">
 <div class="label">Company</div><input id="setCompany" class="field" maxlength="80" value="${esc(state.profile.company||"")}">
 <div class="label">Profile picture URL</div><input id="setAvatar" class="field" maxlength="500" value="${esc(state.profile.avatar||"")}">
 <div class="label">Description</div><textarea id="setDescription" class="field" rows="5" maxlength="300">${esc(state.profile.description||"")}</textarea>
 <button class="primary">Save profile</button></form></div>
 <div><div class="card"><h3>Account & Appearance</h3><div class="listItem"><div class="listMain"><div class="listTitle">Spook ID</div><div class="listSub">Use this to find your account precisely</div></div><span class="pill">#${state.me.id}</span></div><div class="listItem"><div class="listMain"><div class="listTitle">Global role</div><div class="listSub">Your site-wide permission level</div></div><span class="pill">${esc(state.profile.global_role)}</span></div>
 <div class="formGrid" style="margin-top:14px"><div class="label">Theme</div><select id="themeSelect" class="field"><option value="original" ${state.profile.theme==="original"?"selected":""}>Original Dark + Purple</option><option value="dark" ${state.profile.theme==="dark"?"selected":""}>Dark</option><option value="light" ${state.profile.theme==="light"?"selected":""}>Light</option></select>${["moderator","admin","owner"].includes(state.profile.global_role)?`<label class="row"><input id="staffTagToggle" type="checkbox" ${state.profile.show_staff_tag?"checked":""}> Show my staff tag publicly</label>`:""}<button class="ghost" onclick="savePreferences()">Save appearance</button></div>
 <form class="formGrid" onsubmit="changePassword(event)" style="margin-top:14px"><div class="label">New password</div><input id="newPassword" class="field" type="password" minlength="8" placeholder="At least 8 characters"><button class="ghost">Change password</button></form></div>
 <div class="card"><h3>Notifications</h3><div class="muted" style="margin-bottom:12px">SpookChat can show a Windows/browser popup when a new DM or group message arrives while the app is in the background.</div><div class="row"><button class="primary" type="button" onclick="enableDesktopNotifications()">Enable desktop notifications</button><button class="ghost" type="button" onclick="disableDesktopNotifications()">Disable</button></div></div>
 <div class="card"><h3>Desktop App</h3><div class="muted" style="margin-bottom:12px">Install the Windows desktop version of SpookChat.</div><a class="primary" href="/static/downloads/SpookChatPCSet-up.exe" download="SpookChatPCSet-up.exe" style="display:inline-block;text-decoration:none">Download SpookChat for Windows</a></div>
 ${state.profile.global_role==="owner"?`<div class="card"><h3>Owner Security</h3><div class="muted" style="margin-bottom:12px">Set a separate password required before viewing sensitive moderation account records.</div><form class="formGrid" onsubmit="setAccountInfoPassword(event)"><div class="label">Account Info Access Password</div><input id="accountInfoAccessPassword" class="field" type="password" minlength="8" placeholder="At least 8 characters" required><button class="primary">Set / Change Access Password</button></form></div>`:""}<div class="card"><h3>Session</h3><button class="danger" onclick="logout()">Log out of SpookChat</button></div></div></div></div>`;
}
async function saveProfile(e){e.preventDefault();try{const d=await api("/api/profile",{method:"PATCH",body:JSON.stringify({username:setUsername.value,pronouns:setPronouns.value,company:setCompany.value,avatar:setAvatar.value,description:setDescription.value})});state.profile=d.profile;state.servers=(await api("/api/servers")).servers;toast("Profile saved");renderApp()}catch(e){toast(e.message)}}
async function changePassword(e){e.preventDefault();try{await api("/api/account/password",{method:"POST",body:JSON.stringify({password:newPassword.value})});newPassword.value="";toast("Password changed")}catch(e){toast(e.message)}}


async function savePreferences(){try{const body={theme:themeSelect.value};if(document.getElementById("staffTagToggle"))body.show_staff_tag=staffTagToggle.checked;const d=await api("/api/account/preferences",{method:"POST",body:JSON.stringify(body)});state.profile.theme=d.theme;state.profile.show_staff_tag=d.show_staff_tag;applyTheme(d.theme);toast("Preferences saved")}catch(e){toast(e.message)}}

function createChannelPrompt(){modalOpen("Create channel",`<form class="formGrid" onsubmit="createChannel(event)"><div class="label">Channel name</div><input id="newChannelName" class="field" maxlength="40" required><div class="label">Type</div><select id="newChannelKind" class="field"><option value="chat">Chat</option><option value="announcement">Announcement</option></select><div class="modalActions"><button class="primary">Create</button></div></form>`)}
async function createChannel(e){e.preventDefault();try{await api(`/api/servers/${state.activeServer}/channels`,{method:"POST",body:JSON.stringify({name:newChannelName.value,kind:newChannelKind.value})});modalClose();await openServer(state.activeServer)}catch(e){toast(e.message)}}

async function channelMenu(ev,cid){ev.preventDefault();ev.stopPropagation();if(state.serverInfo.my_role!=="owner")return;overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-220)}px;top:${Math.min(ev.clientY,innerHeight-230)}px" onclick="event.stopPropagation()"><button onclick="channelSettings(${cid});closeContext()">⚙ Channel settings</button><button onclick="showSpookHooks(${cid});closeContext()">🔗 SpookHooks (Beta)</button><button class="red" onclick="deleteChannel(${cid});closeContext()">🗑 Delete channel</button></div>`}
function permissionChoices(selected,prefix){const built=[["member","Member"],["moderator","Moderator"],["admin","Admin"],["owner","Owner"]];const custom=state.serverRoles.map(r=>[`custom:${r.id}`,r.name]);return [...built,...custom].map(([v,n])=>`<label class="row"><input type="checkbox" data-${prefix}="${esc(v)}" ${selected.includes(v)?"checked":""}> ${esc(n)}</label>`).join("")}
async function channelSettings(cid){const c=state.serverChannels.find(x=>Number(x.id)===Number(cid));if(!c)return;modalOpen("Channel settings",`<form class="formGrid" onsubmit="saveChannelSettings(event,${cid})"><div class="label">Channel name</div><input id="channelSetName" class="field" value="${esc(c.name)}"><div class="grid2"><div class="card"><h3>Who can VIEW</h3>${permissionChoices(c.view_roles,"viewrole")}</div><div class="card"><h3>Who can TALK</h3>${permissionChoices(c.talk_roles,"talkrole")}</div></div><div class="muted">Owner always has access regardless of these settings.</div><div class="modalActions"><button class="primary">Save channel</button></div></form>`)}
async function saveChannelSettings(e,cid){e.preventDefault();const view_roles=[...document.querySelectorAll("[data-viewrole]:checked")].map(x=>x.dataset.viewrole);const talk_roles=[...document.querySelectorAll("[data-talkrole]:checked")].map(x=>x.dataset.talkrole);try{await api(`/api/servers/${state.activeServer}/channels/${cid}`,{method:"PATCH",body:JSON.stringify({name:channelSetName.value,view_roles,talk_roles})});modalClose();await openServer(state.activeServer,cid);toast("Channel updated")}catch(e){toast(e.message)}}
async function deleteChannel(cid){if(!confirm("Delete this channel and its messages?"))return;try{await api(`/api/servers/${state.activeServer}/channels/${cid}`,{method:"DELETE"});await openServer(state.activeServer);toast("Channel deleted")}catch(e){toast(e.message)}}

function createCustomRole(sid){modalOpen("Create custom role",`<form class="formGrid" onsubmit="saveNewCustomRole(event,${sid})"><input id="newCustomRoleName" class="field" maxlength="30" placeholder="VIP" required><div class="modalActions"><button class="primary">Create role</button></div></form>`)}
async function saveNewCustomRole(e,sid){e.preventDefault();try{await api(`/api/servers/${sid}/roles`,{method:"POST",body:JSON.stringify({name:newCustomRoleName.value})});modalClose();state.serverRoles=(await api(`/api/servers/${sid}/roles`)).roles;showServerSettings(sid)}catch(e){toast(e.message)}}
async function deleteCustomRole(sid,rid){if(!confirm("Delete this custom role?"))return;try{await api(`/api/servers/${sid}/roles/${rid}`,{method:"DELETE"});state.serverRoles=(await api(`/api/servers/${sid}/roles`)).roles;modalClose();showServerSettings(sid)}catch(e){toast(e.message)}}
async function manageMemberCustomRoles(sid,uid,username){try{const d=await api(`/api/servers/${sid}/members/${uid}/custom-roles`);modalOpen("Roles for "+username,`<div class="formGrid">${state.serverRoles.length?state.serverRoles.map(r=>`<label class="row"><input type="checkbox" ${d.role_ids.includes(r.id)?"checked":""} onchange="toggleMemberCustomRole(${sid},${uid},${r.id},this.checked)"> ${esc(r.name)}</label>`).join(""):'<div class="muted">Create custom roles first.</div>'}</div>`)}catch(e){toast(e.message)}}
async function toggleMemberCustomRole(sid,uid,rid,enabled){try{await api(`/api/servers/${sid}/members/${uid}/custom-role`,{method:"POST",body:JSON.stringify({role_id:rid,enabled})});toast("Role assignment updated")}catch(e){toast(e.message)}}

async function showSpookHooks(cid){try{const d=await api(`/api/servers/${state.activeServer}/channels/${cid}/spookhooks`);modalOpen("SpookHooks · Beta",`<div class="muted">A SpookHook is a secret incoming link that can post messages into this channel. Never share a hook URL publicly.</div><div class="card" style="margin-top:12px"><div class="searchBox"><input id="hookName" class="field" placeholder="Hook name" value="SpookHook"><button class="primary" onclick="createSpookHook(${cid})">Create</button></div></div><div>${d.hooks.length?d.hooks.map(h=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(h.name)}</div><div class="listSub">Created ${new Date(h.created_at).toLocaleString()}</div></div><button class="danger" onclick="deleteSpookHook(${cid},${h.id})">Delete</button></div>`).join(""):'<div class="muted">No hooks for this channel.</div>'}</div>`)}catch(e){toast(e.message)}}
async function createSpookHook(cid){try{const d=await api(`/api/servers/${state.activeServer}/channels/${cid}/spookhooks`,{method:"POST",body:JSON.stringify({name:hookName.value})});modalOpen("SpookHook created",`<div class="card"><div class="muted">Copy this URL now. For security, SpookChat will not show this secret URL again.</div><input id="newHookUrl" class="field" value="${esc(d.url)}" readonly style="margin-top:10px"><button class="primary" style="margin-top:10px" onclick="navigator.clipboard.writeText(newHookUrl.value);toast('Copied')">Copy URL</button></div><div class="card"><div class="label">Example JSON POST body</div><pre style="white-space:pre-wrap">{"content":"Hello from my app","username":"My Bot"}</pre></div>`)}catch(e){toast(e.message)}}
async function deleteSpookHook(cid,hid){if(!confirm("Delete this SpookHook? Its URL will stop working."))return;try{await api(`/api/servers/${state.activeServer}/spookhooks/${hid}`,{method:"DELETE"});showSpookHooks(cid)}catch(e){toast(e.message)}}


async function setAccountInfoPassword(e){
 e.preventDefault();
 try{
   await api("/api/owner/account-info-password",{method:"POST",body:JSON.stringify({password:accountInfoAccessPassword.value})});
   accountInfoAccessPassword.value="";
   toast("Account Info Access Password saved");
 }catch(e){toast(e.message)}
}

function moderationUserMenu(ev,uid,username){
 ev.preventDefault();ev.stopPropagation();
 overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-230)}px;top:${Math.min(ev.clientY,innerHeight-240)}px" onclick="event.stopPropagation()">
 <button onclick="staffUserActions(${uid});closeContext()">🛡 Manage account</button>
 ${state.profile.global_role==="owner"?`<button onclick="unlockSensitiveUserInfo(${uid},'${username.replace(/'/g,"&#39;")}');closeContext()">🔐 View protected account info</button>`:""}
 <button onclick="viewProfile(${uid});closeContext()">👤 View public profile</button>
 </div>`;
}
function unlockSensitiveUserInfo(uid,username){
 modalOpen("Protected Account Info",`<form class="formGrid" onsubmit="unlockAndViewSensitive(event,${uid},'${username.replace(/'/g,"&#39;")}')"><div class="muted">Enter your Owner Account Info Access Password. Unlock lasts 10 minutes.</div><input id="ownerUnlockPassword" class="field" type="password" placeholder="Access password" required><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Unlock</button></div></form>`);
}
async function unlockAndViewSensitive(e,uid,username){
 e.preventDefault();
 try{
   await api("/api/owner/account-info-unlock",{method:"POST",body:JSON.stringify({password:ownerUnlockPassword.value})});
   await viewSensitiveUserInfo(uid);
 }catch(e){toast(e.message)}
}
async function viewSensitiveUserInfo(uid){
 try{
   const d=await api(`/api/owner/user-sensitive/${uid}`);
   const u=d.user;
   modalOpen("Protected Account Info",`<div class="card"><div class="listItem"><div class="listMain"><div class="listTitle">${esc(u.username)} · Spook ID #${u.id}</div><div class="listSub">${esc(u.global_role)}</div></div></div></div>
   <div class="card"><h3>Account Record</h3>
   <div class="listItem"><div class="listMain"><div class="listTitle">Login email</div><div class="listSub">${esc(u.email)}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Last known IP</div><div class="listSub">${esc(u.last_ip||"Not recorded")}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Device</div><div class="listSub">${esc(u.device_type||"Unknown")}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Account created</div><div class="listSub">${u.created_at?new Date(u.created_at).toLocaleString():"Unknown"}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Last seen</div><div class="listSub">${u.last_seen?new Date(u.last_seen).toLocaleString():"Unknown"}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Password</div><div class="listSub">Not viewable. SpookChat stores a one-way password hash.</div></div></div>
   </div>
   <div class="card"><h3>Security Action</h3><div class="muted" style="margin-bottom:10px">If an account must be recovered or secured, you can generate a temporary password. This replaces the old password.</div><button class="danger" onclick="forceTemporaryPassword(${uid})">Generate Temporary Password</button></div>`);
 }catch(e){
   if(String(e.message).includes("locked"))unlockSensitiveUserInfo(uid,"User");
   else toast(e.message)
 }
}
async function forceTemporaryPassword(uid){
 if(!confirm("Replace this user's password with a new temporary password?"))return;
 try{
   const d=await api(`/api/owner/user-force-password-reset/${uid}`,{method:"POST"});
   modalOpen("Temporary Password Created",`<div class="muted">The previous password no longer works. Give this temporary password to the account owner through a secure method.</div><input id="temporaryPasswordBox" class="field" readonly value="${esc(d.temporary_password)}" style="margin-top:12px"><button class="primary" style="margin-top:10px" onclick="navigator.clipboard.writeText(temporaryPasswordBox.value);toast('Copied')">Copy Temporary Password</button>`);
 }catch(e){toast(e.message)}
}

function showStaff(){state.view="staff";state.activeServer=null;renderApp()}
async function renderStaff(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Moderation</div><div class="topSub">Global SpookChat staff controls</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page"><div class="pageHero"><div><h1>Moderation center</h1><div class="muted">Review reports and manage users.</div></div></div>
 <div class="card"><div class="row between"><div><h3 style="margin:0">All SpookChat Users</h3><div class="muted">Search by username or Spook ID, for example <b>#14</b>.</div></div><button class="ghost" onclick="loadAllStaffUsers()">Refresh</button></div><div class="searchBox"><input id="staffSearch" class="field" placeholder="Search username or Spook ID (#123)..." onkeydown="if(event.key===\'Enter\')staffUserSearch()"><button class="primary" onclick="staffUserSearch()">Search</button></div><div id="staffUsers">Loading users...</div></div>
 <div class="card"><div class="row between"><h3 style="margin:0">Open reports</h3><button class="ghost" onclick="loadReports()">Refresh</button></div><div id="reportsList" style="margin-top:10px">Loading...</div></div>
 <div class="card"><h3>IP bans</h3><div id="ipBanList">Loading...</div></div></div>`;
 loadAllStaffUsers();loadReports();loadIPBans();
}
function drawStaffUsers(list){
 staffUsers.innerHTML=list.length?list.map(u=>`<div class="listItem" oncontextmenu="moderationUserMenu(event,${u.id},'${esc(u.username)}')"><img class="avatar" src="${avatarSrc(u.avatar)}"><div class="listMain"><div class="listTitle">${esc(u.username)} <span class="pill">${esc(u.global_role)}</span></div><div class="listSub">Spook ID #${u.id} · ${esc(u.email)}${u.banned?" · BANNED":""}${u.created_at?` · Joined ${new Date(u.created_at).toLocaleDateString()}`:""}</div></div><button class="ghost" onclick="staffUserActions(${u.id})">Manage</button></div>`).join(""):`<div class="muted">No users found.</div>`;
}
async function loadAllStaffUsers(){
 try{
   const d=await api("/api/staff/users?limit=500");
   drawStaffUsers(d.users);
 }catch(e){toast(e.message)}
}
async function staffUserSearch(){
 const q=staffSearch.value.trim();
 try{
   const d=await api("/api/staff/users?q="+encodeURIComponent(q)+"&limit=500");
   drawStaffUsers(d.users);
 }catch(e){toast(e.message)}
}
async function staffUserActions(uid){
 try{
   const d=await api("/api/staff/user/"+uid);const u=d.user;const me=state.profile.global_role;
   modalOpen("Manage "+u.username,`<div class="card"><div class="listItem"><div class="listMain"><div class="listTitle">${esc(u.username)}</div><div class="listSub">${esc(u.email)} · ${esc(u.global_role)} · Last IP ${esc(u.last_ip||"unknown")}</div></div></div></div>
   <div class="formGrid">
   ${["moderator","admin","owner"].includes(me)?`<button class="danger" onclick="staffTempBan(${u.id})">Temporary ban</button>`:""}
   ${["admin","owner"].includes(me)?`<button class="danger" onclick="staffPermanentBan(${u.id})">Permanent account ban</button><button class="danger" onclick="staffIPBan(${u.id})">Ban last IP</button>`:""}
   ${me==="owner"?`<button class="ghost" onclick="staffChangeRole(${u.id})">Change global role</button><button class="danger" onclick="staffDeleteUser(${u.id})">Delete account</button>`:""}
   </div>`);
 }catch(e){toast(e.message)}
}
async function staffTempBan(uid){const mins=prompt("Ban for how many minutes?","60");if(!mins)return;try{await api("/api/staff/ban",{method:"POST",body:JSON.stringify({user_id:uid,minutes:Number(mins),permanent:false})});toast("User temporarily banned");modalClose()}catch(e){toast(e.message)}}
async function staffPermanentBan(uid){if(!confirm("Permanently ban this account?"))return;try{await api("/api/staff/ban",{method:"POST",body:JSON.stringify({user_id:uid,permanent:true})});toast("User banned");modalClose()}catch(e){toast(e.message)}}
async function staffIPBan(uid){if(!confirm("Ban this user's last known IP?"))return;try{await api("/api/staff/ip-ban",{method:"POST",body:JSON.stringify({user_id:uid})});toast("IP banned");modalClose();loadIPBans()}catch(e){toast(e.message)}}
function staffChangeRole(uid){modalOpen("Change global role",`<form class="formGrid" onsubmit="saveGlobalRole(event,${uid})"><select id="globalRoleSelect" class="field"><option value="user">User</option><option value="moderator">Moderator</option><option value="admin">Admin</option></select><div class="modalActions"><button class="primary">Save role</button></div></form>`)}
async function saveGlobalRole(e,uid){e.preventDefault();try{await api("/api/staff/role",{method:"POST",body:JSON.stringify({user_id:uid,role:globalRoleSelect.value})});toast("Role updated");modalClose();staffUserSearch()}catch(e){toast(e.message)}}
async function staffDeleteUser(uid){if(!confirm("PERMANENTLY delete this account and its messages?"))return;try{await api("/api/staff/user/"+uid,{method:"DELETE"});toast("Account deleted");modalClose();staffUserSearch()}catch(e){toast(e.message)}}
async function loadReports(){try{const d=await api("/api/staff/reports");reportsList.innerHTML=d.reports.length?d.reports.map(r=>`<div class="listItem"><div class="listMain"><div class="listTitle">Report #${r.id}: ${esc(r.reported_username||"Deleted user")}</div><div class="listSub">Reported by ${esc(r.reporter_username||"Unknown")} · ${new Date(r.created_at).toLocaleString()}</div><div style="margin-top:7px">${esc(r.message_snapshot)}</div></div><button class="ghost" onclick="resolveReport(${r.id})">Resolve</button>${r.message_id?`<button class="danger" onclick="staffDeleteReportedMessage(${r.message_id},${r.id})">Delete message</button>`:""}</div>`).join(""):`<div class="muted">No open reports.</div>`}catch(e){reportsList.innerHTML=`<div class="muted">${esc(e.message)}</div>`}}
async function resolveReport(id){try{await api("/api/staff/reports/"+id,{method:"PATCH",body:JSON.stringify({status:"resolved"})});loadReports()}catch(e){toast(e.message)}}
async function staffDeleteReportedMessage(mid,rid){try{await api("/api/messages/"+mid,{method:"DELETE"});await resolveReport(rid);toast("Message deleted")}catch(e){toast(e.message)}}
async function loadIPBans(){try{const d=await api("/api/staff/ip-bans");ipBanList.innerHTML=d.bans.length?d.bans.map(b=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(b.ip)}</div><div class="listSub">${b.banned_until?"Until "+new Date(b.banned_until).toLocaleString():"Permanent"} · ${esc(b.reason||"")}</div></div><button class="ghost" onclick="unbanIP('${esc(b.ip)}')">Unban</button></div>`).join(""):`<div class="muted">No IP bans.</div>`}catch(e){}}
async function unbanIP(ip){try{await api("/api/staff/ip-ban",{method:"DELETE",body:JSON.stringify({ip})});loadIPBans()}catch(e){toast(e.message)}}


async function loadNotifications(showDesktop=false){
 try{
   const d=await api("/api/notifications");
   const previous=state.unreadCount||0;
   state.notifications=d.notifications||[];
   state.unreadCount=d.unread_count||0;
   updateNotificationBadges();

   if(showDesktop && state.unreadCount>previous && state.notifications.length){
     const newest=state.notifications.find(n=>!n.read);
     if(newest && document.hidden && localStorage.getItem("spookchatDesktopNotifications")==="1" && "Notification" in window && Notification.permission==="granted"){
       try{
         const n=new Notification(newest.title||"SpookChat",{body:newest.body||"New message",icon:"/static/spookchat_pfp.png",tag:"spookchat-"+newest.id});
         n.onclick=()=>{window.focus();if(newest.chat_id)openChat(newest.chat_id);n.close()}
       }catch(e){}
     }
   }
 }catch(e){}
}
function startNotificationPolling(){
 clearInterval(state.notifPoll);
 loadNotifications(false);
 state.notifPoll=setInterval(()=>loadNotifications(true),2500);
}
async function showNotifications(){
 await loadNotifications(false);
 modalOpen("Notifications",`<div class="row between" style="margin-bottom:10px"><div class="muted">${state.unreadCount} unread</div><button class="ghost" onclick="markAllNotificationsRead()">Mark all read</button></div>
 <div>${state.notifications.length?state.notifications.map(n=>`<div class="listItem notificationPanelItem ${n.read?"":"unread"}" onclick="${n.chat_id?`openNotificationChat(${n.chat_id})`:""}"><img class="avatar" src="${avatarSrc(n.actor_avatar)}"><div class="listMain"><div class="listTitle">${esc(n.title)}</div><div class="listSub">${esc(n.body)} · ${new Date(n.created_at).toLocaleString()}</div></div>${n.read?"":"<span class='notifyDot'></span>"}</div>`).join(""):'<div class="empty">No notifications yet.</div>'}</div>`);
}
async function markAllNotificationsRead(){try{await api("/api/notifications/read-all",{method:"POST"});await loadNotifications(false);modalClose();toast("Notifications cleared")}catch(e){toast(e.message)}}
async function markChatNotificationsRead(chatId){try{await api("/api/notifications/read-chat",{method:"POST",body:JSON.stringify({chat_id:chatId})});await loadNotifications(false)}catch(e){}}
async function openNotificationChat(chatId){modalClose();await openChat(chatId)}
async function enableDesktopNotifications(){
 if(!("Notification" in window)){toast("Desktop notifications are not supported by this browser.");return}
 const permission=await Notification.requestPermission();
 if(permission==="granted"){localStorage.setItem("spookchatDesktopNotifications","1");toast("Desktop notifications enabled")}
 else{localStorage.setItem("spookchatDesktopNotifications","0");toast("Notification permission was not granted")}
}
function disableDesktopNotifications(){localStorage.setItem("spookchatDesktopNotifications","0");toast("Desktop notifications disabled")}


async function showServerInvite(sid){
 try{
   const s=state.serverInfo;
   if(!s)return;
   if(s.my_role!=="owner"){
     modalOpen("Invite People",`<div class="muted">Only the server owner can create invite links right now.</div>`);
     return;
   }
   const d=await api(`/api/servers/${sid}/invites`);
   modalOpen("Invite People",`<div class="muted">Share an invite link so people can choose to join ${esc(s.name)}.</div>
   <div class="card" style="margin-top:14px"><button class="primary" onclick="createServerInvite(${sid})">Create New Invite Link</button></div>
   <div class="card"><h3>Active Invite Links</h3>${d.invites.length?d.invites.map(i=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(i.code)}</div><div class="listSub">${i.uses} use${i.uses===1?"":"s"} · ${new Date(i.created_at).toLocaleString()}</div></div><button class="ghost" onclick="navigator.clipboard.writeText('${esc(i.url)}');toast('Invite copied')">Copy</button><button class="danger" onclick="deleteServerInvite(${sid},${i.id})">Delete</button></div>`).join(""):'<div class="muted">No active invite links yet.</div>'}</div>`);
 }catch(e){toast(e.message)}
}
async function createServerInvite(sid){
 try{
   const d=await api(`/api/servers/${sid}/invites`,{method:"POST"});
   modalOpen("Invite Created",`<div class="muted">Anyone with this link can choose to join your server.</div><input id="inviteLinkBox" class="field" readonly value="${esc(d.url)}" style="margin-top:12px"><div class="modalActions"><button class="primary" onclick="navigator.clipboard.writeText(inviteLinkBox.value);toast('Invite copied')">Copy Invite Link</button><button class="ghost" onclick="showServerInvite(${sid})">Back</button></div>`);
 }catch(e){toast(e.message)}
}
async function deleteServerInvite(sid,iid){
 if(!confirm("Delete this invite link? It will stop working immediately."))return;
 try{
   await api(`/api/servers/${sid}/invites/${iid}`,{method:"DELETE"});
   toast("Invite deleted");
   showServerInvite(sid);
 }catch(e){toast(e.message)}
}
async function checkInviteFromURL(){
 const code=new URLSearchParams(location.search).get("invite");
 if(!code)return;
 try{
   const d=await api("/api/invite/"+encodeURIComponent(code));
   modalOpen("Server Invite",`<div class="row"><img class="avatar" style="width:72px;height:72px;border-radius:18px" src="${avatarSrc(d.server.icon)}"><div><h2 style="margin:0">${esc(d.server.name)}</h2><div class="muted">${d.server.member_count} member${d.server.member_count===1?"":"s"}</div></div></div><div class="card" style="margin-top:14px"><div class="muted">You've been invited to join this SpookChat server.</div></div><div class="modalActions"><button class="primary" onclick="joinInviteCode('${esc(code)}')">Join Server</button><button class="ghost" onclick="modalClose();history.replaceState({},'',location.pathname)">Cancel</button></div>`);
 }catch(e){toast(e.message)}
}
async function joinInviteCode(code){
 try{
   const d=await api(`/api/invite/${encodeURIComponent(code)}/join`,{method:"POST"});
   state.servers=(await api("/api/servers")).servers;
   modalClose();
   history.replaceState({},'',location.pathname);
   if(d.join_request){
     toast("Join request sent to the server owner");
     return;
   }
   toast(d.already_joined?"You are already in this server":"Joined server");
   await openServer(d.server_id);
 }catch(e){toast(e.message)}
}

async function logout(){await api("/api/logout",{method:"POST"});location.reload()}
boot();
</script>
</body>
</html>
"""

# ============================================================
# BASIC ROUTES
# ============================================================

@app.get("/")
def home():
    return render_template_string(HTML)

@app.get("/api/health")
def health():
    try:
        with connect() as c:
            c.execute("select 1").fetchone()
            cols = c.execute("""
                select column_name from information_schema.columns
                where table_schema='public' and table_name='users'
            """).fetchall()
            names = {r[0] for r in cols}
            required = {"id","email","username","password_hash","global_role","banned_until","last_ip","device_type","theme","show_staff_tag"}
            missing = sorted(required - names)
        return jsonify(ok=(len(missing)==0), database=True, missing_columns=missing), (200 if not missing else 500)
    except Exception as e:
        return jsonify(ok=False, database=False, error=str(e)), 500

@app.post("/api/register")
def register():
    if ip_is_banned(client_ip()):
        return jsonify(error="This IP address is banned."), 403
    d = request.get_json(silent=True) or {}
    email = str(d.get("email","")).strip().lower()
    username = str(d.get("username","")).strip()
    password = str(d.get("password",""))
    if not email or len(username) < 2 or len(username) > 32 or len(password) < 8:
        return jsonify(error="Use a valid email, 2-32 character username, and 8+ character password."), 400
    try:
        with connect() as c:
            count = c.execute("select count(*) from users").fetchone()[0]
            role = "owner" if count == 0 else "user"
            uid = c.execute("""
                insert into users(email,username,password_hash,global_role,last_ip)
                values(%s,%s,%s,%s,%s) returning id
            """, (email, username, generate_password_hash(password), role, client_ip())).fetchone()[0]
            c.commit()
        session["uid"] = uid
        return jsonify(ok=True)
    except psycopg.errors.UniqueViolation:
        return jsonify(error="That email or username is already registered."), 409
    except Exception as e:
        print("REGISTER ERROR:", repr(e))
        return jsonify(error="Database error while creating account."), 500

@app.post("/api/login")
def login():
    if ip_is_banned(client_ip()):
        return jsonify(error="This IP address is banned."), 403
    d = request.get_json(silent=True) or {}
    with connect() as c:
        r = c.execute("""
            select id,password_hash,banned_until from users where lower(email)=lower(%s)
        """, (str(d.get("email","")).strip(),)).fetchone()
    if not r or not check_password_hash(r[1], str(d.get("password",""))):
        return jsonify(error="Invalid email or password"), 401
    if r[2] and r[2] > datetime.now(timezone.utc):
        return jsonify(error="Account is banned."), 403
    session["uid"] = r[0]
    with connect() as c:
        c.execute("update users set last_ip=%s,device_type=%s,last_seen=now() where id=%s", (client_ip(), device_type(), r[0]))
        c.commit()
    return jsonify(ok=True)

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
@login_required
def me():
    u = request.me
    return jsonify(
        user={"id":u["id"],"email":u["email"]},
        profile={k:u[k] for k in ["id","username","description","avatar","pronouns","company","global_role","device_type","theme","show_staff_tag"]}
    )

@app.get("/api/profile/<int:uid>")
@login_required
def profile_get(uid):
    u = row_user(uid)
    if not u:
        return jsonify(error="User not found"), 404
    return jsonify(profile={k:u[k] for k in ["id","username","description","avatar","pronouns","company","global_role","device_type","theme","show_staff_tag"]})

@app.patch("/api/profile")
@login_required
def profile_edit():
    d = request.get_json(silent=True) or {}
    username = str(d.get("username","")).strip()
    if not 2 <= len(username) <= 32:
        return jsonify(error="Username must be 2-32 characters."), 400
    try:
        with connect() as c:
            c.execute("""
                update users set username=%s,description=%s,avatar=%s,pronouns=%s,company=%s
                where id=%s
            """, (
                username,
                str(d.get("description",""))[:300],
                str(d.get("avatar",""))[:500],
                str(d.get("pronouns",""))[:40],
                str(d.get("company",""))[:80],
                request.me["id"]
            ))
            c.commit()
    except psycopg.errors.UniqueViolation:
        return jsonify(error="That username is already taken."), 409
    u = row_user(request.me["id"])
    return jsonify(profile={k:u[k] for k in ["id","username","description","avatar","pronouns","company","global_role","device_type","theme","show_staff_tag"]})


@app.post("/api/account/preferences")
@login_required
def account_preferences():
    d = request.get_json(silent=True) or {}
    theme = str(d.get("theme", request.me["theme"]))
    if theme not in ("original","dark","light"):
        return jsonify(error="Invalid theme"),400
    show_tag = bool(d.get("show_staff_tag", request.me["show_staff_tag"]))
    if request.me["global_role"] == "user":
        show_tag = True
    with connect() as c:
        c.execute("update users set theme=%s,show_staff_tag=%s where id=%s",
                  (theme,show_tag,request.me["id"]))
        c.commit()
    return jsonify(ok=True,theme=theme,show_staff_tag=show_tag)

@app.post("/api/account/password")
@login_required
def password_change():
    d = request.get_json(silent=True) or {}
    password = str(d.get("password",""))
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    with connect() as c:
        c.execute("update users set password_hash=%s where id=%s", (generate_password_hash(password), request.me["id"]))
        c.commit()
    return jsonify(ok=True)

# ============================================================
# FRIENDS / SEARCH / DMS
# ============================================================

@app.get("/api/users/search")
@login_required
def user_search():
    q = request.args.get("q","").strip()
    if len(q) < 1:
        return jsonify(users=[])
    raw_id = q[1:] if q.startswith("#") else q
    with connect() as c:
        if raw_id.isdigit():
            rows = c.execute("""
                select u.id,u.username,u.avatar,u.company,
                       exists(
                         select 1 from friends f
                         where (f.user_a=%s and f.user_b=u.id) or (f.user_b=%s and f.user_a=u.id)
                       ) as is_friend
                from users u where u.id=%s and u.id<>%s limit 25
            """,(request.me["id"],request.me["id"],int(raw_id),request.me["id"])).fetchall()
        else:
            like = "%" + q[:50] + "%"
            rows = c.execute("""
                select u.id,u.username,u.avatar,u.company,
                       exists(
                         select 1 from friends f
                         where (f.user_a=%s and f.user_b=u.id) or (f.user_b=%s and f.user_a=u.id)
                       ) as is_friend
                from users u
                where u.id<>%s and u.username ilike %s
                order by case when lower(u.username)=lower(%s) then 0 else 1 end,u.username
                limit 25
            """,(request.me["id"],request.me["id"],request.me["id"],like,q)).fetchall()
    return jsonify(users=[
        {"id":r[0],"username":r[1],"avatar":r[2],"company":r[3],"is_friend":r[4]} for r in rows
    ])

@app.get("/api/friends")
@login_required
def friends_get():
    with connect() as c:
        rows = c.execute("""
            select u.id,u.username,u.avatar,u.pronouns
            from friends f
            join users u on u.id=(case when f.user_a=%s then f.user_b else f.user_a end)
            where (f.user_a=%s or f.user_b=%s) and f.status='accepted'
            order by u.username
        """, (request.me["id"],request.me["id"],request.me["id"])).fetchall()
    return jsonify(friends=[{"id":r[0],"username":r[1],"avatar":r[2],"pronouns":r[3]} for r in rows])

@app.post("/api/friends")
@login_required
def friends_add():
    d = request.get_json(silent=True) or {}
    try:
        target = int(d.get("user_id"))
    except Exception:
        return jsonify(error="Invalid user"), 400
    if target == request.me["id"] or not row_user(target):
        return jsonify(error="Invalid user"), 400
    a,b = sorted([request.me["id"], target])
    with connect() as c:
        c.execute("insert into friends(user_a,user_b,status) values(%s,%s,'accepted') on conflict do nothing", (a,b))
        c.commit()
    return jsonify(ok=True)

@app.get("/api/chats")
@login_required
def chats_list():
    with connect() as c:
        rows = c.execute("""
            select c.id,c.kind,c.name,c.owner_id
            from chats c join chat_members cm on cm.chat_id=c.id
            where cm.user_id=%s order by c.created_at desc
        """, (request.me["id"],)).fetchall()
        out=[]
        for cid,kind,name,owner in rows:
            if kind == "group":
                display = name or "Group chat"
            else:
                other = c.execute("""
                    select u.username from chat_members cm join users u on u.id=cm.user_id
                    where cm.chat_id=%s and cm.user_id<>%s limit 1
                """, (cid,request.me["id"])).fetchone()
                display = other[0] if other else "Direct message"
            out.append({"id":cid,"kind":kind,"display_name":display})
    return jsonify(chats=out)

@app.get("/api/chats/<int:cid>")
@login_required
def chat_info(cid):
    with connect() as c:
        chat = c.execute("select id,kind,name,owner_id from chats where id=%s", (cid,)).fetchone()
        member = c.execute("select 1 from chat_members where chat_id=%s and user_id=%s", (cid,request.me["id"])).fetchone()
        if not chat or not member:
            return jsonify(error="Chat not found"), 404
        if chat[1] == "group":
            display = chat[2] or "Group chat"
        else:
            other = c.execute("""
                select u.username from chat_members cm join users u on u.id=cm.user_id
                where cm.chat_id=%s and cm.user_id<>%s limit 1
            """, (cid,request.me["id"])).fetchone()
            display = other[0] if other else "Direct message"
    return jsonify(chat={"id":chat[0],"kind":chat[1],"display_name":display})

@app.post("/api/dms")
@login_required
def dm_create():
    d = request.get_json(silent=True) or {}
    try:
        target = int(d.get("user_id"))
    except Exception:
        return jsonify(error="Invalid user"), 400
    if target == request.me["id"] or not row_user(target):
        return jsonify(error="Invalid user"), 400
    with connect() as c:
        r = c.execute("""
            select c.id from chats c
            join chat_members a on a.chat_id=c.id
            join chat_members b on b.chat_id=c.id
            where c.kind='dm' and a.user_id=%s and b.user_id=%s
            and (select count(*) from chat_members x where x.chat_id=c.id)=2
            limit 1
        """, (request.me["id"],target)).fetchone()
        if r:
            return jsonify(chat_id=r[0])
        cid = c.execute("insert into chats(kind,owner_id) values('dm',%s) returning id", (request.me["id"],)).fetchone()[0]
        c.execute("insert into chat_members(chat_id,user_id) values(%s,%s),(%s,%s)",
                  (cid,request.me["id"],cid,target))
        c.commit()
    return jsonify(chat_id=cid)

@app.post("/api/groups")
@login_required
def group_create():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name","")).strip()[:50]
    if not name:
        return jsonify(error="Group name required"), 400
    with connect() as c:
        cid = c.execute("insert into chats(kind,name,owner_id) values('group',%s,%s) returning id",
                        (name,request.me["id"])).fetchone()[0]
        c.execute("insert into chat_members(chat_id,user_id,role) values(%s,%s,'owner')",
                  (cid,request.me["id"]))
        for uname in (d.get("usernames") or [])[:50]:
            r = c.execute("select id from users where lower(username)=lower(%s)", (str(uname).strip(),)).fetchone()
            if r:
                c.execute("insert into chat_members(chat_id,user_id) values(%s,%s) on conflict do nothing", (cid,r[0]))
        c.commit()
    return jsonify(chat_id=cid)


@app.get("/api/notifications")
@login_required
def notifications_get():
    with connect() as c:
        rows=c.execute("""
            select n.id,n.type,n.title,n.body,n.chat_id,n.read_at,n.created_at,
                   actor.avatar
            from notifications n
            left join users actor on actor.id=n.actor_id
            where n.user_id=%s
            order by n.created_at desc
            limit 80
        """,(request.me["id"],)).fetchall()
        unread=c.execute("select count(*) from notifications where user_id=%s and read_at is null",
                         (request.me["id"],)).fetchone()[0]
    return jsonify(
        unread_count=unread,
        notifications=[{
            "id":r[0],"type":r[1],"title":r[2],"body":r[3],"chat_id":r[4],
            "read":bool(r[5]),"created_at":r[6].isoformat(),"actor_avatar":r[7]
        } for r in rows]
    )

@app.post("/api/notifications/read-all")
@login_required
def notifications_read_all():
    with connect() as c:
        c.execute("update notifications set read_at=coalesce(read_at,now()) where user_id=%s",
                  (request.me["id"],))
        c.commit()
    return jsonify(ok=True)

@app.post("/api/notifications/read-chat")
@login_required
def notifications_read_chat():
    d=request.get_json(silent=True) or {}
    try: cid=int(d.get("chat_id"))
    except Exception:return jsonify(error="Invalid chat"),400
    with connect() as c:
        c.execute("""
            update notifications set read_at=coalesce(read_at,now())
            where user_id=%s and chat_id=%s
        """,(request.me["id"],cid))
        c.commit()
    return jsonify(ok=True)


# ============================================================
# SERVERS
# ============================================================


@app.get("/api/servers/discover")
@login_required
def servers_discover():
    q = request.args.get("q","").strip()[:80]
    like = "%" + q + "%"
    with connect() as c:
        rows = c.execute("""
            select s.id,s.name,s.icon,owner.username,s.privacy_mode,
                   (select count(*) from server_members sm2
                    where sm2.server_id=s.id and
                    (sm2.banned_until is null or sm2.banned_until<=now())) as member_count,
                   exists(
                     select 1 from server_members mine
                     where mine.server_id=s.id and mine.user_id=%s
                     and (mine.banned_until is null or mine.banned_until<=now())
                   ) as joined,
                   exists(
                     select 1 from server_join_requests jr
                     where jr.server_id=s.id and jr.user_id=%s and jr.status='pending'
                   ) as request_pending
            from servers s
            join users owner on owner.id=s.owner_id
            where s.name ilike %s
              and s.privacy_mode in ('public','public_approval')
            order by member_count desc, lower(s.name)
            limit 200
        """, (request.me["id"],request.me["id"], like)).fetchall()
    return jsonify(servers=[{
        "id":r[0],"name":r[1],"icon":r[2],"owner_username":r[3],
        "privacy_mode":r[4],"member_count":r[5],"joined":bool(r[6]),
        "request_pending":bool(r[7])
    } for r in rows])

@app.post("/api/servers/<int:sid>/join")
@login_required
def server_join(sid):
    with connect() as c:
        server = c.execute("select id,privacy_mode from servers where id=%s", (sid,)).fetchone()
        if not server:
            return jsonify(error="Server no longer exists"), 404

        existing = c.execute("""
            select role,banned_until from server_members
            where server_id=%s and user_id=%s
        """, (sid,request.me["id"])).fetchone()

        if existing:
            if existing[1] and existing[1] > datetime.now(timezone.utc):
                return jsonify(error="You are banned from this server"), 403
            return jsonify(ok=True, already_joined=True)

        mode = server[1]

        if mode == "private":
            return jsonify(error="This server is private."), 403
        if mode == "invite_only":
            return jsonify(error="This server is invite-only. Use a valid invite link."), 403

        if mode == "public_approval":
            c.execute("""
                insert into server_join_requests(server_id,user_id,status)
                values(%s,%s,'pending')
                on conflict(server_id,user_id)
                do update set status='pending',created_at=now()
            """, (sid,request.me["id"]))
            c.commit()
            return jsonify(ok=True, join_request=True)

        c.execute("""
            insert into server_members(server_id,user_id,role)
            values(%s,%s,'member')
        """, (sid,request.me["id"]))
        c.commit()
    return jsonify(ok=True, already_joined=False)

@app.get("/api/servers")
@login_required
def servers_list():
    with connect() as c:
        rows = c.execute("""
            select s.id,s.name,s.icon,sm.role,
                   (select count(*) from server_members x where x.server_id=s.id and
                    (x.banned_until is null or x.banned_until<=now())) as member_count
            from servers s join server_members sm on sm.server_id=s.id
            where sm.user_id=%s and (sm.banned_until is null or sm.banned_until<=now())
            order by s.created_at
        """, (request.me["id"],)).fetchall()
    return jsonify(servers=[
        {"id":r[0],"name":r[1],"icon":r[2],"role":r[3],"member_count":r[4]} for r in rows
    ])

@app.post("/api/servers")
@login_required
def server_create():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name","")).strip()[:60]
    icon = str(d.get("icon",""))[:500]
    if not name:
        return jsonify(error="Server name required"), 400
    with connect() as c:
        sid = c.execute("insert into servers(owner_id,name,icon) values(%s,%s,%s) returning id",
                        (request.me["id"],name,icon)).fetchone()[0]
        c.execute("insert into server_members(server_id,user_id,role) values(%s,%s,'owner')",
                  (sid,request.me["id"]))
        c.execute("""
            insert into server_channels(server_id,name,kind,view_roles,talk_roles,position)
            values(%s,'announcements','announcement',
                   '["member","moderator","admin","owner"]'::jsonb,
                   '["moderator","admin","owner"]'::jsonb,0),
                  (%s,'chat','chat',
                   '["member","moderator","admin","owner"]'::jsonb,
                   '["member","moderator","admin","owner"]'::jsonb,1)
        """,(sid,sid))
        c.commit()
    return jsonify(id=sid)

@app.get("/api/servers/<int:sid>")
@login_required
def server_get(sid):
    sm = server_member(sid,request.me["id"])
    if not sm:
        return jsonify(error="Not a server member"), 403
    if sm["banned_until"] and sm["banned_until"] > datetime.now(timezone.utc):
        return jsonify(error="You are banned from this server"), 403
    with connect() as c:
        s = c.execute("""
            select id,name,icon,owner_id,privacy_mode,(select count(*) from server_members where server_id=%s and
            (banned_until is null or banned_until<=now())) from servers where id=%s
        """, (sid,sid)).fetchone()
    if not s:return jsonify(error="Server not found"),404
    return jsonify(server={"id":s[0],"name":s[1],"icon":s[2],"owner_id":s[3],"privacy_mode":s[4],"member_count":s[5],"my_role":sm["role"]})

@app.patch("/api/servers/<int:sid>")
@login_required
def server_edit(sid):
    sm = server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":
        return jsonify(error="Server owner only"),403
    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip()[:60];icon=str(d.get("icon",""))[:500]
    if not name:return jsonify(error="Server name required"),400
    with connect() as c:
        mode=str(d.get("privacy_mode","public"))
        if mode not in ("public","public_approval","invite_only","private"):
            return jsonify(error="Invalid privacy mode"),400
        c.execute("update servers set name=%s,icon=%s,privacy_mode=%s where id=%s",(name,icon,mode,sid));c.commit()
    return jsonify(ok=True)

@app.delete("/api/servers/<int:sid>")
@login_required
def server_delete(sid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    with connect() as c:c.execute("delete from servers where id=%s",(sid,));c.commit()
    return jsonify(ok=True)

@app.get("/api/servers/<int:sid>/members")
@login_required
def server_members_get(sid):
    sm=server_member(sid,request.me["id"])
    if not sm:return jsonify(error="Not a server member"),403
    with connect() as c:
        rows=c.execute("""
            select u.id,u.username,u.avatar,sm.role,sm.muted_until,sm.banned_until,u.device_type
            from server_members sm join users u on u.id=sm.user_id
            where sm.server_id=%s order by
            case sm.role when 'owner' then 3 when 'admin' then 2 when 'moderator' then 1 else 0 end desc,
            u.username
        """,(sid,)).fetchall()
    now=datetime.now(timezone.utc)
    return jsonify(members=[
        {"id":r[0],"username":r[1],"avatar":r[2],"role":r[3],
         "muted":bool(r[4] and r[4]>now),"banned":bool(r[5] and r[5]>now),"device_type":r[6]} for r in rows
    ])

@app.post("/api/servers/<int:sid>/members")
@login_required
def server_member_add(sid):
    return jsonify(error="Members must join servers themselves from Discover Servers."),403

@app.delete("/api/servers/<int:sid>/members/<int:uid>")
@login_required
def server_member_remove(sid,uid):
    sm=server_member(sid,request.me["id"])
    target=server_member(sid,uid)
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    if not target or target["role"]=="owner":return jsonify(error="Cannot remove the owner"),400
    with connect() as c:c.execute("delete from server_members where server_id=%s and user_id=%s",(sid,uid));c.commit()
    return jsonify(ok=True)

@app.post("/api/server/member-action")
@login_required
def server_member_action():
    d=request.get_json(silent=True) or {}
    sid=d.get("server_id");uid=d.get("user_id");action=d.get("action")
    actor=server_member(sid,request.me["id"]);target=server_member(sid,uid)
    if not actor or not target:return jsonify(error="Server member not found"),404
    if target["role"]=="owner":return jsonify(error="The server owner cannot be moderated"),403
    if server_level(actor["role"]) <= server_level(target["role"]) and actor["role"]!="owner":
        return jsonify(error="You cannot manage this member"),403
    mins=max(1,min(int(d.get("minutes") or 60),525600))
    until=datetime.now(timezone.utc)+timedelta(minutes=mins)
    with connect() as c:
        if action=="mute":
            if actor["role"] not in ("moderator","admin","owner"):return jsonify(error="No permission"),403
            c.execute("update server_members set muted_until=%s where server_id=%s and user_id=%s",(until,sid,uid))
        elif action=="unmute":
            if actor["role"] not in ("moderator","admin","owner"):return jsonify(error="No permission"),403
            c.execute("update server_members set muted_until=null where server_id=%s and user_id=%s",(sid,uid))
        elif action=="ban":
            if actor["role"] not in ("admin","owner"):return jsonify(error="Admin/Owner only"),403
            c.execute("update server_members set banned_until=%s where server_id=%s and user_id=%s",(until,sid,uid))
        elif action=="unban":
            if actor["role"] not in ("admin","owner"):return jsonify(error="Admin/Owner only"),403
            c.execute("update server_members set banned_until=null where server_id=%s and user_id=%s",(sid,uid))
        elif action=="role":
            if actor["role"]!="owner":return jsonify(error="Server owner only"),403
            role=d.get("role")
            if role not in ("member","moderator","admin"):return jsonify(error="Invalid role"),400
            c.execute("update server_members set role=%s where server_id=%s and user_id=%s",(role,sid,uid))
        else:
            return jsonify(error="Invalid action"),400
        c.commit()
    return jsonify(ok=True)



@app.get("/api/servers/<int:sid>/join-requests")
@login_required
def server_join_requests_get(sid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":
        return jsonify(error="Server owner only"),403
    with connect() as c:
        rows=c.execute("""
            select jr.id,u.id,u.username,u.avatar,jr.created_at
            from server_join_requests jr
            join users u on u.id=jr.user_id
            where jr.server_id=%s and jr.status='pending'
            order by jr.created_at asc
        """,(sid,)).fetchall()
    return jsonify(requests=[{
        "request_id":r[0],"user_id":r[1],"username":r[2],
        "avatar":r[3],"created_at":r[4].isoformat()
    } for r in rows])

@app.post("/api/servers/<int:sid>/join-requests/<int:rid>")
@login_required
def server_join_request_decide(sid,rid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":
        return jsonify(error="Server owner only"),403
    d=request.get_json(silent=True) or {}
    decision=d.get("decision")
    if decision not in ("accept","deny"):
        return jsonify(error="Invalid decision"),400

    with connect() as c:
        jr=c.execute("""
            select user_id from server_join_requests
            where id=%s and server_id=%s and status='pending'
        """,(rid,sid)).fetchone()
        if not jr:
            return jsonify(error="Join request not found"),404

        if decision=="accept":
            c.execute("""
                insert into server_members(server_id,user_id,role)
                values(%s,%s,'member')
                on conflict(server_id,user_id) do update set banned_until=null
            """,(sid,jr[0]))
            c.execute("update server_join_requests set status='accepted' where id=%s",(rid,))
        else:
            c.execute("update server_join_requests set status='denied' where id=%s",(rid,))
        c.commit()
    return jsonify(ok=True)

@app.get("/api/servers/<int:sid>/channels")
@login_required
def server_channels_get(sid):
    if not server_member(sid,request.me["id"]):
        return jsonify(error="Not a server member"),403
    with connect() as c:
        rows=c.execute("""
            select id,name,kind,view_roles,talk_roles,position
            from server_channels where server_id=%s order by position,id
        """,(sid,)).fetchall()
    channels=[]
    for r in rows:
        if channel_access(sid,r[0],request.me["id"],"view"):
            channels.append({"id":r[0],"name":r[1],"kind":r[2],"view_roles":r[3],"talk_roles":r[4],"position":r[5]})
    return jsonify(channels=channels)

@app.post("/api/servers/<int:sid>/channels")
@login_required
def server_channel_create(sid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip().lower().replace(" ","-")[:40]
    if not name:return jsonify(error="Channel name required"),400
    kind="announcement" if d.get("kind")=="announcement" else "chat"
    talk='["moderator","admin","owner"]' if kind=="announcement" else '["member","moderator","admin","owner"]'
    try:
        with connect() as c:
            pos=c.execute("select coalesce(max(position),-1)+1 from server_channels where server_id=%s",(sid,)).fetchone()[0]
            cid=c.execute("""
                insert into server_channels(server_id,name,kind,talk_roles,position)
                values(%s,%s,%s,%s::jsonb,%s) returning id
            """,(sid,name,kind,talk,pos)).fetchone()[0]
            c.commit()
        return jsonify(id=cid)
    except psycopg.errors.UniqueViolation:
        return jsonify(error="A channel with that name already exists"),409

@app.patch("/api/servers/<int:sid>/channels/<int:cid>")
@login_required
def server_channel_edit(sid,cid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    d=request.get_json(silent=True) or {}
    with connect() as c:
        old=c.execute("select name,view_roles,talk_roles from server_channels where id=%s and server_id=%s",(cid,sid)).fetchone()
        if not old:return jsonify(error="Channel not found"),404
        name=str(d.get("name",old[0])).strip().lower().replace(" ","-")[:40]
        view_roles=d.get("view_roles",old[1]);talk_roles=d.get("talk_roles",old[2])
        if not isinstance(view_roles,list) or not isinstance(talk_roles,list):
            return jsonify(error="Invalid permissions"),400
        c.execute("""
            update server_channels set name=%s,view_roles=%s,talk_roles=%s
            where id=%s and server_id=%s
        """,(name,psycopg.types.json.Jsonb(view_roles),psycopg.types.json.Jsonb(talk_roles),cid,sid))
        c.commit()
    return jsonify(ok=True)

@app.delete("/api/servers/<int:sid>/channels/<int:cid>")
@login_required
def server_channel_delete(sid,cid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    with connect() as c:
        count=c.execute("select count(*) from server_channels where server_id=%s",(sid,)).fetchone()[0]
        if count<=1:return jsonify(error="A server must keep at least one channel"),400
        c.execute("delete from server_channels where id=%s and server_id=%s",(cid,sid));c.commit()
    return jsonify(ok=True)

@app.get("/api/servers/<int:sid>/roles")
@login_required
def server_roles_get(sid):
    if not server_member(sid,request.me["id"]):return jsonify(error="Not a server member"),403
    with connect() as c:
        rows=c.execute("select id,name from server_roles where server_id=%s order by id",(sid,)).fetchall()
    return jsonify(roles=[{"id":r[0],"name":r[1]} for r in rows])

@app.post("/api/servers/<int:sid>/roles")
@login_required
def server_role_create(sid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    name=str((request.get_json(silent=True) or {}).get("name","")).strip()[:30]
    if not name:return jsonify(error="Role name required"),400
    try:
        with connect() as c:
            rid=c.execute("insert into server_roles(server_id,name) values(%s,%s) returning id",(sid,name)).fetchone()[0];c.commit()
        return jsonify(id=rid)
    except psycopg.errors.UniqueViolation:return jsonify(error="Role already exists"),409

@app.delete("/api/servers/<int:sid>/roles/<int:rid>")
@login_required
def server_role_delete(sid,rid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    with connect() as c:c.execute("delete from server_roles where id=%s and server_id=%s",(rid,sid));c.commit()
    return jsonify(ok=True)

@app.post("/api/servers/<int:sid>/members/<int:uid>/custom-role")
@login_required
def server_custom_role_assign(sid,uid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    d=request.get_json(silent=True) or {};rid=int(d.get("role_id") or 0);enabled=bool(d.get("enabled",True))
    with connect() as c:
        valid=c.execute("select 1 from server_roles where id=%s and server_id=%s",(rid,sid)).fetchone()
        if not valid:return jsonify(error="Role not found"),404
        if enabled:
            c.execute("insert into server_member_roles(server_id,user_id,role_id) values(%s,%s,%s) on conflict do nothing",(sid,uid,rid))
        else:
            c.execute("delete from server_member_roles where server_id=%s and user_id=%s and role_id=%s",(sid,uid,rid))
        c.commit()
    return jsonify(ok=True)

@app.get("/api/servers/<int:sid>/members/<int:uid>/custom-roles")
@login_required
def server_custom_roles_get(sid,uid):
    if not server_member(sid,request.me["id"]):return jsonify(error="Not a server member"),403
    with connect() as c:
        rows=c.execute("select role_id from server_member_roles where server_id=%s and user_id=%s",(sid,uid)).fetchall()
    return jsonify(role_ids=[r[0] for r in rows])

@app.get("/api/servers/<int:sid>/channels/<int:cid>/spookhooks")
@login_required
def spookhooks_get(sid,cid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    with connect() as c:
        rows=c.execute("select id,name,created_at from spookhooks where server_id=%s and channel_id=%s order by id desc",(sid,cid)).fetchall()
    return jsonify(hooks=[{"id":r[0],"name":r[1],"created_at":r[2].isoformat()} for r in rows])

@app.post("/api/servers/<int:sid>/channels/<int:cid>/spookhooks")
@login_required
def spookhook_create(sid,cid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    with connect() as c:
        channel=c.execute("select 1 from server_channels where id=%s and server_id=%s",(cid,sid)).fetchone()
        if not channel:return jsonify(error="Channel not found"),404
        name=str((request.get_json(silent=True) or {}).get("name","SpookHook")).strip()[:40] or "SpookHook"
        token=secrets.token_urlsafe(32);token_hash=hashlib.sha256(token.encode()).hexdigest()
        hid=c.execute("""
            insert into spookhooks(server_id,channel_id,created_by,name,token_hash)
            values(%s,%s,%s,%s,%s) returning id
        """,(sid,cid,request.me["id"],name,token_hash)).fetchone()[0];c.commit()
    return jsonify(id=hid,url=request.host_url.rstrip("/")+"/api/spookhook/"+token)

@app.delete("/api/servers/<int:sid>/spookhooks/<int:hid>")
@login_required
def spookhook_delete(sid,hid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    with connect() as c:c.execute("delete from spookhooks where id=%s and server_id=%s",(hid,sid));c.commit()
    return jsonify(ok=True)

@app.post("/api/spookhook/<token>")
def spookhook_receive(token):
    token_hash=hashlib.sha256(token.encode()).hexdigest()
    d=request.get_json(silent=True) or {}
    content=str(d.get("content","")).strip()
    if not content or len(content)>4000:return jsonify(error="content is required (max 4000 chars)"),400
    with connect() as c:
        h=c.execute("""
            select h.server_id,h.channel_id,h.created_by,h.name
            from spookhooks h where h.token_hash=%s
        """,(token_hash,)).fetchone()
        if not h:return jsonify(error="Invalid SpookHook"),404
        hook_name=str(d.get("username",h[3])).strip()[:40] or h[3]
        c.execute("""
            insert into messages(user_id,content,kind,channel,server_id,is_spookhook,hook_name)
            values(%s,%s,'server',%s,%s,true,%s)
        """,(h[2],content,str(h[1]),h[0],hook_name));c.commit()
    return jsonify(ok=True)



@app.get("/api/servers/<int:sid>/invites")
@login_required
def server_invites_get(sid):
    sm = server_member(sid, request.me["id"])
    if not sm or sm["role"] != "owner":
        return jsonify(error="Server owner only"), 403
    with connect() as c:
        rows = c.execute("""
            select id,code,uses,created_at
            from server_invites
            where server_id=%s
            order by created_at desc
        """, (sid,)).fetchall()
    base = request.host_url.rstrip("/")
    return jsonify(invites=[{
        "id":r[0],
        "code":r[1],
        "uses":r[2],
        "created_at":r[3].isoformat(),
        "url":f"{base}/invite/{r[1]}"
    } for r in rows])

@app.post("/api/servers/<int:sid>/invites")
@login_required
def server_invite_create(sid):
    sm = server_member(sid, request.me["id"])
    if not sm or sm["role"] != "owner":
        return jsonify(error="Server owner only"), 403
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(10):
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        try:
            with connect() as c:
                iid = c.execute("""
                    insert into server_invites(server_id,created_by,code)
                    values(%s,%s,%s) returning id
                """, (sid,request.me["id"],code)).fetchone()[0]
                c.commit()
            return jsonify(id=iid, code=code, url=request.host_url.rstrip("/")+"/invite/"+code)
        except psycopg.errors.UniqueViolation:
            continue
    return jsonify(error="Could not create invite"),500

@app.delete("/api/servers/<int:sid>/invites/<int:iid>")
@login_required
def server_invite_delete(sid,iid):
    sm = server_member(sid, request.me["id"])
    if not sm or sm["role"] != "owner":
        return jsonify(error="Server owner only"), 403
    with connect() as c:
        c.execute("delete from server_invites where id=%s and server_id=%s",(iid,sid))
        c.commit()
    return jsonify(ok=True)

@app.get("/api/invite/<code>")
def invite_info(code):
    code = str(code).strip().upper()[:32]
    with connect() as c:
        r = c.execute("""
            select i.server_id,s.name,s.icon,
                   (select count(*) from server_members sm
                    where sm.server_id=s.id
                    and (sm.banned_until is null or sm.banned_until<=now()))
            from server_invites i
            join servers s on s.id=i.server_id
            where i.code=%s
        """,(code,)).fetchone()
    if not r:
        return jsonify(error="Invite not found or expired"),404
    return jsonify(server={
        "id":r[0],"name":r[1],"icon":r[2],"member_count":r[3],"code":code
    })

@app.post("/api/invite/<code>/join")
@login_required
def invite_join(code):
    code = str(code).strip().upper()[:32]
    with connect() as c:
        invite = c.execute("""
            select i.server_id,s.privacy_mode
            from server_invites i join servers s on s.id=i.server_id
            where i.code=%s
        """,(code,)).fetchone()
        if not invite:
            return jsonify(error="Invite not found or expired"),404

        sid, mode = invite
        if mode == "private":
            return jsonify(error="This server is currently private."),403

        existing = c.execute("""
            select role,banned_until from server_members
            where server_id=%s and user_id=%s
        """,(sid,request.me["id"])).fetchone()

        if existing:
            if existing[1] and existing[1] > datetime.now(timezone.utc):
                return jsonify(error="You are banned from this server"),403
            return jsonify(ok=True,server_id=sid,already_joined=True)

        if mode == "public_approval":
            c.execute("""
                insert into server_join_requests(server_id,user_id,status)
                values(%s,%s,'pending')
                on conflict(server_id,user_id)
                do update set status='pending',created_at=now()
            """,(sid,request.me["id"]))
            c.execute("update server_invites set uses=uses+1 where code=%s",(code,))
            c.commit()
            return jsonify(ok=True,server_id=sid,join_request=True)

        c.execute("""
            insert into server_members(server_id,user_id,role)
            values(%s,%s,'member')
        """,(sid,request.me["id"]))
        c.execute("update server_invites set uses=uses+1 where code=%s",(code,))
        c.commit()
    return jsonify(ok=True,server_id=sid,already_joined=False)

@app.get("/invite/<code>")
def invite_page(code):
    code = str(code).strip().upper()[:32]
    with connect() as c:
        r = c.execute("""
            select s.name,s.icon,
                   (select count(*) from server_members sm
                    where sm.server_id=s.id
                    and (sm.banned_until is null or sm.banned_until<=now()))
            from server_invites i
            join servers s on s.id=i.server_id
            where i.code=%s
        """,(code,)).fetchone()

    if not r:
        return """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>SpookChat Invite</title></head>
        <body style="margin:0;background:#09070e;color:white;font-family:system-ui;display:grid;place-items:center;height:100vh">
        <div style="background:#120e19;border:1px solid #332641;padding:28px;border-radius:18px;text-align:center">
        <h1>Invite not found</h1><p>This invite may have been deleted.</p><a href="/" style="color:#b77cff">Open SpookChat</a></div></body></html>""",404

    name,icon,count = r
    icon_url = icon or "/static/spookchat_pfp.png"
    return f"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Join {name} · SpookChat</title><style>
    body{{margin:0;background:radial-gradient(circle at 20% 0,#2a123e,transparent 35%),#09070e;color:#f5f3ff;font-family:system-ui;display:grid;place-items:center;min-height:100vh}}
    .card{{width:min(430px,92vw);background:#120e19;border:1px solid #382b46;border-radius:22px;padding:30px;text-align:center;box-shadow:0 30px 100px #000}}
    .btn{{display:inline-block;margin-top:18px;background:linear-gradient(135deg,#9b4dff,#7c3aed);color:white;text-decoration:none;padding:12px 18px;border-radius:11px;font-weight:800}}
    .muted{{color:#9b93aa}}</style></head><body><div class="card">
    <img src="{icon_url}" style="width:86px;height:86px;border-radius:22px;object-fit:cover">
    <h1>{name}</h1><div class="muted">{count} member{"s" if count != 1 else ""}</div>
    <p>You were invited to join this SpookChat server.</p>
    <a class="btn" href="/?invite={code}">Open SpookChat</a>
    </div></body></html>"""


# ============================================================
# MESSAGES / REPORTS
# ============================================================

@app.get("/api/messages")
@login_required
def messages_get():
    kind=request.args.get("kind");channel=request.args.get("channel")
    sid=request.args.get("server_id");cid=request.args.get("chat_id")
    with connect() as c:
        if kind=="public":
            rows=c.execute("""
              select m.id,m.user_id,m.content,m.created_at,m.edited_at,u.username,u.avatar,case when u.show_staff_tag then u.global_role else 'user' end
              from messages m join users u on u.id=m.user_id
              where m.kind='public' and m.channel=%s order by m.created_at desc limit 150
            """,(channel,)).fetchall()
        elif kind=="server":
            sm=server_member(sid,request.me["id"])
            if not sm:return jsonify(error="Not a server member"),403
            if sm["banned_until"] and sm["banned_until"]>datetime.now(timezone.utc):return jsonify(error="Banned"),403
            try: channel_id=int(channel)
            except Exception:return jsonify(error="Invalid channel"),400
            if not channel_access(sid,channel_id,request.me["id"],"view"):return jsonify(error="You cannot view this channel"),403
            rows=c.execute("""
              select m.id,m.user_id,m.content,m.created_at,m.edited_at,
                     case when m.is_spookhook then m.hook_name else u.username end,
                     u.avatar,coalesce(sm.role,'member'),m.is_spookhook
              from messages m join users u on u.id=m.user_id
              left join server_members sm on sm.server_id=m.server_id and sm.user_id=m.user_id
              where m.kind='server' and m.server_id=%s and m.channel=%s order by m.created_at desc limit 150
            """,(sid,str(channel_id))).fetchall()
        else:
            ok=c.execute("select 1 from chat_members where chat_id=%s and user_id=%s",(cid,request.me["id"])).fetchone()
            if not ok:return jsonify(error="Not a chat member"),403
            rows=c.execute("""
              select m.id,m.user_id,m.content,m.created_at,m.edited_at,u.username,u.avatar,case when u.show_staff_tag then u.global_role else 'user' end
              from messages m join users u on u.id=m.user_id
              where m.kind='dm' and m.chat_id=%s order by m.created_at desc limit 150
            """,(cid,)).fetchall()
    return jsonify(messages=[
      {"id":r[0],"user_id":r[1],"content":r[2],"created_at":r[3].isoformat(),
       "edited_at":r[4].isoformat() if r[4] else None,"username":r[5],"avatar":r[6],"role":r[7],
       "is_spookhook":bool(r[8]) if len(r)>8 else False}
      for r in reversed(rows)
    ])

@app.post("/api/messages")
@login_required
def messages_post():
    d=request.get_json(silent=True) or {}
    content=str(d.get("content","")).strip();kind=d.get("kind")
    if not content or len(content)>4000 or kind not in ("public","server","dm"):
        return jsonify(error="Invalid message"),400
    channel=d.get("channel");sid=d.get("server_id");cid=d.get("chat_id")
    if kind=="public" and channel not in ("chat1","chat2"):
        return jsonify(error="Invalid public channel"),400
    if kind=="server":
        sm=server_member(sid,request.me["id"]);now=datetime.now(timezone.utc)
        if not sm:return jsonify(error="Not a server member"),403
        if sm["banned_until"] and sm["banned_until"]>now:return jsonify(error="Banned from server"),403
        if sm["muted_until"] and sm["muted_until"]>now:return jsonify(error="Restricted from talking"),403
        try: channel=int(channel)
        except Exception:return jsonify(error="Invalid channel"),400
        if not channel_access(sid,channel,request.me["id"],"view"):return jsonify(error="You cannot view this channel"),403
        if not channel_access(sid,channel,request.me["id"],"talk"):return jsonify(error="Your role cannot talk in this channel"),403
        channel=str(channel)
    if kind=="dm":
        with connect() as c:
            if not c.execute("select 1 from chat_members where chat_id=%s and user_id=%s",(cid,request.me["id"])).fetchone():
                return jsonify(error="Not a chat member"),403
    with connect() as c:
        mid=c.execute("""
          insert into messages(user_id,content,kind,channel,server_id,chat_id)
          values(%s,%s,%s,%s,%s,%s) returning id
        """,(request.me["id"],content,kind,channel,sid,cid)).fetchone()[0]

        if kind=="dm" and cid:
            chat=c.execute("select kind,name from chats where id=%s",(cid,)).fetchone()
            recipients=c.execute("""
                select user_id from chat_members
                where chat_id=%s and user_id<>%s
            """,(cid,request.me["id"])).fetchall()
            notification_type="group_message" if chat and chat[0]=="group" else "dm_message"
            title=(chat[1]+" · "+request.me["username"]) if chat and chat[0]=="group" and chat[1] else request.me["username"]
            preview=content[:180]
            for recipient in recipients:
                c.execute("""
                    insert into notifications(user_id,actor_id,type,title,body,chat_id)
                    values(%s,%s,%s,%s,%s,%s)
                """,(recipient[0],request.me["id"],notification_type,title,preview,cid))

        c.commit()
    return jsonify(id=mid)

@app.patch("/api/messages/<int:mid>")
@login_required
def message_edit(mid):
    content=str((request.get_json(silent=True) or {}).get("content","")).strip()
    if not content or len(content)>4000:return jsonify(error="Invalid message"),400
    with connect() as c:
        m=c.execute("select user_id from messages where id=%s",(mid,)).fetchone()
        if not m:return jsonify(error="Message not found"),404
        if m[0]!=request.me["id"]:return jsonify(error="You can only edit your own messages"),403
        c.execute("update messages set content=%s,edited_at=now() where id=%s",(content,mid));c.commit()
    return jsonify(ok=True)

@app.delete("/api/messages/<int:mid>")
@login_required
def message_delete(mid):
    with connect() as c:
        m=c.execute("select user_id,kind,server_id from messages where id=%s",(mid,)).fetchone()
        if not m:return jsonify(error="Message not found"),404
        allowed=m[0]==request.me["id"] or request.me["global_role"] in ("moderator","admin","owner")
        if m[1]=="server" and m[2]:
            sm=server_member(m[2],request.me["id"])
            allowed=allowed or bool(sm and sm["role"] in ("moderator","admin","owner"))
        if not allowed:return jsonify(error="No permission"),403
        c.execute("delete from messages where id=%s",(mid,));c.commit()
    return jsonify(ok=True)

@app.post("/api/reports")
@login_required
def report_create():
    mid=(request.get_json(silent=True) or {}).get("message_id")
    with connect() as c:
        m=c.execute("select content,user_id from messages where id=%s",(mid,)).fetchone()
        if not m:return jsonify(error="Message not found"),404
        c.execute("""
          insert into reports(reporter_id,message_id,message_snapshot,reported_user_id)
          values(%s,%s,%s,%s)
        """,(request.me["id"],mid,m[0],m[1]));c.commit()
    return jsonify(ok=True)

# ============================================================
# GLOBAL MODERATION
# ============================================================


@app.post("/api/owner/account-info-password")
@staff_required("owner")
def owner_set_account_info_password():
    d=request.get_json(silent=True) or {}
    password=str(d.get("password",""))
    if len(password)<8:
        return jsonify(error="Use at least 8 characters."),400
    with connect() as c:
        c.execute("update users set account_info_password_hash=%s where id=%s",
                  (generate_password_hash(password),request.me["id"]))
        c.commit()
    return jsonify(ok=True)

@app.post("/api/owner/account-info-unlock")
@staff_required("owner")
def owner_unlock_account_info():
    d=request.get_json(silent=True) or {}
    password=str(d.get("password",""))
    owner=row_user(request.me["id"])
    stored=owner["account_info_password_hash"]
    if not stored:
        return jsonify(error="Set an Account Info Access Password in Settings first."),400
    if not check_password_hash(stored,password):
        return jsonify(error="Incorrect Account Info Access Password."),403
    session["account_info_unlocked_until"]=(datetime.now(timezone.utc)+timedelta(minutes=10)).timestamp()
    return jsonify(ok=True,unlocked_for_minutes=10)

def owner_sensitive_unlocked():
    if not session.get("uid"):
        return False
    u=row_user(session.get("uid"))
    if not u or u["global_role"]!="owner":
        return False
    until=session.get("account_info_unlocked_until",0)
    return float(until or 0) > datetime.now(timezone.utc).timestamp()

@app.get("/api/owner/user-sensitive/<int:uid>")
@login_required
def owner_user_sensitive(uid):
    if request.me["global_role"]!="owner":
        return jsonify(error="Owner only"),403
    if not owner_sensitive_unlocked():
        return jsonify(error="Sensitive account info is locked."),423
    u=row_user(uid)
    if not u:
        return jsonify(error="User not found"),404
    return jsonify(user={
        "id":u["id"],
        "username":u["username"],
        "email":u["email"],
        "last_ip":u["last_ip"],
        "device_type":u["device_type"],
        "global_role":u["global_role"],
        "created_at":u["created_at"].isoformat() if u["created_at"] else None,
        "last_seen":u["last_seen"].isoformat() if u["last_seen"] else None,
        "banned_until":u["banned_until"].isoformat() if u["banned_until"] else None,
        "password_recoverable":False
    })

@app.post("/api/owner/user-force-password-reset/<int:uid>")
@staff_required("owner")
def owner_force_password_reset(uid):
    if not owner_sensitive_unlocked():
        return jsonify(error="Sensitive account info is locked."),423
    target=row_user(uid)
    if not target:
        return jsonify(error="User not found"),404
    if target["id"]==request.me["id"]:
        return jsonify(error="Use your own password settings for your account."),400
    temporary=secrets.token_urlsafe(12)
    with connect() as c:
        c.execute("update users set password_hash=%s where id=%s",
                  (generate_password_hash(temporary),uid))
        c.commit()
    return jsonify(ok=True,temporary_password=temporary)

@app.get("/api/staff/users")
@staff_required("moderator","admin","owner")
def staff_users():
    q = request.args.get("q","").strip()
    limit = min(max(int(request.args.get("limit","500")),1),500)

    with connect() as c:
        if not q:
            rows = c.execute("""
              select id,email,username,avatar,global_role,banned_until,created_at
              from users
              order by created_at desc,id desc
              limit %s
            """,(limit,)).fetchall()
        else:
            raw_id = q[1:] if q.startswith("#") else q
            if raw_id.isdigit():
                rows = c.execute("""
                  select id,email,username,avatar,global_role,banned_until,created_at
                  from users
                  where id=%s
                  limit %s
                """,(int(raw_id),limit)).fetchall()
            else:
                like = "%" + q[:80] + "%"
                rows = c.execute("""
                  select id,email,username,avatar,global_role,banned_until,created_at
                  from users
                  where username ilike %s
                  order by case when lower(username)=lower(%s) then 0 else 1 end,username
                  limit %s
                """,(like,q,limit)).fetchall()

    now = datetime.now(timezone.utc)
    return jsonify(users=[{
        "id":r[0],"email":r[1],"username":r[2],"avatar":r[3],
        "global_role":r[4],"banned":bool(r[5] and r[5]>now),
        "created_at":r[6].isoformat() if r[6] else None
    } for r in rows])

@app.get("/api/staff/user/<int:uid>")
@staff_required("moderator","admin","owner")
def staff_user(uid):
    u=row_user(uid)
    if not u:return jsonify(error="User not found"),404
    return jsonify(user={
      "id":u["id"],"email":u["email"],"username":u["username"],"global_role":u["global_role"],
      "last_ip":u["last_ip"],"banned_until":u["banned_until"].isoformat() if u["banned_until"] else None
    })

@app.post("/api/staff/ban")
@staff_required("moderator","admin","owner")
def staff_ban():
    d=request.get_json(silent=True) or {}
    target=row_user(d.get("user_id"))
    if not target:return jsonify(error="User not found"),404
    if not can_manage_global(request.me,target):return jsonify(error="You cannot manage this user"),403
    permanent=bool(d.get("permanent"))
    if request.me["global_role"]=="moderator" and permanent:
        return jsonify(error="Moderators can only temporarily ban accounts"),403
    if permanent and request.me["global_role"] not in ("admin","owner"):
        return jsonify(error="No permission"),403
    if permanent:
        until=datetime.now(timezone.utc)+timedelta(days=36500)
    else:
        mins=max(1,min(int(d.get("minutes") or 60),10080 if request.me["global_role"]=="moderator" else 525600))
        until=datetime.now(timezone.utc)+timedelta(minutes=mins)
    with connect() as c:c.execute("update users set banned_until=%s where id=%s",(until,target["id"]));c.commit()
    return jsonify(ok=True)

@app.post("/api/staff/role")
@staff_required("owner")
def staff_role():
    d=request.get_json(silent=True) or {};target=row_user(d.get("user_id"));role=d.get("role")
    if not target:return jsonify(error="User not found"),404
    if target["id"]==request.me["id"]:return jsonify(error="You cannot change your own owner role here"),400
    if role not in ("user","moderator","admin"):return jsonify(error="Invalid role"),400
    with connect() as c:c.execute("update users set global_role=%s where id=%s",(role,target["id"]));c.commit()
    return jsonify(ok=True)

@app.delete("/api/staff/user/<int:uid>")
@staff_required("owner")
def staff_user_delete(uid):
    target=row_user(uid)
    if not target:return jsonify(error="User not found"),404
    if target["id"]==request.me["id"] or target["global_role"]=="owner":
        return jsonify(error="Cannot delete the owner account"),403
    with connect() as c:c.execute("delete from users where id=%s",(uid,));c.commit()
    return jsonify(ok=True)

@app.post("/api/staff/ip-ban")
@staff_required("admin","owner")
def staff_ip_ban():
    d=request.get_json(silent=True) or {};target=row_user(d.get("user_id"))
    if not target:return jsonify(error="User not found"),404
    if not can_manage_global(request.me,target):return jsonify(error="You cannot manage this user"),403
    ip=target["last_ip"]
    if not ip:return jsonify(error="No recorded IP for this user"),400
    with connect() as c:
        c.execute("""
          insert into ip_bans(ip,banned_until,reason) values(%s,null,%s)
          on conflict(ip) do update set banned_until=null,reason=excluded.reason
        """,(ip,"Banned by "+request.me["username"]));c.commit()
    return jsonify(ok=True)

@app.delete("/api/staff/ip-ban")
@staff_required("admin","owner")
def staff_ip_unban():
    ip=str((request.get_json(silent=True) or {}).get("ip",""))[:64]
    with connect() as c:c.execute("delete from ip_bans where ip=%s",(ip,));c.commit()
    return jsonify(ok=True)

@app.get("/api/staff/ip-bans")
@staff_required("admin","owner")
def staff_ip_bans():
    with connect() as c:rows=c.execute("select ip,banned_until,reason from ip_bans order by created_at desc").fetchall()
    return jsonify(bans=[{"ip":r[0],"banned_until":r[1].isoformat() if r[1] else None,"reason":r[2]} for r in rows])

@app.get("/api/staff/reports")
@staff_required("moderator","admin","owner")
def staff_reports():
    with connect() as c:
        rows=c.execute("""
          select r.id,r.message_id,r.message_snapshot,r.created_at,
                 reporter.username,reported.username
          from reports r
          left join users reporter on reporter.id=r.reporter_id
          left join users reported on reported.id=r.reported_user_id
          where r.status='open' order by r.created_at desc limit 100
        """).fetchall()
    return jsonify(reports=[
      {"id":r[0],"message_id":r[1],"message_snapshot":r[2],"created_at":r[3].isoformat(),
       "reporter_username":r[4],"reported_username":r[5]} for r in rows
    ])

@app.patch("/api/staff/reports/<int:rid>")
@staff_required("moderator","admin","owner")
def staff_report_update(rid):
    status=str((request.get_json(silent=True) or {}).get("status","resolved"))
    if status not in ("open","resolved","dismissed"):return jsonify(error="Invalid status"),400
    with connect() as c:c.execute("update reports set status=%s where id=%s",(status,rid));c.commit()
    return jsonify(ok=True)

# Vercel imports `app`.
