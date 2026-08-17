import os
import base64
import secrets
import hashlib
import html as html_lib
import re as re_lib
import time
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
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
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
 session_version integer not null default 1,
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





create table if not exists site_settings(
 id integer primary key default 1,
 maintenance_mode boolean not null default false,
 maintenance_message text not null default 'VYNTRA is temporarily under maintenance.',
 registrations_enabled boolean not null default true,
 site_name text not null default 'VYNTRA',
 announcement text not null default '',
 public_channels_locked boolean not null default false,
 public_embeds_enabled boolean not null default true,
 updated_at timestamptz not null default now()
);

insert into site_settings(id) values(1) on conflict(id) do nothing;

create table if not exists site_roles(
 id bigserial primary key,
 name text not null unique,
 permissions jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);

create table if not exists user_site_roles(
 user_id bigint not null references users(id) on delete cascade,
 role_id bigint not null references site_roles(id) on delete cascade,
 primary key(user_id,role_id)
);

create table if not exists owner_audit_log(
 id bigserial primary key,
 actor_id bigint references users(id) on delete set null,
 action text not null,
 target_type text not null default '',
 target_id text not null default '',
 details text not null default '',
 created_at timestamptz not null default now()
);

create index if not exists owner_audit_log_created_idx
on owner_audit_log(created_at desc);


create table if not exists server_bans(
 server_id bigint not null references servers(id) on delete cascade,
 user_id bigint not null references users(id) on delete cascade,
 banned_by bigint references users(id) on delete set null,
 banned_until timestamptz,
 created_at timestamptz not null default now(),
 primary key(server_id,user_id)
);

create index if not exists server_bans_server_idx
on server_bans(server_id,banned_until);

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
 permissions jsonb not null default '{}'::jsonb,
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


create table if not exists channel_role_overrides(
 channel_id bigint not null references server_channels(id) on delete cascade,
 role_key text not null,
 allow_permissions jsonb not null default '[]'::jsonb,
 deny_permissions jsonb not null default '[]'::jsonb,
 primary key(channel_id,role_key)
);

create table if not exists spookhooks(
 id bigserial primary key,
 server_id bigint not null references servers(id) on delete cascade,
 channel_id bigint not null references server_channels(id) on delete cascade,
 created_by bigint not null references users(id) on delete cascade,
 name text not null default 'VyntraHook',
 token_hash text not null unique,
 created_at timestamptz not null default now()
);


create table if not exists vyntra_bots(
 id bigserial primary key,
 owner_id bigint not null references users(id) on delete cascade,
 public_id text not null unique,
 name text not null,
 description text not null default '',
 avatar text not null default '',
 token_hash text not null unique,
 requested_permissions jsonb not null default '[]'::jsonb,
 created_at timestamptz not null default now()
);

create table if not exists bot_server_installs(
 bot_id bigint not null references vyntra_bots(id) on delete cascade,
 server_id bigint not null references servers(id) on delete cascade,
 installed_by bigint not null references users(id) on delete cascade,
 permissions jsonb not null default '[]'::jsonb,
 installed_at timestamptz not null default now(),
 primary key(bot_id,server_id)
);

create index if not exists bot_server_installs_server_idx
on bot_server_installs(server_id);

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
 reply_to_id bigint references messages(id) on delete set null,
 bot_id bigint references vyntra_bots(id) on delete set null,
 image_data text not null default '',
 created_at timestamptz not null default now()
);





create table if not exists call_participants(
 scope_key text not null,
 user_id bigint not null references users(id) on delete cascade,
 joined_at timestamptz not null default now(),
 last_seen timestamptz not null default now(),
 primary key(scope_key,user_id)
);
create index if not exists call_participants_scope_idx on call_participants(scope_key,last_seen);

create table if not exists call_signals(
 id bigserial primary key,
 scope_key text not null,
 from_user_id bigint not null references users(id) on delete cascade,
 to_user_id bigint not null references users(id) on delete cascade,
 signal_type text not null,
 payload jsonb not null,
 created_at timestamptz not null default now()
);
create index if not exists call_signals_target_idx on call_signals(scope_key,to_user_id,id);

create table if not exists message_read_state(
 user_id bigint not null references users(id) on delete cascade,
 scope_key text not null,
 last_message_id bigint not null default 0,
 updated_at timestamptz not null default now(),
 primary key(user_id,scope_key)
);

create index if not exists message_read_state_user_idx
on message_read_state(user_id,updated_at);

create table if not exists typing_status(
 user_id bigint not null references users(id) on delete cascade,
 scope_key text not null,
 expires_at timestamptz not null,
 primary key(user_id,scope_key)
);

create index if not exists typing_status_scope_idx
on typing_status(scope_key,expires_at);

create table if not exists message_reactions(
 message_id bigint not null references messages(id) on delete cascade,
 user_id bigint not null references users(id) on delete cascade,
 emoji text not null,
 created_at timestamptz not null default now(),
 primary key(message_id,user_id,emoji)
);

create index if not exists message_reactions_message_idx
on message_reactions(message_id);

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
create index if not exists messages_reply_idx on messages(reply_to_id);
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

            # Repair/upgrade databases created by older VYNTRA versions.
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
            c.execute("alter table users add column if not exists session_version integer not null default 1")

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

            c.execute("""
                create table if not exists vyntra_bots(
                 id bigserial primary key,
                 owner_id bigint not null references users(id) on delete cascade,
                 public_id text not null unique,
                 name text not null,
                 description text not null default '',
                 avatar text not null default '',
                 token_hash text not null unique,
                 requested_permissions jsonb not null default '[]'::jsonb,
                 created_at timestamptz not null default now()
                )
            """)
            c.execute("""
                create table if not exists bot_server_installs(
                 bot_id bigint not null references vyntra_bots(id) on delete cascade,
                 server_id bigint not null references servers(id) on delete cascade,
                 installed_by bigint not null references users(id) on delete cascade,
                 permissions jsonb not null default '[]'::jsonb,
                 installed_at timestamptz not null default now(),
                 primary key(bot_id,server_id)
                )
            """)
            c.execute("create index if not exists bot_server_installs_server_idx on bot_server_installs(server_id)")
            c.execute("alter table messages add column if not exists bot_id bigint references vyntra_bots(id) on delete set null")

            c.execute("alter table messages add column if not exists reply_to_id bigint references messages(id) on delete set null")
            c.execute("alter table messages add column if not exists image_data text not null default '';")
            c.execute("create index if not exists messages_reply_idx on messages(reply_to_id)")

            c.execute("alter table server_roles add column if not exists permissions jsonb not null default '{}'::jsonb")
            c.execute("""
                create table if not exists channel_role_overrides(
                 channel_id bigint not null references server_channels(id) on delete cascade,
                 role_key text not null,
                 allow_permissions jsonb not null default '[]'::jsonb,
                 deny_permissions jsonb not null default '[]'::jsonb,
                 primary key(channel_id,role_key)
                )
            """)


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



            c.execute("""
                create table if not exists message_reactions(
                 message_id bigint not null references messages(id) on delete cascade,
                 user_id bigint not null references users(id) on delete cascade,
                 emoji text not null,
                 created_at timestamptz not null default now(),
                 primary key(message_id,user_id,emoji)
                )
            """)
            c.execute("create index if not exists message_reactions_message_idx on message_reactions(message_id)")

            c.execute("""
                create table if not exists typing_status(
                 user_id bigint not null references users(id) on delete cascade,
                 scope_key text not null,
                 expires_at timestamptz not null,
                 primary key(user_id,scope_key)
                )
            """)
            c.execute("create index if not exists typing_status_scope_idx on typing_status(scope_key,expires_at)")


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

            c.execute("""
                create table if not exists site_settings(
                 id integer primary key default 1,
                 maintenance_mode boolean not null default false,
                 maintenance_message text not null default 'VYNTRA is temporarily under maintenance.',
                 registrations_enabled boolean not null default true,
                 site_name text not null default 'VYNTRA',
                 announcement text not null default '',
                 updated_at timestamptz not null default now()
                )
            """)

            c.execute("""
                create table if not exists server_bans(
                 server_id bigint not null references servers(id) on delete cascade,
                 user_id bigint not null references users(id) on delete cascade,
                 banned_by bigint references users(id) on delete set null,
                 banned_until timestamptz,
                 created_at timestamptz not null default now(),
                 primary key(server_id,user_id)
                )
            """)
            c.execute("create index if not exists server_bans_server_idx on server_bans(server_id,banned_until)")


            c.execute("""
                create table if not exists message_read_state(
                 user_id bigint not null references users(id) on delete cascade,
                 scope_key text not null,
                 last_message_id bigint not null default 0,
                 updated_at timestamptz not null default now(),
                 primary key(user_id,scope_key)
                )
            """)
            c.execute("create index if not exists message_read_state_user_idx on message_read_state(user_id,updated_at)")


            c.execute("""
                create table if not exists call_participants(
                 scope_key text not null,
                 user_id bigint not null references users(id) on delete cascade,
                 joined_at timestamptz not null default now(),
                 last_seen timestamptz not null default now(),
                 primary key(scope_key,user_id)
                )
            """)
            c.execute("create index if not exists call_participants_scope_idx on call_participants(scope_key,last_seen)")
            c.execute("""
                create table if not exists call_signals(
                 id bigserial primary key,
                 scope_key text not null,
                 from_user_id bigint not null references users(id) on delete cascade,
                 to_user_id bigint not null references users(id) on delete cascade,
                 signal_type text not null,
                 payload jsonb not null,
                 created_at timestamptz not null default now()
                )
            """)
            c.execute("create index if not exists call_signals_target_idx on call_signals(scope_key,to_user_id,id)")

            c.execute("insert into site_settings(id) values(1) on conflict(id) do nothing")

            c.execute("alter table site_settings add column if not exists public_channels_locked boolean not null default false")
            c.execute("alter table site_settings add column if not exists public_embeds_enabled boolean not null default true")

            c.execute("update site_settings set site_name='VYNTRA' where site_name='SpookChat'")
            c.execute("update site_settings set maintenance_message='VYNTRA is temporarily under maintenance.' where maintenance_message='SpookChat is temporarily under maintenance.'")
            c.execute("""
                create table if not exists site_roles(
                 id bigserial primary key,
                 name text not null unique,
                 permissions jsonb not null default '{}'::jsonb,
                 created_at timestamptz not null default now()
                )
            """)
            c.execute("""
                create table if not exists user_site_roles(
                 user_id bigint not null references users(id) on delete cascade,
                 role_id bigint not null references site_roles(id) on delete cascade,
                 primary key(user_id,role_id)
                )
            """)
            c.execute("""
                create table if not exists owner_audit_log(
                 id bigserial primary key,
                 actor_id bigint references users(id) on delete set null,
                 action text not null,
                 target_type text not null default '',
                 target_id text not null default '',
                 details text not null default '',
                 created_at timestamptz not null default now()
                )
            """)
            c.execute("create index if not exists owner_audit_log_created_idx on owner_audit_log(created_at desc)")




            c.commit()
            print("VYNTRA database migration complete.")
    except Exception as e:
        print("DATABASE INITIALIZATION ERROR:", repr(e))

init_db()


def device_type():
    ua = (request.headers.get("user-agent") or "").lower()
    mobile_words = ("android","iphone","ipad","ipod","mobile","windows phone")
    return "Mobile" if any(x in ua for x in mobile_words) else "PC"


URL_RE = re_lib.compile(r'https?://[^\s<>"\']+', re_lib.I)

def extract_first_url(text):
    m = URL_RE.search(text or "")
    return m.group(0)[:500] if m else ""

def message_embed_allowed(kind, sid, uid):
    if kind != "server":
        return True
    return has_server_permission(sid, uid, "embed_links")



ONLINE_SECONDS = 75

def presence_payload(last_seen):
    if not last_seen:
        return {"online":False,"last_seen":None}

    now=datetime.now(timezone.utc)
    return {
        "online":(now-last_seen).total_seconds() <= ONLINE_SECONDS,
        "last_seen":last_seen.isoformat()
    }



def call_scope_key(kind,channel=None,server_id=None,chat_id=None):
    if kind=="public":
        return f"public:{str(channel)}"
    if kind=="server":
        return f"server:{int(server_id)}:{int(channel)}"
    if kind=="dm":
        return f"dm:{int(chat_id)}"
    return ""

def verify_call_access(kind,uid,channel=None,server_id=None,chat_id=None):
    if kind=="public":
        return True
    if kind=="server":
        try:
            sid=int(server_id); cid=int(channel)
        except Exception:
            return False
        sm,perms=channel_effective_permissions(sid,cid,uid)
        return bool(sm and "view_channels" in perms)
    if kind=="dm":
        try:
            cid=int(chat_id)
        except Exception:
            return False
        with connect() as c:
            return bool(c.execute(
                "select 1 from chat_members where chat_id=%s and user_id=%s",
                (cid,uid)
            ).fetchone())
    return False

def message_scope_key(kind,channel=None,server_id=None,chat_id=None):
    if kind=="public":
        return f"public:{str(channel)}"
    if kind=="server":
        return f"server:{int(server_id)}:{str(channel)}"
    if kind=="dm":
        return f"dm:{int(chat_id)}"
    return ""

def typing_scope_key(kind,channel=None,server_id=None,chat_id=None):
    if kind=="public":
        return f"public:{str(channel)[:80]}"
    if kind=="server":
        return f"server:{int(server_id)}:{str(channel)[:80]}"
    if kind=="dm":
        return f"dm:{int(chat_id)}"
    return ""




# Vyntra Bot security boundary:
# Bot tokens authenticate ONLY /api/bot/v1/* routes.
# They do not authenticate browser/user APIs, owner controls, staff APIs,
# account endpoints, database access, server deletion, or ownership transfer.

BOT_PERMISSION_KEYS = [
    "administrator",
    "view_channels",
    "read_messages",
    "send_messages",
    "embed_links",
    "add_reactions",
    "manage_messages",
    "manage_channels",
    "manage_roles",
    "manage_members",
    "mute_members",
    "ban_members",
    "invite_members",
    "manage_server"
]

BOT_ADMIN_PERMISSIONS = {
    "view_channels",
    "read_messages",
    "send_messages",
    "embed_links",
    "add_reactions",
    "manage_messages",
    "manage_channels",
    "manage_roles",
    "manage_members",
    "mute_members",
    "ban_members",
    "invite_members",
    "manage_server"
}

def normalize_bot_permissions(value):
    if not isinstance(value,(list,tuple,set)):
        return set()

    perms={str(x) for x in value if str(x) in BOT_PERMISSION_KEYS}

    if "administrator" in perms:
        perms |= set(BOT_ADMIN_PERMISSIONS)

    return perms

def can_install_bot_to_server(sid,uid):
    sm=server_member(sid,uid)
    if not sm:
        return False
    if sm["role"] in ("admin","owner"):
        return True

    # A custom Administrator role counts as server admin permission.
    with connect() as c:
        rows=c.execute("""
            select sr.permissions
            from server_member_roles smr
            join server_roles sr on sr.id=smr.role_id
            where smr.server_id=%s and smr.user_id=%s
        """,(sid,uid)).fetchall()

    for row in rows:
        if "administrator" in normalize_permissions(row[0]):
            return True
    return False

def create_bot_token():
    return "vyntra_bot_" + secrets.token_urlsafe(36)

def bot_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def bot_auth_required(fn):
    @wraps(fn)
    def wrap(*args,**kwargs):
        header=request.headers.get("Authorization","").strip()
        token=""
        if header.lower().startswith("bot "):
            token=header[4:].strip()
        elif header.lower().startswith("bearer "):
            token=header[7:].strip()

        if not token or not token.startswith("vyntra_bot_"):
            return jsonify(error="Missing or invalid bot token"),401

        with connect() as c:
            row=c.execute("""
                select id,owner_id,public_id,name,description,avatar,requested_permissions
                from vyntra_bots
                where token_hash=%s
            """,(bot_token_hash(token),)).fetchone()

        if not row:
            return jsonify(error="Invalid bot token"),401

        request.bot={
            "id":row[0],
            "owner_id":row[1],
            "public_id":row[2],
            "name":row[3],
            "description":row[4],
            "avatar":row[5],
            "requested_permissions":list(row[6] or [])
        }
        return fn(*args,**kwargs)
    return wrap

def bot_install_permissions(bot_id,sid):
    with connect() as c:
        row=c.execute("""
            select permissions
            from bot_server_installs
            where bot_id=%s and server_id=%s
        """,(bot_id,sid)).fetchone()

    if not row:
        return set()

    raw=set(row[0] or [])
    perms=normalize_bot_permissions(raw)

    # Compatibility for existing installs that only stored Administrator.
    if "administrator" in raw:
        perms |= set(BOT_ADMIN_PERMISSIONS)

    return perms



ALLOWED_IMAGE_PREFIXES = (
    "data:image/jpeg;base64,",
    "data:image/png;base64,",
    "data:image/webp;base64,",
    "data:image/gif;base64,"
)

def validate_message_image(value):
    value=str(value or "").strip()

    if not value:
        return ""

    prefix=next(
        (p for p in ALLOWED_IMAGE_PREFIXES if value.startswith(p)),
        None
    )

    if not prefix:
        raise ValueError("Only JPEG, PNG, WEBP, and GIF images are supported.")

    encoded=value[len(prefix):]

    # Client-side images are compressed first, but enforce a hard
    # backend limit too so a message cannot be used to flood the DB.
    if len(encoded) > 2_400_000:
        raise ValueError("Image is too large.")

    try:
        raw=base64.b64decode(encoded,validate=True)
    except Exception:
        raise ValueError("Invalid image data.")

    if len(raw) > 1_800_000:
        raise ValueError("Image is too large.")

    return value


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
                   global_role,banned_until,last_ip,last_seen,device_type,theme,show_staff_tag,account_info_password_hash,session_version,created_at
            from users where id=%s
        """, (uid,)).fetchone()
    if not r:
        return None
    keys = ["id","email","username","description","avatar","pronouns","company",
            "global_role","banned_until","last_ip","last_seen","device_type","theme","show_staff_tag","account_info_password_hash","session_version","created_at"]
    return dict(zip(keys, r))

def current_user():
    uid = session.get("uid")
    return row_user(uid) if uid else None

_IP_BAN_CACHE = {}

def clear_ip_ban_cache():
    _IP_BAN_CACHE.clear()

def ip_is_banned(ip):
    if not ip:
        return False

    now=time.monotonic()
    cached=_IP_BAN_CACHE.get(ip)
    if cached and now-cached[0]<5:
        return cached[1]

    with connect() as c:
        r=c.execute("select banned_until from ip_bans where ip=%s",(ip,)).fetchone()

    banned=bool(r and (r[0] is None or r[0]>datetime.now(timezone.utc)))
    _IP_BAN_CACHE[ip]=(now,banned)

    # Keep cache tiny.
    if len(_IP_BAN_CACHE)>200:
        _IP_BAN_CACHE.clear()

    return banned


def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        if ip_is_banned(client_ip()):
            return jsonify(error="This IP address is banned from VYNTRA."), 403
        u = current_user()
        settings=get_site_settings()
        if not u:
            return jsonify(error="Not logged in"), 401
        if int(session.get("session_version",0) or 0) != int(u.get("session_version",1)):
            session.clear()
            return jsonify(error="Your session expired. Please log in again."),401
        is_app_staff = u["global_role"] in ("moderator","admin","owner")
        if settings["maintenance_mode"] and not is_app_staff and request.endpoint != "me":
            return jsonify(error=settings["maintenance_message"],maintenance=True),503
        if u["banned_until"] and u["banned_until"] > datetime.now(timezone.utc):
            return jsonify(error="Your account is temporarily banned."), 403
        try:
            now_ts=int(time.time())
            last_write=int(session.get("_presence_write",0) or 0)
            if now_ts-last_write>=60:
                with connect() as c:
                    c.execute(
                        "update users set last_ip=%s,device_type=%s,last_seen=now() where id=%s",
                        (client_ip(),device_type(),u["id"])
                    )
                    c.commit()
                session["_presence_write"]=now_ts
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


def active_server_ban(sid, uid, conn=None):
    own_conn = conn is None
    c = conn or connect()

    try:
        row = c.execute("""
            select banned_until
            from server_bans
            where server_id=%s and user_id=%s
        """, (sid, uid)).fetchone()

        if not row:
            return None

        until = row[0]
        now = datetime.now(timezone.utc)

        if until is not None and until <= now:
            c.execute(
                "delete from server_bans where server_id=%s and user_id=%s",
                (sid, uid)
            )
            if own_conn:
                c.commit()
            return None

        return until
    finally:
        if own_conn:
            c.close()


def ban_server_user(sid, uid, banned_by, until, conn):
    target = conn.execute("""
        select role
        from server_members
        where server_id=%s and user_id=%s
    """, (sid, uid)).fetchone()

    if not target:
        return False, "Member not found"

    if target[0] == "owner":
        return False, "The server owner cannot be banned"

    conn.execute("""
        insert into server_bans(server_id,user_id,banned_by,banned_until,created_at)
        values(%s,%s,%s,%s,now())
        on conflict(server_id,user_id)
        do update set
            banned_by=excluded.banned_by,
            banned_until=excluded.banned_until,
            created_at=now()
    """, (sid, uid, banned_by, until))

    conn.execute(
        "delete from server_member_roles where server_id=%s and user_id=%s",
        (sid, uid)
    )

    conn.execute("""
        update server_join_requests
        set status='denied'
        where server_id=%s and user_id=%s and status='pending'
    """, (sid, uid))

    conn.execute(
        "delete from server_members where server_id=%s and user_id=%s",
        (sid, uid)
    )

    return True, None


def unban_server_user(sid, uid, conn):
    conn.execute(
        "delete from server_bans where server_id=%s and user_id=%s",
        (sid, uid)
    )



_GLOBAL_OWNER_CACHE={}

def is_global_owner(uid):
    now=time.monotonic()
    cached=_GLOBAL_OWNER_CACHE.get(uid)

    if cached and now-cached[0] < 10:
        return cached[1]

    with connect() as c:
        row=c.execute(
            "select global_role from users where id=%s",
            (uid,)
        ).fetchone()

    result=bool(row and row[0]=="owner")
    _GLOBAL_OWNER_CACHE[uid]=(now,result)

    if len(_GLOBAL_OWNER_CACHE)>100:
        _GLOBAL_OWNER_CACHE.clear()

    return result

def server_member(sid, uid):
    # The global VYNTRA owner can manage every server without needing
    # to join it as a normal server member.
    if is_global_owner(uid):
        return {
            "role":"owner",
            "banned_until":None,
            "muted_until":None,
            "joined_at":None,
            "global_owner_override":True
        }

    with connect() as c:
        r = c.execute("""
            select role,banned_until,muted_until,joined_at
            from server_members where server_id=%s and user_id=%s
        """, (sid, uid)).fetchone()

    if not r:
        return None

    return {
        "role":r[0],
        "banned_until":r[1],
        "muted_until":r[2],
        "joined_at":r[3]
    }

def server_level(role):
    return {"member":0, "moderator":1, "admin":2, "owner":3}.get(role, -1)



SERVER_PERMISSION_KEYS = [
    "administrator",
    "view_channels",
    "send_messages",
    "invite_members",
    "manage_channels",
    "manage_roles",
    "manage_members",
    "mute_members",
    "ban_members",
    "manage_messages",
    "embed_links",
    "add_reactions",
    "manage_spookhooks",
    "manage_server"
]

ALL_SERVER_PERMISSIONS_EXCEPT_DELETE = {
    "view_channels","send_messages","invite_members","manage_channels","manage_roles",
    "manage_members","mute_members","ban_members","manage_messages","embed_links","add_reactions","manage_spookhooks","manage_server"
}

BUILTIN_SERVER_PERMISSIONS = {
    "member": {"view_channels","send_messages","add_reactions"},
    "moderator": {"view_channels","send_messages","add_reactions","manage_messages","mute_members"},
    "admin": set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE),
    "owner": set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE) | {"delete_server"}
}

def normalize_permissions(value):
    if isinstance(value, dict):
        return {k for k,v in value.items() if bool(v) and k in SERVER_PERMISSION_KEYS}
    if isinstance(value, list):
        return {str(x) for x in value if str(x) in SERVER_PERMISSION_KEYS}
    return set()

def member_role_keys(sid, uid):
    sm = server_member(sid, uid)
    if not sm:
        return set()
    keys = {sm["role"]}
    with connect() as c:
        rows = c.execute("""
            select smr.role_id
            from server_member_roles smr
            where smr.server_id=%s and smr.user_id=%s
        """,(sid,uid)).fetchall()
    keys |= {f"custom:{r[0]}" for r in rows}
    return keys

def server_permissions_for_user(sid, uid):
    sm = server_member(sid, uid)
    if not sm:
        return set()
    if sm["role"] == "owner":
        return set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE) | {"delete_server"}

    perms = set(BUILTIN_SERVER_PERMISSIONS.get(sm["role"], set()))
    with connect() as c:
        rows = c.execute("""
            select sr.permissions
            from server_member_roles smr
            join server_roles sr on sr.id=smr.role_id
            where smr.server_id=%s and smr.user_id=%s
        """,(sid,uid)).fetchall()

    for r in rows:
        rp = normalize_permissions(r[0])
        if "administrator" in rp:
            perms |= set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)
        perms |= (rp - {"administrator"})
    return perms

def has_server_permission(sid, uid, permission):
    return permission in server_permissions_for_user(sid, uid)

def channel_permission(sid, channel_id, uid, permission):
    sm = server_member(sid,uid)
    if not sm:
        return False
    if sm["role"] == "owner":
        return True

    base = has_server_permission(sid,uid,permission)
    role_keys = member_role_keys(sid,uid)

    with connect() as c:
        rows = c.execute("""
            select role_key,allow_permissions,deny_permissions
            from channel_role_overrides
            where channel_id=%s
        """,(channel_id,)).fetchall()

    allowed = False
    denied = False
    for role_key,allow,deny in rows:
        if role_key not in role_keys:
            continue
        allow_set = set(allow or [])
        deny_set = set(deny or [])
        if permission in deny_set:
            denied = True
        if permission in allow_set:
            allowed = True

    if denied:
        return False
    if allowed:
        return True
    return base


def server_custom_roles(sid, uid):
    with connect() as c:
        rows = c.execute("""
            select smr.role_id from server_member_roles smr
            where smr.server_id=%s and smr.user_id=%s
        """,(sid,uid)).fetchall()
    return {f"custom:{r[0]}" for r in rows}

def channel_effective_permissions(sid,channel_id,uid):
    """Return (server_member_dict, effective_permission_set) using one DB connection."""
    if is_global_owner(uid):
        return (
            {
                "role":"owner",
                "banned_until":None,
                "muted_until":None,
                "joined_at":None,
                "global_owner_override":True
            },
            set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)|{"delete_server"}
        )

    with connect() as c:
        sm_row=c.execute("""
            select role,banned_until,muted_until,joined_at
            from server_members
            where server_id=%s and user_id=%s
        """,(sid,uid)).fetchone()

        if not sm_row:
            return None,set()

        sm={
            "role":sm_row[0],
            "banned_until":sm_row[1],
            "muted_until":sm_row[2],
            "joined_at":sm_row[3]
        }

        if sm["role"]=="owner":
            return sm,set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)|{"delete_server"}

        role_rows=c.execute("""
            select sr.id,sr.permissions
            from server_member_roles smr
            join server_roles sr on sr.id=smr.role_id
            where smr.server_id=%s and smr.user_id=%s
        """,(sid,uid)).fetchall()

        override_rows=c.execute("""
            select role_key,allow_permissions,deny_permissions
            from channel_role_overrides
            where channel_id=%s
        """,(channel_id,)).fetchall()

    perms=set(BUILTIN_SERVER_PERMISSIONS.get(sm["role"],set()))
    role_keys={sm["role"]}

    for rid,raw in role_rows:
        role_keys.add(f"custom:{rid}")
        rp=normalize_permissions(raw)
        if "administrator" in rp:
            perms|=set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)
        perms|=(rp-{"administrator"})

    allow=set()
    deny=set()
    for role_key,allowed,denied in override_rows:
        if role_key not in role_keys:
            continue
        allow|=set(allowed or [])
        deny|=set(denied or [])

    perms-=deny
    perms|=allow
    return sm,perms

def channel_access(sid, channel_id, uid, mode):
    permission="view_channels" if mode=="view" else "send_messages"
    _,perms=channel_effective_permissions(sid,channel_id,uid)
    return permission in perms



SITE_ROLE_PERMISSION_KEYS = [
    "view_moderation",
    "manage_users",
    "manage_reports",
    "manage_ip_bans",
    "manage_global_roles",
    "manage_site_roles",
    "view_audit_log"
]

_SITE_SETTINGS_CACHE = {"at":0.0,"value":None}

def clear_site_settings_cache():
    _SITE_SETTINGS_CACHE["at"]=0.0
    _SITE_SETTINGS_CACHE["value"]=None

def get_site_settings(force=False):
    now=time.monotonic()
    cached=_SITE_SETTINGS_CACHE.get("value")
    if not force and cached is not None and now-_SITE_SETTINGS_CACHE.get("at",0)<5:
        return dict(cached)

    with connect() as c:
        r=c.execute("""
            select maintenance_mode,maintenance_message,registrations_enabled,site_name,announcement,
                   public_channels_locked,public_embeds_enabled
            from site_settings where id=1
        """).fetchone()

    if not r:
        value={
            "maintenance_mode":False,
            "maintenance_message":"VYNTRA is temporarily under maintenance.",
            "registrations_enabled":True,
            "site_name":"VYNTRA",
            "announcement":"",
            "public_channels_locked":False,
            "public_embeds_enabled":True
        }
    else:
        value={
            "maintenance_mode":bool(r[0]),
            "maintenance_message":r[1],
            "registrations_enabled":bool(r[2]),
            "site_name":r[3],
            "announcement":r[4],
            "public_channels_locked":bool(r[5]),
            "public_embeds_enabled":bool(r[6])
        }

    _SITE_SETTINGS_CACHE["at"]=now
    _SITE_SETTINGS_CACHE["value"]=dict(value)
    return value


def site_permissions_for_user(uid):
    u=row_user(uid)
    if not u:
        return set()
    if u["global_role"]=="owner":
        return set(SITE_ROLE_PERMISSION_KEYS) | {"owner_control"}

    perms=set()
    if u["global_role"]=="moderator":
        perms |= {"view_moderation","manage_reports"}
    elif u["global_role"]=="admin":
        perms |= {"view_moderation","manage_reports","manage_users","manage_ip_bans"}

    with connect() as c:
        rows=c.execute("""
            select sr.permissions
            from user_site_roles usr
            join site_roles sr on sr.id=usr.role_id
            where usr.user_id=%s
        """,(uid,)).fetchall()
    for r in rows:
        raw=r[0] or {}
        if isinstance(raw,dict):
            perms |= {k for k,v in raw.items() if v and k in SITE_ROLE_PERMISSION_KEYS}
    return perms

def has_site_permission(uid,perm):
    return perm in site_permissions_for_user(uid)

def audit_owner_action(actor_id,action,target_type="",target_id="",details=""):
    try:
        with connect() as c:
            c.execute("""
                insert into owner_audit_log(actor_id,action,target_type,target_id,details)
                values(%s,%s,%s,%s,%s)
            """,(actor_id,action,str(target_type)[:80],str(target_id)[:120],str(details)[:500]))
            c.commit()
    except Exception as e:
        print("AUDIT LOG ERROR:",repr(e))


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
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,viewport-fit=cover">
<title>VYNTRA</title>
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

/* ---------- VYNTRA polish ---------- */
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
   VYNTRA CLEAN UI
   Original VYNTRA visual identity
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

/* Original VYNTRA identity: flatter server navigation, custom VYNTRA navigation */
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
   VYNTRA FULL VIEWPORT / SCROLL FIX
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


/* ============================================================
   NATIVE-LIKE MOBILE UI
   ============================================================ */
@media(max-width:720px){
  .mobilebar{
    position:fixed!important;
    left:0!important;right:0!important;bottom:0!important;
    z-index:80!important;
    height:68px!important;
    padding:6px max(8px,env(safe-area-inset-right)) calc(6px + env(safe-area-inset-bottom)) max(8px,env(safe-area-inset-left))!important;
    background:rgba(12,9,17,.96)!important;
    backdrop-filter:blur(20px)!important;
    border-top:1px solid rgba(255,255,255,.08)!important;
    box-shadow:0 -12px 40px rgba(0,0,0,.35)!important;
  }
  .mobilebar button{
    min-width:52px!important;
    flex:1!important;
    display:flex!important;
    flex-direction:column!important;
    align-items:center!important;
    justify-content:center!important;
    gap:2px!important;
    border-radius:12px!important;
    padding:4px 3px!important;
    color:#91889c!important;
    transition:.16s ease!important;
  }
  .mobilebar button b{font-size:18px!important;line-height:20px!important}
  .mobilebar button span:not(.notifyBadge){font-size:10px!important;font-weight:700!important}
  .mobilebar button.active{
    color:#d8c2ff!important;
    background:rgba(155,77,255,.11)!important;
  }
  .app{
    height:calc(100dvh - 68px)!important;
    max-height:calc(100dvh - 68px)!important;
  }
  .main{border-radius:0!important}
  .topbar{
    position:sticky!important;
    top:0!important;
    z-index:20!important;
    padding:0 14px!important;
  }
  .topActions .ghost{padding:8px!important;font-size:0!important}
  .topActions .ghost::first-letter{font-size:14px}
  .page{padding:16px 14px 100px!important}
  .pageHero{gap:10px!important}
  .pageHero h1{font-size:24px!important}
  .card{border-radius:15px!important;padding:14px!important}
  .messages{padding:12px 10px 84px!important}
  .msg{padding:9px 8px!important}
  .composer{
    position:sticky!important;
    bottom:0!important;
    z-index:25!important;
    margin:0 8px 8px!important;
    border-radius:15px!important;
  }
  .modalWrap{
    align-items:flex-end!important;
    padding:0!important;
  }
  .modal{
    width:100%!important;
    max-width:none!important;
    max-height:88dvh!important;
    border-radius:22px 22px 0 0!important;
    padding:18px 16px calc(22px + env(safe-area-inset-bottom))!important;
    animation:mobileSheetIn .18s ease!important;
  }
  @keyframes mobileSheetIn{from{transform:translateY(30px);opacity:.75}to{transform:none;opacity:1}}
  .grid2{grid-template-columns:1fr!important}
  .listItem{gap:9px!important}
}


/* ============================================================
   VYNTRA MOBILE REBUILD
   ============================================================ */
.serverMobileMenu{display:none}

.serverWorkspace{
  display:flex;
  min-height:0;
  flex:1;
}
.serverChannelRail{
  width:190px;
  flex:0 0 190px;
  border-right:1px solid var(--line);
  padding:12px;
  background:#0d0a12;
  min-height:0;
  overflow-y:auto;
}
.serverConversation{
  min-width:0;
  min-height:0;
  flex:1;
  display:flex;
  flex-direction:column;
}
.serverChannelButtons{display:block}

@media(max-width:720px){
  body{
    background:#09070d!important;
  }

  .sidebar,.membersPane{display:none!important}

  .app,.app.with-members{
    height:calc(100dvh - 76px)!important;
    max-height:calc(100dvh - 76px)!important;
    display:flex!important;
    flex-direction:column!important;
    overflow:hidden!important;
  }

  .main,#mainArea{
    width:100%!important;
    height:100%!important;
    min-height:0!important;
  }

  .topbar{
    height:58px!important;
    min-height:58px!important;
    padding:0 13px!important;
    background:rgba(9,7,13,.93)!important;
    border-bottom:1px solid rgba(255,255,255,.055)!important;
    backdrop-filter:blur(18px)!important;
  }

  .topTitle{
    max-width:62vw;
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
    font-size:16px!important;
  }

  .topSub{display:none!important}
  .serverDesktopActions{display:none!important}
  .serverMobileMenu{display:grid!important;place-items:center;margin-left:auto}

  /* Server becomes channels-across-top + conversation */
  .serverWorkspace{
    flex:1!important;
    min-height:0!important;
    flex-direction:column!important;
    overflow:hidden!important;
  }

  .serverChannelRail{
    width:100%!important;
    flex:0 0 auto!important;
    height:auto!important;
    min-height:0!important;
    padding:7px 8px!important;
    border-right:0!important;
    border-bottom:1px solid rgba(255,255,255,.06)!important;
    overflow:hidden!important;
    background:#0c0911!important;
  }

  .serverChannelTitle{
    display:none!important;
  }

  .serverChannelButtons{
    display:flex!important;
    gap:7px!important;
    overflow-x:auto!important;
    overflow-y:hidden!important;
    padding:1px 2px 3px!important;
    scrollbar-width:none!important;
  }
  .serverChannelButtons::-webkit-scrollbar{display:none!important}

  .serverChannelButtons .channelBtn{
    width:auto!important;
    flex:0 0 auto!important;
    margin:0!important;
    padding:8px 11px!important;
    border-radius:999px!important;
    font-size:12px!important;
    background:#16111d!important;
    border:1px solid rgba(255,255,255,.055)!important;
    transform:none!important;
  }
  .serverChannelButtons .channelBtn.active{
    background:rgba(155,77,255,.18)!important;
    border-color:rgba(155,77,255,.38)!important;
    box-shadow:none!important;
  }

  .serverConversation{
    flex:1!important;
    min-height:0!important;
    width:100%!important;
  }

  .messages{
    padding:12px 9px 16px!important;
  }

  .msg{
    padding:8px 7px!important;
    gap:9px!important;
    border-radius:12px!important;
  }

  .msg .avatar{
    width:35px!important;
    height:35px!important;
  }

  .msgBody{
    max-width:calc(100vw - 62px)!important;
  }

  .text{
    font-size:14px!important;
    line-height:1.42!important;
  }

  .composer{
    flex:0 0 auto!important;
    position:relative!important;
    bottom:auto!important;
    margin:5px 8px 8px!important;
    min-height:54px!important;
    padding:7px!important;
    border-radius:17px!important;
    background:#14101b!important;
  }

  .composer input{
    min-width:0!important;
    font-size:16px!important;
    padding:10px!important;
  }

  .composer .primary{
    width:42px!important;
    min-width:42px!important;
    height:42px!important;
    padding:0!important;
    font-size:0!important;
    border-radius:13px!important;
  }
  .composer .primary::after{
    content:"➤";
    font-size:16px;
  }

  /* Bottom navigation */
  .mobilebar{
    position:fixed!important;
    left:8px!important;
    right:8px!important;
    bottom:calc(6px + env(safe-area-inset-bottom))!important;
    width:auto!important;
    height:66px!important;
    z-index:90!important;
    display:grid!important;
    grid-template-columns:repeat(5,1fr)!important;
    align-items:center!important;
    padding:5px!important;
    border-radius:21px!important;
    background:rgba(17,13,24,.96)!important;
    border:1px solid rgba(255,255,255,.08)!important;
    box-shadow:0 16px 50px rgba(0,0,0,.5)!important;
    backdrop-filter:blur(22px)!important;
  }

  .mobilebar button{
    height:55px!important;
    min-width:0!important;
    position:relative!important;
    display:flex!important;
    flex-direction:column!important;
    align-items:center!important;
    justify-content:center!important;
    gap:2px!important;
    background:transparent!important;
    border-radius:15px!important;
    color:#7f7689!important;
    padding:3px!important;
  }

  .mobilebar button > span:not(.notifyBadge){
    font-size:9px!important;
    font-weight:800!important;
  }

  .mobilebar .mobileNavIcon{
    font-size:20px!important;
    line-height:23px!important;
    color:#9c91a9!important;
  }

  .mobilebar button.active{
    color:#dbc8ff!important;
    background:rgba(155,77,255,.10)!important;
  }

  .mobilebar button.active .mobileNavIcon{
    color:#c28aff!important;
  }

  .mobileNavCenter{
    overflow:visible!important;
  }

  .mobileNavOrb{
    display:grid!important;
    place-items:center!important;
    width:36px!important;
    height:36px!important;
    margin-top:-19px!important;
    border-radius:14px!important;
    color:white!important;
    font-size:18px!important;
    background:linear-gradient(135deg,#a855f7,#6d28d9)!important;
    border:3px solid #110d18!important;
    box-shadow:0 7px 22px rgba(155,77,255,.42)!important;
  }

  .mobilebar .notifyBadge{
    position:absolute!important;
    top:2px!important;
    right:8px!important;
    min-width:17px!important;
    height:17px!important;
    padding:0 4px!important;
    font-size:9px!important;
  }

  /* Main pages */
  .page{
    padding:14px 12px 88px!important;
  }

  .pageHero{
    margin-bottom:13px!important;
  }

  .pageHero h1{
    font-size:23px!important;
  }

  .card{
    padding:13px!important;
    border-radius:16px!important;
    margin-bottom:10px!important;
  }

  .grid2{
    grid-template-columns:1fr!important;
    gap:9px!important;
  }

  .listItem{
    padding:10px 0!important;
    flex-wrap:wrap;
  }

  .listItem .primary,.listItem .ghost,.listItem .danger,.listItem .good{
    padding:8px 10px!important;
  }

  .searchBox{
    gap:6px!important;
  }

  /* Mobile sheets */
  .modalWrap{
    align-items:flex-end!important;
    padding:0!important;
  }

  .modal{
    width:100%!important;
    max-width:none!important;
    max-height:86dvh!important;
    border-radius:24px 24px 0 0!important;
    padding:18px 15px calc(20px + env(safe-area-inset-bottom))!important;
    border-left:0!important;
    border-right:0!important;
    border-bottom:0!important;
  }

  .context{
    max-width:calc(100vw - 16px)!important;
  }
}


/* ============================================================
   VYNTRA UI RELIABILITY + FORM CONTROLS
   ============================================================ */
.modalHeader{display:flex;align-items:center;gap:12px;margin-bottom:14px;position:sticky;top:-20px;z-index:4;background:#110d18;padding:4px 0 10px;border-bottom:1px solid rgba(255,255,255,.055)}
.modalHeader h2{margin:0!important;flex:1;min-width:0}
.modalCloseBtn{width:34px;height:34px;border-radius:11px;background:#1c1524;color:#bdb4c7;font-size:23px;line-height:1;display:grid;place-items:center;border:1px solid rgba(255,255,255,.06)}
.modalCloseBtn:hover{background:#2a1c37;color:white;transform:rotate(4deg)}

input[type="checkbox"]{
  appearance:none;-webkit-appearance:none;width:20px;height:20px;min-width:20px;border-radius:7px;
  border:1px solid #4b3a5d;background:#0d0a12;display:inline-grid;place-items:center;cursor:pointer;
  transition:.16s ease;box-shadow:inset 0 0 0 1px rgba(255,255,255,.015)
}
input[type="checkbox"]::after{content:"";width:9px;height:5px;border-left:2px solid white;border-bottom:2px solid white;transform:rotate(-45deg) scale(0);margin-top:-2px;transition:.14s ease}
input[type="checkbox"]:hover{border-color:#8b5cf6;box-shadow:0 0 0 3px rgba(139,92,246,.08)}
input[type="checkbox"]:checked{border-color:#9b4dff;background:linear-gradient(135deg,#a855f7,#6d28d9);box-shadow:0 0 18px rgba(155,77,255,.25)}
input[type="checkbox"]:checked::after{transform:rotate(-45deg) scale(1)}
input[type="checkbox"]:focus-visible{outline:2px solid #c084fc;outline-offset:2px}
body.theme-light input[type="checkbox"]{background:#f3eff7;border-color:#cfc5d8}

.maintenanceScreen{height:100vh;height:100dvh;display:grid;place-items:center;padding:22px;background:radial-gradient(circle at 50% 0,rgba(155,77,255,.16),transparent 38%),#08070b}
.maintenanceCard{width:min(520px,94vw);text-align:center;padding:36px 30px;background:linear-gradient(180deg,#13101a,#0e0b13);border:1px solid #352840;border-radius:24px;box-shadow:0 35px 110px #000}
.maintenanceLogo{width:82px;height:82px;border-radius:24px;object-fit:cover;box-shadow:0 0 38px rgba(155,77,255,.3);border:1px solid rgba(155,77,255,.4)}
.maintenanceEyebrow{margin-top:18px;color:#a987d1;font-size:11px;font-weight:900;letter-spacing:.18em}
.maintenanceCard h1{font-size:32px;margin:8px 0 8px;letter-spacing:-.04em}
.maintenanceCard p{color:#a49baa;font-size:15px;line-height:1.55;white-space:pre-wrap}
.maintenanceActions{display:flex;justify-content:center;gap:9px;margin-top:22px}
@media(max-width:720px){.maintenanceCard{padding:28px 20px}.maintenanceCard h1{font-size:27px}.modalHeader{top:-18px}}


/* ============================================================
   VYNTRA PHONE / TABLET AUTO-FIT
   Fits the UI to the device viewport without browser zoom hacks.
   ============================================================ */
html{
  width:100%;
  height:100%;
  -webkit-text-size-adjust:100%;
  text-size-adjust:100%;
  overflow:hidden;
}
body{
  width:100%;
  min-width:0;
  height:100%;
  min-height:100dvh;
  margin:0;
  overflow:hidden;
}
*,*::before,*::after{box-sizing:border-box}
img,video,canvas,svg{max-width:100%}
input,textarea,select,button{max-width:100%}

@media (max-width:1100px){
  :root{
    --mobile-side-gap: clamp(8px,2.4vw,18px);
  }

  body{
    min-width:0!important;
    width:100vw!important;
    max-width:100vw!important;
  }

  .app,.app.with-members{
    width:100%!important;
    max-width:100vw!important;
    min-width:0!important;
  }

  .main,#mainArea,.content,.page,.serverWorkspace,.serverConversation{
    min-width:0!important;
    max-width:100%!important;
  }

  .page{
    width:100%!important;
    overflow-x:hidden!important;
  }

  .card,.listItem,.formGrid,.grid2,.searchBox{
    min-width:0!important;
    max-width:100%!important;
  }

  input,textarea,select{
    min-width:0!important;
    width:100%;
  }

  .topbar{
    width:100%!important;
    max-width:100vw!important;
  }

  .modal{
    width:min(94vw,680px)!important;
    max-width:calc(100vw - 16px)!important;
  }
}

/* Phones */
@media (max-width:720px){
  html,body{
    width:100%!important;
    max-width:100%!important;
    min-width:0!important;
    overflow-x:hidden!important;
  }

  .app,.app.with-members{
    width:100vw!important;
    max-width:100vw!important;
    min-width:0!important;
    height:calc(100dvh - 78px)!important;
    max-height:calc(100dvh - 78px)!important;
  }

  .topbar{
    padding-left:max(10px,env(safe-area-inset-left))!important;
    padding-right:max(10px,env(safe-area-inset-right))!important;
  }

  .page{
    padding-left:max(10px,env(safe-area-inset-left))!important;
    padding-right:max(10px,env(safe-area-inset-right))!important;
    padding-bottom:94px!important;
  }

  .mobilebar{
    left:max(7px,env(safe-area-inset-left))!important;
    right:max(7px,env(safe-area-inset-right))!important;
    bottom:max(6px,env(safe-area-inset-bottom))!important;
  }

  .serverChannelButtons{
    max-width:100vw!important;
  }

  .composer{
    max-width:calc(100vw - 16px)!important;
  }

  .msgBody{
    min-width:0!important;
    max-width:calc(100vw - 62px)!important;
  }

  .text,.listTitle,.listSub,.muted{
    overflow-wrap:anywhere;
    word-break:break-word;
  }

  .modalWrap{
    width:100vw!important;
    max-width:100vw!important;
  }

  .modal{
    width:100%!important;
    max-width:100%!important;
    max-height:88dvh!important;
  }

  /* Prevent iOS from zooming the whole page when focusing form fields. */
  input,textarea,select{
    font-size:16px!important;
  }
}

/* Small phones */
@media (max-width:390px){
  .topTitle{font-size:14px!important}
  .pageHero h1{font-size:20px!important}
  .card{padding:11px!important}
  .mobilebar{height:62px!important}
  .mobilebar button{height:51px!important}
  .mobileNavOrb{width:34px!important;height:34px!important}
}

/* Tablets: use the available width rather than oversized desktop sizing. */
@media (min-width:721px) and (max-width:1100px){
  .sidebar{
    width:220px!important;
    flex-basis:220px!important;
  }

  .membersPane{
    width:220px!important;
    flex-basis:220px!important;
  }

  .page{
    padding:18px!important;
  }

  .grid2{
    gap:12px!important;
  }

  .serverChannelRail{
    width:170px!important;
    flex-basis:170px!important;
  }
}


/* ============================================================
   VYNTRA REACTIONS + LINK EMBEDS
   ============================================================ */
.reactionRow{display:flex;flex-wrap:wrap;gap:5px;margin-top:7px;align-items:center}
.reactionChip,.reactionAdd{min-height:26px;border-radius:9px;border:1px solid rgba(255,255,255,.08);background:#15101d;color:#ddd5e6;padding:3px 8px;display:inline-flex;align-items:center;gap:5px;cursor:pointer}
.reactionChip span{font-size:11px;font-weight:800;color:#a89caf}
.reactionChip.mine{background:rgba(155,77,255,.16);border-color:rgba(155,77,255,.45)}
.reactionAdd{color:#968ba0;font-size:15px}
.reactionPicker{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.reactionPicker button{height:50px;border-radius:13px;background:#181120;border:1px solid rgba(255,255,255,.07);font-size:22px}
.linkEmbed{display:block;margin-top:8px;max-width:520px;padding:10px 12px;border-radius:12px;text-decoration:none;color:inherit;background:linear-gradient(180deg,#17111f,#110d18);border-left:3px solid #9b4dff;border-top:1px solid rgba(255,255,255,.05);border-right:1px solid rgba(255,255,255,.05);border-bottom:1px solid rgba(255,255,255,.05)}
.linkEmbed:hover{background:#1c1425}
.linkEmbedHost{font-size:12px;font-weight:900;color:#c99cff;margin-bottom:4px}
.linkEmbedUrl{font-size:12px;color:#9f95a8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.publicReadOnly{justify-content:center;min-height:52px}
@media(max-width:720px){.linkEmbed{max-width:100%}.reactionPicker{grid-template-columns:repeat(3,1fr)}}


/* ============================================================
   VYNTRA CLICKABLE LINKS + REPLIES
   ============================================================ */
.messageLink{
  color:#b57cff;
  text-decoration:none;
  font-weight:650;
  word-break:break-all;
}
.messageLink:hover{
  text-decoration:underline;
}
.replyPreview{
  margin-bottom:6px;
  padding:6px 9px;
  border-left:2px solid #8051aa;
  background:rgba(155,77,255,.055);
  border-radius:0 8px 8px 0;
  cursor:pointer;
  max-width:560px;
}
.replyName{
  font-size:11px;
  font-weight:900;
  color:#c798ff;
  margin-bottom:2px;
}
.replyText{
  font-size:12px;
  color:#92899b;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
.replyBar{
  margin:0 18px -7px;
  padding:8px 10px;
  display:flex;
  align-items:center;
  gap:10px;
  border:1px solid rgba(155,77,255,.20);
  border-bottom:0;
  border-radius:13px 13px 0 0;
  background:#16101e;
}
.replyBarText{
  min-width:0;
  flex:1;
  display:flex;
  flex-direction:column;
}
.replyBarText b{
  font-size:11px;
  color:#c799ff;
}
.replyBarText span{
  font-size:11px;
  color:#89818f;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}
.replyFlash{
  animation:vyntraReplyFlash 1.2s ease!important;
}
@keyframes vyntraReplyFlash{
  0%,100%{background:transparent}
  25%,65%{background:rgba(155,77,255,.14)}
}
body.theme-light .replyBar{
  background:#f2edf6;
}
@media(max-width:720px){
  .replyBar{
    margin:0 8px -5px;
  }
}


/* ============================================================
   VYNTRA PERFORMANCE UI
   ============================================================ */
.msg.sending{
  opacity:.68;
}
.msg.sending .text{
  transition:opacity .15s ease;
}


/* ============================================================
   VYNTRA TYPING + PRESENCE
   ============================================================ */

.typingIndicator{
  min-height:24px;
  margin:0 20px -3px;
  padding:4px 8px;
  display:flex;
  align-items:center;
  gap:7px;
  color:#958a9e;
  font-size:11px;
  font-weight:700;
}

.typingDots{
  display:inline-flex;
  gap:3px;
  align-items:center;
}

.typingDots i{
  width:4px;
  height:4px;
  border-radius:50%;
  background:#a855f7;
  animation:vyntraTyping 1s infinite ease-in-out;
}

.typingDots i:nth-child(2){
  animation-delay:.14s;
}

.typingDots i:nth-child(3){
  animation-delay:.28s;
}

@keyframes vyntraTyping{
  0%,60%,100%{
    transform:translateY(0);
    opacity:.45;
  }

  30%{
    transform:translateY(-3px);
    opacity:1;
  }
}

.presenceLine{
  display:flex;
  align-items:center;
  gap:7px;
  color:#9c92a4;
  font-size:12px;
  margin-top:4px;
}

.presenceDot{
  width:9px;
  height:9px;
  min-width:9px;
  border-radius:50%;
}

.presenceDot.online{
  background:#4ade80;
  box-shadow:0 0 10px rgba(74,222,128,.5);
}

.presenceDot.offline{
  background:#625c68;
}

@media(max-width:720px){
  .typingIndicator{
    margin:0 10px -2px;
  }
}


/* ============================================================
   VYNTRA BOTS BETA
   ============================================================ */
.betaTabs{margin-bottom:14px}
.botCard{min-width:0}
.botAvatar{width:48px;height:48px}
.botPermSummary{display:flex;flex-wrap:wrap;gap:5px}
.botCode{
  padding:13px;
  border-radius:13px;
  background:#0b0810;
  border:1px solid rgba(255,255,255,.07);
  color:#bcaacb;
  white-space:pre-wrap;
  overflow-x:auto;
  font-size:12px;
}
.botPermissionRow input{flex:0 0 auto}
@media(max-width:720px){
  .desktopBetaPage{display:none!important}
  .sideBtn[onclick="showBeta()"]{display:none!important}
}


.botAdminPermission{
  border:1px solid rgba(168,85,247,.22);
  border-radius:14px;
  padding:10px!important;
  background:rgba(168,85,247,.055);
}


/* ============================================================
   VYNTRA MEMBER ROLES + BOT MEMBERS + MOBILE HOLD
   ============================================================ */
.botMemberAvatar{
  box-shadow:0 0 0 2px rgba(168,85,247,.28);
}
.profileRoleSection{
  margin-top:12px;
}
.profileRoleBadges{
  display:flex;
  flex-wrap:wrap;
  gap:6px;
  margin-top:6px;
}
.mobileHoldTarget{
  -webkit-touch-callout:none;
  user-select:none;
}


/* ============================================================
   VYNTRA MOBILE CONTEXT BUTTON + PHOTO MESSAGES
   ============================================================ */
.mobileContextBtn{
  display:none;
  border:0;
  background:transparent;
  color:#8f8599;
  min-width:34px;
  height:30px;
  border-radius:9px;
  cursor:pointer;
  font-size:15px;
  font-weight:900;
}
.mobileContextBtn:hover{
  background:rgba(255,255,255,.055);
  color:#d2c8dc;
}
.photoSendBtn{
  width:38px;
  min-width:38px;
  height:38px;
  border-radius:11px;
  border:1px solid rgba(255,255,255,.07);
  background:#181120;
  color:#c89aff;
  cursor:pointer;
  font-size:17px;
}
.pendingPhotoPreview{
  display:flex;
  align-items:center;
  gap:10px;
  margin:0 18px -7px;
  padding:8px 10px;
  border:1px solid rgba(168,85,247,.20);
  border-bottom:0;
  border-radius:13px 13px 0 0;
  background:#16101e;
}
.pendingPhotoPreview img{
  width:50px;
  height:50px;
  object-fit:cover;
  border-radius:9px;
}
.messagePhotoButton{
  display:block;
  max-width:min(520px,100%);
  border:0;
  background:transparent;
  padding:0;
  margin:7px 0 2px;
  cursor:pointer;
  border-radius:14px;
  overflow:hidden;
}
.messagePhoto{
  display:block;
  max-width:100%;
  max-height:440px;
  object-fit:contain;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.07);
}
.photoViewer{
  display:flex;
  align-items:center;
  justify-content:center;
  max-height:78dvh;
}
.photoViewer img{
  display:block;
  max-width:100%;
  max-height:76dvh;
  object-fit:contain;
  border-radius:13px;
}
.msg{
  position:relative;
}
.memberRow{
  position:relative;
}
@media(max-width:720px){
  .mobileContextBtn{
    display:inline-flex;
    align-items:center;
    justify-content:center;
  }
  .messageContextBtn{
    position:absolute;
    right:5px;
    top:7px;
  }
  .memberContextBtn{
    margin-left:auto;
    flex:0 0 34px;
  }
  .msg{
    padding-right:40px!important;
    -webkit-touch-callout:none;
    user-select:none;
  }
  .msg .text{
    user-select:none;
    -webkit-user-select:none;
  }
  .memberRow{
    -webkit-touch-callout:none;
    user-select:none;
  }
  .photoSendBtn{
    width:36px;
    min-width:36px;
    height:36px;
  }
  .pendingPhotoPreview{
    margin:0 8px -5px;
  }
  .messagePhoto{
    max-height:54dvh;
  }
}


/* ============================================================
   VYNTRA MOBILE SERVER FEATURE PARITY
   ============================================================ */
.mobileServerQuickBar{
  display:none;
}
.mobileChannelWrap{
  display:block;
}
.mobileChannelEditBtn{
  display:none;
}
.mobileServerToolGrid{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:9px;
}
.mobileServerTool{
  min-height:88px;
  border-radius:15px;
  border:1px solid rgba(255,255,255,.07);
  background:#15101d;
  color:#eee7f4;
  padding:12px;
  text-align:left;
  display:flex;
  flex-direction:column;
  gap:5px;
  cursor:pointer;
}
.mobileServerTool b{
  font-size:13px;
}
.mobileServerTool span{
  color:#958b9f;
  font-size:11px;
  line-height:1.35;
}
.mobileServerToolWide{
  grid-column:1/-1;
}
.ownerMobileTestCard{
  border-color:rgba(168,85,247,.24);
  background:linear-gradient(135deg,rgba(168,85,247,.08),rgba(17,13,24,.7));
}
.iphone11PreviewMode::after{
  content:"iPhone 11 Preview · 414 × 896";
  position:fixed;
  top:4px;
  left:50%;
  transform:translateX(-50%);
  z-index:1000;
  background:rgba(14,10,20,.88);
  border:1px solid rgba(168,85,247,.25);
  color:#bda8cd;
  padding:3px 8px;
  border-radius:999px;
  font-size:9px;
  pointer-events:none;
}

@media(max-width:720px){
  .mobileServerQuickBar{
    display:flex;
    flex:0 0 auto;
    width:100%;
    gap:6px;
    padding:6px 8px;
    overflow-x:auto;
    overflow-y:hidden;
    background:#0d0a12;
    border-bottom:1px solid rgba(255,255,255,.055);
    scrollbar-width:none;
  }
  .mobileServerQuickBar::-webkit-scrollbar{
    display:none;
  }
  .mobileServerQuickBar button{
    flex:0 0 auto;
    min-height:34px;
    padding:7px 10px;
    border-radius:10px;
    border:1px solid rgba(255,255,255,.07);
    background:#17121e;
    color:#bbaec8;
    font-size:11px;
    font-weight:800;
  }

  .mobileChannelWrap{
    display:flex;
    flex:0 0 auto;
    align-items:center;
    gap:4px;
  }
  .mobileChannelWrap .channelBtn{
    flex:0 0 auto!important;
  }
  .mobileChannelEditBtn{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    width:30px;
    height:30px;
    flex:0 0 30px;
    border-radius:999px;
    border:1px solid rgba(168,85,247,.18);
    background:#181120;
    color:#b98cf0;
    font-size:12px;
  }

  .mobileServerToolGrid{
    grid-template-columns:1fr 1fr;
  }

  .ownerMobileTestRow{
    align-items:flex-start!important;
    flex-direction:column!important;
  }

  .ownerMobileTestRow .primary{
    width:100%;
  }

  /* Ensure the full desktop-equivalent settings modal is usable on phones. */
  .modalWrap{
    align-items:flex-end!important;
    padding:8px!important;
  }
  .modal{
    width:100%!important;
    max-width:100%!important;
    max-height:88dvh!important;
    overflow-y:auto!important;
    border-radius:20px!important;
  }
  .modal .grid2{
    grid-template-columns:1fr!important;
  }
  .modal .listItem{
    min-width:0!important;
  }
}

/* The preview popup is resized to 414 × 896, and this class makes it
   visually obvious that the owner is in test mode. */
body.iphone11PreviewMode{
  min-width:0!important;
  width:100%!important;
  height:100dvh!important;
  overflow:hidden!important;
}


/* ============================================================
   VYNTRA UNREAD BADGES
   ============================================================ */
.unreadBadge{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-width:18px;
  height:18px;
  padding:0 5px;
  margin-left:auto;
  border-radius:999px;
  background:#a855f7;
  color:white;
  font-size:10px;
  font-weight:900;
  line-height:1;
  box-shadow:0 0 12px rgba(168,85,247,.28);
}
.sideBtn .unreadBadge{
  margin-left:auto;
}
.channelBtn .unreadBadge{
  margin-left:6px;
}
.serverBtn{
  position:relative;
}
.serverBtn .serverUnreadBadge,
.serverBtn .unreadBadge{
  position:absolute;
  right:-3px;
  top:-4px;
  min-width:17px;
  height:17px;
  padding:0 4px;
  font-size:9px;
  border:2px solid #0d0912;
}
.listTitle .unreadBadge{
  margin-left:6px;
  vertical-align:middle;
}
@media(max-width:720px){
  .mobilebar button{
    position:relative;
  }
  .mobilebar .unreadBadge{
    position:absolute;
    right:6px;
    top:3px;
    min-width:16px;
    height:16px;
    font-size:9px;
  }
}


/* ============================================================
   VYNTRA STRONG UNREAD INDICATORS
   ============================================================ */
.unreadDot{
  width:7px;
  height:7px;
  min-width:7px;
  border-radius:50%;
  background:#ffffff;
  box-shadow:0 0 8px rgba(255,255,255,.35);
  display:inline-block;
}
.sideBtn.hasUnread{
  color:#f4eef8;
  font-weight:900;
}
.sideBtn.hasUnread .navLabel{
  color:#ffffff;
  font-weight:900;
}
.sideBtn > .unreadDot{
  margin-right:1px;
}
.channelBtn.hasUnread{
  color:#f4eef8;
  font-weight:900;
  background:rgba(255,255,255,.025);
}
.channelBtn.hasUnread .channelLabel{
  color:#ffffff;
  font-weight:900;
}
.channelBtn > .unreadDot{
  margin-right:6px;
}
.serverBtn.hasUnread{
  transform:translateX(2px);
}
.serverBtn > .unreadDot{
  position:absolute;
  left:-8px;
  top:50%;
  width:6px;
  height:22px;
  border-radius:0 6px 6px 0;
  transform:translateY(-50%);
  background:#ffffff;
  z-index:2;
}
.listTitle.hasUnread{
  color:#ffffff;
  font-weight:900;
  display:flex;
  align-items:center;
  gap:6px;
}
.listTitle.hasUnread > .unreadDot{
  background:#a855f7;
}
@media(max-width:720px){
  .sideBtn.hasUnread,
  .channelBtn.hasUnread{
    font-weight:900;
  }
  .unreadDot{
    width:6px;
    height:6px;
    min-width:6px;
  }
}


/* ============================================================
   VYNTRA UNREAD EXACT UI FIX
   ============================================================ */
.sideBtn.hasUnread,
.serverBtn.hasUnread,
.channelBtn.hasUnread{
  position:relative;
  color:#f5eefb!important;
  font-weight:900!important;
}
.sideBtn.hasUnread .navLabel,
.serverBtn.hasUnread .serverNameLabel,
.channelBtn.hasUnread .channelLabel{
  color:#fff!important;
  font-weight:900!important;
}
.sideBtn.hasUnread::before{
  content:"";
  position:absolute;
  left:1px;
  top:50%;
  width:3px;
  height:20px;
  transform:translateY(-50%);
  border-radius:0 5px 5px 0;
  background:#fff;
}
.sideBtn > .unreadDot{
  display:none;
}
.serverBtn > .unreadDot{
  position:absolute;
  left:1px;
  top:50%;
  width:3px;
  min-width:3px;
  height:24px;
  transform:translateY(-50%);
  border-radius:0 5px 5px 0;
  background:#fff;
}
.channelBtn > .unreadDot{
  width:6px;
  height:6px;
  min-width:6px;
  margin-right:6px;
  background:#fff;
}
.mobilebar button.hasUnread{
  color:#fff!important;
  font-weight:900!important;
}
.mobilebar button > .unreadDot{
  display:block!important;
  position:absolute;
  right:9px;
  top:5px;
  width:6px;
  height:6px;
  min-width:6px;
  background:#a855f7;
}


/* ============================================================
   VYNTRA WEBRTC CALLS
   ============================================================ */
.callTopBtn{color:#c797ff}.callTopBtn.inCall{background:rgba(168,85,247,.15);box-shadow:0 0 0 1px rgba(168,85,247,.25)}
.callPanel{display:flex;flex-direction:column;gap:14px}.callHeaderCard{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border-radius:14px;border:1px solid rgba(255,255,255,.07);background:#14101b}
.callParticipants{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.callTile{overflow:hidden;border-radius:15px;border:1px solid rgba(255,255,255,.07);background:#100c16}.callVideoWrap{aspect-ratio:16/10;background:#09070d;overflow:hidden}.callVideoWrap video{width:100%;height:100%;object-fit:cover;display:block}
.callAvatarFallback{width:100%;height:100%;display:flex;flex-direction:column;gap:8px;align-items:center;justify-content:center;color:#a99cb4;font-size:12px}.callAvatarFallback img{width:72px;height:72px;border-radius:50%;object-fit:cover}.callTileFooter{display:flex;align-items:center;gap:6px;min-height:38px;padding:8px 10px;color:#d8cfdf;font-size:12px;font-weight:800}
.callControls{display:flex;flex-wrap:wrap;justify-content:center;gap:8px}.callControlBtn{min-height:40px;padding:0 14px;border-radius:12px;border:1px solid rgba(255,255,255,.07);background:#191220;color:#e8deef;cursor:pointer;font-weight:800}.callControlBtn.off{background:#27151b;color:#ffb6c2}.callControlBtn.active{border-color:rgba(168,85,247,.35);background:rgba(168,85,247,.14);color:#e1c7ff}.callHint{color:#8f8599;font-size:11px;line-height:1.5}
@media(max-width:720px){.callParticipants{grid-template-columns:1fr}.callDeviceGrid{grid-template-columns:1fr!important}.callControls{display:grid;grid-template-columns:1fr 1fr}.callControls .callControlBtn:last-child{grid-column:1/-1}.callVideoWrap{aspect-ratio:4/3}.callHeaderCard{align-items:flex-start}.mobileCallQuick{color:#d4b2ff!important;border-color:rgba(168,85,247,.22)!important}}


.profileFriendStatus{
  display:inline-flex;
  align-items:center;
  margin-top:8px;
  padding:4px 8px;
  border-radius:999px;
  border:1px solid rgba(168,85,247,.22);
  background:rgba(168,85,247,.08);
  color:#c9a7ef;
  font-size:11px;
  font-weight:800;
}


/* ============================================================
   VYNTRA CALL PERMISSION PROMPT + LARGE BUTTON
   ============================================================ */
.callTopBtn{
  min-width:100px!important;
  height:44px!important;
  padding:0 18px!important;
  border-radius:13px!important;
  border:1px solid rgba(168,85,247,.30)!important;
  background:rgba(168,85,247,.14)!important;
  color:#e3c8ff!important;
  display:inline-flex!important;
  align-items:center!important;
  justify-content:center!important;
  gap:8px!important;
  font-size:13px!important;
  font-weight:900!important;
  cursor:pointer!important;
}
.callTopBtn:hover{background:rgba(168,85,247,.22)!important;transform:translateY(-1px)}
.callTopBtn.inCall{background:rgba(74,222,128,.11)!important;border-color:rgba(74,222,128,.28)!important;color:#adf3c4!important}
.callTopIcon{font-size:17px}
.callPermissionWarning{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 12px;border:1px solid rgba(251,191,36,.20);background:rgba(251,191,36,.06);border-radius:13px}
.callPermissionWarning>div{display:flex;flex-direction:column;gap:3px}
.callPermissionWarning b{color:#f5d78b;font-size:12px}
.callPermissionWarning span{color:#aa9b87;font-size:11px;line-height:1.4}
@media(max-width:720px){
 .callTopBtn{min-width:88px!important;height:40px!important;padding:0 14px!important}
 .callPermissionWarning{flex-direction:column;align-items:stretch}
}


/* ============================================================
   VYNTRA CALL DEVICE PREFLIGHT
   ============================================================ */
.callSetupIntro{
  padding:4px 2px 10px;
}
.callSetupDevice{
  display:flex;
  flex-direction:column;
  gap:9px;
  padding:13px;
  margin-top:10px;
  border:1px solid rgba(255,255,255,.07);
  background:#131019;
  border-radius:15px;
}
.callPermissionButton{
  width:100%;
}
.callDeviceStatus{
  display:inline-flex;
  align-items:center;
  padding:4px 8px;
  border-radius:999px;
  background:rgba(255,255,255,.06);
  color:#a79daf;
  font-size:10px;
  font-weight:900;
}
.goodStatus{
  color:#9bf0b6;
  background:rgba(74,222,128,.08);
}
.badStatus{
  color:#ffadb9;
  background:rgba(244,63,94,.08);
}
.callTestResult{
  min-height:18px;
  color:#93899c;
  font-size:11px;
}
.goodTest{color:#8fe9ab}
.badTest{color:#ff9dac}
.callSetupPreview{
  display:none;
  width:100%;
  max-height:260px;
  object-fit:cover;
  border-radius:12px;
  background:#08070a;
}
.callSetupActions{
  display:flex;
  justify-content:flex-end;
  gap:8px;
  margin-top:14px;
}
.callJoinBigBtn{
  min-width:140px;
  min-height:42px;
  font-size:13px;
  font-weight:900;
}
@media(max-width:720px){
  .callSetupActions{
    display:grid;
    grid-template-columns:1fr 1fr;
  }
  .callJoinBigBtn{
    min-width:0;
  }
}


.callPolicyStatus{
  margin-top:8px;
  color:#8fe9ab;
  font-size:10px;
  font-weight:800;
}


/* ============================================================
   VYNTRA CALL STATUS + INCOMING CALL BANNER
   ============================================================ */
.inCallStatusBtn{
  min-height:36px;
  padding:0 12px;
  border-radius:12px;
  border:1px solid rgba(74,222,128,.24);
  background:rgba(74,222,128,.09);
  color:#aaf0bf;
  display:inline-flex;
  align-items:center;
  gap:7px;
  font-size:11px;
  font-weight:900;
  cursor:pointer;
}
.inCallStatusDot{
  width:8px;
  height:8px;
  border-radius:50%;
  background:#4ade80;
  box-shadow:0 0 10px rgba(74,222,128,.45);
}
.incomingCallBanner{
  position:fixed;
  left:50%;
  bottom:18px;
  transform:translateX(-50%);
  width:min(620px,calc(100vw - 28px));
  z-index:99999;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:14px;
  padding:12px 14px;
  border-radius:16px;
  border:1px solid rgba(74,222,128,.28);
  background:rgba(14,12,18,.97);
  box-shadow:0 16px 44px rgba(0,0,0,.42);
  backdrop-filter:blur(14px);
}
.incomingCallInfo{
  min-width:0;
  display:flex;
  flex-direction:column;
  gap:3px;
}
.incomingCallTitle{
  color:#f4eef8;
  font-size:13px;
  font-weight:900;
}
.incomingCallSub{
  color:#9d93a7;
  font-size:11px;
  overflow:hidden;
  text-overflow:ellipsis;
  white-space:nowrap;
}
.incomingCallActions{
  display:flex;
  align-items:center;
  gap:8px;
  flex:0 0 auto;
}
.incomingJoinBtn{
  min-height:38px;
  padding:0 16px;
  border:0;
  border-radius:12px;
  background:#22c55e;
  color:#06110a;
  font-size:12px;
  font-weight:900;
  cursor:pointer;
}
.incomingJoinBtn:hover{
  background:#2bd468;
}
@media(max-width:720px){
  .inCallStatusBtn{
    min-height:34px;
    padding:0 10px;
    font-size:10px;
  }
  .incomingCallBanner{
    bottom:74px;
    align-items:stretch;
    flex-direction:column;
  }
  .incomingCallActions{
    width:100%;
    display:grid;
    grid-template-columns:1fr 1fr;
  }
  .incomingCallActions button{
    width:100%;
  }
}


/* ============================================================
   VYNTRA REMOTE CAMERA + SCREEN SHARE FIX
   ============================================================ */
.callMediaStatus{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:8px;
  padding:8px 10px;
  border-radius:11px;
  background:rgba(255,255,255,.035);
  color:#8f8599;
  font-size:10px;
  font-weight:800;
}
.callMediaLive{
  color:#75e89b;
}
.callTile.hasVideo .callVideoWrap{
  background:#050407;
}
.callTile.hasVideo video{
  background:#050407;
}
@media(max-width:720px){
  .callMediaStatus{
    align-items:flex-start;
    flex-direction:column;
  }
}

</style>
</head>
<body>
<div id="siteBanner"></div><div id="root"></div>
<div id="modal"></div>
<div id="overlay"></div>
<div id="toastWrap"></div>

<script>
const state={
 me:null, profile:null, view:"public", channel:"chat1", messages:[],
 servers:[], activeServer:null, serverInfo:null, serverMembers:[],serverChannels:[],serverRoles:[],
 activeChat:null, poll:null,notifPoll:null,notifications:[],unreadCount:0,lastSeenUnread:0,replyingTo:null,
 messagesLoading:false,lastMessageSignature:"",sendingMessage:false,
 messageLoadSeq:0,typingPoll:null,lastTypingSent:0,typingUsers:[],memberPoll:null,
 pendingImage:null,unreads:{public:{},dms:{},servers:{},server_totals:{},friends_total:0,total:0},
 unreadPoll:null,notificationPermission:"default",lastNotified:{},
 call:{active:false,scopeKey:"",participants:[],peers:{},localStream:null,videoStream:null,signalAfter:0,signalPoll:null,heartbeatPoll:null,micEnabled:true,cameraEnabled:false,sharingScreen:false,selectedMic:"",selectedCamera:"",micPermission:"unknown",cameraPermission:"unknown",micError:"",cameraError:"",preflightMicStream:null,preflightCameraStream:null,incomingCalls:[],incomingPoll:null,lastIncomingNotified:{}}
};
const esc=s=>String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
const avatarSrc=s=>esc(s||"/static/spookchat_pfp.png");

function linkifyText(raw){
 const safe=esc(raw||"");
 return safe.replace(/https?:\/\/[^\s<]+/g,(full)=>{
   let url=full;
   let tail="";
   while(/[.,!?;:)\]]$/.test(url)){
     tail=url.slice(-1)+tail;
     url=url.slice(0,-1);
   }
   return `<a class="messageLink" href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>${tail}`;
 });
}

const roleRank=r=>({user:0,member:0,moderator:1,admin:2,owner:3}[r]??0);
function hasServerPerm(permission){
  if(!state.serverInfo) return false;
  if(state.serverInfo.my_role==="owner") return true;
  return Array.isArray(state.serverInfo.permissions) && state.serverInfo.permissions.includes(permission);
}

async function api(path,opts={}){
 const r=await fetch(path,{headers:{"Content-Type":"application/json",...(opts.headers||{})},credentials:"same-origin",...opts});
 const d=await r.json().catch(()=>({}));
 if(!r.ok){
   if(d.maintenance && typeof renderMaintenance==="function") renderMaintenance(d.error||"VYNTRA is temporarily under maintenance.");
   throw Error(d.error||`Request failed (${r.status})`);
 }
 return d;
}
function toast(msg){toastWrap.innerHTML=`<div class="toast">${esc(msg)}</div>`;setTimeout(()=>toastWrap.innerHTML="",2500)}
function applyTheme(theme){document.body.classList.remove("theme-dark","theme-light");if(theme==="dark")document.body.classList.add("theme-dark");if(theme==="light")document.body.classList.add("theme-light")}
function modalOpen(title,body){modal.innerHTML=`<div class="modalWrap"><div class="modal" onclick="event.stopPropagation()"><div class="modalHeader"><h2>${esc(title)}</h2><button type="button" class="modalCloseBtn" onclick="modalClose()" aria-label="Close">×</button></div>${body}</div></div>`}
function modalClose(){modal.innerHTML=""}
function closeContext(){overlay.innerHTML=""}
document.addEventListener("click",e=>{if(!e.target.closest(".context"))closeContext()});


async function loadSiteStatus(){
 try{
   const s=await api("/api/site-status");
   if(s.announcement){
     siteBanner.innerHTML=`<div style="position:fixed;left:50%;transform:translateX(-50%);top:10px;z-index:300;background:#1a1224;border:1px solid #7144a0;color:#eee;padding:9px 14px;border-radius:12px;box-shadow:0 10px 40px #0008;max-width:min(700px,90vw);text-align:center">${esc(s.announcement)}</div>`;
   }else siteBanner.innerHTML="";
   window._siteStatus=s;
   return s;
 }catch(e){return null}
}

async function boot(){
 const siteStatus=await loadSiteStatus();
 try{
   const d=await api("/api/me");
   state.me=d.user;state.profile=d.profile;
   applyTheme(state.profile.theme||"original");
 setTimeout(updateNotificationSettingUI,40);
   applyIPhone11PreviewMode();
   if(d.maintenance){
     renderMaintenance(d.maintenance_message||"VYNTRA is temporarily under maintenance.");
     return;
   }
   state.servers=(await api("/api/servers")).servers;
   renderApp();
   startNotificationPolling();
   setTimeout(checkInviteFromURL,150);
   setTimeout(checkBotInviteFromURL,220);
   setTimeout(startUnreadPolling,300);
   setTimeout(startIncomingCallPolling,360);
 }catch(e){renderLogin()}
}

function renderMaintenance(message){
 clearInterval(state.poll);clearInterval(state.notifPoll);
 siteBanner.innerHTML="";
 root.innerHTML=`<div class="maintenanceScreen"><div class="maintenanceCard"><img src="/static/spookchat_pfp.png" class="maintenanceLogo"><div class="maintenanceEyebrow">VYNTRA STATUS</div><h1>We'll be back soon.</h1><p>${esc(message||"VYNTRA is temporarily under maintenance.")}</p><div class="maintenanceActions"><button class="primary" onclick="boot()">Check Again</button><button class="ghost" onclick="logout()">Log Out</button></div></div></div>`;
}

function renderLogin(){
 clearInterval(state.poll);
 root.innerHTML=`<div class="login"><div class="loginCard">
 <div class="row" style="gap:12px"><img src="/static/spookchat_pfp.png" style="width:58px;height:58px;border-radius:18px;box-shadow:0 0 30px #a855f744;border:1px solid #7c3aed66"><div class="loginLogo">VYN<b>TRA</b></div></div>
 <p class="muted">A private community and messaging app.</p>
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
 <div class="brand"><div class="brandLogo"><img src="/static/spookchat_pfp.png"></div>VYN<span>TRA</span></div>
 <div class="sideScroll">
   <div class="sectionTitle">Home</div>
   <button class="sideBtn ${state.view==="public"&&state.channel==="chat1"?"active":""}${unreadClass(unreadCountFor("public","chat1"))}" data-unread-scope="public" data-channel="chat1" onclick="openPublic('chat1')">${unreadDot(unreadCountFor("public","chat1"))}<span class="iconBox">#</span><span class="navLabel">Chat 1</span>${badgeHtml(unreadCountFor("public","chat1"))}</button>
   <button class="sideBtn ${state.view==="public"&&state.channel==="chat2"?"active":""}${unreadClass(unreadCountFor("public","chat2"))}" data-unread-scope="public" data-channel="chat2" onclick="openPublic('chat2')">${unreadDot(unreadCountFor("public","chat2"))}<span class="iconBox">#</span><span class="navLabel">Chat 2</span>${badgeHtml(unreadCountFor("public","chat2"))}</button>
   <button class="sideBtn ${state.view==="friends"?"active":""}${unreadClass(unreadCountFor("friends"))}" data-unread-scope="friends" onclick="showFriendsPage()">${unreadDot(unreadCountFor("friends"))}<span class="iconBox">👥</span><span class="navLabel">Friends</span>${badgeHtml(unreadCountFor("friends"))}</button>
   <button class="sideBtn" onclick="showNotifications()"><span class="iconBox">🔔</span>Notifications <span id="notificationsUnreadSide" class="notifyBadge ${state.unreadCount?"":"hidden"}">${state.unreadCount||""}</span></button>
   <button class="sideBtn" onclick="groupCreate()"><span class="iconBox">＋</span>New Group</button>
   ${isStaff?`<button class="sideBtn ${state.view==="staff"?"active":""}" onclick="showStaff()"><span class="iconBox">🛡</span>Moderation</button>`:""}${state.profile.global_role==="owner"?`<button class="sideBtn ${state.view==="owner"?"active":""}" onclick="showOwnerPanel()"><span class="iconBox">👑</span>Owner Control</button>`:""}
   <button class="sideBtn ${state.view==="beta"?"active":""}" onclick="showBeta()"><span class="iconBox">🧪</span>Beta</button>
   <button class="sideBtn ${state.view==="settings"?"active":""}" onclick="showSettings()"><span class="iconBox">⚙</span>VYNTRA Settings</button>
   <a class="sideBtn" href="/static/downloads/VYNTRAPCSet-up.exe" download="VYNTRAPCSet-up.exe" style="text-decoration:none"><span class="iconBox">⬇</span>Download Desktop App</a>
   <button class="sideBtn ${state.view==="discover"?"active":""}" onclick="showServerDiscovery()"><span class="iconBox">🔎</span>Discover Servers</button>

   <div class="sectionTitle"><span>Your Servers</span><button class="roundBtn" style="width:27px;height:27px" onclick="serverCreate()">＋</button></div>
   ${state.servers.map(s=>{const uc=unreadCountFor("server",s.id);return `<button class="serverBtn ${state.activeServer==s.id?"active":""}${unreadClass(uc)}" data-unread-scope="server" data-server-id="${s.id}" onclick="openServer(${s.id},'chat')">
      ${unreadDot(uc)}
      <span class="serverIcon">${s.icon?`<img src="${esc(s.icon)}" onerror="this.remove()">`:esc((s.name||"S")[0].toUpperCase())}</span>
      <span class="serverNameLabel" style="min-width:0;overflow:hidden;text-overflow:ellipsis">${esc(s.name)}</span>
      ${badgeHtml(uc,"serverUnreadBadge")}<span class="badge">${s.member_count}</span>
   </button>`}).join("")}
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
   <button class="${state.view==="public"||state.view==="dm"?"active":""}${unreadClass(unreadCountFor("public","chat1")+unreadCountFor("public","chat2"))}" data-unread-scope="mobile-public-total" onclick="openPublic('chat1')">
     ${unreadDot(unreadCountFor("public","chat1")+unreadCountFor("public","chat2"))}<span class="mobileNavIcon">✦</span><span>Home</span>${badgeHtml(unreadCountFor("public","chat1")+unreadCountFor("public","chat2"))}
   </button>
   <button class="${state.view==="friends"?"active":""}${unreadClass(unreadCountFor("friends"))}" data-unread-scope="friends" onclick="showFriendsPage()">
     ${unreadDot(unreadCountFor("friends"))}<span class="mobileNavIcon">♧</span><span>Friends</span>${badgeHtml(unreadCountFor("friends"))}
   </button>
   <button class="mobileNavCenter ${state.view==="discover"||state.view==="server"?"active":""}" onclick="showMobileServerSheet()">
     <span class="mobileNavOrb">◈</span><span>Spaces</span>
   </button>
   <button onclick="showNotifications()" style="position:relative">
     <span class="mobileNavIcon">◇</span><span>Alerts</span>
     <span id="notificationsUnreadMobile" class="notifyBadge ${state.unreadCount?"":"hidden"}">${state.unreadCount||""}</span>
   </button>
   <button class="${state.view==="settings"||state.view==="owner"?"active":""}" onclick="showMobileAccountSheet()">
     <span class="mobileNavIcon">○</span><span>Me</span>
   </button>
 </nav>`;
}
function showMobileAccountSheet(){
 modalOpen("Your VYNTRA",`<div class="formGrid">
   <div class="row" style="padding:6px 0 12px"><img class="avatar" style="width:58px;height:58px" src="${avatarSrc(state.profile.avatar)}"><div><div style="font-size:18px;font-weight:900">${esc(state.profile.username)}</div><div class="muted">Vyntra ID #${state.me.id}</div></div></div>
   <button class="ghost" onclick="modalClose();showSettings()">⚙ Settings</button>
   ${["moderator","admin","owner"].includes(state.profile.global_role)?`<button class="ghost" onclick="modalClose();showStaff()">🛡 Moderation</button>`:""}
   ${state.profile.global_role==="owner"?`<button class="ghost" onclick="modalClose();showOwnerPanel()">👑 Owner Control</button>`:""}
   <a class="ghost" href="/static/downloads/VYNTRAPCSet-up.exe" download="VYNTRAPCSet-up.exe" style="text-decoration:none;text-align:center">⬇ Desktop App</a>
   <button class="danger" onclick="logout()">Log Out</button>
 </div>`);
}

function showMobileServerSheet(){
 modalOpen("Servers",`<div class="formGrid"><button class="primary" onclick="modalClose();showServerDiscovery()">Discover Servers</button><button class="ghost" onclick="modalClose();serverCreate()">Create Server</button>${state.servers.map(s=>`<button class="serverBtn" onclick="modalClose();openServer(${s.id})"><span class="serverIcon">${s.icon?`<img src="${esc(s.icon)}">`:esc(s.name[0])}</span><span class="listMain">${esc(s.name)}</span><span class="badge">${s.member_count}</span></button>`).join("")}</div>`);
}


function relativeLastSeen(iso){
 if(!iso)return "Last seen unknown";

 const d=new Date(iso);
 const seconds=Math.max(
   0,
   Math.floor(
     (Date.now()-d.getTime())/1000
   )
 );

 if(seconds<60)return "Last seen just now";

 const minutes=Math.floor(seconds/60);
 if(minutes<60)return `Last seen ${minutes}m ago`;

 const hours=Math.floor(minutes/60);
 if(hours<24)return `Last seen ${hours}h ago`;

 const days=Math.floor(hours/24);
 if(days<7)return `Last seen ${days}d ago`;

 return `Last seen ${d.toLocaleString()}`;
}

function presenceText(p){
 return p?.online
   ? "Online"
   : relativeLastSeen(p?.last_seen);
}

function presenceDot(p){
 return `<span class="presenceDot ${p?.online?"online":"offline"}"></span>`;
}


const VYNTRA_IPHONE11_PREVIEW=
 new URLSearchParams(location.search).get("mobile_preview")==="iphone11";

function launchIPhone11Preview(){
 if(state.profile?.global_role!=="owner"){
   toast("Owner only");
   return;
 }

 const u=new URL(location.href);
 u.searchParams.set("mobile_preview","iphone11");

 const w=window.open(
   u.toString(),
   "vyntra_iphone11_preview",
   "popup=yes,width=414,height=896,resizable=yes,scrollbars=no"
 );

 if(!w){
   toast("Allow popups to open the mobile preview");
   return;
 }

 setTimeout(()=>{
   try{
     const chromeW=w.outerWidth-w.innerWidth;
     const chromeH=w.outerHeight-w.innerHeight;
     w.resizeTo(414+chromeW,896+chromeH);
     w.focus();
   }catch(e){}
 },500);
}

function applyIPhone11PreviewMode(){
 if(!VYNTRA_IPHONE11_PREVIEW)return;

 document.body.classList.add("iphone11PreviewMode");

 setTimeout(()=>{
   try{
     const chromeW=window.outerWidth-window.innerWidth;
     const chromeH=window.outerHeight-window.innerHeight;
     window.resizeTo(414+chromeW,896+chromeH);
   }catch(e){}
 },250);
}



function unreadClass(count){
 return Number(count||0)>0?" hasUnread":"";
}

function unreadDot(count){
 return Number(count||0)>0?`<span class="unreadDot" aria-hidden="true"></span>`:"";
}

function unreadCountFor(type,a,b=null){
 if(type==="public"){
   return Number(state.unreads.public?.[String(a)]?.count||0);
 }
 if(type==="friends"){
   return Number(state.unreads.friends_total||0);
 }
 if(type==="server"){
   return Number(state.unreads.server_totals?.[String(a)]||0);
 }
 if(type==="server-channel"){
   return Number(state.unreads.servers?.[String(a)]?.[String(b)]?.count||0);
 }
 if(type==="dm"){
   return Number(state.unreads.dms?.[String(a)]?.count||0);
 }
 return 0;
}

function badgeHtml(count,extraClass=""){
 count=Number(count||0);
 if(count<=0)return "";
 return `<span class="unreadBadge ${extraClass}">${count>99?"99+":count}</span>`;
}

function currentReadPayload(){
 if(state.view==="public"){
   return {kind:"public",channel:state.channel};
 }
 if(state.view==="server"){
   return {
     kind:"server",
     channel:state.channel,
     server_id:state.activeServer
   };
 }
 if(state.view==="dm"){
   return {
     kind:"dm",
     chat_id:state.activeChat
   };
 }
 return null;
}


function clearUnreadLocal(kind,a,b=null){
 if(kind==="public"){
   if(state.unreads.public)delete state.unreads.public[String(a)];
 }else if(kind==="dm"){
   if(state.unreads.dms)delete state.unreads.dms[String(a)];
   state.unreads.friends_total=Object.values(state.unreads.dms||{}).reduce((n,v)=>n+Number(v?.count||0),0);
 }else if(kind==="server-channel"){
   const sid=String(a),cid=String(b);
   if(state.unreads.servers?.[sid])delete state.unreads.servers[sid][cid];
   const total=Object.values(state.unreads.servers?.[sid]||{}).reduce((n,v)=>n+Number(v?.count||0),0);
   if(state.unreads.server_totals){
     if(total>0)state.unreads.server_totals[sid]=total;
     else delete state.unreads.server_totals[sid];
   }
 }

 state.unreads.total=
   Object.values(state.unreads.public||{}).reduce((n,v)=>n+Number(v?.count||0),0)+
   Object.values(state.unreads.dms||{}).reduce((n,v)=>n+Number(v?.count||0),0)+
   Object.values(state.unreads.server_totals||{}).reduce((n,v)=>n+Number(v||0),0);

 updateUnreadBadges();
}

async function markCurrentConversationRead(){
 const payload=currentReadPayload();
 if(!payload)return;

 try{
   await api("/api/read-state",{
     method:"POST",
     body:JSON.stringify(payload)
   });

   if(payload.kind==="public"){
     delete state.unreads.public?.[String(payload.channel)];
   }else if(payload.kind==="dm"){
     delete state.unreads.dms?.[String(payload.chat_id)];
   }else if(payload.kind==="server"){
     const sid=String(payload.server_id);
     const cid=String(payload.channel);

     if(state.unreads.servers?.[sid]){
       delete state.unreads.servers[sid][cid];
     }
   }

   await loadUnreadCounts(false);

 }catch(e){}
}

function unreadNotificationKey(type,a,b=null){
 return b===null?`${type}:${a}`:`${type}:${a}:${b}`;
}

function maybeShowSystemNotifications(previous,next){
 if(document.visibilityState==="visible"&&document.hasFocus())return;
 if(Notification.permission!=="granted")return;

 // Public channels
 for(const [channel,data] of Object.entries(next.public||{})){
   const old=Number(previous.public?.[channel]?.last_message_id||0);
   const now=Number(data.last_message_id||0);

   if(now>old){
     showSystemNotification(
       `New message in ${channel}`,
       `${data.count} unread message${data.count===1?"":"s"}`,
       {kind:"public",channel}
     );
   }
 }

 // DMs and group chats
 for(const [chatId,data] of Object.entries(next.dms||{})){
   const old=Number(previous.dms?.[chatId]?.last_message_id||0);
   const now=Number(data.last_message_id||0);

   if(now>old){
     showSystemNotification(
       "New VYNTRA message",
       `${data.count} unread message${data.count===1?"":"s"} in Friends`,
       {kind:"dm",chat_id:Number(chatId)}
     );
   }
 }

 // Server channels
 for(const [sid,channels] of Object.entries(next.servers||{})){
   for(const [cid,data] of Object.entries(channels||{})){
     const old=Number(previous.servers?.[sid]?.[cid]?.last_message_id||0);
     const now=Number(data.last_message_id||0);

     if(now>old){
       const server=(state.servers||[]).find(s=>String(s.id)===String(sid));
       const ch=(
         state.activeServer&&String(state.activeServer)===String(sid)
           ?state.serverChannels
           :[]
       )?.find(c=>String(c.id)===String(cid));

       showSystemNotification(
         server?`New message in ${server.name}`:"New server message",
         ch?`#${ch.name}`:"A server channel has a new message",
         {kind:"server",server_id:Number(sid),channel:Number(cid)}
       );
     }
   }
 }
}

async function loadUnreadCounts(notify=true){
 try{
   const previous=state.unreads||{
     public:{},dms:{},servers:{},server_totals:{},
     friends_total:0,total:0
   };

   const next=await api("/api/unreads");
   state.unreads=next;

   if(notify){
     maybeShowSystemNotifications(previous,next);
   }

   updateUnreadBadges();

 }catch(e){}
}

function startUnreadPolling(){
 clearInterval(state.unreadPoll);
 loadUnreadCounts(false);
 state.unreadPoll=setInterval(
   ()=>loadUnreadCounts(true),
   2500
 );
}

function updateUnreadBadges(){
 document.querySelectorAll("[data-unread-scope]").forEach(el=>{
   const type=el.dataset.unreadScope;
   let count=0;

   if(type==="public"){
     count=state.unreads.public?.[el.dataset.channel]?.count||0;
   }else if(type==="mobile-public-total"){
     count=unreadCountFor("public","chat1")+unreadCountFor("public","chat2");
   }else if(type==="friends"){
     count=state.unreads.friends_total||0;
   }else if(type==="server"){
     count=state.unreads.server_totals?.[el.dataset.serverId]||0;
   }else if(type==="server-channel"){
     count=state.unreads.servers?.[el.dataset.serverId]?.[el.dataset.channel]?.count||0;
   }else if(type==="dm"){
     count=state.unreads.dms?.[el.dataset.chatId]?.count||0;
   }

   el.classList.toggle("hasUnread",Number(count)>0);

   let dot=el.querySelector(":scope > .unreadDot");

   if(Number(count)>0){
     if(!dot){
       dot=document.createElement("span");
       dot.className="unreadDot";
       el.insertBefore(dot,el.firstChild);
     }
   }else if(dot){
     dot.remove();
   }

   let badge=el.querySelector(":scope > .unreadBadge");

   if(Number(count)>0){
     if(!badge){
       badge=document.createElement("span");
       badge.className="unreadBadge";
       el.appendChild(badge);
     }
     badge.textContent=Number(count)>99?"99+":String(count);
   }else if(badge){
     badge.remove();
   }
 });

 document.title=state.unreads.total>0
   ?`(${state.unreads.total}) VYNTRA`
   :"VYNTRA";
}
async function requestSystemNotifications(){
 if(!("Notification" in window)){
   toast("Notifications are not supported by this browser.");
   return;
 }

 try{
   const result=await Notification.requestPermission();
   state.notificationPermission=result;

   toast(
     result==="granted"
       ?"System notifications enabled"
       :result==="denied"
         ?"Notifications were blocked"
         :"Notification permission was not granted"
   );

   updateNotificationSettingUI();

 }catch(e){
   toast("Could not enable notifications");
 }
}

function updateNotificationSettingUI(){
 const el=document.getElementById("notificationPermissionState");
 if(!el)return;

 if(!("Notification" in window)){
   el.textContent="Not supported";
   return;
 }

 el.textContent=Notification.permission==="granted"
   ?"Enabled"
   :Notification.permission==="denied"
     ?"Blocked in browser settings"
     :"Not enabled";
}

function showSystemNotification(title,body,target){
 if(!("Notification" in window)||Notification.permission!=="granted")return;

 try{
   const n=new Notification(title,{
     body,
     icon:"/static/spookchat_pfp.png",
     badge:"/static/spookchat_pfp.png",
     tag:`vyntra-${target.kind}-${target.server_id||target.chat_id||target.channel||""}`,
     renotify:true
   });

   n.onclick=()=>{
     window.focus();

     if(target.kind==="public"){
       openPublic(target.channel);
     }else if(target.kind==="dm"){
       openChat(target.chat_id);
     }else if(target.kind==="server"){
       openServer(target.server_id,target.channel);
     }

     n.close();
   };

 }catch(e){}
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
 clearInterval(state.typingPoll);
 clearInterval(state.memberPoll);
 root.innerHTML=`<div id="appShell" class="app">${sidebar()}<main class="main"><div id="mainArea" style="height:100%;display:flex;flex-direction:column"></div></main><aside id="membersPane" class="membersPane"></aside></div>${mobilebar()}`;
 if(state.view==="friends")renderFriendsPage();
 else if(state.view==="settings")renderSettings();
 else if(state.view==="staff")renderStaff();
 else if(state.view==="owner")renderOwnerPanel();
 else if(state.view==="beta")renderBeta();
 else if(state.view==="discover")renderServerDiscovery();
 else if(state.view==="server")renderServer();
 else renderChat();
 setTimeout(updateNotificationBadges,0);
}

function renderChat(){
 const title=state.view==="public"?(state.channel==="chat1"?"# Chat 1":"# Chat 2"):"Chat";
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">${esc(title)}</div><div class="topSub">Public VYNTRA channel</div></div><div class="topActions">${inCallStatusButton()}${callButton()}${notificationBellButton()}</div></header>
 <div class="content"><div id="messageList" class="messages"></div></div>
 ${(!window._siteStatus?.public_channels_locked||state.profile.global_role==="admin"||state.profile.global_role==="owner")?`<div class="composer">${photoComposerControls()}<input id="messageInput" maxlength="4000" placeholder="Message ${esc(title)}..." onkeydown="if(event.key==='Enter'){event.preventDefault();sendMessage()}"><button class="primary" onclick="sendMessage()">Send</button></div>`:`<div class="composer publicReadOnly"><div class="muted" style="padding:10px 12px">This public channel is currently locked. Only VYNTRA Admins and Owner can post.</div></div>`}`;
 appShell.classList.remove("with-members");
 loadMessages(true);
 attachTypingListener();
 renderPhotoPreview();
 state.poll=setInterval(loadMessages,2000);
}
function openPublic(c){
 clearUnreadLocal("public",c);
 state.view="public";
 state.channel=c;
 state.activeServer=null;
 state.serverInfo=null;
 state.lastMessageSignature="";
 state.messageLoadSeq++;
 renderApp();
}

async function loadMessages(force=false){
 const requestSeq=++state.messageLoadSeq;

 const viewAtStart=state.view;
 const channelAtStart=state.channel;
 const serverAtStart=state.activeServer;
 const chatAtStart=state.activeChat;

 try{
   state.messagesLoading=true;

   let url;

   if(viewAtStart==="public"){
     url=`/api/messages?kind=public&channel=${encodeURIComponent(channelAtStart)}`;
   }else if(viewAtStart==="server"){
     url=`/api/messages?kind=server&channel=${encodeURIComponent(channelAtStart)}&server_id=${serverAtStart}`;
   }else if(viewAtStart==="dm"){
     url=`/api/messages?kind=dm&chat_id=${chatAtStart}`;
   }else{
     return;
   }

   const d=await api(url);

   // Ignore an older response after either:
   // 1. a newer load started, or
   // 2. the user navigated to another conversation.
   if(
     requestSeq!==state.messageLoadSeq ||
     state.view!==viewAtStart ||
     state.channel!==channelAtStart ||
     state.activeServer!==serverAtStart ||
     state.activeChat!==chatAtStart
   ){
     return;
   }

   const messages=d.messages||[];

   const sig=messages.map(m=>[
     m.id,
     m.edited_at||"",
     m.content,
     (m.reactions||[]).map(r=>`${r.emoji}:${r.count}:${r.mine?1:0}`).join(","),
     m.reply?.id||0,
     m.is_bot?1:0,
     m.image_data?m.image_data.length:0
   ].join("|")).join("~");

   state.messages=messages;
   window._lastMessages=messages;

   const messageList=document.getElementById("messageList");

   // A newly rebuilt chat has an empty DOM even when the message
   // signature matches the last visit. Always paint that new panel.
   const needsFreshPaint=!!messageList && messageList.childElementCount===0;

   if(force||needsFreshPaint||sig!==state.lastMessageSignature){
     state.lastMessageSignature=sig;
     drawMessages();
   }

   // Reading is tied to actually opening/loading this exact conversation.
   // Do not mark unrelated background conversations as read.
   if(
     document.visibilityState==="visible" &&
     state.view===viewAtStart &&
     state.channel===channelAtStart &&
     state.activeServer===serverAtStart &&
     state.activeChat===chatAtStart
   ){
     markCurrentConversationRead();
   }

 }catch(e){
 }finally{
   if(requestSeq===state.messageLoadSeq){
     state.messagesLoading=false;
   }
 }
}
function drawMessages(){
 const el=document.getElementById("messageList");if(!el)return;
 const near=el.scrollHeight-el.scrollTop-el.clientHeight<130;
 if(!state.messages.length){el.innerHTML=`<div class="empty">No messages here yet.<br>Be the first to say something.</div>`;return}
 el.innerHTML=state.messages.map(m=>`<div class="msg ${m._optimistic?"sending":""}" id="message-${m.id}" oncontextmenu="${m._optimistic?"":`messageMenu(event,${m.id})`}">
   <img class="avatar" src="${avatarSrc(m.avatar)}" onerror="this.style.visibility='hidden'">
   <div class="msgBody"><div class="meta"><span class="name">${esc(m.username)}</span>
   ${m.is_bot?`<span class="roleTag">BOT</span>`:(m.is_spookhook?`<span class="roleTag">VYNTRAHOOK</span>`:(m.role&&m.role!=="user"&&m.role!=="member"?`<span class="roleTag">${esc(m.role)}</span>`:""))}
   <span class="time">${new Date(m.created_at).toLocaleString([], {hour:'2-digit',minute:'2-digit'})}</span>
   ${m.edited_at?`<span class="edited">(edited)</span>`:""}${m._optimistic?`<span class="edited">sending…</span>`:""}</div>${m.reply?`<div class="replyPreview" onclick="scrollToMessage(${m.reply.id})"><div class="replyName">↩ ${esc(m.reply.username)}</div><div class="replyText">${esc(m.reply.content)}</div></div>`:""}${m.content?`<div class="text">${linkifyText(m.content)}</div>`:""}${renderMessagePhoto(m)}${renderLinkEmbed(m)}${renderReactions(m)}</div>
   ${m._optimistic?"":`<button class="mobileContextBtn messageContextBtn" onclick="messageMenuFromButton(event,${m.id})" aria-label="Message menu">•••</button>`}
 </div>`).join("");
 if(near)el.scrollTop=el.scrollHeight;
}

function currentTypingScope(){
 if(state.view==="public"){
   return {kind:"public",channel:state.channel};
 }

 if(state.view==="server"){
   return {
     kind:"server",
     channel:state.channel,
     server_id:state.activeServer
   };
 }

 if(state.view==="dm"){
   return {
     kind:"dm",
     chat_id:state.activeChat
   };
 }

 return null;
}

function typingQuery(scope){
 const p=new URLSearchParams();

 Object.entries(scope||{}).forEach(([k,v])=>{
   if(v!==null&&v!==undefined)p.set(k,String(v));
 });

 return p.toString();
}

async function sendTypingSignal(){
 const scope=currentTypingScope();
 if(!scope)return;

 const now=Date.now();
 if(now-state.lastTypingSent<1700)return;

 state.lastTypingSent=now;

 try{
   await api("/api/typing",{
     method:"POST",
     body:JSON.stringify(scope)
   });
 }catch(e){}
}

async function loadTypingUsers(){
 const scope=currentTypingScope();

 if(!scope){
   state.typingUsers=[];
   renderTypingIndicator();
   return;
 }

 const viewAtStart=state.view;
 const channelAtStart=state.channel;
 const serverAtStart=state.activeServer;
 const chatAtStart=state.activeChat;

 try{
   const d=await api(
     "/api/typing?"+typingQuery(scope)
   );

   if(
     state.view!==viewAtStart ||
     state.channel!==channelAtStart ||
     state.activeServer!==serverAtStart ||
     state.activeChat!==chatAtStart
   ){
     return;
   }

   state.typingUsers=d.typing||[];
   renderTypingIndicator();

 }catch(e){}
}

function startTypingPolling(){
 clearInterval(state.typingPoll);
 loadTypingUsers();
 state.typingPoll=setInterval(
   loadTypingUsers,
   1500
 );
}

function attachTypingListener(){
 const input=document.getElementById("messageInput");
 if(!input)return;

 if(input.dataset.typingAttached==="1")return;
 input.dataset.typingAttached="1";

 input.addEventListener("input",()=>{
   if(input.value.trim()){
     sendTypingSignal();
   }
 });

 startTypingPolling();
}

function renderTypingIndicator(){
 let el=document.getElementById(
   "typingIndicator"
 );

 const composer=document.querySelector(
   ".composer"
 );

 if(!composer){
   if(el)el.remove();
   return;
 }

 if(!el){
   el=document.createElement("div");
   el.id="typingIndicator";
   el.className="typingIndicator";
   composer.parentNode.insertBefore(
     el,
     composer
   );
 }

 const users=state.typingUsers||[];

 if(!users.length){
   el.classList.add("hidden");
   el.innerHTML="";
   return;
 }

 let label="";

 if(users.length===1){
   label=`${esc(users[0].username)} is typing`;
 }else if(users.length===2){
   label=`${esc(users[0].username)} and ${esc(users[1].username)} are typing`;
 }else{
   label=`${esc(users[0].username)}, ${esc(users[1].username)} and ${users.length-2} more are typing`;
 }

 el.classList.remove("hidden");

 el.innerHTML=`
   <span class="typingDots">
     <i></i><i></i><i></i>
   </span>
   <span>${label}</span>
 `;
}



const VYNTRA_RTC_CONFIG={iceServers:[
 {urls:"stun:stun.l.google.com:19302"},
 {urls:"stun:stun1.l.google.com:19302"}
]};

function currentCallScopePayload(){
 if(state.view==="public")return {kind:"public",channel:state.channel};
 if(state.view==="server")return {kind:"server",channel:state.channel,server_id:state.activeServer};
 if(state.view==="dm")return {kind:"dm",chat_id:state.activeChat};
 return null;
}

function inCallStatusButton(){
 if(!state.call.active)return "";

 return `<button class="inCallStatusBtn" onclick="openCallPanel()" title="Open current call">
   <span class="inCallStatusDot"></span>
   <span>You're in a call</span>
 </button>`;
}

function callButton(){
 return `<button class="callTopBtn ${state.call.active?"inCall":""}" onclick="${state.call.active?"openCallPanel()":"openCallSetup()"}" title="${state.call.active?"Open current call":"Start call"}"><span class="callTopIcon">☎</span><span>${state.call.active?"In Call":"Call"}</span></button>`;
}


function incomingCallKey(call){
 return call.scope_key;
}

function currentCallScopeKey(){
 const p=currentCallScopePayload();
 if(!p)return "";

 if(p.kind==="public")return `public:${p.channel}`;
 if(p.kind==="server")return `server:${p.server_id}:${p.channel}`;
 if(p.kind==="dm")return `dm:${p.chat_id}`;

 return "";
}

async function pollIncomingCalls(){
 try{
   const d=await api("/api/calls/active");
   const calls=d.calls||[];

   state.call.incomingCalls=calls;

   // Ignore the call we're already inside.
   const currentActive=state.call.active?state.call.scopeKey:"";
   const candidates=calls.filter(c=>c.scope_key!==currentActive);

   if(!candidates.length){
     hideIncomingCallBanner();
     return;
   }

   // Show the newest active call.
   const call=candidates[0];

   showIncomingCallBanner(call);

   // If the tab/page is hidden or unfocused, use a system notification.
   if(
     (document.visibilityState!=="visible" || !document.hasFocus()) &&
     "Notification" in window &&
     Notification.permission==="granted"
   ){
     const key=incomingCallKey(call);
     const last=Number(state.call.lastIncomingNotified?.[key]||0);
     const now=Date.now();

     // Avoid spamming the same incoming call notification.
     if(now-last>30000){
       state.call.lastIncomingNotified[key]=now;
       showIncomingCallSystemNotification(call);
     }
   }

 }catch(e){}
}

function startIncomingCallPolling(){
 clearInterval(state.call.incomingPoll);
 pollIncomingCalls();
 state.call.incomingPoll=setInterval(pollIncomingCalls,2500);
}

function showIncomingCallBanner(call){
 let wrap=document.getElementById("incomingCallBanner");

 if(!wrap){
   wrap=document.createElement("div");
   wrap.id="incomingCallBanner";
   wrap.className="incomingCallBanner";
   document.body.appendChild(wrap);
 }

 wrap.innerHTML=`
   <div class="incomingCallInfo">
     <div class="incomingCallTitle">Someone is calling you</div>
     <div class="incomingCallSub">${esc(call.display_name||"VYNTRA call")} · ${call.participant_count||1} in call</div>
   </div>
   <div class="incomingCallActions">
     <button class="ghost" onclick="dismissIncomingCallBanner()">Dismiss</button>
     <button class="incomingJoinBtn" onclick='joinIncomingCall(${JSON.stringify(call).replace(/'/g,"&#39;")})'>Join Call</button>
   </div>
 `;
}

function hideIncomingCallBanner(){
 const el=document.getElementById("incomingCallBanner");
 if(el)el.remove();
}

function dismissIncomingCallBanner(){
 hideIncomingCallBanner();
}

async function joinIncomingCall(call){
 if(!call)return;

 if(call.kind==="public"){
   openPublic(call.channel);
 }else if(call.kind==="server"){
   await openServer(call.server_id,call.channel);
 }else if(call.kind==="dm"){
   await openChat(call.chat_id);
 }

 hideIncomingCallBanner();

 // Open setup so the user can verify mic/camera before joining.
 setTimeout(openCallSetup,120);
}

function showIncomingCallSystemNotification(call){
 try{
   const n=new Notification("Incoming VYNTRA call",{
     body:`${call.display_name||"Someone"} is calling you`,
     icon:"/static/spookchat_pfp.png",
     badge:"/static/spookchat_pfp.png",
     tag:`vyntra-incoming-call-${call.scope_key}`,
     renotify:true
   });

   n.onclick=()=>{
     window.focus();

     if(call.kind==="public"){
       openPublic(call.channel);
     }else if(call.kind==="server"){
       openServer(call.server_id,call.channel);
     }else if(call.kind==="dm"){
       openChat(call.chat_id);
     }

     setTimeout(openCallSetup,150);
     n.close();
   };

 }catch(e){}
}

function callPermissionStatus(kind){
 const value=kind==="mic"?state.call.micPermission:state.call.cameraPermission;

 if(value==="granted")return `<span class="callDeviceStatus goodStatus">Ready</span>`;
 if(value==="denied")return `<span class="callDeviceStatus badStatus">Blocked</span>`;
 if(value==="missing")return `<span class="callDeviceStatus badStatus">Not Found</span>`;
 if(value==="error")return `<span class="callDeviceStatus badStatus">Error</span>`;
 return `<span class="callDeviceStatus">Not Tested</span>`;
}

async function openCallSetup(){
 if(state.call.active){
   openCallPanel();
   return;
 }

 const scope=currentCallScopePayload();

 if(!scope){
   toast("Open a messaging channel first.");
   return;
 }

 let devices={mics:[],cameras:[]};

 try{
   devices=await enumerateCallDevices();
 }catch(e){}

 modalOpen("Call Setup",`
   <div class="callSetupIntro">
     <div class="listTitle">Set up your call</div>
     <div class="listSub">VYNTRA will test your microphone and camera before joining. Your camera stays off until you turn it on in the call.</div>
     <div class="callPolicyStatus">Secure media access enabled for this VYNTRA page.</div>
   </div>

   <div class="callSetupDevice">
     <div class="row between">
       <div>
         <div class="listTitle">Microphone</div>
         <div class="listSub">Choose and test the microphone you want to use.</div>
       </div>
       ${callPermissionStatus("mic")}
     </div>

     <select id="callSetupMic" class="field" onchange="state.call.selectedMic=this.value">
       <option value="">Default microphone</option>
       ${devices.mics.map((d,i)=>`<option value="${esc(d.deviceId)}" ${state.call.selectedMic===d.deviceId?"selected":""}>${esc(d.label||`Microphone ${i+1}`)}</option>`).join("")}
     </select>

     <button class="primary callPermissionButton" onclick="testCallMicrophone()">Enable / Test Microphone</button>

     <div id="callMicTestResult" class="callTestResult">
       ${state.call.micPermission==="granted"?"Microphone is ready.":esc(state.call.micError||"")}
     </div>
   </div>

   <div class="callSetupDevice">
     <div class="row between">
       <div>
         <div class="listTitle">Camera</div>
         <div class="listSub">Choose and test your camera. Testing does not turn it on for the call.</div>
       </div>
       ${callPermissionStatus("camera")}
     </div>

     <select id="callSetupCamera" class="field" onchange="state.call.selectedCamera=this.value">
       <option value="">Default camera</option>
       ${devices.cameras.map((d,i)=>`<option value="${esc(d.deviceId)}" ${state.call.selectedCamera===d.deviceId?"selected":""}>${esc(d.label||`Camera ${i+1}`)}</option>`).join("")}
     </select>

     <button class="primary callPermissionButton" onclick="testCallCamera()">Enable / Test Camera</button>

     <div id="callCameraTestResult" class="callTestResult">
       ${state.call.cameraPermission==="granted"?"Camera is ready.":esc(state.call.cameraError||"")}
     </div>

     <video id="callCameraPreview" class="callSetupPreview" autoplay muted playsinline></video>
   </div>

   <div class="callSetupActions">
     <button class="ghost" onclick="closeCallSetup()">Cancel</button>
     <button class="primary callJoinBigBtn" onclick="joinCallAfterSetup()">Join Call</button>
   </div>
 `);

 // If access had already been granted earlier, device labels become available
 // only after getUserMedia has succeeded. Refresh selectors after a moment.
 setTimeout(refreshCallSetupDevices,150);
}

async function refreshCallSetupDevices(){
 if(!document.getElementById("callSetupMic"))return;

 try{
   const devices=await enumerateCallDevices();

   const mic=document.getElementById("callSetupMic");
   const cam=document.getElementById("callSetupCamera");

   if(mic){
     const selected=state.call.selectedMic||mic.value;
     mic.innerHTML=`<option value="">Default microphone</option>`+
       devices.mics.map((d,i)=>`<option value="${esc(d.deviceId)}">${esc(d.label||`Microphone ${i+1}`)}</option>`).join("");
     mic.value=selected;
   }

   if(cam){
     const selected=state.call.selectedCamera||cam.value;
     cam.innerHTML=`<option value="">Default camera</option>`+
       devices.cameras.map((d,i)=>`<option value="${esc(d.deviceId)}">${esc(d.label||`Camera ${i+1}`)}</option>`).join("");
     cam.value=selected;
   }
 }catch(e){}
}

async function testCallMicrophone(){
 const result=document.getElementById("callMicTestResult");
 const select=document.getElementById("callSetupMic");

 if(select)state.call.selectedMic=select.value;

 if(result)result.textContent="Requesting microphone access...";

 try{
   state.call.preflightMicStream?.getTracks().forEach(t=>t.stop());

   const stream=await navigator.mediaDevices.getUserMedia({
     audio:state.call.selectedMic
       ?{deviceId:{exact:state.call.selectedMic}}
       :true,
     video:false
   });

   const track=stream.getAudioTracks()[0];

   if(!track){
     throw new Error("Browser returned no microphone track.");
   }

   state.call.preflightMicStream=stream;
   state.call.localStream=stream;
   state.call.micPermission="granted";
   state.call.micError="";
   state.call.micEnabled=true;

   if(result){
     result.textContent=`Microphone ready: ${track.label||"Default microphone"}`;
     result.className="callTestResult goodTest";
   }

   await refreshCallSetupDevices();

 }catch(e){
   state.call.micPermission=
     e?.name==="NotAllowedError"||e?.name==="PermissionDeniedError"
       ?"denied"
       :e?.name==="NotFoundError"
         ?"missing"
         :"error";

   state.call.micError=
     state.call.micPermission==="denied"
       ?`Microphone request was denied (${e?.name||"NotAllowedError"}): ${e?.message||"Access denied"}`
       :state.call.micPermission==="missing"
         ?"No microphone was found."
         :`${e?.name||"MediaError"}: ${e?.message||"Microphone test failed."}`;

   if(result){
     result.textContent=state.call.micError;
     result.className="callTestResult badTest";
   }
 }
}

async function testCallCamera(){
 const result=document.getElementById("callCameraTestResult");
 const preview=document.getElementById("callCameraPreview");
 const select=document.getElementById("callSetupCamera");

 if(select)state.call.selectedCamera=select.value;

 if(result)result.textContent="Requesting camera access...";

 try{
   state.call.preflightCameraStream?.getTracks().forEach(t=>t.stop());

   const stream=await navigator.mediaDevices.getUserMedia({
     audio:false,
     video:state.call.selectedCamera
       ?{deviceId:{exact:state.call.selectedCamera}}
       :true
   });

   const track=stream.getVideoTracks()[0];

   if(!track){
     throw new Error("Browser returned no camera track.");
   }

   state.call.preflightCameraStream=stream;
   state.call.cameraPermission="granted";
   state.call.cameraError="";

   if(preview){
     preview.srcObject=stream;
     preview.style.display="block";
     preview.play().catch(()=>{});
   }

   if(result){
     result.textContent=`Camera ready: ${track.label||"Default camera"}`;
     result.className="callTestResult goodTest";
   }

   await refreshCallSetupDevices();

 }catch(e){
   state.call.cameraPermission=
     e?.name==="NotAllowedError"||e?.name==="PermissionDeniedError"
       ?"denied"
       :e?.name==="NotFoundError"
         ?"missing"
         :"error";

   state.call.cameraError=
     state.call.cameraPermission==="denied"
       ?`Camera request was denied (${e?.name||"NotAllowedError"}): ${e?.message||"Access denied"}`
       :state.call.cameraPermission==="missing"
         ?"No camera was found."
         :`${e?.name||"MediaError"}: ${e?.message||"Camera test failed."}`;

   if(result){
     result.textContent=state.call.cameraError;
     result.className="callTestResult badTest";
   }
 }
}

function closeCallSetup(){
 state.call.preflightCameraStream?.getTracks().forEach(t=>t.stop());
 state.call.preflightCameraStream=null;

 // Keep a successfully tested microphone stream available only if we're
 // about to join; canceling should release it.
 state.call.preflightMicStream?.getTracks().forEach(t=>t.stop());
 state.call.preflightMicStream=null;
 state.call.localStream=null;

 modalClose();
}

async function joinCallAfterSetup(){
 // Camera is only a permission/device test; turn the preview off before join.
 state.call.preflightCameraStream?.getTracks().forEach(t=>t.stop());
 state.call.preflightCameraStream=null;

 await startCall(true);
}

async function enumerateCallDevices(){
 if(!navigator.mediaDevices?.enumerateDevices)return {mics:[],cameras:[]};
 const all=await navigator.mediaDevices.enumerateDevices();
 return {mics:all.filter(x=>x.kind==="audioinput"),cameras:all.filter(x=>x.kind==="videoinput")};
}
async function ensureCallAudio(showMessage=false){
 if(state.call.localStream?.getAudioTracks?.().length)return state.call.localStream;
 if(!navigator.mediaDevices?.getUserMedia){
  state.call.micPermission="unsupported";state.call.micEnabled=false;state.call.localStream=new MediaStream();return state.call.localStream;
 }
 try{
  const stream=await navigator.mediaDevices.getUserMedia({audio:state.call.selectedMic?{deviceId:{exact:state.call.selectedMic}}:true,video:false});
  state.call.localStream=stream;state.call.micPermission="granted";state.call.micError="";state.call.micEnabled=true;return stream;
 }catch(e){
  state.call.localStream=new MediaStream();state.call.micEnabled=false;
  if(e?.name==="NotAllowedError"||e?.name==="PermissionDeniedError"){
   state.call.micPermission="denied";state.call.micError="Microphone permission is blocked.";
   if(showMessage)toast("Microphone blocked — joining muted.");
  }else if(e?.name==="NotFoundError"){
   state.call.micPermission="missing";state.call.micError="No microphone was found.";
   if(showMessage)toast("No microphone found — joining muted.");
  }else{
   state.call.micPermission="error";state.call.micError=e?.message||"Could not open microphone.";
   if(showMessage)toast("Microphone unavailable — joining muted.");
  }
  return state.call.localStream;
 }
}

async function requestInitialCallPermissions(){
 if(!navigator.mediaDevices?.getUserMedia)return;
 await ensureCallAudio(true);

 try{
  const cam=await navigator.mediaDevices.getUserMedia({audio:false,video:state.call.selectedCamera?{deviceId:{exact:state.call.selectedCamera}}:true});
  state.call.cameraPermission="granted";state.call.cameraError="";
  cam.getTracks().forEach(track=>track.stop());
 }catch(e){
  if(e?.name==="NotAllowedError"||e?.name==="PermissionDeniedError"){
   state.call.cameraPermission="denied";state.call.cameraError="Camera permission is blocked.";toast("Camera blocked — you can still join the call.");
  }else if(e?.name==="NotFoundError"){
   state.call.cameraPermission="missing";state.call.cameraError="No camera was found.";
  }else{
   state.call.cameraPermission="error";state.call.cameraError=e?.message||"Could not open camera.";
  }
 }
}
async function startCall(fromSetup=false){
 if(state.call.active)return openCallPanel();

 if(!fromSetup){
   await openCallSetup();
   return;
 }

 const scope=currentCallScopePayload();
 if(!scope){
   toast("Open a messaging channel first.");
   return;
 }

 try{
   // If microphone was not tested or permission was denied, still join muted.
   if(!state.call.localStream){
     state.call.localStream=new MediaStream();
     state.call.micEnabled=false;
   }

   const d=await api("/api/calls/join",{
     method:"POST",
     body:JSON.stringify(scope)
   });

   state.call.active=true;
   state.call.scopeKey=d.scope_key;
   state.call.participants=d.participants||[];
   state.call.signalAfter=0;
   hideIncomingCallBanner();

   // The preflight stream is now the real call microphone stream.
   state.call.preflightMicStream=null;

   modalClose();

   await syncCallPeers();
   startCallPolling();
   await openCallPanel();

 }catch(e){
   state.call.active=false;
   state.call.scopeKey="";

   const msg=String(e?.message||"Could not start call");

   if(msg.toLowerCase().includes("you cannot join this call")){
     toast("Call access denied by VYNTRA. You may not have access to this channel/chat.");
   }else if(msg.toLowerCase().includes("permission")){
     toast("Call backend rejected the request: "+msg);
   }else{
     toast(msg);
   }
 }
}
function startCallPolling(){
 clearInterval(state.call.signalPoll);clearInterval(state.call.heartbeatPoll);
 state.call.signalPoll=setInterval(pollCallSignals,850);state.call.heartbeatPoll=setInterval(callHeartbeat,5000);
 pollCallSignals();callHeartbeat();
}
async function callHeartbeat(){
 if(!state.call.active)return;
 try{const d=await api("/api/calls/heartbeat",{method:"POST",body:JSON.stringify({scope_key:state.call.scopeKey})});state.call.participants=d.participants||[];await syncCallPeers();renderCallParticipants()}catch(e){}
}
async function syncCallPeers(){
 if(!state.call.active)return;
 const me=Number(state.me.id), wanted=new Set((state.call.participants||[]).map(p=>Number(p.id)).filter(id=>id!==me));
 Object.keys(state.call.peers).forEach(id=>{if(!wanted.has(Number(id)))closeCallPeer(Number(id))});
 for(const p of state.call.participants||[]){const id=Number(p.id);if(id===me||state.call.peers[id])continue;await createCallPeer(id,me<id)}
}
async function createCallPeer(remoteId,makeOffer){
 const pc=new RTCPeerConnection(VYNTRA_RTC_CONFIG);
 const remoteStream=new MediaStream();

 state.call.peers[remoteId]={
   pc,
   stream:remoteStream,
   videoSender:null
 };

 const audio=await ensureCallAudio(false);
 audio.getAudioTracks().forEach(track=>pc.addTrack(track,audio));

 // The OFFERER reserves one send/receive video m-line from the beginning.
 // This lets camera and screen sharing turn on later with replaceTrack()
 // without needing a second negotiation just to add video.
 if(makeOffer){
   const tx=pc.addTransceiver("video",{direction:"sendrecv"});
   state.call.peers[remoteId].videoSender=tx.sender;

   const currentVideo=state.call.videoStream?.getVideoTracks?.()[0];
   if(currentVideo){
     await tx.sender.replaceTrack(currentVideo);
   }
 }

 pc.onicecandidate=e=>{
   if(e.candidate){
     sendCallSignal(remoteId,"ice",{candidate:e.candidate.toJSON()});
   }
 };

 pc.ontrack=e=>{
   // Do NOT depend on event.streams[0]. Some browsers/mobile WebRTC
   // implementations deliver a valid track with an empty streams array.
   const track=e.track;

   if(track && !remoteStream.getTracks().some(t=>t.id===track.id)){
     remoteStream.addTrack(track);
   }

   // When the remote side later replaceTrack()s camera/screen sharing,
   // the same receiver track becomes live automatically.
   renderCallParticipants();

   track.onunmute=()=>renderCallParticipants();
   track.onended=()=>renderCallParticipants();
 };

 pc.onconnectionstatechange=()=>{
   if(pc.connectionState==="failed"){
     toast("A call connection failed. Try leaving and rejoining.");
   }
   renderCallParticipants();
 };

 if(makeOffer){
   const offer=await pc.createOffer();
   await pc.setLocalDescription(offer);
   await sendCallSignal(remoteId,"offer",{
     sdp:pc.localDescription.toJSON()
   });
 }

 return pc;
}

function getPeerVideoSender(peer){
 if(peer?.videoSender)return peer.videoSender;

 const tx=peer?.pc?.getTransceivers?.().find(t=>
   t.receiver?.track?.kind==="video" ||
   t.sender?.track?.kind==="video"
 );

 if(tx){
   peer.videoSender=tx.sender;
   return tx.sender;
 }

 return null;
}

async function attachCurrentVideoToPeer(peer){
 if(!peer?.pc)return;

 const track=state.call.videoStream?.getVideoTracks?.()[0]||null;
 const sender=getPeerVideoSender(peer);

 if(sender){
   await sender.replaceTrack(track);
 }
}

async function renegotiateCallPeer(remoteId){
 const peer=state.call.peers[remoteId];
 if(!peer?.pc || peer.pc.signalingState!=="stable")return;

 try{
   const offer=await peer.pc.createOffer();
   await peer.pc.setLocalDescription(offer);
   await sendCallSignal(remoteId,"offer",{
     sdp:peer.pc.localDescription.toJSON()
   });
 }catch(e){}
}

async function sendCallSignal(uid,type,payload){
 try{await api("/api/calls/signal",{method:"POST",body:JSON.stringify({scope_key:state.call.scopeKey,to_user_id:uid,signal_type:type,payload})})}catch(e){}
}
async function pollCallSignals(){
 if(!state.call.active)return;
 try{
  const d=await api(`/api/calls/signals?scope_key=${encodeURIComponent(state.call.scopeKey)}&after_id=${state.call.signalAfter||0}`);
  for(const s of d.signals||[]){
   state.call.signalAfter=Math.max(state.call.signalAfter||0,Number(s.id));const uid=Number(s.from_user_id);
   if(!state.call.peers[uid])await createCallPeer(uid,false);const pc=state.call.peers[uid].pc;
   if(s.signal_type==="offer"){
    await pc.setRemoteDescription(new RTCSessionDescription(s.payload.sdp));

    const peer=state.call.peers[uid];

    // The incoming offer creates the matching video transceiver on this
    // side. Store its sender and attach our current video before answering.
    peer.videoSender=getPeerVideoSender(peer);
    await attachCurrentVideoToPeer(peer);

    const answer=await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await sendCallSignal(uid,"answer",{
      sdp:pc.localDescription.toJSON()
    });
   }else if(s.signal_type==="answer"){
    if(pc.signalingState!=="stable")await pc.setRemoteDescription(new RTCSessionDescription(s.payload.sdp));
   }else if(s.signal_type==="ice"){
    try{await pc.addIceCandidate(new RTCIceCandidate(s.payload.candidate))}catch(e){}
   }
  }
 }catch(e){}
}
function closeCallPeer(uid){const p=state.call.peers[uid];if(!p)return;try{p.pc.close()}catch(e){};delete state.call.peers[uid];renderCallParticipants()}
async function leaveCall(){
 if(!state.call.active)return;
 try{await api("/api/calls/leave",{method:"POST",body:JSON.stringify({scope_key:state.call.scopeKey})})}catch(e){}
 clearInterval(state.call.signalPoll);clearInterval(state.call.heartbeatPoll);Object.values(state.call.peers).forEach(p=>{try{p.pc.close()}catch(e){}});
 state.call.localStream?.getTracks().forEach(t=>t.stop());state.call.videoStream?.getTracks().forEach(t=>t.stop());
 const mic=state.call.selectedMic,cam=state.call.selectedCamera;
 state.call={active:false,scopeKey:"",participants:[],peers:{},localStream:null,videoStream:null,signalAfter:0,signalPoll:null,heartbeatPoll:null,micEnabled:true,cameraEnabled:false,sharingScreen:false,selectedMic:mic,selectedCamera:cam,micPermission:"unknown",cameraPermission:"unknown",micError:"",cameraError:"",preflightMicStream:null,preflightCameraStream:null,incomingCalls:[],incomingPoll:null,lastIncomingNotified:{}};
 document.querySelectorAll('[id^="callAudio-"]').forEach(e=>e.remove());modalClose();renderApp();toast("Left call");
}
async function enableCallMicrophone(){
 if(state.call.localStream?.getAudioTracks?.().length){
  state.call.micEnabled=true;state.call.localStream.getAudioTracks().forEach(t=>t.enabled=true);updateCallControls();return;
 }
 state.call.localStream=null;
 const stream=await ensureCallAudio(true);const track=stream.getAudioTracks()[0];
 if(!track){openCallPermissionHelp("microphone");updateCallControls();return}
 track.enabled=true;state.call.micEnabled=true;
 for(const p of Object.values(state.call.peers)){
  const sender=p.pc.getSenders().find(s=>s.track?.kind==="audio");
  if(sender)await sender.replaceTrack(track);else p.pc.addTrack(track,stream);
 }
 updateCallControls();toast("Microphone enabled");
}
function openCallPermissionHelp(type){
 const isMic=type==="microphone",title=isMic?"Microphone Permission":"Camera Permission",err=isMic?state.call.micError:state.call.cameraError;
 modalOpen(title,`<div class="card"><h3>${title} is blocked</h3><div class="muted">${esc(err||`${title} is unavailable.`)}</div></div><div class="card"><h3>Allow access</h3><div class="muted" style="line-height:1.65">Click the site/lock icon beside the VYNTRA address, set <b>${isMic?"Microphone":"Camera"}</b> to <b>Allow</b>, then reload VYNTRA.<br><br>On Windows you may also need Settings → Privacy & security.</div></div><div class="modalActions"><button class="ghost" onclick="modalClose()">Close</button><button class="primary" onclick="modalClose();${isMic?"enableCallMicrophone()":"toggleCamera()"}">Try Again</button></div>`);
}
function toggleCallMute(){
 const tracks=state.call.localStream?.getAudioTracks?.()||[];
 if(!tracks.length){enableCallMicrophone();return}
 state.call.micEnabled=!state.call.micEnabled;tracks.forEach(t=>t.enabled=state.call.micEnabled);updateCallControls();
}
async function setOutgoingVideoTrack(track,stream){
 for(const [remoteId,peer] of Object.entries(state.call.peers)){
   let sender=getPeerVideoSender(peer);

   if(!sender){
     // Fallback for an old/already-open peer that was created before this
     // update or a browser that did not expose the expected transceiver.
     const tx=peer.pc.addTransceiver("video",{direction:"sendrecv"});
     peer.videoSender=tx.sender;
     sender=tx.sender;

     await sender.replaceTrack(track||null);
     await renegotiateCallPeer(Number(remoteId));
     continue;
   }

   await sender.replaceTrack(track||null);
 }
}
async function toggleCamera(){
 try{
  if(state.call.sharingScreen){toast("Stop screen sharing before turning on the camera.");return}
  if(state.call.cameraEnabled){state.call.videoStream?.getTracks().forEach(t=>t.stop());await setOutgoingVideoTrack(null,null);state.call.videoStream=null;state.call.cameraEnabled=false;renderCallParticipants();updateCallControls();return}
  const stream=await navigator.mediaDevices.getUserMedia({
   audio:false,
   video:state.call.selectedCamera?{deviceId:{exact:state.call.selectedCamera}}:true
  });

  const track=stream.getVideoTracks()[0];
  if(!track)throw new Error("Camera opened but returned no video track.");

  state.call.videoStream=stream;
  state.call.cameraEnabled=true;
  state.call.cameraPermission="granted";
  state.call.cameraError="";

  await setOutgoingVideoTrack(track,stream);

  track.onended=()=>{
   if(state.call.cameraEnabled)toggleCamera();
  };

  renderCallParticipants();
  updateCallControls();
  toast("Camera is now being sent to the call.");
 }catch(e){
  if(e?.name==="NotAllowedError"||e?.name==="PermissionDeniedError"){
   state.call.cameraPermission="denied";state.call.cameraError="Camera permission is blocked.";openCallPermissionHelp("camera");
  }else toast(e.message||"Could not use camera");
 }
}
async function toggleScreenShare(){
 if(!navigator.mediaDevices?.getDisplayMedia){toast("Screen sharing is not available in this browser.");return}
 try{
  if(state.call.sharingScreen){await stopScreenShare();return}
  if(state.call.cameraEnabled)await toggleCamera();
  const stream=await navigator.mediaDevices.getDisplayMedia({
   video:{
     frameRate:{ideal:30,max:30}
   },
   audio:false
  });

  const track=stream.getVideoTracks()[0];
  if(!track)throw new Error("Screen sharing returned no video track.");

  state.call.videoStream=stream;
  state.call.sharingScreen=true;

  await setOutgoingVideoTrack(track,stream);

  track.onended=()=>stopScreenShare();

  renderCallParticipants();
  updateCallControls();
  toast("Your screen is now being shared to the call.");
 }catch(e){if(e?.name!=="NotAllowedError")toast(e.message||"Could not share screen")}
}
async function stopScreenShare(){
 if(!state.call.sharingScreen)return;const stream=state.call.videoStream;state.call.sharingScreen=false;state.call.videoStream=null;await setOutgoingVideoTrack(null,null);stream?.getTracks().forEach(t=>t.stop());renderCallParticipants();updateCallControls();
}
async function changeCallMic(el){
 state.call.selectedMic=el.value;if(!state.call.active)return;
 try{
  const stream=await navigator.mediaDevices.getUserMedia({audio:el.value?{deviceId:{exact:el.value}}:true,video:false});
  const track=stream.getAudioTracks()[0];track.enabled=true;
  for(const p of Object.values(state.call.peers)){const s=p.pc.getSenders().find(x=>x.track?.kind==="audio");if(s)await s.replaceTrack(track);else p.pc.addTrack(track,stream)}
  state.call.localStream?.getAudioTracks().forEach(t=>t.stop());state.call.localStream=new MediaStream([track]);state.call.micEnabled=true;state.call.micPermission="granted";state.call.micError="";updateCallControls();toast("Microphone changed");
 }catch(e){
  if(e?.name==="NotAllowedError"||e?.name==="PermissionDeniedError"){state.call.micPermission="denied";state.call.micError="Microphone permission is blocked.";openCallPermissionHelp("microphone")}
  else toast(e.message||"Could not change microphone");
 }
}
async function changeCallCamera(el){state.call.selectedCamera=el.value;if(state.call.cameraEnabled){await toggleCamera();await toggleCamera()}}
async function openCallPanel(){
 if(!state.call.active)return startCall();
 let devices={mics:[],cameras:[]};try{devices=await enumerateCallDevices()}catch(e){}
 modalOpen("VYNTRA Call",`<div class="callPanel">
  <div class="callHeaderCard"><div><div class="listTitle">Connected Call</div><div class="listSub">${state.call.participants.length} participant${state.call.participants.length===1?"":"s"}</div></div><button class="danger" onclick="leaveCall()">Leave</button></div>
  <div id="callParticipants" class="callParticipants"></div>
  ${(state.call.micPermission==="denied"||state.call.cameraPermission==="denied")?`<div class="callPermissionWarning"><div><b>Device permission blocked</b><span>${state.call.micPermission==="denied"?"Microphone ":""}${state.call.micPermission==="denied"&&state.call.cameraPermission==="denied"?"and ":""}${state.call.cameraPermission==="denied"?"camera ":""}access is blocked. You can still stay in the call.</span></div><button class="ghost" onclick="openCallPermissionHelp('${state.call.micPermission==="denied"?"microphone":"camera"}')">Fix Permission</button></div>`:""}
  <div class="callControls"><button id="callMuteBtn" class="callControlBtn" onclick="toggleCallMute()"></button><button id="callCameraBtn" class="callControlBtn" onclick="toggleCamera()"></button><button id="callScreenBtn" class="callControlBtn" onclick="toggleScreenShare()"></button></div>
  <div class="grid2 callDeviceGrid"><div><div class="label">Microphone</div><select class="field" onchange="changeCallMic(this)"><option value="">Default microphone</option>${devices.mics.map((d,i)=>`<option value="${esc(d.deviceId)}" ${state.call.selectedMic===d.deviceId?"selected":""}>${esc(d.label||`Microphone ${i+1}`)}</option>`).join("")}</select></div><div><div class="label">Camera</div><select class="field" onchange="changeCallCamera(this)"><option value="">Default camera</option>${devices.cameras.map((d,i)=>`<option value="${esc(d.deviceId)}" ${state.call.selectedCamera===d.deviceId?"selected":""}>${esc(d.label||`Camera ${i+1}`)}</option>`).join("")}</select></div></div>
  <div class="callMediaStatus">
   ${state.call.cameraEnabled
     ?`<span class="callMediaLive">● Camera sending</span>`
     :state.call.sharingScreen
       ?`<span class="callMediaLive">● Screen sharing</span>`
       :`<span>Video off</span>`
   }
   <span>${Object.keys(state.call.peers||{}).length} peer connection${Object.keys(state.call.peers||{}).length===1?"":"s"}</span>
  </div>
  <div class="callHint">Microphone: ${state.call.micPermission==="granted"?"Ready":state.call.micPermission}. Camera permission: ${state.call.cameraPermission==="granted"?"Ready":state.call.cameraPermission}. A PC can share its screen to both PC and mobile callers. Sending a screen from a phone depends on whether that phone browser supports screen capture.</div>
 </div>`);renderCallParticipants();updateCallControls();
}
function updateCallControls(){
 const m=document.getElementById("callMuteBtn"),c=document.getElementById("callCameraBtn"),s=document.getElementById("callScreenBtn");
 if(m){
  const hasMic=!!state.call.localStream?.getAudioTracks?.().length;
  if(!hasMic){m.textContent="🎤 Enable Mic";m.classList.add("off")}
  else{m.textContent=state.call.micEnabled?"🎤 Mute":"🔇 Unmute";m.classList.toggle("off",!state.call.micEnabled)}
 }
 if(c){c.textContent=state.call.cameraEnabled?"📷 Camera Off":"📷 Camera On";c.classList.toggle("active",state.call.cameraEnabled)}
 if(s){s.textContent=state.call.sharingScreen?"🖥 Stop Sharing":"🖥 Share Screen";s.classList.toggle("active",state.call.sharingScreen)}
}
function renderCallParticipants(){
 const el=document.getElementById("callParticipants");if(!el)return;const me=Number(state.me.id);const people=[{id:me,username:state.profile.username,avatar:state.profile.avatar,local:true,stream:state.call.videoStream||state.call.localStream}];
 for(const p of state.call.participants||[]){const id=Number(p.id);if(id===me)continue;people.push({...p,local:false,stream:state.call.peers[id]?.stream||null})}
 el.innerHTML=people.map(p=>{
  const videoTracks=p.stream?.getVideoTracks?.()||[];
  const hasVideoTrack=videoTracks.length>0;

  return `<div class="callTile ${hasVideoTrack?"hasVideo":""}">
   <div class="callVideoWrap">
    ${hasVideoTrack
      ?`<video id="callVideo-${p.id}" autoplay playsinline ${p.local?"muted":""}></video>`
      :`<div class="callAvatarFallback"><img src="${avatarSrc(p.avatar)}"><span>${esc(p.username)}</span></div>`
    }
   </div>
   <div class="callTileFooter">
    <span>${esc(p.username)}${p.local?" (You)":""}</span>
    ${p.local&&!state.call.micEnabled?`<span class="pill">Muted</span>`:""}
    ${p.local&&state.call.cameraEnabled?`<span class="pill">Camera</span>`:""}
    ${p.local&&state.call.sharingScreen?`<span class="pill">Sharing Screen</span>`:""}
   </div>
  </div>`;
 }).join("");
 for(const p of people){if(p.stream&&p.stream.getVideoTracks().length){const v=document.getElementById(`callVideo-${p.id}`);if(v){v.srcObject=p.stream;v.play().catch(()=>{})}}if(!p.local&&p.stream){let a=document.getElementById(`callAudio-${p.id}`);if(!a){a=document.createElement("audio");a.id=`callAudio-${p.id}`;a.autoplay=true;a.style.display="none";document.body.appendChild(a)}a.srcObject=p.stream;a.play().catch(()=>{})}}
}
window.addEventListener("beforeunload",()=>{if(state.call.active&&state.call.scopeKey){try{navigator.sendBeacon("/api/calls/leave",new Blob([JSON.stringify({scope_key:state.call.scopeKey})],{type:"application/json"}))}catch(e){}}});

function photoComposerControls(){
 return `<button class="photoSendBtn" type="button" onclick="choosePhoto()" title="Send photo">📷</button>
 <input id="photoInput" type="file" accept="image/jpeg,image/png,image/webp,image/gif" hidden onchange="handlePhotoSelected(this)">`;
}

function choosePhoto(){
 const input=document.getElementById("photoInput");
 if(input)input.click();
}

async function compressPhoto(file){
 if(!file)return null;

 if(file.type==="image/gif"){
   if(file.size>1400000){
     throw new Error("GIF is too large. Maximum is about 1.4 MB.");
   }
   return await fileToDataURL(file);
 }

 const raw=await fileToDataURL(file);
 const img=await new Promise((resolve,reject)=>{
   const i=new Image();
   i.onload=()=>resolve(i);
   i.onerror=()=>reject(new Error("Could not read that image."));
   i.src=raw;
 });

 const maxSide=1400;
 let w=img.width;
 let h=img.height;

 if(Math.max(w,h)>maxSide){
   const scale=maxSide/Math.max(w,h);
   w=Math.round(w*scale);
   h=Math.round(h*scale);
 }

 const canvas=document.createElement("canvas");
 canvas.width=w;
 canvas.height=h;

 const ctx=canvas.getContext("2d");
 ctx.drawImage(img,0,0,w,h);

 let quality=.84;
 let result=canvas.toDataURL("image/jpeg",quality);

 while(result.length>1900000 && quality>.48){
   quality-=.08;
   result=canvas.toDataURL("image/jpeg",quality);
 }

 if(result.length>2200000){
   throw new Error("Photo is still too large after compression.");
 }

 return result;
}

function fileToDataURL(file){
 return new Promise((resolve,reject)=>{
   const reader=new FileReader();
   reader.onload=()=>resolve(reader.result);
   reader.onerror=()=>reject(new Error("Could not read that file."));
   reader.readAsDataURL(file);
 });
}

async function handlePhotoSelected(input){
 const file=input?.files?.[0];
 if(!file)return;

 try{
   state.pendingImage=await compressPhoto(file);
   renderPhotoPreview();
   toast("Photo ready to send");
 }catch(e){
   state.pendingImage=null;
   toast(e.message);
 }

 input.value="";
}

function clearPendingPhoto(){
 state.pendingImage=null;
 renderPhotoPreview();
}

function renderPhotoPreview(){
 let preview=document.getElementById("pendingPhotoPreview");

 if(!state.pendingImage){
   if(preview)preview.remove();
   return;
 }

 const composer=document.querySelector(".composer");
 if(!composer)return;

 if(!preview){
   preview=document.createElement("div");
   preview.id="pendingPhotoPreview";
   preview.className="pendingPhotoPreview";
   composer.parentNode.insertBefore(preview,composer);
 }

 preview.innerHTML=`
   <img src="${state.pendingImage}" alt="Photo ready to send">
   <div class="listMain">
     <div class="listTitle">Photo ready</div>
     <div class="listSub">It will be sent with your message.</div>
   </div>
   <button class="roundBtn" type="button" onclick="clearPendingPhoto()">×</button>
 `;
}

function renderMessagePhoto(m){
 if(!m.image_data)return "";
 return `<button class="messagePhotoButton" onclick="openMessagePhoto(${m.id})">
   <img class="messagePhoto" src="${m.image_data}" alt="Photo from ${esc(m.username)}">
 </button>`;
}

function openMessagePhoto(mid){
 const m=(state.messages||[]).find(x=>Number(x.id)===Number(mid));
 if(!m?.image_data)return;

 modalOpen("Photo",`
   <div class="photoViewer">
     <img src="${m.image_data}" alt="Message photo">
   </div>
 `);
}

function messageMenuFromButton(ev,mid){
 ev.preventDefault();
 ev.stopPropagation();

 const r=ev.currentTarget.getBoundingClientRect();
 messageMenu({
   preventDefault(){},
   stopPropagation(){},
   clientX:Math.max(8,r.right-210),
   clientY:Math.min(innerHeight-20,r.bottom+4)
 },mid);
}

function memberMenuFromButton(ev,id,isBot){
 ev.preventDefault();
 ev.stopPropagation();

 const r=ev.currentTarget.getBoundingClientRect();
 const fake={
   preventDefault(){},
   stopPropagation(){},
   clientX:Math.max(8,r.right-220),
   clientY:Math.min(innerHeight-20,r.bottom+4)
 };

 if(isBot){
   serverBotMemberMenu(fake,id);
 }else{
   serverMemberMenu(fake,id);
 }
}


async function sendMessage(){
 if(state.sendingMessage)return;

 const inp=document.getElementById("messageInput");
 if(!inp)return;

 const content=inp.value.trim();
 const pendingImage=state.pendingImage;

 if(!content&&!pendingImage)return;

 const b={
   content,
   image_data:pendingImage||"",
   reply_to_id:state.replyingTo?.id||null
 };

 if(state.view==="public"){
   b.kind="public";b.channel=state.channel;
 }else if(state.view==="server"){
   b.kind="server";b.channel=state.channel;b.server_id=state.activeServer;
 }else{
   b.kind="dm";b.chat_id=state.activeChat;
 }

 // Clear immediately so the interface feels instant.
 inp.value="";
 const originalReply=state.replyingTo;
 const originalImage=pendingImage;
 state.replyingTo=null;
 state.pendingImage=null;
 renderReplyBar();
 renderPhotoPreview();

 const tempId=-Date.now();
 const optimistic={
   id:tempId,
   user_id:state.profile.id,
   content,
   image_data:originalImage||"",
   created_at:new Date().toISOString(),
   edited_at:null,
   username:state.profile.username,
   avatar:state.profile.avatar,
   role:state.profile.global_role,
   is_spookhook:false,
   reactions:[],
   embed_url:"",
   embed_allowed:false,
   reply:originalReply?{
     id:originalReply.id,
     username:originalReply.username,
     content:originalReply.content.slice(0,180)
   }:null,
   _optimistic:true
 };

 state.messages=[...(state.messages||[]),optimistic];
 window._lastMessages=state.messages;
 state.lastMessageSignature="";
 drawMessages();

 try{
   state.sendingMessage=true;
   await api("/api/messages",{
     method:"POST",
     body:JSON.stringify(b)
   });

   // Replace optimistic message with authoritative DB version.
   await loadMessages(true);

 }catch(e){
   state.messages=(state.messages||[]).filter(m=>m.id!==tempId);
   window._lastMessages=state.messages;
   drawMessages();
   inp.value=content;
   state.replyingTo=originalReply;
   state.pendingImage=originalImage;
   renderReplyBar();
   renderPhotoPreview();
   toast(e.message);
 }finally{
   state.sendingMessage=false;
   inp.focus();
 }
}

const REACTION_CHOICES=["👍","❤️","😂","🔥","🎉","👻","💜","✅","❌"];

function renderReactions(m){
 const current=(m.reactions||[]).map(r=>`<button class="reactionChip ${r.mine?"mine":""}" onclick="toggleReaction(${m.id},'${r.emoji}')">${r.emoji}<span>${r.count}</span></button>`).join("");
 return `<div class="reactionRow">${current}<button class="reactionAdd" onclick="showReactionPicker(${m.id})">＋</button></div>`;
}

function renderLinkEmbed(m){
 if(!m.embed_url||!m.embed_allowed)return "";
 try{
   const u=new URL(m.embed_url);
   return `<a class="linkEmbed" href="${esc(m.embed_url)}" target="_blank" rel="noopener noreferrer"><div class="linkEmbedHost">${esc(u.hostname)}</div><div class="linkEmbedUrl">${esc(m.embed_url)}</div></a>`;
 }catch(e){
   return "";
 }
}

function showReactionPicker(mid){
 modalOpen("React to message",`<div class="reactionPicker">${REACTION_CHOICES.map(e=>`<button onclick="toggleReaction(${mid},'${e}');modalClose()">${e}</button>`).join("")}</div>`);
}

async function toggleReaction(mid,emoji){
 try{
   await api(`/api/messages/${mid}/reaction`,{
     method:"POST",
     body:JSON.stringify({emoji})
   });

   await loadMessages(true);

 }catch(e){
   toast(e.message);
 }
}



function startReply(mid){
 const m=(window._lastMessages||state.messages||[]).find(x=>Number(x.id)===Number(mid));
 if(!m){toast("Could not find that message to reply to");return;}
 state.replyingTo={id:Number(m.id),username:m.username,content:m.content};
 renderReplyBar();
 toast(`Replying to ${m.username}`);
 const input=document.getElementById("messageInput");
 if(input)input.focus();
}
function cancelReply(){
 state.replyingTo=null;
 renderReplyBar();
}
function renderReplyBar(){
 const old=document.getElementById("replyBar");
 if(old)old.remove();
 if(!state.replyingTo)return;
 const composer=document.querySelector(".composer");
 if(!composer)return;
 const bar=document.createElement("div");
 bar.id="replyBar";
 bar.className="replyBar";
 bar.innerHTML=`<div class="replyBarText"><b>Replying to ${esc(state.replyingTo.username)}</b><span>${esc(state.replyingTo.content.slice(0,120))}</span></div><button type="button" class="roundBtn" onclick="cancelReply()">×</button>`;
 composer.parentNode.insertBefore(bar,composer);
}
function scrollToMessage(mid){
 const el=document.getElementById("message-"+mid);
 if(!el)return;
 el.scrollIntoView({behavior:"smooth",block:"center"});
 el.classList.add("replyFlash");
 setTimeout(()=>el.classList.remove("replyFlash"),1200);
}


async function copyText(text){
 const value=String(text??"");
 try{
   if(navigator.clipboard && window.isSecureContext){
     await navigator.clipboard.writeText(value);
     return true;
   }
 }catch(e){}

 try{
   const ta=document.createElement("textarea");
   ta.value=value;
   ta.setAttribute("readonly","");
   ta.style.position="fixed";
   ta.style.opacity="0";
   ta.style.pointerEvents="none";
   document.body.appendChild(ta);
   ta.focus();
   ta.select();
   const ok=document.execCommand("copy");
   ta.remove();
   return !!ok;
 }catch(e){
   return false;
 }
}

async function copyMessage(mid){
 const m=(state.messages||[]).find(x=>Number(x.id)===Number(mid));
 if(!m){toast("Message not found");return;}
 const ok=await copyText(m.content);
 toast(ok?"Message copied":"Copy failed");
 closeContext();
}


let _holdTimer=null;
let _holdStartX=0;
let _holdStartY=0;

function clearMobileHold(){
 if(_holdTimer){
   clearTimeout(_holdTimer);
   _holdTimer=null;
 }
}

function attachMobileHoldMenus(){
 if(window.innerWidth>720)return;

 document.querySelectorAll(".msg").forEach(el=>{
   if(el.dataset.holdAttached==="1")return;
   el.dataset.holdAttached="1";

   el.addEventListener("touchstart",ev=>{
     if(ev.touches.length!==1)return;

     const touch=ev.touches[0];
     _holdStartX=touch.clientX;
     _holdStartY=touch.clientY;

     const id=Number((el.id||"").replace("message-",""));
     if(!id)return;

     clearMobileHold();

     _holdTimer=setTimeout(()=>{
       _holdTimer=null;

       const fakeEvent={
         preventDefault(){},
         stopPropagation(){},
         clientX:_holdStartX,
         clientY:_holdStartY
       };

       messageMenu(fakeEvent,id);

       if(navigator.vibrate){
         navigator.vibrate(25);
       }
     },520);
   },{passive:true});

   el.addEventListener("touchmove",ev=>{
     if(!_holdTimer||!ev.touches.length)return;

     const touch=ev.touches[0];

     if(
       Math.abs(touch.clientX-_holdStartX)>12 ||
       Math.abs(touch.clientY-_holdStartY)>12
     ){
       clearMobileHold();
     }
   },{passive:true});

   el.addEventListener("touchend",clearMobileHold,{passive:true});
   el.addEventListener("touchcancel",clearMobileHold,{passive:true});
 });

 document.querySelectorAll(".memberRow").forEach(el=>{
   if(el.dataset.holdAttached==="1")return;
   el.dataset.holdAttached="1";

   el.addEventListener("touchstart",ev=>{
     if(ev.touches.length!==1)return;

     const touch=ev.touches[0];
     _holdStartX=touch.clientX;
     _holdStartY=touch.clientY;

     const id=Number(el.dataset.memberId);
     const isBot=el.dataset.isBot==="1";

     if(!id)return;

     clearMobileHold();

     _holdTimer=setTimeout(()=>{
       _holdTimer=null;

       const fakeEvent={
         preventDefault(){},
         stopPropagation(){},
         clientX:_holdStartX,
         clientY:_holdStartY
       };

       if(isBot){
         serverBotMemberMenu(fakeEvent,id);
       }else{
         serverMemberMenu(fakeEvent,id);
       }

       if(navigator.vibrate){
         navigator.vibrate(25);
       }
     },520);
   },{passive:true});

   el.addEventListener("touchmove",ev=>{
     if(!_holdTimer||!ev.touches.length)return;

     const touch=ev.touches[0];

     if(
       Math.abs(touch.clientX-_holdStartX)>12 ||
       Math.abs(touch.clientY-_holdStartY)>12
     ){
       clearMobileHold();
     }
   },{passive:true});

   el.addEventListener("touchend",clearMobileHold,{passive:true});
   el.addEventListener("touchcancel",clearMobileHold,{passive:true});
 });
}

function messageMenu(ev,id){
 ev.preventDefault();ev.stopPropagation();
 const m=state.messages.find(x=>x.id===id);if(!m)return;
 const mine=!m.is_bot&&Number(m.user_id)===Number(state.me.id);
 const globalStaff=["moderator","admin","owner"].includes(state.profile.global_role);
 const serverStaff=state.view==="server"&&state.serverInfo&&["moderator","admin","owner"].includes(state.serverInfo.my_role);
 const canDelete=mine||globalStaff||serverStaff;
 overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-220)}px;top:${Math.min(ev.clientY,innerHeight-260)}px" onclick="event.stopPropagation()">
 <button onclick="startReply(${m.id});closeContext()">↩ Reply</button><button onclick="viewProfile(${m.user_id});closeContext()">👤 View profile</button>
 <button onclick="copyMessage(${m.id})">📋 Copy message</button>
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
   const profileUrl="/api/profile/"+uid+(state.view==="server"&&state.activeServer?`?server_id=${state.activeServer}`:"");
   const d=await api(profileUrl);
   const p=d.profile;

   modalOpen(
     "User profile",
     `<div class="row">
       <img
         class="avatar"
         style="width:72px;height:72px"
         src="${avatarSrc(p.avatar)}"
         onerror="this.style.visibility='hidden'"
       >
       <div>
         <h2 style="margin:0">${esc(p.username)}</h2>
         <div class="presenceLine">
           ${presenceDot(p)}
           <span>${esc(presenceText(p))}</span>
         </div>
         <div style="margin-top:6px">
           <span class="pill">${esc(p.global_role)}</span>
           <span class="pill">${p.device_type==="Mobile"?"📱 Mobile":"🖥 PC"}</span>
         </div>
       </div>
     </div>

     <div class="card" style="margin-top:14px">
       <div class="listSub">Vyntra ID: #${p.id}</div>${p.friend_status==="friends"?`<div class="profileFriendStatus">Friends</div>`:""}
       ${p.server_role?`<div class="profileRoleSection"><div class="label">Server Roles</div><div class="profileRoleBadges"><span class="pill">${esc(p.server_role)}</span>${(p.server_roles||[]).map(r=>`<span class="pill">${esc(r.name)}</span>`).join("")}</div></div>`:""}
       <div class="muted" style="margin-top:8px">${esc(p.pronouns||"No pronouns set")}</div>
       <p>${esc(p.description||"No description.")}</p>
       <div class="muted">${esc(p.company||"")}</div>
     </div>

     ${Number(uid)!==Number(state.me.id)
       ?`<div class="modalActions">
          ${
            p.friend_status==="friends"
              ?`<button class="ghost" disabled>Friends</button>`
              :`<button class="primary" onclick="addFriend(${uid});modalClose()">Add Friend</button>`
          }
          <button class="ghost" onclick="startDM(${uid});modalClose()">Message</button>
        </div>`
       :""
     }`
   );

 }catch(e){
   toast(e.message);
 }
}

async function showFriendsPage(){state.view="friends";state.activeServer=null;renderApp()}
async function renderFriendsPage(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Friends</div><div class="topSub">Find people and manage conversations</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page"><div class="pageHero"><div><h1>Your friends</h1><div class="muted">Search VYNTRA by username or open a DM.</div></div><button class="primary" onclick="groupCreate()">＋ New group chat</button></div>
 <div class="card"><h3>Find people</h3><div class="searchBox"><input id="userSearchInput" placeholder="Search username or Vyntra ID (#123)..." onkeydown="if(event.key==='Enter')searchUsers()"><button class="primary" onclick="searchUsers()">Search</button></div><div id="userSearchResults"></div></div>
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
async function startDM(uid){
 try{
   const d=await api("/api/dms",{
     method:"POST",
     body:JSON.stringify({user_id:uid})
   });

   state.view="dm";
   state.activeChat=d.chat_id;
   state.activeServer=null;
   state.lastMessageSignature="";
   state.messageLoadSeq++;

   await renderDM(d.chat_id);
 }catch(e){
   toast(e.message);
 }
}
function drawChats(list){chatList.innerHTML=list.length?list.map(c=>{const uc=unreadCountFor("dm",c.id);return `<button class="sideBtn ${unreadClass(uc)}" data-unread-scope="dm" data-chat-id="${c.id}" onclick="openChat(${c.id})">${unreadDot(uc)}<span class="iconBox">${c.kind==="group"?"👥":"💬"}</span><span class="navLabel">${esc(c.display_name)}</span>${badgeHtml(uc)}</button>`}).join(""):`<div class="muted">No DMs or groups yet.</div>`}
async function openChat(id){
 clearUnreadLocal("dm",id);
 state.view="dm";
 state.activeChat=id;
 state.activeServer=null;
 state.lastMessageSignature="";
 state.messageLoadSeq++;
 await renderDM(id);
}
async function renderDM(id){
 clearInterval(state.poll);
 root.innerHTML=`<div id="appShell" class="app">${sidebar()}<main class="main"><div id="mainArea" style="height:100%;display:flex;flex-direction:column"></div></main><aside id="membersPane" class="membersPane"></aside></div>${mobilebar()}`;
 let info=await api("/api/chats/"+id);
 await markChatNotificationsRead(id);
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">${esc(info.chat.display_name)}</div><div class="topSub">${info.chat.kind==="group"?"Group chat":"Direct message"}</div></div><div class="topActions">${inCallStatusButton()}${callButton()}${notificationBellButton()}</div></header><div class="content"><div id="messageList" class="messages"></div></div><div class="composer">${photoComposerControls()}<input id="messageInput" maxlength="4000" placeholder="Message..." onkeydown="if(event.key==='Enter'){event.preventDefault();sendMessage()}"><button class="primary" onclick="sendMessage()">Send</button></div>`;
 loadMessages(true);attachTypingListener();renderPhotoPreview();state.poll=setInterval(loadMessages,2000);
}
function groupCreate(){modalOpen("Create group chat",`<form class="formGrid" onsubmit="makeGroup(event)"><div class="label">Group name</div><input id="groupName" class="field" maxlength="50" required><div class="label">Add usernames</div><input id="groupUsers" class="field" placeholder="alex, sam, jordan"><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Create</button></div></form>`)}
async function makeGroup(e){e.preventDefault();try{const d=await api("/api/groups",{method:"POST",body:JSON.stringify({name:groupName.value,usernames:groupUsers.value.split(",").map(x=>x.trim()).filter(Boolean)})});modalClose();openChat(d.chat_id)}catch(e){toast(e.message)}}


function showServerDiscovery(){state.view="discover";state.activeServer=null;state.serverInfo=null;renderApp()}
async function renderServerDiscovery(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Discover Servers</div><div class="topSub">Browse and join VYNTRA communities</div></div><div class="topActions"><button class="primary" onclick="serverCreate()">＋ Create Server</button></div></header>
 <div class="page"><div class="pageHero"><div><h1>Server Discovery</h1><div class="muted">Every public VYNTRA server appears here. Search by name and join instantly.</div></div></div>
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
   if(state.view==="discover")await loadServerDiscovery();
 }catch(e){toast(e.message)}
}

function serverCreate(){modalOpen("Create server",`<form class="formGrid" onsubmit="makeServer(event)"><div class="label">Server name</div><input id="newServerName" class="field" maxlength="60" required><div class="label">Server picture URL (optional)</div><input id="newServerIcon" class="field" maxlength="500"><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Create server</button></div></form>`)}
async function makeServer(e){e.preventDefault();try{await api("/api/servers",{method:"POST",body:JSON.stringify({name:newServerName.value,icon:newServerIcon.value})});modalClose();state.servers=(await api("/api/servers")).servers;renderApp()}catch(e){toast(e.message)}}
async function openServer(id,ch=null){
 const wantedServer=Number(id);

 // Change navigation immediately, but don't render an empty/wrong server.
 state.view="server";
 state.activeServer=wantedServer;
 state.lastMessageSignature="";
 state.messageLoadSeq++;

 try{
   const d=await api(`/api/servers/${wantedServer}/bootstrap`);

   // Ignore an old response if the user navigated elsewhere while loading.
   if(state.view!=="server"||state.activeServer!==wantedServer)return;

   state.serverInfo=d.server;
   state.serverMembers=d.members||[];
   state.serverChannels=d.channels||[];
   state.serverRoles=d.roles||[];

   if(ch && !Number.isNaN(Number(ch))){
     state.channel=Number(ch);
   }else if(ch){
     const found=state.serverChannels.find(c=>
       c.name===ch||
       c.name===String(ch).replace("announcement","announcements")
     );
     state.channel=found?found.id:(state.serverChannels[0]?.id||null);
   }else if(!state.serverChannels.some(c=>Number(c.id)===Number(state.channel))){
     state.channel=state.serverChannels[0]?.id||null;
   }

   if(state.channel){
     state.serverMembers=(state.serverMembers||[]).filter(m=>
       !Array.isArray(m.visible_channel_ids) ||
       m.visible_channel_ids.includes(Number(state.channel))
     );
   }

   if(state.channel){
     clearUnreadLocal("server-channel",wantedServer,state.channel);
   }

   state.lastMessageSignature="";
   renderApp();

 }catch(e){
   if(state.view==="server"&&state.activeServer===wantedServer){
     toast(e.message);
   }
 }
}


function openMobileRoleManager(){
 if(state.view!=="server"||!state.activeServer)return;

 const sid=state.activeServer;

 modalOpen("Server Roles",`
   <div class="row between" style="margin-bottom:12px">
     <div>
       <div class="listTitle">Roles</div>
       <div class="listSub">Create roles, edit permissions, or remove roles.</div>
     </div>
     ${hasServerPerm("manage_roles")?`<button class="primary" onclick="modalClose();createCustomRole(${sid})">＋ Role</button>`:""}
   </div>

   <div class="formGrid">
     ${(state.serverRoles||[]).length
       ?state.serverRoles.map(r=>`
         <div class="listItem">
           <div class="listMain">
             <div class="listTitle">${esc(r.name)}</div>
             <div class="listSub">${Object.entries(r.permissions||{}).filter(([k,v])=>v).length} enabled permissions</div>
           </div>
           ${hasServerPerm("manage_roles")?`
             <button class="ghost" onclick="modalClose();editCustomRole(${sid},${r.id})">Edit</button>
             <button class="danger" onclick="deleteCustomRole(${sid},${r.id})">Delete</button>
           `:""}
         </div>`).join("")
       :`<div class="muted">No custom roles yet.</div>`
     }
   </div>
 `);
}

function openMobileCurrentChannelSettings(){
 if(state.view!=="server"||!state.channel)return;

 if(!hasServerPerm("manage_channels")){
   toast("Manage Channels permission required");
   return;
 }

 channelSettings(Number(state.channel));
}

function openMobileServerTools(){
 if(state.view!=="server"||!state.activeServer)return;

 const s=state.serverInfo;
 const canChannels=hasServerPerm("manage_channels");
 const canRoles=hasServerPerm("manage_roles");
 const canServer=hasServerPerm("manage_server")||s?.my_role==="owner";
 const canInvite=hasServerPerm("invite_members");
 const canBan=hasServerPerm("ban_members");

 modalOpen("Server Tools",`
   <div class="mobileServerToolGrid">
     <button class="mobileServerTool" onclick="modalClose();showMobileMembers()">
       <b>Members</b>
       <span>Members, bots, roles, moderation</span>
     </button>

     ${canChannels?`
       <button class="mobileServerTool" onclick="modalClose();createChannelPrompt()">
         <b>Create Channel</b>
         <span>Add chat or announcement channels</span>
       </button>

       <button class="mobileServerTool" onclick="modalClose();openMobileCurrentChannelSettings()">
         <b>Edit Channel</b>
         <span>Name and channel role permissions</span>
       </button>
     `:""}

     ${canRoles?`
       <button class="mobileServerTool" onclick="modalClose();openMobileRoleManager()">
         <b>Roles</b>
         <span>Create roles and edit permissions</span>
       </button>
     `:""}

     ${canInvite?`
       <button class="mobileServerTool" onclick="modalClose();showServerInvite(${s.id})">
         <b>Invites</b>
         <span>Create and copy server invite links</span>
       </button>
     `:""}

     ${canBan?`
       <button class="mobileServerTool" onclick="modalClose();showServerSettings(${s.id})">
         <b>Bans & Requests</b>
         <span>Unban users and review join requests</span>
       </button>
     `:""}

     ${canServer?`
       <button class="mobileServerTool mobileServerToolWide" onclick="modalClose();showServerSettings(${s.id})">
         <b>Server Settings</b>
         <span>Name, picture, privacy, roles, bots, members, bans and join requests</span>
       </button>
     `:""}
   </div>
 `);
}

function showMobileServerActions(){
 const s=state.serverInfo;
 if(!s)return;

 modalOpen(s.name,`
   <div class="formGrid">
     <button class="primary" onclick="modalClose();openMobileServerTools()">⚙ Server Tools</button>

     ${hasServerPerm("manage_channels")?`
       <button class="ghost" onclick="modalClose();createChannelPrompt()">＋ Create Channel</button>
       <button class="ghost" onclick="modalClose();openMobileCurrentChannelSettings()">✎ Edit Current Channel</button>
     `:""}

     ${hasServerPerm("manage_roles")?`
       <button class="ghost" onclick="modalClose();openMobileRoleManager()">🏷 Roles & Permissions</button>
     `:""}

     ${hasServerPerm("invite_members")?`
       <button class="ghost" onclick="modalClose();showServerInvite(${s.id})">🔗 Invite People</button>
     `:""}

     ${hasServerPerm("manage_server")||s.my_role==="owner"?`
       <button class="ghost" onclick="modalClose();showServerSettings(${s.id})">⚙ Full Server Settings</button>
     `:""}

     <button class="ghost" onclick="modalClose();showMobileMembers()">👥 Members · ${s.member_count}</button>
     <button class="ghost" onclick="modalClose();showNotifications()">🔔 Notifications</button>
   </div>
 `);
}
function showMobileMembers(){
 const rows=(state.serverMembers||[]).map(m=>`<div class="listItem memberRow mobileHoldTarget" data-member-id="${m.is_bot?m.bot_id:m.id}" data-is-bot="${m.is_bot?1:0}"><img class="avatar" src="${avatarSrc(m.avatar)}"><div class="listMain"><div class="listTitle">${esc(m.username)} ${m.is_bot?`<span class="roleTag">BOT</span>`:""}</div><div class="listSub">${m.is_bot?(m.role==="admin"?"Administrator Bot":"Bot"):`${m.online?"Online":relativeLastSeen(m.last_seen)} · ${esc(m.role)}${(m.custom_roles||[]).length?` · ${(m.custom_roles||[]).map(r=>esc(r.name)).join(", ")}`:""} · ${m.device_type==="Mobile"?"Mobile":"PC"}${m.muted?" · restricted":""}${m.banned?" · banned":""}`}</div></div><button class="mobileContextBtn memberContextBtn mobileSheetMenu"
 onclick="memberMenuFromButton(event,${m.is_bot?m.bot_id:m.id},${m.is_bot?"true":"false"})">•••</button></div>`).join("");
 modalOpen(`Members · ${state.serverMembers.length}`,rows||`<div class="muted">No members.</div>`);
 setTimeout(attachMobileHoldMenus,30);
}

function renderServer(){
 clearInterval(state.poll);
 const s=state.serverInfo; if(!s){openPublic("chat1");return}
 if(window.innerWidth>1000)appShell.classList.add("with-members");else appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">${esc(s.name)}</div><div class="topSub">${s.member_count} member${s.member_count===1?"":"s"}</div></div><div class="topActions serverDesktopActions">${inCallStatusButton()}${callButton()}${notificationBellButton()}${hasServerPerm("invite_members")?`<button class="ghost" onclick="showServerInvite(${s.id})">🔗 Invite</button>`:""}${hasServerPerm("manage_server")||s.my_role==="owner"?`<button class="ghost" onclick="showServerSettings(${s.id})">⚙ Settings</button>`:""}<button class="ghost" onclick="toggleMembers()">👥 Members</button></div><button class="roundBtn serverMobileMenu" onclick="showMobileServerActions()">•••</button></header>
 <div class="mobileServerQuickBar">
   <button class="mobileCallQuick" onclick="${state.call.active?"openCallPanel()":"startCall()"}">${state.call.active?"Open Call":"Call"}</button>
   <button onclick="showMobileMembers()">Members</button>
   ${hasServerPerm("manage_channels")?`<button onclick="createChannelPrompt()">＋ Channel</button>`:""}
   ${hasServerPerm("manage_channels")?`<button onclick="openMobileCurrentChannelSettings()">Edit Channel</button>`:""}
   ${hasServerPerm("manage_roles")?`<button onclick="openMobileRoleManager()">Roles</button>`:""}
   ${hasServerPerm("manage_server")||s.my_role==="owner"?`<button onclick="showServerSettings(${s.id})">Settings</button>`:""}
 </div>
 <div class="serverWorkspace">
   <div class="serverChannelRail">
     <div class="sectionTitle serverChannelTitle"><span>Channels</span>${hasServerPerm("manage_channels")?`<button class="roundBtn" style="width:25px;height:25px" onclick="createChannelPrompt()">＋</button>`:""}</div>
     <div class="serverChannelButtons">
       ${state.serverChannels.map(c=>`<div class="mobileChannelWrap"><button class="channelBtn ${Number(state.channel)===Number(c.id)?"active":""}${unreadClass(unreadCountFor("server-channel",s.id,c.id))}" data-unread-scope="server-channel" data-server-id="${s.id}" data-channel="${c.id}" onclick="openServer(${s.id},${c.id})" oncontextmenu="channelMenu(event,${c.id})">${unreadDot(unreadCountFor("server-channel",s.id,c.id))}<span class="channelLabel">${c.kind==="announcement"?"📢":"#"} ${esc(c.name)}</span>${badgeHtml(unreadCountFor("server-channel",s.id,c.id))}</button>${hasServerPerm("manage_channels")?`<button class="mobileChannelEditBtn" onclick="event.stopPropagation();channelSettings(${c.id})" title="Edit channel">⚙</button>`:""}</div>`).join("")||'<div class="muted" style="padding:10px">No visible channels</div>'}
     </div>
   </div>
   <div class="serverConversation">
     <div class="content"><div id="messageList" class="messages"></div></div>
     <div class="composer">${photoComposerControls()}<input id="messageInput" maxlength="4000" placeholder="Message channel..." onkeydown="if(event.key==='Enter'){event.preventDefault();sendMessage()}"><button class="primary" onclick="sendMessage()">Send</button></div>
   </div>
 </div>`;
 renderMembers();
 loadMessages(true);
 attachTypingListener();
 renderPhotoPreview();
 state.poll=setInterval(loadMessages,2200);
 state.memberPoll=setInterval(refreshActiveServerMembers,15000);
}

async function refreshActiveServerMembers(){
 if(state.view!=="server"||!state.activeServer)return;

 const sid=state.activeServer;
 try{
   const d=await api(`/api/servers/${sid}/members?channel_id=${encodeURIComponent(state.channel||"")}`);

   if(state.view!=="server"||state.activeServer!==sid)return;

   state.serverMembers=d.members||[];
   renderMembers();

 }catch(e){}
}

function renderMembers(){
 const p=document.getElementById("membersPane");if(!p)return;

 const list=(state.serverMembers||[]).filter(m=>
   !Array.isArray(m.visible_channel_ids) ||
   m.visible_channel_ids.includes(Number(state.channel))
 );

 p.innerHTML=`<div class="memberHead">Members · ${list.length}</div><div style="padding-top:8px">${list.map(m=>`
   <div class="memberRow mobileHoldTarget"
     data-member-id="${m.id}"
     data-is-bot="${m.is_bot?1:0}"
     oncontextmenu="${m.is_bot?`serverBotMemberMenu(event,${m.bot_id})`:`serverMemberMenu(event,${m.id})`}">
     <img class="avatar ${m.is_bot?"botMemberAvatar":""}" src="${avatarSrc(m.avatar)}" onerror="this.style.visibility='hidden'">
     <div class="memberInfo">
       <div class="memberName">${esc(m.username)} ${m.is_bot?`<span class="roleTag">BOT</span>`:""}</div>
       <div class="memberRole">
         ${m.is_bot
           ?`${m.role==="admin"?"Administrator Bot":"Bot"}`
           :`${m.online?"● Online":relativeLastSeen(m.last_seen)} · ${esc(m.role)}${(m.custom_roles||[]).length?` · ${(m.custom_roles||[]).map(r=>esc(r.name)).join(", ")}`:""} · ${m.device_type==="Mobile"?"📱":"🖥"}${m.muted?" · muted":""}${m.banned?" · banned":""}`
         }
       </div>
     </div>
     <button class="mobileContextBtn memberContextBtn"
       onclick="memberMenuFromButton(event,${m.is_bot?m.bot_id:m.id},${m.is_bot?"true":"false"})"
       aria-label="Member menu">•••</button>
   </div>`).join("")}</div>`;

 attachMobileHoldMenus();
}
function toggleMembers(){appShell.classList.toggle("with-members")}
function serverMemberMenu(ev,uid){
 ev.preventDefault();ev.stopPropagation();

 const m=(state.serverMembers||[]).find(x=>!x.is_bot&&Number(x.id)===Number(uid));
 if(!m)return;

 const my=state.serverInfo.my_role;
 const canBuiltIn=my==="owner"&&m.role!=="owner";
 const canRoles=hasServerPerm("manage_roles")&&m.role!=="owner";
 const canMute=(hasServerPerm("mute_members")||["owner","admin","moderator"].includes(my))&&m.role!=="owner";
 const canBan=(hasServerPerm("ban_members")||["owner","admin"].includes(my))&&m.role!=="owner";

 overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-230)}px;top:${Math.min(ev.clientY,innerHeight-330)}px" onclick="event.stopPropagation()">
 <button onclick="viewProfile(${uid});closeContext()">👤 View profile</button>
 ${canRoles?`<button onclick="manageMemberCustomRoles(${state.activeServer},${uid});closeContext()">🏷 Add / Remove Roles</button>`:""}
 ${canMute?`<button onclick="serverAction(${uid},'${m.muted?"unmute":"mute"}');closeContext()">🔇 ${m.muted?"Unrestrict":"Restrict from talking"}</button>`:""}
 ${canBan?`<button class="red" onclick="serverAction(${uid},'${m.banned?"unban":"ban"}');closeContext()">⛔ ${m.banned?"Unban":"Ban from server"}</button>`:""}
 ${canBuiltIn?`<button onclick="changeServerRole(${uid});closeContext()">🛡 Change Staff Role</button>`:""}
 </div>`;
}

function serverBotMemberMenu(ev,bid){
 ev.preventDefault();ev.stopPropagation();

 const b=(state.serverMembers||[]).find(x=>x.is_bot&&Number(x.bot_id)===Number(bid));
 if(!b)return;

 const canEdit=["admin","owner"].includes(state.serverInfo?.my_role) || hasServerPerm("administrator");

 overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-235)}px;top:${Math.min(ev.clientY,innerHeight-260)}px" onclick="event.stopPropagation()">
   <button onclick="viewBotServerInfo(${bid});closeContext()">🤖 View Bot</button>
   ${canEdit?`<button onclick="editInstalledBotPermissions(${bid});closeContext()">⚙ Edit Permissions</button>`:""}
   ${canEdit?`<button class="red" onclick="removeServerBot(${state.activeServer},${bid});closeContext()">🗑 Remove Bot</button>`:""}
 </div>`;
}

function viewBotServerInfo(bid){
 const b=(state.serverMembers||[]).find(x=>x.is_bot&&Number(x.bot_id)===Number(bid));
 if(!b)return;

 modalOpen("Bot Profile",`
   <div class="row">
     <img class="avatar" style="width:72px;height:72px" src="${avatarSrc(b.avatar)}">
     <div>
       <h2 style="margin:0">${esc(b.username)} <span class="roleTag">BOT</span></h2>
       <div class="muted">${b.role==="admin"?"Administrator Bot":"Vyntra Bot"}</div>
     </div>
   </div>
   <div class="card" style="margin-top:14px">
     <h3>Server Permissions</h3>
     <div class="botPermSummary">${(b.bot_permissions||[]).map(p=>`<span class="pill">${esc(BOT_PERMISSION_LABELS[p]?.[0]||p)}</span>`).join("")||'<span class="muted">No permissions.</span>'}</div>
   </div>`);
}

async function editInstalledBotPermissions(bid){
 try{
   const d=await api(`/api/servers/${state.activeServer}/bots/${bid}/permissions`);
   const selected=d.bot.permissions||[];

   modalOpen("Edit Bot Permissions",`
     <div class="row">
       <img class="avatar" src="${avatarSrc(d.bot.avatar)}">
       <div>
         <div class="listTitle">${esc(d.bot.name)} <span class="roleTag">BOT</span></div>
         <div class="listSub">Permissions apply only in this server.</div>
       </div>
     </div>
     <div class="card" style="margin-top:12px">
       ${botInstallPermissionChecks(selected)}
     </div>
     <div class="modalActions">
       <button class="ghost" onclick="modalClose()">Cancel</button>
       <button class="primary" onclick="saveInstalledBotPermissions(${bid})">Save Permissions</button>
     </div>`);
 }catch(e){toast(e.message)}
}

function botInstallPermissionChecks(selected=[]){
 const have=new Set(selected||[]);

 return Object.entries(BOT_PERMISSION_LABELS).map(([key,[name,desc]])=>`
   <label class="listItem botPermissionRow ${key==="administrator"?"botAdminPermission":""}" style="cursor:pointer">
     <input type="checkbox" data-installbotperm="${key}" ${have.has(key)?"checked":""} onchange="installedBotAdminChanged(this)">
     <div class="listMain">
       <div class="listTitle">${name}${key==="administrator"?` <span class="roleTag">ADMIN ROLE</span>`:""}</div>
       <div class="listSub">${desc}</div>
     </div>
   </label>`).join("");
}

function installedBotAdminChanged(el){
 if(el.dataset.installbotperm!=="administrator")return;

 document.querySelectorAll("[data-installbotperm]").forEach(box=>{
   if(box!==el){
     box.checked=el.checked;
     box.disabled=el.checked;
   }
 });
}

async function saveInstalledBotPermissions(bid){
 const checked=[...document.querySelectorAll("[data-installbotperm]:checked")].map(x=>x.dataset.installbotperm);
 const perms=checked.includes("administrator")?["administrator"]:checked;

 try{
   await api(`/api/servers/${state.activeServer}/bots/${bid}`,{
     method:"PATCH",
     body:JSON.stringify({permissions:perms})
   });

   modalClose();
   toast("Bot permissions updated");
   await openServer(state.activeServer,state.channel);

 }catch(e){
   toast(e.message);
 }
}

async function serverAction(uid,action){
 try{
   const result=await api("/api/server/member-action",{
     method:"POST",
     body:JSON.stringify({
       server_id:state.activeServer,
       user_id:uid,
       action,
       minutes:60
     })
   });

   await openServer(state.activeServer,state.channel);

   if(action==="ban"&&result.removed_from_server){
     toast("User banned and removed from the server");
   }else{
     toast("Member updated");
   }

 }catch(e){
   toast(e.message);
 }
}
function changeServerRole(uid){modalOpen("Change server role",`<form class="formGrid" onsubmit="saveServerRole(event,${uid})"><select id="serverRoleSelect" class="field"><option value="member">Member</option><option value="moderator">Moderator</option><option value="admin">Admin</option></select><div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Save</button></div></form>`)}
async function saveServerRole(e,uid){e.preventDefault();try{await api("/api/server/member-action",{method:"POST",body:JSON.stringify({server_id:state.activeServer,user_id:uid,action:"role",role:serverRoleSelect.value})});modalClose();await openServer(state.activeServer,state.channel)}catch(e){toast(e.message)}}
async function showServerSettings(id){
 try{
   const d=await api("/api/servers/"+id+"/members");
   const s=state.serverInfo;
   modalOpen("Server settings",`<div class="formGrid"><div class="label">Server name</div><input id="serverSetName" class="field" value="${esc(s.name)}"><div class="label">Server picture URL</div><input id="serverSetIcon" class="field" value="${esc(s.icon||"")}"><div class="label">Server privacy</div><select id="serverPrivacyMode" class="field"><option value="public" ${s.privacy_mode==="public"?"selected":""}>Public — anyone can join</option><option value="public_approval" ${s.privacy_mode==="public_approval"?"selected":""}>Public + Owner Approval — join requests</option><option value="invite_only" ${s.privacy_mode==="invite_only"?"selected":""}>Invite Only — hidden from Discover</option><option value="private" ${s.privacy_mode==="private"?"selected":""}>Private — no joining</option></select><button class="primary" onclick="saveServerSettings(${id})">Save server settings</button></div>
   <div class="card" style="margin-top:16px"><h3>Joining</h3><div class="muted">Members can only join this server themselves from Discover Servers.</div></div><div class="card"><div class="row between"><div><h3 style="margin:0">Banned Users</h3><div class="muted">Banned users are removed from the server completely and cannot rejoin until the ban expires or you unban them.</div></div><button class="ghost" onclick="loadServerBans(${id})">Refresh</button></div><div id="serverBansList" style="margin-top:10px">Loading...</div></div><div class="card"><div class="row between"><div><h3 style="margin:0">Join Requests</h3><div class="muted">Used when Server Privacy is set to Public + Owner Approval.</div></div><button class="ghost" onclick="loadJoinRequests(${id})">Refresh</button></div><div id="joinRequestsList" style="margin-top:10px">Loading...</div></div>
   <div class="card"><div class="row between"><h3 style="margin:0">Custom Roles</h3>${hasServerPerm("manage_roles")?`<button class="primary" onclick="createCustomRole(${id})">＋ Role</button>`:""}</div><div style="margin-top:10px">${state.serverRoles.length?state.serverRoles.map(r=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(r.name)}</div><div class="listSub">${Object.entries(r.permissions||{}).filter(([k,v])=>v).length} enabled permission${Object.entries(r.permissions||{}).filter(([k,v])=>v).length===1?"":"s"}</div></div><button class="ghost" onclick="editCustomRole(${id},${r.id})">Edit Permissions</button><button class="danger" onclick="deleteCustomRole(${id},${r.id})">Delete</button></div>`).join(""):'<div class="muted">No custom roles yet.</div>'}</div>
   <div class="card"><h3>Members (${d.members.length})</h3>${d.members.map(m=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(m.username)}</div><div class="listSub">${esc(m.role)}</div></div>${m.role!=="owner"?`<button class="ghost" onclick="changeServerRoleFromSettings(${id},${m.id})">Staff Role</button><button class="ghost" onclick="manageMemberCustomRoles(${id},${m.id})">Custom Roles</button><button class="danger" onclick="removeServerMember(${id},${m.id})">Remove</button>`:""}</div>`).join("")}</div>
   <div class="card"><div class="row between"><div><h3 style="margin:0">Installed Bots</h3><div class="muted">Bots installed through Vyntra Bot invite links.</div></div><button class="ghost" onclick="loadServerBots(${id})">Refresh</button></div><div id="installedBotsList" style="margin-top:10px">Loading...</div></div>
   <div class="card"><h3>Danger zone</h3><button class="danger" onclick="deleteServer(${id})">Delete server</button></div>`);
   setTimeout(()=>loadJoinRequests(id),20);
   setTimeout(()=>loadServerBans(id),25);
   setTimeout(()=>loadServerBots(id),30);
 }catch(e){toast(e.message)}
}


async function loadServerBots(sid){
 const el=document.getElementById("installedBotsList");
 if(!el)return;
 try{
   const d=await api(`/api/servers/${sid}/bots`);
   el.innerHTML=d.bots.length?d.bots.map(b=>`
     <div class="listItem">
       <img class="avatar" src="${avatarSrc(b.avatar)}">
       <div class="listMain"><div class="listTitle">${esc(b.name)} <span class="roleTag">BOT</span></div><div class="listSub">${(b.permissions||[]).map(p=>BOT_PERMISSION_LABELS[p]?.[0]||p).join(", ")||"No permissions"}</div></div>
       ${state.serverInfo&&["admin","owner"].includes(state.serverInfo.my_role)?`<button class="danger" onclick="removeServerBot(${sid},${b.id})">Remove</button>`:""}
     </div>`).join(""):`<div class="muted">No bots installed.</div>`;
 }catch(e){
   el.innerHTML=`<div class="muted">${esc(e.message)}</div>`;
 }
}

async function removeServerBot(sid,bid){
 if(!confirm("Remove this bot from the server?"))return;
 try{
   await api(`/api/servers/${sid}/bots/${bid}`,{method:"DELETE"});
   toast("Bot removed");
   loadServerBots(sid);
 }catch(e){toast(e.message)}
}


async function loadServerBans(sid){
 const el=document.getElementById("serverBansList");
 if(!el)return;

 try{
   const d=await api(`/api/servers/${sid}/bans`);

   el.innerHTML=d.bans.length
     ?d.bans.map(b=>`
       <div class="listItem">
         <img class="avatar" src="${avatarSrc(b.avatar)}">
         <div class="listMain">
           <div class="listTitle">${esc(b.username)}</div>
           <div class="listSub">
             ${b.banned_until
               ?`Banned until ${new Date(b.banned_until).toLocaleString()}`
               :"Permanently banned"}
             ${b.banned_by?` · by ${esc(b.banned_by)}`:""}
           </div>
         </div>
         <button class="good" onclick="unbanServerUser(${sid},${b.user_id})">Unban</button>
       </div>`).join("")
     :`<div class="muted">No active server bans.</div>`;

 }catch(e){
   el.innerHTML=`<div class="muted">${esc(e.message)}</div>`;
 }
}

async function unbanServerUser(sid,uid){
 try{
   await api(`/api/servers/${sid}/bans/${uid}`,{
     method:"DELETE"
   });

   toast("User unbanned");
   loadServerBans(sid);

 }catch(e){
   toast(e.message);
 }
}


async function loadJoinRequests(sid){
 const el=document.getElementById("joinRequestsList");if(!el)return;
 try{
   const d=await api(`/api/servers/${sid}/join-requests`);
   el.innerHTML=d.requests.length?d.requests.map(r=>`<div class="listItem"><img class="avatar" src="${avatarSrc(r.avatar)}"><div class="listMain"><div class="listTitle">${esc(r.username)}</div><div class="listSub">Vyntra ID #${r.user_id} · Requested ${new Date(r.created_at).toLocaleString()}</div></div><button class="good" onclick="decideJoinRequest(${sid},${r.request_id},'accept')">Accept</button><button class="danger" onclick="decideJoinRequest(${sid},${r.request_id},'deny')">Deny</button></div>`).join(""):`<div class="muted">No pending join requests.</div>`;
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
function showServersMobile(){modalOpen("Your servers",state.servers.map(s=>{const uc=unreadCountFor("server",s.id);return `<button class="serverBtn ${unreadClass(uc)}" data-unread-scope="server" data-server-id="${s.id}" onclick="modalClose();openServer(${s.id},'chat')">${unreadDot(uc)}<span class="serverIcon">${s.icon?`<img src="${esc(s.icon)}">`:esc(s.name[0])}</span><span class="serverNameLabel">${esc(s.name)}</span>${badgeHtml(uc)}<span class="badge">${s.member_count}</span></button>`}).join("")||"<div class='muted'>No servers yet.</div>")}

function showSettings(){state.view="settings";state.activeServer=null;renderApp()}
function renderSettings(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">VYNTRA Settings</div><div class="topSub">Profile and account settings</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page"><div class="pageHero"><div><h1>Settings</h1><div class="muted">Control how your account appears across VYNTRA.</div></div></div>
 <div class="grid2"><div class="card"><h3>Profile</h3><form class="formGrid" onsubmit="saveProfile(event)">
 <div class="label">Username</div><input id="setUsername" class="field" maxlength="32" value="${esc(state.profile.username)}">
 <div class="label">Pronouns</div><input id="setPronouns" class="field" maxlength="40" value="${esc(state.profile.pronouns||"")}">
 <div class="label">Company</div><input id="setCompany" class="field" maxlength="80" value="${esc(state.profile.company||"")}">
 <div class="label">Profile picture URL</div><input id="setAvatar" class="field" maxlength="500" value="${esc(state.profile.avatar||"")}">
 <div class="label">Description</div><textarea id="setDescription" class="field" rows="5" maxlength="300">${esc(state.profile.description||"")}</textarea>
 <button class="primary">Save profile</button></form></div>
 <div><div class="card"><h3>Account & Appearance</h3><div class="listItem"><div class="listMain"><div class="listTitle">Vyntra ID</div><div class="listSub">Use this to find your account precisely</div></div><span class="pill">#${state.me.id}</span></div><div class="listItem"><div class="listMain"><div class="listTitle">Global role</div><div class="listSub">Your site-wide permission level</div></div><span class="pill">${esc(state.profile.global_role)}</span></div>
 <div class="formGrid" style="margin-top:14px"><div class="label">Theme</div><select id="themeSelect" class="field"><option value="original" ${state.profile.theme==="original"?"selected":""}>Original Dark + Purple</option><option value="dark" ${state.profile.theme==="dark"?"selected":""}>Dark</option><option value="light" ${state.profile.theme==="light"?"selected":""}>Light</option></select>${["moderator","admin","owner"].includes(state.profile.global_role)?`<label class="row"><input id="staffTagToggle" type="checkbox" ${state.profile.show_staff_tag?"checked":""}> Show my staff tag publicly</label>`:""}<button class="ghost" onclick="savePreferences()">Save appearance</button></div>
 <form class="formGrid" onsubmit="changePassword(event)" style="margin-top:14px"><div class="label">New password</div><input id="newPassword" class="field" type="password" minlength="8" placeholder="At least 8 characters"><button class="ghost">Change password</button></form></div>
 <div class="card"><h3>Notifications</h3><div class="muted" style="margin-bottom:12px">VYNTRA can show a Windows/browser popup when a new DM or group message arrives while the app is in the background.</div><div class="row"><button class="primary" type="button" onclick="enableDesktopNotifications()">Enable desktop notifications</button><button class="ghost" type="button" onclick="disableDesktopNotifications()">Disable</button></div></div>
 <div class="card"><h3>Desktop App</h3><div class="muted" style="margin-bottom:12px">Install the Windows desktop version of VYNTRA.</div><a class="primary" href="/static/downloads/VYNTRAPCSet-up.exe" download="VYNTRAPCSet-up.exe" style="display:inline-block;text-decoration:none">Download VYNTRA for Windows</a></div>
 ${state.profile.global_role==="owner"?`<div class="card"><h3>Owner Security</h3><div class="muted" style="margin-bottom:12px">Set a separate password required before viewing sensitive moderation account records.</div><form class="formGrid" onsubmit="setAccountInfoPassword(event)"><div class="label">Account Info Access Password</div><input id="accountInfoAccessPassword" class="field" type="password" minlength="8" placeholder="At least 8 characters" required><button class="primary">Set / Change Access Password</button></form></div>`:""}${state.profile.global_role==="owner"?`<div class="card"><h3>Owner</h3><button class="primary" onclick="showOwnerPanel()">Open Owner Control Center</button></div>`:""}<div class="card"><h3>Session</h3><button class="danger" onclick="logout()">Log out of VYNTRA</button></div></div></div><div class="card">
   <div class="row between">
     <div>
       <h3 style="margin:0">System Notifications</h3>
       <div class="muted" style="margin-top:5px">Show normal phone/PC notifications for new messages while VYNTRA is open or running in the background.</div>
     </div>
     <button class="primary" onclick="requestSystemNotifications()">Enable Notifications</button>
   </div>
   <div class="listSub" style="margin-top:10px">Status: <b id="notificationPermissionState">Checking...</b></div>
 </div>
 </div>`;
}
async function saveProfile(e){e.preventDefault();try{const d=await api("/api/profile",{method:"PATCH",body:JSON.stringify({username:setUsername.value,pronouns:setPronouns.value,company:setCompany.value,avatar:setAvatar.value,description:setDescription.value})});state.profile=d.profile;state.servers=(await api("/api/servers")).servers;toast("Profile saved");renderApp()}catch(e){toast(e.message)}}
async function changePassword(e){e.preventDefault();try{await api("/api/account/password",{method:"POST",body:JSON.stringify({password:newPassword.value})});newPassword.value="";toast("Password changed")}catch(e){toast(e.message)}}


async function savePreferences(){try{const body={theme:themeSelect.value};if(document.getElementById("staffTagToggle"))body.show_staff_tag=staffTagToggle.checked;const d=await api("/api/account/preferences",{method:"POST",body:JSON.stringify(body)});state.profile.theme=d.theme;state.profile.show_staff_tag=d.show_staff_tag;applyTheme(d.theme);toast("Preferences saved")}catch(e){toast(e.message)}}

function createChannelPrompt(){modalOpen("Create channel",`<form class="formGrid" onsubmit="createChannel(event)"><div class="label">Channel name</div><input id="newChannelName" class="field" maxlength="40" required><div class="label">Type</div><select id="newChannelKind" class="field"><option value="chat">Chat</option><option value="announcement">Announcement</option></select><div class="modalActions"><button class="primary">Create</button></div></form>`)}
async function createChannel(e){e.preventDefault();try{await api(`/api/servers/${state.activeServer}/channels`,{method:"POST",body:JSON.stringify({name:newChannelName.value,kind:newChannelKind.value})});modalClose();await openServer(state.activeServer)}catch(e){toast(e.message)}}

async function channelMenu(ev,cid){ev.preventDefault();ev.stopPropagation();if(!hasServerPerm("manage_channels"))return;overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-220)}px;top:${Math.min(ev.clientY,innerHeight-230)}px" onclick="event.stopPropagation()"><button onclick="channelSettings(${cid});closeContext()">⚙ Channel settings</button><button onclick="showVyntraHooks(${cid});closeContext()">🔗 VyntraHooks</button><button class="red" onclick="deleteChannel(${cid});closeContext()">🗑 Delete channel</button></div>`}
function channelRoleOptions(){
 const built=[["member","Member"],["moderator","Moderator"],["admin","Admin"],["owner","Owner"]];
 return [...built,...state.serverRoles.map(r=>[`custom:${r.id}`,r.name])];
}
async function channelSettings(cid){
 const c=state.serverChannels.find(x=>Number(x.id)===Number(cid));if(!c)return;
 let overrides=[];
 try{overrides=(await api(`/api/servers/${state.activeServer}/channels/${cid}/role-overrides`)).overrides}catch(e){}
 modalOpen("Channel settings",`<form class="formGrid" onsubmit="saveChannelNameOnly(event,${cid})"><div class="label">Channel name</div><input id="channelSetName" class="field" value="${esc(c.name)}"><button class="ghost">Save Channel Name</button></form>
 <div class="card" style="margin-top:14px"><h3>Role Permissions</h3><div class="muted" style="margin-bottom:10px">Choose a role, then set each channel permission to Allow, Deny, or Inherit from the server role.</div><select id="channelRoleSelector" class="field" onchange="renderSelectedChannelRolePermissions(${cid})">${channelRoleOptions().map(([k,n])=>`<option value="${esc(k)}">${esc(n)}</option>`).join("")}</select><div id="channelRolePermissionEditor" style="margin-top:12px"></div></div>`);
 window._channelOverrides=overrides;
 setTimeout(()=>renderSelectedChannelRolePermissions(cid),20);
}
async function saveChannelNameOnly(e,cid){
 e.preventDefault();
 try{
   const c=state.serverChannels.find(x=>Number(x.id)===Number(cid));
   await api(`/api/servers/${state.activeServer}/channels/${cid}`,{method:"PATCH",body:JSON.stringify({name:channelSetName.value,view_roles:c.view_roles,talk_roles:c.talk_roles})});
   await openServer(state.activeServer,cid);toast("Channel renamed");
 }catch(e){toast(e.message)}
}
function renderSelectedChannelRolePermissions(cid){
 const roleKey=channelRoleSelector.value;
 const existing=(window._channelOverrides||[]).find(x=>x.role_key===roleKey)||{allow:[],deny:[]};
 const perms=[
   ["view_channels","View Channel"],
   ["send_messages","Send Messages"],
   ["manage_messages","Manage Messages"],
   ["manage_spookhooks","Manage VyntraHooks"]
 ];
 channelRolePermissionEditor.innerHTML=perms.map(([key,label])=>{
   const stateValue=existing.deny.includes(key)?"deny":existing.allow.includes(key)?"allow":"inherit";
   return `<div class="listItem"><div class="listMain"><div class="listTitle">${label}</div></div><select class="field" style="width:150px" data-chanperm="${key}"><option value="inherit" ${stateValue==="inherit"?"selected":""}>Inherit</option><option value="allow" ${stateValue==="allow"?"selected":""}>Allow</option><option value="deny" ${stateValue==="deny"?"selected":""}>Deny</option></select></div>`;
 }).join("")+`<button class="primary" style="margin-top:12px" onclick="saveSelectedChannelRolePermissions(${cid})">Save Role Channel Permissions</button>`;
}
async function saveSelectedChannelRolePermissions(cid){
 const roleKey=channelRoleSelector.value;
 const allow=[],deny=[];
 document.querySelectorAll("[data-chanperm]").forEach(x=>{if(x.value==="allow")allow.push(x.dataset.chanperm);if(x.value==="deny")deny.push(x.dataset.chanperm)});
 try{
   await api(`/api/servers/${state.activeServer}/channels/${cid}/role-overrides/${encodeURIComponent(roleKey)}`,{method:"PUT",body:JSON.stringify({allow,deny})});
   const d=await api(`/api/servers/${state.activeServer}/channels/${cid}/role-overrides`);
   window._channelOverrides=d.overrides;
   toast("Channel role permissions saved");
 }catch(e){toast(e.message)}
}

async function deleteChannel(cid){if(!confirm("Delete this channel and its messages?"))return;try{await api(`/api/servers/${state.activeServer}/channels/${cid}`,{method:"DELETE"});await openServer(state.activeServer);toast("Channel deleted")}catch(e){toast(e.message)}}

const SERVER_PERMISSION_LABELS={
 administrator:["Administrator","Gives every server permission except Delete Server."],
 view_channels:["View Channels","Can see server channels unless a channel override denies it."],
 send_messages:["Send Messages","Can text in channels unless a channel override denies it."],
 invite_members:["Invite Members","Can create and manage server invite links."],
 manage_channels:["Manage Channels","Can create, rename, delete, and configure channels."],
 manage_roles:["Manage Roles","Can create/edit roles and assign custom roles."],
 manage_members:["Manage Members","Can remove members and manage member settings."],
 mute_members:["Mute Members","Can restrict members from talking."],
 ban_members:["Ban Members","Can ban and unban members."],
 manage_messages:["Manage Messages","Can delete other members' messages."],
 embed_links:["Embed Links","Allows links to appear as preview cards in server channels."],
 add_reactions:["Add Reactions","Allows reacting to messages with emoji."],
 manage_spookhooks:["Manage VyntraHooks","Can create and delete VyntraHooks."],
 manage_server:["Manage Server","Can change server name, icon, and privacy. Cannot delete the server."]
};
function rolePermissionChecks(perms,prefix){
 return Object.entries(SERVER_PERMISSION_LABELS).map(([key,[name,desc]])=>`<label class="listItem" style="cursor:pointer"><input type="checkbox" data-${prefix}="${key}" ${perms?.[key]?"checked":""}><div class="listMain"><div class="listTitle">${name}</div><div class="listSub">${desc}</div></div></label>`).join("");
}
function collectRolePermissions(prefix){
 const out={};
 document.querySelectorAll(`[data-${prefix}]`).forEach(x=>out[x.dataset[prefix]]=x.checked);
 return out;
}
function createCustomRole(sid){
 modalOpen("Create custom role",`<form class="formGrid" onsubmit="saveNewCustomRole(event,${sid})"><div class="label">Role name</div><input id="newCustomRoleName" class="field" maxlength="30" placeholder="VIP" required><div class="card"><h3>Permissions</h3>${rolePermissionChecks({},"newroleperm")}</div><div class="modalActions"><button class="primary">Create role</button></div></form>`);
}
async function saveNewCustomRole(e,sid){
 e.preventDefault();
 try{
   await api(`/api/servers/${sid}/roles`,{method:"POST",body:JSON.stringify({name:newCustomRoleName.value,permissions:collectRolePermissions("newroleperm")})});
   modalClose();
   state.serverRoles=(await api(`/api/servers/${sid}/roles`)).roles;
   showServerSettings(sid);
 }catch(e){toast(e.message)}
}
function editCustomRole(sid,rid){
 const r=state.serverRoles.find(x=>Number(x.id)===Number(rid));if(!r)return;
 modalOpen("Edit role permissions",`<form class="formGrid" onsubmit="saveEditedCustomRole(event,${sid},${rid})"><div class="label">Role name</div><input id="editRoleName" class="field" maxlength="30" value="${esc(r.name)}"><div class="card"><h3>Permissions</h3>${rolePermissionChecks(r.permissions||{},"editroleperm")}</div><div class="modalActions"><button class="primary">Save Permissions</button></div></form>`);
}
async function saveEditedCustomRole(e,sid,rid){
 e.preventDefault();
 try{
   await api(`/api/servers/${sid}/roles/${rid}`,{method:"PATCH",body:JSON.stringify({name:editRoleName.value,permissions:collectRolePermissions("editroleperm")})});
   modalClose();
   state.serverRoles=(await api(`/api/servers/${sid}/roles`)).roles;
   showServerSettings(sid);
   toast("Role permissions updated");
 }catch(e){toast(e.message)}
}
async function deleteCustomRole(sid,rid){if(!confirm("Delete this custom role?"))return;try{await api(`/api/servers/${sid}/roles/${rid}`,{method:"DELETE"});state.serverRoles=(await api(`/api/servers/${sid}/roles`)).roles;modalClose();showServerSettings(sid)}catch(e){toast(e.message)}}
async function manageMemberCustomRoles(sid,uid){try{const username=(state.serverMembers.find(x=>Number(x.id)===Number(uid))?.username||"Member");const d=await api(`/api/servers/${sid}/members/${uid}/custom-roles`);modalOpen("Roles for "+username,`<div class="formGrid">${state.serverRoles.length?state.serverRoles.map(r=>`<label class="row"><input type="checkbox" ${d.role_ids.includes(r.id)?"checked":""} onchange="toggleMemberCustomRole(${sid},${uid},${r.id},this.checked)"> ${esc(r.name)}</label>`).join(""):'<div class="muted">Create custom roles first.</div>'}</div>`)}catch(e){toast(e.message)}}
async function toggleMemberCustomRole(sid,uid,rid,enabled){
 try{
   await api(`/api/servers/${sid}/members/${uid}/custom-role`,{
     method:"POST",
     body:JSON.stringify({role_id:rid,enabled})
   });

   const member=(state.serverMembers||[]).find(x=>!x.is_bot&&Number(x.id)===Number(uid));
   const role=(state.serverRoles||[]).find(x=>Number(x.id)===Number(rid));

   if(member&&role){
     member.custom_roles=member.custom_roles||[];

     if(enabled&&!member.custom_roles.some(x=>Number(x.id)===Number(rid))){
       member.custom_roles.push({id:role.id,name:role.name});
     }

     if(!enabled){
       member.custom_roles=member.custom_roles.filter(x=>Number(x.id)!==Number(rid));
     }

     renderMembers();
   }

   toast(enabled?"Role added":"Role removed");

 }catch(e){
   toast(e.message);
 }
}

async function showVyntraHooks(cid){try{const d=await api(`/api/servers/${state.activeServer}/channels/${cid}/spookhooks`);modalOpen("VyntraHooks",`<div class="muted">A VyntraHook is a secret incoming link that can post messages into this channel. Never share a hook URL publicly.</div><div class="card" style="margin-top:12px"><div class="searchBox"><input id="hookName" class="field" placeholder="Hook name" value="VyntraHook"><button class="primary" onclick="createVyntraHook(${cid})">Create</button></div></div><div>${d.hooks.length?d.hooks.map(h=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(h.name)}</div><div class="listSub">Created ${new Date(h.created_at).toLocaleString()}</div></div><button class="danger" onclick="deleteVyntraHook(${cid},${h.id})">Delete</button></div>`).join(""):'<div class="muted">No hooks for this channel.</div>'}</div>`)}catch(e){toast(e.message)}}
async function createVyntraHook(cid){try{const d=await api(`/api/servers/${state.activeServer}/channels/${cid}/spookhooks`,{method:"POST",body:JSON.stringify({name:hookName.value})});modalOpen("VyntraHook created",`<div class="card"><div class="muted">Copy this URL now. For security, VYNTRA will not show this secret URL again.</div><input id="newHookUrl" class="field" value="${esc(d.url)}" readonly style="margin-top:10px"><button class="primary" style="margin-top:10px" onclick="navigator.clipboard.writeText(newHookUrl.value);toast('Copied')">Copy URL</button></div><div class="card"><div class="label">Example JSON POST body</div><pre style="white-space:pre-wrap">{"content":"Hello from my app","username":"My Bot"}</pre></div>`)}catch(e){toast(e.message)}}
async function deleteVyntraHook(cid,hid){if(!confirm("Delete this VyntraHook? Its URL will stop working."))return;try{await api(`/api/servers/${state.activeServer}/spookhooks/${hid}`,{method:"DELETE"});showVyntraHooks(cid)}catch(e){toast(e.message)}}


async function setAccountInfoPassword(e){
 e.preventDefault();
 try{
   await api("/api/owner/account-info-password",{method:"POST",body:JSON.stringify({password:accountInfoAccessPassword.value})});
   accountInfoAccessPassword.value="";
   toast("Account Info Access Password saved");
 }catch(e){toast(e.message)}
}

function moderationUserMenu(ev,uid){
 ev.preventDefault();ev.stopPropagation();
 overlay.innerHTML=`<div class="context" style="left:${Math.min(ev.clientX,innerWidth-230)}px;top:${Math.min(ev.clientY,innerHeight-240)}px" onclick="event.stopPropagation()">
 <button onclick="staffUserActions(${uid});closeContext()">🛡 Manage account</button>
 ${state.profile.global_role==="owner"?`<button onclick="unlockSensitiveUserInfo(${uid},'User');closeContext()">🔐 View protected account info</button>`:""}
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
   modalOpen("Protected Account Info",`<div class="card"><div class="listItem"><div class="listMain"><div class="listTitle">${esc(u.username)} · Vyntra ID #${u.id}</div><div class="listSub">${esc(u.global_role)}</div></div></div></div>
   <div class="card"><h3>Account Record</h3>
   <div class="listItem"><div class="listMain"><div class="listTitle">Login email</div><div class="listSub">${esc(u.email)}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Last known IP</div><div class="listSub">${esc(u.last_ip||"Not recorded")}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Device</div><div class="listSub">${esc(u.device_type||"Unknown")}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Account created</div><div class="listSub">${u.created_at?new Date(u.created_at).toLocaleString():"Unknown"}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Last seen</div><div class="listSub">${u.last_seen?new Date(u.last_seen).toLocaleString():"Unknown"}</div></div></div>
   <div class="listItem"><div class="listMain"><div class="listTitle">Password</div><div class="listSub">Not viewable. VYNTRA stores a one-way password hash.</div></div></div>
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


const SITE_PERMISSION_LABELS={
 view_moderation:["View Moderation","Can open the moderation center."],
 manage_users:["Manage Users","Can manage user bans and account actions."],
 manage_reports:["Manage Reports","Can review and resolve reports."],
 manage_ip_bans:["Manage IP Bans","Can view and manage IP bans."],
 manage_global_roles:["Manage Global Roles","Can manage built-in global roles where allowed."],
 manage_site_roles:["Manage Site Roles","Can work with custom site-wide roles."],
 view_audit_log:["View Audit Log","Can inspect owner/site administration activity."]
};

function showOwnerPanel(){
 state.view="owner";state.activeServer=null;renderApp();
}

async function renderOwnerPanel(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Owner Control Center</div><div class="topSub">Whole-site administration</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page"><div class="pageHero"><div><h1>Owner Control Center</h1><div class="muted">Manage VYNTRA as a platform.</div></div></div>
 <div id="ownerStats" class="grid2"></div>

 <div class="card ownerMobileTestCard">
   <div class="row between ownerMobileTestRow">
     <div>
       <h3 style="margin:0">Mobile UI Testing</h3>
       <div class="muted" style="margin-top:5px">Open VYNTRA in a separate iPhone 11-sized test window. The preview uses a 414 × 896 CSS-pixel viewport and the real mobile navigation/server controls.</div>
     </div>
     <button class="primary" onclick="launchIPhone11Preview()">Open iPhone 11 Preview</button>
   </div>
 </div>

 <div class="grid2">
   <div class="card"><h3>Site Controls</h3><div id="ownerSiteControls">Loading...</div></div>
   <div class="card"><h3>Global Announcement</h3><div class="muted" style="margin-bottom:10px">Shown to everyone in the app.</div><textarea id="ownerAnnouncement" class="field" rows="5" maxlength="500"></textarea><button class="primary" style="margin-top:10px" onclick="saveOwnerSettings()">Save Announcement</button></div>
 </div>
 <div class="card"><div class="row between"><div><h3 style="margin:0">Custom Site Roles</h3><div class="muted">Users can have multiple custom site-wide roles at once.</div></div><button class="primary" onclick="createSiteRole()">＋ Create Site Role</button></div><div id="ownerSiteRoles" style="margin-top:12px">Loading...</div></div>
 <div class="card"><h3>Assign Multiple Roles</h3><div class="searchBox"><input id="ownerUserRoleSearch" class="field" placeholder="Username or Vyntra ID (#123)"><button class="primary" onclick="ownerSearchUsersForRoles()">Search</button></div><div id="ownerRoleUserResults"></div></div>
 <div class="card"><div class="row between"><div><h3 style="margin:0">Owner Audit Log</h3><div class="muted">Recent website administration actions.</div></div><button class="ghost" onclick="loadOwnerAudit()">Refresh</button></div><div id="ownerAuditList" style="margin-top:12px">Loading...</div></div>
 </div>`;
 await loadOwnerDashboard();
 await loadOwnerSiteRoles();
 await loadOwnerAudit();
}

async function loadOwnerDashboard(){
 try{
   const d=await api("/api/owner/dashboard");
   const s=d.settings,st=d.stats;
   ownerStats.innerHTML=[
     ["Users",st.users],["Active 24h",st.active_24h],["Servers",st.servers],["Messages",st.messages],
     ["Open Reports",st.open_reports],["Banned Users",st.banned_users],["IP Bans",st.ip_bans]
   ].map(([n,v])=>`<div class="card"><div class="muted">${n}</div><div style="font-size:28px;font-weight:900;margin-top:5px">${v}</div></div>`).join("");
   ownerSiteControls.innerHTML=`<div class="formGrid">
     <label class="row"><input id="ownerMaintenance" type="checkbox" ${s.maintenance_mode?"checked":""}> <div><div class="listTitle">Maintenance Mode</div><div class="listSub">Normal users are blocked while you can still access Owner controls.</div></div></label>
     <div class="label">Maintenance message</div><textarea id="ownerMaintenanceMessage" class="field" rows="3">${esc(s.maintenance_message)}</textarea>
     <label class="row"><input id="ownerRegistrations" type="checkbox" ${s.registrations_enabled?"checked":""}> <div><div class="listTitle">Allow New Registrations</div><div class="listSub">Turn off to stop new account creation.</div></div></label>

     <label class="row"><input id="ownerPublicLock" type="checkbox" ${s.public_channels_locked?"checked":""}> <div><div class="listTitle">Lock Public Channels</div><div class="listSub">When enabled, normal users and moderators can read but only global Admin and Owner can post.</div></div></label>

     <label class="row"><input id="ownerPublicEmbeds" type="checkbox" ${s.public_embeds_enabled?"checked":""}> <div><div class="listTitle">Public Chat Link Embeds</div><div class="listSub">Controls preview cards in public chats. Links themselves are always clickable.</div></div></label>

     <div class="label">Site name</div><input id="ownerSiteName" class="field" value="${esc(s.site_name)}">
     <button class="danger" onclick="confirmMaintenanceToggle()">${s.maintenance_mode?"Disable Maintenance Mode":"Enable Maintenance Mode"}</button>
     <button class="primary" onclick="saveOwnerSettings()">Save Site Settings</button>
   </div>`;
   ownerAnnouncement.value=s.announcement||"";
 }catch(e){toast(e.message)}
}

async function confirmMaintenanceToggle(){
 const enable=!ownerMaintenance.checked;
 if(enable && !confirm("Enable Maintenance Mode? Normal users will be blocked from VYNTRA until you turn it off."))return;
 ownerMaintenance.checked=enable;
 await saveOwnerSettings();
}

async function saveOwnerSettings(){
 try{
   const d=await api("/api/owner/site-settings",{method:"PATCH",body:JSON.stringify({
     maintenance_mode:ownerMaintenance.checked,
     maintenance_message:ownerMaintenanceMessage.value,
     registrations_enabled:ownerRegistrations.checked,
     public_channels_locked:ownerPublicLock.checked,
     public_embeds_enabled:ownerPublicEmbeds.checked,
     site_name:ownerSiteName.value,
     announcement:ownerAnnouncement.value
   })});
   toast("Site settings saved");
   await loadOwnerDashboard();
 }catch(e){toast(e.message)}
}

function siteRolePermissionChecks(perms,prefix){
 return Object.entries(SITE_PERMISSION_LABELS).map(([key,[name,desc]])=>`<label class="listItem" style="cursor:pointer"><input type="checkbox" data-${prefix}="${key}" ${perms?.[key]?"checked":""}><div class="listMain"><div class="listTitle">${name}</div><div class="listSub">${desc}</div></div></label>`).join("");
}
function collectSiteRolePermissions(prefix){
 const out={};document.querySelectorAll(`[data-${prefix}]`).forEach(x=>out[x.dataset[prefix]]=x.checked);return out;
}
async function loadOwnerSiteRoles(){
 try{
   const d=await api("/api/owner/site-roles");
   window._siteRoles=d.roles;
   ownerSiteRoles.innerHTML=d.roles.length?d.roles.map(r=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(r.name)}</div><div class="listSub">${Object.values(r.permissions||{}).filter(Boolean).length} permissions</div></div><button class="ghost" onclick="editSiteRole(${r.id})">Edit</button><button class="danger" onclick="deleteSiteRole(${r.id})">Delete</button></div>`).join(""):`<div class="muted">No custom site roles yet.</div>`;
 }catch(e){toast(e.message)}
}
function createSiteRole(){
 modalOpen("Create Site Role",`<form class="formGrid" onsubmit="saveNewSiteRole(event)"><div class="label">Role name</div><input id="newSiteRoleName" class="field" maxlength="40" required><div class="card"><h3>Permissions</h3>${siteRolePermissionChecks({},"newsiteperm")}</div><div class="modalActions"><button class="primary">Create Role</button></div></form>`);
}
async function saveNewSiteRole(e){
 e.preventDefault();
 try{
   await api("/api/owner/site-roles",{method:"POST",body:JSON.stringify({name:newSiteRoleName.value,permissions:collectSiteRolePermissions("newsiteperm")})});
   modalClose();toast("Site role created");loadOwnerSiteRoles();
 }catch(e){toast(e.message)}
}
function editSiteRole(rid){
 const r=(window._siteRoles||[]).find(x=>x.id===rid);if(!r)return;
 modalOpen("Edit Site Role",`<form class="formGrid" onsubmit="saveEditedSiteRole(event,${rid})"><div class="label">Role name</div><input id="editSiteRoleName" class="field" value="${esc(r.name)}"><div class="card"><h3>Permissions</h3>${siteRolePermissionChecks(r.permissions||{},"editsiteperm")}</div><div class="modalActions"><button class="primary">Save Role</button></div></form>`);
}
async function saveEditedSiteRole(e,rid){
 e.preventDefault();
 try{
   await api(`/api/owner/site-roles/${rid}`,{method:"PATCH",body:JSON.stringify({name:editSiteRoleName.value,permissions:collectSiteRolePermissions("editsiteperm")})});
   modalClose();toast("Role updated");loadOwnerSiteRoles();
 }catch(e){toast(e.message)}
}
async function deleteSiteRole(rid){
 if(!confirm("Delete this site role? It will be removed from everyone who has it."))return;
 try{await api(`/api/owner/site-roles/${rid}`,{method:"DELETE"});toast("Role deleted");loadOwnerSiteRoles()}catch(e){toast(e.message)}
}

async function ownerSearchUsersForRoles(){
 const q=ownerUserRoleSearch.value.trim();
 try{
   const d=await api("/api/staff/users?q="+encodeURIComponent(q)+"&limit=100");
   ownerRoleUserResults.innerHTML=d.users.length?d.users.map(u=>`<div class="listItem"><img class="avatar" src="${avatarSrc(u.avatar)}"><div class="listMain"><div class="listTitle">${esc(u.username)}</div><div class="listSub">Vyntra ID #${u.id} · ${esc(u.global_role)}</div></div><button class="ghost" onclick="manageUserSiteRoles(${u.id})">Manage Roles</button></div>`).join(""):`<div class="muted">No users found.</div>`;
 }catch(e){toast(e.message)}
}
async function manageUserSiteRoles(uid){
 try{
   const d=await api(`/api/owner/users/${uid}/roles`);
   const assigned=new Set(d.assigned.map(r=>r.id));
   modalOpen("Roles for "+d.user.username,`<div class="muted">Built-in global role: ${esc(d.user.global_role)}</div><div class="card" style="margin-top:12px"><h3>Custom Site Roles</h3>${d.all_roles.length?d.all_roles.map(r=>`<label class="listItem" style="cursor:pointer"><input type="checkbox" ${assigned.has(r.id)?"checked":""} onchange="toggleUserSiteRole(${uid},${r.id},this.checked)"><div class="listMain"><div class="listTitle">${esc(r.name)}</div><div class="listSub">${Object.values(r.permissions||{}).filter(Boolean).length} permissions</div></div></label>`).join(""):'<div class="muted">Create a site role first.</div>'}</div>`);
 }catch(e){toast(e.message)}
}
async function toggleUserSiteRole(uid,rid,enabled){
 try{
   await api(`/api/owner/users/${uid}/roles/${rid}`,{method:enabled?"POST":"DELETE"});
   toast(enabled?"Role assigned":"Role removed");
 }catch(e){toast(e.message)}
}
async function loadOwnerAudit(){
 try{
   const d=await api("/api/owner/audit-log");
   ownerAuditList.innerHTML=d.logs.length?d.logs.map(l=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(l.action)}</div><div class="listSub">${esc(l.actor_username||"Unknown")} · ${esc(l.target_type)} ${esc(l.target_id)} · ${new Date(l.created_at).toLocaleString()}</div><div style="margin-top:4px">${esc(l.details||"")}</div></div></div>`).join(""):`<div class="muted">No audit events yet.</div>`;
 }catch(e){toast(e.message)}
}


const BOT_PERMISSION_LABELS={
 administrator:["Administrator","Installs the bot with the server Admin role and every VYNTRA bot server permission. It still cannot access website Owner controls, private account data, delete servers, or transfer ownership."],
 view_channels:["View Channels","Allows the bot to see the server channel list."],
 read_messages:["Read Message History","Allows the bot API to read recent channel messages."],
 send_messages:["Send Messages","Allows the bot to send messages into server channels."],
 embed_links:["Embed Links","Allows bot messages to include link previews where supported."],
 add_reactions:["Add Reactions","Allows the bot to react to messages."],
 manage_messages:["Manage Messages","Allows the bot to delete messages it does not own."],
 manage_channels:["Manage Channels","Allows creating, renaming, and deleting server channels."],
 manage_roles:["Manage Roles","Allows creating, editing, and deleting custom server roles."],
 manage_members:["Manage Members","Allows reading and managing server member information."],
 mute_members:["Mute Members","Allows muting and unmuting server members."],
 ban_members:["Ban Members","Allows banning and unbanning server members, except the server owner."],
 invite_members:["Invite Members","Allows the bot to create server invite links."],
 manage_server:["Manage Server","Allows changing the server name and icon. It cannot delete the server or transfer ownership."]
};

function showBeta(){
 state.view="beta";
 state.activeServer=null;
 renderApp();
}

async function renderBeta(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Beta</div><div class="topSub">Experimental VYNTRA features</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page desktopBetaPage">
   <div class="pageHero"><div><h1>Beta</h1><div class="muted">Try experimental desktop features before they move into VYNTRA.</div></div></div>
   <div class="tabs betaTabs"><button class="active">Vyntra Bots</button></div>
   <div class="card"><div class="row between"><div><h3 style="margin:0">Vyntra Bots</h3><div class="muted">Create programmable bots, choose their permissions, then install them into servers with an invite link.</div></div><button class="primary" onclick="createBotPrompt()">＋ Create Bot</button></div></div>
   <div id="botList" class="grid2"><div class="muted">Loading bots...</div></div>
   <div class="card"><h3>Bot API</h3><div class="muted">Use your bot token in the Authorization header. Keep the token secret.</div><pre class="botCode">Authorization: Bot YOUR_BOT_TOKEN

GET    /api/bot/v1/me
GET    /api/bot/v1/servers

GET    /api/bot/v1/servers/&lt;server_id&gt;/channels
POST   /api/bot/v1/servers/&lt;server_id&gt;/channels
PATCH  /api/bot/v1/channels/&lt;channel_id&gt;
DELETE /api/bot/v1/channels/&lt;channel_id&gt;

GET    /api/bot/v1/channels/&lt;channel_id&gt;/messages
POST   /api/bot/v1/channels/&lt;channel_id&gt;/messages
DELETE /api/bot/v1/messages/&lt;message_id&gt;
POST   /api/bot/v1/messages/&lt;message_id&gt;/reactions

GET    /api/bot/v1/servers/&lt;server_id&gt;/roles
POST   /api/bot/v1/servers/&lt;server_id&gt;/roles
PATCH  /api/bot/v1/servers/&lt;server_id&gt;/roles/&lt;role_id&gt;
DELETE /api/bot/v1/servers/&lt;server_id&gt;/roles/&lt;role_id&gt;

GET    /api/bot/v1/servers/&lt;server_id&gt;/members
POST   /api/bot/v1/servers/&lt;server_id&gt;/members/&lt;user_id&gt;/mute
POST   /api/bot/v1/servers/&lt;server_id&gt;/members/&lt;user_id&gt;/unmute
POST   /api/bot/v1/servers/&lt;server_id&gt;/members/&lt;user_id&gt;/ban
POST   /api/bot/v1/servers/&lt;server_id&gt;/members/&lt;user_id&gt;/unban

PATCH  /api/bot/v1/servers/&lt;server_id&gt;
POST   /api/bot/v1/servers/&lt;server_id&gt;/invites</pre></div>
 </div>`;
 await loadBots();
}

function botPermissionChecks(selected=[]){
 const have=new Set(selected||[]);
 return Object.entries(BOT_PERMISSION_LABELS).map(([key,[name,desc]])=>`
 <label class="listItem botPermissionRow ${key==="administrator"?"botAdminPermission":""}" style="cursor:pointer">
   <input type="checkbox" data-botperm="${key}" ${have.has(key)?"checked":""} onchange="botPermissionChanged(this)">
   <div class="listMain"><div class="listTitle">${name}${key==="administrator"?` <span class="roleTag">ALL SERVER PERMISSIONS</span>`:""}</div><div class="listSub">${desc}</div></div>
 </label>`).join("");
}

function botPermissionChanged(el){
 if(el.dataset.botperm!=="administrator")return;

 document.querySelectorAll("[data-botperm]").forEach(box=>{
   if(box!==el){
     box.checked=el.checked;
     box.disabled=el.checked;
   }
 });
}

function collectBotPermissions(){
 const checked=[...document.querySelectorAll("[data-botperm]:checked")].map(x=>x.dataset.botperm);
 if(checked.includes("administrator")){
   return ["administrator"];
 }
 return checked;
}

async function loadBots(){
 try{
   const d=await api("/api/bots");
   window._vyntraBots=d.bots||[];
   const el=document.getElementById("botList");
   if(!el)return;
   el.innerHTML=d.bots.length?d.bots.map(b=>`
     <div class="card botCard">
       <div class="row">
         <img class="avatar botAvatar" src="${avatarSrc(b.avatar)}">
         <div class="listMain"><div class="listTitle">${esc(b.name)} <span class="roleTag">BOT</span></div><div class="listSub">${b.server_count} server${b.server_count===1?"":"s"} · ID ${esc(b.public_id)}</div></div>
       </div>
       <p class="muted">${esc(b.description||"No description.")}</p>
       <div class="botPermSummary">${(b.permissions||[]).map(p=>`<span class="pill">${esc(BOT_PERMISSION_LABELS[p]?.[0]||p)}</span>`).join(" ")||'<span class="muted">No permissions selected.</span>'}</div>
       <div class="row" style="margin-top:12px;flex-wrap:wrap">
         <button class="primary" onclick="copyBotInvite(${b.id})">Copy Invite Link</button>
         <button class="ghost" onclick="editBotPrompt(${b.id})">Edit</button>
         <button class="ghost" onclick="resetBotToken(${b.id})">Reset Token</button>
         <button class="danger" onclick="deleteBot(${b.id})">Delete</button>
       </div>
     </div>`).join(""):`<div class="card"><div class="muted">You haven't created a bot yet.</div></div>`;
 }catch(e){toast(e.message)}
}

function createBotPrompt(){
 modalOpen("Create Vyntra Bot",`<form class="formGrid" onsubmit="createBot(event)">
   <div class="label">Bot name</div><input id="botName" class="field" maxlength="40" placeholder="My Bot" required>
   <div class="label">Description</div><textarea id="botDescription" class="field" rows="3" maxlength="240" placeholder="What does your bot do?"></textarea>
   <div class="label">Avatar URL</div><input id="botAvatar" class="field" placeholder="https://...">
   <div class="card"><h3>Requested Server Permissions</h3><div class="muted" style="margin-bottom:8px">People installing the bot will see these permissions before choosing a server.</div>${botPermissionChecks([])}</div>
   <div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Create Bot</button></div>
 </form>`);
}

async function createBot(e){
 e.preventDefault();
 try{
   const d=await api("/api/bots",{method:"POST",body:JSON.stringify({
     name:botName.value,
     description:botDescription.value,
     avatar:botAvatar.value,
     permissions:collectBotPermissions()
   })});
   showBotToken(d.token,d.invite_url,true);
 }catch(e){toast(e.message)}
}

function showBotToken(token,inviteUrl,isNew=false){
 modalOpen(isNew?"Bot Created":"New Bot Token",`
   <div class="card">
     <h3>${isNew?"Your bot is ready":"Token reset complete"}</h3>
     <div class="muted">Copy this token now. VYNTRA stores only a one-way hash and cannot show this exact token again.</div>
     <input id="botTokenBox" class="field" readonly value="${esc(token)}" style="margin-top:10px">
     <button class="primary" style="margin-top:8px" onclick="copyText(botTokenBox.value).then(ok=>toast(ok?'Token copied':'Copy failed'))">Copy Bot Token</button>
   </div>
   ${inviteUrl?`<div class="card"><h3>Invite Link</h3><input id="botInviteBox" class="field" readonly value="${esc(inviteUrl)}"><button class="ghost" style="margin-top:8px" onclick="copyText(botInviteBox.value).then(ok=>toast(ok?'Invite copied':'Copy failed'))">Copy Invite Link</button></div>`:""}
   <div class="modalActions"><button class="primary" onclick="modalClose();renderBeta()">Done</button></div>
 `);
}

async function copyBotInvite(bid){
 const b=(window._vyntraBots||[]).find(x=>Number(x.id)===Number(bid));
 if(!b)return;
 const ok=await copyText(b.invite_url);
 toast(ok?"Bot invite copied":"Copy failed");
}

function editBotPrompt(bid){
 const b=(window._vyntraBots||[]).find(x=>Number(x.id)===Number(bid));
 if(!b)return;
 modalOpen("Edit Vyntra Bot",`<form class="formGrid" onsubmit="saveBotEdit(event,${bid})">
   <div class="label">Bot name</div><input id="botEditName" class="field" maxlength="40" value="${esc(b.name)}" required>
   <div class="label">Description</div><textarea id="botEditDescription" class="field" rows="3" maxlength="240">${esc(b.description||"")}</textarea>
   <div class="label">Avatar URL</div><input id="botEditAvatar" class="field" value="${esc(b.avatar||"")}">
   <div class="card"><h3>Requested Permissions</h3>${botPermissionChecks(b.permissions||[])}</div>
   <div class="muted">Changing requested permissions does not silently change old installs. Reinstalling from the invite link updates that server's bot permissions.</div>
   <div class="modalActions"><button type="button" class="ghost" onclick="modalClose()">Cancel</button><button class="primary">Save Bot</button></div>
 </form>`);
}

async function saveBotEdit(e,bid){
 e.preventDefault();
 try{
   await api(`/api/bots/${bid}`,{method:"PATCH",body:JSON.stringify({
     name:botEditName.value,
     description:botEditDescription.value,
     avatar:botEditAvatar.value,
     permissions:collectBotPermissions()
   })});
   modalClose();toast("Bot updated");renderBeta();
 }catch(e){toast(e.message)}
}

async function resetBotToken(bid){
 if(!confirm("Reset this bot token? The old token will stop working immediately."))return;
 try{
   const d=await api(`/api/bots/${bid}/reset-token`,{method:"POST"});
   showBotToken(d.token,"",false);
 }catch(e){toast(e.message)}
}

async function deleteBot(bid){
 if(!confirm("Delete this bot? It will be removed from every server and its token will stop working."))return;
 try{
   await api(`/api/bots/${bid}`,{method:"DELETE"});
   toast("Bot deleted");loadBots();
 }catch(e){toast(e.message)}
}

async function checkBotInviteFromURL(){
 const publicId=new URLSearchParams(location.search).get("bot_invite");
 if(!publicId)return;

 try{
   const d=await api("/api/bots/invite/"+encodeURIComponent(publicId));
   const b=d.bot;

   modalOpen("Add Vyntra Bot",`
     <div class="row">
       <img class="avatar" style="width:72px;height:72px" src="${avatarSrc(b.avatar)}">
       <div><h2 style="margin:0">${esc(b.name)}</h2><div class="muted">${esc(b.description||"Vyntra Bot")}</div></div>
     </div>
     <div class="card" style="margin-top:12px"><h3>Requested Permissions</h3>${(b.permissions||[]).map(p=>`<div class="listItem"><div class="listMain"><div class="listTitle">${esc(BOT_PERMISSION_LABELS[p]?.[0]||p)}</div><div class="listSub">${esc(BOT_PERMISSION_LABELS[p]?.[1]||"")}</div></div></div>`).join("")||'<div class="muted">This bot requests no permissions.</div>'}</div>
     <div class="card"><h3>Choose a Server</h3>
       ${d.servers.length?`<select id="botInstallServer" class="field">${d.servers.map(s=>`<option value="${s.id}">${esc(s.name)}${s.installed?" · already installed":""}</option>`).join("")}</select>
       <div class="muted" style="margin-top:8px">Only servers where you have Admin permissions are shown.</div>`:`<div class="muted">You do not have Admin permissions in any server where this bot can be installed.</div>`}
     </div>
     <div class="modalActions">
       <button class="ghost" onclick="history.replaceState({},'',location.pathname);modalClose()">Cancel</button>
       ${d.servers.length?`<button class="primary" onclick="installBotFromInvite('${esc(publicId)}')">Add Bot</button>`:""}
     </div>
   `);
 }catch(e){
   toast(e.message);
 }
}

async function installBotFromInvite(publicId){
 try{
   const sid=Number(botInstallServer.value);
   await api(`/api/bots/invite/${encodeURIComponent(publicId)}/install`,{
     method:"POST",
     body:JSON.stringify({server_id:sid})
   });
   history.replaceState({},'',location.pathname);
   modalClose();
   toast("Bot added to server");
   if(state.activeServer===sid)await openServer(sid,state.channel);
 }catch(e){toast(e.message)}
}

function showStaff(){state.view="staff";state.activeServer=null;renderApp()}
async function renderStaff(){
 appShell.classList.remove("with-members");
 mainArea.innerHTML=`<header class="topbar"><div><div class="topTitle">Moderation</div><div class="topSub">Global VYNTRA staff controls</div></div><div class="topActions">${notificationBellButton()}</div></header>
 <div class="page"><div class="pageHero"><div><h1>Moderation center</h1><div class="muted">Review reports and manage users.</div></div></div>
 <div class="card"><div class="row between"><div><h3 style="margin:0">All VYNTRA Users</h3><div class="muted">Search by username or Vyntra ID, for example <b>#14</b>.</div></div><button class="ghost" onclick="loadAllStaffUsers()">Refresh</button></div><div class="searchBox"><input id="staffSearch" class="field" placeholder="Search username or Vyntra ID (#123)..." onkeydown="if(event.key===\'Enter\')staffUserSearch()"><button class="primary" onclick="staffUserSearch()">Search</button></div><div id="staffUsers">Loading users...</div></div>
 <div class="card"><div class="row between"><h3 style="margin:0">Open reports</h3><button class="ghost" onclick="loadReports()">Refresh</button></div><div id="reportsList" style="margin-top:10px">Loading...</div></div>
 <div class="card"><h3>IP bans</h3><div id="ipBanList">Loading...</div></div></div>`;
 loadAllStaffUsers();loadReports();loadIPBans();
}
function drawStaffUsers(list){
 staffUsers.innerHTML=list.length?list.map(u=>`<div class="listItem" oncontextmenu="moderationUserMenu(event,${u.id})"><img class="avatar" src="${avatarSrc(u.avatar)}"><div class="listMain"><div class="listTitle">${esc(u.username)} <span class="pill">${esc(u.global_role)}</span></div><div class="listSub">Vyntra ID #${u.id} · ${esc(u.email)}${u.banned?" · BANNED":""}${u.created_at?` · Joined ${new Date(u.created_at).toLocaleDateString()}`:""}</div></div><button class="ghost" onclick="staffUserActions(${u.id})">Manage</button></div>`).join(""):`<div class="muted">No users found.</div>`;
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
     if(newest && document.hidden && localStorage.getItem("vyntraDesktopNotifications")==="1" && "Notification" in window && Notification.permission==="granted"){
       try{
         const n=new Notification(newest.title||"VYNTRA",{body:newest.body||"New message",icon:"/static/spookchat_pfp.png",tag:"spookchat-"+newest.id});
         n.onclick=()=>{window.focus();if(newest.chat_id)openChat(newest.chat_id);n.close()}
       }catch(e){}
     }
   }
 }catch(e){}
}
function startNotificationPolling(){
 clearInterval(state.notifPoll);
 loadNotifications(false);
 state.notifPoll=setInterval(()=>loadNotifications(true),5000);
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
 if(permission==="granted"){localStorage.setItem("vyntraDesktopNotifications","1");toast("Desktop notifications enabled")}
 else{localStorage.setItem("vyntraDesktopNotifications","0");toast("Notification permission was not granted")}
}
function disableDesktopNotifications(){localStorage.setItem("vyntraDesktopNotifications","0");toast("Desktop notifications disabled")}


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
 const rawCode=new URLSearchParams(location.search).get("invite")||"";
 const code=rawCode.toUpperCase().replace(/[^A-Z0-9]/g,"").slice(0,32);
 if(!code)return;
 try{
   const d=await api("/api/invite/"+encodeURIComponent(code));
   modalOpen("Server Invite",`<div class="row"><img class="avatar" style="width:72px;height:72px;border-radius:18px" src="${avatarSrc(d.server.icon)}"><div><h2 style="margin:0">${esc(d.server.name)}</h2><div class="muted">${d.server.member_count} member${d.server.member_count===1?"":"s"}</div></div></div><div class="card" style="margin-top:14px"><div class="muted">You've been invited to join this VYNTRA server.</div></div><div class="modalActions"><button class="primary" onclick="joinInviteCode('${esc(code)}')">Join Server</button><button class="ghost" onclick="modalClose();history.replaceState({},'',location.pathname)">Cancel</button></div>`);
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

document.addEventListener("visibilitychange",()=>{
 if(document.visibilityState==="visible"){
   loadUnreadCounts(false);
   if(["public","server","dm"].includes(state.view)){
     loadMessages(true);
   }
 }
});

</script>
</body>
</html>
"""

# ============================================================
# BASIC ROUTES
# ============================================================

@app.before_request
def same_origin_api_guard():
    if request.method not in ("POST","PUT","PATCH","DELETE"):
        return None
    # VyntraHooks are intentionally external incoming endpoints protected by a secret token.
    if (
        request.path.startswith("/api/vyntrahook/")
        or request.path.startswith("/api/spookhook/")
        or request.path.startswith("/api/bot/v1/")
    ):
        return None
    origin=request.headers.get("Origin")
    if origin:
        expected=request.host_url.rstrip("/")
        if origin.rstrip("/") != expected:
            return jsonify(error="Blocked cross-site request."),403
    return None

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Permissions-Policy"]="camera=(self), microphone=(self), display-capture=(self), geolocation=()"
    response.headers["Content-Security-Policy"]="default-src 'self'; img-src 'self' data: https: http:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if request.is_secure:
        response.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"]="no-store"
    return response

@app.get("/")
def home():
    return render_template_string(HTML)


@app.get("/api/bot/v1/me")
@bot_auth_required
def bot_api_me():
    return jsonify(bot=request.bot)


@app.get("/api/bot/v1/servers")
@bot_auth_required
def bot_api_servers():
    with connect() as c:
        rows=c.execute("""
            select s.id,s.name,s.icon,bi.permissions
            from bot_server_installs bi
            join servers s on s.id=bi.server_id
            where bi.bot_id=%s
            order by lower(s.name)
        """,(request.bot["id"],)).fetchall()

    return jsonify(servers=[{
        "id":r[0],
        "name":r[1],
        "icon":r[2],
        "permissions":list(r[3] or [])
    } for r in rows])


@app.get("/api/bot/v1/servers/<int:sid>/channels")
@bot_auth_required
def bot_api_channels(sid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "view_channels" not in perms:
        return jsonify(error="Bot lacks View Channels permission"),403

    with connect() as c:
        rows=c.execute("""
            select id,name,kind,position
            from server_channels
            where server_id=%s
            order by position,id
        """,(sid,)).fetchall()

    return jsonify(channels=[{
        "id":r[0],"name":r[1],"kind":r[2],"position":r[3]
    } for r in rows])


@app.get("/api/bot/v1/channels/<int:cid>/messages")
@bot_auth_required
def bot_api_channel_messages(cid):
    with connect() as c:
        channel=c.execute(
            "select server_id from server_channels where id=%s",
            (cid,)
        ).fetchone()
        if not channel:
            return jsonify(error="Channel not found"),404

        sid=channel[0]
        perms=bot_install_permissions(request.bot["id"],sid)
        if "view_channels" not in perms or "read_messages" not in perms:
            return jsonify(error="Bot lacks message read permissions"),403

        rows=c.execute("""
            select m.id,m.content,m.created_at,
                   case
                     when m.bot_id is not null then b.name
                     when m.is_spookhook then m.hook_name
                     else u.username
                   end as username,
                   m.bot_id
            from messages m
            join users u on u.id=m.user_id
            left join vyntra_bots b on b.id=m.bot_id
            where m.kind='server' and m.server_id=%s and m.channel=%s
            order by m.created_at desc
            limit 100
        """,(sid,str(cid))).fetchall()

    return jsonify(messages=[{
        "id":r[0],
        "content":r[1],
        "created_at":r[2].isoformat(),
        "username":r[3],
        "is_bot":bool(r[4])
    } for r in reversed(rows)])


@app.post("/api/bot/v1/channels/<int:cid>/messages")
@bot_auth_required
def bot_api_send_message(cid):
    d=request.get_json(silent=True) or {}
    content=str(d.get("content","")).strip()
    reply_to_id=d.get("reply_to_id")

    if not content or len(content)>4000:
        return jsonify(error="Message must be 1-4000 characters"),400

    try:
        reply_to_id=int(reply_to_id) if reply_to_id else None
    except Exception:
        reply_to_id=None

    with connect() as c:
        channel=c.execute(
            "select server_id from server_channels where id=%s",
            (cid,)
        ).fetchone()
        if not channel:
            return jsonify(error="Channel not found"),404

        sid=channel[0]
        perms=bot_install_permissions(request.bot["id"],sid)

        if "view_channels" not in perms or "send_messages" not in perms:
            return jsonify(error="Bot lacks Send Messages permission"),403

        if reply_to_id:
            reply=c.execute("""
                select 1
                from messages
                where id=%s and kind='server' and server_id=%s and channel=%s
            """,(reply_to_id,sid,str(cid))).fetchone()
            if not reply:
                return jsonify(error="Reply target is not in this channel"),400

        mid=c.execute("""
            insert into messages(
                user_id,content,kind,channel,server_id,reply_to_id,bot_id
            )
            values(%s,%s,'server',%s,%s,%s,%s)
            returning id
        """,(
            request.bot["owner_id"],content,str(cid),sid,reply_to_id,request.bot["id"]
        )).fetchone()[0]
        c.commit()

    return jsonify(id=mid)


@app.delete("/api/bot/v1/messages/<int:mid>")
@bot_auth_required
def bot_api_delete_message(mid):
    with connect() as c:
        row=c.execute("""
            select server_id,bot_id
            from messages
            where id=%s and kind='server'
        """,(mid,)).fetchone()
        if not row:
            return jsonify(error="Message not found"),404

        perms=bot_install_permissions(request.bot["id"],row[0])
        owns=bool(row[1] and row[1]==request.bot["id"])

        if not owns and "manage_messages" not in perms:
            return jsonify(error="Bot lacks Manage Messages permission"),403

        c.execute("delete from messages where id=%s",(mid,))
        c.commit()

    return jsonify(ok=True)


@app.post("/api/bot/v1/messages/<int:mid>/reactions")
@bot_auth_required
def bot_api_react(mid):
    d=request.get_json(silent=True) or {}
    emoji=str(d.get("emoji","")).strip()[:16]
    allowed={"👍","❤️","😂","🔥","🎉","👻","💜","✅","❌"}
    if emoji not in allowed:
        return jsonify(error="Invalid reaction"),400

    with connect() as c:
        row=c.execute(
            "select server_id from messages where id=%s and kind='server'",
            (mid,)
        ).fetchone()
        if not row:
            return jsonify(error="Message not found"),404

        perms=bot_install_permissions(request.bot["id"],row[0])
        if "add_reactions" not in perms:
            return jsonify(error="Bot lacks Add Reactions permission"),403

        # Bot reactions use the bot owner's user id plus bot identity isn't stored
        # in the reaction table, so a bot can toggle one reaction per owner account.
        existing=c.execute("""
            select 1 from message_reactions
            where message_id=%s and user_id=%s and emoji=%s
        """,(mid,request.bot["owner_id"],emoji)).fetchone()

        if existing:
            c.execute("""
                delete from message_reactions
                where message_id=%s and user_id=%s and emoji=%s
            """,(mid,request.bot["owner_id"],emoji))
            added=False
        else:
            c.execute("""
                insert into message_reactions(message_id,user_id,emoji)
                values(%s,%s,%s)
            """,(mid,request.bot["owner_id"],emoji))
            added=True
        c.commit()

    return jsonify(ok=True,added=added)



@app.post("/api/bot/v1/servers/<int:sid>/channels")
@bot_auth_required
def bot_api_create_channel(sid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "manage_channels" not in perms:
        return jsonify(error="Bot lacks Manage Channels permission"),403

    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip().lower().replace(" ","-")[:40]
    kind=str(d.get("kind","chat"))

    if not name:
        return jsonify(error="Channel name required"),400
    if kind not in ("chat","announcement"):
        return jsonify(error="Invalid channel type"),400

    with connect() as c:
        installed=c.execute("""
            select 1 from bot_server_installs
            where bot_id=%s and server_id=%s
        """,(request.bot["id"],sid)).fetchone()
        if not installed:
            return jsonify(error="Bot is not installed in this server"),403

        pos=c.execute(
            "select coalesce(max(position),0)+1 from server_channels where server_id=%s",
            (sid,)
        ).fetchone()[0]

        cid=c.execute("""
            insert into server_channels(server_id,name,kind,position)
            values(%s,%s,%s,%s)
            returning id
        """,(sid,name,kind,pos)).fetchone()[0]
        c.commit()

    return jsonify(id=cid,name=name,kind=kind)


@app.patch("/api/bot/v1/channels/<int:cid>")
@bot_auth_required
def bot_api_edit_channel(cid):
    d=request.get_json(silent=True) or {}

    with connect() as c:
        row=c.execute(
            "select server_id,name from server_channels where id=%s",
            (cid,)
        ).fetchone()
        if not row:
            return jsonify(error="Channel not found"),404

        sid=row[0]
        perms=bot_install_permissions(request.bot["id"],sid)
        if "manage_channels" not in perms:
            return jsonify(error="Bot lacks Manage Channels permission"),403

        name=str(d.get("name",row[1])).strip().lower().replace(" ","-")[:40]
        if not name:
            return jsonify(error="Channel name required"),400

        c.execute(
            "update server_channels set name=%s where id=%s",
            (name,cid)
        )
        c.commit()

    return jsonify(ok=True,name=name)


@app.delete("/api/bot/v1/channels/<int:cid>")
@bot_auth_required
def bot_api_delete_channel(cid):
    with connect() as c:
        row=c.execute(
            "select server_id from server_channels where id=%s",
            (cid,)
        ).fetchone()
        if not row:
            return jsonify(error="Channel not found"),404

        sid=row[0]
        perms=bot_install_permissions(request.bot["id"],sid)
        if "manage_channels" not in perms:
            return jsonify(error="Bot lacks Manage Channels permission"),403

        count=c.execute(
            "select count(*) from server_channels where server_id=%s",
            (sid,)
        ).fetchone()[0]

        if count<=1:
            return jsonify(error="A server must keep at least one channel"),400

        c.execute("delete from server_channels where id=%s",(cid,))
        c.commit()

    return jsonify(ok=True)


@app.get("/api/bot/v1/servers/<int:sid>/roles")
@bot_auth_required
def bot_api_roles(sid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "manage_roles" not in perms:
        return jsonify(error="Bot lacks Manage Roles permission"),403

    with connect() as c:
        rows=c.execute("""
            select id,name,permissions
            from server_roles
            where server_id=%s
            order by id
        """,(sid,)).fetchall()

    return jsonify(roles=[
        {"id":r[0],"name":r[1],"permissions":r[2] or {}}
        for r in rows
    ])


@app.post("/api/bot/v1/servers/<int:sid>/roles")
@bot_auth_required
def bot_api_create_role(sid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "manage_roles" not in perms:
        return jsonify(error="Bot lacks Manage Roles permission"),403

    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip()[:30]
    raw=d.get("permissions") or {}

    if not name:
        return jsonify(error="Role name required"),400

    role_perms={
        k:bool(raw.get(k,False))
        for k in SERVER_PERMISSION_KEYS
    } if isinstance(raw,dict) else {}

    with connect() as c:
        rid=c.execute("""
            insert into server_roles(server_id,name,permissions)
            values(%s,%s,%s)
            returning id
        """,(sid,name,psycopg.types.json.Jsonb(role_perms))).fetchone()[0]
        c.commit()

    return jsonify(id=rid)


@app.patch("/api/bot/v1/servers/<int:sid>/roles/<int:rid>")
@bot_auth_required
def bot_api_edit_role(sid,rid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "manage_roles" not in perms:
        return jsonify(error="Bot lacks Manage Roles permission"),403

    d=request.get_json(silent=True) or {}

    with connect() as c:
        old=c.execute(
            "select name,permissions from server_roles where id=%s and server_id=%s",
            (rid,sid)
        ).fetchone()
        if not old:
            return jsonify(error="Role not found"),404

        name=str(d.get("name",old[0])).strip()[:30]
        raw=d.get("permissions",old[1] or {})
        role_perms={
            k:bool(raw.get(k,False))
            for k in SERVER_PERMISSION_KEYS
        } if isinstance(raw,dict) else old[1]

        c.execute("""
            update server_roles
            set name=%s,permissions=%s
            where id=%s and server_id=%s
        """,(name,psycopg.types.json.Jsonb(role_perms),rid,sid))
        c.commit()

    return jsonify(ok=True)


@app.delete("/api/bot/v1/servers/<int:sid>/roles/<int:rid>")
@bot_auth_required
def bot_api_delete_role(sid,rid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "manage_roles" not in perms:
        return jsonify(error="Bot lacks Manage Roles permission"),403

    with connect() as c:
        c.execute(
            "delete from server_roles where id=%s and server_id=%s",
            (rid,sid)
        )
        c.commit()

    return jsonify(ok=True)


@app.get("/api/bot/v1/servers/<int:sid>/members")
@bot_auth_required
def bot_api_members(sid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "manage_members" not in perms and "view_channels" not in perms:
        return jsonify(error="Bot lacks member access permission"),403

    with connect() as c:
        rows=c.execute("""
            select u.id,u.username,u.avatar,sm.role,sm.muted_until,sm.banned_until
            from server_members sm
            join users u on u.id=sm.user_id
            where sm.server_id=%s
            order by lower(u.username)
        """,(sid,)).fetchall()

    now=datetime.now(timezone.utc)

    return jsonify(members=[
        {
            "id":r[0],
            "username":r[1],
            "avatar":r[2],
            "role":r[3],
            "muted":bool(r[4] and r[4]>now),
            "banned":bool(r[5] and r[5]>now)
        }
        for r in rows
    ])



@app.post("/api/bot/v1/servers/<int:sid>/members/<int:uid>/moderate")
@bot_auth_required
def bot_api_moderate_member(sid,uid):
    d=request.get_json(silent=True) or {}
    action=str(d.get("action","")).lower().strip()

    if action not in ("mute","unmute","ban","unban"):
        return jsonify(error="Invalid moderation action"),400

    required={
        "mute":"mute_members",
        "unmute":"mute_members",
        "ban":"ban_members",
        "unban":"ban_members"
    }[action]

    perms=bot_install_permissions(request.bot["id"],sid)

    if required not in perms:
        return jsonify(
            error=f"Bot lacks {required.replace('_',' ').title()} permission"
        ),403

    try:
        mins=max(1,min(int(d.get("minutes") or 60),525600))
    except Exception:
        mins=60

    until=datetime.now(timezone.utc)+timedelta(minutes=mins)

    with connect() as c:
        if action=="unban":
            unban_server_user(sid,uid,c)
            c.commit()
            return jsonify(ok=True,action="unban")

        target=c.execute("""
            select role
            from server_members
            where server_id=%s and user_id=%s
        """,(sid,uid)).fetchone()

        if not target:
            return jsonify(error="Member not found"),404

        if target[0]=="owner":
            return jsonify(error="Cannot moderate the server owner"),403

        if action=="ban":
            ok,error=ban_server_user(
                sid,uid,request.bot["owner_id"],until,c
            )

            if not ok:
                return jsonify(error=error),403

            c.commit()

            return jsonify(
                ok=True,
                action="ban",
                removed_from_server=True,
                until=until.isoformat()
            )

        if action=="mute":
            c.execute("""
                update server_members
                set muted_until=%s
                where server_id=%s and user_id=%s
            """,(until,sid,uid))
        else:
            c.execute("""
                update server_members
                set muted_until=null
                where server_id=%s and user_id=%s
            """,(sid,uid))

        c.commit()

    return jsonify(ok=True,action=action)

@app.post("/api/bot/v1/servers/<int:sid>/members/<int:uid>/mute")
@bot_auth_required
def bot_api_mute_member(sid,uid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "mute_members" not in perms:
        return jsonify(error="Bot lacks Mute Members permission"),403

    d=request.get_json(silent=True) or {}
    mins=max(1,min(int(d.get("minutes") or 60),525600))
    until=datetime.now(timezone.utc)+timedelta(minutes=mins)

    with connect() as c:
        target=c.execute(
            "select role from server_members where server_id=%s and user_id=%s",
            (sid,uid)
        ).fetchone()
        if not target:
            return jsonify(error="Member not found"),404
        if target[0]=="owner":
            return jsonify(error="Cannot mute the server owner"),403

        c.execute("""
            update server_members
            set muted_until=%s
            where server_id=%s and user_id=%s
        """,(until,sid,uid))
        c.commit()

    return jsonify(ok=True,muted_until=until.isoformat())


@app.post("/api/bot/v1/servers/<int:sid>/members/<int:uid>/unmute")
@bot_auth_required
def bot_api_unmute_member(sid,uid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "mute_members" not in perms:
        return jsonify(error="Bot lacks Mute Members permission"),403

    with connect() as c:
        c.execute("""
            update server_members
            set muted_until=null
            where server_id=%s and user_id=%s
        """,(sid,uid))
        c.commit()

    return jsonify(ok=True)


@app.post("/api/bot/v1/servers/<int:sid>/members/<int:uid>/ban")
@bot_auth_required
def bot_api_ban_member(sid,uid):
    perms=bot_install_permissions(request.bot["id"],sid)

    if "ban_members" not in perms:
        return jsonify(error="Bot lacks Ban Members permission"),403

    d=request.get_json(silent=True) or {}

    try:
        mins=max(1,min(int(d.get("minutes") or 525600),525600))
    except Exception:
        mins=525600

    until=datetime.now(timezone.utc)+timedelta(minutes=mins)

    with connect() as c:
        ok,error=ban_server_user(
            sid,uid,request.bot["owner_id"],until,c
        )

        if not ok:
            return jsonify(
                error=error
            ),404 if error=="Member not found" else 403

        c.commit()

    return jsonify(
        ok=True,
        removed_from_server=True,
        banned_until=until.isoformat()
    )


@app.post("/api/bot/v1/servers/<int:sid>/members/<int:uid>/unban")
@bot_auth_required
def bot_api_unban_member(sid,uid):
    perms=bot_install_permissions(request.bot["id"],sid)

    if "ban_members" not in perms:
        return jsonify(error="Bot lacks Ban Members permission"),403

    with connect() as c:
        unban_server_user(sid,uid,c)
        c.commit()

    return jsonify(ok=True)


@app.get("/api/bot/v1/servers/<int:sid>/bans")
@bot_auth_required
def bot_api_bans(sid):
    perms=bot_install_permissions(request.bot["id"],sid)

    if "ban_members" not in perms:
        return jsonify(error="Bot lacks Ban Members permission"),403

    with connect() as c:
        c.execute("""
            delete from server_bans
            where server_id=%s
              and banned_until is not null
              and banned_until<=now()
        """,(sid,))

        rows=c.execute("""
            select sb.user_id,u.username,sb.banned_until
            from server_bans sb
            join users u on u.id=sb.user_id
            where sb.server_id=%s
            order by lower(u.username)
        """,(sid,)).fetchall()

        c.commit()

    return jsonify(bans=[{
        "user_id":r[0],
        "username":r[1],
        "banned_until":r[2].isoformat() if r[2] else None
    } for r in rows])

@app.patch("/api/bot/v1/servers/<int:sid>")
@bot_auth_required
def bot_api_edit_server(sid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "manage_server" not in perms:
        return jsonify(error="Bot lacks Manage Server permission"),403

    d=request.get_json(silent=True) or {}

    with connect() as c:
        old=c.execute(
            "select name,icon from servers where id=%s",
            (sid,)
        ).fetchone()
        if not old:
            return jsonify(error="Server not found"),404

        name=str(d.get("name",old[0])).strip()[:60]
        icon=str(d.get("icon",old[1] or "")).strip()[:1000]

        if not name:
            return jsonify(error="Server name required"),400

        c.execute(
            "update servers set name=%s,icon=%s where id=%s",
            (name,icon,sid)
        )
        c.commit()

    return jsonify(ok=True)


@app.post("/api/bot/v1/servers/<int:sid>/invites")
@bot_auth_required
def bot_api_create_invite(sid):
    perms=bot_install_permissions(request.bot["id"],sid)
    if "invite_members" not in perms:
        return jsonify(error="Bot lacks Invite Members permission"),403

    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    for _ in range(10):
        code="".join(secrets.choice(alphabet) for _ in range(8))
        try:
            with connect() as c:
                c.execute("""
                    insert into server_invites(server_id,created_by,code)
                    values(%s,%s,%s)
                """,(sid,request.bot["owner_id"],code))
                c.commit()

            return jsonify(
                code=code,
                url=request.host_url.rstrip("/")+"/invite/"+code
            )
        except psycopg.errors.UniqueViolation:
            continue

    return jsonify(error="Could not create invite"),500


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
            required = {"id","email","username","password_hash","global_role","banned_until","last_ip","device_type","theme","show_staff_tag","session_version"}
            missing = sorted(required - names)
        return jsonify(ok=(len(missing)==0), database=True, missing_columns=missing), (200 if not missing else 500)
    except Exception as e:
        return jsonify(ok=False, database=False, error=str(e)), 500


@app.get("/api/site-status")
def site_status():
    s=get_site_settings()
    return jsonify(
        maintenance_mode=s["maintenance_mode"],
        maintenance_message=s["maintenance_message"],
        registrations_enabled=s["registrations_enabled"],
        site_name=s["site_name"],
        announcement=s["announcement"],
        public_channels_locked=s["public_channels_locked"],
        public_embeds_enabled=s["public_embeds_enabled"]
    )

@app.post("/api/register")
def register():
    settings=get_site_settings()
    if not settings["registrations_enabled"]:
        return jsonify(error="New registrations are currently disabled."),403
    if settings["maintenance_mode"]:
        return jsonify(error=settings["maintenance_message"]),503
    if ip_is_banned(client_ip()):
        return jsonify(error="This IP address is banned."), 403
    d = request.get_json(silent=True) or {}
    email = str(d.get("email","")).strip().lower()[:254]
    username = " ".join(str(d.get("username","")).strip().split())
    password = str(d.get("password",""))
    email_ok = bool(re_lib.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email))
    username_ok = 2 <= len(username) <= 32 and not any(ord(ch) < 32 for ch in username)
    if not email_ok or not username_ok or len(password) < 8 or len(password) > 256:
        return jsonify(error="Use a valid email, a 2-32 character username, and an 8+ character password."), 400
    try:
        with connect() as c:
            count = c.execute("select count(*) from users").fetchone()[0]
            role = "owner" if count == 0 else "user"
            uid = c.execute("""
                insert into users(email,username,password_hash,global_role,last_ip)
                values(%s,%s,%s,%s,%s) returning id
            """, (email, username, generate_password_hash(password), role, client_ip())).fetchone()[0]
            c.commit()
        session.clear()
        session["uid"] = uid
        session["session_version"] = 1
        session.permanent=True
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
            select id,password_hash,banned_until,session_version from users where lower(email)=lower(%s)
        """, (str(d.get("email","")).strip(),)).fetchone()
    if not r or not check_password_hash(r[1], str(d.get("password",""))):
        return jsonify(error="Invalid email or password"), 401
    if r[2] and r[2] > datetime.now(timezone.utc):
        return jsonify(error="Account is banned."), 403
    session.clear()
    session["uid"] = r[0]
    session["session_version"] = int(r[3] or 1)
    session.permanent=True
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
    settings = get_site_settings()
    is_app_staff = u["global_role"] in ("moderator","admin","owner")
    return jsonify(
        user={"id":u["id"],"email":u["email"]},
        profile={k:u[k] for k in ["id","username","description","avatar","pronouns","company","global_role","device_type","theme","show_staff_tag"]},
        maintenance=bool(settings["maintenance_mode"] and not is_app_staff),
        maintenance_message=settings["maintenance_message"]
    )

@app.get("/api/profile/<int:uid>")
@login_required
def profile_get(uid):
    u = row_user(uid)
    if not u:
        return jsonify(error="User not found"), 404

    profile={k:u[k] for k in [
        "id","username","description","avatar","pronouns","company",
        "global_role","device_type","theme","show_staff_tag"
    ]}

    presence=presence_payload(u["last_seen"])
    profile["online"]=presence["online"]
    profile["last_seen"]=presence["last_seen"]
    profile["server_role"]=None
    profile["server_roles"]=[]

    sid=request.args.get("server_id")
    if sid:
        try:
            sid=int(sid)
        except Exception:
            sid=None

    if sid and server_member(sid,request.me["id"]):
        with connect() as c:
            builtin=c.execute("""
                select role
                from server_members
                where server_id=%s and user_id=%s
            """,(sid,uid)).fetchone()

            roles=c.execute("""
                select sr.id,sr.name
                from server_member_roles smr
                join server_roles sr on sr.id=smr.role_id
                where smr.server_id=%s and smr.user_id=%s
                order by lower(sr.name),sr.id
            """,(sid,uid)).fetchall()

        if builtin:
            profile["server_role"]=builtin[0]

        profile["server_roles"]=[
            {"id":r[0],"name":r[1]}
            for r in roles
        ]


    profile["friend_status"]="self" if uid==request.me["id"] else "none"

    if uid!=request.me["id"]:
        a,b=sorted([int(request.me["id"]),int(uid)])

        with connect() as c:
            fr=c.execute("""
                select status
                from friends
                where user_a=%s and user_b=%s
                limit 1
            """,(a,b)).fetchone()

        if fr and str(fr[0] or "").lower()=="accepted":
            profile["friend_status"]="friends"

    return jsonify(profile=profile)

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
    if len(password) < 8 or len(password) > 256:
        return jsonify(error="Password must be 8-256 characters."), 400
    with connect() as c:
        new_version=c.execute("update users set password_hash=%s,session_version=session_version+1 where id=%s returning session_version", (generate_password_hash(password), request.me["id"])).fetchone()[0]
        c.commit()
    session["session_version"]=int(new_version)
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



@app.get("/api/bots")
@login_required
def bots_list():
    with connect() as c:
        rows=c.execute("""
            select id,public_id,name,description,avatar,requested_permissions,created_at,
                   (select count(*) from bot_server_installs bi where bi.bot_id=b.id)
            from vyntra_bots b
            where owner_id=%s
            order by created_at desc
        """,(request.me["id"],)).fetchall()

    base=request.host_url.rstrip("/")
    return jsonify(bots=[{
        "id":r[0],
        "public_id":r[1],
        "name":r[2],
        "description":r[3],
        "avatar":r[4],
        "permissions":list(r[5] or []),
        "created_at":r[6].isoformat(),
        "server_count":r[7],
        "invite_url":f"{base}/?bot_invite={r[1]}"
    } for r in rows],permission_keys=BOT_PERMISSION_KEYS)


@app.post("/api/bots")
@login_required
def bot_create():
    d=request.get_json(silent=True) or {}
    name=" ".join(str(d.get("name","")).strip().split())[:40]
    description=str(d.get("description","")).strip()[:240]
    avatar=str(d.get("avatar","")).strip()[:1000]
    perms=sorted(normalize_bot_permissions(d.get("permissions") or []))

    if len(name)<2:
        return jsonify(error="Bot name must be at least 2 characters."),400

    public_id=secrets.token_urlsafe(10).replace("-","").replace("_","")[:16]
    token=create_bot_token()

    with connect() as c:
        bid=c.execute("""
            insert into vyntra_bots(
                owner_id,public_id,name,description,avatar,token_hash,requested_permissions
            )
            values(%s,%s,%s,%s,%s,%s,%s)
            returning id
        """,(
            request.me["id"],public_id,name,description,avatar,
            bot_token_hash(token),psycopg.types.json.Jsonb(perms)
        )).fetchone()[0]
        c.commit()

    return jsonify(
        id=bid,
        public_id=public_id,
        token=token,
        invite_url=request.host_url.rstrip("/")+"/?bot_invite="+public_id
    )


@app.patch("/api/bots/<int:bid>")
@login_required
def bot_edit(bid):
    d=request.get_json(silent=True) or {}
    with connect() as c:
        old=c.execute("""
            select name,description,avatar,requested_permissions
            from vyntra_bots
            where id=%s and owner_id=%s
        """,(bid,request.me["id"])).fetchone()
        if not old:
            return jsonify(error="Bot not found"),404

        name=" ".join(str(d.get("name",old[0])).strip().split())[:40]
        description=str(d.get("description",old[1])).strip()[:240]
        avatar=str(d.get("avatar",old[2])).strip()[:1000]
        raw=d.get("permissions",old[3] or [])
        perms=sorted(normalize_bot_permissions(raw))

        if len(name)<2:
            return jsonify(error="Bot name must be at least 2 characters."),400

        c.execute("""
            update vyntra_bots
            set name=%s,description=%s,avatar=%s,requested_permissions=%s
            where id=%s and owner_id=%s
        """,(name,description,avatar,psycopg.types.json.Jsonb(perms),bid,request.me["id"]))
        c.commit()

    return jsonify(ok=True)


@app.post("/api/bots/<int:bid>/reset-token")
@login_required
def bot_reset_token(bid):
    token=create_bot_token()
    with connect() as c:
        exists=c.execute(
            "select 1 from vyntra_bots where id=%s and owner_id=%s",
            (bid,request.me["id"])
        ).fetchone()
        if not exists:
            return jsonify(error="Bot not found"),404

        c.execute(
            "update vyntra_bots set token_hash=%s where id=%s",
            (bot_token_hash(token),bid)
        )
        c.commit()

    return jsonify(token=token)


@app.delete("/api/bots/<int:bid>")
@login_required
def bot_delete(bid):
    with connect() as c:
        c.execute(
            "delete from vyntra_bots where id=%s and owner_id=%s",
            (bid,request.me["id"])
        )
        c.commit()
    return jsonify(ok=True)


@app.get("/api/bots/invite/<public_id>")
@login_required
def bot_invite_info(public_id):
    with connect() as c:
        bot=c.execute("""
            select id,public_id,name,description,avatar,requested_permissions
            from vyntra_bots
            where public_id=%s
        """,(public_id,)).fetchone()
        if not bot:
            return jsonify(error="Bot invite not found"),404

        servers=c.execute("""
            select s.id,s.name,s.icon,
                   exists(
                     select 1 from bot_server_installs bi
                     where bi.bot_id=%s and bi.server_id=s.id
                   )
            from servers s
            join server_members sm on sm.server_id=s.id
            where sm.user_id=%s
            order by lower(s.name)
        """,(bot[0],request.me["id"])).fetchall()

    eligible=[]
    for s in servers:
        if can_install_bot_to_server(s[0],request.me["id"]):
            eligible.append({
                "id":s[0],
                "name":s[1],
                "icon":s[2],
                "installed":bool(s[3])
            })

    return jsonify(
        bot={
            "id":bot[0],
            "public_id":bot[1],
            "name":bot[2],
            "description":bot[3],
            "avatar":bot[4],
            "permissions":list(bot[5] or [])
        },
        servers=eligible
    )


@app.post("/api/bots/invite/<public_id>/install")
@login_required
def bot_install(public_id):
    d=request.get_json(silent=True) or {}
    try:
        sid=int(d.get("server_id"))
    except Exception:
        return jsonify(error="Choose a server"),400

    if not can_install_bot_to_server(sid,request.me["id"]):
        return jsonify(error="You need server Admin permissions to add a bot."),403

    with connect() as c:
        bot=c.execute("""
            select id,requested_permissions
            from vyntra_bots
            where public_id=%s
        """,(public_id,)).fetchone()
        if not bot:
            return jsonify(error="Bot invite not found"),404

        requested=set(bot[1] or [])
        perms=sorted(normalize_bot_permissions(requested))

        # Keep Administrator explicitly stored so the UI can show that this
        # bot was installed as a server admin bot.
        if "administrator" in requested and "administrator" not in perms:
            perms.insert(0,"administrator")

        c.execute("""
            insert into bot_server_installs(
                bot_id,server_id,installed_by,permissions
            )
            values(%s,%s,%s,%s)
            on conflict(bot_id,server_id)
            do update set
                installed_by=excluded.installed_by,
                permissions=excluded.permissions,
                installed_at=now()
        """,(bot[0],sid,request.me["id"],psycopg.types.json.Jsonb(perms)))
        c.commit()

    return jsonify(ok=True,server_id=sid)



@app.get("/api/servers/<int:sid>/bots/<int:bid>/permissions")
@login_required
def server_bot_permissions_get(sid,bid):
    if not server_member(sid,request.me["id"]):
        return jsonify(error="Not a server member"),403

    with connect() as c:
        row=c.execute("""
            select b.id,b.name,b.avatar,bi.permissions
            from bot_server_installs bi
            join vyntra_bots b on b.id=bi.bot_id
            where bi.server_id=%s and bi.bot_id=%s
        """,(sid,bid)).fetchone()

    if not row:
        return jsonify(error="Bot is not installed in this server"),404

    return jsonify(
        bot={
            "id":row[0],
            "name":row[1],
            "avatar":row[2],
            "permissions":list(row[3] or [])
        },
        permission_keys=BOT_PERMISSION_KEYS
    )


@app.patch("/api/servers/<int:sid>/bots/<int:bid>")
@login_required
def server_bot_permissions_edit(sid,bid):
    if not can_install_bot_to_server(sid,request.me["id"]):
        return jsonify(error="You need server Admin permissions to edit bot permissions."),403

    d=request.get_json(silent=True) or {}
    requested=set(d.get("permissions") or [])
    perms=sorted(normalize_bot_permissions(requested))

    if "administrator" in requested and "administrator" not in perms:
        perms.insert(0,"administrator")

    with connect() as c:
        exists=c.execute("""
            select 1 from bot_server_installs
            where bot_id=%s and server_id=%s
        """,(bid,sid)).fetchone()

        if not exists:
            return jsonify(error="Bot is not installed in this server"),404

        c.execute("""
            update bot_server_installs
            set permissions=%s
            where bot_id=%s and server_id=%s
        """,(psycopg.types.json.Jsonb(perms),bid,sid))
        c.commit()

    return jsonify(ok=True,permissions=perms)

@app.delete("/api/servers/<int:sid>/bots/<int:bid>")
@login_required
def bot_uninstall(sid,bid):
    if not can_install_bot_to_server(sid,request.me["id"]):
        return jsonify(error="You need server Admin permissions to remove bots."),403

    with connect() as c:
        c.execute(
            "delete from bot_server_installs where bot_id=%s and server_id=%s",
            (bid,sid)
        )
        c.commit()
    return jsonify(ok=True)


@app.get("/api/servers/<int:sid>/bots")
@login_required
def server_bots_list(sid):
    if not server_member(sid,request.me["id"]):
        return jsonify(error="Not a server member"),403

    with connect() as c:
        rows=c.execute("""
            select b.id,b.public_id,b.name,b.description,b.avatar,bi.permissions,bi.installed_at
            from bot_server_installs bi
            join vyntra_bots b on b.id=bi.bot_id
            where bi.server_id=%s
            order by lower(b.name)
        """,(sid,)).fetchall()

    return jsonify(bots=[{
        "id":r[0],
        "public_id":r[1],
        "name":r[2],
        "description":r[3],
        "avatar":r[4],
        "permissions":list(r[5] or []),
        "installed_at":r[6].isoformat()
    } for r in rows])


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
            select role from server_members
            where server_id=%s and user_id=%s
        """, (sid,request.me["id"])).fetchone()

        if existing:
            return jsonify(ok=True, already_joined=True)

        ban_until = active_server_ban(sid, request.me["id"], c)
        if ban_until is not None:
            return jsonify(
                error="You are banned from this server.",
                banned=True,
                banned_until=ban_until.isoformat() if ban_until else None
            ), 403

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
        if request.me["global_role"]=="owner":
            rows=c.execute("""
                select s.id,s.name,s.icon,'owner' as role,
                       (select count(*) from server_members x where x.server_id=s.id) as member_count
                from servers s
                order by s.created_at
            """).fetchall()
        else:
            rows=c.execute("""
                select s.id,s.name,s.icon,sm.role,
                       (select count(*) from server_members x where x.server_id=s.id) as member_count
                from servers s
                join server_members sm on sm.server_id=s.id
                where sm.user_id=%s
                order by s.created_at
            """,(request.me["id"],)).fetchall()

    return jsonify(servers=[
        {
            "id":r[0],
            "name":r[1],
            "icon":r[2],
            "role":r[3],
            "member_count":r[4],
            "global_owner_access":request.me["global_role"]=="owner"
        }
        for r in rows
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


@app.get("/api/servers/<int:sid>/bootstrap")
@login_required
def server_bootstrap(sid):
    now=datetime.now(timezone.utc)

    with connect() as c:
        if request.me["global_role"]=="owner":
            member=("owner",None,None,None)
        else:
            member=c.execute("""
                select role,banned_until,muted_until,joined_at
                from server_members
                where server_id=%s and user_id=%s
            """,(sid,request.me["id"])).fetchone()

            if not member:
                return jsonify(error="Not a server member"),403

        server=c.execute("""
            select s.id,s.name,s.icon,s.owner_id,s.privacy_mode,
                   (select count(*) from server_members sm where sm.server_id=s.id)
            from servers s
            where s.id=%s
        """,(sid,)).fetchone()

        if not server:
            return jsonify(error="Server not found"),404

        member_rows=c.execute("""
            select u.id,u.username,u.avatar,sm.role,sm.muted_until,sm.banned_until,
                   u.device_type,u.last_seen
            from server_members sm
            join users u on u.id=sm.user_id
            where sm.server_id=%s
            order by
              case sm.role
                when 'owner' then 3
                when 'admin' then 2
                when 'moderator' then 1
                else 0
              end desc,
              lower(u.username)
        """,(sid,)).fetchall()

        role_rows=c.execute("""
            select id,name,permissions
            from server_roles
            where server_id=%s
            order by id
        """,(sid,)).fetchall()

        all_member_role_rows=c.execute("""
            select smr.user_id,sr.id,sr.name,sr.permissions
            from server_member_roles smr
            join server_roles sr on sr.id=smr.role_id
            where smr.server_id=%s
            order by smr.user_id,sr.id
        """,(sid,)).fetchall()

        bot_rows=c.execute("""
            select b.id,b.public_id,b.name,b.avatar,bi.permissions
            from bot_server_installs bi
            join vyntra_bots b on b.id=bi.bot_id
            where bi.server_id=%s
            order by lower(b.name)
        """,(sid,)).fetchall()

        custom_for_viewer=c.execute("""
            select sr.id,sr.permissions
            from server_member_roles smr
            join server_roles sr on sr.id=smr.role_id
            where smr.server_id=%s and smr.user_id=%s
        """,(sid,request.me["id"])).fetchall()

        channel_rows=c.execute("""
            select id,name,kind,position
            from server_channels
            where server_id=%s
            order by position,id
        """,(sid,)).fetchall()

        # Pull all channel overrides once, not once per channel.
        channel_ids=[r[0] for r in channel_rows]
        override_rows=[]
        if channel_ids:
            override_rows=c.execute("""
                select channel_id,role_key,allow_permissions,deny_permissions
                from channel_role_overrides
                where channel_id=any(%s)
            """,(channel_ids,)).fetchall()

    sm_role=member[0]

    base=set(BUILTIN_SERVER_PERMISSIONS.get(sm_role,set()))
    role_keys={sm_role}

    if sm_role=="owner":
        base=set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)|{"delete_server"}
    else:
        for rid,raw in custom_for_viewer:
            role_keys.add(f"custom:{rid}")
            rp=normalize_permissions(raw)
            if "administrator" in rp:
                base|=set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)
            base|=(rp-{"administrator"})

    override_map={}
    for cid,role_key,allow,deny in override_rows:
        if role_key not in role_keys:
            continue
        slot=override_map.setdefault(cid,{"allow":set(),"deny":set()})
        slot["allow"]|=set(allow or [])
        slot["deny"]|=set(deny or [])

    channels=[]
    for cid,name,kind,position in channel_rows:
        perms=set(base)
        ov=override_map.get(cid)
        if ov:
            perms-=ov["deny"]
            perms|=ov["allow"]

        if sm_role=="owner" or "view_channels" in perms:
            channels.append({
                "id":cid,
                "name":name,
                "kind":kind,
                "position":position,
                "can_send":sm_role=="owner" or "send_messages" in perms
            })

    member_custom={}
    for user_id,role_id,role_name,raw_perms in all_member_role_rows:
        member_custom.setdefault(user_id,[]).append({
            "id":role_id,
            "name":role_name,
            "permissions":raw_perms or {}
        })

    all_overrides={}
    for cid,role_key,allow,deny in override_rows:
        slot=all_overrides.setdefault(cid,{})
        slot[role_key]={
            "allow":set(allow or []),
            "deny":set(deny or [])
        }

    members=[]

    for r in member_rows:
        uid=r[0]
        builtin=r[3]
        custom_roles=member_custom.get(uid,[])

        if builtin=="owner":
            base_perms=set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)|{"delete_server"}
        else:
            base_perms=set(BUILTIN_SERVER_PERMISSIONS.get(builtin,set()))
            for cr in custom_roles:
                rp=normalize_permissions(cr["permissions"])
                if "administrator" in rp:
                    base_perms|=set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)
                base_perms|=(rp-{"administrator"})

        role_keys={builtin}|{f"custom:{cr['id']}" for cr in custom_roles}
        visible=[]

        for cid,_,_,_ in channel_rows:
            effective=set(base_perms)
            by_role=all_overrides.get(cid,{})
            allow=set()
            deny=set()

            for key in role_keys:
                ov=by_role.get(key)
                if ov:
                    allow|=ov["allow"]
                    deny|=ov["deny"]

            effective-=deny
            effective|=allow

            if builtin=="owner" or "view_channels" in effective:
                visible.append(cid)

        p=presence_payload(r[7])

        members.append({
            "id":uid,
            "username":r[1],
            "avatar":r[2],
            "role":builtin,
            "custom_roles":[{"id":cr["id"],"name":cr["name"]} for cr in custom_roles],
            "muted":bool(r[4] and r[4]>now),
            "banned":bool(r[5] and r[5]>now),
            "device_type":r[6],
            "online":p["online"],
            "last_seen":p["last_seen"],
            "visible_channel_ids":visible,
            "is_bot":False
        })

    for bid,public_id,name,avatar,raw_perms in bot_rows:
        stored=set(raw_perms or [])
        effective=bot_install_permissions(bid,sid)
        bot_admin="administrator" in stored

        visible=[
            cid for cid,_,_,_ in channel_rows
            if "view_channels" in effective
        ]

        members.append({
            "id":bid,
            "bot_id":bid,
            "public_id":public_id,
            "username":name,
            "avatar":avatar,
            "role":"admin" if bot_admin else "bot",
            "custom_roles":[],
            "bot_permissions":list(raw_perms or []),
            "muted":False,
            "banned":False,
            "device_type":"Bot",
            "online":True,
            "last_seen":None,
            "visible_channel_ids":visible,
            "is_bot":True
        })

    return jsonify(
        server={
            "id":server[0],
            "name":server[1],
            "icon":server[2],
            "owner_id":server[3],
            "privacy_mode":server[4],
            "member_count":server[5],
            "my_role":sm_role,
            "permissions":sorted(base)
        },
        members=members,
        channels=channels,
        roles=[
            {"id":r[0],"name":r[1],"permissions":r[2] or {}}
            for r in role_rows
        ]
    )

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
    return jsonify(server={"id":s[0],"name":s[1],"icon":s[2],"owner_id":s[3],"privacy_mode":s[4],"member_count":s[5],"my_role":sm["role"],"permissions":sorted(server_permissions_for_user(sid,request.me["id"]))})

@app.patch("/api/servers/<int:sid>")
@login_required
def server_edit(sid):
    if not has_server_permission(sid,request.me["id"],"manage_server"):
        return jsonify(error="Manage Server permission required"),403
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
    if not sm or sm["role"]!="owner":
        return jsonify(error="Only the server owner can delete the server"),403

    with connect() as c:
        c.execute("delete from servers where id=%s",(sid,))
        c.commit()

    return jsonify(ok=True)

@app.get("/api/servers/<int:sid>/members")
@login_required
def server_members_get(sid):
    viewer=server_member(sid,request.me["id"])
    if not viewer:
        return jsonify(error="Not a server member"),403

    channel_id=request.args.get("channel_id")
    try:
        channel_id=int(channel_id) if channel_id else None
    except Exception:
        channel_id=None

    with connect() as c:
        rows=c.execute("""
            select u.id,u.username,u.avatar,sm.role,sm.muted_until,sm.banned_until,
                   u.device_type,u.last_seen
            from server_members sm
            join users u on u.id=sm.user_id
            where sm.server_id=%s
            order by
              case sm.role when 'owner' then 3 when 'admin' then 2 when 'moderator' then 1 else 0 end desc,
              lower(u.username)
        """,(sid,)).fetchall()

        custom_rows=c.execute("""
            select smr.user_id,sr.id,sr.name,sr.permissions
            from server_member_roles smr
            join server_roles sr on sr.id=smr.role_id
            where smr.server_id=%s
        """,(sid,)).fetchall()

        bot_rows=c.execute("""
            select b.id,b.public_id,b.name,b.avatar,bi.permissions
            from bot_server_installs bi
            join vyntra_bots b on b.id=bi.bot_id
            where bi.server_id=%s
            order by lower(b.name)
        """,(sid,)).fetchall()

        override_rows=[]
        if channel_id:
            override_rows=c.execute("""
                select role_key,allow_permissions,deny_permissions
                from channel_role_overrides
                where channel_id=%s
            """,(channel_id,)).fetchall()

    custom_by_user={}
    for uid,rid,rname,rperms in custom_rows:
        custom_by_user.setdefault(uid,[]).append({
            "id":rid,
            "name":rname,
            "permissions":rperms or {}
        })

    overrides={
        role_key:{
            "allow":set(allow or []),
            "deny":set(deny or [])
        }
        for role_key,allow,deny in override_rows
    }

    now=datetime.now(timezone.utc)
    members=[]

    for r in rows:
        uid=r[0]
        builtin=r[3]
        custom=custom_by_user.get(uid,[])

        if channel_id:
            if builtin=="owner":
                effective=set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)|{"delete_server"}
            else:
                effective=set(BUILTIN_SERVER_PERMISSIONS.get(builtin,set()))
                for cr in custom:
                    rp=normalize_permissions(cr["permissions"])
                    if "administrator" in rp:
                        effective|=set(ALL_SERVER_PERMISSIONS_EXCEPT_DELETE)
                    effective|=(rp-{"administrator"})

            keys={builtin}|{f"custom:{cr['id']}" for cr in custom}
            allow=set()
            deny=set()

            for key in keys:
                ov=overrides.get(key)
                if ov:
                    allow|=ov["allow"]
                    deny|=ov["deny"]

            effective-=deny
            effective|=allow

            if builtin!="owner" and "view_channels" not in effective:
                continue

        presence=presence_payload(r[7])

        members.append({
            "id":uid,
            "username":r[1],
            "avatar":r[2],
            "role":builtin,
            "custom_roles":[{"id":x["id"],"name":x["name"]} for x in custom],
            "muted":bool(r[4] and r[4]>now),
            "banned":bool(r[5] and r[5]>now),
            "device_type":r[6],
            "online":presence["online"],
            "last_seen":presence["last_seen"],
            "is_bot":False
        })

    for bid,public_id,name,avatar,raw_perms in bot_rows:
        stored=set(raw_perms or [])
        effective=bot_install_permissions(bid,sid)

        if channel_id and "view_channels" not in effective:
            continue

        members.append({
            "id":bid,
            "bot_id":bid,
            "public_id":public_id,
            "username":name,
            "avatar":avatar,
            "role":"admin" if "administrator" in stored else "bot",
            "custom_roles":[],
            "bot_permissions":list(raw_perms or []),
            "muted":False,
            "banned":False,
            "device_type":"Bot",
            "online":True,
            "last_seen":None,
            "is_bot":True
        })

    return jsonify(members=members)
@app.post("/api/servers/<int:sid>/members")
@login_required
def server_member_add(sid):
    return jsonify(error="Members must join servers themselves from Discover Servers."),403

@app.delete("/api/servers/<int:sid>/members/<int:uid>")
@login_required
def server_member_remove(sid,uid):
    target=server_member(sid,uid)
    if not has_server_permission(sid,request.me["id"],"manage_members"):
        return jsonify(error="Manage Members permission required"),403
    if not target or target["role"]=="owner":return jsonify(error="Cannot remove the owner"),400
    with connect() as c:c.execute("delete from server_members where server_id=%s and user_id=%s",(sid,uid));c.commit()
    return jsonify(ok=True)

@app.post("/api/server/member-action")
@login_required
def server_member_action():
    d=request.get_json(silent=True) or {}

    try:
        sid=int(d.get("server_id"))
        uid=int(d.get("user_id"))
    except Exception:
        return jsonify(error="Invalid server or user"),400

    action=d.get("action")
    actor=server_member(sid,request.me["id"])

    if not actor:
        return jsonify(error="Server member not found"),404

    try:
        mins=max(1,min(int(d.get("minutes") or 60),525600))
    except Exception:
        mins=60

    until=datetime.now(timezone.utc)+timedelta(minutes=mins)

    with connect() as c:
        if action=="unban":
            if not has_server_permission(sid,request.me["id"],"ban_members"):
                return jsonify(error="Ban Members permission required"),403

            unban_server_user(sid,uid,c)
            c.commit()
            return jsonify(ok=True,unbanned=True)

        target=c.execute("""
            select role
            from server_members
            where server_id=%s and user_id=%s
        """,(sid,uid)).fetchone()

        if not target:
            return jsonify(error="Server member not found"),404

        if target[0]=="owner":
            return jsonify(error="The server owner cannot be moderated"),403

        if action=="mute":
            if not has_server_permission(sid,request.me["id"],"mute_members"):
                return jsonify(error="Mute Members permission required"),403

            c.execute("""
                update server_members
                set muted_until=%s
                where server_id=%s and user_id=%s
            """,(until,sid,uid))

        elif action=="unmute":
            if not has_server_permission(sid,request.me["id"],"mute_members"):
                return jsonify(error="Mute Members permission required"),403

            c.execute("""
                update server_members
                set muted_until=null
                where server_id=%s and user_id=%s
            """,(sid,uid))

        elif action=="ban":
            if not has_server_permission(sid,request.me["id"],"ban_members"):
                return jsonify(error="Ban Members permission required"),403

            ok,error=ban_server_user(
                sid,uid,request.me["id"],until,c
            )

            if not ok:
                return jsonify(error=error),403

            c.commit()

            return jsonify(
                ok=True,
                banned=True,
                removed_from_server=True,
                banned_until=until.isoformat()
            )

        elif action=="role":
            if not has_server_permission(sid,request.me["id"],"manage_roles"):
                return jsonify(error="Manage Roles permission required"),403

            role=d.get("role")

            if role not in ("member","moderator","admin"):
                return jsonify(error="Invalid role"),400

            c.execute("""
                update server_members
                set role=%s
                where server_id=%s and user_id=%s
            """,(role,sid,uid))

        else:
            return jsonify(error="Invalid action"),400

        c.commit()

    return jsonify(ok=True)



@app.get("/api/servers/<int:sid>/bans")
@login_required
def server_bans_get(sid):
    if not has_server_permission(sid,request.me["id"],"ban_members"):
        return jsonify(error="Ban Members permission required"),403

    with connect() as c:
        c.execute("""
            delete from server_bans
            where server_id=%s
              and banned_until is not null
              and banned_until<=now()
        """,(sid,))

        rows=c.execute("""
            select sb.user_id,u.username,u.avatar,sb.banned_until,
                   sb.created_at,actor.username
            from server_bans sb
            join users u on u.id=sb.user_id
            left join users actor on actor.id=sb.banned_by
            where sb.server_id=%s
            order by sb.created_at desc
        """,(sid,)).fetchall()

        c.commit()

    return jsonify(bans=[{
        "user_id":r[0],
        "username":r[1],
        "avatar":r[2],
        "banned_until":r[3].isoformat() if r[3] else None,
        "created_at":r[4].isoformat(),
        "banned_by":r[5]
    } for r in rows])


@app.delete("/api/servers/<int:sid>/bans/<int:uid>")
@login_required
def server_ban_remove(sid,uid):
    if not has_server_permission(sid,request.me["id"],"ban_members"):
        return jsonify(error="Ban Members permission required"),403

    with connect() as c:
        unban_server_user(sid,uid,c)
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
            ban_until = active_server_ban(sid, jr[0], c)
            if ban_until is not None:
                return jsonify(error="That user is currently banned from this server."),403

            c.execute("""
                insert into server_members(server_id,user_id,role)
                values(%s,%s,'member')
                on conflict(server_id,user_id) do nothing
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
    if not has_server_permission(sid,request.me["id"],"manage_channels"):
        return jsonify(error="Manage Channels permission required"),403
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
    if not has_server_permission(sid,request.me["id"],"manage_channels"):
        return jsonify(error="Manage Channels permission required"),403
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
    if not has_server_permission(sid,request.me["id"],"manage_channels"):
        return jsonify(error="Manage Channels permission required"),403
    with connect() as c:
        count=c.execute("select count(*) from server_channels where server_id=%s",(sid,)).fetchone()[0]
        if count<=1:return jsonify(error="A server must keep at least one channel"),400
        c.execute("delete from server_channels where id=%s and server_id=%s",(cid,sid));c.commit()
    return jsonify(ok=True)

@app.get("/api/servers/<int:sid>/roles")
@login_required
def server_roles_get(sid):
    if not server_member(sid,request.me["id"]):
        return jsonify(error="Not a server member"),403
    with connect() as c:
        rows=c.execute("""
            select id,name,permissions
            from server_roles
            where server_id=%s
            order by id
        """,(sid,)).fetchall()
    return jsonify(
        roles=[{"id":r[0],"name":r[1],"permissions":r[2] or {}} for r in rows],
        permission_keys=SERVER_PERMISSION_KEYS
    )

@app.post("/api/servers/<int:sid>/roles")
@login_required
def server_role_create(sid):
    if not has_server_permission(sid,request.me["id"],"manage_roles"):
        return jsonify(error="Manage Roles permission required"),403
    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip()[:30]
    if not name:
        return jsonify(error="Role name required"),400
    raw=d.get("permissions") or {}
    perms={k:bool(raw.get(k,False)) for k in SERVER_PERMISSION_KEYS} if isinstance(raw,dict) else {}
    try:
        with connect() as c:
            rid=c.execute("""
                insert into server_roles(server_id,name,permissions)
                values(%s,%s,%s) returning id
            """,(sid,name,psycopg.types.json.Jsonb(perms))).fetchone()[0]
            c.commit()
        return jsonify(id=rid)
    except psycopg.errors.UniqueViolation:
        return jsonify(error="Role already exists"),409

@app.patch("/api/servers/<int:sid>/roles/<int:rid>")
@login_required
def server_role_edit(sid,rid):
    if not has_server_permission(sid,request.me["id"],"manage_roles"):
        return jsonify(error="Manage Roles permission required"),403
    d=request.get_json(silent=True) or {}
    with connect() as c:
        old=c.execute("select name,permissions from server_roles where id=%s and server_id=%s",(rid,sid)).fetchone()
        if not old:
            return jsonify(error="Role not found"),404
        name=str(d.get("name",old[0])).strip()[:30]
        raw=d.get("permissions",old[1] or {})
        if not isinstance(raw,dict):
            return jsonify(error="Invalid permissions"),400
        perms={k:bool(raw.get(k,False)) for k in SERVER_PERMISSION_KEYS}
        c.execute("""
            update server_roles set name=%s,permissions=%s
            where id=%s and server_id=%s
        """,(name,psycopg.types.json.Jsonb(perms),rid,sid))
        c.commit()
    return jsonify(ok=True)

@app.delete("/api/servers/<int:sid>/roles/<int:rid>")
@login_required
def server_role_delete(sid,rid):
    if not has_server_permission(sid,request.me["id"],"manage_roles"):
        return jsonify(error="Manage Roles permission required"),403
    with connect() as c:
        c.execute("delete from server_roles where id=%s and server_id=%s",(rid,sid))
        c.commit()
    return jsonify(ok=True)

@app.post("/api/servers/<int:sid>/members/<int:uid>/custom-role")
@login_required
def server_custom_role_assign(sid,uid):
    if not has_server_permission(sid,request.me["id"],"manage_roles"):
        return jsonify(error="Manage Roles permission required"),403
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


@app.get("/api/servers/<int:sid>/channels/<int:cid>/role-overrides")
@login_required
def channel_role_overrides_get(sid,cid):
    if not server_member(sid,request.me["id"]):
        return jsonify(error="Not a server member"),403
    with connect() as c:
        rows=c.execute("""
            select role_key,allow_permissions,deny_permissions
            from channel_role_overrides
            where channel_id=%s
        """,(cid,)).fetchall()
    return jsonify(overrides=[{
        "role_key":r[0],
        "allow":r[1] or [],
        "deny":r[2] or []
    } for r in rows])

@app.put("/api/servers/<int:sid>/channels/<int:cid>/role-overrides/<role_key>")
@login_required
def channel_role_override_set(sid,cid,role_key):
    if not has_server_permission(sid,request.me["id"],"manage_channels"):
        return jsonify(error="Manage Channels permission required"),403
    with connect() as c:
        channel=c.execute("select 1 from server_channels where id=%s and server_id=%s",(cid,sid)).fetchone()
        if not channel:
            return jsonify(error="Channel not found"),404

    d=request.get_json(silent=True) or {}
    allow=[p for p in (d.get("allow") or []) if p in ("view_channels","send_messages","manage_messages","manage_spookhooks")]
    deny=[p for p in (d.get("deny") or []) if p in ("view_channels","send_messages","manage_messages","manage_spookhooks")]

    # A permission can't be both.
    allow=[p for p in allow if p not in deny]

    valid_builtin={"member","moderator","admin","owner"}
    if role_key not in valid_builtin:
        if not role_key.startswith("custom:"):
            return jsonify(error="Invalid role"),400
        try: rid=int(role_key.split(":",1)[1])
        except Exception:return jsonify(error="Invalid role"),400
        with connect() as c:
            if not c.execute("select 1 from server_roles where id=%s and server_id=%s",(rid,sid)).fetchone():
                return jsonify(error="Role not found"),404

    with connect() as c:
        c.execute("""
            insert into channel_role_overrides(channel_id,role_key,allow_permissions,deny_permissions)
            values(%s,%s,%s,%s)
            on conflict(channel_id,role_key)
            do update set allow_permissions=excluded.allow_permissions,
                          deny_permissions=excluded.deny_permissions
        """,(cid,role_key,psycopg.types.json.Jsonb(allow),psycopg.types.json.Jsonb(deny)))
        c.commit()
    return jsonify(ok=True)

@app.get("/api/servers/<int:sid>/channels/<int:cid>/spookhooks")
@login_required
def spookhooks_get(sid,cid):
    sm=server_member(sid,request.me["id"])
    if not has_server_permission(sid,request.me["id"],"manage_spookhooks"):return jsonify(error="Manage VyntraHooks permission required"),403
    with connect() as c:
        rows=c.execute("select id,name,created_at from spookhooks where server_id=%s and channel_id=%s order by id desc",(sid,cid)).fetchall()
    return jsonify(hooks=[{"id":r[0],"name":r[1],"created_at":r[2].isoformat()} for r in rows])

@app.post("/api/servers/<int:sid>/channels/<int:cid>/spookhooks")
@login_required
def spookhook_create(sid,cid):
    sm=server_member(sid,request.me["id"])
    if not has_server_permission(sid,request.me["id"],"manage_spookhooks"):return jsonify(error="Manage VyntraHooks permission required"),403
    with connect() as c:
        channel=c.execute("select 1 from server_channels where id=%s and server_id=%s",(cid,sid)).fetchone()
        if not channel:return jsonify(error="Channel not found"),404
        name=str((request.get_json(silent=True) or {}).get("name","VyntraHook")).strip()[:40] or "VyntraHook"
        token=secrets.token_urlsafe(32);token_hash=hashlib.sha256(token.encode()).hexdigest()
        hid=c.execute("""
            insert into spookhooks(server_id,channel_id,created_by,name,token_hash)
            values(%s,%s,%s,%s,%s) returning id
        """,(sid,cid,request.me["id"],name,token_hash)).fetchone()[0];c.commit()
    return jsonify(id=hid,url=request.host_url.rstrip("/")+"/api/vyntrahook/"+token)

@app.delete("/api/servers/<int:sid>/spookhooks/<int:hid>")
@login_required
def spookhook_delete(sid,hid):
    sm=server_member(sid,request.me["id"])
    if not sm or sm["role"]!="owner":return jsonify(error="Server owner only"),403
    with connect() as c:c.execute("delete from spookhooks where id=%s and server_id=%s",(hid,sid));c.commit()
    return jsonify(ok=True)

@app.post("/api/vyntrahook/<token>")
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
        if not h:return jsonify(error="Invalid VyntraHook"),404
        hook_name=str(d.get("username",h[3])).strip()[:40] or h[3]
        c.execute("""
            insert into messages(user_id,content,kind,channel,server_id,is_spookhook,hook_name)
            values(%s,%s,'server',%s,%s,true,%s)
        """,(h[2],content,str(h[1]),h[0],hook_name));c.commit()
    return jsonify(ok=True)



@app.get("/api/servers/<int:sid>/invites")
@login_required
def server_invites_get(sid):
    if not has_server_permission(sid,request.me["id"],"invite_members"):
        return jsonify(error="Invite Members permission required"),403
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
    if not has_server_permission(sid,request.me["id"],"invite_members"):
        return jsonify(error="Invite Members permission required"),403
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
    if not has_server_permission(sid,request.me["id"],"invite_members"):
        return jsonify(error="Invite Members permission required"),403
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
            select role from server_members
            where server_id=%s and user_id=%s
        """,(sid,request.me["id"])).fetchone()

        if existing:
            return jsonify(ok=True,server_id=sid,already_joined=True)

        ban_until = active_server_ban(sid, request.me["id"], c)
        if ban_until is not None:
            return jsonify(
                error="You are banned from this server.",
                banned=True,
                banned_until=ban_until.isoformat() if ban_until else None
            ),403

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
        return """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>VYNTRA Invite</title></head>
        <body style="margin:0;background:#09070e;color:white;font-family:system-ui;display:grid;place-items:center;height:100vh">
        <div style="background:#120e19;border:1px solid #332641;padding:28px;border-radius:18px;text-align:center">
        <h1>Invite not found</h1><p>This invite may have been deleted.</p><a href="/" style="color:#b77cff">Open VYNTRA</a></div></body></html>""",404

    name,icon,count = r
    safe_name = html_lib.escape(str(name), quote=True)
    raw_icon = str(icon or "")
    icon_url = raw_icon if raw_icon.startswith(("https://","http://","/")) else "/static/spookchat_pfp.png"
    safe_icon = html_lib.escape(icon_url, quote=True)
    return f"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Join {safe_name} · VYNTRA</title><style>
    body{{margin:0;background:radial-gradient(circle at 20% 0,#2a123e,transparent 35%),#09070e;color:#f5f3ff;font-family:system-ui;display:grid;place-items:center;min-height:100vh}}
    .card{{width:min(430px,92vw);background:#120e19;border:1px solid #382b46;border-radius:22px;padding:30px;text-align:center;box-shadow:0 30px 100px #000}}
    .btn{{display:inline-block;margin-top:18px;background:linear-gradient(135deg,#9b4dff,#7c3aed);color:white;text-decoration:none;padding:12px 18px;border-radius:11px;font-weight:800}}
    .muted{{color:#9b93aa}}</style></head><body><div class="card">
    <img src="{safe_icon}" style="width:86px;height:86px;border-radius:22px;object-fit:cover">
    <h1>{safe_name}</h1><div class="muted">{count} member{"s" if count != 1 else ""}</div>
    <p>You were invited to join this VYNTRA server.</p>
    <a class="btn" href="/?invite={code}">Open VYNTRA</a>
    </div></body></html>"""


# ============================================================
# MESSAGES / REPORTS
# ============================================================

@app.get("/api/messages")
@login_required
def messages_get():
    kind=request.args.get("kind")
    channel=request.args.get("channel")
    sid=request.args.get("server_id")
    cid=request.args.get("chat_id")
    settings=get_site_settings()

    with connect() as c:
        if kind=="public":
            rows=c.execute("""
              select m.id,m.user_id,m.content,m.created_at,m.edited_at,
                     u.username,u.avatar,
                     case when u.show_staff_tag then u.global_role else 'user' end,
                     m.is_spookhook,m.reply_to_id,m.image_data
              from messages m
              join users u on u.id=m.user_id
              where m.kind='public' and m.channel=%s
              order by m.created_at desc
              limit 150
            """,(channel,)).fetchall()

        elif kind=="server":
            try:
                channel_id=int(channel)
                sid_int=int(sid)
            except Exception:
                return jsonify(error="Invalid channel"),400

            sm,viewer_perms=channel_effective_permissions(
                sid_int,channel_id,request.me["id"]
            )
            if not sm:
                return jsonify(error="Not a server member"),403
            if sm["banned_until"] and sm["banned_until"]>datetime.now(timezone.utc):
                return jsonify(error="Banned"),403
            if "view_channels" not in viewer_perms:
                return jsonify(error="You cannot view this channel"),403

            rows=c.execute("""
              select m.id,m.user_id,m.content,m.created_at,m.edited_at,
                     case
                       when m.bot_id is not null then b.name
                       when m.is_spookhook then m.hook_name
                       else u.username
                     end,
                     case when m.bot_id is not null then b.avatar else u.avatar end,
                     case when m.bot_id is not null then 'bot' else coalesce(author_sm.role,'member') end,
                     m.is_spookhook,m.reply_to_id,m.bot_id,m.image_data
              from messages m
              join users u on u.id=m.user_id
              left join vyntra_bots b on b.id=m.bot_id
              left join server_members author_sm
                on author_sm.server_id=m.server_id
               and author_sm.user_id=m.user_id
              where m.kind='server'
                and m.server_id=%s
                and m.channel=%s
              order by m.created_at desc
              limit 150
            """,(sid_int,str(channel_id))).fetchall()

        elif kind=="dm":
            try:
                cid_int=int(cid)
            except Exception:
                return jsonify(error="Invalid chat"),400

            ok=c.execute(
                "select 1 from chat_members where chat_id=%s and user_id=%s",
                (cid_int,request.me["id"])
            ).fetchone()
            if not ok:
                return jsonify(error="Not a chat member"),403

            rows=c.execute("""
              select m.id,m.user_id,m.content,m.created_at,m.edited_at,
                     u.username,u.avatar,
                     case when u.show_staff_tag then u.global_role else 'user' end,
                     m.is_spookhook,m.reply_to_id,m.image_data
              from messages m
              join users u on u.id=m.user_id
              where m.kind='dm' and m.chat_id=%s
              order by m.created_at desc
              limit 150
            """,(cid_int,)).fetchall()
        else:
            return jsonify(error="Invalid message type"),400

        ordered=list(reversed(rows))
        message_ids=[r[0] for r in ordered]

        reaction_map={}
        if message_ids:
            reaction_rows=c.execute("""
                select message_id,emoji,count(*),bool_or(user_id=%s)
                from message_reactions
                where message_id=any(%s)
                group by message_id,emoji
                order by emoji
            """,(request.me["id"],message_ids)).fetchall()

            for mid,emoji,count,mine in reaction_rows:
                reaction_map.setdefault(mid,[]).append({
                    "emoji":emoji,
                    "count":count,
                    "mine":bool(mine)
                })

        reply_ids=list({r[9] for r in ordered if r[9]})
        reply_map={}
        if reply_ids:
            reply_rows=c.execute("""
                select m.id,m.content,u.username
                from messages m
                join users u on u.id=m.user_id
                where m.id=any(%s)
            """,(reply_ids,)).fetchall()

            reply_map={
                rr[0]:{
                    "id":rr[0],
                    "content":rr[1][:180],
                    "username":rr[2]
                }
                for rr in reply_rows
            }

        embed_author_ids=set()
        if kind=="server":
            author_ids=list({r[1] for r in ordered})
            if author_ids:
                # Admin/owner built-in roles already get embed_links.
                for r in ordered:
                    if r[7] in ("admin","owner"):
                        embed_author_ids.add(r[1])

                custom_rows=c.execute("""
                    select smr.user_id,sr.permissions
                    from server_member_roles smr
                    join server_roles sr on sr.id=smr.role_id
                    where smr.server_id=%s and smr.user_id=any(%s)
                """,(int(sid),author_ids)).fetchall()

                for author_id,raw in custom_rows:
                    rp=normalize_permissions(raw)
                    if "embed_links" in rp or "administrator" in rp:
                        embed_author_ids.add(author_id)

    payload=[]
    for r in ordered:
        item={
            "id":r[0],
            "user_id":r[1],
            "content":r[2],
            "created_at":r[3].isoformat(),
            "edited_at":r[4].isoformat() if r[4] else None,
            "username":r[5],
            "avatar":r[6],
            "role":r[7],
            "is_spookhook":bool(r[8]),
            "is_bot":bool(r[10]) if kind=="server" and len(r)>10 else False,
            "reactions":reaction_map.get(r[0],[]),
            "embed_url":extract_first_url(r[2]),
            "embed_allowed":True,
            "reply":reply_map.get(r[9]) if r[9] else None,
            "image_data":(
                r[11] if kind=="server" and len(r)>11
                else (r[10] if kind!="server" and len(r)>10 else "")
            )
        }

        if kind=="server":
            item["embed_allowed"]=r[1] in embed_author_ids
        elif kind=="public":
            item["embed_allowed"]=settings["public_embeds_enabled"]

        payload.append(item)

    return jsonify(messages=payload)


@app.post("/api/typing")
@login_required
def typing_update():
    d=request.get_json(silent=True) or {}
    kind=str(d.get("kind",""))
    channel=d.get("channel")
    sid=d.get("server_id")
    cid=d.get("chat_id")

    try:
        scope=typing_scope_key(kind,channel,sid,cid)
    except Exception:
        return jsonify(error="Invalid typing scope"),400

    if not scope:
        return jsonify(error="Invalid typing scope"),400

    if kind=="server":
        try:
            sid=int(sid)
            channel=int(channel)
        except Exception:
            return jsonify(error="Invalid server channel"),400

        sm,perms=channel_effective_permissions(
            sid,channel,request.me["id"]
        )
        if not sm or "view_channels" not in perms:
            return jsonify(error="No channel access"),403

    elif kind=="dm":
        try:
            cid=int(cid)
        except Exception:
            return jsonify(error="Invalid chat"),400

        with connect() as c:
            ok=c.execute(
                "select 1 from chat_members where chat_id=%s and user_id=%s",
                (cid,request.me["id"])
            ).fetchone()

        if not ok:
            return jsonify(error="Not a chat member"),403

    with connect() as c:
        c.execute("""
            insert into typing_status(user_id,scope_key,expires_at)
            values(%s,%s,now()+interval '4 seconds')
            on conflict(user_id,scope_key)
            do update set expires_at=excluded.expires_at
        """,(request.me["id"],scope))
        c.commit()

    return jsonify(ok=True)





@app.get("/api/calls/active")
@login_required
def active_calls_for_user():
    uid=request.me["id"]

    with connect() as c:
        # Clean stale call participants/signals first.
        c.execute("""
            delete from call_participants
            where last_seen < now()-interval '20 seconds'
        """)
        c.execute("""
            delete from call_signals
            where created_at < now()-interval '2 minutes'
        """)

        rows=c.execute("""
            select distinct cp.scope_key,
                   min(cp.joined_at) as started_at,
                   count(*) as participant_count
            from call_participants cp
            where cp.user_id<>%s
              and cp.last_seen >= now()-interval '20 seconds'
            group by cp.scope_key
            order by started_at desc
            limit 50
        """,(uid,)).fetchall()

        c.commit()

    out=[]

    for scope,started_at,participant_count in rows:
        parts=str(scope).split(":")

        try:
            if parts[0]=="public" and len(parts)>=2:
                channel=":".join(parts[1:])

                if not verify_call_access("public",uid,channel,None,None):
                    continue

                out.append({
                    "scope_key":scope,
                    "kind":"public",
                    "channel":channel,
                    "server_id":None,
                    "chat_id":None,
                    "display_name":channel.replace("chat1","Chat 1").replace("chat2","Chat 2"),
                    "participant_count":int(participant_count),
                    "started_at":started_at
                })

            elif parts[0]=="server" and len(parts)==3:
                sid=int(parts[1])
                cid=int(parts[2])

                if not verify_call_access("server",uid,cid,sid,None):
                    continue

                with connect() as c:
                    row=c.execute("""
                        select s.name,sc.name
                        from servers s
                        join server_channels sc on sc.server_id=s.id
                        where s.id=%s and sc.id=%s
                    """,(sid,cid)).fetchone()

                if not row:
                    continue

                out.append({
                    "scope_key":scope,
                    "kind":"server",
                    "channel":cid,
                    "server_id":sid,
                    "chat_id":None,
                    "display_name":f"{row[0]} · #{row[1]}",
                    "participant_count":int(participant_count),
                    "started_at":started_at
                })

            elif parts[0]=="dm" and len(parts)==2:
                cid=int(parts[1])

                if not verify_call_access("dm",uid,None,None,cid):
                    continue

                with connect() as c:
                    row=c.execute("""
                        select kind,name
                        from chats
                        where id=%s
                    """,(cid,)).fetchone()

                    names=c.execute("""
                        select u.username
                        from chat_members cm
                        join users u on u.id=cm.user_id
                        where cm.chat_id=%s and cm.user_id<>%s
                        order by u.username
                        limit 5
                    """,(cid,uid)).fetchall()

                display=(row[1] if row and row[1] else None) or ", ".join(r[0] for r in names) or "Direct Message"

                out.append({
                    "scope_key":scope,
                    "kind":"dm",
                    "channel":None,
                    "server_id":None,
                    "chat_id":cid,
                    "display_name":display,
                    "participant_count":int(participant_count),
                    "started_at":started_at
                })

        except Exception:
            continue

    return jsonify(calls=out)

@app.post("/api/calls/join")
@login_required
def call_join():
    d=request.get_json(silent=True) or {}
    kind=str(d.get("kind","")); channel=d.get("channel")
    sid=d.get("server_id"); cid=d.get("chat_id")
    try:
        scope=call_scope_key(kind,channel,sid,cid)
    except Exception:
        return jsonify(error="Invalid call scope"),400
    if not scope or not verify_call_access(kind,request.me["id"],channel,sid,cid):
        return jsonify(error="You cannot join this call"),403
    with connect() as c:
        c.execute("""
            insert into call_participants(scope_key,user_id,joined_at,last_seen)
            values(%s,%s,now(),now())
            on conflict(scope_key,user_id) do update set last_seen=now()
        """,(scope,request.me["id"]))
        c.execute("delete from call_participants where last_seen < now()-interval '20 seconds'")
        c.execute("delete from call_signals where created_at < now()-interval '2 minutes'")
        rows=c.execute("""
            select cp.user_id,u.username,u.avatar,u.device_type
            from call_participants cp join users u on u.id=cp.user_id
            where cp.scope_key=%s and cp.last_seen >= now()-interval '20 seconds'
            order by cp.joined_at
        """,(scope,)).fetchall()
        c.commit()
    return jsonify(scope_key=scope,participants=[
        {"id":r[0],"username":r[1],"avatar":r[2],"device_type":r[3]} for r in rows
    ])

@app.post("/api/calls/heartbeat")
@login_required
def call_heartbeat():
    d=request.get_json(silent=True) or {}; scope=str(d.get("scope_key",""))
    if not scope:return jsonify(error="Missing call scope"),400
    with connect() as c:
        c.execute("update call_participants set last_seen=now() where scope_key=%s and user_id=%s",(scope,request.me["id"]))
        rows=c.execute("""
            select cp.user_id,u.username,u.avatar,u.device_type
            from call_participants cp join users u on u.id=cp.user_id
            where cp.scope_key=%s and cp.last_seen >= now()-interval '20 seconds'
            order by cp.joined_at
        """,(scope,)).fetchall()
        c.commit()
    return jsonify(participants=[{"id":r[0],"username":r[1],"avatar":r[2],"device_type":r[3]} for r in rows])

@app.post("/api/calls/leave")
@login_required
def call_leave():
    d=request.get_json(silent=True) or {}; scope=str(d.get("scope_key",""))
    if not scope:return jsonify(ok=True)
    with connect() as c:
        c.execute("delete from call_participants where scope_key=%s and user_id=%s",(scope,request.me["id"]))
        c.execute("delete from call_signals where scope_key=%s and (from_user_id=%s or to_user_id=%s)",(scope,request.me["id"],request.me["id"]))
        c.commit()
    return jsonify(ok=True)

@app.post("/api/calls/signal")
@login_required
def call_signal_send():
    d=request.get_json(silent=True) or {}
    scope=str(d.get("scope_key","")); typ=str(d.get("signal_type","")); payload=d.get("payload")
    try: to_uid=int(d.get("to_user_id"))
    except Exception:return jsonify(error="Invalid target user"),400
    if not scope or typ not in ("offer","answer","ice") or not isinstance(payload,dict):
        return jsonify(error="Invalid call signal"),400
    with connect() as c:
        sender=c.execute("select 1 from call_participants where scope_key=%s and user_id=%s and last_seen>=now()-interval '20 seconds'",(scope,request.me["id"])).fetchone()
        target=c.execute("select 1 from call_participants where scope_key=%s and user_id=%s and last_seen>=now()-interval '20 seconds'",(scope,to_uid)).fetchone()
        if not sender or not target:return jsonify(error="Call participant unavailable"),404
        c.execute("""
            insert into call_signals(scope_key,from_user_id,to_user_id,signal_type,payload)
            values(%s,%s,%s,%s,%s)
        """,(scope,request.me["id"],to_uid,typ,psycopg.types.json.Jsonb(payload)))
        c.commit()
    return jsonify(ok=True)

@app.get("/api/calls/signals")
@login_required
def call_signal_get():
    scope=request.args.get("scope_key","")
    try: after_id=int(request.args.get("after_id","0"))
    except Exception: after_id=0
    if not scope:return jsonify(signals=[])
    with connect() as c:
        rows=c.execute("""
            select cs.id,cs.from_user_id,cs.signal_type,cs.payload,u.username,u.avatar
            from call_signals cs join users u on u.id=cs.from_user_id
            where cs.scope_key=%s and cs.to_user_id=%s and cs.id>%s
            order by cs.id limit 100
        """,(scope,request.me["id"],after_id)).fetchall()
    return jsonify(signals=[{"id":r[0],"from_user_id":r[1],"signal_type":r[2],"payload":r[3],"username":r[4],"avatar":r[5]} for r in rows])

@app.post("/api/read-state")
@login_required
def mark_scope_read():
    d=request.get_json(silent=True) or {}
    kind=str(d.get("kind",""))
    channel=d.get("channel")
    sid=d.get("server_id")
    cid=d.get("chat_id")

    try:
        scope=message_scope_key(kind,channel,sid,cid)
    except Exception:
        return jsonify(error="Invalid conversation"),400

    if not scope:
        return jsonify(error="Invalid conversation"),400

    with connect() as c:
        if kind=="public":
            row=c.execute("""
                select coalesce(max(id),0)
                from messages
                where kind='public' and channel=%s
            """,(channel,)).fetchone()

        elif kind=="server":
            try:
                sid=int(sid)
                channel=str(int(channel))
            except Exception:
                return jsonify(error="Invalid server channel"),400

            sm,perms=channel_effective_permissions(
                sid,int(channel),request.me["id"]
            )

            if not sm or "view_channels" not in perms:
                return jsonify(error="No channel access"),403

            row=c.execute("""
                select coalesce(max(id),0)
                from messages
                where kind='server' and server_id=%s and channel=%s
            """,(sid,channel)).fetchone()

        elif kind=="dm":
            try:
                cid=int(cid)
            except Exception:
                return jsonify(error="Invalid chat"),400

            ok=c.execute("""
                select 1
                from chat_members
                where chat_id=%s and user_id=%s
            """,(cid,request.me["id"])).fetchone()

            if not ok:
                return jsonify(error="Not a chat member"),403

            row=c.execute("""
                select coalesce(max(id),0)
                from messages
                where kind='dm' and chat_id=%s
            """,(cid,)).fetchone()

        else:
            return jsonify(error="Invalid conversation"),400

        last_id=int(row[0] or 0)

        c.execute("""
            insert into message_read_state(
                user_id,scope_key,last_message_id,updated_at
            )
            values(%s,%s,%s,now())
            on conflict(user_id,scope_key)
            do update set
                last_message_id=greatest(
                    message_read_state.last_message_id,
                    excluded.last_message_id
                ),
                updated_at=now()
        """,(request.me["id"],scope,last_id))

        c.commit()

    return jsonify(ok=True,last_message_id=last_id)


@app.get("/api/unreads")
@login_required
def unread_counts():
    uid=request.me["id"]

    with connect() as c:
        states={
            r[0]:int(r[1] or 0)
            for r in c.execute("""
                select scope_key,last_message_id
                from message_read_state
                where user_id=%s
            """,(uid,)).fetchall()
        }

        public_rows=c.execute("""
            select channel,count(*),max(id)
            from messages
            where kind='public' and user_id<>%s
            group by channel
        """,(uid,)).fetchall()

        dm_rows=c.execute("""
            select m.chat_id,count(*),max(m.id)
            from messages m
            join chat_members cm
              on cm.chat_id=m.chat_id
             and cm.user_id=%s
            where m.kind='dm' and m.user_id<>%s
            group by m.chat_id
        """,(uid,uid)).fetchall()

        server_rows=c.execute("""
            select m.server_id,m.channel,count(*),max(m.id)
            from messages m
            where m.kind='server'
              and m.user_id<>%s
            group by m.server_id,m.channel
        """,(uid,)).fetchall()

        # Exact unread counts require counting messages newer than each
        # user's last-read id. Do it in one query per messaging family.
        public_unreads=c.execute("""
            select m.channel,count(*),max(m.id)
            from messages m
            where m.kind='public'
              and m.user_id<>%s
              and m.id > coalesce((
                  select rs.last_message_id
                  from message_read_state rs
                  where rs.user_id=%s
                    and rs.scope_key='public:'||m.channel
              ),0)
            group by m.channel
        """,(uid,uid)).fetchall()

        dm_unreads=c.execute("""
            select m.chat_id,count(*),max(m.id)
            from messages m
            join chat_members cm
              on cm.chat_id=m.chat_id
             and cm.user_id=%s
            where m.kind='dm'
              and m.user_id<>%s
              and m.id > coalesce((
                  select rs.last_message_id
                  from message_read_state rs
                  where rs.user_id=%s
                    and rs.scope_key='dm:'||m.chat_id::text
              ),0)
            group by m.chat_id
        """,(uid,uid,uid)).fetchall()

        # Server unread rows are filtered in Python against current channel
        # visibility so private channels do not leak through counts.
        raw_server_unreads=c.execute("""
            select m.server_id,m.channel,count(*),max(m.id)
            from messages m
            where m.kind='server'
              and m.user_id<>%s
              and m.id > coalesce((
                  select rs.last_message_id
                  from message_read_state rs
                  where rs.user_id=%s
                    and rs.scope_key=
                        'server:'||m.server_id::text||':'||m.channel
              ),0)
            group by m.server_id,m.channel
        """,(uid,uid)).fetchall()

    public_map={
        str(r[0]):{"count":int(r[1]),"last_message_id":int(r[2])}
        for r in public_unreads
    }

    dm_map={
        str(r[0]):{"count":int(r[1]),"last_message_id":int(r[2])}
        for r in dm_unreads
    }

    server_map={}
    server_totals={}

    for sid,channel,count,last_mid in raw_server_unreads:
        try:
            cid=int(channel)
        except Exception:
            continue

        sm,perms=channel_effective_permissions(sid,cid,uid)

        if not sm or "view_channels" not in perms:
            continue

        server_map.setdefault(str(sid),{})[str(channel)]={
            "count":int(count),
            "last_message_id":int(last_mid)
        }

        server_totals[str(sid)]=server_totals.get(str(sid),0)+int(count)

    return jsonify(
        public=public_map,
        dms=dm_map,
        servers=server_map,
        server_totals=server_totals,
        friends_total=sum(v["count"] for v in dm_map.values()),
        total=(
            sum(v["count"] for v in public_map.values())
            + sum(v["count"] for v in dm_map.values())
            + sum(server_totals.values())
        )
    )

@app.get("/api/typing")
@login_required
def typing_get():
    kind=request.args.get("kind","")
    channel=request.args.get("channel")
    sid=request.args.get("server_id")
    cid=request.args.get("chat_id")

    try:
        scope=typing_scope_key(kind,channel,sid,cid)
    except Exception:
        return jsonify(typing=[])

    if not scope:
        return jsonify(typing=[])

    with connect() as c:
        rows=c.execute("""
            select u.id,u.username
            from typing_status ts
            join users u on u.id=ts.user_id
            where ts.scope_key=%s
              and ts.expires_at>now()
              and ts.user_id<>%s
            order by lower(u.username)
            limit 8
        """,(scope,request.me["id"])).fetchall()

    return jsonify(
        typing=[
            {"id":r[0],"username":r[1]}
            for r in rows
        ]
    )

@app.post("/api/messages")
@login_required
def messages_post():
    d=request.get_json(silent=True) or {}
    content=str(d.get("content","")).strip()
    kind=d.get("kind")

    try:
        image_data=validate_message_image(d.get("image_data",""))
    except ValueError as e:
        return jsonify(error=str(e)),400

    if (
        (not content and not image_data)
        or len(content)>4000
        or kind not in ("public","server","dm")
    ):
        return jsonify(error="Message text or photo required"),400

    if kind=="public":
        public_settings=get_site_settings()
        if public_settings["public_channels_locked"] and request.me["global_role"] not in ("admin","owner"):
            return jsonify(error="Public channels are currently locked. Only VYNTRA Admins and Owner can post."),403

    channel=d.get("channel");sid=d.get("server_id");cid=d.get("chat_id")
    reply_to_id=d.get("reply_to_id")
    try:
        reply_to_id=int(reply_to_id) if reply_to_id else None
    except Exception:
        reply_to_id=None
    if kind=="public" and channel not in ("chat1","chat2"):
        return jsonify(error="Invalid public channel"),400
    if kind=="server":
        now=datetime.now(timezone.utc)
        try:
            sid=int(sid);channel=int(channel)
        except Exception:
            return jsonify(error="Invalid channel"),400

        sm,effective_perms=channel_effective_permissions(
            sid,channel,request.me["id"]
        )
        if not sm:return jsonify(error="Not a server member"),403
        if sm["banned_until"] and sm["banned_until"]>now:return jsonify(error="Banned from server"),403
        if sm["muted_until"] and sm["muted_until"]>now:return jsonify(error="Restricted from talking"),403
        if "view_channels" not in effective_perms:return jsonify(error="You cannot view this channel"),403
        if "send_messages" not in effective_perms:return jsonify(error="Your role cannot talk in this channel"),403
        channel=str(channel)
    if kind=="dm":
        try:
            cid=int(cid)
        except Exception:
            return jsonify(error="Invalid chat"),400
        with connect() as c:
            if not c.execute("select 1 from chat_members where chat_id=%s and user_id=%s",(cid,request.me["id"])).fetchone():
                return jsonify(error="Not a chat member"),403
    with connect() as c:
        if reply_to_id:
            reply=c.execute("""
                select kind,channel,server_id,chat_id
                from messages where id=%s
            """,(reply_to_id,)).fetchone()
            if not reply:
                reply_to_id=None
            elif reply[0] != kind:
                return jsonify(error="You can only reply to a message in the same conversation."),400
            elif kind=="public" and reply[1] != channel:
                return jsonify(error="Reply target is not in this public channel."),400
            elif kind=="server" and (reply[2] != sid or str(reply[1]) != str(channel)):
                return jsonify(error="Reply target is not in this server channel."),400
            elif kind=="dm" and int(reply[3]) != int(cid):
                return jsonify(error="Reply target is not in this chat."),400

        mid=c.execute("""
          insert into messages(
              user_id,content,kind,channel,server_id,chat_id,reply_to_id,image_data
          )
          values(%s,%s,%s,%s,%s,%s,%s,%s)
          returning id
        """,(
            request.me["id"],content,kind,channel,sid,cid,reply_to_id,image_data
        )).fetchone()[0]

        if kind=="dm" and cid:
            chat=c.execute("select kind,name from chats where id=%s",(cid,)).fetchone()
            recipients=c.execute("""
                select user_id from chat_members
                where chat_id=%s and user_id<>%s
            """,(cid,request.me["id"])).fetchall()
            notification_type="group_message" if chat and chat[0]=="group" else "dm_message"
            title=(chat[1]+" · "+request.me["username"]) if chat and chat[0]=="group" and chat[1] else request.me["username"]
            preview=content[:180] if content else "Sent a photo"
            for recipient in recipients:
                c.execute("""
                    insert into notifications(user_id,actor_id,type,title,body,chat_id)
                    values(%s,%s,%s,%s,%s,%s)
                """,(recipient[0],request.me["id"],notification_type,title,preview,cid))

        c.commit()
    return jsonify(id=mid)


@app.post("/api/messages/<int:mid>/reaction")
@login_required
def message_reaction_toggle(mid):
    d=request.get_json(silent=True) or {}
    emoji=str(d.get("emoji","")).strip()[:16]
    allowed_emojis={"👍","❤️","😂","🔥","🎉","👻","💜","✅","❌"}

    if emoji not in allowed_emojis:
        return jsonify(error="Invalid reaction"),400

    with connect() as c:
        m=c.execute("select kind,server_id from messages where id=%s",(mid,)).fetchone()
        if not m:
            return jsonify(error="Message not found"),404

        if m[0]=="server":
            sid=m[1]
            if not server_member(sid,request.me["id"]):
                return jsonify(error="Not a server member"),403
            if not has_server_permission(sid,request.me["id"],"add_reactions"):
                return jsonify(error="Add Reactions permission required"),403

        existing=c.execute("""
            select 1 from message_reactions
            where message_id=%s and user_id=%s and emoji=%s
        """,(mid,request.me["id"],emoji)).fetchone()

        if existing:
            c.execute("""
                delete from message_reactions
                where message_id=%s and user_id=%s and emoji=%s
            """,(mid,request.me["id"],emoji))
            added=False
        else:
            c.execute("""
                insert into message_reactions(message_id,user_id,emoji)
                values(%s,%s,%s)
            """,(mid,request.me["id"],emoji))
            added=True

        c.commit()

    return jsonify(ok=True,added=added)

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
            allowed=allowed or has_server_permission(m[2],request.me["id"],"manage_messages")
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
        c.execute("update users set password_hash=%s,session_version=session_version+1 where id=%s",
                  (generate_password_hash(temporary),uid))
        c.commit()
    return jsonify(ok=True,temporary_password=temporary)


@app.get("/api/owner/dashboard")
@staff_required("owner")
def owner_dashboard():
    with connect() as c:
        total_users=c.execute("select count(*) from users").fetchone()[0]
        total_servers=c.execute("select count(*) from servers").fetchone()[0]
        total_messages=c.execute("select count(*) from messages").fetchone()[0]
        total_reports=c.execute("select count(*) from reports where status='open'").fetchone()[0]
        active_24h=c.execute("select count(*) from users where last_seen>=now()-interval '24 hours'").fetchone()[0]
        banned_users=c.execute("select count(*) from users where banned_until>now()").fetchone()[0]
        ip_bans=c.execute("select count(*) from ip_bans").fetchone()[0]
    return jsonify(
        settings=get_site_settings(),
        stats={
            "users":total_users,
            "servers":total_servers,
            "messages":total_messages,
            "open_reports":total_reports,
            "active_24h":active_24h,
            "banned_users":banned_users,
            "ip_bans":ip_bans
        }
    )

@app.patch("/api/owner/site-settings")
@staff_required("owner")
def owner_site_settings():
    d=request.get_json(silent=True) or {}
    current=get_site_settings()
    maintenance=bool(d.get("maintenance_mode",current["maintenance_mode"]))
    registrations=bool(d.get("registrations_enabled",current["registrations_enabled"]))
    msg=str(d.get("maintenance_message",current["maintenance_message"]))[:500]
    site_name=str(d.get("site_name",current["site_name"])).strip()[:60] or "VYNTRA"
    announcement=str(d.get("announcement",current["announcement"]))[:500]
    public_channels_locked=bool(d.get("public_channels_locked",current["public_channels_locked"]))
    public_embeds_enabled=bool(d.get("public_embeds_enabled",current["public_embeds_enabled"]))
    with connect() as c:
        c.execute("""
            update site_settings
            set maintenance_mode=%s,maintenance_message=%s,registrations_enabled=%s,
                site_name=%s,announcement=%s,public_channels_locked=%s,
                public_embeds_enabled=%s,updated_at=now()
            where id=1
        """,(maintenance,msg,registrations,site_name,announcement,
             public_channels_locked,public_embeds_enabled))
        c.commit()
    clear_site_settings_cache()
    audit_owner_action(request.me["id"],"update_site_settings","site","1",
                       f"maintenance={maintenance}, registrations={registrations}")
    return jsonify(ok=True,settings=get_site_settings())

@app.get("/api/owner/site-roles")
@staff_required("owner")
def owner_site_roles_get():
    with connect() as c:
        rows=c.execute("select id,name,permissions,created_at from site_roles order by name").fetchall()
    return jsonify(
        roles=[{"id":r[0],"name":r[1],"permissions":r[2] or {},"created_at":r[3].isoformat()} for r in rows],
        permission_keys=SITE_ROLE_PERMISSION_KEYS
    )

@app.post("/api/owner/site-roles")
@staff_required("owner")
def owner_site_role_create():
    d=request.get_json(silent=True) or {}
    name=str(d.get("name","")).strip()[:40]
    if not name:return jsonify(error="Role name required"),400
    raw=d.get("permissions") or {}
    perms={k:bool(raw.get(k,False)) for k in SITE_ROLE_PERMISSION_KEYS} if isinstance(raw,dict) else {}
    try:
        with connect() as c:
            rid=c.execute("""
                insert into site_roles(name,permissions) values(%s,%s) returning id
            """,(name,psycopg.types.json.Jsonb(perms))).fetchone()[0]
            c.commit()
        audit_owner_action(request.me["id"],"create_site_role","site_role",rid,name)
        return jsonify(id=rid)
    except psycopg.errors.UniqueViolation:
        return jsonify(error="A site role with that name already exists"),409

@app.patch("/api/owner/site-roles/<int:rid>")
@staff_required("owner")
def owner_site_role_edit(rid):
    d=request.get_json(silent=True) or {}
    with connect() as c:
        old=c.execute("select name,permissions from site_roles where id=%s",(rid,)).fetchone()
        if not old:return jsonify(error="Role not found"),404
        name=str(d.get("name",old[0])).strip()[:40]
        raw=d.get("permissions",old[1] or {})
        perms={k:bool(raw.get(k,False)) for k in SITE_ROLE_PERMISSION_KEYS}
        c.execute("update site_roles set name=%s,permissions=%s where id=%s",
                  (name,psycopg.types.json.Jsonb(perms),rid))
        c.commit()
    audit_owner_action(request.me["id"],"edit_site_role","site_role",rid,name)
    return jsonify(ok=True)

@app.delete("/api/owner/site-roles/<int:rid>")
@staff_required("owner")
def owner_site_role_delete(rid):
    with connect() as c:
        c.execute("delete from site_roles where id=%s",(rid,))
        c.commit()
    audit_owner_action(request.me["id"],"delete_site_role","site_role",rid,"")
    return jsonify(ok=True)

@app.get("/api/owner/users/<int:uid>/roles")
@staff_required("owner")
def owner_user_roles_get(uid):
    user=row_user(uid)
    if not user:return jsonify(error="User not found"),404
    with connect() as c:
        assigned=c.execute("""
            select sr.id,sr.name,sr.permissions
            from user_site_roles usr join site_roles sr on sr.id=usr.role_id
            where usr.user_id=%s order by sr.name
        """,(uid,)).fetchall()
        all_roles=c.execute("select id,name,permissions from site_roles order by name").fetchall()
    return jsonify(
        user={"id":uid,"username":user["username"],"global_role":user["global_role"]},
        assigned=[{"id":r[0],"name":r[1],"permissions":r[2] or {}} for r in assigned],
        all_roles=[{"id":r[0],"name":r[1],"permissions":r[2] or {}} for r in all_roles]
    )

@app.post("/api/owner/users/<int:uid>/roles/<int:rid>")
@staff_required("owner")
def owner_user_role_assign(uid,rid):
    if not row_user(uid):return jsonify(error="User not found"),404
    with connect() as c:
        if not c.execute("select 1 from site_roles where id=%s",(rid,)).fetchone():
            return jsonify(error="Role not found"),404
        c.execute("insert into user_site_roles(user_id,role_id) values(%s,%s) on conflict do nothing",(uid,rid))
        c.commit()
    audit_owner_action(request.me["id"],"assign_site_role","user",uid,f"role_id={rid}")
    return jsonify(ok=True)

@app.delete("/api/owner/users/<int:uid>/roles/<int:rid>")
@staff_required("owner")
def owner_user_role_remove(uid,rid):
    with connect() as c:
        c.execute("delete from user_site_roles where user_id=%s and role_id=%s",(uid,rid))
        c.commit()
    audit_owner_action(request.me["id"],"remove_site_role","user",uid,f"role_id={rid}")
    return jsonify(ok=True)

@app.get("/api/owner/audit-log")
@staff_required("owner")
def owner_audit_log_get():
    with connect() as c:
        rows=c.execute("""
            select l.id,l.action,l.target_type,l.target_id,l.details,l.created_at,
                   u.username
            from owner_audit_log l
            left join users u on u.id=l.actor_id
            order by l.created_at desc
            limit 300
        """).fetchall()
    return jsonify(logs=[{
        "id":r[0],"action":r[1],"target_type":r[2],"target_id":r[3],
        "details":r[4],"created_at":r[5].isoformat(),"actor_username":r[6]
    } for r in rows])

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
