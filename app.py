"""둘의 하루 — 로컬/오프라인 커플 다이어리

[처음 한 번 준비: 패키지 다운로드에는 인터넷 필요]
  pip install -r requirements.txt
[실행: 이후 인터넷/외부 DB/Streamlit Secrets 불필요]
  streamlit run app.py --server.address 0.0.0.0 --server.port 8501 --browser.gatherUsageStats false

PC 브라우저: http://localhost:8501
휴대폰: 실행 PC와 같은 Wi-Fi에 연결한 후 http://PC의내부IPv4주소:8501
앱의 QR 버튼에서 위 휴대폰 접속 주소를 입력하여 QR을 만듭니다.
Windows의 ipconfig, macOS의 시스템 설정 > Wi-Fi > 세부사항에서 PC 주소를 확인하세요.
방화벽에서는 신뢰하는 사설 네트워크에 한해 8501 포트를 허용하세요.
게스트 Wi-Fi/단말 격리가 켜져 있으면 휴대폰 접속이 차단될 수 있습니다.

최초 화면에서 두 사람의 이름과 서로 다른 비밀번호를 등록합니다.
일기/계정은 app.py 옆 couple_diary.sqlite3에 저장됩니다.
비밀번호는 솔트가 있는 PBKDF2 해시로 저장되지만 일기 본문은 암호화되지 않습니다.
종료 후 DB 파일을 안전한 곳에 복사하면 백업할 수 있습니다.
PC가 켜져 있고 앱이 실행 중이어야 휴대폰에서 접속됩니다.
인터넷을 통한 원격 접속/포트포워딩 용도가 아닙니다. 신뢰하는 Wi-Fi에서만 사용하세요.
HTTP 접속은 전송 암호화가 없으므로 공용 Wi-Fi에서 사용하지 마세요.
Streamlit Cloud에서도 실행은 가능하나 로컬 디스크 기록은 영구 보존되지 않습니다.
이 버전은 PC 로컬 실행용입니다. 휴대폰 단독 설치형 앱은 아닙니다.
"""
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import hmac
import html
import secrets
import sqlite3
import time

import qrcode
import streamlit as st

st.set_page_config(page_title="둘의 하루", page_icon="💌", layout="centered", initial_sidebar_state="collapsed")
DB_PATH = Path(__file__).resolve().with_name("couple_diary.sqlite3")
KST = timezone(timedelta(hours=9))
MOODS = ["🥰 행복", "😊 평온", "🥺 그리움", "😴 피곤", "😢 속상", "😤 화남"]

st.markdown("""<style>
[data-testid="stHeader"]{display:none}
.block-container{max-width:470px;padding:.5rem .8rem .6rem!important}
[data-testid="stAppViewContainer"]{background:#fff8f6}
[data-testid="stVerticalBlock"]{gap:.35rem}
h1{font-size:1.5rem!important;padding:0!important;color:#633b49}
p{margin-bottom:.2rem}
[data-testid="stTextArea"] textarea{font-size:16px;min-height:88px!important}
[data-testid="stTextInput"] input{font-size:16px}
.stButton button,.stDownloadButton button{min-height:2.25rem;border-radius:12px}
.diary{height:104px;overflow-y:auto;white-space:pre-wrap;overflow-wrap:anywhere;
background:#fff;border:1px solid #eed8df;border-radius:14px;padding:9px 12px;
color:#49343b;font-size:14px;line-height:1.5}
.tag{font-size:12px;color:#754957;margin-bottom:4px}
.brand{font-weight:800;font-size:22px;color:#633b49}
@media(max-height:690px){.diary{height:80px}}
</style>""", unsafe_allow_html=True)


@contextmanager
def database():
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize():
    with database() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY CHECK(id IN ('a','b')), name TEXT NOT NULL,
            salt TEXT NOT NULL, password_hash TEXT NOT NULL,
            failures INTEGER NOT NULL DEFAULT 0, blocked_until REAL NOT NULL DEFAULT 0,
            last_failure REAL NOT NULL DEFAULT 0)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS entries (
            author TEXT NOT NULL, day TEXT NOT NULL, mood TEXT NOT NULL,
            body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 800),
            updated_at TEXT NOT NULL, read_at TEXT,
            version INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(author,day))""")


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000).hex()


def users():
    with database() as conn:
        return {row["id"]: dict(row) for row in conn.execute("SELECT * FROM users")}


def register(name_a, pass_a, name_b, pass_b):
    records = []
    for key, name, password in (("a", name_a, pass_a), ("b", name_b, pass_b)):
        salt = secrets.token_hex(16)
        records.append((key, name, salt, password_hash(password, salt)))
    with database() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT count(*) FROM users").fetchone()[0]:
            return False
        conn.executemany("INSERT INTO users(id,name,salt,password_hash) VALUES (?,?,?,?)", records)
    return True


def login(account, password):
    with database() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM users WHERE id=?", (account,)).fetchone()
        now = time.time()
        if not row or row["blocked_until"] > now:
            return False, "로그인 시도가 많아요. 5분 후 다시 시도해주세요."
        if hmac.compare_digest(password_hash(password, row["salt"]), row["password_hash"]):
            conn.execute("UPDATE users SET failures=0,blocked_until=0,last_failure=0 WHERE id=?", (account,))
            return True, ""
        failures = row["failures"] + 1 if now - row["last_failure"] < 300 else 1
        conn.execute("UPDATE users SET failures=?,blocked_until=?,last_failure=? WHERE id=?", (failures, now+300 if failures >= 5 else 0, now, account))
        return False, "비밀번호를 확인해주세요. 5회 실패하면 5분간 잠깁니다."


def now_text():
    return datetime.now(KST).isoformat(timespec="seconds")


def entries(day):
    with database() as conn:
        return {r["author"]: dict(r) for r in conn.execute("SELECT * FROM entries WHERE day=?", (str(day),))}


def save(author, day, mood, body):
    with database() as conn:
        conn.execute("""INSERT INTO entries(author,day,mood,body,updated_at) VALUES (?,?,?,?,?)
            ON CONFLICT(author,day) DO UPDATE SET mood=excluded.mood,body=excluded.body,
            updated_at=excluded.updated_at,read_at=NULL,version=entries.version+1""", (author,str(day),mood,body,now_text()))


def acknowledge(author, day, version):
    with database() as conn:
        result = conn.execute("UPDATE entries SET read_at=? WHERE author=? AND day=? AND version=? AND read_at IS NULL", (now_text(),author,str(day),version))
        return result.rowcount == 1


def stamp(value):
    return datetime.fromisoformat(value).astimezone(KST).strftime("%m/%d %H:%M") if value else ""


@st.dialog("같은 Wi-Fi에서 QR로 접속")
def qr_dialog():
    st.caption("PC의 내부 IPv4 주소를 입력하세요. 예: http://192.168.0.10:8501 · localhost는 휴대폰에서 사용할 수 없어요.")
    address = st.text_input("휴대폰 접속 주소", value=st.session_state.get("share_url", ""), placeholder="http://PC의내부IP:8501")
    parsed = urlparse(address)
    try:
        port = parsed.port
        valid = parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    except ValueError:
        valid = False
    if not address:
        return
    if not valid or parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        st.warning("PC의 실제 내부 IP가 포함된 http://주소:8501 형식으로 입력해주세요.")
        return
    st.session_state.share_url = address
    image = BytesIO()
    qrcode.make(address).save(image, format="PNG")
    st.image(image.getvalue(), width=210)
    st.download_button("QR 다운로드", image.getvalue(), "couple-qr.png", "image/png")
    st.caption("두 휴대폰과 PC를 같은 Wi-Fi에 연결하고 PC에서 앱을 계속 실행해주세요.")


def setup():
    st.title("💌 둘의 하루")
    st.caption("최초 한 번만 등록하면 끝! 외부 DB나 Secrets는 필요 없어요.")
    with st.form("setup"):
        name_a = st.text_input("첫 번째 이름", value="나무", max_chars=16)
        pass_a = st.text_input("첫 번째 비밀번호 (8자 이상)", type="password")
        name_b = st.text_input("두 번째 이름", value="구름", max_chars=16)
        pass_b = st.text_input("두 번째 비밀번호 (8자 이상)", type="password")
        submit = st.form_submit_button("우리 일기 시작하기", type="primary", use_container_width=True)
    if submit:
        if not name_a.strip() or not name_b.strip() or name_a.strip() == name_b.strip():
            st.error("서로 다른 이름 두 개를 입력해주세요.")
        elif len(pass_a) < 8 or len(pass_b) < 8 or pass_a == pass_b:
            st.error("서로 다른 비밀번호를 각각 8자 이상 입력해주세요.")
        else:
            register(name_a.strip(), pass_a, name_b.strip(), pass_b)
            st.rerun()
    st.caption("처음 등록은 PC에서 진행하세요. 비밀번호 복구 기능은 없으니 안전하게 보관해주세요.")


def main():
    initialize()
    people = users()
    if not people:
        setup()
        return
    if st.session_state.get("account") not in people:
        st.title("💌 둘의 하루")
        st.caption("오늘의 마음을, 가장 가까운 사람에게")
        with st.form("login"):
            account = st.selectbox("나는", list(people), format_func=lambda a: people[a]["name"])
            password = st.text_input("비밀번호", type="password")
            submit = st.form_submit_button("우리 일기 열기", type="primary", use_container_width=True)
        if submit:
            ok, message = login(account, password)
            if ok:
                st.session_state.account = account
                st.rerun()
            else:
                st.error(message)
        st.caption("🔒 이 PC의 로컬 파일에 저장 · 같은 Wi-Fi에서 함께 사용")
        return
    me = st.session_state.account
    partner = "b" if me == "a" else "a"
    names = {a: people[a]["name"] for a in people}
    a,b,c = st.columns([6,1.5,2])
    a.markdown('<div class="brand">💌 둘의 하루</div>', unsafe_allow_html=True)
    if b.button("QR", use_container_width=True):
        qr_dialog()
    if c.button("나가기", use_container_width=True):
        st.session_state.clear()
        st.rerun()
    today = datetime.now(KST).date()
    day = st.date_input("일기 날짜 · 한국 시간", value=today, min_value=date(2000,1,1), max_value=today)
    mine = entries(day).get(me)
    key = f"{me}_{day}"
    st.caption(f"✏️ {names[me]}의 마음 · 하루 한 편, 수정 가능")
    with st.form(f"write_{key}"):
        mood = st.selectbox("오늘 기분", MOODS, index=MOODS.index(mine["mood"]) if mine and mine["mood"] in MOODS else 0, key=f"mood_{key}", label_visibility="collapsed")
        body = st.text_area("나의 일기", value=mine["body"] if mine else "", height=88, max_chars=800, placeholder="오늘 너에게 들려주고 싶은 이야기…", key=f"body_{key}", label_visibility="collapsed")
        submit = st.form_submit_button("💌 수정해서 보내기" if mine else "💌 마음 보내기", type="primary", use_container_width=True)
    if submit:
        if body.strip():
            save(me,day,mood,body.strip())
            st.toast("마음을 저장했어요 💌")
            st.rerun()
        else:
            st.toast("오늘의 마음을 짧게라도 적어주세요.")

    @st.fragment(run_every="15s")
    def shared_panel():
        try:
            rows = entries(day)
            own, other = rows.get(me), rows.get(partner)
            if own:
                st.caption(f"내 일기 · ✅ {names[partner]} 확인 {stamp(own['read_at'])}" if own["read_at"] else "내 일기 · 💌 아직 상대가 확인하지 않았어요")
            else:
                st.caption("내 일기 · 오늘의 마음을 기다려요")
            if other:
                label = f"{names[partner]}의 마음 · {other['mood']} · {stamp(other['updated_at'])}"
                st.markdown(f'<div class="tag">{html.escape(label)}</div><div class="diary">{html.escape(other["body"])}</div>', unsafe_allow_html=True)
                checked = st.checkbox("확인했어요 💗", value=bool(other["read_at"]), disabled=bool(other["read_at"]), key=f"read_{key}_{other['version']}")
                if checked and not other["read_at"]:
                    changed = acknowledge(partner, day, other["version"])
                    st.toast("상대에게 확인 표시를 남겼어요 💗" if changed else "일기가 갱신됐어요. 다시 확인해주세요.")
                    st.rerun(scope="fragment")
            else:
                st.markdown(f'<div class="diary">{html.escape(names[partner])}의 일기가 아직 없어요.\n조금만 기다려볼까요? 🌷</div>', unsafe_allow_html=True)
            st.caption("💾 PC에 저장 · 15초마다 확인 · 수정하면 읽음 초기화")
        except sqlite3.Error:
            st.warning("저장소가 잠시 사용 중이에요. 잠시 후 다시 확인합니다.")
    shared_panel()


if __name__ == "__main__":
    try:
        main()
    except sqlite3.Error:
        st.error("로컬 저장소를 열지 못했어요. 앱 폴더의 쓰기 권한과 여유 공간을 확인해주세요. DB 파일은 삭제하지 마세요.")
        if st.button("다시 시도"):
            st.rerun()
