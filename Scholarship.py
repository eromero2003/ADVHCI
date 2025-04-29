from flask import Flask, render_template, request, redirect, url_for, session, flash
from markupsafe import Markup
import sqlite3
from Crypto.Cipher import AES
import base64
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = 'users.db'
AES_KEY = b'0123456789abcdef0123456789abcdef'  

SCHOLARSHIPS = [
    {
        "id": 1,
        "name": "GSU Academic Excellence Scholarship",
        "description": "Awarded to students with outstanding academic achievement.",
        "student_type": ["Domestic", "International"],
        "academic_level": ["Freshman", "Sophomore", "Junior", "Senior"],
        "college_major": "Any",
        "deadline": "2025-05-30",
        "amount": "$2,500 per year",
        "requirements": [
            "Minimum GPA: 3.7",
            "Full-time enrollment",
            "Submission of academic transcript"
        ],
        "how_to_apply": "Complete the online application and upload your transcript.",
        "apply_link": "https://scholarships.gsu.edu/academic-excellence"
    },
    {
        "id": 2,
        "name": "GSU STEM Scholarship",
        "description": "Supports students pursuing degrees in STEM fields.",
        "student_type": ["Domestic"],
        "academic_level": ["Junior", "Senior", "Graduate"],
        "college_major": "STEM",
        "deadline": "2025-06-15",
        "amount": "$3,000 one-time",
        "requirements": [
            "Declared STEM major",
            "GPA: 3.5 or above",
            "Letter of recommendation from faculty"
        ],
        "how_to_apply": "Submit the application form and recommendation letter online.",
        "apply_link": "https://scholarships.gsu.edu/stem"
    },
    {
        "id": 3,
        "name": "GSU International Leadership Award",
        "description": "For international students demonstrating leadership.",
        "student_type": ["International"],
        "academic_level": ["Freshman", "Sophomore", "Junior", "Senior"],
        "college_major": "Any",
        "deadline": "2025-04-20",
        "amount": "$1,500 per semester",
        "requirements": [
            "International student status",
            "Evidence of leadership (essay required)",
            "Minimum GPA: 3.0"
        ],
        "how_to_apply": "Write a 500-word essay on your leadership experience and submit online.",
        "apply_link": "https://scholarships.gsu.edu/international-leadership"
    },
    {
        "id": 4,
        "name": "GSU Business Scholars Award",
        "description": "For business majors with high academic performance.",
        "student_type": ["Domestic", "International"],
        "academic_level": ["Junior", "Senior"],
        "college_major": "Business",
        "deadline": "2025-07-01",
        "amount": "$2,000 per year",
        "requirements": [
            "Business major",
            "GPA: 3.6 or above",
            "Resume and cover letter"
        ],
        "how_to_apply": "Upload your resume and cover letter through the portal.",
        "apply_link": "https://scholarships.gsu.edu/business-scholars"
    },
    {
        "id": 5,
        "name": "GSU First-Generation Student Grant",
        "description": "Supporting first-generation college students at GSU.",
        "student_type": ["Domestic"],
        "academic_level": ["Freshman", "Sophomore"],
        "college_major": "Any",
        "deadline": "2025-08-15",
        "amount": "$1,000 one-time",
        "requirements": [
            "First-generation college student",
            "Personal statement (250 words)",
            "Proof of enrollment"
        ],
        "how_to_apply": "Submit your personal statement and proof of enrollment online.",
        "apply_link": "https://scholarships.gsu.edu/first-gen"
    },
    {
        "id": 6,
        "name": "GSU Community Service Scholarship",
        "description": "Recognizing students with exemplary community service.",
        "student_type": ["Domestic", "International"],
        "academic_level": ["Sophomore", "Junior", "Senior"],
        "college_major": "Any",
        "deadline": "2025-09-10",
        "amount": "$1,200 per year",
        "requirements": [
            "Minimum 50 hours of community service in the past year",
            "Service verification letter",
            "GPA: 2.8 or above"
        ],
        "how_to_apply": "Upload your verification letter and fill out the application form.",
        "apply_link": "https://scholarships.gsu.edu/community-service"
    },
    {
        "id": 7,
        "name": "GSU Graduate Research Fellowship",
        "description": "For graduate students conducting outstanding research.",
        "student_type": ["Domestic", "International"],
        "academic_level": ["Graduate"],
        "college_major": "Any",
        "deadline": "2025-10-01",
        "amount": "$4,000 per semester",
        "requirements": [
            "Graduate student status",
            "Research proposal (max 2 pages)",
            "Faculty advisor endorsement"
        ],
        "how_to_apply": "Submit your research proposal and advisor endorsement online.",
        "apply_link": "https://scholarships.gsu.edu/grad-research"
    }
]

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt_password(password):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(password).encode('utf-8'))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def decrypt_password(enc_password):
    enc = base64.b64decode(enc_password)
    iv = enc[:16]
    ct = enc[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt.decode('utf-8'))

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campusid TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS saved_scholarships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campusid TEXT NOT NULL,
            scholarship_id INTEGER NOT NULL,
            UNIQUE (campusid, scholarship_id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS general_application (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campusid TEXT NOT NULL,
            major TEXT,
            personal_background TEXT,
            lapse_in_enrollment TEXT,
            campus_housing TEXT,
            academic_interests TEXT,
            why_gsu TEXT,
            scholarship_help TEXT,
            benefit_gsu TEXT,
            obstacles_family TEXT,
            obstacles_school TEXT,
            betterment_groups TEXT,
            betterment_explain TEXT,
            employment_status TEXT,
            student_success_roles TEXT,
            community_service TEXT,
            employment_info TEXT,
            reference_contacts TEXT,
            authorize_statement INTEGER,
            full_name TEXT,
            authorize_date TEXT,
            submitted INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS arts_science_application (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campusid TEXT NOT NULL,
            major TEXT,
            personal_background TEXT,
            lapse_in_enrollment TEXT,
            campus_housing TEXT,
            academic_interests TEXT,
            why_gsu TEXT,
            scholarship_help TEXT,
            benefit_gsu TEXT,
            obstacles_family TEXT,
            obstacles_school TEXT,
            betterment_groups TEXT,
            betterment_explain TEXT,
            employment_status TEXT,
            student_success_roles TEXT,
            community_service TEXT,
            employment_info TEXT,
            reference_contacts TEXT,
            authorize_statement INTEGER,
            full_name TEXT,
            authorize_date TEXT,
            submitted INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        dt = datetime.strptime(value, "%Y-%m-%d")
        return dt.strftime("%b %d, %Y")
    except Exception:
        return value

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and request.form.get("action") == "login":
        campusid = request.form['campusid']
        password = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE campusid=?", (campusid,))
        row = c.fetchone()
        conn.close()
        if row:
            try:
                if decrypt_password(row[0]) == password:
                    session['user'] = campusid
                    return redirect(url_for('homepage'))
                else:
                    flash('Invalid credentials', 'danger')
            except Exception:
                flash('Decryption error.', 'danger')
        else:
            flash('Invalid credentials', 'danger')
    elif request.method == 'POST' and request.form.get("action") == "signup":
        campusid = request.form['campusid_signup']
        password = request.form['password_signup']
        if not campusid or not password:
            flash('Please fill out all fields.', 'danger')
        else:
            enc_password = encrypt_password(password)
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO users (campusid, password) VALUES (?, ?)", (campusid, enc_password))
                conn.commit()
                conn.close()
                flash('Account created successfully! Please log in.', 'success')
            except sqlite3.IntegrityError:
                flash('CampusID already exists.', 'danger')
    return render_template('login.html')

@app.route('/homepage', methods=['GET'])
def homepage():
    if 'user' not in session:
        return redirect(url_for('login'))

    # --- Search and Filter Logic ---
    search = request.args.get('search', '').lower()
    student_type = request.args.getlist('student_type')
    academic_level = request.args.getlist('academic_level')
    college_major = request.args.get('college_major', '')
    deadline_filter = request.args.getlist('deadline')

    filtered = SCHOLARSHIPS
    if search:
        filtered = [s for s in filtered if search in s['name'].lower() or search in s['description'].lower()]
    if student_type:
        filtered = [s for s in filtered if any(st in s['student_type'] for st in student_type)]
    if academic_level:
        filtered = [s for s in filtered if any(al in s['academic_level'] for al in academic_level)]
    if college_major and college_major != "Any" and college_major != "":
        filtered = [s for s in filtered if s['college_major'] == college_major or s['college_major'] == "Any"]
    now = datetime.now()
    if "1" in deadline_filter:
        filtered = [s for s in filtered if datetime.strptime(s['deadline'], "%Y-%m-%d") <= now + timedelta(days=30)]
    elif "3" in deadline_filter:
        filtered = [s for s in filtered if datetime.strptime(s['deadline'], "%Y-%m-%d") <= now + timedelta(days=90)]
    elif "future" in deadline_filter:
        filtered = [s for s in filtered if datetime.strptime(s['deadline'], "%Y-%m-%d") > now + timedelta(days=90)]

    majors = sorted({s['college_major'] for s in SCHOLARSHIPS if s['college_major'] != "Any"})

    return render_template(
        'homepage.html',
        user=session['user'],
        scholarships=filtered,
        majors=majors,
        selected_major=college_major,
        search=search,
        selected_student_type=student_type,
        selected_academic_level=academic_level,
        selected_deadline=deadline_filter
    )

@app.route('/scholarship/<int:scholarship_id>')
def scholarship_detail(scholarship_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    scholarship = next((s for s in SCHOLARSHIPS if s['id'] == scholarship_id), None)
    if not scholarship:
        return "Scholarship not found", 404
    return render_template('scholarship_detail.html', scholarship=scholarship)

@app.route('/save_scholarship/<int:scholarship_id>', methods=['POST'])
def save_scholarship(scholarship_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    campusid = session['user']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO saved_scholarships (campusid, scholarship_id) VALUES (?, ?)",
            (campusid, scholarship_id)
        )
        conn.commit()
        flash('Scholarship saved!', 'success')
    except sqlite3.IntegrityError:
        flash('Scholarship already saved.', 'info')
    finally:
        conn.close()
    return redirect(request.referrer or url_for('homepage'))

@app.route('/saved_scholarships')
def saved_scholarships():
    if 'user' not in session:
        return redirect(url_for('login'))
    campusid = session['user']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT scholarship_id FROM saved_scholarships WHERE campusid = ?", (campusid,))
    rows = c.fetchall()
    conn.close()
    saved_ids = [row[0] for row in rows]
    saved = [s for s in SCHOLARSHIPS if s['id'] in saved_ids]
    return render_template('saved_scholarships.html', saved_scholarships=saved)

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html', user=session['user'])

@app.route('/apply_general', methods=['GET', 'POST'])
def apply_general():
    if 'user' not in session:
        return redirect(url_for('login'))
    campusid = session['user']

    majors = sorted({s['college_major'] for s in SCHOLARSHIPS if s['college_major'] != "Any"})
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM general_application WHERE campusid=?', (campusid,))
    user_app = c.fetchone()
    colnames = [desc[0] for desc in c.description]
    conn.close()

    if request.method == 'POST':
        data = {
            'major': request.form.get('major', ''),
            'personal_background': ','.join(request.form.getlist('personal_background')),
            'lapse_in_enrollment': request.form.get('lapse_in_enrollment', ''),
            'campus_housing': request.form.get('campus_housing', ''),
            'academic_interests': ','.join(request.form.getlist('academic_interests')),
            'why_gsu': request.form.get('why_gsu', ''),
            'scholarship_help': request.form.get('scholarship_help', ''),
            'benefit_gsu': request.form.get('benefit_gsu', ''),
            'obstacles_family': request.form.get('obstacles_family', ''),
            'obstacles_school': request.form.get('obstacles_school', ''),
            'betterment_groups': ','.join(request.form.getlist('betterment_groups')),
            'betterment_explain': request.form.get('betterment_explain', ''),
            'employment_status': request.form.get('employment_status', ''),
            'student_success_roles': ','.join(request.form.getlist('student_success_roles')),
            'community_service': request.form.get('community_service', ''),
            'employment_info': request.form.get('employment_info', ''),
            'reference_contacts': request.form.get('reference_contacts', ''),
            'authorize_statement': 1 if request.form.get('authorize_statement') == 'on' else 0,
            'full_name': request.form.get('full_name', ''),
            'authorize_date': request.form.get('authorize_date', ''),
            'submitted': 1 if request.form.get('submit') == 'finish' else 0
        }
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if user_app:
            c.execute('''
                UPDATE general_application SET
                major=?, personal_background=?, lapse_in_enrollment=?, campus_housing=?, academic_interests=?,
                why_gsu=?, scholarship_help=?, benefit_gsu=?, obstacles_family=?, obstacles_school=?,
                betterment_groups=?, betterment_explain=?, employment_status=?, student_success_roles=?,
                community_service=?, employment_info=?, reference_contacts=?, authorize_statement=?, full_name=?, authorize_date=?, submitted=?
                WHERE campusid=?
            ''', (*data.values(), campusid))
        else:
            c.execute('''
                INSERT INTO general_application (
                    campusid, major, personal_background, lapse_in_enrollment, campus_housing, academic_interests,
                    why_gsu, scholarship_help, benefit_gsu, obstacles_family, obstacles_school, betterment_groups,
                    betterment_explain, employment_status, student_success_roles, community_service, employment_info,
                    reference_contacts, authorize_statement, full_name, authorize_date, submitted
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (campusid, *data.values()))
        conn.commit()
        conn.close()
        if data['submitted']:
            flash('Application submitted!', 'success')
        else:
            flash('Progress saved. You can continue editing.', 'info')
        return redirect(url_for('apply_general'))

    form_data = {}
    if user_app:
        form_data = dict(zip(colnames, user_app))
    return render_template(
        'apply_general.html',
        majors=majors,
        form_data=form_data
    )

@app.route('/apply_arts_science', methods=['GET', 'POST'])
def apply_arts_science():
    if 'user' not in session:
        return redirect(url_for('login'))
    campusid = session['user']
    majors = [
        "Biology", "Chemistry", "Computer Science", "English", "Mathematics", "Psychology", "Sociology"
    ]

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM arts_science_application WHERE campusid=?', (campusid,))
    user_app = c.fetchone()
    colnames = [desc[0] for desc in c.description]
    conn.close()

    if request.method == 'POST':
        data = {
            'major': request.form.get('major', ''),
            'personal_background': ','.join(request.form.getlist('personal_background')),
            'lapse_in_enrollment': request.form.get('lapse_in_enrollment', ''),
            'campus_housing': request.form.get('campus_housing', ''),
            'academic_interests': ','.join(request.form.getlist('academic_interests')),
            'why_gsu': request.form.get('why_gsu', ''),
            'scholarship_help': request.form.get('scholarship_help', ''),
            'benefit_gsu': request.form.get('benefit_gsu', ''),
            'obstacles_family': request.form.get('obstacles_family', ''),
            'obstacles_school': request.form.get('obstacles_school', ''),
            'betterment_groups': ','.join(request.form.getlist('betterment_groups')),
            'betterment_explain': request.form.get('betterment_explain', ''),
            'employment_status': request.form.get('employment_status', ''),
            'student_success_roles': ','.join(request.form.getlist('student_success_roles')),
            'community_service': request.form.get('community_service', ''),
            'employment_info': request.form.get('employment_info', ''),
            'reference_contacts': request.form.get('reference_contacts', ''),
            'authorize_statement': 1 if request.form.get('authorize_statement') == 'on' else 0,
            'full_name': request.form.get('full_name', ''),
            'authorize_date': request.form.get('authorize_date', ''),
            'submitted': 1 if request.form.get('submit') == 'finish' else 0
        }
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if user_app:
            c.execute('''
                UPDATE arts_science_application SET
                major=?, personal_background=?, lapse_in_enrollment=?, campus_housing=?, academic_interests=?,
                why_gsu=?, scholarship_help=?, benefit_gsu=?, obstacles_family=?, obstacles_school=?,
                betterment_groups=?, betterment_explain=?, employment_status=?, student_success_roles=?,
                community_service=?, employment_info=?, reference_contacts=?, authorize_statement=?, full_name=?, authorize_date=?, submitted=?
                WHERE campusid=?
            ''', (*data.values(), campusid))
        else:
            c.execute('''
                INSERT INTO arts_science_application (
                    campusid, major, personal_background, lapse_in_enrollment, campus_housing, academic_interests,
                    why_gsu, scholarship_help, benefit_gsu, obstacles_family, obstacles_school, betterment_groups,
                    betterment_explain, employment_status, student_success_roles, community_service, employment_info,
                    reference_contacts, authorize_statement, full_name, authorize_date, submitted
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (campusid, *data.values()))
        conn.commit()
        conn.close()
        if data['submitted']:
            flash('Application submitted!', 'success')
        else:
            flash('Progress saved. You can continue editing.', 'info')
        return redirect(url_for('apply_arts_science'))

    form_data = {}
    if user_app:
        form_data = dict(zip(colnames, user_app))
    return render_template(
        'apply_arts_science.html',
        majors=majors,
        form_data=form_data
    )

@app.route('/application_status')
def application_status():
    applications = [
        {
            "name": "GSU Academic Excellence Scholarship",
            "amount": "$2,500 per year",
            "deadline": "May 30, 2025",
            "eligibility": "Freshman, Sophomore, Junior, Senior, Domestic, International",
            "status": "pending" 
        },
    ]
    return render_template('application_status.html', applications=applications)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)




