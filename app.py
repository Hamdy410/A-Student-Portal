from os import environ
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from sendgrid.helpers.mail import Mail, Email, To, Content
import sendgrid
from werkzeug.security import check_password_hash, generate_password_hash
from re import match, search
from string import ascii_letters, digits
from random import choice
from datetime import timedelta
from csv import DictReader
from time import sleep
from json import loads

from helpers import *


app = Flask(__name__)

# Configure the sessions to be permanent and last for only 15 minutes per usage
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
Session(app)

# This is an API Key provided through the platform SENDGRID, which is stored in the environment to check the validity of the e-mail
sg = sendgrid.SendGridAPIClient(api_key=environ.get("SENDGRID_API_KEY"))

# This is the e-mail that will send the OTP. In this case, It's not provided for security reasons but should be inserted (preferred to be extracted from the environment variables) make the function initiated.
from_email = Email(environ.get("SOURCE_EMAIL"))
subject = "First time Registration OTP"

# This is the path to the database file which uses sqlite3. Currently the data inside the file is empty and that's why a python program called "encrypt.py" is provided separately
db = SQL("sqlite:///uni.db")


# The list of items needed in case changed or appended manually by the developers in the future
IDENTITIES = ["Students", "Faculty Staff", "Admins"]

# The names of the countries and their nationalities are found in a .csv file named as new_countries.csv (for easier editing) and the data is extracted
# Please note that the csv file is credit to https://gist.github.com/zspine/2365808#file-countries-csv.
# Since some countries in the file are not currently found (i.e., the U.S. Miscellaneous Pacific Islands, the U.S.S.R, etc.), I edited the csv file and compared its contents using pycountry library. In case of any abnormalities in the names, codes or nationalities or in case some countries' names are not found, it will be completely unintended.
with open("new_countries.csv", "r") as file:
    file_reader = DictReader(file)
    rows = list(file_reader)

# Constants needed to be used for verification purposes
COUNTRIES = sorted([row["Name"] for row in rows])  # type: ignore
NATIONALITIES = sorted([row["Nationality"] for row in rows if row["Nationality"] != "???"])  # type: ignore
NATIONALITIES = list(set(NATIONALITIES))
NATIONALITIES.sort()
GENDERS = ["M", "F"]
RELIGIONS = ["Islam", "Christianity"]
YEARS_OF_STUDY = ["1", "2", "3", "4"]
SEMESTERS = ["1", "2"]
FACULTY_STAFF_ROLES = [
    "Classroom Instructor",
    "Researcher",
    "Academic Advisor",
    "Curriculum Developer",
    "Department Chair",
    "Program Director",
    "Dean",
    "Research Collaborator",
    "Committee Member",
    "Community Engager",
    "Mentor",
    "Lecturer",
    "Scholarly Writer",
    "Advocate for Inclusion and Diversity",
    "Professional Development Participant",
]
FACULTY_STAFF_ROLES.sort()
MAJORS = [
    "Artificial Intelligence",
    "Cybersecurity",
    "Software Engineering",
    "Bioinformatics",
    "Robotics",
    "Digital Multi-Media",
    "Computer Science",
    "Scientific Computing",
    "Information Systems",
    "Game Development",
    "Data Science and Analytics",
]
MAJORS.sort()
CREDIT_HOURS = ["1", "2", "3"]

MASTER_ADMIN_CONTROL_UNIT_PASSWORD = "_e^><+@~a]cUOA9L#y(dT[3J|}r*:DSMoHpVb"


@app.after_request
def after_request(response):
    response.headers["Cache-control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()
    if request.method == "POST":
        data = request.get_json()
        if (
            not data["identity"]
            or data["identity"] not in IDENTITIES
            or not data["user_name"]
        ):
            return jsonify({"url": "/apology"})

        # Store the beginning of the user data
        identity = clean(data["identity"])
        user_id = data["user_name"]

        # Check the presence of the user themselves or that they were suspended for authoritative reasons
        rows = db.execute("SELECT * FROM ? WHERE user_id = ?", identity, user_id)
        if len(rows) != 1:
            return jsonify({"PasswordIsWrong": True})

        # if the user is a first timer, by default their pass_hash will be None from the database
        # if they were: send them to the register page where they will start to register some sensitive data
        # if the user was not found then render the apology page
        # if the user was found and password was wrong it would send an alert message handled by JSON
        if rows[0]["password_hash"] is None:
            session["identity"] = identity
            session["user_id"] = rows[0]["user_id"]
            session["approved_to_register"] = True
            return jsonify({"url": "/register", "PasswordIsWrong": False})
        elif not check_password_hash(rows[0]["password_hash"], data["password"]):
            return jsonify({"PasswordIsWrong": True})
        else:
            session["identity"] = identity
            session["user_id"] = rows[0]["user_id"]
            if rows[0]["status"] == "suspended":
                return jsonify({"url": "/apology", "PasswordIsWrong": False})

            if identity == "admins":
                return jsonify({"url": "/admins", "PasswordIsWrong": False})
            elif identity == "faculty_staff":
                return jsonify({"url": "/faculty_staff", "PasswordIsWrong": False})
            elif identity == "students":
                return jsonify({"url": "/students", "PasswordIsWrong": False})

            return jsonify({"url": "/", "PasswordIsWrong": False})

    else:
        return render_template("login.html", identities=IDENTITIES)


@app.route("/register", methods=["POST", "GET"])  # type: ignore
@login_required
def register():
    """
    This page is used to allow the first time user (student, admin, or faculty_staff)
    who were preregistered by active admins to insert their active emails
    along with personal password.
    """
    user_id = session.get("user_id")
    identity = session.get("identity")
    checks = [
        "Length between 5 and 10 characters",
        "Contains at Least 1 Numerical Character",
        "Contains at least 1 UpperCase",
        "Contains at least 1 LowerCase",
        "Contains at least 1 Special Character",
        "No Spaces",
    ]
    if request.method == "POST":
        data = request.get_json()
        national_id = data["national_id"]
        email = data["email"]
        password = data["password"]
        confirmed_password = data["confirmed_password"]

        # Check that all the information are not empty strings
        if (
            national_id == ""
            or email == ""
            or password == ""
            or confirmed_password == ""
        ):
            return jsonify({"url": "/apology"})

        # Check that the national_id Is found in the database
        rows = db.execute(
            "SELECT encrypted_info, nonce, tag FROM secure WHERE id = (SELECT nationalId_id FROM ? WHERE user_id = ?)",
            identity,
            user_id,
        )
        nationalId_from_database = decrypt(
            rows[0]["encrypted_info"], rows[0]["nonce"], rows[0]["tag"]
        )
        if nationalId_from_database != national_id:
            return jsonify({"url": "/apology", "NationalIdIsNotFound": True})

        # Check that the email is formatted correctly
        email_pattern = r"^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$"
        if match(email_pattern, email) is False:
            return jsonify({"url": "/apology"})

        # Check that the password follows the right characteristics
        if (
            (not (5 <= len(password) <= 10))
            or (search(r"[0-9]", password) is None)
            or (search(r"[a-z]", password) is None)
            or (search(r"[A-Z]", password) is None)
            or (search(r"[^A-Za-z0-9]", password) is None)
            or (" " in password)
            or (not password)
        ):
            return jsonify({"url": "/apology"})

        # Check that the password is equivalent to the confirmed_password
        if password != confirmed_password:
            return jsonify({"url": "/apology"})

        password_hash = generate_password_hash(password)
        session["password_hash"] = password_hash
        session["email"] = email
        session["approved_to_otp"] = True
        return jsonify({"url": "/send_otp"})
    else:
        # Check that the user has never registered themselves and that they are approved by the session. After the page loads, the session is turned False.
        rows = db.execute(
            "SELECT password_hash FROM ? WHERE user_id = ?", identity, user_id
        )
        if session.get("approved_to_register") is False or not session.get(
            "approved_to_register"
        ):
            return redirect("/apology")
        elif rows[0]["password_hash"] is not None:
            return redirect("/login")
        elif session.get("approved_to_register") is True:
            session["approved_to_register"] = False
            return render_template(
                "register.html", checks=checks, template_name="register.html"
            )


@app.route("/send_otp", methods=["POST", "GET"])  # type: ignore
@login_required
def send_otp():
    """Render an OTP page to check the validity of the user's email."""

    session["attempts"] = 0
    member_id = session.get("user_id")
    identity = session.get("identity")

    if request.method == "POST":
        while session.get("attempts") < 4:  # type: ignore
            data = request.get_json()
            if not data["send"] or not data["otp"] or data["send"] is not True:
                return jsonify({"url": "/apology"})

            # Compare between the inserted otp and the real otp
            server_otp = session.get("otp")
            user_otp = data["otp"]
            user_otp = "".join(user_otp)
            if server_otp != user_otp:
                return jsonify({"OTPIsWrong": True})  # type: ignore

            # Call all the required sessions to allow the configuration into the database
            email = session.get("email")
            password_hash = session.get("password_hash")

            # encrypt the email and get its ciphertext, nonce, and tag
            encrypted_email = encrypt(email)

            db.execute(
                "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES (?, ?, ?, ?, 'email')",
                member_id,
                encrypted_email["ciphertext"],
                encrypted_email["nonce"],
                encrypted_email["tag"],
            )
            db.execute(
                "UPDATE ? SET password_hash = ? WHERE user_id = ?",
                identity,
                password_hash,
                member_id,
            )
            return jsonify({"url": "/login"})

        return jsonify({"url": "/apology"})
    else:
        # Checks that the user has never registered before. However, for OTP idealization reasons we can't pop the approval session,
        # because that OTP could be sent more than once and that will be understood after looking into the html page and its javascript.
        rows = db.execute(
            "SELECT password_hash FROM ? WHERE user_id = ?", identity, member_id
        )
        if rows[0]["password_hash"] is not None:
            return apology("An error Occurred", 403)

        # Check the required data which are the approval session, email, password_hash
        if (
            not session.get("approved_to_otp")
            or not session.get("password_hash")
            or not session.get("email")
            or session.get("approved_to_otp") is not True
        ):
            return redirect("/apology")
        else:
            # Increase the attempts to become 1 (i.e., first attempt) and it should be installed as a session to become unique among different users.
            session["attempts"] = session.get("attempts") + 1  # type: ignore
            if session.get("attempts") == 4:
                session.clear()
                return apology(
                    "You exceeded the number of times (3 times) to send OTP. Please check your e-mail was correct and try again.",
                    429,
                )

            # Start generating an OTP using 6 characters of distinctive digits and letters
            all_chars = ascii_letters + digits
            otp = ""
            for i in range(6):
                otp += choice(all_chars)

            # Send an email with the OTP of the user as from https://docs.sendgrid.com/for-developers/sending-email/quickstart-python
            to_email = To(session.get("email"))
            content = Content("text/plain", f"Your OTP is {otp}")
            mail = Mail(from_email, to_email, subject, content)
            mail_json = mail.get()

            # This line is a necessity to send the HTTPS order for the email to be sent.
            sg.client.mail.send.post(request_body=mail_json)  # type: ignore

            session["otp"] = otp
            return render_template("otp.html")


@app.route("/master_admin_control_unit")
@login_required
def master_admin_control_unit():
    """Opens the Instructions page for the Master Admin and how to use it."""
    user_id = session.get("user_id")
    identity = session.get("identity")
    if not session.get("approved_to_master") or identity != "admins":
        return redirect("/apology")

    rows = db.execute(
        "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'", user_id
    )
    if len(rows) != 1:
        return redirect("/apology")

    return render_template("master_admin_intructions.html")


@app.route("/master_admin_control_unit/new_users", methods=["POST", "GET"])
@login_required
def master_admin_control_unit_new_users():
    """Handles requests made my the Master Admin to add new users to the system"""
    user_id = session.get("user_id")
    identity = session.get("identity")
    if request.method == "POST":
        # Checks that the user sending the post request is an admin and they were the Master Admin
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")

        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")

        # Checks that the data inputs are not empty strings
        data = request.get_json()
        # Strips the leading and trailing in the string regarding the values of the dictionary "data"
        data = {key: value.strip() for key, value in data.items()}
        # Check the availability of the fields and then check if they were all following the conditions needed.
        variables = [
            "first_name",
            "second_name",
            "date_of_birth",
            "country_of_birth",
            "address",
            "nationality",
            "gender",
            "religion",
            "national_id",
        ]
        all_data_present = all(data[variable] != "" for variable in variables)
        # Checks the validity of the inputs using the arrays at the top of the file.
        valid_options = {
            "country_of_birth": COUNTRIES,
            "nationality": NATIONALITIES,
            "gender": GENDERS,
            "religion": RELIGIONS,
            "user_type": ["faculty_staff", "admins"],
        }
        if all_data_present is True:
            for field, options in valid_options.items():
                if data[field] not in options:
                    return jsonify({"url": "/login"})

            # Makes sure that the "role" key is found when the value of "user_type" in "data" is equal to the string "faculty_staff"
            if data["user_type"] == "faculty_staff" and not data["role"]:
                return jsonify({"url": "/login"})

        # Encrypts Sensitive Data
        encrypted_nationalID = encrypt(data["national_id"])
        encrypted_address = encrypt(data["address"])

        # Handles the cases where the new registrant is a faculty_staff member or an admin
        if data["user_type"] == "faculty_staff":
            db.execute(
                "INSERT INTO faculty_staff (first_name, second_name, role, nationality, gender, religion, date_of_birth, country_of_birth) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                data["first_name"],
                data["second_name"],
                data["role"],
                data["nationality"],
                data["gender"],
                data["religion"],
                data["date_of_birth"],
                data["country_of_birth"],
            )
            rows = db.execute(
                "SELECT user_id FROM faculty_staff WHERE first_name = ? AND second_name = ? AND role = ? AND nationality = ? AND gender = ? AND religion = ? AND date_of_birth = ? AND country_of_birth = ?",
                data["first_name"],
                data["second_name"],
                data["role"],
                data["nationality"],
                data["gender"],
                data["religion"],
                data["date_of_birth"],
                data["country_of_birth"],
            )
            db.execute(
                "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES (?, ?, ?, ?, 'national_id')",
                rows[0]["user_id"],
                encrypted_nationalID["ciphertext"],
                encrypted_nationalID["nonce"],
                encrypted_nationalID["tag"],
            )
            db.execute(
                "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES (?, ?, ?, ?, 'address')",
                rows[0]["user_id"],
                encrypted_address["ciphertext"],
                encrypted_address["nonce"],
                encrypted_address["tag"],
            )
            flash("A new Faculty Staff has been registered.")
        elif data["user_type"] == "admins":
            db.execute(
                "Insert INTO admins (first_name, second_name, nationality, gender, religion, date_of_birth, country_of_birth, role) VALUES (?, ?, ?, ?, ?, ?, ?, 'Developer')",
                data["first_name"],
                data["second_name"],
                data["nationality"],
                data["gender"],
                data["religion"],
                data["date_of_birth"],
                data["country_of_birth"],
            )
            rows = db.execute(
                "SELECT user_id FROM admins WHERE first_name = ? AND second_name = ? AND nationality = ? AND gender = ? AND religion = ? AND date_of_birth = ? AND country_of_birth = ?",
                data["first_name"],
                data["second_name"],
                data["nationality"],
                data["gender"],
                data["religion"],
                data["date_of_birth"],
                data["country_of_birth"],
            )
            db.execute(
                "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES (?, ?, ?, ?, 'national_id')",
                rows[0]["user_id"],
                encrypted_nationalID["ciphertext"],
                encrypted_nationalID["nonce"],
                encrypted_nationalID["tag"],
            )
            db.execute(
                "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES (?, ?, ?, ?, 'address')",
                rows[0]["user_id"],
                encrypted_address["ciphertext"],
                encrypted_address["nonce"],
                encrypted_address["tag"],
            )
            flash("A new Admin has been registered.")

        # Redirect the user to the same page with the "GET" HTTPS method
        return jsonify({"url": "/master_admin_control_unit/new_users"})

    else:
        # If approved_to_master session is not found then the user has to be redirected to the apology page.
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")

        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")

        return render_template(
            "master_admin_new_users.html",
            countries=COUNTRIES,
            nationalities=NATIONALITIES,
            roles=FACULTY_STAFF_ROLES,
        )


@app.route("/master_admin_control_unit/suspensions", methods=["POST", "PATCH", "GET"])
@login_required
def master_admin_control_unit_suspensions():
    """Handles data inserted by the Master Admin to suspend users from the system"""
    # get the necessary characteristics to ensure that the user is the Master Admin
    user_id = session.get("user_id")
    identity = session.get("identity")

    # Assign a dictionary to be used later to get the tables associated with the user_id(s)
    user_tables = {"S": "students", "F": "faculty_staff", "A": "admins"}
    if request.method == "POST":
        # Apply necessary security measures to prevent other unauthorized users from accessing the page through a post request
        if identity != "admins" or not session.get("approved_to_master"):
            return jsonify({"url": "/apology"})

        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        # get data from the client-side using JSON
        data = request.get_json()
        # Checks that the data is valid
        if not data["to_suspend"] or len(data) == 0:
            return jsonify({"url": "/apology"})

        # declares an array of suspended users information to be used later
        suspended = []
        # splits the information data of users into their user_id, first_name and second_na,e
        for each in data["to_suspend"]:
            parts = each.split(" ")

            if parts[0][0] in user_tables:
                table_name = user_tables[parts[0][0]]
                # Checks the presence of the pre-suspended users if not found, then it would return an apology
                row = db.execute(
                    "SELECT user_id, first_name, second_name FROM ? WHERE user_id = ? AND first_name = ? AND second_name = ?",
                    table_name,
                    parts[0],
                    parts[1],
                    parts[2],
                )
                if len(row) != 1:
                    return jsonify({"url": "/apology"})
                # appends the necessary data to the "suspended" list
                dictionary = {
                    "suspended_user_id": parts[0],
                    "first_name": parts[1],
                    "second_name": parts[2],
                }
                suspended.append(dictionary)
            else:
                return jsonify({"url": "/apology"})
        # iterates through the "suspended" lust to update the data "status" of the user and suspend the,
        for suspended_user in suspended:
            db.execute(
                "UPDATE ? SET status = 'suspended' WHERE user_id = ? AND first_name = ? AND second_name = ?",
                table_name,
                suspended_user["suspended_user_id"],
                suspended_user["first_name"],
                suspended_user["second_name"],
            )
        # returns a flash message to ensure that the user was suspended successfully
        flash("Inserted Users have been suspended successfully")
        return jsonify({"url": "/master_admin_control_unit/suspensions"})

    elif request.method == "PATCH":
        # ensure the needed security measures
        if identity != "admins" or not session.get("approved_to_master"):
            return jsonify({"url": "/apology"})

        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        # get data from the client-side using JSON
        data = request.get_json()
        # check that the data is valid
        if not all(data["user_id"] and data["first_name"] and data["second_name"]):
            return jsonify({"url": "/apology"})
        # Checks that the first letter is indeed a type of user
        if data["user_id"][0] in user_tables:
            # Assigns a string called "table_name" according to the first letter of the user_id
            table_name = user_tables[data["user_id"][0]]
            # Checks the presence of the user in their table
            row = db.execute(
                "SELECT user_id FROM ? WHERE user_id = ? AND first_name = ? AND second_name = ?",
                table_name,
                data["user_id"],
                data["first_name"],
                data["second_name"],
            )
            if len(row) != 1:
                return jsonify({"url": "/apology"})
            # unsuspend the user returning a NULL value in their status
            db.execute(
                "UPDATE ? SET status = NULL WHERE user_id = ?",
                table_name,
                row[0]["user_id"],
            )
        else:
            return jsonify({"url": "/apology"})

        return "", 200

    else:
        # ensures security measures
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")

        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        # Gets the data of all unsuspended users
        ALL_USERS = db.execute(
            "SELECT first_name, second_name, user_id FROM admins WHERE user_id != ? AND (status != 'suspended' OR status IS NULL) UNION ALL SELECT first_name, second_name, user_id FROM faculty_staff WHERE status != 'suspended' OR status IS NULL UNION ALL SELECT first_name, second_name, user_id FROM students WHERE status != 'suspended' OR status IS NULL",
            user_id,
        )
        # Gets the data of all suspended users
        SUSPENDED_USERS = db.execute(
            "SELECT first_name, second_name, user_id FROM admins WHERE user_id != ? AND status = 'suspended' UNION ALL SELECT first_name, second_name, user_id FROM faculty_staff WHERE status = 'suspended' UNION ALL SELECT first_name, second_name, user_id FROM students WHERE status = 'suspended'",
            user_id,
        )
        return render_template(
            "master_admin_suspensions.html",
            all_users=ALL_USERS,
            suspended_users=SUSPENDED_USERS,
        )


@app.route("/master_admin_control_unit/courses", methods=["POST", "PATCH", "GET"])
@login_required
def courses():
    """Handles data and requests from Master Admin regarding courses page"""
    # stores the required user data
    user_id = session.get("user_id")
    identity = session.get("identity")
    if request.method == "POST":
        # ensures required security measures.
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")
        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        # gets data from client-side using JSON
        data = request.get_json()
        # ensures that the data is valid
        if (
            not all(
                data["name"]
                and data["faculty_staff"]
                and data["year"]
                and data["semester"]
            )
            or data["year"] not in YEARS_OF_STUDY
            or data["semester"] not in SEMESTERS
            or data["major"] not in MAJORS
            or data["credit_hours"] not in CREDIT_HOURS
        ):
            return jsonify({"url": "/apology"})
        # loads the JSON list value found in the "faculty_staff" key
        faculty_staff_data = loads(data["faculty_staff"].replace("'", '"'))
        # Checks that the faculty_staff data is valid and found.
        rows = db.execute(
            "SELECT * FROM faculty_staff WHERE first_name = ? AND second_name = ? AND user_id = ?",
            faculty_staff_data["first_name"],
            faculty_staff_data["second_name"],
            faculty_staff_data["user_id"],
        )
        if len(rows) != 1:
            return {"url": "/apology"}
        # inserts the course data into the database
        db.execute(
            "INSERT INTO courses (name, faculty_staff_user_id, semester, year, major, credit_hours) VALUES (?, ?, ?, ?, ?, ?)",
            data["name"],
            faculty_staff_data["user_id"],
            data["semester"],
            data["year"],
            data["major"],
            data["credit_hours"],
        )
        # gives a flash memory to assure the course was stored successfully
        flash("The Course has been added!")

        return jsonify({"url": "/master_admin_control_unit/courses"})

    elif request.method == "PATCH":
        # ensures security measures.
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")
        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        # gets data from client-side using JSON
        data = request.get_json()
        if not all(
            data["course_id"]
            and data["course_name"]
            and data["faculty_staff_user_id"]
            and data["course_major"]
            and data["course_semester"]
            and data["course_year"]
        ):
            return jsonify({"url": "/apology"})
        # Checks the data is valid and that the course is actually found in the database
        rows = db.execute(
            "SELECT * FROM courses WHERE id = ? AND name = ? AND faculty_staff_user_id = ? AND major = ? AND semester = ? AND year = ?",
            data["course_id"],
            data["course_name"],
            data["faculty_staff_user_id"],
            data["course_major"],
            data["course_semester"],
            data["course_year"],
        )
        if len(rows) != 1:
            return jsonify({"url": "/apology"})
        # Deletes the course from the database
        db.execute(
            "DELETE FROM courses WHERE id = ? AND name = ? AND faculty_staff_USER_id = ? AND MAJOR = ? AND semester = ? AND year = ?",
            data["course_id"],
            data["course_name"],
            data["faculty_staff_user_id"],
            data["course_major"],
            data["course_semester"],
            data["course_year"],
        )

        return "", 200

    else:
        # ensures security measures
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")
        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        # sends the data of the faculty staff to the user to be chosen
        FACULTY_STAFF = db.execute(
            "SELECT first_name, second_name, user_id FROM faculty_staff"
        )
        # sends the already stored courses in the database to the client-side
        COURSES = db.execute(
            "SELECT courses.id, courses.name, courses.faculty_staff_user_id, courses.major, courses.semester, courses.year, courses.credit_hours, faculty_staff.first_name, faculty_staff.second_name FROM courses JOIN faculty_staff ON courses.faculty_staff_user_id = faculty_staff.user_id"
        )
        return render_template(
            "master_admin_courses.html",
            faculty_staff=FACULTY_STAFF,
            courses=COURSES,
            majors=MAJORS,
        )


@app.route("/master_admin_control_unit/alerts_to_all", methods=["POST", "GET"])
@login_required
def alerts_to_all():
    """Handles data sent by the master Admin in the alerts section"""
    user_id = session.get("user_id")
    identity = session.get("identity")
    if request.method == "POST":
        # ensures security measures
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")
        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        # get data from client-side using JSON
        data = request.get_json()
        # get the user_id(s) of all users
        all_users_id = db.execute(
            "SELECT user_id FROM all_users WHERE user_id != ?", user_id
        )
        # iterate over "all_users" according to their user_id(s) and send the alert to all of them one by one.
        for user in all_users_id:
            db.execute(
                "INSERT INTO alerts (sender_id, recipient_id, subject_title, content, type) VALUES (?, ?, ?, ?, 'active alert')",
                user_id,
                user["user_id"],
                data["subject_title"],
                data["content"],
            )
        # Send a flash alert to assure the user that the alert has been sent
        flash("Alert has been sent!")
        return jsonify({"url": "/master_admin_control_unit/alerts_to_all"})

    else:
        # ensures security measures
        if not session.get("approved_to_master") or identity != "admins":
            return redirect("/apology")
        rows = db.execute(
            "SELECT * FROM admins WHERE user_id = ? AND role = 'Head Developer'",
            user_id,
        )
        if len(rows) != 1:
            return redirect("/apology")
        return render_template("master_admin_alerts.html")


@app.route("/admins")
@login_required
def admins():
    """The main route for admins and there functionalities."""
    if not session.get("user_id") or not session.get("identity"):
        return redirect("/apology")

    user_id = session.get("user_id")
    identity = session.get("identity")
    # Check that the user is actually an admin and not any other user.
    if identity != "admins" or user_id[0] != "A":  # type: ignore
        return redirect("/login")
    # Check that the user has been registered with a password before
    rows = db.execute("SELECT * FROM ? WHERE user_id = ?", identity, user_id)
    if rows[0]["password_hash"] is None:
        return redirect("/login")

    return render_template("admins.html")


@app.route("/admins/register", methods=["POST", "GET"])
@login_required
def admins_register_students():
    """The admins page of registering new students"""

    if request.method == "POST":
        data = request.get_json()
        # Strips the leading and trailing spaces in the string in the values of the dictionary
        # The if condition is used to ignore integers found in the values
        data = {
            key: value.strip() if isinstance(value, str) else value
            for key, value in data.items()
        }
        if session.get("identity") != "admins":
            return jsonify({"url": "/login"})
        # Check that all the variables are present and not empty string. However, we ignore the status variable if it was an empty string.
        variables = [
            "first_name",
            "second_name",
            "date_of_birth",
            "country_of_birth",
            "address",
            "nationality",
            "gender",
            "religion",
            "national_id",
            "year_of_study",
            "semester",
            "major",
        ]
        all_data_present = all(data[variable] != "" for variable in variables)

        # Check that the inputs were in the lists, to ensure that not incorrect variables could be found.
        if all_data_present is True:
            if (
                data["country_of_birth"] not in COUNTRIES
                or data["nationality"] not in NATIONALITIES
                or data["gender"] not in GENDERS
                or data["religion"] not in RELIGIONS
                or data["year_of_study"] not in YEARS_OF_STUDY
                or data["semester"] not in SEMESTERS
                or data["major"] not in MAJORS
            ):
                return jsonify(
                    {
                        "message": "The inputs are not found in our database!",
                        "url": "/login",
                    }
                )

        # First we need to insert the details into the students' table
        db.execute(
            "INSERT INTO students (first_name, second_name, major, year_of_study, semester, nationality, gender, religion, date_of_birth, country_of_birth) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            data["first_name"],
            data["second_name"],
            data["major"],
            int(data["year_of_study"]),
            int(data["semester"]),
            data["nationality"],
            data["gender"],
            data["religion"],
            data["date_of_birth"],
            data["country_of_birth"],
        )

        # Afterwards, we extract the user_id which is updated using a trigger in the SQL Database
        rows = db.execute(
            "SELECT user_id FROM students WHERE first_name = ? AND second_name = ? AND major = ? AND year_of_study = ? AND semester = ? AND nationality = ? AND gender = ? AND religion = ? AND date_of_birth = ? AND country_of_birth = ?",
            data["first_name"],
            data["second_name"],
            data["major"],
            int(data["year_of_study"]),
            int(data["semester"]),
            data["nationality"],
            data["gender"],
            data["religion"],
            data["date_of_birth"],
            data["country_of_birth"],
        )

        # Encrypt the sensitive data, then insert them into the secure table
        encrypted_nationalID = encrypt(data["national_id"])
        encrypted_address = encrypt(data["address"])

        db.execute(
            "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES (?, ?, ?, ?, 'national_id')",
            rows[0]["user_id"],
            encrypted_nationalID["ciphertext"],
            encrypted_nationalID["nonce"],
            encrypted_nationalID["tag"],
        )
        db.execute(
            "INSERT INTO secure (member_id, encrypted_info, nonce, tag, types) VALUES (?, ?, ?, ?, 'address')",
            rows[0]["user_id"],
            encrypted_address["ciphertext"],
            encrypted_address["nonce"],
            encrypted_address["tag"],
        )

        # Send a flash message at the top of the page to assure the admin that their operation has been successful
        flash("The student has been registered successfully!")

        return jsonify({"url": "/admins/register"})

    else:
        # ensures required security measures
        if not session.get("user_id") or not session.get("identity"):
            return redirect("/login")

        user_id = session.get("user_id")
        identity = session.get("identity")
        if user_id[0] != "A" or identity != "admins":  # type: ignore
            return redirect("/login")
        # returns the required template
        return render_template(
            "admins_register.html",
            countries=COUNTRIES,
            nationalities=NATIONALITIES,
            majors=MAJORS,
        )


@app.route("/faculty_staff")
@login_required
def faculty_staff():
    """Handles the redirection of the user into their instructions page."""
    # ensure required security measures
    if not session.get("user_id") or not session.get("identity"):
        return redirect("/apology")
    # acquires the user's info
    user_id = session.get("user_id")
    identity = session.get("identity")

    if identity != "faculty_staff" or user_id[0] != "F":  # type: ignore
        return redirect("/apology")
    # returns the suitable template to the user
    return render_template("faculty_staff.html")


@app.route("/faculty_staff/courses_details")
@login_required
def courses_details():
    # ensure required security measures
    if not session.get("user_id") or not session.get("identity"):
        return redirect("/apology")
    # acquires the user's info
    user_id = session.get("user_id")
    identity = session.get("identity")
    if identity != "faculty_staff" or user_id[0] != "F":  # type: ignore
        return redirect("/apology")

    # returns the required data from both the courses table and enrollments
    COURSES_AND_STUDENTS = db.execute(
        "SELECT courses.id, courses.name, courses.major, courses.year, courses.semester, courses.credit_hours, COUNT(enrollments.id) AS numof_registrants FROM courses LEFT JOIN enrollments ON courses.id = enrollments.course_id WHERE courses.faculty_staff_user_id = ? GROUP BY courses.id",
        user_id,
    )

    # returns the suitable template to the user
    return render_template(
        "faculty_staff_course_details.html", courses_and_students=COURSES_AND_STUDENTS
    )


@app.route("/students")
@login_required
def students_instructions():
    """Handles the redirection of the user into their instructions page."""
    # ensures required security measures.
    if not session.get("user_id") or not session.get("identity"):
        return redirect("/apology")
    # acquires the user's information
    user_id = session.get("user_id")
    identity = session.get("identity")
    if identity != "students" or user_id[0] != "S":  # type: ignore
        return redirect("/apology")
    # returns the suitable template for the user
    return render_template("students.html")


@app.route("/students/course_enrollments", methods=["POST", "PATCH", "GET"])
@login_required
def course_enrollments():
    """Handles the course enrollments section for students"""
    # gets the required data about the current user.
    user_id = session.get("user_id")
    identity = session.get("identity")

    if request.method == "POST":
        # ensure security measures
        if user_id[0] != "S" or identity != "students":  # type: ignore
            return redirect("/apology")
        # get the data from the client-side using JSON
        data = request.get_json()
        # ensures the specific chosen course is found in the database.
        rows = db.execute(
            "SELECT * FROM courses WHERE id = ? AND name = ? AND faculty_staff_user_id = ? AND major = ? AND semester = ? AND year = ? AND credit_hours = ?",
            data["course_id"],
            data["course_name"],
            data["faculty_staff_user_id"],
            data["course_major"],
            data["course_semester"],
            data["course_year"],
            data["course_credit_hours"],
        )
        if len(rows) != 1:
            return jsonify({"url": "/apology"})
        # Inserts the enrollment of the user into the database
        db.execute(
            "INSERT INTO enrollments (course_id, student_user_id) VALUES (?, ?)",
            data["course_id"],
            user_id,
        )
        return "", 200

    elif request.method == "PATCH":
        # ensures needed security measures.
        if user_id[0] != "S" or identity != "students":  # type: ignore
            return redirect("/apology")
        # gets data from client-side using JSON
        data = request.get_json()
        # ensures that the specific course is found.
        rows = db.execute(
            "SELECT * FROM courses WHERE id = ? AND name = ? AND faculty_staff_user_id = ? AND major = ? AND semester = ? AND year = ? AND credit_hours = ?",
            data["course_id"],
            data["course_name"],
            data["faculty_staff_user_id"],
            data["course_major"],
            data["course_semester"],
            data["course_year"],
            data["course_credit_hours"],
        )
        if len(rows) != 1:
            return jsonify({"url": "/apology"})
        # deletes the enrollment of the student from the database
        db.execute(
            "DELETE FROM enrollments WHERE course_id = ? AND student_user_id = ?",
            data["course_id"],
            user_id,
        )
        return "", 200

    else:
        # ensures required security measures.
        if user_id[0] != "S" or identity != "students":  # type: ignore
            return redirect("/apology")
        # extracts the students info from the database to be used in accurately extracting the suitable courses for them.
        student_info = db.execute(
            "SELECT semester, year_of_study AS year, major FROM students WHERE user_id = ?",
            user_id,
        )
        # extracts the compatible courses for the student along with the faculty staff assigned to the course. Also, it checks if the user is already enrolled in the course or not.
        COURSES = db.execute(
            "SELECT courses.id, courses.name, courses.faculty_staff_user_id, courses.major, courses.semester, courses.year, courses.credit_hours, faculty_staff.first_name, faculty_staff.second_name, COALESCE(enrollments.enrolled, 'false') AS enrolled FROM courses JOIN faculty_staff ON faculty_staff.user_id = courses.faculty_staff_user_id LEFT JOIN enrollments ON enrollments.student_user_id = ? WHERE courses.major = ? AND courses.year = ? AND courses.semester = ?",
            user_id,
            student_info[0]["major"],
            student_info[0]["year"],
            student_info[0]["semester"],
        )
        # returns the suitable template to the user (student).
        return render_template("students_course_enrollments.html", courses=COURSES)


@app.route("/students/alerts", methods=["GET"])
@login_required
def students_alerts():
    """Handles only the Get method request for the students alerts section"""
    # ensure security measures
    if not session.get("user_id") or not session.get("identity"):
        return jsonify({"url": "/apology"})

    user_id = session.get("user_id")
    identity = session.get("identity")

    if user_id[0] != "S" or identity != "students":  # type: ignore
        return redirect("/apology")

    # acquire all the data required to enhance the user experience and get some details regarding the name and identity of sender as well as the timestamp of the alert.
    alerts = db.execute(
        "SELECT alerts.*, admins.first_name, admins.second_name FROM alerts JOIN admins ON alerts.sender_id = admins.user_id WHERE substr(alerts.sender_id, 1, 1) = 'A' AND alerts.recipient_id = ? AND alerts.read = 'false' UNION SELECT alerts.*, faculty_staff.first_name, faculty_staff.second_name FROM alerts JOIN faculty_staff ON faculty_staff.user_id=alerts.sender_id WHERE substr(alerts.sender_id, 1, 1) = 'F' AND alerts.recipient_id = ? AND alerts.read = 'false' ORDER BY alerts.timestamp DESC",
        user_id,
        user_id,
    )
    for dict in alerts:
        # ensures that the user_type in the alerts dictionary is correctly implemented
        if dict["sender_id"][0] == "A":
            dict["user_type"] = "admins"
        elif dict["sender_id"][0] == "F":
            dict["user_type"] = "faculty_staff"
    # send the user to their template.
    return render_template("students_alerts.html", alerts=alerts)


@app.route("/admin/password", methods=["POST", "GET"])
@login_required
def admin_password():
    """Handles the password insertion to reach the Master Admin Control Unit"""
    if request.method == "POST":
        # Checks that the inserted password is the same as the one at the beginning of the file (Can be changed if necessary)
        password = request.form.get("password")
        if password != MASTER_ADMIN_CONTROL_UNIT_PASSWORD:
            return redirect("/apology")

        # Creates a session that expires in 15 minutes to allow only the Head Developer (Admin) to reach the Master Unit
        session["approved_to_master"] = True
        return redirect("/master_admin_control_unit")

    else:
        # Checks the identity of the user to be an admin
        identity = session.get("identity")
        if identity != "admins":
            return redirect("/apology")

        # Checks the presence of that admin as for being the Head Developer (Admin)
        user_id = session.get("user_id")
        row = db.execute("SELECT role FROM admins WHERE user_id = ?", user_id)
        if len(row) != 1 or row[0]["role"] != "Head Developer":  # type: ignore
            return redirect("/apology")

        # The user has three attempts. If wrong, or the page is refreshed more than once it would create an apology
        session["number"] = session.get("number", 0) + 1
        if session.get("number") == 3:
            return redirect("/apology")

        return render_template("master_admin_password.html")


@app.route("/check_nationalID", methods=["POST"])
@login_required
def admins_check_nationalID():
    """This route is configured to detect any duplicated National IDs and alert the admins of such a condition"""

    # Considers the presence of the users' sessions
    if not session.get("user_id") or not session.get("identity"):
        return redirect("/login")

    user_id = session.get("user_id")
    identity = session.get("identity")
    if user_id[0] != "A" or identity != "admins":  # type: ignore
        return redirect("/login")

    rows = db.execute("SELECT * FROM ? WHERE user_id = ?", identity, user_id)
    if rows[0]["password_hash"] is None:
        return redirect("/login")

    is_taken = False
    data = request.get_json()
    # Checks the presence of the national ID of a user before being registered on the system.
    rows = db.execute("SELECT * FROM secure WHERE types = 'national_id'")
    for row in rows:
        if data["national_id"] == decrypt(
            row["encrypted_info"], row["nonce"], row["tag"]
        ):
            is_taken = True

    return jsonify({"is_taken": is_taken})


@app.route("/posts")
@login_required
def admins_media_control():
    user_id = session.get("user_id")

    # The argument is used to find all the data related to the post, as well as checking if the like is found regarding the specific user_id found in session (the then current user) and if it was found, the string 'true' is applied else 'false'
    # True and False are handled using jinja in the HTML DJANGO code exactly at "posts.html" to show the (Love icon) red "which means checked" or empty "which means unchecked."
    admins_posts = db.execute(
        "SELECT p.id, p.user_id, p.subject, p.content, p.timestamp, a.first_name, a.second_name, u.user_type, COALESCE(l.found, 'false') AS found FROM post as p JOIN all_users AS u ON p.user_id = u.user_id JOIN admins AS a ON u.user_id = a.user_id LEFT JOIN likes AS l ON l.user_id = u.user_id AND l.post_id = p.id AND l.user_id = ? ORDER BY p.timestamp DESC;",
        user_id,
    )
    faculty_staff_posts = db.execute(
        "SELECT p.id, p.user_id, p.subject, p.content, p.timestamp, a.first_name, a.second_name, u.user_type, COALESCE(l.found, 'false') AS found FROM post as p JOIN all_users AS u ON p.user_id = u.user_id JOIN faculty_staff AS a ON u.user_id = a.user_id LEFT JOIN likes AS l ON l.user_id = u.user_id AND l.post_id = p.id AND l.user_id = ? ORDER BY p.timestamp DESC;",
        user_id,
    )
    students_posts = db.execute(
        "SELECT p.id, p.user_id, p.subject, p.content, p.timestamp, a.first_name, a.second_name, u.user_type, COALESCE(l.found, 'false') AS found FROM post as p JOIN all_users AS u ON p.user_id = u.user_id JOIN students AS a ON u.user_id = a.user_id LEFT JOIN likes AS l ON l.user_id = u.user_id AND l.post_id = p.id AND l.user_id = ? ORDER BY p.timestamp DESC;",
        user_id,
    )
    return render_template(
        "posts.html",
        admins_posts=admins_posts,
        faculty_staff_posts=faculty_staff_posts,
        students_posts=students_posts,
    )


@app.route("/get_replies", methods=["POST"])
@login_required
def get_replies():
    """Sends a list of all replies on a post with a specific idea when needed"""

    rows = db.execute(
        "SELECT r.id, r.sender_id, r.post_id, r.timestamp, u.user_type, r.message FROM replies AS r JOIN all_users AS u ON u.user_id = r.sender_id"
    )

    # This for loop adds the associated first_name and second_name found for the sender of the reply to make it more clear and distinctive and be shown to the current user.
    # Notice that this specific route is called every, approximately, 5 seconds to ensure an updated reply list for all posts
    for row in rows:
        name = db.execute("SELECT first_name, second_name FROM ?", row["user_type"])
        row["first_name"] = name[0]["first_name"]
        row["second_name"] = name[0]["second_name"]

    return jsonify(rows)


@app.route("/create_post", methods=["POST"])
@login_required
def create_post():
    """Handles the creation of a new post by the user."""
    user_id = session.get("user_id")
    data = request.get_json()
    # Inserts the required data regarding the post into the database
    db.execute(
        "INSERT INTO post (user_id, subject, content) VALUES (?, ?, ?)",
        user_id,
        data["subject_title"],
        data["post_content"],
    )
    flash("Your post was saved successfully")
    return jsonify({"url": "/posts"})


@app.route("/remove_post", methods=["POST"])
@login_required
def remove_post():
    """Handles removing a post if and only if the remover is an Admin"""
    user_id = session.get("user_id")
    identity = session.get("identity")
    # Makes sure that the remover is an admin.
    if user_id[0] != "A" or identity != "admins":  # type: ignore
        return jsonify({"url": "/apology"})
    data = request.get_json()
    rows = db.execute(
        "SELECT p.id, a.first_name, a.second_name FROM post AS p JOIN all_users AS u ON p.user_id=u.user_id JOIN ? AS a ON a.user_id=u.user_id WHERE p.id = ? AND p.timestamp = ?",
        data["identity"],
        int(data["post_id"]),
        data["timestamp"],
    )
    if len(rows) != 1:
        return jsonify({"url": "/apology"})

    # Removes the likes associated with the post
    db.execute("DELETE FROM likes WHERE post_id = ?", int(data["post_id"]))
    # Removes the replies associated with the post
    db.execute("DELETE FROM replies WHERE post_id = ?", int(data["post_id"]))
    # Removes the post's content itself
    db.execute("DELETE FROM post WHERE id = ?", int(data["post_id"]))

    # Sends a flash message to ensure the successful deletion
    flash("The Post has been Removed!")
    return jsonify({"url": "/posts"})


@app.route("/add_like", methods=["POST"])
@login_required
def add_like():
    """Adds a like to the posts selected by a user"""

    user_id = session.get("user_id")
    data = request.get_json()
    # Checks the presence of the post itself
    rows = db.execute(
        "SELECT p.id, a.first_name, a.second_name FROM post AS p JOIN all_users AS u ON p.user_id=u.user_id JOIN ? AS a ON a.user_id=u.user_id WHERE p.id = ? AND p.timestamp = ?",
        data["identity"],
        int(data["post_id"]),
        data["timestamp"],
    )
    if len(rows) != 1:
        return apology("An error occurred.", 400)
    # Inserts the like info into the database
    db.execute(
        "INSERT INTO likes (user_id, post_id) VALUES (?, ?)",
        user_id,
        int(data["post_id"]),
    )
    return "", 200


@app.route("/add_reply", methods=["POST"])
@login_required
def add_reply():
    """Handles storing a reply on a post into the database"""
    user_id = session.get("user_id")
    data = request.get_json()
    # Checks the presence of the post itself
    rows = db.execute(
        "SELECT p.id, a.first_name, a.second_name FROM post AS p JOIN all_users AS u ON p.user_id=u.user_id JOIN ? AS a ON a.user_id=u.user_id WHERE p.id = ? AND p.timestamp = ?",
        data["identity"],
        int(data["post_id"]),
        data["timestamp"],
    )
    if len(rows) != 1:
        return apology("An error occurred", 403)
    # Stores the reply in the database
    db.execute(
        "INSERT INTO replies (sender_id, message, post_id) VALUES (?, ?, ?)",
        user_id,
        data["message"],
        int(data["post_id"]),
    )
    return "", 200


@app.route("/remove_like", methods=["POST"])
@login_required
def remove_like():
    """Handles removing a like off a post (Unlike)"""
    user_id = session.get("user_id")
    data = request.get_json()
    # Checks the presence of the post itself
    rows = db.execute(
        "SELECT p.id, p.user_id, a.first_name, a.second_name FROM post AS p JOIN all_users AS u ON p.user_id=u.user_id JOIN ? AS a ON a.user_id=u.user_id WHERE p.id = ? AND p.timestamp = ?",
        data["identity"],
        int(data["post_id"]),
        data["timestamp"],
    )
    if len(rows) != 1:
        return apology("An error occurred.", 400)
    # Deletes that reply
    db.execute(
        "DELETE FROM likes WHERE user_id = ? AND post_id = ?",
        user_id,
        int(data["post_id"]),
    )
    return "", 200


@app.route("/alerts", methods=["POST", "GET"])
@login_required
def admins_alerts():
    """Handles specific users like Admins and Faculty Staff to send alerts to each other and to students"""
    user_id = session.get("user_id")
    identity = session.get("identity")
    if identity == "admins":
        ALL_USERS = db.execute(
            "SELECT first_name, second_name, user_id FROM admins WHERE user_id != ? UNION ALL SELECT first_name, second_name, user_id FROM faculty_staff UNION ALL SELECT first_name, second_name, user_id FROM students",
            user_id,
        )
    elif identity == "faculty_staff":
        ALL_USERS = db.execute(
            "SELECT first_name, second_name, user_id FROM faculty_staff WHERE user_id != ? UNION ALL SELECT first_name, second_name, user_id FROM students",
            user_id,
        )
    elif identity == "students":
        ALL_USERS = None

    if request.method == "POST":
        # Assigns the tables to their specific start of user_ids, where A means an admin and so on.
        user_tables = {"S": "students", "F": "faculty_staff", "A": "admins"}
        # Since the users allowed to send alerts are admins and faculty_staff, then the only users assigned would be faculty_staff and admins. It's understood that an if condition could be implemented instead. However, there for now, I would like to make sure that in the future POST would not handle anything from the students' identity.
        allowed_identities = ["admins", "faculty_staff"]

        data = request.get_json()
        # Checks that the data caught from JSON is not empty.
        if not all([data["recipients"], data["subject_title"], data["content"]]):
            return jsonify({"url": "/apology"})

        # declares an empty list to be used later in the code.
        recipients = []

        # handles the data either in case of single or multiple recipients.
        for each in data["recipients"]:
            # For each element inside the recipients list caught from javascript, we will split the id (for example, "A1 first_name second_name" into ["A1", "first_name", "second_name"])
            parts = each.split(" ")

            # Checks that the first letter in the id is inside the user_tables if not, returns a url handled by JSON on the client toward the apology page
            if parts[0][0] in user_tables:
                table_name = user_tables[parts[0][0]]
                # Here, there are three conditions:
                # First: to admins, where only admins can send to each other
                # Second: to faculty_staff, where admins and faculty_staff can send to other faculty_staff
                # Third: to students where only admins and faculty_staff are the ones who can send alerts to students, and students could not send to each other or other kinds of users
                if (
                    table_name == "admins" and identity != "admins"
                ) or identity not in allowed_identities:
                    return jsonify({"url": "/apology"})

                # Checks that the recipient is found in the data, other ways we move to apology
                row = db.execute(
                    "SELECT user_id, first_name, second_name FROM ? WHERE user_id = ? AND first_name = ? AND second_name = ?",
                    table_name,
                    parts[0],
                    parts[1],
                    parts[2],
                )
                if len(row) != 1:
                    return jsonify({"url": "/apology"})

                # Ensures creating a list of dictionaries of the users (recipients) who would receive the alert and then append it to the list created earlier
                dictionary = {
                    "recipient_id": parts[0],
                    "first_name": parts[1],
                    "second_name": parts[2],
                }
                recipients.append(dictionary)
            else:
                return jsonify({"url": "/apology"})

        # Enters a loop to start inserting the alerts into the database for each individual recipient on their own
        for recipient in recipients:
            db.execute(
                "INSERT INTO alerts (sender_id, recipient_id, subject_title, content, type) VALUES (?, ?, ?, ?, 'active alert')",
                user_id,
                recipient["recipient_id"],
                data["subject_title"],
                data["content"],
            )

        # Creates a flash alert to make the sender know that their data was handled
        flash("Alert was sent Successfully!")
        return jsonify({"url": "/alerts"})

    else:
        alerts = db.execute(
            "SELECT alerts.*, admins.first_name, admins.second_name FROM alerts JOIN admins ON alerts.sender_id = admins.user_id WHERE substr(alerts.sender_id, 1, 1) = 'A' AND alerts.recipient_id = ? AND alerts.read = 'false' UNION SELECT alerts.*, faculty_staff.first_name, faculty_staff.second_name FROM alerts JOIN faculty_staff ON faculty_staff.user_id=alerts.sender_id WHERE substr(alerts.sender_id, 1, 1) = 'F' AND alerts.recipient_id = ? AND alerts.read = 'false' ORDER BY alerts.timestamp DESC",
            user_id,
            user_id,
        )
        for dict in alerts:
            if dict["sender_id"][0] == "A":
                dict["user_type"] = "admins"
            elif dict["sender_id"][0] == "F":
                dict["user_type"] = "faculty_staff"

        return render_template("alerts.html", alerts=alerts, all_users=ALL_USERS)


@app.route("/remove_alert", methods=["POST"])
@login_required
def remove_alert():
    """Handles removing an alert from being seen next time, but not deleted from the database"""
    user_id = session.get("user_id")
    identity = session.get("identity")
    if identity not in ["students", "faculty_staff", "admins"]:
        return jsonify({"url": "/apology"})

    # A map created to specify the users with their corresponding user_id first letter and table name in the database
    # This ensures filtering and sterilizing the data being sent from the user.
    user_type_map = {"admins": ("admins", "A"), "faculty_staff": ("faculty_staff", "F")}

    data = request.get_json()

    # Assigns the values of the table name and the first character of a sender to a values
    table_name, sender_id_char = user_type_map.get(data["user_type"], (None, None))

    # Checks that the variables are not None.
    if table_name is None or sender_id_char is None:
        return jsonify({"url": "/apology"})

    # Checks the presence of the alert itself.
    alerts = db.execute(
        f"SELECT alerts.*, {table_name}.first_name, {table_name}.second_name FROM alerts JOIN {table_name} ON alerts.sender_id={table_name}.user_id WHERE substr(alerts.sender_id, 1, 1) = '{sender_id_char}' AND alerts.recipient_id = ? AND alerts.read = 'false' AND {table_name}.first_name = ? AND {table_name}.second_name = ? AND timestamp = ? AND alerts.id = ?",
        user_id,
        data["first_name"],
        data["second_name"],
        data["timestamp"],
        data["alert_id"],
    )
    if len(alerts) != 1:
        return jsonify({"url": "/apology"})

    # Updates a column value in the database to make the alert assigned to read and not appear to the same receiver once more.
    db.execute("UPDATE alerts SET read = 'true' WHERE id = ?", data["alert_id"])

    return "", 200


@app.route("/numof_alerts", methods=["POST"])
@login_required
def get_numof_alerts():
    """Sends the number of alerts that a specific user has received."""
    user_id = session.get("user_id")
    # Waits for 0.02s just in case another route is updating the data ("/remove_alert") to be more specific
    sleep(0.02)

    # Sends the exact count of alerts received by the current user.
    row = db.execute(
        "SELECT alerts.*, admins.first_name, admins.second_name FROM alerts JOIN admins ON alerts.sender_id = admins.user_id WHERE substr(alerts.sender_id, 1, 1) = 'A' AND alerts.recipient_id = ? AND alerts.read = 'false' UNION SELECT alerts.*, faculty_staff.first_name, faculty_staff.second_name FROM alerts JOIN faculty_staff ON faculty_staff.user_id=alerts.sender_id WHERE substr(alerts.sender_id, 1, 1) = 'F' AND alerts.recipient_id = ? AND alerts.read = 'false' ORDER BY alerts.timestamp DESC",
        user_id,
        user_id,
    )
    numof_alerts = len(row)
    return jsonify({"numof_alerts": numof_alerts})


@app.route("/apology")
def apology_route():
    """Generate an apology page and clears all the sessions that the user have."""

    session.clear()
    return apology("An error occurred", 403)


@app.route("/")
def index():
    """Redirects the user to the login page."""
    # I considered it to be useful to have a clear route for the login page, but this route could be removed if preferred.
    return redirect("/login")
