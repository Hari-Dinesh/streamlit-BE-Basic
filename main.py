import streamlit as st
from pymongo import MongoClient
import bcrypt

# MongoDB Connection
MONGO_URI = "mongodb+srv://sriharidinesh77:Asdfg123&()@cluster0.lqftn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

def connect_to_db():
    try:
        client = MongoClient(MONGO_URI)
        db = client["streamlit_app"]
        return db
    except Exception as e:
        st.error(f"Database connection error: {e}")
        return None

# Database Operations
def get_user(username):
    db = connect_to_db()
    if db is None:
        return None
    users = db["users"]
    return users.find_one({"username": username})

def create_user(username, hashed_password):
    db = connect_to_db()
    if db is None:
        return False

    users = db["users"]
    # Check if the user already exists
    if users.find_one({"username": username}):
        return False

    try:
        users.insert_one({"username": username, "password": hashed_password})
        return True
    except Exception as e:
        st.error(f"Error creating user: {e}")
        return False

# Utility Functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# App State
if "page" not in st.session_state:
    st.session_state["page"] = "login"

# Login Page
def login_page():
    st.title("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = get_user(username)
        if user and verify_password(password, user["password"]):
            st.success("Login successful!")
            st.session_state["authenticated"] = True
            st.session_state["page"] = "welcome"
            st.session_state["username"] = username
            st.rerun()
        else:
            st.error("Invalid username or password!")

    if st.button("Create User"):
        st.session_state["page"] = "create_user"
        st.rerun()

# Create User Page
def create_user_page():
    st.title("Create User")

    username = st.text_input("Enter a username")
    password = st.text_input("Enter a password", type="password")
    confirm_password = st.text_input("Confirm your password", type="password")

    if st.button("Register"):
        if password != confirm_password:
            st.error("Passwords do not match!")
        elif create_user(username, hash_password(password)):
            st.success("User created successfully! Please log in.")
            st.session_state["page"] = "login"
            st.rerun()
        else:
            st.error("Username already exists or could not create user.")

    if st.button("Back to Login"):
        st.session_state["page"] = "login"
        st.rerun()

# Welcome Page
def welcome_page():
    st.balloons()
    st.title(f"Welcome '{st.session_state.get("username",None)}'")
    st.write("Welcome to the application!")

    if st.button("Logout"):
        st.session_state["authenticated"] = False
        st.session_state["page"] = "login"
        st.rerun()

# Page Navigation
if st.session_state["page"] == "login":
    login_page()
elif st.session_state["page"] == "create_user":
    create_user_page()
elif st.session_state["page"] == "welcome":
    if "authenticated" in st.session_state and st.session_state["authenticated"]:
        welcome_page()
    else:
        st.warning("Please log in first.")
        st.session_state["page"] = "login"
        st.rerun()



        #commit line 1

        ##testing commmit 2


        ##commit 3