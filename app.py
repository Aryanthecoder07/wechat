import streamlit as st
import json
from pathlib import Path
from hashlib import sha256
from datetime import datetime

# Function to hash passwords
def hash_password(password):
    return sha256(password.encode()).hexdigest()

# Function to check if user exists
def user_exists(email):
    try:
        with open('users.json', 'r') as file:
            users = json.load(file)
        if email in users:
            return True
        return False
    except json.JSONDecodeError:
        return False

# Function to register new user
def register_user(email, password):
    hashed_password = hash_password(password)
    try:
        with open('users.json', 'r') as file:
            users = json.load(file)
    except json.JSONDecodeError:
        users = {}
    users[email] = {"hashed_password": hashed_password, "messages": []}
    with open('users.json', 'w') as file:
        json.dump(users, file)

# Function to verify login credentials
def verify_login(email, password):
    hashed_password = hash_password(password)
    try:
        with open('users.json', 'r') as file:
            users = json.load(file)
        if email in users and users[email]["hashed_password"] == hashed_password:
            return True
        return False
    except json.JSONDecodeError:
        return False

# Function to send message
def send_message(sender_email, recipient_email, message_content):
    try:
        with open('users.json', 'r') as file:
            users = json.load(file)
    except json.JSONDecodeError:
        users = {}
    if recipient_email in users:
        users[recipient_email]["messages"].append({
            "sender": sender_email,
            "content": message_content,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        with open('users.json', 'w') as file:
            json.dump(users, file)
        return True
    return False

# Streamlit UI
def main():
    st.title("Simple Chat Application")

    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
        st.session_state['email'] = ''

    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        st.subheader("Register")
        email = st.text_input("Email", key="register_email")
        password = st.text_input("Password", type="password", key="register_password")
        if st.button("Register"):
            if user_exists(email):
                st.warning("User already exists. Please login.")
            else:
                register_user(email, password)
                st.success("Registration successful. Please login.")

    elif choice == "Login":
        st.subheader("Login")
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            if verify_login(email, password):
                st.session_state['logged_in'] = True
                st.session_state['email'] = email
                st.success(f"Logged in as {email}")
            else:
                st.warning("Invalid credentials. Please try again.")

    if st.session_state['logged_in']:
        email = st.session_state['email']
        
        # Messaging section
        st.subheader("Send Message")
        recipient_email = st.text_input("Recipient's Email", key="recipient_email")
        message_content = st.text_area("Message Content", key="message_content")
        if st.button("Send"):
            if send_message(email, recipient_email, message_content):
                st.success("Message sent!")
            else:
                st.warning("Recipient not found!")

        # Display received messages
        st.subheader("Inbox")
        with open('users.json', 'r') as file:
            users = json.load(file)
            if email in users:
                messages = users[email]["messages"]
                for message in messages:
                    st.info(f"From: {message['sender']} | Sent at: {message['timestamp']}")
                    st.text_area("Message:", message["content"], height=80, key=message["timestamp"])
                    st.text("--------------------")

if __name__ == "__main__":
    # Initialize the users.json file if it doesn't exist or is empty
    users_file = Path('users.json')
    if not users_file.is_file() or users_file.read_text().strip() == '':
        users_file.write_text('{}')
    main()
