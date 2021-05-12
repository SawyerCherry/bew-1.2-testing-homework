import os
from unittest import TestCase

from datetime import date
 
from books_app import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.main.tests

"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
 
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()

    def test_signup(self):
        """test signup"""
        sample_data = {
            "username": "sawyer_19",
            "password": "bigChungus",
        }
        self.app.post("/signup", data=sample_data)

        sample_user = User.query.filter_by(username="sawyer_19").one()
        self.assertIsNotNone(sample_user)
        self.assertEqual(sample_user.username, "sawyer_19")

    def test_signup_existing_user(self):
        """Make sure you can't sign up existing user me1"""
        # TODO: Write a test for the signup route. It should:
        # - Create a user
        create_user()

        sample_data = {
            "username": "me1",
            "password": "password",
        }
        # - Make a POST request to /signup, sending the same username & password
        response = self.app.post("/signup", data=sample_data)
        # - Check that the form is displayed again with an error message
        response_msg = response.get_data(as_text=True)
        self.assertIn("Sign Up", response_msg)
        self.assertIn(
            "That username is taken. Please choose a different one.",
            response_msg,
        )
        

    def test_login_correct_password(self):
        """test correct password"""
        # TODO: Write a test for the login route. It should:
        # - Create a user
        sample_data = {
            "username": "me1",
            "password": "password",
        }

        self.app.post("/signup", data=sample_data)
        # - Make a POST request to /login, sending the created username & password
        
        response = self.app.post("/login", data=sample_data)
        # - Check that the "login" button is not displayed on the homepage
        response_msg = response.get_data(as_text=True)
        self.assertIn("Redirecting...", response_msg)
        self.assertNotIn("Log In", response_msg)
        

    def test_login_nonexistent_user(self):
        """test a nonexistent user, make sure it fails"""
       
        sample_data = {
            "username": "me1",
            "password": "password",
        }
        response = self.app.post("/login", data=sample_data)

        response_msg = response.get_data(as_text=True)
        self.assertIn("Log In", response_msg)
        self.assertIn(
            "No user with that username. Please try again.", response_msg
        )
        self.assertNotIn("Log Out", response_msg)

    def test_login_incorrect_password(self):
        # TODO: Write a test for the login route. It should:
        # - Create a user
        create_user()
        sample_data = {
            "username": "me1",
            "password": "helloWorld",
        }
    
        # - Make a POST request to /login, sending the created username &
        #   an incorrect password
        response = self.app.post("/login", data=sample_data)
        # - Check that the login form is displayed again, with an appropriate
        response_msg = response.get_data(as_text=True)
        self.assertIn("Log In", response_msg)
        #   error message
        self.assertIn(
            "Password doesnt match. Please try again.", response_msg
        )
        self.assertNotIn("Log Out", response_msg)
        

    def test_logout(self):
        """test logout"""
        # TODO: Write a test for the logout route. It should:
        # - Create a user
        create_user()
        sample_data = {
            "username":"me1",
            "password":"password"
        }
        # - Log the user in (make a POST request to /login)
        self.app.post("/login", data=sample_data)
        # - Make a GET request to /logout
        response = self.app.get("/logout", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        response_msg = response.get_data(as_text=True)
        # - Check that the "login" button appears on the homepage
        self.assertIn("Log In", response_msg)
        self.assertNotIn("Log Out", response_msg)
