# Name: Delsius Yib, Admin No: 221025N, Module Group: IT2852
# If this is for an actual book management system,
# There will not be any unhashed passwords shown in the database,
# I hashed only for security purposes
# username and passwords in initialize_user_shelves function (start from Line 387 for authorized users, Line 434 for general users)

import logging
import shelve
import os
import bcrypt
from tabulate import tabulate
import copy
import random
import re
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                           filename='book_management.log')

# format for the tabulate
custom_tablefmt = {
    'tablefmt': 'grid',  # Personally feel that 'grid' is the best way to display data
    'numalign': 'right',  # Align numbers to the right
    'stralign': 'left',   # Align strings to the left
    'floatfmt': '.2f',    # Default float formatting
    'showindex': False    # Do not show the row index
}

def add_vertical_lines(tabulated_str):
    try:
        lines = tabulated_str.split('\n')
        result = []
        for line in lines:
            result.append(line)
            if line and line[0] == '|':  # Check if the line is a table row
                result.append('| ' + ' | '.join(['-' * len(column.strip()) for column in line.split('|')[1:-1]]) + ' |')
        return '\n'.join(result)
    except Exception as e:
        logging.error(f"Error in add_vertical_lines: {e}")
        return tabulated_str

class Book:
    def __init__(self, title, isbn_num, publisher, author, language, genre, year_published, number_of_copies, availability, addedbywho):
        self.title = title
        self.isbn_num = isbn_num
        self.publisher = publisher
        self.author = author
        self.language = language
        self.genre = genre
        self.year_published = int(year_published)
        self.number_of_copies = int(number_of_copies)
        self.availability = bool(availability)
        self.addedbywho = addedbywho

    def __str__(self):
        return (f"Title: {self.title}, ISBN: {self.isbn_num}, Publisher: {self.publisher}, "
                f"Author: {self.author}, Language: {self.language}, Genre: {self.genre}, Year: {self.year_published}, "
                f"Copies: {self.number_of_copies}, Available: {self.availability}, Added by: {self.addedbywho}")

class User:
    def __init__(self, customerid, username, password, name, email, tier='Standard', points=0):
        self.customerid = customerid
        self.username = username
        self.password = password
        self.name = name
        self.email = email
        self.tier = tier
        self.points = points
        self.borrowed_books_stack = Stack()

    def __str__(self):
        return f"Customer ID: {self.customerid}, Username: {self.username}, Name: {self.name}, Email: {self.email}, Tier: {self.tier}, Points: {self.points}"

    def get_user_info(self):
        return {
            'customerid': self.customerid,
            'username': self.username,
            'password': self.password,
            'name': self.name,
            'email': self.email,
            'tier': self.tier,
            'points': self.points,
            'borrowed_books_stack': self.borrowed_books_stack
        }

class Borrow(Book):
    def __init__(self, title, isbn_num, publisher, author, language, genre, year_published, number_of_copies_borrowed, availability, addedbywho, username):
        super().__init__(title, isbn_num, publisher, author, language, genre, year_published, number_of_copies_borrowed, availability, addedbywho)
        self.username = username
        self.number_of_copies_borrowed = int(number_of_copies_borrowed)

    def __str__(self):
        return (f"Title: {self.title}, ISBN: {self.isbn_num}, Publisher: {self.publisher}, "
                f"Author: {self.author}, Language: {self.language}, Genre: {self.genre}, Year: {self.year_published}, "
                f"Copies Borrowed: {self.number_of_copies_borrowed}, Borrowed by: {self.username}")

class CustomerRequest:
    def __init__(self, customer_id, request):
        self.customer_id = customer_id
        self.request = request

    def __str__(self):
        return f"Customer ID: {self.customer_id}, Request: {self.request}"

class Reservation:
    def __init__(self, isbn_num, username, reserved_on):
        self.isbn_num = isbn_num
        self.username = username
        self.reserved_on = reserved_on

    def __str__(self):
        return f"ISBN: {self.isbn_num}, Reserved by: {self.username}, Reserved on: {self.reserved_on}"

class BorrowedBook(Borrow):
    def __init__(self, title, isbn_num, publisher, author, language, genre, year_published, number_of_copies_borrowed, availability, addedbywho, username, borrowed_on):
        super().__init__(title, isbn_num, publisher, author, language, genre, year_published, number_of_copies_borrowed, availability, addedbywho, username)
        self.borrowed_on = borrowed_on

class Review:
    def __init__(self, username, rating, review_text):
        self.username = username
        self.rating = rating
        self.review_text = review_text

    def __str__(self):
        return f"{self.username} rated {self.rating}/5: {self.review_text}"

class Stack:
    def __init__(self):
        self.items = []

    def is_empty(self):
        return len(self.items) == 0

    def push(self, item):
        self.items.append(item)

    def pop(self):
        if not self.is_empty():
            return self.items.pop()
        else:
            raise IndexError("pop from empty stack")

    def peek(self):
        if not self.is_empty():
            return self.items[-1]
        else:
            return None

    def size(self):
        return len(self.items)

    def __str__(self):
        return str(self.items)

class TreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []

class CategoryTree:
    def __init__(self):
        self.root = TreeNode("Categories")

    def add_category_recursive(self, node, category_path_list):
        if not category_path_list:
            return
        category = category_path_list[0]
        found = False
        for child in node.children:
            if child.value == category:
                found = True
                self.add_category_recursive(child, category_path_list[1:])
                break
        if not found:
            new_node = TreeNode(category)
            node.children.append(new_node)
            self.add_category_recursive(new_node, category_path_list[1:])

    def add_category(self, category_path):
        category_path_list = category_path.split('/')
        self.add_category_recursive(self.root, category_path_list)

    def display_tree_recursive(self, node, level):
        print(' ' * level * 2 + node.value)
        for child in node.children:
            self.display_tree_recursive(child, level + 1)

    def display_tree(self, node=None, level=0):
        if node is None:
            node = self.root
        self.display_tree_recursive(node, level)

def build_dynamic_category_tree(books):
    category_tree = CategoryTree()
    for book in books:
        genre_path = f"Genres/{book.genre}"
        category_tree.add_category(genre_path)
    return category_tree

def calculate_tier(points):
    """Calculate the user's tier based on their points."""
    if points >= 5000:
        return 'Gold'
    elif points >= 2000:
        return 'Silver'
    elif points >= 1000:
        return 'Bronze'
    else:
        return 'Standard'

def update_user_tier(user_info):
    points = user_info['points']
    if points >= 5000:
        user_info['tier'] = 'Gold'
    elif points >= 2000:
        user_info['tier'] = 'Silver'
    elif points >= 1000:
        user_info['tier'] = 'Bronze'
    else:
        user_info['tier'] = 'Standard'

def award_points(user, action):
    """Award points to a user based on their action and update their tier."""
    points_awarded = 0
    if action == "borrow_book":
        points_awarded = 20  # 20 points for borrowing a book
    elif action == "return_book_on_time":
        points_awarded = 30  # 30 points for timely return
    elif action == "account_creation":
        points_awarded = 50  # 50 points for new account creation
    elif action == "add_book":
        points_awarded = 40  # 40 points for adding a new book
    elif action == "late_return":
        deduct_points(user, action)  # -10 points for late return (deduction)
    user['points'] += points_awarded
    user['tier'] = calculate_tier(user['points'])

    # Save the updated user data after awarding points
    is_authorized = user['userid'].startswith('A')
    if is_authorized:
        save_authorized_users(authorized_user)
    else:
        save_general_users(general_user)

    return points_awarded

def deduct_points(user, action):
    """Deduct points from a user based on their action and update their tier."""
    points_deducted = 0
    if action == "late_return":
        points_deducted = -10  # Deduct 10 points for a late return

    user['points'] += points_deducted
    user['tier'] = calculate_tier(user['points'])

    # Save the updated user data after deducting points
    is_authorized = user['userid'].startswith('A')
    if is_authorized:
        save_authorized_users(authorized_user)
    else:
        save_general_users(general_user)

    return points_deducted

def hash_password(password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    logging.info(f"Password hashed: {hashed[:10]}***")
    return hashed

def verify_password(stored_password, entered_password):
    try:
        result = bcrypt.checkpw(entered_password.encode('utf-8'), stored_password.encode('utf-8'))
        logging.info(f"Password verification: {'successful' if result else 'failed'}")
        return result
    except ValueError as e:
        logging.error(f"Error verifying password: {e}")
        return False

#this function below is here in cases where an username is present in both authorized and non authorized
#if this happens, deduplicate by removing the user from the authorized_users
def deduplicate_users():
    try:
        with shelve.open('authorized_users') as auth_users, shelve.open('general_users') as non_auth_users:
            authorized_users = auth_users.get('users', {})
            general_users = non_auth_users.get('users', {})
            duplicated_users = authorized_users.keys() & general_users.keys()

            for user in duplicated_users:
                del authorized_users[user]
                logging.info(f"Duplicated user {user} removed from authorized_users.")

            if duplicated_users:
                auth_users['users'] = authorized_users  # Save changes if any duplication was resolved
    except IOError:
        print("File does not exist or is missing.")
    except EOFError:
        print("End of file reached.")
    except:
        print("Something went wrong. Please try again later or rerun the program.")

#Cher, username and password i have set for authorized and general users.
# You can play around with adding/removing the initialized users below
#If you want to try adding/removing the users below, please remember to
# delete the .bak .dat .dir files first if not it will not exist even if you rerun
#E.g. u create new authorized user, delete authorized_users.bak, authorized_users.dat and authorized_users.dir then rerun
def generate_userid(role):
    base = {'authorized': 'A', 'general': 'G'}
    role_char = base.get(role, 'R')
    suffix = str(random.randint(0, 999)).zfill(3)
    return f"{role_char}{suffix}"

def is_password_complex(password):
    """Check password complexity requirements: length, uppercase, lowercase, digit, special character."""
    complexity_rules = [
        (r".{8,}", "Password must be at least 8 characters long."),
        (r"[A-Z]", "Password must contain at least one uppercase letter."),
        (r"[a-z]", "Password must contain at least one lowercase letter."),
        (r"[0-9]", "Password must contain at least one digit."),
        (r"[!@#$%^&*(),.?\":{}|<>]", "Password must contain at least one special character.")
    ]
    for pattern, message in complexity_rules:
        if not re.search(pattern, password):
            return False, message
    return True, ""

def validate_username(username):
    """Validate the username based on specified rules."""
    validation_rules = [
        (r"^.{4,}$", "Username must be at least 4 characters long."),     # reason why i put 4 is because got one general user called test
        (r"^.{1,20}$", "Username cannot be more than 20 characters long."),
        (r"^[a-zA-Z0-9_.-]+$", "Username can only contain letters, numbers, dots, hyphens, and underscores."),
        (r"^(?!.*[_.]{2}).*$", "Username cannot contain consecutive special characters like '__' or '..'.")
    ]
    for pattern, message in validation_rules:
        if not re.search(pattern, username):
            return False, message
    return True, ""

def is_email_valid(email):
    email_rules = [
        (r"[^@]+@[^@]+\.[^@]+", "Invalid email format. Please enter a valid email.")
    ]
    for pattern, message in email_rules:
        if not re.search(pattern, email):
            return False, message
    return True, ""

def is_name_valid(name):
    """Check name validation requirements: only letters, hyphens, spaces, and minimum length."""
    validation_rules = [
        (r"^[a-zA-Z-' ]+$", "Name can only contain letters, hyphens, and spaces."),
        (r".{2,}", "Name must be at least 2 characters long.")
    ]

    for pattern, message in validation_rules:
        if not re.search(pattern, name):
            return False, message
    return True, ""

def is_request_valid(request_details):
    """Check request validation requirements: length, prohibited content."""
    validation_rules = [
        (r".{10,}", "Request must be at least 10 characters long."),
    ]

    # Check length validation
    for pattern, message in validation_rules:
        if not re.search(pattern, request_details):
            return False, message

    # Check prohibited content
    offensive_words = ["arse", "arsehead", "arsehole", "ass", "ass hole", "asshole", "bastard", "bitch", "bloody", "bollocks",
        "brotherfucker", "bugger", "bullshit", "cb", "cheebye", "child-fucker", "Christ on a bike", "Christ on a cracker", "cock",
        "cocksucker", "crap", "cunt", "dammit", "damn", "damned", "damn it", "dick", "dick-head", "dickhead", "dumb ass",
        "dumb-ass", "dumbass", "dyke", "father-fucker", "fatherfucker", "frigger", "fuck", "fucker", "fucking", "god dammit",
        "god damn", "goddammit", "God damn", "goddamn", "Goddamn", "goddamned", "goddamnit", "godsdamn", "hell", "holy shit", "honggan", "hong gan"
        "horseshit", "in shit", "jack-ass", "jackarse", "jackass", "Jesus Christ", "Jesus fuck", "Jesus H. Christ", "Jesus Harold Christ",
        "Jesus, Mary and Joseph", "Jesus wept", "kanina", "ka ni na", "kike", "knn", "mother fucker", "mother-fucker", "motherfucker", "negro", "nigga", "nigra",
        "pigfucker", "piss", "prick", "pussy", "shit", "shit ass", "shite", "sibling fucker", "sisterfuck", "sisterfucker",
        "slut", "son of a bitch", "son of a whore", "spastic", "sweet Jesus", "twat", "wanker", "What the Fuck", "What the Hell", "wtf", "wth"]
    for word in offensive_words:
        if re.search(rf"\b{word}\b", request_details.lower()):
            return False, "Request contains prohibited content."

    return True, ""

# Load unhashed passwords from persistent storage
def load_unhashed_passwords():
    try:
        with shelve.open('unhashed_passwords') as unhashed_shelf:
            return unhashed_shelf.get('unhashed_passwords', {})
    except Exception as e:
        logging.error(f"Error loading unhashed passwords: {e}")
        return {}
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return {}

def save_unhashed_passwords(unhashed_passwords):
    try:
        with shelve.open('unhashed_passwords') as unhashed_shelf:
            unhashed_shelf['unhashed_passwords'] = unhashed_passwords
    except Exception as e:
        logging.error(f"Error saving unhashed passwords: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

# Update and save the unhashed passwords after every change
def update_and_save_unhashed_password(username, password):
    simulated_unhashed_passwords[username] = password
    save_unhashed_passwords(simulated_unhashed_passwords)

# Initialize unhashed passwords (global scope)
simulated_unhashed_passwords = load_unhashed_passwords()

# Function to initialize user shelves
def initialize_user_shelves():
    """Initialize the authorized and non-authorized user shelves with proper handling of unhashed passwords."""
    def is_hashed_password(password):
        return password.startswith('$2b$')  # bcrypt hash identifier
    # Load existing unhashed passwords
    unhashed_passwords = load_unhashed_passwords()
    # User details for initialization
    user_details = {
        'admin': {'name': 'Delsius Admin', 'email': 'delsiusyib@gmail.com'},
        'alanchow': {'name': 'Alan Chow', 'email': 'alan_chow@nyp.edu.sg'},
        'bobbyliu': {'name': 'Bobby Liu', 'email': 'bobby_liu@nyp.edu.sg'},
        'test': {'name': 'Delsius General', 'email': 'delsiusyib@gmail.com'},
        'felixyeo': {'name': 'Felix Yeo', 'email': 'felix_yeo@nyp.edu.sg'},
        'farisfoo': {'name': 'Faris Foo', 'email': 'farisfoo@myaccount.nyp.edu.sg'}
    }
    # Initialize authorized users
    try:
        with shelve.open('authorized_users') as auth_users:
            if 'users' not in auth_users:
                initial_users = {
                    'admin': 'Admin123.',
                    'alanchow': 'Alanchow123.',
                    'bobbyliu': 'Bobbyliu123.'
                }
                # Update unhashed passwords with initial users
                unhashed_passwords.update(initial_users)
                auth_users['users'] = {
                    'admin': {
                        'userid': "A000",
                        'password': hash_password('Admin123.'),   #admin's password
                        'name': user_details['admin']['name'],
                        'email': user_details['admin']['email'],
                        'tier': 'Gold',
                        'points': 5000
                    },
                    'alanchow': {
                        'userid': generate_userid('authorized'),
                        'password': hash_password('Alanchow123.'), #alanchow's password
                        'name': user_details['alanchow']['name'],
                        'email': user_details['alanchow']['email'],
                        'tier': 'Bronze',
                        'points': 1500
                    },
                    'bobbyliu': {
                        'userid': generate_userid('authorized'),
                        'password': hash_password('Bobbyliu123.'), #bobbyliu's password
                        'name': user_details['bobbyliu']['name'],
                        'email': user_details['bobbyliu']['email'],
                        'tier': 'Standard',
                        'points': 300
                    }
                }
            else:
                updated_users = {}
                for username, user_data in auth_users['users'].items():
                    # Ensure unhashed passwords are set
                    unhashed_passwords[username] = unhashed_passwords.get(username, 'Unknown')
                    password = user_data['password']
                    if not is_hashed_password(password):
                        # Hash the unhashed password and update it
                        unhashed_passwords[username] = password
                        user_data['password'] = hash_password(password)
                    updated_users[username] = user_data
                auth_users['users'] = updated_users  # Save updated user data
    except IOError:
        print("File does not exist or is missing.")
    except EOFError:
        print("End of file reached.")
    except:
        print("Something went wrong. Please try again later or rerun the program.")

    # Initialize non-authorized users
    try:
        with shelve.open('general_users') as non_auth_users:
            if 'users' not in non_auth_users:
                initial_users = {
                    'test': 'Test123.',
                    'felixyeo': 'Felixyeo123.',
                    'farisfoo': 'Farisfoo123.'
                }
                # Update unhashed passwords with initial users
                unhashed_passwords.update(initial_users)
                non_auth_users['users'] = {
                    'test': {
                        'userid': generate_userid('general'),
                        'password': hash_password('Test123.'),   #test's password
                        'name': user_details['test']['name'],
                        'email': user_details['test']['email'],
                        'tier': 'Silver',
                        'points': 3000
                    },
                    'felixyeo': {
                        'userid': generate_userid('general'),
                        'password': hash_password('Felixyeo123.'), #felixyeo's password
                        'name': user_details['felixyeo']['name'],
                        'email': user_details['felixyeo']['email'],
                        'tier': 'Standard',
                        'points': 50
                    },
                    'farisfoo': {
                        'userid': generate_userid('general'),
                        'password': hash_password('Farisfoo123.'), #farisfoo's password
                        'name': user_details['farisfoo']['name'],
                        'email': user_details['farisfoo']['email'],
                        'tier': 'Bronze',
                        'points': 1000
                    }
                }
            else:
                updated_users = {}
                for username, user_data in non_auth_users['users'].items():
                    # Ensure unhashed passwords are set
                    unhashed_passwords[username] = unhashed_passwords.get(username, 'Unknown')
                    password = user_data['password']
                    if not is_hashed_password(password):
                        # Hash the unhashed password and update it
                        unhashed_passwords[username] = password
                        user_data['password'] = hash_password(password)
                    updated_users[username] = user_data
                non_auth_users['users'] = updated_users  # Save updated user data
    except IOError:
        print("File does not exist or is missing.")
    except EOFError:
        print("End of file reached.")
    except:
        print("Something went wrong. Please try again later or rerun the program.")
    # Save the updated unhashed passwords back to storage
    save_unhashed_passwords(unhashed_passwords)
    # Deduplicate users if any overlap between authorized and non-authorized users
    deduplicate_users()

def load_user(username,db_path='users.db'):
    try:
        with shelve.open(db_path) as db:
            user_info = None
            if username in authorized_user:
                user_info = authorized_user[username]
            elif username in general_user:
                user_info = general_user[username]

            if user_info and 'borrowed_books_stack' not in user_info:
                user_info['borrowed_books_stack'] = Stack()

            return user_info
    except Exception as e:
        logging.error(f"Error in load_user: {e}")
        return None

def safe_load_shelve(filename, key, default_value):
    """Safely load data from shelve, returning a default value if the key is missing."""
    try:
        with shelve.open(filename) as db:
            return db.get(key, default_value)
    except IOError:
        print("File does not exist.")
    except EOFError:
        print("End of file reached.")
    except:
        print("Something went wrong. Please try again later or rerun the program.")

def get_authorized_users():
    return safe_load_shelve('authorized_users', 'users', {})

def get_general_users():
    return safe_load_shelve('general_users', 'users', {})

def save_authorized_users(users):
    try:
        with shelve.open('authorized_users') as auth_users:
            auth_users['users'] = users
    except Exception as e:
        logging.error(f"Error saving authorized users: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

def save_general_users(users):
    try:
        with shelve.open('general_users') as non_auth_users:
            non_auth_users['users'] = users
    except Exception as e:
        logging.error(f"Error saving non-authorized users: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

# Initialize user databases
initialize_user_shelves()
authorized_user = get_authorized_users()
general_user = get_general_users()

def load_books():
    try:
        with shelve.open('book_shelf') as book_shelf:
            return book_shelf.get('books', [])
    except Exception as e:
        logging.error(f"Error loading books: {e}")
        return []
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return []

def save_books(books):
    try:
        with shelve.open('book_shelf') as book_shelf:
            book_shelf['books'] = books
    except Exception as e:
        logging.error(f"Error saving books: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

def load_borrowed_books():
    try:
        with shelve.open('borrowed_books') as borrowed_shelf:
            borrowed_books_data = borrowed_shelf.get('borrowed_books', [])
            borrowed_books = []
            for book_data in borrowed_books_data:
                borrowed_book = BorrowedBook(
                    book_data['title'],
                    book_data['isbn_num'],
                    book_data['publisher'],
                    book_data['author'],
                    book_data['language'],
                    book_data['genre'],
                    book_data['year_published'],
                    book_data['number_of_copies_borrowed'],
                    book_data['availability'],
                    book_data['addedbywho'],
                    book_data['username'],
                    book_data['borrowed_on']
                )
                borrowed_books.append(borrowed_book)
            return borrowed_books
    except (EOFError, KeyError) as e:
        logging.error(f"Error loading borrowed books: {e}")
        # Handle corruption by deleting the shelve files
        for ext in ['.bak', '.dat', '.dir']:
            try:
                os.remove(f'borrowed_books{ext}')
            except FileNotFoundError:
                pass
        return []
    except IOError:
        print("File does not exist.")
        return []
    except Exception as e:
        logging.error(f"Error while loading borrowed books: {e}")
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return []

def save_borrowed_books(borrowed_books):
    try:
        with shelve.open('borrowed_books') as borrowed_shelf:
            borrowed_books_data = []
            for book in borrowed_books:
                book_data = {
                    'title': book.title,
                    'isbn_num': book.isbn_num,
                    'publisher': book.publisher,
                    'author': book.author,
                    'language': book.language,
                    'genre': book.genre,
                    'year_published': book.year_published,
                    'number_of_copies_borrowed': book.number_of_copies_borrowed,
                    'availability': book.availability,
                    'addedbywho': book.addedbywho,
                    'username': book.username,
                    'borrowed_on': book.borrowed_on
                }
                borrowed_books_data.append(book_data)
            borrowed_shelf['borrowed_books'] = borrowed_books_data
    except Exception as e:
        logging.error(f"Error saving borrowed books: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

def load_borrowing_history():
    """Load the borrowing history from a shelve file."""
    try:
        with shelve.open('borrow_history') as borrow_shelf:
            return borrow_shelf.get('user_borrow_history', {})
    except Exception as e:
        logging.error(f"Error loading borrowing history: {e}")
        return {}
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return {}

def save_borrowing_history(borrow_history):
    """Save the borrowing history to a shelve file."""
    try:
        with shelve.open('borrow_history') as borrow_shelf:
            borrow_shelf['user_borrow_history'] = borrow_history
    except Exception as e:
        logging.error(f"Error saving borrowing history: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

def load_reviews():
    try:
        with shelve.open('reviews') as reviews_shelf:
            return reviews_shelf.get('book_reviews', {})
    except Exception as e:
        logging.error(f"Error loading reviews: {e}")
        return {}
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return {}

def save_reviews(reviews):
    try:
        with shelve.open('reviews') as reviews_shelf:
            reviews_shelf['book_reviews'] = reviews
    except Exception as e:
        logging.error(f"Error saving reviews: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

def update_review(user_id, book_isbn, review_text):
    try:
        with shelve.open('reviews') as reviews_shelf:
            reviews = reviews_shelf.get('book_reviews', {})

            # Add or update the review for the specific user and book
            if user_id not in reviews:
                reviews[user_id] = {}
            reviews[user_id][book_isbn] = review_text

            # Save the updated dictionary using the existing save_reviews function
            save_reviews(reviews)
    except Exception as e:
        logging.error(f"Error updating review: {e}")


def save_notifications(notifications):
    try:
        with shelve.open('notifications') as notifications_shelf:
            notifications_shelf['notifications'] = notifications
    except Exception as e:
        logging.error(f"Error saving notifications: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

def load_notifications():
    try:
        with shelve.open('notifications') as notifications_shelf:
            return notifications_shelf.get('notifications', {})
    except Exception as e:
        logging.error(f"Error loading notifications: {e}")
        return {}
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return {}

def save_customer_requests(requests):
    try:
        with shelve.open('customer_requests') as requests_shelf:
            requests_shelf['requests'] = requests
    except Exception as e:
        logging.error(f"Error saving customer requests: {e}")
        return False
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return False
    return True

def load_customer_requests():
    try:
        with shelve.open('customer_requests') as requests_shelf:
            return requests_shelf.get('requests', [])
    except Exception as e:
        logging.error(f"Error loading customer requests: {e}")
        return []
    except:
        print("Something went wrong. Please try again later or rerun the program.")
        return []

customer_requests_queue = []  # This stores the customer requests in a list simulating a queue

# Initialize books from storage
books = load_books()
borrowed_books = load_borrowed_books()  # load borrowed books from the persistent storage

reservations = []

def reserve_book(current_user):
    search_term = input("Enter the ISBN or keyword for the book you want to reserve: ").strip()
    normalized_search_term = search_term.zfill(13) if search_term.isdigit() and len(search_term) in [10, 13] else search_term

    search_results = []
    for book in books:
        borrowed_count = sum(b.number_of_copies_borrowed for b in borrowed_books if b.isbn_num == book.isbn_num)
        if (normalized_search_term in book.isbn_num or normalized_search_term.lower() in book.title.lower()) and borrowed_count >= book.number_of_copies:
            search_results.append(book)

    if not search_results:
        print("This book is available for borrowing or does not exist.")
        return

    print("Search results:")
    for i, book in enumerate(search_results, start=1):
        print(f"{i}. {book}")

    choice = input("Enter the number of the book you want to reserve or 'exit' to return to menu: ")
    if choice.lower() == 'exit':
        return

    try:
        choice = int(choice)
        if 1 <= choice <= len(search_results):
            book_to_reserve = search_results[choice - 1]
            # Check if the user already reserved this book
            for reservation in reservations:
                if reservation.isbn_num == book_to_reserve.isbn_num and reservation.username == current_user:
                    print(f"You have already reserved the book '{book_to_reserve.title}'.")
                    return
            reserved_book = Reservation(book_to_reserve.isbn_num, current_user, datetime.now())
            reservations.append(reserved_book)
            print(f"Book '{book_to_reserve.title}' reserved successfully!")

            # Initialize notifications for the user if not already present
            if current_user not in user_notifications:
                user_notifications[current_user] = []

            # Add a reservation notification
            user_notifications[current_user].append(f"You have reserved the book '{book_to_reserve.title}'.")
        else:
            print("Invalid choice.")
    except ValueError:
        print("Please enter a valid number.")

def notify_reservations():
    for reservation in reservations[:]:
        for book in books:
            borrowed_count = sum(b.number_of_copies_borrowed for b in borrowed_books if b.isbn_num == book.isbn_num)
            available_copies = book.number_of_copies - borrowed_count
            if book.isbn_num == reservation.isbn_num and available_copies > 0:
                if reservation.username not in user_notifications:
                    user_notifications[reservation.username] = []

                user_notifications[reservation.username].append(f"The book '{book.title}' is now available.")
                reservations.remove(reservation)
                break

book_reviews = {}
user_notifications = {}

def add_review(book_isbn, user_id, rating, comment):
    try:
        with shelve.open('reviews') as reviews_shelf:
            reviews = reviews_shelf.get('book_reviews', {})
            if user_id not in reviews:
                reviews[user_id] = {}
            reviews[user_id][book_isbn] = {"rating": rating, "comment": comment}
            save_reviews(reviews)
    except Exception as e:
        logging.error(f"Error saving review: {e}")

def display_reviews(isbn_num):
    isbn_num = isbn_num.zfill(13)
    book_reviews = load_reviews()
    if isbn_num not in book_reviews or not book_reviews[isbn_num]:
        print("No reviews for this book have been made so far. Be the first to do it!")
        return

    # Calculate the overall rating
    total_rating = 0
    review_count = len(book_reviews[isbn_num])
    for review in book_reviews[isbn_num]:
        total_rating += int(review.rating)  # Ensure the rating is an integer
    average_rating = total_rating / review_count

    print(f"Overall rating of the book: {average_rating:.1f}/5")

    # Display individual reviews
    print("Reviews for this book:")
    for review in book_reviews[isbn_num]:
        print(f"Reviewer: {review.username}")
        print(f"Rating: {review.rating}")
        print(f"Comment: {review.review_text}")
        print("-" * 40)

def display_books(sort_by_isbn=True):
    if not books:
        print("There are currently no books to be displayed.")
        return

    if sort_by_isbn:
        sort_books_by_isbn_ascending()  # Sort books by ISBN in ascending order
    merged_books = {}
    borrowed_counts = {}

    for borrowed_book in borrowed_books:
        key = borrowed_book.isbn_num
        if key in borrowed_counts:
            borrowed_counts[key] += borrowed_book.number_of_copies_borrowed
        else:
            borrowed_counts[key] = borrowed_book.number_of_copies_borrowed

    for book in books:
        key = book.isbn_num
        if key in merged_books:
            merged_books[key].number_of_copies += book.number_of_copies
        else:
            merged_books[key] = book

    book_table = []
    for isbn, book in merged_books.items():
        borrowed_count = borrowed_counts.get(isbn, 0)
        total_copies = book.number_of_copies
        available_copies = total_copies - borrowed_count
        availability = available_copies > 0

        book_table.append([
            book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
            book.number_of_copies, availability, book.addedbywho
        ])

    # Ensure the table is sorted by ISBN
    book_table.sort(key=lambda x: x[0])  # x[0] is the ISBN column

    print("=== All Books in Inventory ===")
    print(tabulate(book_table, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                        "Number of Copies", "Availability", "Added by"], tablefmt='grid'))

# Display sorted books in the desired format
def display_sorted_books(sorted_books):
    # Display the books sorted by the chosen criteria first
    book_table = [
        [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
         book.number_of_copies, book.availability, book.addedbywho]
        for book in sorted_books
    ]
    print(tabulate(book_table, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                        "Number of Copies", "Availability", "Added by"], tablefmt='grid'))

    # Re-sort by ISBN ascending after displaying the sorted results
    sorted_by_isbn_books = sorted(books, key=lambda book: book.isbn_num)
    sorted_book_table = [
        [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
         book.number_of_copies, book.availability, book.addedbywho]
        for book in sorted_by_isbn_books
    ]

def sort_and_display_books(books):
    # Sort books by ISBN in ascending order
    sorted_books = sorted(books, key=lambda book: book.isbn_num)

    # Display sorted books
    book_table = [
        [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published, book.number_of_copies, book.availability, book.addedbywho]
        for book in sorted_books
    ]
    print(tabulate(book_table, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published", "Number of Copies", "Availability", "Added by"], tablefmt='grid'))

def display_available_books():
    borrowed_counts = {}
    for book in borrowed_books:
        key = (book.title, book.publisher, book.author, book.language, book.genre, book.year_published)
        if key in borrowed_counts:
            borrowed_counts[key] += book.number_of_copies_borrowed
        else:
            borrowed_counts[key] = book.number_of_copies_borrowed

    available_books = {}
    for book in books:
        key = (book.title, book.publisher, book.author, book.language, book.genre, book.year_published)
        total_copies = book.number_of_copies
        borrowed_copies = borrowed_counts.get(key, 0)
        available_copies = total_copies - borrowed_copies
        if available_copies > 0:
            if key in available_books:
                available_books[key].number_of_copies += available_copies
            else:
                new_book = Book(book.title, book.isbn_num, book.publisher, book.author, book.language, book.genre, book.year_published, available_copies, book.availability, book.addedbywho)
                available_books[key] = new_book

    available_books_table = [
        [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published, book.number_of_copies, book.addedbywho]
        for book in available_books.values()
    ]

    # Sort the table by ISBN
    available_books_table.sort(key=lambda x: x[0])  # x[0] is the ISBN column

    if not available_books_table:
        print("There are no available books in this book management system.")
    else:
        print("=== Available Books ===")
        print(tabulate(available_books_table, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published", "Number of Copies", "Added by"], tablefmt='grid'))

def display_unavailable_books():
    borrowed_counts = {}
    for book in borrowed_books:
        key = book.isbn_num
        if key in borrowed_counts:
            borrowed_counts[key] += book.number_of_copies_borrowed
        else:
            borrowed_counts[key] = book.number_of_copies_borrowed

    unavailable_books = []
    for book in books:
        key = book.isbn_num
        total_copies = book.number_of_copies
        borrowed_copies = borrowed_counts.get(key, 0)
        available_copies = total_copies - borrowed_copies
        if available_copies <= 0:  # If no copies are available, mark as unavailable
            unavailable_books.append(book)

    if not unavailable_books:
        print("All books are currently available.")
        return

    unavailable_books_table = [
        [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published, book.number_of_copies, book.addedbywho]
        for book in unavailable_books
    ]

    # Sort the table by ISBN
    unavailable_books_table.sort(key=lambda x: x[0])  # x[0] is the ISBN column

    print("=== Unavailable Books ===")
    print(tabulate(unavailable_books_table,
                   headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                            "Number of Copies", "Added by"], tablefmt='grid'))

def check_borrowed_books_by_current_user(current_user):
    user_borrowed_books = [book for book in borrowed_books if isinstance(book, Borrow) and book.username == current_user]
    if user_borrowed_books:
        merged_user_borrowed_books = {}
        for book in user_borrowed_books:
            key = (book.title, book.publisher, book.author, book.language, book.genre, book.year_published)
            if key in merged_user_borrowed_books:
                merged_user_borrowed_books[key].number_of_copies += book.number_of_copies
                if not merged_user_borrowed_books[key].availability:
                    merged_user_borrowed_books[key].availability = book.availability
            else:
                merged_user_borrowed_books[key] = book

        user_borrowed_books_table = [
            [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published, book.number_of_copies, book.availability]
            for book in merged_user_borrowed_books.values()
        ]

        # Sort the table by ISBN
        user_borrowed_books_table.sort(key=lambda x: x[0])  # x[0] is the ISBN column

        print(f"Books borrowed by you, {current_user}:")
        print(tabulate(user_borrowed_books_table, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published", "Number of Copies", "Availability"], tablefmt='grid'))
    else:
        print(f"You did not borrow any books.")

def display_borrowed_books(current_user):
    if not borrowed_books:
        print("No books have been borrowed.")
        return

    borrowed_books_table = []
    for book in borrowed_books:
        borrowed_on_str = book.borrowed_on.strftime('%Y-%m-%d %H:%M:%S')
        borrowed_books_table.append([
            book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
            book.number_of_copies_borrowed, book.username, borrowed_on_str
        ])

    # Sort the table by ISBN
    borrowed_books_table.sort(key=lambda x: x[0])  # x[0] is the ISBN column

    print("=== Borrowed Books ===")
    print(tabulate(borrowed_books_table, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                                  "Number of Copies Borrowed", "Borrowed by", "Borrowed on"], tablefmt='grid'))

def add_book(title, isbn_num, publisher, author, language, genre, year_published, number_of_copies, availability, addedbywho):
    global books
    isbn_num = isbn_num.zfill(13)
    number_of_copies = int(number_of_copies)
    year_published = int(year_published)
    book_found = False
    for existing_book in books:
        if existing_book.isbn_num == isbn_num:
            if (existing_book.title != title or
                existing_book.publisher != publisher or
                existing_book.author != author or
                existing_book.language != language or
                existing_book.genre != genre or
                existing_book.year_published != year_published):
                print(f"Another different book with ISBN number {isbn_num} is already existing")
                logging.warning(f"Attempted to add a different book with existing ISBN {isbn_num}")
                return False
            existing_book.number_of_copies += number_of_copies
            existing_book.availability = existing_book.number_of_copies > 0
            logging.info(f"Updated book copies for ISBN {isbn_num}: +{number_of_copies} copies added by {addedbywho}.")
            book_found = True
            break
    if not book_found:
        new_book = Book(title, isbn_num, publisher, author, language, genre, year_published, number_of_copies,
                        availability, addedbywho)
        books.append(new_book)
        logging.info(f"Added new book: {title} by {addedbywho}.")
    save_books(books)
    books = load_books()
    notify_reservations()
    user_info = authorized_user.get(addedbywho, general_user.get(addedbywho))
    if user_info:
        points_awarded = award_points(user_info, "add_book")
        print(f"{addedbywho} earned {points_awarded} points for adding the book! Total points: {user_info['points']}, Tier: {user_info['tier']}")
        is_authorized = addedbywho in authorized_user
        save_user_data(addedbywho, is_authorized)
    return True

def validate_year(year):
    if not year.isdigit() or int(year) > 2024:
        return False, "Year must be a number and not in the future."
    return True, ""

def check_existing_book_with_same_isbn(isbn_num, title, publisher, author, language, genre, year_published):
    for book in books:
        if book.isbn_num == isbn_num:
            if (book.title != title or
                book.publisher != publisher or
                book.author != author or
                book.language != language or
                book.genre != genre or
                book.year_published != year_published):
                return book
    return None

def validate_number_of_copies(copies):
    if not copies.isdigit() or int(copies) < 0:
        return False, "Number of copies must be a non-negative integer."
    return True, ""

def update_book(current_user):
    if not books:
        print("There are no books in the inventory to be updated.")
        return

    isbn_num = input("Enter the ISBN number of the book to update or 'exit' to return to menu: ").zfill(13)
    if isbn_num.lower() == 'exit':
        return
    for book in books:
        if str(book.isbn_num) == isbn_num:
            print(f"Current details: {book}")
            title = input(f"Enter new title or press Enter to keep (current: {book.title}): ")
            if title.lower() == 'exit':
                return
            if title == "":
                title = book.title

            publisher = input(f"Enter new publisher or 'exit' to return to menu or press Enter to keep (current: {book.publisher}): ")
            if publisher.lower() == 'exit':
                return
            if publisher == "":
                publisher = book.publisher

            author = input(f"Enter new author or 'exit' to return to menu or press Enter to keep (current: {book.author}): ")
            if author.lower() == 'exit':
                return
            if author == "":
                author = book.author

            language = input(f"Enter new language or 'exit' to return to menu or press Enter to keep (current: {book.language}): ")
            if language.lower() == 'exit':
                return
            if language == "":
                language = book.language

            genre = input(f"Enter new genre or 'exit' to return to menu or press Enter to keep (current: {book.genre}): ")
            if genre.lower() == 'exit':
                return
            if genre == "":
                genre = book.genre

            year_published = input(f"Enter new year published or 'exit' to return to menu or press Enter to keep (current: {book.year_published}): ")
            if year_published.lower() == 'exit':
                return
            if year_published == "":
                year_published = book.year_published

            number_of_copies = input(f"Enter new number of copies or 'exit' to return to menu or press Enter to keep (current: {book.number_of_copies}): ")
            if number_of_copies.lower() == 'exit':
                return
            if number_of_copies == "":
                number_of_copies = book.number_of_copies

            book.title = title
            book.publisher = publisher
            book.author = author
            book.language = language
            book.genre = genre
            book.year_published = int(year_published)
            book.number_of_copies = int(number_of_copies)
            book.availability = book.number_of_copies > 0

            logging.info(f"Book with ISBN {isbn_num} updated by {book.addedbywho}.")
            save_books(books)
            print("Book updated successfully.")
            return
    print("Book not found.")

def validate_isbn(isbn):
    try:
        if isbn.lower() != "exit":
            isbn = isbn.zfill(13)  # Ensure ISBN is 13 characters long with leading zeros
            if not isbn.isdigit() or len(isbn) != 13:
                return False, "ISBN must be a number with 13 digits."
            else:
                return True, isbn
    except ValueError:
        print("\nInvalid ISBN. Please enter a valid number.")

def delete_book(current_user):
    global books
    if not books:
        print("There are no books in the inventory to be deleted.")
        return

    isbn_num = input("Enter the ISBN number of the book to delete or 'exit' to return to menu: ").zfill(13)
    if isbn_num.lower() == 'exit':
        return
    valid, message = validate_isbn(isbn_num)
    if not valid:
        print(message)
        return
    # Load the updated list of books
    books = load_books()
    total_copies = sum(book.number_of_copies for book in books if book.isbn_num == isbn_num)
    if total_copies == 0:
        print("Book not found.")
        return
    print(f"There are {total_copies} copies of this book.")
    howmanytodelete = input("How many copies do you want to delete?: ").strip()
    if not howmanytodelete.isdigit():
        print("Invalid number of copies.")
        return
    howmanytodelete = int(howmanytodelete)
    if howmanytodelete > total_copies:
        print(f"You cannot delete more than {total_copies} copies.")
        return
    copies_to_delete = howmanytodelete
    for book in books:
        if book.isbn_num == isbn_num:
            if copies_to_delete >= book.number_of_copies:
                copies_to_delete -= book.number_of_copies
                books.remove(book)
            else:
                book.number_of_copies -= copies_to_delete
                book.availability = book.number_of_copies > 0
                break
    save_books(books)
    books = load_books()
    print("Book updated successfully.")

def sort_books_by_isbn_ascending():
    global books
    books = sorted(books, key=lambda book: book.isbn_num)
    save_books(books)

def bubble_sort_by_publisher_in_ascending():
    n = len(books)
    for i in range(n - 1):
        for j in range(0, n - i - 1):
            if books[j].publisher.lower() > books[j + 1].publisher.lower():
                books[j], books[j + 1] = books[j + 1], books[j]
    save_books(books)  # Save the sorted list
    print("Books sorted by publisher in ascending alphabetical order:")
    display_sorted_books(books)

def bubble_sort_by_publisher_in_descending():
    n = len(books)
    for i in range(n - 1):
        for j in range(0, n - i - 1):
            if books[j].publisher.lower() < books[j + 1].publisher.lower():
                books[j], books[j + 1] = books[j + 1], books[j]
    save_books(books)  # Save the sorted list
    print("Books sorted by publisher in descending alphabetical order:")
    display_sorted_books(books)

def insertion_sort_by_copies_in_ascending():
    for i in range(1, len(books)):
        key = books[i]
        j = i - 1
        while j >= 0 and books[j].number_of_copies > key.number_of_copies:
            books[j + 1] = books[j]
            j -= 1
        books[j + 1] = key
    save_books(books)  # Save the sorted list
    print("Books sorted by number of copies in ascending order:")
    display_sorted_books(books)

def insertion_sort_by_copies_in_descending():
    for i in range(1, len(books)):
        key = books[i]
        j = i - 1
        while j >= 0 and books[j].number_of_copies < key.number_of_copies:
            books[j + 1] = books[j]
            j -= 1
        books[j + 1] = key
    save_books(books)  # Save the sorted list
    print("Books sorted by number of copies in descending order:")
    display_sorted_books(books)

def quick_sort_books_by_title(books_list, low, high, ascending=True):
    if low < high:
        pi = partition(books_list, low, high, ascending)
        quick_sort_books_by_title(books_list, low, pi - 1, ascending)
        quick_sort_books_by_title(books_list, pi + 1, high, ascending)

def partition(books_list, low, high, ascending):
    pivot = books_list[high].title.lower()
    i = low - 1
    for j in range(low, high):
        if (ascending and books_list[j].title.lower() <= pivot) or (not ascending and books_list[j].title.lower() >= pivot):
            i += 1
            books_list[i], books_list[j] = books_list[j], books_list[i]
    books_list[i + 1], books_list[high] = books_list[high], books_list[i + 1]
    return i + 1

def quick_sort_by_title_ascending():
    quick_sort_books_by_title(books, 0, len(books) - 1, ascending=True)
    save_books(books)  # Save the sorted list
    print("Books sorted by title in ascending order:")
    display_sorted_books(books)

def quick_sort_by_title_descending():
    quick_sort_books_by_title(books, 0, len(books) - 1, ascending=False)
    save_books(books)  # Save the sorted list
    print("Books sorted by title in descending order:")
    display_sorted_books(books)

def merge_sort_books_by_language_isbn(books_list, lang_ascending=True, isbn_ascending=True):
    if len(books_list) > 1:
        mid = len(books_list) // 2
        left_half = books_list[:mid]
        right_half = books_list[mid:]

        merge_sort_books_by_language_isbn(left_half, lang_ascending, isbn_ascending)
        merge_sort_books_by_language_isbn(right_half, lang_ascending, isbn_ascending)

        i = j = k = 0

        while i < len(left_half) and j < len(right_half):
            left_key = (left_half[i].language.lower(), left_half[i].isbn_num)
            right_key = (right_half[j].language.lower(), right_half[j].isbn_num)

            if (lang_ascending and left_key[0] < right_key[0]) or (not lang_ascending and left_key[0] > right_key[0]) or (
                    left_key[0] == right_key[0] and (
                    (isbn_ascending and left_key[1] <= right_key[1]) or (not isbn_ascending and left_key[1] >= right_key[1]))):
                books_list[k] = left_half[i]
                i += 1
            else:
                books_list[k] = right_half[j]
                j += 1
            k += 1

        while i < len(left_half):
            books_list[k] = left_half[i]
            i += 1
            k += 1

        while j < len(right_half):
            books_list[k] = right_half[j]
            j += 1
            k += 1

def merge_sort_by_language_asc_isbn_asc():
    merge_sort_books_by_language_isbn(books, lang_ascending=True, isbn_ascending=True)
    save_books(books)  # Save the sorted list
    print("Books sorted by language ascending and ISBN ascending.")
    display_sorted_books(books)

def merge_sort_by_language_asc_isbn_desc():
    merge_sort_books_by_language_isbn(books, lang_ascending=True, isbn_ascending=False)
    save_books(books)  # Save the sorted list
    print("Books sorted by language ascending and ISBN descending.")
    display_sorted_books(books)

def merge_sort_by_language_desc_isbn_asc():
    merge_sort_books_by_language_isbn(books, lang_ascending=False, isbn_ascending=True)
    save_books(books)  # Save the sorted list
    print("Books sorted by language descending and ISBN ascending.")
    display_sorted_books(books)

def merge_sort_by_language_desc_isbn_desc():
    merge_sort_books_by_language_isbn(books, lang_ascending=False, isbn_ascending=False)
    save_books(books)  # Save the sorted list
    print("Books sorted by language descending and ISBN descending.")
    display_sorted_books(books)

def advanced_search_books(sort_by_isbn=True):
    print("=== Advanced Search ===")
    title = input("Enter title (or part of it) to search or press Enter to skip: ").strip().lower()
    publisher = input("Enter publisher (or part of it) to search or press Enter to skip: ").strip().lower()
    author = input("Enter author (or part of it) to search or press Enter to skip: ").strip().lower()
    genre = input("Enter genre (or part of it) to search or press Enter to skip: ").strip().lower()
    language = input("Enter language (or part of it) to search or press Enter to skip: ").strip().lower()
    year = input("Enter year of publication or press Enter to skip: ").strip()

    def match_criteria(book):
        if title and title not in book.title.lower():
            return False
        if publisher and publisher not in book.publisher.lower():
            return False
        if author and author not in book.author.lower():
            return False
        if genre and genre not in book.genre.lower():
            return False
        if language and language not in book.language.lower():
            return False
        if year and (not year.isdigit() or int(year) != book.year_published):
            return False
        return True

    if sort_by_isbn:
        sort_books_by_isbn_ascending()  # Sort books by ISBN in ascending order
    search_results = [book for book in books if match_criteria(book)]

    if search_results:
        results_table = [
            [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published, book.number_of_copies, book.availability]
            for book in search_results
        ]

        # Sort the table by ISBN
        results_table.sort(key=lambda x: x[0])  # x[0] is the ISBN column

        print("Books matching your search criteria:")
        print(tabulate(results_table, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published", "Number of Copies", "Availability"], tablefmt='grid'))

        # Option to view reviews
        isbn_for_review = input("Enter the ISBN number to view reviews or 'exit' to return: ").strip()
        if isbn_for_review.lower() != 'exit':
            display_reviews(isbn_for_review)
    else:
        print("No books found matching your search criteria.")

def search_books():
    search_term = input("Enter an ISBN number or any search keywords to search for books: ").strip()
    merged_results = {}
    combined_books = books + [book for book in sample_books if book not in books]

    for book in combined_books:
        if (search_term.lower() in book.title.lower() or
            search_term in book.isbn_num or
            search_term.lower() in book.publisher.lower() or
            search_term.lower() in book.author.lower() or
            search_term.lower() in book.language.lower() or
            search_term.lower() in book.genre.lower() or
            search_term.lower() in str(book.year_published)):
            key = (book.title, book.publisher, book.author, book.language, book.genre, book.year_published)
            if key in merged_results:
                merged_results[key].number_of_copies += book.number_of_copies
                if not merged_results[key].availability:
                    merged_results[key].availability = book.availability
            else:
                merged_results[key] = book

    results = [
        [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published, book.number_of_copies, book.availability]
        for book in merged_results.values()
    ]

    results.sort(key=lambda x: x[0])

    if results:
        print(f"Books matching '{search_term}' have been found:")
        print(tabulate(results, headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published", "Number of Copies", "Availability"], tablefmt='grid'))
        isbn_for_review = input("Enter the ISBN number to view reviews or 'exit' to return: ").strip()
        if isbn_for_review.lower() != 'exit':
            display_reviews(isbn_for_review)
    else:
        print(f"No books matching '{search_term}' have been found.")

def recommend_books_for_user(current_user):
    print(f"\n=== Personalized Recommendations for {current_user} ===")

    # Load the user's borrowing history
    with shelve.open('borrow_history') as borrow_shelf:
        history = borrow_shelf.get(current_user, [])

    if not history:
        print("No borrowing history found. Here are some popular books:")
        popular_books = sorted(books, key=lambda x: x.number_of_copies, reverse=True)[:5]
        recommendation_table = [
            [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
             book.number_of_copies]
            for book in popular_books
        ]
        print(tabulate(recommendation_table,
                       headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                "Number of Copies"], tablefmt='grid'))
        return

    # Load the reviews for the user
    with shelve.open('reviews') as reviews_shelf:
        reviews = reviews_shelf.get('book_reviews', {}).get(current_user, {})

    # Identify genres of books rated 3.6 or higher and their corresponding ratings
    genre_ratings = {}
    for isbn, review in reviews.items():
        if review['rating'] >= 3.6:
            for record in history:
                if record[0] == isbn:
                    with shelve.open('book_shelf') as book_shelf:
                        books_data = book_shelf.get('books', [])
                        book_details = next((book for book in books_data if book.isbn_num == isbn), None)
                        if book_details:
                            genre = book_details.genre
                            if genre not in genre_ratings:
                                genre_ratings[genre] = []
                            genre_ratings[genre].append(review['rating'])

    if not genre_ratings:
        print("No highly-rated genres found in your borrowing history. Here are some popular books:")
        popular_books = sorted(books, key=lambda x: x.number_of_copies, reverse=True)[:5]
        recommendation_table = [
            [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
             book.number_of_copies]
            for book in popular_books
        ]
        print(tabulate(recommendation_table,
                       headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                "Number of Copies"], tablefmt='grid'))
        return

    # Determine the number of recommendations to allocate per genre
    total_books_to_recommend = 5
    recommended_books = []
    remaining_slots = total_books_to_recommend

    for genre, ratings in sorted(genre_ratings.items(), key=lambda item: -max(item[1])):
        genre_books = [book for book in books if
                       book.genre == genre and book.isbn_num not in [record[0] for record in history]]
        num_books_to_recommend = min(remaining_slots, max(1, int(total_books_to_recommend * (
                    len(ratings) / sum(map(len, genre_ratings.values()))))))

        if len(genre_books) < num_books_to_recommend:
            num_books_to_recommend = len(genre_books)

        recommended_books.extend(genre_books[:num_books_to_recommend])
        remaining_slots -= num_books_to_recommend

    # Fill remaining slots with random books if needed
    if remaining_slots > 0:
        remaining_books = [book for book in books if
                           book.isbn_num not in [record[0] for record in history] and book.genre not in genre_ratings]
        random_books = sorted(remaining_books, key=lambda x: x.number_of_copies, reverse=True)[:remaining_slots]
        recommended_books.extend(random_books)

    # Display the recommendations
    if recommended_books:
        recommendation_table = [
            [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
             book.number_of_copies]
            for book in recommended_books
        ]
        print("Based on your borrowing history and reviews, you might like:")
        print(tabulate(recommendation_table,
                       headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                "Number of Copies"], tablefmt='grid'))
    else:
        print("No recommendations available based on your history. Here are some popular books:")
        popular_books = sorted(books, key=lambda x: x.number_of_copies, reverse=True)[:5]
        recommendation_table = [
            [book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre, book.year_published,
             book.number_of_copies]
            for book in popular_books
        ]
        print(tabulate(recommendation_table,
                       headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                "Number of Copies"], tablefmt='grid'))

def save_user_data(current_user, is_authorized=True):
    try:
        user_info = load_user(current_user)
        if is_authorized:
            authorized_user[current_user] = user_info
            save_authorized_users(authorized_user)
        else:
            general_user[current_user] = user_info
            save_general_users(general_user)
    except Exception as e:
        logging.error(f"Error in save_user_data: {e}")


def get_borrowing_history(user_id):
    """Retrieve and display the borrowing history for a specific user from the shelve database, including reviews."""

    # Open the shelve file that contains the borrowing history
    with shelve.open('borrow_history') as borrow_shelf:
        history = borrow_shelf.get(user_id, [])

    if not history:
        print(f"No borrowing history found for user ID {user_id}.")
        return []

    # Retrieve reviews and book details
    with shelve.open('reviews') as reviews_shelf:
        reviews = reviews_shelf.get('book_reviews', {})

    with shelve.open('book_shelf') as book_shelf:
        books = book_shelf.get('books', [])
        history_table = []

        for record in history:
            book_isbn, borrowed_date = record
            formatted_isbn = book_isbn.zfill(13)

            # Find the book details using the ISBN
            book_details = next((book for book in books if book.isbn_num == formatted_isbn), None)

            # Fetch the review for this book and user
            review_data = reviews.get(user_id, {}).get(formatted_isbn)
            review_text = f"Rating: {review_data['rating']}/5, Comment: {review_data['comment']}" if review_data else "No Review"

            if book_details:
                # Append the full book details to the history table, including the review
                history_table.append([
                    book_details.isbn_num, book_details.title, book_details.author,
                    book_details.publisher, book_details.year_published, book_details.language,
                    book_details.genre, borrowed_date.strftime('%Y-%m-%d %H:%M:%S'), review_text
                ])
            else:
                # Handle case where book details are not found, including the review
                history_table.append([
                    book_isbn, "Unknown Title", "Unknown Author", "Unknown Publisher",
                    "Unknown Year", "Unknown Language", "Unknown Genre",
                    borrowed_date.strftime('%Y-%m-%d %H:%M:%S'), review_text
                ])

    # Print the history in a tabulated format, including all records
    print(f"Borrowing history for user ID {user_id}:")
    print(tabulate(history_table, headers=[
        'ISBN', 'Title', 'Author', 'Publisher', 'Year Published', 'Language', 'Genre', 'Borrowed Date', 'Review'
    ], tablefmt='grid'))

    return history

def borrow_book(current_user):
    while True:
        if not books:
            print("There are no books available in this book management system.")
            logging.info(f"{current_user} attempted to borrow a book but no books are available.")
            return

        search_term = input("Enter the ISBN or keyword for the book you want to borrow or 'exit' to return to menu: ").strip()
        if search_term.lower() == 'exit':
            return

        normalized_search_term = search_term.zfill(13) if search_term.isdigit() and len(search_term) in [10, 13] else search_term

        search_results = {}
        for book in books:
            normalized_isbn = book.isbn_num.zfill(13)
            if (normalized_search_term == normalized_isbn or
                    normalized_search_term.lower() in book.isbn_num or
                    normalized_search_term.lower() in book.title.lower() or
                    normalized_search_term.lower() in book.publisher.lower() or
                    normalized_search_term.lower() in book.author.lower() or
                    normalized_search_term.lower() in book.language.lower() or
                    normalized_search_term.lower() in book.genre.lower() or
                    normalized_search_term.lower() in str(book.year_published)):
                if normalized_isbn not in search_results:
                    search_results[normalized_isbn] = copy.copy(book)
                else:
                    search_results[normalized_isbn].number_of_copies += book.number_of_copies

        if not search_results:
            print("No books matching your search were found.")
            continue

        results_table = []
        for book in search_results.values():
            borrowed_count = sum(b.number_of_copies_borrowed for b in borrowed_books if b.isbn_num == book.isbn_num)
            available_copies = book.number_of_copies - borrowed_count

            book.availability = available_copies > 0
            results_table.append([
                book.isbn_num, book.title, book.publisher, book.author, book.language, book.genre,
                book.year_published, available_copies, book.availability
            ])

        if not results_table:
            print("No available books matching your search were found.")
            continue

        print("Search results:")
        print(tabulate(results_table,
                       headers=["ISBN", "Title", "Publisher", "Author", "Language", "Genre", "Year Published",
                                "Available Copies", "Availability"], tablefmt='grid'))

        isbn_to_borrow = input(
            "Enter the ISBN number of the book you want to borrow or 'exit' to return to menu: ").strip()
        if isbn_to_borrow.lower() == 'exit':
            return

        normalized_isbn_to_borrow = isbn_to_borrow.zfill(13)

        if normalized_isbn_to_borrow in search_results:
            book_to_borrow = search_results[normalized_isbn_to_borrow]
            if not book_to_borrow.availability:
                print(f"'{book_to_borrow.title}' is currently not available for borrowing.")
                logging.info(f"{current_user} attempted to borrow '{book_to_borrow.title}' which is not available.")
                continue

            borrowed_count = sum(
                b.number_of_copies_borrowed for b in borrowed_books if b.isbn_num == normalized_isbn_to_borrow)
            available_copies = book_to_borrow.number_of_copies - borrowed_count

            if available_copies > 0:
                confirm = input(f"Do you want to borrow '{book_to_borrow.title}'? (y/n): ").lower()
                if confirm == 'y':
                    attempts = 3
                    while attempts > 0:
                        password = input("Enter your password to confirm: ")
                        if verify_password(authorized_user.get(current_user, {}).get('password', ''),
                                           password) or verify_password(
                                general_user.get(current_user, {}).get('password', ''), password):
                            # Save borrowing to shelve
                            with shelve.open('borrow_history') as borrow_shelf:
                                # Retrieve the current user's history, default to an empty list if not found
                                current_history = borrow_shelf.get(current_user, [])

                                # Append the new borrowing record to the history
                                current_history.append((book_to_borrow.isbn_num, datetime.now()))

                                # Save the updated history back to the shelve
                                borrow_shelf[current_user] = current_history

                            borrowed_book = BorrowedBook(book_to_borrow.title, book_to_borrow.isbn_num,
                                                         book_to_borrow.publisher, book_to_borrow.author,
                                                         book_to_borrow.language, book_to_borrow.genre,
                                                         book_to_borrow.year_published, 1, book_to_borrow.availability,
                                                         book_to_borrow.addedbywho, current_user, datetime.now())
                            borrowed_books.append(borrowed_book)
                            save_borrowed_books(borrowed_books)
                            logging.info(f"{current_user} borrowed '{book_to_borrow.title}'.")

                            user_info = authorized_user.get(current_user, general_user.get(current_user))
                            if user_info:
                                user_info['borrowed_books_stack'].push(borrowed_book)
                                points_awarded = award_points(user_info, "borrow_book")
                                print(f"You have successfully borrowed '{book_to_borrow.title}'. You earned {points_awarded} points! Total points: {user_info['points']}, Tier: {user_info['tier']}")

                                # Save the updated user information back to the storage
                                is_authorized = current_user in authorized_user
                                save_user_data(current_user, is_authorized)
                            return
                        else:
                            attempts -= 1
                            print(f"Incorrect password. You have {attempts} {'attempt' if attempts == 1 else 'attempts'} left.")
                    if attempts == 0:
                        print("You have exceeded the maximum number of attempts. Borrowing cancelled.")
                        logging.warning(
                            f"{current_user} failed to borrow '{book_to_borrow.title}' due to incorrect password.")
                else:
                    print("Borrowing cancelled.")
            else:
                print("No available copies left for this book.")
        else:
            print("No book found with that ISBN.")

def update_genre_preferences(user_info, book_genre):
    if 'preferred_genres' not in user_info:
        user_info['preferred_genres'] = set()
    user_info['preferred_genres'].add(book_genre)

def return_book(current_user):
    user_info = authorized_user.get(current_user, general_user.get(current_user))
    if not user_info:
        print("You did not borrow any books.")
        logging.info(f"{current_user} attempted to return a book but has no borrowed books.")
        return

    user_borrowed_books_stack = user_info['borrowed_books_stack']
    if user_borrowed_books_stack.is_empty():
        print("You did not borrow any books.")
        logging.info(f"{current_user} attempted to return a book but has no borrowed books.")
        return

    print("Books you have borrowed (most recent first):")
    borrowed_books_list = []
    while not user_borrowed_books_stack.is_empty():
        borrowed_books_list.append(user_borrowed_books_stack.pop())

    # Display the list of borrowed books
    for i, borrowed_book in enumerate(borrowed_books_list, 1):
        print(
            f"{i}. Title: {borrowed_book.title}, ISBN: {borrowed_book.isbn_num}, Publisher: {borrowed_book.publisher}, "
            f"Author: {borrowed_book.author}, Language: {borrowed_book.language}, Genre: {borrowed_book.genre}, "
            f"Year: {borrowed_book.year_published}, Borrowed On: {borrowed_book.borrowed_on}")

    while True:
        try:
            choice = input("Enter the number of the book you are returning or 'exit' to return to menu: ").strip()
            if choice.lower() == 'exit':
                print("Returning to menu...")
                # Restore the stack
                for book in reversed(borrowed_books_list):
                    user_borrowed_books_stack.push(book)
                return
            choice = int(choice)
            if 1 <= choice <= len(borrowed_books_list):
                borrowed_book_to_return = borrowed_books_list[choice - 1]
                print(f"Book to return: {borrowed_book_to_return.title}")

                # Remove the book from the borrowed_books_list
                borrowed_books_list.remove(borrowed_book_to_return)

                # Restore the stack to its original state except for the returned book
                for book in reversed(borrowed_books_list):
                    user_borrowed_books_stack.push(book)

                # Remove the book from the borrowed_books if it exists
                if borrowed_book_to_return in borrowed_books:
                    borrowed_books.remove(borrowed_book_to_return)
                else:
                    print(f"Book '{borrowed_book_to_return.title}' not found in borrowed_books list.")

                save_borrowed_books(borrowed_books)
                logging.info(
                    f"{current_user} returned '{borrowed_book_to_return.title}' (ISBN: {borrowed_book_to_return.isbn_num}).")
                print(f"You have successfully returned '{borrowed_book_to_return.title}'.")

                notify_reservations()

                # Update points for the user
                return_date = datetime.now()
                borrowed_duration = (return_date - borrowed_book_to_return.borrowed_on).days
                if borrowed_duration > 14:  # Assuming 2 weeks borrowing period
                    points_deducted = deduct_points(user_info, "late_return")
                    print(f"You returned the book late. {points_deducted} points have been deducted from your account. Total points: {user_info['points']}, Tier: {user_info['tier']}")
                else:
                    points_awarded = award_points(user_info, "return_book")
                    print(f"You have successfully returned the book on time. You earned {points_awarded} points! Total points: {user_info['points']}, Tier: {user_info['tier']}")

                # Save the updated user information back to the storage
                is_authorized = current_user in authorized_user
                save_user_data(current_user, is_authorized)

                # Prompt for review
                review_choice = input("Would you like to give a review? (y/n): ").strip().lower()
                if review_choice == 'y':
                    rating = float(input("Please give a rating (1-5): ").strip())
                    while rating < 1 or rating > 5:
                        rating = float(input("Invalid input. Please give a rating (1-5): ").strip())

                    comment = input("Please provide your comment: ").strip()
                    if rating >= 3.6:
                        update_genre_preferences(user_info, borrowed_book_to_return.genre)
                    add_review(borrowed_book_to_return.isbn_num, current_user, rating, comment)
                    print("Thank you for your review!")
                else:
                    print("Returning to the menu...")

                return
            else:
                print(f"Invalid number. Please enter a number from the list.")
        except ValueError as e:
            print("Invalid input. Please enter a number from the list or 'exit' to return to menu.")

def create_account():
    while True:
        new_username = input("Enter a new username or 'exit' to return: ")
        if new_username.lower() == "exit":
            return
        if not new_username:
            print("Username cannot be empty. Please try again.")
            return
        if new_username in authorized_user or new_username in general_user:
            print("This username already exists.")
            logging.warning(f"Account creation failed: Username {new_username} already exists.")
            return

        valid, message = validate_username(new_username)
        if not valid:
            print(message)
            continue
        break

    while True:
        new_password = input("Enter a new password or 'exit' to return: ")
        if new_password.lower() == "exit":
            return
        valid, message = is_password_complex(new_password)
        if not valid:
            print(message)
            continue
        break

    while True:
        new_name = input("Enter the name or 'exit' to return to menu: ")
        if new_name.lower() == "exit":
            return
        if new_name == '':
            continue
        valid, message = is_name_valid(new_name)
        if not valid:
            print(message)
            continue
        break

    while True:
        new_email = input("Enter the email or 'exit' to return to menu: ")
        if new_email.lower() == "exit":
            return
        if new_email == '':
            continue
        valid, message = is_email_valid(new_email)
        if not valid:
            print(message)
            continue
        break
    new_userid = generate_userid('general')

    hashed_password = hash_password(new_password)
    # Store unhashed password
    simulated_unhashed_passwords[new_username] = new_password
    save_unhashed_passwords(simulated_unhashed_passwords)

    starting_points = 0
    initial_tier = calculate_tier(starting_points)

    general_user[new_username] = {
        'userid': new_userid,
        'password': hashed_password,
        'name': new_name,
        'email': new_email,
        'tier': initial_tier,
        'points': starting_points
    }

    save_general_users(general_user)
    logging.info(f"New general user {new_username} created with UserID: {new_userid}.")
    print(f"User '{new_username}' created successfully with UserID: {new_userid}.")

    save_user_data(new_username, is_authorized=False)
    return True

def reload_unhashed_passwords():
    global simulated_unhashed_passwords
    simulated_unhashed_passwords = load_unhashed_passwords()

    # Validate that all users have their unhashed passwords loaded
    for username in authorized_user:
        if username not in simulated_unhashed_passwords:
            logging.warning(f"Unhashed password for authorized user {username} is missing.")
    for username in general_user:
        if username not in simulated_unhashed_passwords:
            logging.warning(f"Unhashed password for non-authorized user {username} is missing.")

def display_authorized_users(current_user):
    if current_user == "admin":
        reload_unhashed_passwords()  # Ensure latest data is loaded
        user_table = [
            [user_data['userid'], username, user_data['name'], user_data['email'], user_data['tier'], user_data['points'], simulated_unhashed_passwords.get(username, 'Unknown'), user_data['password']]
            for username, user_data in authorized_user.items()
        ]
        print("Authorized users and their details:")
        print(tabulate(user_table, headers=["UserID", "Username", "Name", "Email", "Tier", "Points", "Unhashed Password", "Hashed Password"], tablefmt='grid'))
    else:
        print("You do not have the permissions to view authorized users.")
        logging.warning(f"Attempt to view existing authorized users by {current_user}")

def display_general_users(current_user):
    if current_user in authorized_user:
        reload_unhashed_passwords()
        if not general_user:
            print("There are no general users existing now.")
            return False
        else:
            user_table = [
                [user_data['userid'], username, user_data['name'], user_data['email'], user_data['tier'], user_data['points'], simulated_unhashed_passwords.get(username, 'Unknown'), user_data['password']]
                for username, user_data in general_user.items()
            ]
            print("General users and their details:")
            print(tabulate(user_table, headers=["UserID", "Username", "Name", "Email", "Tier", "Points", "Unhashed Password", "Hashed Password"], tablefmt='grid'))
            return True
    else:
        print("You do not have the permissions to view general users.")
        logging.warning(f"Attempt to view existing general users by {current_user}")

def add_general_user(current_user):
    if current_user in authorized_user:
        while True:
            new_username = input("Enter a new username or 'exit' to return to menu: ")
            if new_username.lower() == "exit":
                return
            if not new_username:
                print("Username cannot be empty. Please try again.")
                return
            if new_username in authorized_user or new_username in general_user:
                print("This username already exists in the system. Please choose a different username.")
                logging.warning(f"Account creation failed: Username {new_username} already exists.")
                return

            valid, message = validate_username(new_username)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_password = input("Enter a new password or 'exit' to return to menu: ")
            if new_password.lower() == "exit":
                return
            valid, message = is_password_complex(new_password)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_name = input("Enter the name or 'exit' to return to menu: ")
            if new_name.lower() == "exit":
                return
            if new_name == '':
                continue
            valid, message = is_name_valid(new_name)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_email = input("Enter the email or 'exit' to return to menu: ")
            if new_email.lower() == "exit":
                return
            if new_email == '':
                continue
            valid, message = is_email_valid(new_email)
            if not valid:
                print(message)
                continue
            break

        hashed_password = hash_password(new_password)
        # Store unhashed password
        simulated_unhashed_passwords[new_username] = new_password
        save_unhashed_passwords(simulated_unhashed_passwords)  # Ensure unhashed password is saved

        general_user[new_username] = {
            'userid': generate_userid('general'),
            'password': hashed_password,
            'name': new_name,
            'email': new_email,
            'tier': 'Standard',
            'points': 0
        }
        save_general_users(general_user)
        logging.info(f"New general user {new_username} created.")
        print(f"General user '{new_username}' created successfully.")
        return True
    else:
        print("You do not have the permissions to add general users.")

def update_general_user(current_user):
    if not general_user:
        print("There are no existing general users to be updated.")
        return False
    if current_user in authorized_user:
        old_username = input("Enter the current username of the general user to update or 'exit' to return to menu: ")
        if old_username not in general_user:
            print(f"There is no existing general user named {old_username}. Please try again.")
            return
        if old_username.lower() == 'exit':
            return
        if not old_username:
            print("Username cannot be empty. Please try again.")
            return

        stored_password = general_user[old_username]['password']
        userid = general_user[old_username]['userid']
        attempts = 3
        while attempts > 0:
            entered_password = input(f"Enter the password for {old_username}: ")
            if verify_password(stored_password, entered_password):
                print("Password verified successfully.")
                break
            else:
                attempts -= 1
                print(f"Incorrect password. You have {attempts} {'attempt' if attempts == 1 else 'attempts'} left.")
        if attempts == 0:
            print("Password verification failed. Update aborted.")
            return False

        while True:
            new_username = input(f"Enter the new username or 'exit' to return to menu or press Enter to keep (current: {old_username}): ")
            if new_username != old_username:
                if new_username.lower() == 'exit':
                    return
                if new_username == "":
                    new_username = old_username
                    break
                if new_username in authorized_user or new_username in general_user:
                    print(f"The username '{new_username}' already exists in the system. Please choose a different username.")
                    return

                valid, message = validate_username(new_username)
                if not valid:
                    print(message)
                    continue
                break

        hashed_password = stored_password  # Initialize with stored password
        unhashed_password = simulated_unhashed_passwords.get(old_username, "")  # Get the existing unhashed password

        while True:
            new_password = input("Enter the new password or 'exit' to return to menu or press Enter to keep current password: ")
            if new_password.lower() == 'exit':
                return
            if new_password == "":
                hashed_password = stored_password
                save_unhashed_passwords(simulated_unhashed_passwords)
                break
            valid, message = is_password_complex(new_password)
            if not valid:
                print(message)
            else:
                hashed_password = hash_password(new_password)
                save_unhashed_passwords(simulated_unhashed_passwords)
                break
            save_unhashed_passwords(simulated_unhashed_passwords)

        while True:
            new_name = input(f"Enter the new name or 'exit' to return to menu or press Enter to keep (current: {general_user[old_username]['name']}): ")
            if new_name.lower() == 'exit':
                return
            if new_name == "":
                new_name = general_user[old_username]['name']
            valid, message = is_name_valid(new_name)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_email = input(f"Enter the new email or 'exit' to return to menu or press Enter to keep (current: {general_user[old_username]['email']}): ")
            if new_email.lower() == 'exit':
                return
            if new_email == "":
                new_email = general_user[old_username]['email']
            valid, message = is_email_valid(new_email)
            if not valid:
                print(message)
                continue
            break

        updated_user_details = {
            'userid': userid,
            'password': hashed_password,
            'name': new_name,
            'email': new_email,
            'tier': general_user[old_username].get('tier', 'Standard'),
            'points': general_user[old_username].get('points', 0)
        }

        general_user.pop(old_username)
        general_user[new_username] = updated_user_details

        if old_username in simulated_unhashed_passwords:
            del simulated_unhashed_passwords[old_username]
        simulated_unhashed_passwords[new_username] = unhashed_password  # Save the unhashed password
        save_unhashed_passwords(simulated_unhashed_passwords)

        save_general_users(general_user)
        logging.info(f"General user updated from {old_username} to {new_username} and details updated.")
        print(f"General user updated from '{old_username}' to '{new_username}' and details updated.")
        return True
    else:
        print("You do not have the permissions to update general users.")
        logging.warning(f"Attempt to update existing general user by {current_user}")

def delete_general_user(current_user):
    if current_user in authorized_user:
        if not general_user:
            print("There are no existing general users to be deleted.")
            return False

        username = input("Enter the username of the general user to delete: ")
        if username not in general_user:
            print("This general user does not exist.")
            return False

        user_data = general_user[username]
        stored_password = user_data['password']
        userid = user_data['userid']
        print(f"User ID for {username}: {userid}")

        password = input("Enter the password of the general user to confirm deletion: ")
        if verify_password(stored_password, password):
            # Proceed to delete the user
            del general_user[username]

            # Also delete from simulated_unhashed_passwords if exists
            if username in simulated_unhashed_passwords:
                del simulated_unhashed_passwords[username]
                save_unhashed_passwords(simulated_unhashed_passwords)

            # Save the updated users
            save_general_users(general_user)
            logging.info(f"General user {username} (UserID: {userid}) has been deleted.")
            print(f"General user '{username}' with UserID '{userid}' has been successfully removed.")
        else:
            logging.warning(f"Attempted to delete user {username} with incorrect password.")
            print("Password does not match. Deletion aborted.")

        return True
    else:
        print("You do not have the permissions to delete general users.")
        logging.warning(f"Attempt to delete existing general user by {current_user}")

def add_authorized_user(current_user):
    if current_user == 'admin':
        while True:
            new_username = input("Enter new username or 'exit' to return to menu: ")
            if new_username.lower() == 'exit':
                return
            if not new_username:
                print("Username cannot be empty. Please try again.")
                return
            if new_username in authorized_user or new_username in general_user:
                print("This username already exists in the system. Please choose a different username.")
                logging.warning(f"Account creation failed: Username {new_username} already exists.")
                return

            valid, message = validate_username(new_username)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_password = input("Enter new password or 'exit' to return to menu: ")
            if new_password.lower() == 'exit':
                return
            valid, message = is_password_complex(new_password)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_name = input("Enter the name or 'exit' to return to menu: ")
            if new_name.lower() == 'exit':
                return
            if new_name == '':
                continue
            valid, message = is_name_valid(new_name)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_email = input("Enter the email or 'exit' to return to menu: ")
            if new_email.lower() == 'exit':
                return
            if new_email == '':
                continue
            valid, message = is_email_valid(new_email)
            if not valid:
                print(message)
                continue
            break

        hashed_password = hash_password(new_password)

        simulated_unhashed_passwords[new_username] = new_password
        save_unhashed_passwords(simulated_unhashed_passwords)

        authorized_user[new_username] = {
            'userid': generate_userid('authorized'),
            'password': hashed_password,
            'name': new_name,
            'email': new_email,
            'tier': 'Standard',
            'points': 0
        }
        save_authorized_users(authorized_user)
        logging.info(f"{current_user} successfully added {new_username}.")
        print(f"User '{new_username}' added successfully.")
    else:
        logging.warning(f"Attempt to create new authorized user by {current_user}")
        print("You do not have the permissions to create new authorized users.")

def update_authorized_user(current_user):
    if current_user == 'admin':
        if not authorized_user:    #never will happen
            print("There are no existing authorized users to be updated.")
            return False
        old_username = input("Enter the current username to update or 'exit' to return to menu: ")
        if old_username not in authorized_user:
            print(f"There is no existing authorized user named {old_username}. Please try again.")
            return
        if old_username.lower() == 'admin':
            print("For security purposes, Admin can never be updated.")
            return
        if old_username.lower() == 'exit':
            return
        if not old_username:
            print("Username cannot be empty. Please try again.")
            return

        stored_password = authorized_user[old_username]['password']
        userid = authorized_user[old_username]['userid']
        attempts = 3
        while attempts > 0:
            entered_password = input(f"Enter the password for {old_username}: ")
            if verify_password(stored_password, entered_password):
                print("Password verified successfully.")
                break
            else:
                attempts -= 1
                print(f"Incorrect password. You have {attempts} {'attempt' if attempts == 1 else 'attempts'} left.")
        if attempts == 0:
            print("Password verification failed. Update aborted.")
            return False

        while True:
            new_username = input(f"Enter the new username or 'exit' to return to menu or press Enter to keep (current: {old_username}): ")
            if new_username != old_username:
                if new_username.lower() == 'exit':
                    return
                if new_username == "":
                    new_username = old_username
                    break
                if new_username in authorized_user or new_username in general_user:
                    print(f"The username '{new_username}' already exists in the system. Please choose a different username.")
                    return

                valid, message = validate_username(new_username)
                if not valid:
                    print(message)
                    continue
                break

        hashed_password = stored_password  # Initialize with stored password
        unhashed_password = simulated_unhashed_passwords.get(old_username, "")  # Get the existing unhashed password

        while True:
            new_password = input("Enter the new password or 'exit' to return to menu or press Enter to keep current password: ")
            if new_password.lower() == 'exit':
                return
            if new_password == "":
                hashed_password = stored_password
                save_unhashed_passwords(simulated_unhashed_passwords)
                break
            valid, message = is_password_complex(new_password)
            if not valid:
                print(message)
            else:
                hashed_password = hash_password(new_password)
                save_unhashed_passwords(simulated_unhashed_passwords)
                break
            save_unhashed_passwords(simulated_unhashed_passwords)

        while True:
            new_name = input(f"Enter the new name or 'exit' to return to menu or press Enter to keep (current: {authorized_user[old_username]['name']}): ")
            if new_name.lower() == 'exit':
                return
            if new_name == "":
                new_name = authorized_user[old_username]['name']
            valid, message = is_name_valid(new_name)
            if not valid:
                print(message)
                continue
            break

        while True:
            new_email = input(f"Enter the new email or 'exit' to return to menu or press Enter to keep (current: {authorized_user[old_username]['email']}): ")
            if new_email.lower() == 'exit':
                return
            if new_email == "":
                new_email = authorized_user[old_username]['email']
            valid, message = is_email_valid(new_email)
            if not valid:
                print(message)
                continue
            break

        user_id = authorized_user[old_username]['userid']
        updated_user_details = {
            'userid': user_id,
            'password': hashed_password,
            'name': new_name,
            'email': new_email,
            'tier': authorized_user[old_username].get('tier', 'Standard'),
            'points': authorized_user[old_username].get('points', 0),
        }
        authorized_user.pop(old_username)
        authorized_user[new_username] = updated_user_details

        if old_username in simulated_unhashed_passwords:
            del simulated_unhashed_passwords[old_username]
        simulated_unhashed_passwords[new_username] = unhashed_password
        save_unhashed_passwords(simulated_unhashed_passwords)

        save_authorized_users(authorized_user)
        logging.info(f"Authorized user updated from {old_username} to {new_username} and details updated.")
        print(f"Authorized user updated from '{old_username}' to '{new_username}' and details updated.")
        return True
    else:
        print("You do not have the permissions to update authorized users.")
        logging.warning(f"Attempt to update authorized user by {current_user}")

def delete_authorized_user(current_user):
    if current_user == 'admin':
        if not authorized_user:  #never will happen
            print("There are no existing authorized users to be deleted.")
            return False
        while True:
            username = input("Enter the username to delete or 'exit' to return to menu: ").strip()
            if username.lower() == 'exit':
                return
            if not username:
                print("Username cannot be empty. Please try again.")
                continue
            if username == "admin":
                print("You cannot delete yourself.")
                continue
            if username not in authorized_user:
                print("This authorized user does not exist. Please try again.")
                continue

            user_data = authorized_user[username]
            stored_password = user_data['password']
            userid = user_data['userid']
            print(f"User ID for {username}: {userid}")

            password = input("Enter the password of the authorized user to confirm deletion: ").strip()
            if verify_password(stored_password, password):
                del authorized_user[username]

                if username in simulated_unhashed_passwords:
                    del simulated_unhashed_passwords[username]
                    save_unhashed_passwords(simulated_unhashed_passwords)

                save_authorized_users(authorized_user)
                logging.info(f"{current_user} deleted authorized user {username} with UserID: {userid}.")
                print(f"Authorized user '{username}' with UserID '{userid}' has been successfully removed.")
                break
            else:
                logging.warning(f"Attempted to delete authorized user {username} with incorrect password.")
                print("Password does not match. Deletion aborted.")
    else:
        print("You do not have the permissions to delete authorized users.")
        logging.warning(f"Attempt to delete existing authorized user by {current_user}")

# Declare a global variable to store sample books
sample_books = []

def populate_data(): #just included this function to save your time from adding books one by one
    global books
    existing_books = load_books()
    existing_isbns = {book.isbn_num for book in existing_books}

    sample_books = [
        Book("Bridgerton", "0000000000001", "Avon", "Julia Quinn", "English", "Romance", 2000, 5, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Queen's Gambit", "0000000000002", "Random House", "Walter Tevis", "English", "Drama", 1983, 3, True,
             random.choice(list(authorized_user.keys()))),
        Book("You", "0000000000003", "Atria/Emily Bestler Books", "Caroline Kepnes", "English", "Thriller", 2014, 1,
             True, random.choice(list(authorized_user.keys()))),
        Book("The Haunting of Hill House", "0000000000004", "Penguin Classics", "Shirley Jackson", "English", "Horror",
             1959, 6, True, random.choice(list(authorized_user.keys()))),
        Book("The Witcher: The Last Wish", "0000000000005", "Gollancz", "Andrzej Sapkowski", "Polish", "Fantasy", 1993,
             2, True, random.choice(list(authorized_user.keys()))),
        Book("One Hundred Years of Solitude", "0000000000006", "Harper & Row", "Gabriel Garcia Marquez", "Spanish",
             "Magic Realism", 1967, 4, True, random.choice(list(authorized_user.keys()))),
        Book("The Little Prince", "0000000000007", "Reynal & Hitchcock", "Antoine de Saint-Exupéry", "French", "Fable",
             1943, 5, True, random.choice(list(authorized_user.keys()))),
        Book("Crime and Punishment", "0000000000008", "The Russian Messenger", "Fyodor Dostoevsky", "Russian",
             "Philosophical Fiction", 1866, 6, True, random.choice(list(authorized_user.keys()))),
        Book("The Alchemist", "0000000000009", "HarperOne", "Paulo Coelho", "Portuguese", "Adventure", 1988, 3, True,
             random.choice(list(authorized_user.keys()))),
        Book("Norwegian Wood", "0000000000010", "Kodansha", "Haruki Murakami", "Japanese", "Romance", 1987, 5, True,
             random.choice(list(authorized_user.keys()))),
        Book("Shadow and Bone", "0000000000011", "Henry Holt and Co.", "Leigh Bardugo", "English", "Fantasy", 2012, 4,
             True, random.choice(list(authorized_user.keys()))),
        Book("Mindhunter: Inside the FBI's Elite Serial Crime Unit", "0000000000012", "Simon & Schuster",
             "John E. Douglas", "English", "True Crime", 1995, 5, True, random.choice(list(authorized_user.keys()))),
        Book("13 Reasons Why", "0000000000013", "Razorbill", "Jay Asher", "English", "Drama", 2007, 6, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Umbrella Academy: Apocalypse Suite", "0000000000014", "Dark Horse Books", "Gerard Way", "English",
             "Sci-Fi", 2007, 3, True, random.choice(list(authorized_user.keys()))),
        Book("Locke & Key: Welcome to Lovecraft", "0000000000015", "IDW Publishing", "Joe Hill", "English", "Horror",
             2008, 5, True, random.choice(list(authorized_user.keys()))),
        Book("Stranger Things: Suspicious Minds", "0000000000016", "Del Rey", "Gwenda Bond", "English", "Sci-Fi", 2019,
             4, True, random.choice(list(authorized_user.keys()))),
        Book("Altered Carbon", "0000000000017", "Del Rey", "Richard K. Morgan", "English", "Sci-Fi", 2002, 6, True,
             random.choice(list(authorized_user.keys()))),
        Book("Bird Box", "0000000000018", "Ecco Press", "Josh Malerman", "English", "Horror", 2014, 3, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Old Guard", "0000000000019", "Image Comics", "Greg Rucka", "English", "Action", 2017, 5, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Silence", "0000000000020", "Pan Macmillan", "Tim Lebbon", "English", "Horror", 2015, 3, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Perfectionists", "0000000000021", "HarperTeen", "Sara Shepard", "English", "Thriller", 2014, 6, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Irregulars: The Case of the Missing Moonstone", "0000000000022", "Knopf Books for Young Readers",
             "Jordan Stratford", "English", "Mystery", 2015, 5, True, random.choice(list(authorized_user.keys()))),
        Book("Dracula", "0000000000023", "Archibald Constable and Company", "Bram Stoker", "English", "Horror", 1897, 4,
             True, random.choice(list(authorized_user.keys()))),
        Book("The Stranger", "0000000000024", "Dutton", "Harlan Coben", "English", "Thriller", 2015, 6, True,
             random.choice(list(authorized_user.keys()))),
        Book("American Gods", "0000000000025", "William Morrow", "Neil Gaiman", "English", "Fantasy", 2001, 3, True,
             random.choice(list(authorized_user.keys()))),
        Book("Anne with an E", "0000000000026", "L.C. Page & Co.", "Lucy Maud Montgomery", "English", "Drama", 1908, 5,
             True, random.choice(list(authorized_user.keys()))),
        Book("Behind Her Eyes", "0000000000027", "HarperCollins", "Sarah Pinborough", "English", "Thriller", 2017, 4,
             True, random.choice(list(authorized_user.keys()))),
        Book("Orange is the New Black", "0000000000028", "Spiegel & Grau", "Piper Kerman", "English", "Memoir", 2010, 3,
             True, random.choice(list(authorized_user.keys()))),
        Book("The OA", "0000000000029", "Farrar, Straus and Giroux", "Brit Marling", "English", "Mystery", 2016, 6,
             True, random.choice(list(authorized_user.keys()))),
        Book("The Punisher: Welcome Back, Frank", "0000000000030", "Marvel Comics", "Garth Ennis", "English", "Action",
             2000, 5, True, random.choice(list(authorized_user.keys()))),
        Book("The Serpent", "0000000000031", "Penguin Books", "Vincent Bugliosi", "English", "True Crime", 1974, 4,
             True, random.choice(list(authorized_user.keys()))),
        Book("The Sinner", "0000000000032", "Penguin Books", "Petra Hammesfahr", "English", "Thriller", 1999, 3, True,
             random.choice(list(authorized_user.keys()))),
        Book("To All the Boys I've Loved Before", "0000000000033", "Simon & Schuster", "Jenny Han", "English",
             "Romance", 2014, 5, True, random.choice(list(authorized_user.keys()))),
        Book("The Kissing Booth", "0000000000034", "Penguin Books", "Beth Reekles", "English", "Romance", 2012, 6, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Baby-Sitters Club", "0000000000035", "Scholastic", "Ann M. Martin", "English", "Children's", 1986, 4,
             True, random.choice(list(authorized_user.keys()))),
        Book("Cursed", "0000000000036", "Simon & Schuster", "Thomas Wheeler", "English", "Fantasy", 2019, 3, True,
             random.choice(list(authorized_user.keys()))),
        Book("I Am Not Okay With This", "0000000000037", "Fantagraphics Books", "Charles Forsman", "English", "Drama",
             2017, 5, True, random.choice(list(authorized_user.keys()))),
        Book("Sweet Magnolias", "0000000000038", "Mira Books", "Sherryl Woods", "English", "Romance", 2007, 4, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Midnight Club", "0000000000039", "Simon Pulse", "Christopher Pike", "English", "Horror", 1994, 3,
             True, random.choice(list(authorized_user.keys()))),
        Book("Lockwood & Co.: The Screaming Staircase", "0000000000040", "Disney-Hyperion", "Jonathan Stroud",
             "English", "Horror", 2013, 5, True, random.choice(list(authorized_user.keys()))),
        Book("Unbelievable: My Front-Row Seat to the Craziest Campaign in American History", "0000000000041",
             "Dey Street Books", "Katy Tur", "English", "Memoir", 2017, 4, True,
             random.choice(list(authorized_user.keys()))),
        Book("Chilling Adventures of Sabrina: Season of the Witch", "0000000000042", "Scholastic", "Sarah Rees Brennan",
             "English", "Horror", 2019, 6, True, random.choice(list(authorized_user.keys()))),
        Book("The Kominsky Method", "0000000000043", "Henry Holt and Co.", "Chuck Lorre", "English", "Comedy", 2018, 5,
             True, random.choice(list(authorized_user.keys()))),
        Book("Warrior Nun Areala: Rituals", "0000000000044", "Antarctic Press", "Ben Dunn", "English", "Fantasy", 1994,
             3, True, random.choice(list(authorized_user.keys()))),
        Book("Death Note", "0000000000045", "Viz Media", "Tsugumi Ohba", "Japanese", "Mystery", 2003, 5, True,
             random.choice(list(authorized_user.keys()))),
        Book("Never Have I Ever", "0000000000046", "Simon & Schuster", "Mindy Kaling", "English", "Comedy", 2015, 4,
             True, random.choice(list(authorized_user.keys()))),
        Book("Sweet Tooth", "0000000000047", "Vertigo", "Jeff Lemire", "English", "Fantasy", 2009, 5, True,
             random.choice(list(authorized_user.keys()))),
        Book("The Sandman", "0000000000048", "DC Comics", "Neil Gaiman", "English", "Fantasy", 1989, 6, True,
             random.choice(list(authorized_user.keys()))),
        Book("Locke & Key", "0000000000049", "IDW Publishing", "Joe Hill", "English", "Horror", 2008, 5, True,
             random.choice(list(authorized_user.keys()))),
        Book("Alice in Borderland", "0000000000050", "Shogakukan", "Haro Aso", "Japanese", "Thriller", 2010, 6, True,
             random.choice(list(authorized_user.keys())))
    ]

    # Add new sample books if they do not exist
    new_books = [book for book in sample_books if book.isbn_num not in existing_isbns]
    if new_books:
        books.extend(new_books)
        save_books(books)
        logging.info(f"Added {len(new_books)} new books to the database.")
        print(f"Added {len(new_books)} new books to the database.")
    else:
        logging.info("No new books were added, all sample books are already populated.")
        print("No new books were added, all sample books are already populated.")

def unpopulate_data():
    global books
    books.clear()
    save_books(books)
    logging.info("All book data has been removed successfully.")
    print("All book data has been removed successfully.")

MAX_LOGIN_ATTEMPTS = 3
ADMIN_CODE = "221025"  # for demo purposes only, in a real system, I will use dynamic codes.
#OVER HERE   ^^^^^^^^

def authenticate_user():
    print("=== Welcome to Smart Lib ===")
    while True:
        check = input("Do you have an account with us? (y/n): ").lower()
        if check == "y":
            while True:
                username = input("Enter your username or 'exit' to quit: ")
                if username.lower() == 'exit':
                    logging.info("User exited login process.")
                    print("\n\n**Sponsored**\nCheck out our latest collection of books and enjoy great discounts!")
                    break  # Break the inner loop and return to account prompt
                user_dict = None
                if username in authorized_user:
                    user_dict = authorized_user
                elif username in general_user:
                    user_dict = general_user

                if user_dict:
                    stored_user_info = user_dict[username]
                    stored_password = stored_user_info['password']  # Extract the password from the dictionary

                    attempts = 0
                    while attempts < MAX_LOGIN_ATTEMPTS:
                        password = input("Enter your password: ")
                        if verify_password(stored_password, password):
                            if username == 'admin':  # Additional check for admin
                                mfa_attempts = 0
                                while mfa_attempts < MAX_LOGIN_ATTEMPTS:
                                    mfa_code = input("Enter the admin code sent to your email (Hint: Refer to the codes slightly above authenticate_user function):  ")
                                    if mfa_code == ADMIN_CODE:
                                        logging.info(f"{username} (Admin) logged in successfully.")
                                        print(f"Successfully logged in as {username} (Admin)")
                                        break
                                    else:
                                        mfa_attempts += 1
                                        print(f"Incorrect admin code. You have {MAX_LOGIN_ATTEMPTS - mfa_attempts} {'attempt' if MAX_LOGIN_ATTEMPTS - mfa_attempts == 1 else 'attempts'} left.")
                                if mfa_attempts == MAX_LOGIN_ATTEMPTS:
                                    logging.warning(f"Admin {username} exceeded maximum MFA attempts.")
                                    print("You have exceeded the maximum number of attempts for admin code. Please try again later or contact support.\n")
                                    return None
                            else:
                                logging.info(f"{username} logged in successfully.")
                                print(f"Successfully logged in as {username}\n")

                            # Display notifications for the user
                            if username in user_notifications:
                                print("=== Notifications ===")
                                for notification in user_notifications[username]:
                                    print(notification)
                                user_notifications[username] = []  # Clear notifications after displaying

                            return username  # Return the username as the current user
                        else:
                            attempts += 1
                            print(f"Incorrect password. You have {MAX_LOGIN_ATTEMPTS - attempts} {'attempt' if MAX_LOGIN_ATTEMPTS - attempts == 1 else 'attempts'} left.")

                    logging.warning(f"User {username} exceeded maximum login attempts.")
                    if attempts == MAX_LOGIN_ATTEMPTS:
                        print("You have exceeded the maximum number of attempts. Please try again.\n")
                        print("\n\n**Sponsored**\nCheck out our latest collection of books and enjoy great discounts!")
                else:
                    print("This user does not exist.")
        elif check == "n":
            create_new_account = input("Would you like to create a new account? (y/n): ").strip().lower()
            if create_new_account == 'y':
                if create_account():
                    print("Account created successfully. Please log in again.")
                    print("\n\n**Sponsored**\nCheck out our latest collection of books and enjoy great discounts!")
                else:
                    print("Account creation failed. Please try again.")
            else:
                print("Account creation cancelled. Please try logging in again.")
                print("\n\n**Sponsored**\nCheck out our latest collection of books and enjoy great discounts!")
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

def validate_current_user():
    current_user = authenticate_user()
    if not current_user:
        print("Exiting program...")
        return

def get_user_role(username):
    if username == 'admin':
        return 'admin'
    elif username in authorized_user:
        return 'authorized'
    elif username in general_user:
        return 'general'
    else:
        return 'unknown'

def generate_menu(options, current_user):
    """Generate a dynamic menu based on available options and return the user choice."""
    for index, option in enumerate(options, start=1):
        print(f"{index}. {option['text']}")

    while True:
        try:
            choice = int(input("Enter your choice: "))
            if 1 <= choice <= len(options):
                action = options[choice - 1]['action']
                if callable(action):
                    import inspect
                    if len(inspect.signature(action).parameters) == 0:
                        return action, None
                    else:
                        return action, current_user
                else:
                    return action, None
            else:
                print(f"Please choose a number between 1 and {len(options)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def main_menu(current_user):
    navigate_to(_main_menu, current_user)

def _main_menu(current_user):
    user_role = get_user_role(current_user)

    while True:
        if user_role == 'admin':
            role_display = ' (Admin)'
        elif user_role == 'authorized':
            role_display = ' (Authorized)'
        else:
            role_display = ''

        print(f"\n==== Smart Lib - Book Management System - {current_user}'s Account{role_display} ====")
        print(f"Currently logged in as {current_user}")

        menu_options = [
            {"text": "Book Management Menu", "action": book_management_menu},
            {"text": "Borrowing Management Menu", "action": borrowing_management_menu},
            {"text": "User Management Menu", "action": user_management_menu if user_role != 'general' else None},
            {"text": "Populate Books Menu", "action": populate_book_menu if user_role != 'general' else None},
            {"text": "Manage Customer Request", "action": customer_request_menu if user_role != 'general' else None},
            {"text": "Input My Customer Request", "action": input_customer_request if user_role == 'general' else None},
            {"text": "Personalized Recommendations", "action": recommend_books_for_user},
            {"text": "Display My Tier and Points", "action": display_tier_and_points},
            {"text": "Log Out", "action": "logout"},
            {"text": "Exit", "action": "exit"}
        ]

        available_options = [option for option in menu_options if option['action'] is not None]
        choice_action, user = generate_menu(available_options, current_user)

        if choice_action == "logout":
            logging.info(f"{current_user} logged out.")
            print("Logging out...\n")
            current_user = authenticate_user()
            if current_user:
                main_menu(current_user)
            else:
                print("Exiting program...")
                break
        elif choice_action == "exit":
            logging.info(f"Program exited by {current_user}.")
            print("Exiting program...")
            break
        else:
            choice_action(current_user)

def book_management_menu(current_user):
    user_role = get_user_role(current_user)

    while True:
        if user_role == 'admin':
            role_display = ' (Admin)'
        elif user_role == 'authorized':
            role_display = ' (Authorized)'
        else:  # general or unknown roles
            role_display = ''

        print(f"\n==== Smart Lib - Book Management Menu - {current_user}'s Account{role_display} ====")
        print(f"Currently logged in as {current_user}")
        menu_options = [
            {"text": "Display All Books", "action": display_books},
            {"text": "Display Book Categories", "action": display_book_categories},
            {"text": "Add New Book", "action": add_book_menu if user_role != 'general' else None},
            {"text": "Update Book", "action": update_book if user_role != 'general' else None},
            {"text": "Delete Book", "action": delete_book if user_role != 'general' else None},
            {"text": "Sort Books", "action": sort_books_menu},
            {"text": "Search for Books", "action": lambda user: search_books()},
            {"text": "Advanced Search and Filtering", "action": lambda user: advanced_search_books()},
            {"text": "Back to Main Menu", "action": lambda user: navigate_to(main_menu, user)},  # Navigate to main menu
            {"text": "Log Out", "action": "logout"},
            {"text": "Exit", "action": "exit"}
        ]

        available_options = [option for option in menu_options if option['action'] is not None]
        choice_action, user = generate_menu(available_options, current_user)

        if choice_action == "logout":
            current_user = authenticate_user()
            if current_user:
                navigate_to(main_menu, current_user)
            else:
                break
        elif choice_action == "exit":
            break
        else:
            choice_action(current_user)

def display_book_categories(current_user):
    print("=== Book Categories ===")
    category_tree.display_tree()
    go_back_to_book_management_menu(current_user)

def go_back_to_book_management_menu(current_user):
    if navigation_stack:
        navigation_stack.pop()  # Pop the current menu
        if navigation_stack:
            last_menu_function, args = navigation_stack[-1]  # Peek at the last menu in the stack
            last_menu_function(*args)  # Navigate to the last menu
        else:
            print("No previous menu to navigate to.")
            main_menu(current_user)  # Return to the main menu if the stack is empty
    else:
        print("Navigation stack is empty.")
        main_menu(current_user)  # Return to the main menu if the stack is empty

category_tree = CategoryTree()

def add_book_menu(current_user):
    """Function to handle the addition of a new book to the library."""
    # Gather book details from the user
    title = input("Enter title or 'exit' to return to menu: ")
    while not title:
        print("Title cannot be empty.")
        title = input("Enter title or 'exit' to return to menu: ")
    if title == "exit":
        return

    isbn_num = input("Enter ISBN number or 'exit' to return to menu: ")
    valid, message = validate_isbn(isbn_num)
    while not valid:
        print(message)
        isbn_num = input("Enter ISBN number or 'exit' to return to menu: ")
        valid, message = validate_isbn(isbn_num)
    if isbn_num == "exit":
        return

    publisher = input("Enter publisher or 'exit' to return to menu: ")
    while not publisher:
        print("Publisher cannot be empty.")
        publisher = input("Enter publisher or 'exit' to return to menu: ")
    if publisher == "exit":
        return

    author = input("Enter author or 'exit' to return to menu: ")
    while not author:
        print("Author cannot be empty.")
        author = input("Enter author or 'exit' to return to menu: ")
    if author == "exit":
        return

    language = input("Enter language or 'exit' to return to menu: ")
    while not language:
        print("Language cannot be empty.")
        language = input("Enter language or 'exit' to return to menu: ")
    if language == "exit":
        return

    genre = input("Enter genre or 'exit' to return to menu: ")
    while not genre:
        print("Genre cannot be empty.")
        genre = input("Enter genre or 'exit' to return to menu: ")
    if genre == "exit":
        return

    year_published = input("Enter year published or 'exit' to return to menu: ")
    valid, message = validate_year(year_published)
    while not valid:
        print(message)
        year_published = input("Enter year published or 'exit' to return to menu: ")
        valid, message = validate_year(year_published)
    if year_published == "exit":
        return

    number_of_copies = input("Enter number of copies or 'exit' to return to menu: ")
    valid, message = validate_number_of_copies(str(number_of_copies))
    while not valid:
        print(message)
        number_of_copies = input("Enter number of copies or 'exit' to return to menu: ")
        valid, message = validate_number_of_copies(number_of_copies)
    if number_of_copies == "exit":
        return

    if int(number_of_copies) > 0:
        availability = True
    else:
        availability = False

    addedbywho = current_user
    success = add_book(title, isbn_num, publisher,
                       author, language, genre,
                       year_published, number_of_copies,
                       availability, addedbywho)
    if success:
        print("Book added successfully!")
    else:
        print("Failed to add the book.")

def sort_books_menu(current_user):
    """Function to display and handle the sort books menu."""
    user_role = get_user_role(current_user)

    while True:
        if user_role == 'admin':
            role_display = ' (Admin)'
        elif user_role == 'authorized':
            role_display = ' (Authorized)'
        else:
            role_display = ''

        if not books:
            print("There are currently no books to be displayed.")
            break

        print(f"\n==== Smart Lib - Sort Books Menu - {current_user}'s Account{role_display} ====")
        print(f"Currently logged in as {current_user}")
        print("1. Sort books by Publisher in Ascending order using Bubble Sort and Display")
        print("2. Sort books by Publisher in Descending order using Bubble Sort and Display")
        print("3. Sort books by Number of Copies in Ascending order using Insertion Sort and Display")
        print("4. Sort books by Number of Copies in Descending order using Insertion Sort and Display")
        print("5. Sort books by Title in Ascending order using Quick Sort and Display")
        print("6. Sort books by Title in Descending order using Quick Sort and Display")
        print("7. Sort books by Language in Ascending order and then ISBN Num in Ascending order using Merge Sort and Display")
        print("8. Sort books by Language in Ascending order and then ISBN Num in Descending order using Merge Sort and Display")
        print("9. Sort books by Language in Descending order and then ISBN Num in Ascending order using Merge Sort and Display")
        print("10. Sort books by Language in Descending order and then ISBN Num in Descending order using Merge Sort and Display")
        print("11. Back to Book Management Menu")
        print("12. Log Out")
        print("13. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            bubble_sort_by_publisher_in_ascending()
        elif choice == '2':
            bubble_sort_by_publisher_in_descending()
        elif choice == '3':
            insertion_sort_by_copies_in_ascending()
        elif choice == '4':
            insertion_sort_by_copies_in_descending()
        elif choice == '5':
            quick_sort_by_title_ascending()
        elif choice == '6':
            quick_sort_by_title_descending()
        elif choice == '7':
            merge_sort_by_language_asc_isbn_asc()
        elif choice == '8':
            merge_sort_by_language_asc_isbn_desc()
        elif choice == '9':
            merge_sort_by_language_desc_isbn_asc()
        elif choice == '10':
            merge_sort_by_language_desc_isbn_desc()
        elif choice == '11':
            go_back(current_user)
            break
        elif choice == '12':
            logging.info(f"{current_user} logged out.")
            print("Logging out...\n")
            current_user = authenticate_user()
            if current_user:
                navigate_to(main_menu, current_user)
            else:
                print("Exiting program...")
                break
        elif choice == '13':
            logging.info(f"Program exited by {current_user}.")
            print("Exiting program...")
            exit()
        else:
            print("Invalid choice. Please choose again.")

def borrowing_management_menu(current_user):
    user_role = get_user_role(current_user)

    while True:
        if user_role == 'admin':
            role_display = ' (Admin)'
        elif user_role == 'authorized':
            role_display = ' (Authorized)'
        else:  # general or unknown roles
            role_display = ''

        print(f"\n==== Smart Lib - Borrowing Management Menu - {current_user}'s Account{role_display} ====")
        print(f"Currently logged in as {current_user}")
        print("1. Display All Borrowed Books")
        print("2. Display Available Books")
        print("3. Display Unavailable Books")
        print("4. Check Your Borrowed Books")
        print("5. Check Your Borrowing History")
        print("6. Borrow a Book")
        print("7. Return a Book")
        print("8. Reserve a Book")
        print("9. Back to Main Menu")
        print("10. Log Out")
        print("11. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            if not borrowed_books:
                print("No books have been borrowed.")
            else:
                display_borrowed_books(current_user)
        elif choice == '2':
            display_available_books()
        elif choice == '3':
            display_unavailable_books()
        elif choice == '4':
            check_borrowed_books_by_current_user(current_user)
        elif choice  == '5':
            get_borrowing_history(current_user)
        elif choice == '6':
            borrow_book(current_user)
        elif choice == '7':
            return_book(current_user)
        elif choice == '8':
            reserve_book(current_user)
        elif choice == '9':
            go_back(current_user)
            break
        elif choice == '10':
            logging.info(f"{current_user} logged out.")
            print("Logging out...\n")
            current_user = authenticate_user()
            if current_user:
                navigate_to(main_menu, current_user)
            else:
                print("Exiting program...")
                break
        elif choice == '11':
            logging.info(f"Program exited by {current_user}.")
            print("Exiting program...")
            exit()
        else:
            print("Invalid choice. Please choose again.")

def user_management_menu(current_user):
    user_role = get_user_role(current_user)

    while True:
        if user_role == 'admin':
            role_display = ' (Admin)'
        elif user_role == 'authorized':
            role_display = ' (Authorized)'
        else:  # general or unknown roles
            role_display = ''

        print(f"\n==== Smart Lib - User Management Menu - {current_user}'s Account{role_display} ====")
        print(f"Currently logged in as {current_user}")

        menu_options = [
            {"text": "Display General Users", "action": display_general_users if user_role != 'general' else None},
            {"text": "Display Authorized Users", "action": display_authorized_users if user_role == 'admin' else None},
            {"text": "Add New General User", "action": add_general_user if user_role != 'general' else None},
            {"text": "Update General User", "action": update_general_user if user_role != 'general' else None},
            {"text": "Delete General User", "action": delete_general_user if user_role != 'general' else None},
            {"text": "Add New Authorized User", "action": add_authorized_user if user_role == 'admin' else None},
            {"text": "Update Authorized User", "action": update_authorized_user if user_role == 'admin' else None},
            {"text": "Delete Authorized User", "action": delete_authorized_user if user_role == 'admin' else None},
            {"text": "Back to Main Menu", "action": go_back},
            {"text": "Log Out", "action": "logout"},
            {"text": "Exit", "action": "exit"}
        ]

        available_options = [option for option in menu_options if option['action'] is not None]
        choice_action, user = generate_menu(available_options, current_user)

        if choice_action == "logout":
            logging.info(f"{current_user} logged out.")
            print("Logging out...\n")
            current_user = authenticate_user()
            if current_user:
                navigate_to(main_menu, current_user)
            else:
                print("Exiting program...")
                break
        elif choice_action == "exit":
            logging.info(f"Program exited by {current_user}.")
            print("Exiting program...")
            exit()
        else:
            choice_action(current_user)

def customer_request_menu(current_user):
    user_role = get_user_role(current_user)

    while True:
        if user_role == 'admin':
            role_display = ' (Admin)'
        elif user_role == 'authorized':
            role_display = ' (Authorized)'
        else:  # general or unknown roles
            role_display = ''

        print(f"\n==== Smart Lib - Customer Request Menu - {current_user}'s Account{role_display} ====")
        print(f"Currently logged in as {current_user}")

        if user_role == 'general':
            menu_options = [
                {"text": "Input My Request", "action": lambda user: input_customer_request(user)},
                {"text": "View Number of Requests", "action": lambda _: view_number_of_requests()},
                {"text": "Back to Main Menu", "action": go_back},
                {"text": "Log Out", "action": "logout"},
                {"text": "Exit", "action": "exit"}
            ]
        else:
            menu_options = [
                {"text": "Input A Customer Request", "action": lambda user: input_customer_request(user)},
                {"text": "View Number of Requests", "action": lambda _: view_number_of_requests()},
                {"text": "Service Next Request in Queue", "action": lambda _: service_next_request()},
                {"text": "Back to Main Menu", "action": go_back},
                {"text": "Log Out", "action": "logout"},
                {"text": "Exit", "action": "exit"}
            ]

        choice_action, user = generate_menu(menu_options, current_user)

        if choice_action == "logout":
            logging.info(f"{current_user} logged out.")
            print("Logging out...\n")
            current_user = authenticate_user()
            if current_user:
                navigate_to(main_menu, current_user)
            else:
                print("Exiting program...")
                break
        elif choice_action == "exit":
            logging.info(f"Program exited by {current_user}.")
            print("Exiting program...")
            exit()
        else:
            choice_action(current_user)

def input_customer_request(current_user):
    user_role = get_user_role(current_user)

    if user_role == 'general':
        # General user inputting their own request
        user_id = general_user[current_user]['userid']
        print(f"Your Customer ID: {user_id}")
    else:
        # Admin or authorized user inputting a request for a customer
        while True:
            user_id = input("Enter Customer ID or 'exit' to return to the menu: ")
            if user_id.lower() == 'exit':
                return

            if not user_id.isalnum():
                print("Invalid Customer ID. Please try again!")
                continue

            user_found = False
            for user_data in general_user.values():
                if user_data['userid'] == user_id:
                    user_found = True
                    break

            if not user_found:
                print("Invalid Customer ID. Please try again!")
                continue
            break
    while True:
        customer_request = input("Enter Customer's request: ")
        valid, message = is_request_valid(customer_request)
        if not valid:
            print(message)
            continue
        break
    new_request = CustomerRequest(user_id, customer_request)
    customer_requests_queue.append(new_request)
    save_customer_requests(customer_requests_queue)  # save requests after adding, prevent from losing them after rerun program
    print("Customer's request added successfully!")

def view_number_of_requests():
    print(f"\nNumber of request: {len(customer_requests_queue)}")

def service_next_request():
    if not customer_requests_queue:
        print("No customer requests to service.")
        return

    next_request = customer_requests_queue.pop(0)
    print("Customer Request Details:")
    print("-" * 40)
    print(next_request)
    print("-" * 40)
    print(f"Remaining requests: {len(customer_requests_queue)}")
    save_customer_requests(customer_requests_queue)

def populate_book_menu(current_user):
    user_role = get_user_role(current_user)

    while True:
        if user_role == 'admin':
            role_display = ' (Admin)'
        elif user_role == 'authorized':
            role_display = ' (Authorized)'
        else:  # general or unknown roles
            role_display = ''

        print(f"\n==== Smart Lib - Populate Books Management Menu - {current_user}'s Account{role_display} ====")
        print(f"Currently logged in as {current_user}")
        print("1. Populate Books")
        print("2. Unpopulate Books")
        print("3. Back to Main Menu")
        print("4. Log Out")
        print("5. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            if current_user in authorized_user:
                sample_books_isbns = {"000000000001", "000000000002", "000000000003", "000000000004", "000000000005",
                                      "000000000006", "000000000007", "000000000008", "000000000009", "000000000010"}
                existing_books_isbns = {book.isbn_num for book in books}
                if sample_books_isbns.issubset(existing_books_isbns):
                    print("The sample books have already been populated.")
                else:
                    confirm = input("Are you sure you want to populate all book data? (y/n): ").lower()
                    if confirm == 'y':
                        if not sample_books:
                            attempts = 3
                            while attempts > 0:
                                password = input("Enter your password: ")
                                if verify_password(authorized_user.get(current_user, {}).get('password', ''), password) \
                                        or verify_password(general_user.get(current_user, {}).get('password', ''), password):
                                    populate_data()
                                    break
                                attempts -= 1
                                print(f"Incorrect password. You have {attempts} attempts left.")
                            if attempts == 0:
                                print("Authentication failed. Populate action cancelled.")
                        else:
                            print("Books from the original sample 50 books are already populated")
                    else:
                        print("Populate action cancelled.")
            else:
                print("You do not have the permissions to populate book data.")
        elif choice == '2':
            if current_user in authorized_user:
                if not books:
                    print("There are no books existing to unpopulate.")
                else:
                    print("Disclaimer: By unpopulating the data, you are removing ALL the books in this book management system.")
                    confirm = input(
                        "Are you sure you want to remove all book data? This action cannot be undone. (y/n): ").lower()
                    if confirm == 'y':
                        attempts = 3
                        while attempts > 0:
                            password = input("Enter your password: ")
                            if verify_password(authorized_user.get(current_user, {}).get('password', ''), password) \
                                    or verify_password(general_user.get(current_user, {}).get('password', ''), password):
                                unpopulate_data()
                                break
                            attempts -= 1
                            print(f"Incorrect password. You have {attempts} attempts left.")
                        if attempts == 0:
                            print("Authentication failed. Unpopulate action cancelled.")
                    else:
                        print("Unpopulate action cancelled.")
            else:
                print("You do not have the permissions to unpopulate book data.")
        elif choice == '3':
            go_back(current_user)
        elif choice == '4':
            logging.info(f"{current_user} logged out.")
            print("Logging out...\n")
            current_user = authenticate_user()
            if current_user:
                navigate_to(main_menu, current_user)  # Return to main menu after successful re-login
            else:
                print("Exiting program...")
                break
        elif choice == '5':
            logging.info(f"Program exited by {current_user}.")
            print("Exiting program...")
            exit()
        else:
            print("Invalid choice. Please choose again.")

def display_tier_and_points(current_user):
    #Display the tier and points of the current user.
    user_info = authorized_user.get(current_user, general_user.get(current_user))
    if user_info:
        tier = user_info.get('tier', 'Standard')
        points = user_info.get('points', 0)
        print(f"\n=== {current_user}'s Tier and Points ===")
        print(f"Tier: {tier}")
        print(f"Points: {points}")
    else:
        print("Unable to retrieve user information.")

navigation_stack = []

def navigate_to(menu_function, current_user):
    navigation_stack.append((menu_function, (current_user,)))
    menu_function(current_user)

def go_back(current_user):
    if navigation_stack:
        navigation_stack.pop()
        if navigation_stack:
            menu_function, args = navigation_stack[-1]
            menu_function(current_user)
        else:
            print("No previous menu to navigate to.")
            main_menu(current_user)
    else:
        print("Navigation stack is empty.")
        main_menu(current_user)

if __name__ == "__main__":
    current_user = authenticate_user()
    if current_user:
        books = load_books()
        book_reviews = load_reviews()
        customer_requests_queue = load_customer_requests()
        authorized_user = get_authorized_users()
        general_user = get_general_users()
        user_notifications = load_notifications()

        for user in authorized_user.values():
            if 'borrowed_books_stack' not in user:
                user['borrowed_books_stack'] = Stack()
        for user in general_user.values():
            if 'borrowed_books_stack' not in user:
                user['borrowed_books_stack'] = Stack()

        if not books:
            populate_data()

        save_books(books)
        save_reviews(book_reviews)
        save_customer_requests(customer_requests_queue)
        save_authorized_users(authorized_user)
        save_general_users(general_user)
        save_notifications(user_notifications)

        category_tree = build_dynamic_category_tree(books)

        navigate_to(main_menu, current_user)

    else:
        print("\nExiting program...")