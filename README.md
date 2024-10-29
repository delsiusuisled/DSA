# DSA
DSA Book Management System Codes
Data Structures & Algorithms - Assignment
SmartLib: Book Management System

SmartLib is an advanced Book Management System developed in Python using PyCharm, aimed at efficiently handling library operations while integrating data structures and algorithms. The system is designed with separate access levels for General Users, Authorized Users, and Administrators, each having a unique set of privileges. The project emphasizes secure user management, robust book sorting and searching mechanisms, efficient request handling, and personalized user experiences.

1. User Management

User Categories and Privileges
SmartLib categorizes users into three types:
General Users: Limited access primarily for browsing and borrowing books.
Authorized Users: Advanced access granted by an administrator.
Admin User: Full access to all management and operational functions within SmartLib.

Features
Account Creation & Role Allocation: 
General users can create accounts on the start page with basic privileges.
Only admins can elevate a general user to an authorized user.
Password and Security Protocols:
Passwords must meet specific security criteria, enforced by regex patterns.
Passwords are hashed with bcrypt and stored securely in a shelve database.
User Identification:
A unique customer ID is assigned to each user.
Admins control the addition of authorized users to ensure system integrity.
Logging and Tracking: 
All program activities are logged to monitor system usage and maintain security.


Feature
Accessible by
Display General Users
Admin, Authorized
Display Authorized Users
Admin
Add New General User
Admin, Authorized
Update General User
Admin, Authorized
Delete General User
Admin, Authorized
Add New Authorized User
Admin
Update Authorized User
Admin
Delete Authorized User
Admin



2. Book Management

Sorting and Searching

Various sorting algorithms, such as Bubble Sort, Insertion Sort, Merge Sort, and Quick Sort, have been implemented to enable efficient book organization. Users can sort books by various attributes, including title, publisher, language, and number of copies.

Book Management Menu Access

Feature
Accessible by
Display All Books
All
Display Book Categories
All
Add New Book
Admin, Authorized
Update Book
Admin, Authorized
Delete Book
Admin, Authorized
Sort Books 
All
Search for Books
All
Advanced Search and Filtering
All



Sorting Options

Attribute
Order
Algorithm Used
Publisher
Ascending/Descending
Bubble Sort
Number of Copies
Ascending/Descending
Insertion Sort
Title
Ascending/Descending
Quick Sort
Language, then ISBN
Ascending/Descending
Merge Sort
ISBN, then Language
Ascending/Descending
Merge Sort


Additional Book Management Features

CRUD Operations for Books: Complete create, read, update, and delete operations for book records.
Reservation System: If a book is unavailable, users can place a reservation, and a notification is sent once the book becomes available.
Tree Data Structure: Book categories are displayed using a tree structure, with recursive algorithms handling new category additions.
Stack-Based Menu Navigation: A stack algorithm manages menu navigation for a smooth user experience.

3. Borrowing and Reservation Management

SmartLib provides all users with access to borrowing and reservation functionalities, with features to view availability, track borrowing history, and handle returns.


Feature
Accessible by
Display All Borrowed Books
All
Display Available Books
All
Display Unavailable Books
All
Check Your Borrowed Books
All
Check Your Borrowing History
All
Borrow a Book
All
Return a Book
All
Reserve a Book
All



4. Customer Request Management

A Queue Algorithm handles customer requests efficiently, ensuring that all user requests are processed in the order they were received.


Feature
Accessible by
Input a Customer Request
All
View Number of Requests
Admin, Authorized
Service Next Request in Queue
Admin, Authorized



5. Membership Tier System and Recommendation

SmartLib implements a membership and point system to enhance user engagement. Users accumulate points based on activity, which influences their membership tier (Gold, Silver, Bronze, Standard).

Personalized Book Recommendations

The system utilizes users' borrowing history to recommend similar books, inspired by algorithms used by Netflix. Users are encouraged to add reviews upon returning books, enhancing the recommendation system and aiding other users in their book selection process.


6. Data Validation

SmartLib includes multiple data validation checks:

Username and Email Validation: All username and email inputs are validated upon account creation to ensure correctness.
ISBN Validation: Exception handling is implemented to validate ISBN inputs.
Customer Request Validation: Input validation includes word length checks and filters for offensive language.

7. Additional Features

Static Advertisements: Advertisements are displayed within the system to enhance user experience and system monetization.
User Interface Enhancement: The `tabulate` library provides an organized and visually appealing display for database content.


Conclusion

SmartLib combines robust data structures, secure user management, and intelligent algorithms to provide an efficient, secure, and user-centric Book Management System. Its modular and scalable design makes it suitable for libraries of various sizes, providing comprehensive tools for users and administrators alike.


