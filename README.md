# Password-Manager

This is a Python program that allows you to securely store and retrieve your passwords. It uses encryption to protect your passwords and has a user-friendly interface for adding, viewing, and editing them.

## Features

- Encrypts and decrypts the passwords using AES256 encryption, with a random salt and key derived from the user's master password for each password
- Allows the user to store multiple passwords under the same account
- Includes a login and registration system using salted and hashed passwords stored in a database
- Generates random secure passwords
- Decrypts and displays passwords for the user to view once logged in
- Update, delete and filter functionality for the existing account passwords
- User-friendly interface created using pyqt5 and QT designer

The program will prompt you to set a master password which will be used to encrypt and decrypt your passwords. Make sure to remember this password, as you will need it to access your passwords.

## Screenshots

![Login](https://github.com/ChristianGleitzman/Password-Manager/blob/main/images/login.PNG)
![Registration](https://github.com/ChristianGleitzman/Password-Manager/blob/main/images/registration.PNG)
![Viewing Passwords](https://github.com/ChristianGleitzman/Password-Manager/blob/main/images/view_passwords.PNG)

## Improvements

A possible improvement that could be made, which can be previewed in the registration process, is to have a master password hint. This password hint can then be sent to the email address entered by the user if they forget their master password. A possible extra security improvement would involve adding a session timeout due to inactivity where, say after 5 minutes, the user is required to log back into the application.

## Disclaimer

Use this program at your own risk. Remember to use a strong and unique master password and never share your passwords or the master password with anyone. The developer of this program is not responsible for any loss of data or unauthorized access to your passwords.
