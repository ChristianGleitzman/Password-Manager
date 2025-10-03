#Importing Libraries
import sqlite3
import faulthandler, traceback, logging, os, sys

faulthandler.enable(all_threads=True)

# Simple logging to a file
log_file = os.path.join(os.path.dirname(__file__), 'pm_debug.log')
logging.basicConfig(level=logging.DEBUG, filename=log_file, filemode='w',
                    format='%(asctime)s %(levelname)s: %(message)s')
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

#Logs uncaught exceptions
def excepthook(type_, value, tb):
    logging.error("Uncaught exception", exc_info=(type_, value, tb))
    # print trace for faulthandler as well
    faulthandler.dump_traceback(file=sys.stdout)
    # still call default
    sys.__excepthook__(type_, value, tb)

sys.excepthook = excepthook
logging.info("Debug instrumentation enabled")

from PyQt5 import QtWidgets, uic, QtGui, QtCore
import re
from validator_collection import checkers
from random import choices
import string
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from sqlite3 import Binary
from sqlite3 import *
from datetime import date

#Database class that executes SQL queries
class Database:
    def __init__(self):
        #Database name set to database file name
        self.__dbname = 'password_database.db'
        self.__currentID = None
        self.__currentMaster = None
    #Returns the current ID of the user
    def get_id(self):
        return self.__currentID
    #Returns the current master password
    def get_master_password(self):
        return self.__currentMaster
    #Creates connection to database file
    def create_connection(self):
        con = connect(self.__dbname)
        cur = con.cursor()
        return con,cur
    #Exectutes an SQL statement with or without arguments
    def __execute_statement(self, query, args=None):
        con,cur = self.create_connection()
        #Executes a given query on the database
        if not args:
            cur.execute(query)
        else:
            cur.execute(query, args)
        #Any data fetched from the database is assigned to 'selectedData'
        selectedData = cur.fetchall()
        #Any changes to the contents of the database are committed
        con.commit()
        #Connection to the database is closed
        con.close()
        #Any selected data is returned
        return selectedData
    #Authenticates a user if the password entered matches the hashed password when the salt is added to it
    def authenticate_user(self, entered_username, entered_password):
        query = '''SELECT userID, hashedMasterPassword, salt FROM users
        WHERE username = ?'''
        user_data = self.__execute_statement(query, (entered_username,))
        if len(user_data) == 0:
            return False
        else:
            hashed_entered = hash_password(entered_password, user_data[0][2])
            if hashed_entered == user_data[0][1]:
                self.__currentID = user_data[0][0]
                self.__currentMaster = entered_password
                return True
            else:
                return False
    #Authenticates a transaction if a user is currently logged in
    def __authenticate_transaction(self):
        if self.__currentID == None:
            return False
        else:
            return True
    #Hashes the master password and saves a new user to the database
    def save_new_user(self, username, email, master_password, hint):
        try:
            random_salt = os.urandom(16)
            hashed_master = hash_password(master_password, random_salt)
            query = '''INSERT INTO users(username, email, hashedMasterPassword, salt, hint)
            VALUES (?,?,?,?,?)'''
            args = (username, email, sqlite3.Binary(hashed_master), sqlite3.Binary(random_salt), hint)
            self.__execute_statement(query, args)
            return True
        except:
            return False
    #Encrypts and saves a new password for a specific user to the database
    def save_new_password(self, plaintext, application, strength):
        if not self.__authenticate_transaction():
            print('[Error] Transaction could not be authenticated')
            return False
        if not self.__currentMaster:
            print('[Error] No master password available for encryption')
            return False
        
        random_salt = os.urandom(16)
        encrypted_password = encrypt_password(self.__currentMaster, plaintext, random_salt)
        query = '''INSERT INTO passwords(encryptedPassword, salt, application, lastUpdate, strength, userID)
        VALUES (?,?,?,?,?,?)'''
        args = (
        sqlite3.Binary(encrypted_password), sqlite3.Binary(random_salt), application, date.today(), strength, self.__currentID)
        self.__execute_statement(query, args)
        return True
    
    #Fetches all the passwords of a specific user from the database
    def fetch_passwords(self):
        if self.__authenticate_transaction():
            query = '''SELECT encryptedPassword, salt, application, lastUpdate, strength FROM passwords
            WHERE userID = ?'''
            passwords = self.__execute_statement(query, (self.__currentID,))
            return passwords
        else:
            print('[Error] Transaction could not be authenticated')
            
    #Verifies whether a specific application already exists for a specific user in the database
    def verify_application(self, application):
        if self.__authenticate_transaction():
            query = '''SELECT passwordID FROM passwords
            WHERE userID = ? AND application = ?'''
            passwordID = self.__execute_statement(query, (self.__currentID, application))
            if len(passwordID) == 0:
                return False
            else:
                return True
        else:
            print('[Error] Transaction could not be authenticated')
            
    #Updates an existing password to a new password for a specific application
    def update_password(self, application, plaintext, strength):
        if self.__authenticate_transaction():
            random_salt = os.urandom(16)
            encrypted_password = encrypt_password(self.__currentMaster, plaintext, random_salt)
            query = '''UPDATE passwords
            SET encryptedPassword = ?, salt = ?, lastUpdate = ?, strength = ?
            WHERE userID = ? AND application = ?;'''
            self.__execute_statement(query, (encrypted_password, random_salt, date.today(), strength, self.__currentID, application))
            return True
        else:
            print('[Error] Transaction could not be authenticated')
            
    #Deletes a password for a specific application and user from the database
    def delete_password(self, application):
        if self.__authenticate_transaction():
            query = '''DELETE FROM passwords
            WHERE userID = ? AND application = ?'''
            self.__execute_statement(query, (self.__currentID, application))
            return True
        else:
            print('[Error] Transaction could not be authenticated')


def hash_password(password: str, salt):
    # Create a new sha256 hash object
    sha256 = hashlib.sha256()

    # Hash the password and salt
    sha256.update(password.encode('utf-8') + salt)

    # Return the hexadecimal representation of the hash and salt
    return salt + sha256.digest()

#Encrypts a password using a key derived from the master password and a random salt
def encrypt_password(master_password, password_to_encrypt, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    # Encrypt the password
    cipher = Fernet(key)
    encrypted_password = cipher.encrypt(password_to_encrypt.encode())

    return encrypted_password

#Decrypts a password using the key derived from the master password and the stored salt
def decrypt_password(master_password, encrypted_password, salt):
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        # Decrypt the password
        cipher = Fernet(key)
        decrypted_password = cipher.decrypt(encrypted_password).decode()

        return decrypted_password
    except InvalidToken:
        logging.exception("InvalidToken during decrypt - wrong master password or corrupted data")
        return "<decrypt-error>"
    except Exception:
        logging.exception("Unexpected error during decrypt")
        return "<decrypt-error>"

#Calculates the strength of the password based on numbers, symbols, length etc. and returns it
def calculate_strength(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if re.search("[a-z]", password):
        strength += 1
    if re.search("[A-Z]", password):
        strength += 1
    if re.search("[0-9]", password):
        strength += 1
    if re.search("[!@#$%^&*()]", password):
        strength += 1
    return strength

#Generates a random password based on a given length
def generate_password(length):
    password = ''.join(choices(string.ascii_letters + string.digits + string.punctuation, k=length))
    return password

class TableModel(QtCore.QAbstractTableModel):
    def __init__(self, data):
        super(TableModel, self).__init__()
        self._data = data
        self.colors = ['#e5f5f9', '#ccece6', '#99d8c9', '#66c2a4', '#41ae76', '#238b45']
        self.header_labels = ['Application', 'Password', 'Last Update', 'Strength']
        
    #Adds the data to the model
    def data(self, index, role):
        if not index.isValid():
            return None
        value = self._data[index.row()][index.column()]
        if role == QtCore.Qt.DisplayRole:
            if isinstance(value, (bytes, bytearray)):
                try:
                    return value.decode('utf-8', errors='replace')
                except Exception:
                    return str(value)
            return value
        if role == QtCore.Qt.DecorationRole:
            if index.column() == 3:
                try:
                    val = int(self._data[index.row()][index.column()])
                    if 0 <= val < len(self.colors):
                        return QtGui.QColor(self.colors[val])
                except Exception:
                    return None
        return None

    def rowCount(self, index):
        #The length of the outer list.
        return len(self._data)

    def columnCount(self, index):
        #The following takes the first sub-list, and returns the length 
        return len(self._data[0])
    
    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        #Adds header labels to the model
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.header_labels[section]
        return super().headerData(section, orientation, role)

#Updates the password strength progress bar object of multiple windows
def update_strength(line_edit_obj, progress_bar_obj):
        current_password = line_edit_obj.text()
        current_strength = calculate_strength(current_password)
        progress_bar_obj.setValue(20*current_strength)
        if current_strength == 0:
            progress_bar_obj.setFormat("Empty")
        elif current_strength == 1:
            progress_bar_obj.setFormat("Very Weak")
        elif current_strength == 2:
            progress_bar_obj.setFormat("Weak")
        elif current_strength == 3:
            progress_bar_obj.setFormat("Moderate")
        elif current_strength == 4:
            progress_bar_obj.setFormat("Strong")
        else:
            progress_bar_obj.setFormat("Very Strong")

class Startup(QtWidgets.QMainWindow):
    def __init__(self):
        super(Startup, self).__init__() # Call the inherited classes __init__ method
        uic.loadUi('start_window.ui',self) #Load the ui file
        
        #Handles the events of buttons being clicked
        self.login_button.clicked.connect(self.login_button_method)
        self.register_button.clicked.connect(self.register_button_method)
        self.exit_button.clicked.connect(self.closeEvent)

        self.show()

    def login_button_method(self):
        #Creates login window when the button is pressed
        self.login_window = Login()
        self.hide()

    def register_button_method(self):
        #Creates new user registration window when the button is pressed
        self.registration_window = Register()
        self.hide()

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        #Ends the application when the exit button is pressed
        return super().closeEvent(a0)
        
class Register(QtWidgets.QMainWindow):
    def __init__(self):
        super(Register, self).__init__() # Call the inherited classes __init__ method
        uic.loadUi('registration_window.ui',self) #Load the ui file
        
        
        #Password input widget contents are initially hidden
        self.__password_covered = True
        
        #Handles the events of buttons being clicked
        self.submit_button.clicked.connect(self.submit_method)
        self.clear_button.clicked.connect(self.clear_method)
        self.back_button.clicked.connect(self.back_method)
        self.check_password_button.clicked.connect(self.check_method)

        #Calls the update strength procedure when change in the password input field is detected
        self.password_input.textChanged.connect(lambda: update_strength(self.password_input, self.password_strength))
        self.show()
    
    def submit_method(self):
        #Contents of input widgets are saved to variables
        email = self.email_input.text().lower()
        username = self.username_input.text().lower()
        password = self.password_input.text()
        confirmed_password = self.confirm_password_input.text()
        password_hint = self.password_hint_input.text()
        #Entered fields are saved to a list
        self.__enteredFields = [email,username,password,confirmed_password,password_hint]
        #Checks if any of the fields have been left blank
        for i in range(len(self.__enteredFields)):
            if self.__enteredFields[i] == '':
                empty = True
                break
        else:
            empty = False
        if empty:
            #Informs the user that they have left fields blank
            self.error_label.setText('Do not leave any fields blank!')
        elif not checkers.is_email(email):
            #Informs the user they have entered an invalid email
            self.email_input.setText('')
            self.error_label.setText('Ensure you have entered a valid email!')
        elif password != confirmed_password:
            #Informs the user the confirmed password does not match
            self.password_input.setText('')
            self.confirm_password_input.setText('')
            self.error_label.setText('The confirmed password does not match!')
        elif calculate_strength(password) <= 3:
            #Informs the user their password is not strong enough
            self.error_label.setText('Ensure you have a strong master password!')
        else:
            #Registers the entered details to the database if all validation requirements have been met
            successful = database.save_new_user(username, email, password, password_hint)
            if successful:
                self.close()
                start_window.show()
            else:
                #Informs the user their username is not unique if the sql statement executes unsuccessfully
                self.error_label.setText('Your username is not unique!')

    def clear_method(self):
        #C#Clears the current contents of the input fields
        self.error_label.setText('')
        self.email_input.setText('')
        self.username_input.setText('')
        self.password_input.setText('')
        self.confirm_password_input.setText('')
        self.password_hint_input.setText('')

    def back_method(self):
        #Returns the user to the start window
        self.close()
        start_window.show()
    
    def check_method(self):
        #Changes the password from being being hidden in the input widget to unhidden and vice versa
        if self.__password_covered:
            self.password_input.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.confirm_password_input.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
            self.confirm_password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.__password_covered = not self.__password_covered
    
class Login(QtWidgets.QMainWindow):
    def __init__(self):
        super(Login, self).__init__() # Call the inherited classes __init__ method
        uic.loadUi('login_window.ui',self) #Load the ui file
        
        #Handles the events of buttons being clicked
        self.submit_button.clicked.connect(self.submit_method)
        self.clear_button.clicked.connect(self.clear_method)
        self.back_button.clicked.connect(self.back_method)

        self.show()
        
    def submit_method(self):
        #Saves current contents of line edit widgets to variables
        entered_username = self.username_input.text().lower()
        entered_password = self.password_input.text()
        if entered_username == '' or entered_password == '':
            #Informs user if any fields are blank
            self.error_label.setText('Ensure you enter both a username and password!')
        else:
            #Attempts to authenticate the user. If authenticated, the current window is closed to allow the main menu to open
            successful_authentication = database.authenticate_user(entered_username, entered_password)
            if successful_authentication:
                self.close()
                self.main_menu = MainMenu()
                self.main_menu.show()
            else:
                #Informs the user that the login attempt was unsuccessful
                self.clear_method()
                self.error_label.setText('Incorrect username or password entered!')

    def clear_method(self):
        #Clears the current contents of the input fields
        self.error_label.setText('')
        self.username_input.setText('')
        self.password_input.setText('')
    
    def back_method(self):
        #Takes the user back to the start window
        self.close()
        start_window.show()

class MainMenu(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainMenu, self).__init__() # Call the inherited classes __init__ method
        uic.loadUi('main_menu.ui',self) #Load the ui file
        self.__cached_passwords = []
        self.__unresolved_update = True

        #Current table model
        self.__current_model = None
        #Creates a proxy model for filtering
        self.filter_proxy_model = QtCore.QSortFilterProxyModel()
        #Filters the table based on application entered
        self.filter_proxy_model.setFilterKeyColumn(0)
        #Filtering is case-insensitive
        self.filter_proxy_model.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        #Filters the table whenever change in the input field is detected
        self.filter_input.textChanged.connect(self.filter_proxy_model.setFilterRegExp)

        #Handles the event of a tab being changed
        self.tabWidget.currentChanged.connect(self.onChange)

        #Handles the events of buttons being clicked
        self.update_password_button.clicked.connect(self.update_method)
        self.delete_password_button.clicked.connect(self.delete_method)
        self.clear_update_button.clicked.connect(self.clear_update_method)
        self.generate_updated_password_button.clicked.connect(self.generate_updated_password_method)

        self.submit_button.clicked.connect(self.submit_method)
        self.clear_button.clicked.connect(self.clear_method)
        self.generate_password_button.clicked.connect(self.generate_method)

        #Calls the update strength procedure when change in the password input fields are detected
        self.password_input.textChanged.connect(lambda: update_strength(self.password_input, self.password_strength))
        self.updated_password_input.textChanged.connect(lambda: update_strength(self.updated_password_input, self.updated_password_strength))
        #Makes an initial call of this method to initially set up the password viewing table
        self.view_passwords_method()
        self.show()
    
    #@pyqtSlot()  
    def onChange(self, index):
        #Calls a method based on what the current tab has been changed to
        if index == 0:
            self.view_passwords_method()
        elif index == 1:
            self.manage_passwords_setup()
        else:
            self.outcome_label.setText('')
    
    #Fetches and decrypted all passwords pertaining to a specific user from the database and formats them for the table
    def decrypt_user_passwords(self):
        try:
            encrypted_passwords = database.fetch_passwords()
            self.__cached_passwords = []
            for row in encrypted_passwords:
                try:
                    enc_pwd, salt, application, lastupdate, strength = row
                    curr_decrypted = decrypt_password(database.get_master_password(), enc_pwd, salt)
                    # ensure str types for Qt
                    if not isinstance(curr_decrypted, str):
                        curr_decrypted = str(curr_decrypted)
                    self.__cached_passwords.append((app, curr_decrypted, lastupdate, strength))
                except Exception:
                    logging.exception("Failed to decrypt one row")
                    self.__cached_passwords.append((application, "<decrypt-error>", lastupdate, strength))
        except Exception:
            logging.exception("Failed to fetch passwords")
            self.__cached_passwords = []

    #If changes have been made to the currently displayed table, the table is updated with the most up-to-date passwords
    def view_passwords_method(self):
        if self.__unresolved_update:
            self.decrypt_user_passwords()
            if len(self.__cached_passwords) != 0:
                self.passwords_table.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
                self.passwords_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
                self.__current_model = TableModel(self.__cached_passwords)
                self.filter_proxy_model.setSourceModel(self.__current_model)
                self.passwords_table.setModel(self.filter_proxy_model)
                self.passwords_table.horizontalHeader().setVisible(True)
                self.__unresolved_update = False

    #Sets up the manage passwords tab by adding all current applications to the application input autocompleter
    def manage_passwords_setup(self):
        self.applications = []
        for password in self.__cached_passwords:
            self.applications.append(password[0])
        self.completer = QtWidgets.QCompleter(self.applications)
        self.completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.completer.setFilterMode(QtCore.Qt.MatchContains)
        self.completer.popup().setStyleSheet('font: 18pt "MS UI Gothic";')
        self.select_application_input.setCompleter(self.completer)

    #Allows the user to update a current password to a new password they have entered for a specific application
    def update_method(self):
        entered_application = self.select_application_input.text()
        updated_password = self.updated_password_input.text()
        confirmed_updated_password = self.confirm_updated_password_input.text()
        if entered_application == '' or updated_password == '' or confirmed_updated_password == '':
            #Informs the user that they have left fields blank
            self.update_outcome_label.setText('Please do not leave any fields blank!')
        elif updated_password != confirmed_updated_password:
            #Informs the user the confirmed password does not match
            self.outcome_label.setText('The confirmed password does not match!')
        elif calculate_strength(updated_password) <= 2:
            #Informs the user their password is not strong enough
            self.outcome_label.setText('Ensure you enter a strong password!')
        elif database.verify_application(entered_application):
            #Updates the password if the application matches an existing application in the database
            database.update_password(entered_application, updated_password, calculate_strength(updated_password))
            self.clear_update_method()
            #Informs the user the password has been updated
            self.update_outcome_label.setText('Password updated successfully!')
            self.__unresolved_update = True
        else:
            #The user is informed that the application they entered does not have a matching password in the database
            self.outcome_label.setText('A password matching this application does not exist!')

    #Allows the user to delete a password for a specific application
    def delete_method(self):
        entered_application = self.select_application_input.text()
        if entered_application == '':
            #Informs the user that they have left the application field blank
            self.update_outcome_label.setText('Please select an application to delete!')
        elif database.verify_application(entered_application):
            #If the application the user entered exists for their account, the password for that application is deleted
            database.delete_password(entered_application)
            self.clear_update_method()
            #The user is informed the password has been deleted
            self.update_outcome_label.setText('Password successfully deleted!')
            self.__unresolved_update = True
        else:
            #The user is informed that the application they entered does not have a matching password in the database
            self.update_outcome_label.setText('A password matching this application does not exist!')

    #Clears the current contents of the manage password input fields
    def clear_update_method(self):
        self.select_application_input.setText('')
        self.updated_password_input.setText('')
        self.confirm_updated_password_input.setText('')
        self.update_outcome_label.setText('')

    #Generates an updated password and adds this to the update password entry fields
    def generate_updated_password_method(self):
        generated_password = generate_password(16)
        self.updated_password_input.setText(generated_password)
        self.confirm_updated_password_input.setText(generated_password)

    #Allows the user to save a new password for a new application to the database
    def submit_method(self):
        entered_password = self.password_input.text()
        entered_confirmed_password = self.confirm_password_input.text()
        entered_application = self.application_input.text()
        if entered_password == '' or entered_confirmed_password == '' or entered_application == '':
            #Informs the user that they have left fields blank
            self.outcome_label.setText('Please do not leave any fields blank!')
        elif entered_password != entered_confirmed_password:
            #Informs the user the confirmed password does not match
            self.outcome_label.setText('The confirmed password does not match!')
        elif calculate_strength(entered_password) <= 2:
            #Informs the user their password is not strong enough
            self.outcome_label.setText('Ensure you enter a strong password!')
        elif database.verify_application(entered_application):
            #Informs the user that a password already exists for the application they entered
            self.outcome_label.setText('A password already exists for this application!')
        else:
            #Saves the new password to the database if all validation requirements have been met
            database.save_new_password(entered_password, entered_application, calculate_strength(entered_password))
            self.clear_method()
            #Informs the user that the new password has been saved
            self.outcome_label.setText('New password saved successfully!')
            self.__unresolved_update = True

    #Clears the current contents of the new password input fields
    def clear_method(self):
        self.outcome_label.setText('')
        self.password_input.setText('')
        self.application_input.setText('')
        self.confirm_password_input.setText('')

    #Generates a password and adds this to the new password entry fields
    def generate_method(self):
        generated_password = generate_password(16)
        self.password_input.setText(generated_password)
        self.confirm_password_input.setText(generated_password)

if __name__ == "__main__":
    #Initialises and displays start window
    app = QtWidgets.QApplication(sys.argv)
    # Creates an instance of the database class
    database = Database()

    start_window = Startup()
    app.exec()