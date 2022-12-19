
from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
import sys
from encryption import encryption, decryption, publicKey, privateKey, data_verification


# Класс отвечающий за стартовое окно
class Login(QMainWindow):
    def __init__(self):
        super(Login, self).__init__()
        loadUi("login.ui", self)

        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login_btn.clicked.connect(lambda: self.personal_ac())
        self.registration_btn.clicked.connect(lambda: self.registration())

    def registration(self):
        self.login.setText('')
        self.password.setText('')
        widget.setCurrentWidget(registration_window)

    def personal_ac(self):
        username = self.login.text().strip()
        password = self.password.text().strip()
        data_user = username + password
        if username != '' and password != '' and \
                encryption(data_user, publicKey, 'авторизация'):
            self.login.setText('')
            self.password.setText('')
            widget.addWidget(account_window)
            widget.setFixedWidth(580)
            widget.setFixedHeight(640)
            widget.setCurrentWidget(account_window)
        else:
            error = QMessageBox()
            error.setWindowTitle("Ошибка\t\t\t\t\t")
            error.setText("Введен неверный логин или пароль.")
            error.setIcon(QMessageBox.Warning)
            error.setStandardButtons(QMessageBox.Ok)
            error.exec_()


# Класс отвечающий за окно регистрации
class Registration(QMainWindow):
    def __init__(self):
        super(Registration, self).__init__()
        loadUi("registration.ui", self)

        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_2.setEchoMode(QtWidgets.QLineEdit.Password)
        self.reg_btn.clicked.connect(lambda: self.ac_window())
        self.back_btn.clicked.connect(lambda: self.login_window())

    def login_window(self):
        self.login.setText('')
        self.password.setText('')
        self.password_2.setText('')
        return widget.setCurrentWidget(login_window)

    def ac_window(self):
        username = self.login.text().strip()
        password = self.password.text().strip()
        password_2 = self.password_2.text().strip()
        if password != password_2:
            error = QMessageBox()
            error.setWindowTitle("Ошибка\t\t\t\t\t")
            error.setText("Пароли не совпадают!")
            error.setIcon(QMessageBox.Warning)
            error.setStandardButtons(QMessageBox.Ok)
            error.exec_()
        else:
            if not data_verification(username, password):
                error = QMessageBox()
                error.setWindowTitle("Ошибка\t\t\t\t\t")
                error.setText("Введены неверный данные!")
                error.setIcon(QMessageBox.Warning)
                error.setStandardButtons(QMessageBox.Ok)
                error.exec_()
            else:
                self.login.setText('')
                self.password.setText('')
                self.password_2.setText('')
                widget.addWidget(account_window)
                widget.setFixedWidth(580)
                widget.setFixedHeight(640)
                widget.setCurrentWidget(account_window)


# Класс отвечающий за личный кабинет
class Personal_account(QMainWindow):
    def __init__(self):
        super(Personal_account, self).__init__()
        loadUi("personalKab.ui", self)

        self.encrypt_btn.clicked.connect(lambda: self.encrypt())
        self.dencrypt_btn.clicked.connect(lambda: self.dencrypt())
        self.exit_btn.clicked.connect(lambda: self.exit())

        self.text_for_encryption.setAcceptRichText(False)
        self.text_for_dencryption.setAcceptRichText(False)
        self.text_for_encryption.setPlaceholderText("Введите текст, который надо зашифровать")
        self.text_for_dencryption.setPlaceholderText("Введите текст, который надо расшифровать")
        self.finished_text.setReadOnly(True)

    def exit(self):
        error = QMessageBox()
        error.setWindowTitle("Предупреждение\t\t\t\t\t")
        error.setText("Вы уверены что хотите выйти из лчного кабинета?")
        error.setStandardButtons(QMessageBox.Ok|QMessageBox.Cancel)
        error.buttonClicked.connect(self.click_btn)
        error.exec_()

    def click_btn(self, btn):
        try:
            if btn.text() == 'OK':
                self.text_for_encryption.setText("")
                self.text_for_dencryption.setText("")
                self.finished_text.setText("")
                widget.removeWidget(account_window)
                widget.setFixedWidth(470)
                widget.setFixedHeight(320)
                widget.setCurrentWidget(login_window)
        except Exception as e:
            print(e)

    def encrypt(self):
        try:
            enc_text = self.text_for_encryption.toPlainText().strip()
            enc_text = enc_text.replace('\n', ' ')
            if len(enc_text) == 0 or not encryption(enc_text, publicKey, 'текст'):
                self.error_text()
        except Exception as e:
            print(e)

    def dencrypt(self):
        try:
            denc_text = self.text_for_dencryption.toPlainText().strip()
            text = decryption(denc_text, privateKey)
            if text == False:
                self.error_text()
            else:
                self.finished_text.setText(text)
        except Exception as e:
            print(e)

    def error_text(self):
        error = QMessageBox()
        error.setWindowTitle("Ошибка\t\t\t\t\t")
        error.setText("Введен неверный текст.")
        error.setIcon(QMessageBox.Warning)
        error.setStandardButtons(QMessageBox.Ok)
        error.exec_()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = Login()
    registration_window = Registration()
    account_window = Personal_account()
    widget = QtWidgets.QStackedWidget()
    widget.addWidget(login_window)
    widget.addWidget(registration_window)
    widget.show()
    sys.exit(app.exec_())