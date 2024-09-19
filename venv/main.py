import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication
from PyQt5.QtWidgets import QMainWindow, QMessageBox
#from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog, QMessageBox, QTableWidgetItem, QInputDialog

from katan import KATAN
from interface import Ui_MainWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Connectez les boutons aux fonctions
        self.ui.crypter_button.clicked.connect(self.encrypt)
        self.ui.decrypter_button.clicked.connect(self.decrypt)

        self.ui.plaintext_input.setPlaceholderText("Entrer le text en claire (en hexadécimal) et respecter le nombre des bits de la variante KATAN choisie")
        self.ui.clef_input.setPlaceholderText("Clef de Sécurité jusqu'a 80 Bits")



    def show_input_warning(self, variant, value):
        max_value = (1 << variant) - 1
        QMessageBox.warning(self, "Entrée invalide",
                            f"Pour KATAN{variant}, la taille maximale d'entrée est de {variant} bits.\n"
                            f"Valeur maximale en hexadécimal : 0x{max_value:X}\n"
                            f"Votre entrée : 0x{value:X}\n"
                            f"Exemple d'entrée valide : 0x{max_value // 2:X}")


    def encrypt(self):
        try:
            key = int(self.ui.clef_input.text(), 16)
            variant = 32 if self.ui.base32_radio.isChecked() else 48 if self.ui.base48_radio.isChecked() else 64
            plaintext = int(self.ui.plaintext_input.toPlainText(), 16)

            max_value = (1 << variant) - 1
            if plaintext > max_value:
                self.show_input_warning(variant, plaintext)
                return

            katan = KATAN(key, variant)
            ciphertext = katan.encrypt(plaintext)

            self.ui.result_output.setPlainText(hex(ciphertext))
        except ValueError:
            QMessageBox.critical(self, "Erreur","Entrée invalide. Assurez-vous d'entrer des valeurs hexadécimales valides.")
            #self.ui.result_output.setPlainText("Erreur: Entrée invalide")

    def decrypt(self):
        try:
            key = int(self.ui.clef_input.text(), 16)
            variant = 32 if self.ui.base32_radio.isChecked() else 48 if self.ui.base48_radio.isChecked() else 64
            ciphertext = int(self.ui.plaintext_input.toPlainText(), 16)

            max_value = (1 << variant) - 1
            if ciphertext > max_value:
                self.show_input_warning(variant, ciphertext)
                return


            katan = KATAN(key, variant)
            plaintext = katan.decrypt(ciphertext)

            self.ui.result_output.setPlainText(hex(plaintext))
        except ValueError:
            #self.ui.result_output.setPlainText("Erreur: Entrée invalide")
            QMessageBox.critical(self, "Erreur","Entrée invalide. Assurez-vous d'entrer des valeurs hexadécimales valides.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())