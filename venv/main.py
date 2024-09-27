import sys
import os
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication , QFileDialog
from PyQt5.QtWidgets import QMainWindow, QMessageBox, QProgressDialog
from PyQt5.QtCore import Qt



from katan import KATAN
from interface import Ui_MainWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.selected_file_path = ""

        # Connectez les boutons aux fonctions
        self.ui.crypter_button.clicked.connect(self.encrypt)
        self.ui.decrypter_button.clicked.connect(self.decrypt)

        self.ui.file_browse_button.clicked.connect(self.select_file)
        self.ui.crypterfile_button.clicked.connect(self.encrypt_file)
        self.ui.decrypterfile_button.clicked.connect(self.decrypt_file)

        self.ui.encryptdecrypt_file.setPlaceholderText("Veuillez sélectionner un fichier")
        self.ui.plaintext_input.setPlaceholderText("Entrez le texte en clair si vous voulez chiffrer un texte. \n\nEntrez le texte chiffré si vous voulez déchiffrer un texte")
        self.ui.clef_input.setPlaceholderText("Clef de Sécurité 80 Bits exp: 0x+20 caractères ")



    def show_input_warning(self, variant, value):
        max_value = (1 << variant) - 1
        QMessageBox.warning(self, "Entrée invalide",
                            f"Pour KATAN{variant}, la taille maximale d'entrée est de {variant} bits.\n"
                            f"Valeur maximale en hexadécimal : 0x{max_value:X}\n"
                            f"Votre entrée : 0x{value:X}\n"
                            f"Exemple d'entrée valide : 0x{max_value // 2:X}")

    def show_radio_warning(self, message):
        QMessageBox.warning(self, "Avertissement", message)

    def show_warning(self, message):
        QMessageBox.warning(self, "Avertissement", message)

    def get_variant(self):
        if self.ui.base32_radio.isChecked():
            return 32
        elif self.ui.base48_radio.isChecked():
            return 48
        elif self.ui.base64_radio.isChecked():
            return 64
        else:
            return None



    def encrypt(self):
        try:
            plaintext = self.ui.plaintext_input.toPlainText().strip()
            if not plaintext:
                self.show_warning("Veuillez saisir le texte en clair.")
                return

            clef_text = self.ui.clef_input.text().strip()
            if not clef_text:
                self.show_warning("Veuillez saisir une clé de sécurité.")
                return

            if len(clef_text) != 20:  # 80 bits = 20 caractères hexadécimaux
                self.show_warning("La clé doit être de 80 bits (20 caractères hexadécimaux).")
                return

            key = int(clef_text, 16)
            variant = self.get_variant()

            if variant is None:
                self.show_radio_warning("Aucun variant sélectionné. Veuillez choisir une base (32, 48 ou 64).")
                return

            katan = KATAN(key, variant)
            ciphertext = katan.encrypt_text(plaintext)

            self.ui.result_output.setPlainText(ciphertext)

        except ValueError:
            QMessageBox.critical(self, "Erreur",
                                 "Entrée invalide. Assurez-vous que la clé est une valeur hexadécimale valide.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Une erreur s'est produite : {str(e)}")

    def decrypt(self):
        try:
            ciphertext = self.ui.plaintext_input.toPlainText().strip()
            if not ciphertext:
                self.show_warning("Veuillez saisir le texte chiffré.")
                return

            clef_text = self.ui.clef_input.text().strip()
            if not clef_text:
                self.show_warning("Veuillez saisir une clé de sécurité.")
                return

            if len(clef_text) != 20:  # 80 bits = 20 caractères hexadécimaux
                self.show_warning("La clé doit être de 80 bits (20 caractères hexadécimaux).")
                return

            key = int(clef_text, 16)
            variant = self.get_variant()

            if variant is None:
                self.show_radio_warning("Aucun variant sélectionné. Veuillez choisir une base (32, 48 ou 64).")
                return

            katan = KATAN(key, variant)

            try:
                # Vérification de la cohérence du variant
                block_size = variant // 8  # Taille du bloc en octets
                if len(ciphertext) % (block_size * 2) != 0:
                    raise ValueError("Longueur du texte chiffré incorrecte")
                plaintext = katan.decrypt_text(ciphertext)
                self.ui.result_output.setPlainText(plaintext)
            except (UnicodeDecodeError, ValueError):
                self.show_warning(f"Le texte chiffré ne correspond pas au variant sélectionné ({variant} bits). "
                                  f"Assurez-vous d'utiliser le même variant que pour le chiffrement.")

        except ValueError:
            QMessageBox.critical(self, "Erreur",
                                 "Entrée invalide. Assurez-vous que la clé et le texte chiffré sont des valeurs hexadécimales valides.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Une erreur s'est produite : {str(e)}")

    def select_file(self):
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("Tous les fichiers (*)")
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                self.selected_file_path = selected_files[0]
                self.ui.encryptdecrypt_file.setText(self.selected_file_path)

    def encrypt_file(self):
        try:
            if not self.selected_file_path:
                self.show_warning("Veuillez sélectionner un fichier.")
                return

            variant = self.get_variant()
            if variant is None:
                self.show_radio_warning("Aucun variant sélectionné. Veuillez choisir une base (32, 48 ou 64).")
                return

            clef_text = self.ui.clef_input.text().strip()
            if not clef_text:
                self.show_warning("Veuillez saisir une clé de sécurité.")
                return

            key = int(clef_text, 16)

            katan = KATAN(key, variant)

            progress = QProgressDialog("Chiffrement en cours...", "Annuler", 0, 100, self)
            progress.setWindowModality(Qt.WindowModal)
            progress.setWindowTitle("Progression")

            def update_progress(value):
                progress.setValue(value)
                QApplication.processEvents()

            # Define cancel callback
            def cancel_callback():
                return progress.wasCanceled()

            ciphertext = katan.encrypt_file(self.selected_file_path, update_progress, cancel_callback)

            if progress.wasCanceled():
                self.ui.result_output.setPlainText("Chiffrement annulé.")
                return

            output_file_path = self.selected_file_path + ".encrypted"
            with open(output_file_path, "wb") as output_file:
                output_file.write(ciphertext)

            self.ui.result_output.setPlainText(f"Fichier chiffré enregistré sous : {output_file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Une erreur est survenue lors du chiffrement : {str(e)}")

    def decrypt_file(self):
        try:
            if not self.selected_file_path:
                self.show_warning("Veuillez sélectionner un fichier.")
                return

            variant = self.get_variant()
            if variant is None:
                self.show_radio_warning("Aucun variant sélectionné. Veuillez choisir une base (32, 48 ou 64).")
                return

            clef_text = self.ui.clef_input.text().strip()
            if not clef_text:
                self.show_warning("Veuillez saisir une clé de sécurité.")
                return

            key = int(clef_text, 16)

            katan = KATAN(key, variant)

            progress = QProgressDialog("Déchiffrement en cours...", "Annuler", 0, 100, self)
            progress.setWindowModality(Qt.WindowModal)
            progress.setWindowTitle("Progression")

            def update_progress(value):
                progress.setValue(value)
                QApplication.processEvents()

            # Define cancel callback
            def cancel_callback():
                return progress.wasCanceled()

            plaintext = katan.decrypt_file(self.selected_file_path, update_progress, cancel_callback)

            if progress.wasCanceled():
                self.ui.result_output.setPlainText("Déchiffrement annulé.")
                return

            output_file_path = self.selected_file_path.rsplit('.', 1)[0]
            if output_file_path.endswith('.encrypted'):
                output_file_path = output_file_path[:-10]

            with open(output_file_path, "wb") as output_file:
                output_file.write(plaintext)

            self.ui.result_output.setPlainText(f"Fichier déchiffré enregistré sous : {output_file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Une erreur est survenue lors du déchiffrement : {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())