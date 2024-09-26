import sys
import os
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication , QFileDialog
from PyQt5.QtWidgets import QMainWindow, QMessageBox


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
        self.ui.plaintext_input.setPlaceholderText("Entrer le text en claire (en hexadécimal) et respecter le nombre des bits de la variante KATAN choisie")
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
            # Vérifier si le champ du ciphertext est vide
            ciphertext_text = self.ui.plaintext_input.toPlainText().strip()
            if not ciphertext_text:
                self.show_warning("Veuillez saisir le texte en clair.")
                return

            # Vérifier si le champ de la clé est vide
            clef_text = self.ui.clef_input.text().strip()  # .strip() supprime les espaces inutiles
            if not clef_text:
                self.show_warning("Veuillez saisir une clé de sécurité.")
                return

            # Conversion de la clé en entier en base hexadécimale
            key = int(clef_text, 16)
            variant = self.get_variant()

            if variant is None:
                self.show_radio_warning("Aucun variant sélectionné. Veuillez choisir une base (32, 48 ou 64).")
                return

            plaintext = int(self.ui.plaintext_input.toPlainText(), 16)

            max_value = (1 << variant) - 1
            if plaintext > max_value:
                self.show_input_warning(variant, plaintext)
                return

            katan = KATAN(key, variant)
            ciphertext = katan.encrypt(plaintext)

            self.ui.result_output.setPlainText(hex(ciphertext))

        except ValueError as e:
            QMessageBox.critical(self, "Erreur", "Entrée invalide. Assurez-vous d'entrer des valeurs hexadécimales valides.")

    def decrypt(self):
        try:
            # Vérifier si le champ du ciphertext est vide
            ciphertext_text = self.ui.plaintext_input.toPlainText().strip()
            if not ciphertext_text:
                self.show_warning("Veuillez saisir le texte chiffré.")
                return

            # Vérifier si le champ de la clé est vide
            clef_text = self.ui.clef_input.text().strip()  # .strip() supprime les espaces inutiles
            if not clef_text:
                self.show_warning("Veuillez saisir une clé de sécurité.")
                return

            # Conversion de la clé en entier en base hexadécimale
            key = int(clef_text, 16)
            variant = self.get_variant()

            if variant is None:
                self.show_radio_warning("Aucun variant sélectionné. Veuillez choisir une base (32, 48 ou 64).")
                return

            # Conversion du ciphertext en entier en base hexadécimale
            ciphertext = int(ciphertext_text, 16)

            max_value = (1 << variant) - 1
            if ciphertext > max_value:
                self.show_input_warning(variant, ciphertext)
                return

            # Déchiffrement avec KATAN
            katan = KATAN(key, variant)
            plaintext = katan.decrypt(ciphertext)

            # Afficher le texte déchiffré
            self.ui.result_output.setPlainText(hex(plaintext))

        except ValueError as e:
            QMessageBox.critical(self, "Erreur", "Entrée invalide. Assurez-vous d'entrer des valeurs hexadécimales valides.")

    def select_file(self):
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("Tous les fichiers (*)")
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                self.selected_file_path = selected_files[0]
                self.ui.encryptdecrypt_file.setText(self.selected_file_path)
    def encrypt_file1(self):
        try:
            if not self.selected_file_path:
                self.show_warning("Veuillez sélectionner un fichier.")
                return

            variant = self.get_variant()
            if variant is None:
                self.show_radio_warning("Aucun variant sélectionné. Veuillez choisir une base (32, 48 ou 64).")
                return

            # Lire le fichier et convertir le contenu en entier (texte en clair)
            with open(self.selected_file_path, "rb") as input_file:
                plaintext = int.from_bytes(input_file.read(), byteorder='big')

            # Vérifier si le texte dépasse la taille maximale autorisée pour la variante choisie
            max_value = (1 << variant) - 1
            if plaintext > max_value:
                self.show_input_warning(variant, plaintext)
                return

            clef_text = self.ui.clef_input.text().strip()
            if not clef_text:
                self.show_warning("Veuillez saisir une clé de sécurité.")
                return

            key = int(clef_text, 16)

            katan = KATAN(key, variant)
            ciphertext = katan.encrypt_file(self.selected_file_path)

            output_file_path = os.path.splitext(self.selected_file_path)[0] + "_encrypted.txt"
            with open(output_file_path, "wb") as output_file:
                output_file.write(ciphertext)

            self.ui.result_output.setPlainText(f"Fichier chiffré enregistré sous : {output_file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Une erreur est survenue lors du chiffrement : {str(e)}")

    def decrypt_file1(self):
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

            # Lire le fichier et convertir le contenu en entier (texte en clair)
            with open(self.selected_file_path, "rb") as input_file:
                plaintext = int.from_bytes(input_file.read(), byteorder='big')

            # Vérifier si le texte dépasse la taille maximale autorisée pour la variante choisie
            max_value = (1 << variant) - 1
            if plaintext > max_value:
                self.show_input_warning(variant, plaintext)
                return

            key = int(clef_text, 16)

            katan = KATAN(key, variant)
            plaintext = katan.decrypt_file(self.selected_file_path)

            output_file_path = os.path.splitext(self.selected_file_path)[0] + "_decrypted.txt"
            with open(output_file_path, "wb") as output_file:
                output_file.write(plaintext)

            self.ui.result_output.setPlainText(f"Fichier déchiffré enregistré sous : {output_file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Une erreur est survenue lors du déchiffrement : {str(e)}")

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
                ciphertext = katan.encrypt_file(self.selected_file_path)

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
                plaintext = katan.decrypt_file(self.selected_file_path)

                output_file_path = self.selected_file_path.rsplit('.', 1)[0]
                if output_file_path.endswith('.encrypted'):
                    output_file_path = output_file_path[:-10]

                with open(output_file_path, "wb") as output_file:
                    output_file.write(plaintext)

                self.ui.result_output.setPlainText(f"Fichier déchiffré enregistré sous : {output_file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Une erreur est survenue lors du déchiffrement : {str(e)}")

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
            ciphertext = katan.encrypt_file(self.selected_file_path)

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
            plaintext = katan.decrypt_file(self.selected_file_path)

            output_file_path = self.selected_file_path.rsplit('.txt', 1)[0]
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