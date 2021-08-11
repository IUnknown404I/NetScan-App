from PySide2 import QtCore, QtGui, QtWidgets
import sys
from main_ui import Ui_MainWindow
 
# global app
app = QtWidgets.QApplication(sys.argv)
 
# global Form
Form = QtWidgets.QMainWindow()
# global ui
ui = Ui_MainWindow()
ui.setupUi(Form)
Form.show()
 
sys.exit(app.exec_())