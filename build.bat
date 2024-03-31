pyinstaller -i icon\main.png --add-data icon:icon -F main.py -w


nuitka  --standalone  --disable-console --enable-plugin=pyqt5 --windows-icon-from-ico=./icon/main.png --output-dir=out main.py