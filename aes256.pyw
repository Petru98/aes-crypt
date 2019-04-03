#!/usr/bin/python3

import sys
import optparse
import tkinter
import tkinter.font
import tkinter.messagebox
from crypt import AES256

def defaultExceptionHandler(type, value, traceback):
    msg = "Type: " + str(type) + "\nValue: " + str(value) + "\nTraceback: " + str(traceback)
    tkinter.messagebox.showerror("Uncaught exception", msg)

sys.excepthook = defaultExceptionHandler

if len(sys.argv) > 3:
    parser = optparse.OptionParser(usage = "usage: %prog FILE [OPTIONS]...")
    parser.add_option("-o", "-f", "--out", "--file", dest = "out", default = "", metavar = "FILE", help = "The file where the encrypted data is written (default is the input file)")
    parser.add_option("-p", "--password", default = "", help = "The password used in encryption/decyption")
    parser.add_option("-e", "--encrypt", dest = "encrypt", action = "store_true", help = "Encrypt the file")
    parser.add_option("-d", "--decrypt", dest = "encrypt", action = "store_false", help = "Decrypt the file")
    parser.add_option("-b", "--binary", dest = "binary", action = "store_true", default = False, help = "By default the program works with plain text (the encrypted data is encoded using base64). This flag tells the program to work with binary data")

    (options, args) = parser.parse_args()

    if options.password == "":
        parser.print_help()
    elif len(args) != 1:
        parser.print_help()
    else:
        data = open(args[0], "rb").read()

        if options.encrypt == True:
            data = AES256.encrypt(data, options.password.encode(), options.binary)
        else:
            data = AES256.decrypt(data, options.password.encode(), options.binary)

        if options.out != "":
            open(options.out, "wb").write(data)
        else:
            open(args[0], "wb").write(data)
    exit()

LINES_COUNT = 32
COLUMNS_COUNT = 32

class TextBox(object):
    def __init__(self, master):
        self.frame = tkinter.Frame(master)
        self.frame.grid_propagate(False)
        self.frame.grid_rowconfigure(0, weight = 1)
        self.frame.grid_columnconfigure(0, weight = 1)

        self.text = tkinter.Text(self.frame, height = LINES_COUNT, width = COLUMNS_COUNT, wrap = tkinter.NONE, undo = True)
        self.text.grid(row = 0, column = 0, sticky = "nsew")

        self.xscroll = tkinter.Scrollbar(self.frame, orient = tkinter.HORIZONTAL, command = self.text.xview)
        self.xscroll.grid(row = 1, column = 0, sticky = "nsew")

        self.yscroll = tkinter.Scrollbar(self.frame, orient = tkinter.VERTICAL, command = self.text.yview)
        self.yscroll.grid(row = 0, column = 1, sticky = "nsew")

        self.text.config(xscrollcommand = self.xscroll.set)
        self.text.config(yscrollcommand = self.yscroll.set)


window = tkinter.Tk()

window.title("AES-256")
window.geometry("768x480")
window.grid_rowconfigure(0, weight = 1)
window.grid_rowconfigure(1, weight = 0)
window.grid_columnconfigure(0, weight = 0)
window.grid_columnconfigure(1, weight = 0)
window.grid_columnconfigure(2, weight = 1)

textbox = TextBox(window)
textbox.frame.grid(row = 0, column = 0, sticky = "nsew", padx = 0, pady = 0, columnspan = 3)

password_label = tkinter.Label(window, text = "Password: ", justify = tkinter.CENTER)
password_label.grid(row = 1, column = 0, sticky = "nsw", padx = 8, pady = 8)

keybox = tkinter.Entry(window, width = 32, show = '*', bd = 2)
keybox.grid(row = 1, column = 1, sticky = "nsw", padx = 8, pady = 8)

def_font = tkinter.font.Font(font = password_label["font"])
def_font["size"] = 12
def_font["weight"] = tkinter.font.NORMAL

textbox.text["font"] = def_font
password_label["font"] = def_font
keybox["font"] = def_font

def encrypt():
    text = textbox.text.get("1.0", tkinter.END + "-1c")
    text = AES256.encrypt(text.encode(), keybox.get().encode())
    textbox.text.delete("1.0", tkinter.END)
    textbox.text.insert("1.0", text)

def decrypt():
    text = textbox.text.get("1.0", tkinter.END + "-1c")
    text = AES256.decrypt(text.encode(), keybox.get().encode())
    textbox.text.delete("1.0", tkinter.END)
    textbox.text.insert("1.0", text)

menubar = tkinter.Menu(window)
menubar.add_command(label = "Encrpyt", command = encrypt)
menubar.add_command(label = "Decrpyt", command = decrypt)

window["menu"] = menubar

window.mainloop()
