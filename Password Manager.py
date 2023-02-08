import hashlib
import tkinter as tk
from tkinter import *
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import random
import string
global hex_hash 

def login_page2():

    
    def destroy_reg():
        root.destroy()
        register()
    def destroy_man():
        root.destroy()
        Password_Manager()
        
    root = tk.Tk()
    Entry1 = tk.Entry(root)
    Entry2 = tk.Entry(root)
    global key
    global iv
    root.title("Password Manager") 
    root.config(bg='#F6EFF2')
    root.tk.call('tk', 'scaling', 1.5)
    root.geometry("161x150")
    label= tk.Label(root, text="LOGIN", bg='#F6EFF2', fg="#000000", font=("TkDefaultFont", 10, "bold"))
    label2 = tk.Label(root,text="Username")
    label3 = tk.Label(root, text="Password")
    def login_button():
        if os.path.exists('Login.txt'):
            with open('Login.txt', 'r') as read_file:
                lines = read_file.readlines()
                position = None
                username = Entry1.get().encode('utf-8')
                password = Entry2.get().encode('utf-8')

                hash_object = hashlib.sha3_512()
                hash_object.update(username)
                hex_username = hash_object.hexdigest()

                hash_object = hashlib.sha3_512()
                hash_object.update(password)
                hex_password = hash_object.hexdigest()

                for line_number, line in enumerate(lines):
                    if line.strip() == hex_username:
                        position = line_number + 1
                        break

                if position:
                    if lines[position].strip() == hex_password:
                        print("Login successful")
                        destroy_man()
                    else:
                        print("Incorrect password")
                else:
                    print("Username not registered")
        else:
            print("Login.txt file not found")


                        
    
    
    
    button2 = tk.Button(root,bg='#F6EFF2', text="Register", fg='#0000EE',bd=0, command=destroy_reg)
    button= tk.Button(root, text="Login",bg='#E80F82', font=("TkDefaultFont", 10, "bold",),bd=0,command=login_button)


    label.pack(side='top')
    label2.pack(side='top')
    Entry1.pack()

    label3.pack(side='top')
    Entry2.pack()
    button2.pack(side='top', fill='both')
    button.pack(side='top',fill='both')


    root.mainloop()



def data_list():
    
    root = tk.Tk()
    root.update()
    root.title("")
    root.config(bg='#F6EFF2')
    root.tk.call('tk', 'scaling', 1.5)
    root.geometry("300x285")

    Entry1 = tk.Text(root)       
    Entry1.pack(side='top', fill='both')       
    global decrypted_message
    def on_closing():
        root.destroy()
        Password_Manager()
    root.protocol("WM_DELETE_WINDOW", on_closing)       
            
    def decrypt(ciphertext, key, iv):
        key = b'\xd2Y\xad\xa4\xc1e\xd4#f\xe9\x04\xf5^\x9c\xe8\xa9'
        iv = b'\xd2Y\xad\xa4\xc1e\xd4#f\xe9\x04\xf5^\x9c\xe8\xa9'
        ciphertext = base64.b64decode(ciphertext)        
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()       
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()       
        pad = plaintext[-1]      
        plaintext = plaintext[:-pad]    
        return plaintext.decode() 
    
    
    data = []
    key = b'\xd2Y\xad\xa4\xc1e\xd4#f\xe9\x04\xf5^\x9c\xe8\xa9'
    iv = b'\xd2Y\xad\xa4\xc1e\xd4#f\xe9\x04\xf5^\x9c\xe8\xa9'
    with open("DataBase.txt", "r") as file:
        lines = file.readlines()
        for i in range(0, len(lines), 3):
            line1 = lines[i].strip()
            line2 = lines[i + 1].strip()
            line = lines[i + 2]
            decrypted_password = decrypt(line, key, iv)
            data.append((line1, line2, decrypted_password))

    data_str = '\n'.join([f"{item[0]} {item[1]} {item[2]}" for item in data])
    Entry1.insert("1.0", data_str) 
    root.update()

    
def password_generator():
    root = tk.Tk()
    root.update()
    root.title("Password Generator")
    root.config(bg='#333333')
    root.resizable(False, False)
    root.tk.call('tk', 'scaling', 1.5)
    upper_case_on_off = tk.IntVar()
    custom_set_on_or_off = tk.IntVar()
    digits_on_or_off = tk.IntVar()
    special_characters_on_or_off = tk.IntVar()
    global password
    characters = 15 
    lowercase = string.ascii_lowercase
    password = ''.join(random.choices(lowercase, k = characters)) 
    def on_closing():
        root.destroy()
        Password_Manager()
    root.protocol("WM_DELETE_WINDOW", on_closing) 
    def password_check_list():
        global password
        if upper_case_on_off.get() == 1 and digits_on_or_off.get() == 0 and special_characters_on_or_off.get() == 0:
            upper_case = string.ascii_letters
            password = ''.join(random.choices(upper_case, k = characters))
            
        elif upper_case_on_off.get() == 0 and digits_on_or_off.get() == 1 and special_characters_on_or_off.get() == 0:
            digit = string.digits + string.ascii_lowercase
            password = ''.join(random.choices(digit, k = characters))
            
        elif upper_case_on_off.get() == 0 and digits_on_or_off.get() == 0 and special_characters_on_or_off.get() == 1:
            punctuation = string.punctuation + string.ascii_lowercase
            password = ''.join(random.choices(punctuation, k = characters))  
            
        elif upper_case_on_off.get() == 1 and digits_on_or_off.get() == 1 and special_characters_on_or_off.get() == 0:
            upper_case_and_digits = string.digits + string.ascii_letters
            password = ''.join(random.choices(upper_case_and_digits, k = characters))       
            
        elif upper_case_on_off.get() == 0 and digits_on_or_off.get() == 1 and special_characters_on_or_off.get() == 1:
            digits_and_punctuation = string.digits + string.punctuation
            password = ''.join(random.choices(digits_and_punctuation , k = characters))         
            
        elif upper_case_on_off.get() == 1 and digits_on_or_off.get() == 0 and special_characters_on_or_off.get() == 1:
            upper_case_and_punctuation = string.ascii_letters + string.punctuation
            password = ''.join(random.choices(upper_case_and_punctuation , k = characters))            
            
        elif upper_case_on_off.get() == 1 and digits_on_or_off.get() == 1 and special_characters_on_or_off.get() == 1:
            custom_set = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choices(custom_set, k = characters)) 
        elif upper_case_on_off.get() == 0 and digits_on_or_off.get() == 0 and special_characters_on_or_off.get() == 0:
            lowercase = string.ascii_lowercase
            password = ''.join(random.choices(lowercase, k = characters))   
            
    def print_password():
        global password
        password_check_list()
        text_box.config(state='normal')
        text_box.delete(0, 'end')
        text_box.insert(0, password)
        text_box.config(state='readonly')
        
    label = tk.Button(root, text="Create your password", bg='#333333', fg='#ffffff', command= print_password)
    label.pack(side='top')

    check_button1 = tk.Checkbutton(root, text="Upper Case", variable=upper_case_on_off, command= password_check_list)
    check_button2 = tk.Checkbutton(root, text="Digits", variable=digits_on_or_off, command= password_check_list)
    check_button3 = tk.Checkbutton(root, text="Special Characters", variable=special_characters_on_or_off, command= password_check_list)

    text_box = tk.Entry(root, state='disabled')
    text_box.pack(side=tk.BOTTOM, fill='both' )
    check_button1.pack(side='left')
    check_button2.pack(side='left')
    check_button3.pack(side='left')


    root.update()

def register():
    root = tk.Tk()
    global key
    global iv
    root.title("Password Manager")
    root.config(bg='#F6EFF2')
    root.tk.call('tk', 'scaling', 1.5)
    root.geometry("161x153")

 
    Entry1 = tk.Entry(root)
    Entry2 = tk.Entry(root)


    def log_back():
        root.destroy()
        login_page2()
       
    
        
        


    def hashing():
        Username = Entry1.get().encode('utf-8')
        Password = Entry2.get().encode('utf-8')
        global hex_hash
        data = Password
        hash_object = hashlib.sha3_512()
        hash_object.update(data)
        hex_hash = hash_object.hexdigest()

        data2 = Username
        hash_object2 = hashlib.sha3_512()
        hash_object2.update(data2)
        hex_hash2 = hash_object2.hexdigest()  
        
        if Password == Username:
            print("Cannot have Username and Password the same")
        else:
            if os.path.exists('Login.txt'):
                with open('Login.txt', 'r') as read_file:
                    content = read_file.read()
                    if hex_hash2 in content:
                        print("Username already registered")  
                    else:
                        with open('Login.txt', 'a') as file:
                            file.write(hex_hash2 + '\n')
                            file.write(hex_hash + '\n')
                            file.close()
                            print("Registration successful")
                            root.destroy()
                            login_page2()
                
   
   
    label= tk.Label(root, text="Registration", bg='#F6EFF2', fg="#000000", font=("TkDefaultFont", 10, "bold"))
    label2 = tk.Label(root,text="Username")
    label3 = tk.Label(root, text="Password")
    button2 = tk.Button(root,bg='#F6EFF2', text="Back to login", fg='#0000EE',bd=0,command=log_back)
    button= tk.Button(root, text="Register",bg='#E80F82', font=("TkDefaultFont", 10, "bold",),bd=0, command=hashing)
    label.pack(side='top')
    label2.pack(side='top')
    Entry1.pack()

    label3.pack(side='top')
    Entry2.pack()
    button2.pack(side='top', fill='both')
    button.pack(side='top',fill='both')
    root.mainloop()


def Password_Manager():
    manager = tk.Tk()
    
    manager.update()
    manager.title("")
    manager.config(bg='#F6EFF2')
    manager.geometry("175x255")
    manager.resizable(True,True)
    
    label1 = tk.Label(manager,text="Password Manager")
    label2 = tk.Label(manager,)
    label3 = tk.Label(manager, text="Website")
    label4 = tk.Label(manager, text="Username")
    label5 = tk.Label(manager, text="Password")
    label6 = tk.Label(manager, text="")
    
    Entry1 = tk.Entry(manager)
    Entry2 = tk.Entry(manager)
    Entry3 = tk.Entry(manager)




    
    
    
    def save_data():
        key = b'\xd2Y\xad\xa4\xc1e\xd4#f\xe9\x04\xf5^\x9c\xe8\xa9'
        iv = b'\xd2Y\xad\xa4\xc1e\xd4#f\xe9\x04\xf5^\x9c\xe8\xa9'
        website = Entry1.get()
        username = Entry2.get()
        password = Entry3.get()
        if os.path.exists('Database.txt'):
            with open('Database.txt', 'a') as file:
                file.write(str(website + '\n'))
                
        if os.path.exists('Database.txt'):
            with open('Database.txt', 'a') as file:
                file.write(str(username + '\n'))
        def encrypt(plaintext, key, iv):
            encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
            pad = 16 - (len(plaintext) % 16)
            plaintext = plaintext + pad * chr(pad)
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            return base64.b64encode(ciphertext).decode()


                
        def encrypt_message(file_name):
            message = password
            encrypted_message = encrypt(message, key, iv)
            with open(file_name, 'a') as f:
                f.write(encrypted_message + '\n')
        encrypt_message("Database.txt")   

 

    def exit_and_data_list():
        manager.destroy()
        data_list()
        
    
    def exit_and_password_generator():
        manager.destroy()
        password_generator()
        
        
    
    button1 = tk.Button(manager, text="Save Data", bd=0.5,bg="#F6EFF2", command=save_data)
    button2 = tk.Button(manager,text="Data List", bd=0.5,bg="#F6EFF2",command=exit_and_data_list )
    button3 = tk.Button(manager,text="Generate Password", bd=0.5, bg="#F6EFF2",command=exit_and_password_generator)
    
    
    
    
    label1.pack(side='top')
    label2.pack(side='top')
    label3.pack(side='top')
    Entry1.pack(side='top')
    label4.pack(side='top')
    Entry2.pack(side='top')
    label5.pack(side='top')
    Entry3.pack(side='top')
    label6.pack(side='top')
    button1.pack(side='top',fill='both')
    button2.pack(side='top',fill='both')
    button3.pack(side='top',fill='both')
    

    
    manager.update()
    manager.mainloop()

    


def login_page():

    
    def destroy_reg():
        root.destroy()
        register()
    def destroy_man():
        root.destroy()
        Password_Manager()
        
    root = tk.Tk()
    Entry1 = tk.Entry(root)
    Entry2 = tk.Entry(root)
    root.title("Password Manager") 
    root.config(bg='#F6EFF2')
    root.tk.call('tk', 'scaling', 1.5)
    root.geometry("161x162")
    label= tk.Label(root, text="LOGIN", bg='#F6EFF2', fg="#000000", font=("TkDefaultFont", 10, "bold"))
    label2 = tk.Label(root,text="Username")
    label3 = tk.Label(root, text="Password")
    label4 = tk.Label(root, text="", bg='#FFFFFF')
    def login_button():
        if os.path.exists('Login.txt'):
            with open('Login.txt', 'r') as read_file:
                lines = read_file.readlines()
                position = None
                username = Entry1.get().encode('utf-8')
                password = Entry2.get().encode('utf-8')

                hash_object = hashlib.sha3_512()
                hash_object.update(username)
                hex_username = hash_object.hexdigest()

                hash_object = hashlib.sha3_512()
                hash_object.update(password)
                hex_password = hash_object.hexdigest()

                for line_number, line in enumerate(lines):
                    if line.strip() == hex_username:
                        position = line_number + 1
                        break

                if position:
                    if lines[position].strip() == hex_password:
                        print("Login successful")
                        destroy_man()
                    else:
                        print("Incorrect password")
                else:
                    print("Username not registered")
        else:
            print("Login.txt file not found")


    
    
    button2 = tk.Button(root,bg='#F6EFF2', text="Register", fg='#0000EE',bd=0, command=destroy_reg)
    button= tk.Button(root, text="Login",bg='#E80F82', font=("TkDefaultFont", 10, "bold",),bd=0,command=login_button)


    label.pack(side='top')
    label2.pack(side='top')
    Entry1.pack()

    label3.pack(side='top')
    Entry2.pack()
    button2.pack(side='top', fill='both')
    button.pack(side='top',fill='both')


    root.mainloop()
login_page()




