from tkinter import *
from tkinter import messagebox
from random import *
import json
from cryptography.fernet import Fernet,MultiFernet
import bcrypt
import os
import re
import base64

mp=""
vk=""
ak=""

letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
           'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
           'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M'
           'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

def create_vault_key(x,salt):
    return bcrypt.hashpw(x.encode(),salt)

def create_auth_key(x,y,salt):
    key=x+y.decode()
    return bcrypt.hashpw(key.encode(),salt)

def encrypt_data(vault_key, data):
    derive_keys = []

    for key in vault_key:
        derive_key = bcrypt.kdf(
            password=key,
            salt=b'\xbf\xdf \xd2\x00\xae\x99\xbb\x0f\x80\xdb\xbf;\\9\x7f',
            desired_key_bytes=32,
            rounds=100
        )
        derive_keys.append(Fernet(base64.urlsafe_b64encode(derive_key)))

    f = MultiFernet(derive_keys)
    return f.encrypt(data.encode())

def decrypt_data(vault_key, data):
    derive_keys = []

    for key in vault_key:
        derive_key = bcrypt.kdf(
            password = key,
            salt=b'\xbf\xdf \xd2\x00\xae\x99\xbb\x0f\x80\xdb\xbf;\\9\x7f',
            desired_key_bytes=32,
            rounds=100
        )
        derive_keys.append(Fernet(base64.urlsafe_b64encode(derive_key)))

    f = MultiFernet(derive_keys)
    print(type(f))
    return f.decrypt(data)

def generate():
    nl=""
    for i in range(0,randint(6, 10)):
        l=choice(letters)
        nl+=l

    nn=""
    for i in range(0, randint(4, 9)):
        n=choice(numbers)
        nn+=n

    ns=""
    for i in range(0, randint(4, 9)):
        s=choice(symbols)
        ns+=s

    g=list(nl+nn+ns)
    v=sample(g,len(g))

    c1="".join(v)

    return c1

def store_key(filename,key):
    f=open(filename,"w+")
    f.write(key)
    f.close()

def get_key(filename):
    try:
        f=open(filename,"r+")
        key=f.read()
        f.close()
        return key
    except:
        return ""

def check_strength(v):
    if(len(v)>=8):
        if(bool(re.match('((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,30})',v))==True):
            messagebox.showinfo(title="Strength",message="Strong")
        elif(bool(re.match('((\d*)([a-z]*)([A-Z]*)([!@#$%^&*]*).{8,30})',v))==True):
            messagebox.showinfo(title="Strength",message="Weak")
    else:
        messagebox.showinfo(title="Strength",message="Weak")




LARGEFONT=("Verdana", 35)



def indicate(lb):
    lb.config()

class tkinterApp(Tk):
    # __init__ function for class tkinterApp
    def __init__(self, *args, **kwargs):
        Tk.__init__(self, *args, **kwargs)

        container=Frame(self)
        container.pack(side = "top", fill = "both", expand = True)

        container.grid_rowconfigure(0, weight = 1)
        container.grid_columnconfigure(0, weight = 1)

        self.frames = {}

        for F in (newUser, existingUser, securityQ, home, newLogin):
            frame=F(container, self)
            self.frames[F]=frame
            frame.grid(row=0, column=0, sticky="nsew")
                        
        if('key.txt' not in os.listdir(os.getcwd())):
            self.show_frame(newUser)
            print("1")
        else:
            self.show_frame(existingUser)
            print("2")
    
    def show_frame(self, cont):
        frame=self.frames[cont]
        frame.tkraise()







class newUser(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)

        fo=font=['Merriweather', 14, 'normal']

        # canv=Canvas(self, width=300, height=200)
        # canv.grid(column=2, row=1)

        # pic=PhotoImage(file="password.png")
        # canv.create_image(100, 100, image=pic)

        mp=Label(self, text='Enter Master Password   :', font=fo)
        mp.grid(column=1, row=2, sticky='e', padx=7)
        m_e=Entry(self, width=39, font=fo)
        m_e.grid(row=2, column=2, columnspan=2, pady=7)
        m_e.focus()

        cmp=Label(self, text='Confirm Master Password   :', font=fo)
        cmp.grid(column=1, row=3, sticky='e', padx=7)
        c_e=Entry(self, width=39, font=fo)
        c_e.grid(row=3, column=2, columnspan=2, pady=7)
        c_e.focus()

        q1=Label(self, text='Enter Security Question 1   :', font=fo)
        q1.grid(column=1, row=4, sticky='e', padx=7)
        q1_e=Entry(self, width=39, font=fo)
        q1_e.grid(row=4, column=2, columnspan=2, pady=7)
        q1_e.focus()

        ans1=Label(self, text='Answer   :', font=fo)
        ans1.grid(column=1, row=5, sticky='e', padx=7)
        ans1_e=Entry(self, width=39, font=fo)
        ans1_e.grid(row=5, column=2, columnspan=2, pady=7)
        ans1_e.focus()

        q2=Label(self, text='Enter Security Question 2   :', font=fo)
        q2.grid(column=1, row=6, sticky='e', padx=7)
        q2_e=Entry(self, width=39, font=fo)
        q2_e.grid(row=6, column=2, columnspan=2, pady=7)
        q2_e.focus()

        ans2=Label(self, text='Answer   :', font=fo)
        ans2.grid(column=1, row=7, sticky='e', padx=7)
        ans2_e=Entry(self, width=39, font=fo)
        ans2_e.grid(row=7, column=2, columnspan=2, pady=7)
        ans2_e.focus()

        gen=Button(self, text="Generate Password", command=lambda: add_mp(m_e,c_e), font=['Merriweather', 10, 'normal'])
        gen.grid(column=3, row=8)

        check=Button(self, text='Check Password Strength', command=lambda: check_strength(m_e.get()), font=['Merriweather', 10, 'normal'])
        check.grid(column=3, row=9)

        go=Button(self, text='Proceed', command=lambda: new_user_proceed(controller,m_e.get(),c_e.get(),q1_e.get(),ans1_e.get(),q2_e.get(),ans2_e.get()), font=['Merriweather', 10, 'normal'])
        go.grid(column=3, row=10)

        back = Button(self, text = 'Back', command = lambda:controller.show_frame(home), font=['Merriweather', 10, 'normal'])
        back.grid(column=3, row = 11)

def new_user_proceed(controller,p,conf_p,q1,ans1,q2,ans2):
    global mp,vk,ak
    if(len(p)==0 or len(conf_p)==0 or len(q1)==0 or len(ans1)==0 or len(q2)==0 or len(ans2)==0):
        messagebox.showerror("A field is empty")
    elif(p==conf_p):
        mp=p
        salt=bcrypt.gensalt()
        vk=create_vault_key(mp,salt)
        ak=create_auth_key(mp,vk,salt)
        store_key("salt.txt",salt.decode())
        store_key("key.txt",ak.decode())
        store_key("Q1.txt",q1)
        store_key("A1.txt",create_vault_key(ans1,salt).decode())
        store_key("Q2.txt",q2)
        store_key("A2.txt",create_vault_key(ans2,salt).decode())
        store_key("key_backup.txt", encrypt_data([ans1.encode(), ans2.encode()], mp).decode())
        controller.show_frame(home)
        print("3")
    else:
        messagebox.showerror(title="Oops",message="Password could not be confirmed")

def add_mp(p_e1,p_e2):
    p=generate()
    p_e1.delete(0, END)
    p_e1.insert(END, p)
    p_e2.delete(0, END)
    p_e2.insert(END, p)





class existingUser(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)

        fo=font=['Merriweather', 14, 'normal']

        # canv = Canvas(self, width=300, height=200)
        # canv.grid(column=2, row=1)

        # pic = PhotoImage(file="password.png")
        # canv.create_image(100,100, image=pic)

        mp=Label(self, text='Enter Master Password   :', font=fo)
        mp.grid(column=1, row=2, sticky='e', padx=7)
        m_e=Entry(self, show="*", width=39, font=fo)
        m_e.grid(row=2, column=2, columnspan=2, pady=7)
        m_e.focus()

        go=Button(self, text="Proceed", command=lambda: existing_user_proceed(controller,m_e), font=['Merriweather', 10, 'normal'])
        go.grid(column=3, row=3)

        check=Button(self, text='Forgot Password', width=42, command=lambda: controller.show_frame(securityQ), font=['Merriweather', 10, 'normal'])
        check.grid(column=3, row=4, columnspan=1, pady=7, padx=5)

def existing_user_proceed(controller,s):
    global mp,vk,ak
    mp=s.get()
    s.delete(0, END)
    salt=get_key("salt.txt").encode()
    vk=create_vault_key(mp,salt)
    ak=create_auth_key(mp,vk,salt)
    print(ak)
    print(get_key("key.txt"))
    if(get_key("key.txt")==ak.decode()):
        print("31")
        controller.show_frame(home)
    else:
        messagebox.showerror(title="Oops", message="Wrong Password")





class securityQ(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)

        fo=font=['Merriweather', 14, 'normal']

        # canv = Canvas(self, width=300, height=200)
        # canv.grid(column=2, row=1)

        # pic = PhotoImage(file="password.png")
        # canv.create_image(100,100, image=pic)

        q1=Label(self, text=str(get_key("Q1.txt"))+'   :', font=fo)
        q1.grid(column=1, row=2, sticky='e', padx=7)
        q1_e=Entry(self, width=39, font=fo)
        q1_e.grid(row=2, column=2, columnspan=2, pady=7)
        q1_e.focus()

        q2=Label(self, text=str(get_key("Q2.txt"))+'   :', font=fo)
        q2.grid(column=1, row=3, sticky='e', padx=7)
        q2_e=Entry(self, width=39, font=fo)
        q2_e.grid(row=3, column=2, columnspan=2, pady=7)
        q2_e.focus()

        go=Button(self, text="Proceed", command=lambda: security_q_proceed(controller,q1_e.get(),q2_e.get()), font=['Merriweather', 10, 'normal'])
        go.grid(column=3,row=4)

def security_q_proceed(controller,a1,a2):
    salt=get_key("salt.txt").encode()
    if(get_key("A1.txt")==create_vault_key(a1,salt).decode() and get_key("A2.txt")==create_vault_key(a2,salt).decode()):
        mp=decrypt_data([a1.encode(), a2.encode()], get_key("key_backup.txt").encode()).decode()
        vk = create_vault_key(mp,salt)
        ak = create_auth_key(mp,vk,salt)
        messagebox.showinfo(title="Master Password", message=f'Your master password was {mp}')
        controller.show_frame(home)
        print("32")
    else:
        messagebox.showerror(title="Oops", message="Wrong Answers")





class home(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)

        fo=font=['Merriweather', 14, 'normal']

        # canv = Canvas(self, width=300, height=200)
        # canv.grid(column=2, row=1)

        # pic = PhotoImage(file="password.png")
        # canv.create_image(100,100, image=pic)

        web = Label(self, text='Website   :', font=fo)
        web.grid(column=1, row=2, sticky='e', padx=7)
        w_e = Entry(self, width=39, font=fo)
        w_e.grid(row=2, column=2, columnspan=2, pady=7)
        w_e.focus()

        find = Button(self, text='Find Website Info', width=42, command=lambda: get_info(w_e.get()), font=['Merriweather', 10, 'normal'])
        find.grid(column=3, row=3)

        new = Button(self, text='Add New Website Info', width=42, command=lambda: controller.show_frame(newLogin), font=['Merriweather', 10, 'normal'])
        new.grid(column=3, row=4, columnspan=1, pady=7, padx=5)

        # set = Button(self, text='Edit Master Login Info', width=42, command=lambda: controller.show_frame(newUser), font=['Merriweather', 10, 'normal'])
        # set.grid(column=3, row=5, columnspan=1, pady=7, padx=5)

        logout = Button(self,text= "Logout", command = lambda: controller.show_frame(existingUser), font=['Merriweather', 10, 'normal'])
        logout.grid(column=3, row = 6)

def get_info(website):
    website = website.lower()
    if len(website) == 0:
        messagebox.showerror(title='Error', message='No website entered!')
        return None
    try:
        with open('Data.json', mode='r') as data:
            f=json.load(data)

    except FileNotFoundError:
        messagebox.showinfo(title='Error', message=f'Data for {website} does not exist!')
    
    else:
        if website in f:
            messagebox.showinfo(title=website, message=f'Email/Username : {decrypt_data([vk],f[f"{website}"]["email"].encode()).decode()}\n\nPassword : {decrypt_data([vk],f[f"{website}"]["password"].encode()).decode()}')
        elif website not in f:
            messagebox.showerror(title='Error', message=f'Data for {website} does not exist!')






class newLogin(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)

        fo=font=['Merriweather', 14, 'normal']

        # canv = Canvas(self, width=300, height=200)
        # canv.grid(column=2, row=1)

        # pic = PhotoImage(file="password.png")
        # canv.create_image(100,100, image=pic)

        web = Label(self, text='Website   :', font=fo)
        web.grid(column=1, row=2, sticky='e', padx=7)
        w_e = Entry(self, width=39, font=fo)
        w_e.grid(row=2, column=2, columnspan=2, pady=7)
        w_e.focus()

        em = Label(self, text='Email/Username   :', font=fo)
        em.grid(column=1, row=3, padx=7)
        em_e = Entry(self, width=39, font=fo)
        em_e.grid(column=2, row=3, columnspan=2, pady=7)
        em_e.insert(0, 'example@mail.com')

        pas = Label(self, text='Password   :', font=fo)
        pas.grid(column=1, row=4, sticky='e', padx=7, pady=7)
        pas_e = Entry(self, width=30, font=fo)
        pas_e.grid(column=2, row=4)

        gen = Button(self, text="Generate Password", command=lambda: add_p(pas_e), font=['Merriweather', 10, 'normal'])
        gen.grid(column=3, row=5)

        save = Button(self, text="Save Info", command=lambda: save_info(controller,w_e,em_e,pas_e), font=['Merriweather', 10, 'normal'])
        save.grid(column=3, row=6)

        back = Button(self,text = "Back", command = lambda : controller.show_frame(home), font=['Merriweather', 10, 'normal'])
        back.grid(column = 3, row = 7)

def save_info(controller,website,email,password):
    d={
        website.get().lower():
            {
            "email" : encrypt_data([vk],email.get()).decode(), 
            "password" : encrypt_data([vk],password.get()).decode()
        }
    }
    if len(website.get()) != 0 and len(email.get()) != 0 and len(password.get()) != 0 :
        try:
            with open('Data.json', mode='r') as data:
                od = json.load(data)
                od.update(d)
        except FileNotFoundError:
            with open('Data.json', mode='w') as data:
                json.dump(d, data, indent=4)
        else:
            with open('Data.json', mode='w') as data:
                json.dump(od, data, indent=4)
        
        controller.show_frame(home)
        messagebox.showinfo(title='Password Manager', message="Successfully Saved")
        website.delete(0,END)
        email.delete(0,END)
        password.delete(0,END)

    else:
        messagebox.showwarning(title="Error", message="Don't leave any field empty")

def add_p(p_e):
    p=generate()
    p_e.delete(0, END)
    p_e.insert(END, p)






w = tkinterApp()
w.title('Password Manager')
w.config(pady=70, padx=70)
w.mainloop()
