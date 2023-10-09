import tkinter as tk
from tkinter import messagebox #Importa para poder ofrecer mensajes de respuesta
import sqlite3 #Importa la base de datos
import re  # Importar el módulo de expresiones regulares
from tkinter import ttk #proporciona el desplegable como el de experiencia
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

class Main:
    #Esta es la función principal donde se van a ejecutar las cosas
    def __init__(self):
        #Inicializar las interfaces y sus funciones
        root = tk.Tk()
        self.menu = MenuPrincipal(root)
        self.interfaz_inicio = InterfazInicio(root)
        self.interfaz_registro = InterfazRegistro
        root.mainloop()


class MenuPrincipal: 
    #Creación de la interafaz del menú principal
    def __init__(self, master):
        #Inicializa el menu
        self.master = master
        self.interfaz_menu_principal()

    def interfaz_menu_principal(self):
        #Ya desarrolla la interfaz
        self.master.title("Menú Principal")
        self.master.geometry("400x400")
        label_menu = tk.Label(self.master, text="¡Bienvenido al Menú Principal!")
        label_menu.pack()

class InterfazInicio:
    #Creación de la interfaz inicio
    def __init__(self, master):
        #Inicializa la Interfaz del Inicio
        self.master = master
        self.interfaz_inicial()

    def interfaz_inicial(self):
        #Inicializa lo que pide en esta interfaz
        self.master.title("Inicio de Sesión")
        self.master.geometry("400x400")

        self.label_usuario = tk.Label(self.master, text="Introduce nombre de usuario:") #Pide el nombre del usuario, lo que enseña la interfaz
        self.label_usuario.pack()

        self.entrada_usuario = tk.Entry(self.master) #Permite escribir en el apartado de nombre del usuario
        self.entrada_usuario.pack()

        self.label_contraseña = tk.Label(self.master, text="Introduce contraseña:") #Pide la contraseña 
        self.label_contraseña.pack()

        self.entrada_contraseña = tk.Entry(self.master, show="*") #Hace que al escribir la contraseña se escriba en *
        self.entrada_contraseña.pack()

        self.boton = tk.Button(self.master, text="Enviar", command=self.verificar_credenciales) #Si le da a enviar, salta a la funciona que verifica los datos
        self.boton.pack()

        self.enlace_label = tk.Label(self.master, text="Registrarse", fg="blue", cursor="hand2") #Si no estas registrado, puedes registrarte en otra ventana
        self.enlace_label.pack()
        self.enlace_label.bind("<Button-1>", lambda e: self.mostrar_segunda_interfaz())

class InterfazRegistro:
    #Creación de la interfaz de registro
    def __init__(self, master):
        #
        self.master = tk.Toplevel(master)
        self.interfaz_registro()

    def interfaz_registro(self):
        #Inicializa las cosas que aparecen en la interfaz de registro
        self.master.title("Registro")
        self.master.geometry("400x400")

        self.configurar_campos() #Se llama a todos los campos que se piden

        self.boton_registrarse = tk.Button(self.master, text="Registrarse", command=self.registrarse) #Se da al botón de registrarse y ahi se producen la funcion registrarse
        self.boton_registrarse.pack()

    def configurar_campos(self):
        #Se inicializa lo que se pide en el registro
        self.label_nombre_apellidos = tk.Label(self.master, text="Nombre y Apellidos:")
        self.label_nombre_apellidos.pack()

        self.entrada_nombre_apellidos = tk.Entry(self.master)
        self.entrada_nombre_apellidos.pack()

        self.label_correo = tk.Label(self.master, text="Correo:")
        self.label_correo.pack()

        self.entrada_correo = tk.Entry(self.master)
        self.entrada_correo.pack()

        self.label_ciudad = tk.Label(self.master, text="Ciudad:")
        self.label_ciudad.pack()

        self.entrada_ciudad = tk.Entry(self.master)
        self.entrada_ciudad.pack()

        self.label_experiencia = tk.Label(self.master, text="Experiencia:")
        self.label_experiencia.pack()

        # Opciones para el menú desplegable de experiencia
        opciones_experiencia = ["Cero Patatero", "Poca", "Media", "Alta", "Modo Dios"]

        self.combobox_experiencia = ttk.Combobox(self.master, values=opciones_experiencia, state="readonly")
        self.combobox_experiencia.pack()

        self.label_nombre_usuario = tk.Label(self.master, text="Nombre de Usuario:")
        self.label_nombre_usuario.pack()

        self.entrada_nombre_usuario = tk.Entry(self.master)
        self.entrada_nombre_usuario.pack()

        self.label_contraseña = tk.Label(self.master, text="Contraseña:")
        self.label_contraseña.pack()

        self.entrada_contraseña = tk.Entry(self.master, show="*")
        self.entrada_contraseña.pack()

    def registrarse(self):
        try:
            # Obtener los valores de los campos de entrada
            nombre_usuario = self.entrada_nombre_usuario.get()
            contraseña = self.entrada_contraseña.get()
            hashed_password = self.guardar_contraseña(contraseña) # Utilizar la función para guardar la contraseña de manera segura
            experiencia = self.combobox_experiencia.get()  # Obtener el valor seleccionado del combobox
            correo = self.entrada_correo.get()
            nombre_apellidos = self.entrada_nombre_apellidos.get()
            ciudad = self.entrada_ciudad.get()

            if not self.validar_correo(correo): # Validar el formato del correo electrónic
                messagebox.showerror("Error", "El correo es incorrecto")
                # Cerrar la ventana actual y volver a la ventana principal
                self.master.destroy()
                return
            
            self.guardar_en_base_de_datos(nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, hashed_password) #Los guardo en la base de datos 
            messagebox.showinfo("Registro Completado", "Registro completado con éxito.") # Mostrar un mensaje de éxito
            self.master.destroy()

        except Exception as e: #para que me salte las excepciones si pasa algo 
            messagebox.showerror("Error", f"Error al registrar: {str(e)}")

    def validar_correo(self, correo):
        # Verifica que el correo tiene el formato correcto
        patron_correo = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        return patron_correo.match(correo) is not None

    def guardar_contraseña(self, contraseña): #revisar con alex
        # Lógica para guardar la contraseña de manera segura
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(contraseña.encode("utf-8"))
        return key #no se si guardar el salt o no 
    
    def guardar_en_base_de_datos(self, nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, hashed_password):
        # Conectar a la base de datos (creará la base de datos si no existe)
        conexion = sqlite3.connect("registro.db")

        # Crear un cursor
        cursor = conexion.cursor()

        # Crear la tabla si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre_apellidos TEXT,
                correo TEXT,
                ciudad TEXT,
                experiencia TEXT,
                nombre_usuario TEXT,
                hashed_password TEXT  
            )
        ''')

        # Insertar los datos en la tabla    
        cursor.execute('''
            INSERT INTO usuarios (nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, key) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, hashed_password))

        # Guardar los cambios y cerrar la conexión
        conexion.commit()
        conexion.close()




if __name__ == "__main__":
    main = Main()
