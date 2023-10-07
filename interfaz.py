import tkinter as tk
from tkinter import messagebox #Importa para poder ofrecer mensajes de respuesta
import sqlite3 #Importa la base de datos
import re  # Importar el módulo de expresiones regulares
from tkinter import ttk #proporciona el desplegable como el de experiencia
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

class MenuPrincipal: 
    #La clase principal lo que hace es abrir el menú 
    def __init__(self, master):
        self.master = master
        master.title("Menú Principal")
        master.geometry("400x400")

        #De momento lo que hace es abrir una pantalla qcon un texto
        label_menu = tk.Label(master, text="¡Bienvenido al Menú Principal!")
        label_menu.pack()

class InterfazPrincipal:
    #Esta ventana es lo primero que se muestra, donde se comprobará si el usuario y la contraseña están en la base de datos
    def __init__(self, master):
        self.master = master
        master.title("Inicio de Sesión")
        master.geometry("400x400")

        self.label_usuario = tk.Label(master, text="Introduce nombre de usuario:")
        self.label_usuario.pack()

        self.entrada_usuario = tk.Entry(master)
        self.entrada_usuario.pack()

        self.label_contraseña = tk.Label(master, text="Introduce contraseña:")
        self.label_contraseña.pack()

        self.entrada_contraseña = tk.Entry(master, show="*")
        self.entrada_contraseña.pack()

        self.boton = tk.Button(master, text="Enviar", command=self.verificar_credenciales)
        self.boton.pack()

        self.enlace_label = tk.Label(master, text="Ir a la Segunda Interfaz", fg="blue", cursor="hand2")
        self.enlace_label.pack()
        self.enlace_label.bind("<Button-1>", lambda e: self.mostrar_segunda_interfaz())

    def verificar_credenciales(self):
        # Obtener los valores de los campos de entrada
        nombre_usuario = self.entrada_usuario.get()
        contraseña = self.entrada_contraseña.get()

        # Verificar las credenciales en la base de datos (o tu lógica de verificación)
        if self.verificar_en_base_de_datos(nombre_usuario, contraseña):
            messagebox.showinfo("Acceso Permitido", "Inicio de sesión exitoso.")
            self.mostrar_menu_principal()
        else:
            messagebox.showerror("Error de Inicio de Sesión", "Nombre de usuario o contraseña incorrectos.")


    def verificar_en_base_de_datos(self, nombre_usuario, contraseña):
        print(f"Verificando credenciales para usuario: {nombre_usuario}")
        conexion = sqlite3.connect("registro.db")

        try:
            cursor = conexion.cursor()
            cursor.execute('''
                SELECT contraseña
                FROM usuarios
                WHERE nombre_usuario = ?
            ''', (nombre_usuario,))

            resultado = cursor.fetchone()

            if resultado:
                contraseña_almacenada = resultado[0]
                if self.verificar_contraseña(contraseña, contraseña_almacenada):
                    return True

            print(f"Contraseña almacenada en la base de datos: {contraseña_almacenada}")

            if self.verificar_contraseña(contraseña, contraseña_almacenada):
                print("Contraseña verificada con éxito.")
                return True
            else:
                print("Contraseña incorrecta.")
            return False
        finally:
            conexion.close()

    def verificar_contraseña(self, contraseña, contraseña_almacenada):
        if len(contraseña) < 8:
            print("La contraseña debe tener al menos 8 caracteres.")
            return False

        salt = bytes.fromhex(contraseña_almacenada[:32])
        clave_almacenada = contraseña_almacenada[32:]

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(contraseña.encode("utf-8"))

        return key == bytes.fromhex(clave_almacenada)
        
    def mostrar_segunda_interfaz(self):
        self.segunda_interfaz = SegundaInterfaz(self.master)

    def guardar_contraseña(self, contraseña):
        # Generar un salt aleatorio
        salt = os.urandom(16)

        # Derivar la clave usando Scrypt
        kdf = Scrypt(
            salt=bytes(salt),
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(contraseña.encode("utf-8"))

        # Devolver la concatenación del salt y la clave derivada como bytes
        return salt + key

class SegundaInterfaz:
    def __init__(self, master):
        self.master = tk.Toplevel(master)
        self.master.title("Segunda Interfaz")
        self.master.geometry("400x400")

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
        opciones_experiencia = ["Ninguna", "Poca", "Media", "Alta", "Modo Dios"]

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

        self.boton_registrarse = tk.Button(self.master, text="Registrarse", command=self.registrarse)
        self.boton_registrarse.pack()

    def registrarse(self):
        try:
            # Obtener los valores de los campos de entrada
            nombre_usuario = self.entrada_nombre_usuario.get()
            contraseña = self.entrada_contraseña.get()

            # Utilizar la función para guardar la contraseña de manera segura
            interfaz_principal = InterfazPrincipal(self.master)
            hashed_password = interfaz_principal.guardar_contraseña(contraseña)

            experiencia = self.combobox_experiencia.get()  # Obtener el valor seleccionado del combobox
            correo = self.entrada_correo.get()
            nombre_apellidos = self.entrada_nombre_apellidos.get()
            ciudad = self.entrada_ciudad.get()

            # Validar el formato del correo electrónico
            if not self.validar_correo(correo):
                messagebox.showerror("Error", "El correo es incorrecto")
                return

            self.guardar_en_base_de_datos(nombre_usuario, contraseña, experiencia, correo, nombre_apellidos, ciudad)

            # Mostrar un mensaje de éxito
            messagebox.showinfo("Registro Completado", "Registro completado con éxito.")

            # Cerrar la ventana actual y volver a la ventana principal
            self.master.destroy()

        except Exception as e: #para que me salte las excepciones si pasa algo 
            messagebox.showerror("Error", f"Error al registrar: {str(e)}")

    def guardar_en_base_de_datos(self, nombre_usuario, contraseña, experiencia, correo, nombre_apellidos, ciudad):
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
                contraseña TEXT
            )
        ''')

        # Utilizar la función para guardar la contraseña de manera segura
        hashed_password = InterfazPrincipal(self.master).guardar_contraseña(contraseña)
        
        # Insertar los datos en la tabla
        cursor.execute('''
            INSERT INTO usuarios (nombre_usuario, contraseña, experiencia, correo, nombre_apellidos, ciudad)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (nombre_usuario, contraseña, experiencia, correo, nombre_apellidos, ciudad))

        # Guardar los cambios y cerrar la conexión
        conexion.commit()
        conexion.close()

    def validar_correo(self, correo):
        # Utilizar una expresión regular para validar el formato del correo electrónico
        patron_correo = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        return patron_correo.match(correo) is not None

if __name__ == "__main__":
    root = tk.Tk()
    app = InterfazPrincipal(root)
    root.mainloop()
