import tkinter as tk
from tkinter import messagebox #Importa para poder ofrecer mensajes de respuesta
import sqlite3 #Importa la base de datos
import re  # Importar el módulo de expresiones regulares
from tkinter import ttk #proporciona el desplegable como el de experiencia
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

class Main:
    def __init__(self):
        # Inicializa solo la interfaz de inicio
        self.root = tk.Tk()
        self.interfaz_inicio = InterfazInicio(self.root,self)
        self.root.mainloop()

    def mostrar_menu_principal(self, nombre_usuario):
        # Muestra la interfaz del menú principal
        root_menu = tk.Tk()  # <-- Cambiado de self.root a root_menu
        self.menu_principal = MenuPrincipal(root_menu, self, nombre_usuario)
        root_menu.mainloop()

    def mostrar_interfaz_registro(self):
        # Muestra la interfaz de registro
        root_registro = tk.Tk()  # <-- Cambiado de self.root a root_registro
        self.interfaz_registro = InterfazRegistro(root_registro, self)
        root_registro.mainloop()

class MenuPrincipal: 
    #Creación de la interafaz del menú principal
    def __init__(self, master, app, nombre_usuario):
        #Inicializa el menu
        self.master = master
        self.app = app
        self.interfaz_menu_principal(nombre_usuario)

    def interfaz_menu_principal(self,nombre_usuario):
        self.master.title("Menú Principal")
        self.master.geometry("400x400")

        # Crear un notebook (pestañas)
        notebook = ttk.Notebook(self.master)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Pestaña Menú Principal
        pestaña_principal = tk.Frame(notebook)
        notebook.add(pestaña_principal, text="Menú Principal")

        # Obtener datos del usuario desde la base de datos
        datos_usuario = self.obtener_datos_usuario(nombre_usuario)

        # Mostrar datos del usuario
        if datos_usuario:
            for i, (columna, valor) in enumerate(zip(["Nombre y Apellidos", "Correo", "Ciudad", "Experiencia", "Nombre de Usuario"], datos_usuario)):
                label = tk.Label(pestaña_principal, text=f"{columna}: {valor}")
                label.grid(row=i, column=0, sticky=tk.W)
        else:
            mensaje_error_label = tk.Label(pestaña_principal, text="Usuario no encontrado")
            mensaje_error_label.pack()

        # Pestaña Mensajes
        self.crear_pestaña_mensajes(notebook)

        # Pestaña Torneos
        self.crear_pestaña_torneos(notebook)

    def crear_pestaña_mensajes(self, notebook):
        pestaña_mensajes = tk.Frame(notebook)
        notebook.add(pestaña_mensajes, text="Mensajes")

        # Buscador de nombres de usuario
        self.buscador_entry = tk.Entry(pestaña_mensajes)
        self.buscador_entry.grid(row=0, column=0, padx=10, pady=10)

        boton_buscar = tk.Button(pestaña_mensajes, text="Buscar", command=self.abrir_chat)
        boton_buscar.grid(row=0, column=1, padx=10, pady=10)

    def crear_pestaña_torneos(self, notebook):
        pestaña_torneos = tk.Frame(notebook)
        notebook.add(pestaña_torneos, text="Torneos")

    def obtener_id_usuario(self, nombre_usuario):
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()
            cursor.execute('''
                SELECT id
                FROM usuarios
                WHERE nombre_usuario = ?
            ''', (nombre_usuario,))
            id_usuario = cursor.fetchone()
        finally:
            conexion.close()

        return id_usuario[0] if id_usuario else None

    def obtener_datos_usuario(self,nombre_usuario):
        # Obtener el ID del usuario actual usando el nombre de usuario
        id_usuario_actual = self.obtener_id_usuario(nombre_usuario)

        if id_usuario_actual is None:
            # Manejar el caso en el que no se encuentra el usuario
            return None


        # Obtener los datos del usuario desde la base de datos usando el ID
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()
            cursor.execute('''
                SELECT nombre_apellidos, correo, ciudad, experiencia, nombre_usuario
                FROM usuarios
                WHERE id = ?
            ''', (id_usuario_actual,))
            datos_usuario = cursor.fetchone()
        finally:
            conexion.close()

        return datos_usuario
    
    def abrir_chat(self):
        nombre_usuario_a_buscar = self.buscador_entry.get()

        # Verificar si el usuario está intentando buscarse a sí mismo
        if nombre_usuario_a_buscar == self.obtener_datos_usuario()[4]:  # Índice 4 para obtener el nombre de usuario
            messagebox.showinfo("Error", "No puedes buscarte a ti mismo.")
            return
        
        # Realizar la búsqueda en la base de datos (reemplazar con la lógica adecuada)
        resultado_busqueda = self.buscar_en_base_de_datos(nombre_usuario_a_buscar)

        if resultado_busqueda:
            self.abrir_ventana_chat(nombre_usuario_a_buscar)
        else:
            messagebox.showinfo("Resultado de la Búsqueda", "Usuario no encontrado.")

    def buscar_en_base_de_datos(self, nombre_usuario):
        # Lógica de búsqueda en la base de datos (reemplazar con la lógica adecuada)
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()
            cursor.execute('''
                SELECT * FROM usuarios WHERE nombre_usuario = ?
            ''', (nombre_usuario,))
            resultado = cursor.fetchone()
        finally:
            conexion.close()

        return resultado is not None
    
    def abrir_ventana_chat(self, nombre_usuario):
        # Lógica para abrir una ventana de chat (puedes personalizar según tus necesidades)
        ventana_chat = tk.Toplevel(self.master)
        ventana_chat.title(f"Chat con {nombre_usuario}")
        # Aquí puedes agregar widgets y lógica para el chat
      

class InterfazInicio:
    #Creación de la interfaz inicio
    def __init__(self, master, app):
        #Inicializa la Interfaz del Inicio
        self.master = master
        self.app = app  # Se pasa la instancia de la aplicación principal
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
        self.enlace_label.bind("<Button-1>", lambda e: self.mostrar_interfaz_registro())

    def mostrar_interfaz_registro(self):
        # Función para que pase a la interfaz de registro
        self.pasar_interfaz_registro = InterfazRegistro(self.master, self.app)

    def mostrar_menu_principal(self):
        # Función para que pase al menú principal
        self.app.mostrar_menu_principal()

    def verificar_credenciales(self):
        # Obtener los valores de los campos de entrada
        nombre_usuario = self.entrada_usuario.get()
        contraseña = self.entrada_contraseña.get()

        # Verificar las credenciales en la base de datos (o tu lógica de verificación)
        if self.verificar_en_base_de_datos(nombre_usuario, contraseña):
            messagebox.showinfo("Acceso Permitido", "Inicio de sesión exitoso.")
            # Cerrar la ventana actual y mostrar el Menú Principal
            self.master.destroy()
            # Mostrar el Menú Principal
            self.app.mostrar_menu_principal(nombre_usuario)
        else:
            messagebox.showerror("Error de Inicio de Sesión", "Nombre de usuario o contraseña incorrectos.")

    def verificar_en_base_de_datos(self, nombre_usuario, contraseña):
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()
            cursor.execute('''
                SELECT salt, hashed_password
                FROM usuarios
                WHERE nombre_usuario = ?
            ''', (nombre_usuario,))

            resultado = cursor.fetchone()

            if resultado:
                stored_salt, hashed_password_en_bd = resultado
                return self.verificar_contraseña(contraseña, stored_salt, hashed_password_en_bd)

                
        finally:
            conexion.close()
            

    def verificar_contraseña(self, contraseña, stored_salt, hashed_password_en_bd):
        kdf = Scrypt(
            salt=stored_salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        key = kdf.derive(contraseña.encode("utf-8"))

        return key == hashed_password_en_bd
    
class InterfazRegistro:
    #Creación de la interfaz de registro
    def __init__(self, master):
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
            salt, hashed_password = self.guardar_contraseña(contraseña) # Utilizar la función para guardar la contraseña de manera segura
            experiencia = self.combobox_experiencia.get()  # Obtener el valor seleccionado del combobox
            correo = self.entrada_correo.get()
            nombre_apellidos = self.entrada_nombre_apellidos.get()
            ciudad = self.entrada_ciudad.get()

            if not self.validar_correo(correo): # Validar el formato del correo electrónic
                messagebox.showerror("Error", "El correo es incorrecto")
                # Cerrar la ventana actual y volver a la ventana principal
                self.master.destroy()
                return
            
            self.guardar_en_base_de_datos(nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, salt, hashed_password) #Los guardo en la base de datos 
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
        return salt,key #no se si guardar el salt o no 
    
    def guardar_en_base_de_datos(self, nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, salt, hashed_password):
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
                salt TEXT, 
                hashed_password TEXT  
            )
        ''')

        # Insertar los datos en la tabla    
        cursor.execute('''
            INSERT INTO usuarios (nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, salt, hashed_password) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, salt, hashed_password))

        # Guardar los cambios y cerrar la conexión
        conexion.commit()
        conexion.close()




if __name__ == "__main__":
    main = Main()
