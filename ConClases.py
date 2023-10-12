import tkinter as tk
from tkinter import messagebox #Importa para poder ofrecer mensajes de respuesta
import sqlite3 #Importa la base de datos
import re  # Importar el módulo de expresiones regulares
from tkinter import ttk #proporciona el desplegable como el de experiencia
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Main:
    def __init__(self):
        # Inicializa solo la interfaz de inicio
        self.root = tk.Tk()
        self.interfaz_inicio = InterfazInicio(self.root,self)
        self.root.mainloop()

    def mostrar_menu_principal(self, nombre_usuario):
        # Muestra la interfaz del menú principal
        key = AESGCM.generate_key(bit_length=128)
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
        self.nombre_usuario_actual = nombre_usuario
        self.key = AESGCM.generate_key(bit_length=128)
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

        # Cuadro de búsqueda
        buscador_entry = tk.Entry(pestaña_mensajes)
        buscador_entry.grid(row=0, column=1, padx=10, pady=10)

        # Botón de búsqueda
        boton_buscar = tk.Button(pestaña_mensajes, text="Buscar", command=lambda: self.buscar_mensajes(buscador_entry.get()))
        boton_buscar.grid(row=0, column=2, padx=10, pady=10)

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
    
    def buscar_mensajes(self, nombre_usuario):
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()
            cursor.execute('''
                SELECT 1
                FROM usuarios
                WHERE nombre_usuario = ?
            ''', (nombre_usuario,))
            resultado = cursor.fetchone()
            print(f"Resultado de la búsqueda: {resultado}")
        finally:
            conexion.close()
        
        if resultado is not None:
            respuesta = messagebox.askquestion("Usuario Encontrado", f"¿Quieres hablar con {nombre_usuario}?")
            if respuesta == 'yes':
                print(f"Iniciar conversación con {nombre_usuario}.")
                self.iniciar_chat(nombre_usuario)
            else:
                print("Conversación cancelada.")
        else:
            messagebox.showinfo("Usuario No Encontrado", f"No se ha encontrado a {nombre_usuario}.")

        return resultado is not None
    
    def iniciar_chat(self, nombre_usuario):
        # Obtener el ID del usuario actual usando el nombre de usuario
        id_usuario_actual = self.obtener_id_usuario(self.nombre_usuario_actual)

        # Abrir una nueva ventana de chat
        chat_ventana = ChatVentana(self.master, nombre_usuario, id_usuario_actual, self.key)

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
        self.pasar_interfaz_registro = InterfazRegistro(self.master, self.app, self)

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
    def __init__(self, master, app, main_app):
        self.master = master
        self.app = app
        self.main_app = main_app
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

class ChatVentana(tk.Toplevel):
    def __init__(self, master, nombre_usuario, id_usuario, key):
        super().__init__(master)
        self.title(f"Chat con {nombre_usuario}")
        self.geometry("400x400")
        print(f"ChatVentana creada para {nombre_usuario} (ID: {id_usuario})")
        self.key = key #para gestionar la encriptaccion

        # Atributos para gestionar la base de datos
        self.id_usuario = id_usuario
        self.id_destinatario = self.obtener_id_destinatario(nombre_usuario)

        # Etiqueta que muestra con quién estás hablando
        self.etiqueta_conversacion = tk.Label(self, text=f"Conversación con {nombre_usuario}")
        self.etiqueta_conversacion.pack(pady=10)

        # Área de visualización para los mensajes
        self.area_mensajes = tk.Text(self, height=15, width=40)
        self.area_mensajes.pack(padx=10, pady=10)

        # Cuadro de texto para escribir mensajes
        self.cuadro_mensaje = tk.Entry(self, width=40)
        self.cuadro_mensaje.pack(padx=10, pady=5)

        # Botón para enviar mensajes
        boton_enviar = tk.Button(self, text="Enviar", command=self.enviar_mensaje)
        boton_enviar.pack(pady=10)

        self.cargar_y_mostrar_mensajes()

    def cargar_y_mostrar_mensajes(self):
        print("Cargando y mostrando mensajes...")
        mensajes = self.obtener_mensajes_desde_bd()
        print("Mensajes obtenidos:", mensajes)
        if not mensajes:
            # No hay mensajes, mostrar mensaje de bienvenida
            self.area_mensajes.insert(tk.END, "¡Bienvenido al chat!\n")
        else:
            for mensaje in mensajes:
                decrypted_message = self.decrypt_message(mensaje[0], bytes(mensaje[1]), self.key, b"additional_authenticated_data")
                self.area_mensajes.insert(tk.END, f"{mensaje[1]}: {decrypted_message.decode('utf-8')}\n")
    def obtener_mensajes_desde_bd(self):
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()
            # Ejemplo de consulta: obtener mensajes enviados al destinatario actual
            cursor.execute('''
                SELECT m.contenido, m.nonce, u.nombre_usuario as nombre_emisor
                FROM mensajes m
                JOIN usuarios u ON m.id_emisor = u.id
                WHERE (m.id_destinatario = ? AND m.id_emisor = ?) OR 
                  (m.id_destinatario = ? AND m.id_emisor = ?) --Esto es para que se enseñen los mensajes solo con esa persona
            ''', (self.id_usuario, self.id_destinatario, self.id_destinatario, self.id_usuario))
            mensajes = cursor.fetchall()
            if not mensajes:
                return False
        except sqlite3.OperationalError as e:
            # Si hay un error de operación, por ejemplo, si la tabla no existe, imprime el error y retorna False
            print(f"Error al obtener mensajes desde la base de datos: {e}")
            return False
        finally:
            conexion.close()
        return mensajes

    def enviar_mensaje(self):
        mensaje = self.cuadro_mensaje.get()
        if mensaje:
            ciphertext, nonce = self.encrypt_message(mensaje.encode("utf-8"), self.key, b"additional_authenticated_data")
            self.area_mensajes.insert(tk.END, f"Tú: {mensaje}\n")
            self.cuadro_mensaje.delete(0, tk.END)

            self.guardar_mensaje(ciphertext, nonce)
        
    def guardar_mensaje(self, ciphertext, nonce):
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()

            # Crear la tabla mensajes si no existe
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mensajes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    id_emisor INTEGER,
                    id_destinatario INTEGER,
                    contenido TEXT,
                    nonce BLOB,  -- Cambiado a BLOB para almacenar bytes
                    FOREIGN KEY (id_emisor) REFERENCES usuarios(id),
                    FOREIGN KEY (id_destinatario) REFERENCES usuarios(id)
                )
            ''')

            # Insertar el mensaje en la tabla mensajes
            cursor.execute('''
                INSERT INTO mensajes (id_emisor, id_destinatario, contenido, nonce)
                VALUES (?, ?, ?, ?)
            ''', (self.id_usuario, self.id_destinatario, ciphertext, nonce))
            conexion.commit()
            print("Mensaje guardado en la base de datos.")
        finally:
            conexion.close()

    def obtener_id_destinatario(self, nombre_destinatario):
        conexion = sqlite3.connect("registro.db")
        try:
            cursor = conexion.cursor()
            cursor.execute('''
                SELECT id
                FROM usuarios
                WHERE nombre_usuario = ?
            ''', (nombre_destinatario,))
            id_destinatario = cursor.fetchone()
        finally:
            conexion.close()

        return id_destinatario[0] if id_destinatario else None

    def encrypt_message(self, message, key, aad):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message, aad)
        return ciphertext, nonce

    def decrypt_message(self, ciphertext, nonce, key, aad):
        print(f"Decryption - Nonce: {nonce}")
        print(f"Decryption - Ciphertext: {ciphertext}")
        print(f"Decryption - AAD: {aad}")

        aesgcm = AESGCM(key)
        decrypted_message = aesgcm.decrypt(nonce, ciphertext, aad)
        return decrypted_message

if __name__ == "__main__":
    main = Main()
