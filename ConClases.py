import tkinter as tk
from tkinter import messagebox #Importa para poder ofrecer mensajes de respuesta
import sqlite3 #Importa la base de datos
import re  # Importar el módulo de expresiones regulares
from tkinter import ttk #proporciona el desplegable como el de experiencia
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class Main:
    #La clase Main donde se inicializan las distintas pantallas
    def __init__(self):
        # Inicializa solo la interfaz de inicio
        self.root = tk.Tk()
        self.interfaz_inicio = InterfazInicio(self.root,self)
        self.root.mainloop()

    def mostrar_menu_principal(self, nombre_usuario):
        # Muestra la interfaz del menú principal
        root_menu = tk.Tk()  
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
        #Inicializa el menu y declara los parametros necesarios
        self.master = master
        self.app = app
        self.nombre_usuario_actual = nombre_usuario
        self.interfaz_menu_principal(nombre_usuario)

    def interfaz_menu_principal(self,nombre_usuario):
        #crea el menú principal donde aparecen los datos del usuario nada más entrar
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
        #crea la pestaña mensajes que se desarrollara el contenido más adelante
        pestaña_mensajes = tk.Frame(notebook)
        notebook.add(pestaña_mensajes, text="Mensajes")

        # Cuadro de búsqueda
        buscador_entry = tk.Entry(pestaña_mensajes)
        buscador_entry.grid(row=0, column=1, padx=10, pady=10)

        # Botón de búsqueda
        boton_buscar = tk.Button(pestaña_mensajes, text="Buscar", command=lambda: self.buscar_mensajes(buscador_entry.get()))
        boton_buscar.grid(row=0, column=2, padx=10, pady=10)

    def crear_pestaña_torneos(self, notebook):
        # Crea la pestaña de torneos, fase de entrega 2
        pestaña_torneos = tk.Frame(notebook)
        notebook.add(pestaña_torneos, text="Torneos")

        # Botón para crear torneo
        boton_crear = tk.Button(pestaña_torneos, text="Crear Torneo", command=lambda: self.crear_torneos(), width=10, height=1)
        boton_crear.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")  # Ajustado ancho, alto y sticky

        # Botón para apuntarse a torneo
        boton_apuntarse = tk.Button(pestaña_torneos, text="Apuntarse a Torneos", command=lambda: self.apuntarse_torneos(), width=10, height=1)
        boton_apuntarse.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")  # Ajustado ancho, alto y sticky

        # Botón para ver torneos
        boton_ver_torneos = tk.Button(pestaña_torneos, text="Ver Torneos", command=lambda: self.ver_torneos(), width=10, height=1)
        boton_ver_torneos.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")  # Ajustado ancho, alto y sticky

        # Configurar pesos de filas y columnas para centrar los botones
        pestaña_torneos.grid_rowconfigure(0, weight=1)
        pestaña_torneos.grid_rowconfigure(1, weight=1)
        pestaña_torneos.grid_rowconfigure(2, weight=1)
        pestaña_torneos.grid_columnconfigure(0, weight=1)
    def crear_torneos(self):
        #te lleva a la clase crear torneos
        id_usuario_actual = self.obtener_id_usuario(self.nombre_usuario_actual)
        crear_torneos = Creacion_torneo(self.master,id_usuario_actual)

    def apuntarse_torneos(self):
        #te llevo a la clase apuntarse a torneos
        id_usuario_actual = self.obtener_id_usuario(self.nombre_usuario_actual)
        apuntarse_torneos = Apuntarse_torneos(self.master,id_usuario_actual)
    
    def ver_torneos(self):
        #te lleva a la clase ver torneos
        id_usuario_actual = self.obtener_id_usuario(self.nombre_usuario_actual)
        ver_torneos = Ver_torneos(self.master,id_usuario_actual)


    def obtener_id_usuario(self, nombre_usuario):
        #busca el nombre en la base de datos, y si está, obtienes su id
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
        #Con el ID obtenido, ya simplemente buscarlo en la tabla y sacar los datos de la tabla
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
    
    def buscar_mensajes(self, nombre_usuario,):
        #Busca la persona con la que vas a hablar 
        conexion = sqlite3.connect("registro.db")
        try:
            #busca la persona con la que quieres hablar
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
                #Al decir que si, lo que también hace es calcular la key que los dos vais a utilizar para cifrar y descrifrar los mensajes
                #Esto lo va a hacer cogiendo los salts de los dos usuarios, y unificandolos para que se cifre con la misma clave
                #Lo primero es obtener los id para asi luego tener acceso a los salt de cada uno
                id_destino = self.obtener_id_usuario(nombre_usuario)
                id_actual = self.obtener_id_usuario(self.nombre_usuario_actual)
                #Saca los salt de cada uno de los usuarios 
                salt_destinatario = self.devolver_salt(nombre_usuario)
                salt_actual = self.devolver_salt(self.nombre_usuario_actual)
                #Ahora voy a concatenar los salt. El problema es que hay que tener cuidado, porque el orden es importante, no calcula el mismo salt si lo cambio de lado
                #La idea es que el id más pequeño vaya primero
                if id_actual < id_destino:
                    salt_conjunto = salt_actual + salt_destinatario
                else: 
                    salt_conjunto = salt_destinatario +salt_actual
                key= self.generar_key(salt_conjunto) 
                self.iniciar_chat(nombre_usuario, key)
            else:
                print("Conversación cancelada.")
        else:
            messagebox.showinfo("Usuario No Encontrado", f"No se ha encontrado a {nombre_usuario}.")

        return resultado is not None
    
    def iniciar_chat(self, nombre_usuario, key):
        #Abrir el chat con la persona
        #Obtener el ID del usuario actual usando el nombre de usuario
        id_usuario_actual = self.obtener_id_usuario(self.nombre_usuario_actual)

        # Abrir una nueva ventana de chat
        chat_ventana = ChatVentana(self.master, nombre_usuario, id_usuario_actual, key)
    
    def devolver_salt(self, nombre_usuario):
        #Dado un nombre de usuario, busca en la tabla su salt y lo devuelve
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
                return stored_salt
        finally:
            conexion.close()

    def generar_key(self,salt):
        #Cifra la key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(b"my great password") #la contraseña de la clave maestra es esta, en una aplicación de verdad tendría que estar cifrada y guardada
        return key

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


    def verificar_credenciales(self):
        #Verifica las credenciales para ver si el nombre del usuario y la contraseña son correctas
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
        #Comprueba los datos dados con los de la base de datos 
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
        #Se utiliza el Scrypt para cifrar la contraseña
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
            if self.usuario_existente(nombre_usuario):
                messagebox.showerror("Error", "El nombre de usuario ya está registrado. Por favor, elige otro.")
                return
            contraseña = self.entrada_contraseña.get()
            if not self.validar_contraseña(contraseña):
                messagebox.showerror("Error", "La contraseña debe tener al menos 8 caracteres y contener letras y números.")
                return
            salt, hashed_password = self.guardar_contraseña(contraseña) # Utilizar la función para guardar la contraseña de manera segura
            experiencia = self.combobox_experiencia.get()  # Obtener el valor seleccionado del combobox
            correo = self.entrada_correo.get()
            if self.correo_existente(correo):
                messagebox.showerror("Error", "El correo ya está registrado. Por favor, utiliza otro.")
                return
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
            
            #guardar la clave privada
            privada_pem = self.creacion_claves(contraseña, nombre_apellidos, ciudad, correo, nombre_usuario)
            
            self.guardar_clave_privada(privada_pem)

        except Exception as e: #para que me salte las excepciones si pasa algo 
            messagebox.showerror("Error", f"Error al registrar: {str(e)}")

    def validar_correo(self, correo):
        # Verifica que el correo tiene el formato correcto
        patron_correo = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
        return patron_correo.match(correo) is not None
    
    def validar_contraseña(self, contraseña):
        # Verifica que la contraseña tenga al menos 8 caracteres, contenga letras y números
        if len(contraseña) < 8 or not re.search(r'[a-zA-Z]', contraseña) or not re.search(r'\d', contraseña):
            return False
        return True
    
    def usuario_existente(self, nombre_usuario):
        # Verificar si el nombre de usuario ya está en la base de datos
        conexion = sqlite3.connect("registro.db")
        cursor = conexion.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE nombre_usuario = ?", (nombre_usuario,))
        resultado = cursor.fetchone()
        conexion.close()
        return resultado is not None

    def correo_existente(self, correo):
        # Verificar si el correo ya está en la base de datos
        conexion = sqlite3.connect("registro.db")
        cursor = conexion.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE correo = ?", (correo,))
        resultado = cursor.fetchone()
        conexion.close()
        return resultado is not None

    def guardar_contraseña(self, contraseña): 
        # Lógica para guardar la contraseña de manera segura
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        key = kdf.derive(contraseña.encode("utf-8"))
        return salt,key  
    
    def guardar_en_base_de_datos(self, nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, salt, hashed_password):
        # Conectar a la base de datos (creará la base de datos si no existe)
        conexion = sqlite3.connect("registro.db")

        # Crear un cursor
        cursor = conexion.cursor()
        print("abre el cursor de la base de datos")
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
                hashed_password TEXT)
        ''')
        print("crea la tabla si no lo esta")
        # Insertar los datos en la tabla    
        cursor.execute('''
            INSERT INTO usuarios (nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, salt, hashed_password) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (nombre_apellidos, correo, ciudad, experiencia, nombre_usuario, salt, hashed_password ))
        print("introduce los datos en la base de datos")

        # Guardar los cambios y cerrar la conexión
        conexion.commit()
        conexion.close()

    def guardar_clave_privada(self, privada_pem):
        # Conectar a la base de datos SQLite
        conn = sqlite3.connect("pem.db")
        cursor = conn.cursor()

        # Crear una tabla si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pem_privadas (
                id INTEGER PRIMARY KEY,
                privada_pem BLOB
            )
        ''')

        # Insertar el CSR en la base de datos
        cursor.execute('INSERT INTO pem_privadas (privada_pem) VALUES (?)', (privada_pem))
        conn.commit()

        # Cerrar la conexión a la base de datos
        conn.close()

    def creacion_claves(self, contraseña, nombre_apellidos, ciudad, correo, nombre_usuario):
        private_key = rsa.generate_private_key(
            public_exponent= 65537,
            key_size=2048)
        
        privada_pem = private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm= serialization.BestAvailableEncryption(contraseña.encode("utf-8"))),
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, nombre_apellidos),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ciudad),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, correo),
            x509.NameAttribute(NameOID.GIVEN_NAME, nombre_usuario),
        ])
        ).sign(private_key, hashes.SHA256())

        # Convertir CSR a bytes para almacenarlo en la base de datos
        csr_bytes = csr.public_bytes(encoding=serialization.Encoding.PEM)

        # Conectar a la base de datos SQLite
        conn = sqlite3.connect("pem.db")
        cursor = conn.cursor()

        # Crear una tabla si no existe
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS csrs (
                id INTEGER PRIMARY KEY,
                csr_data BLOB
            )
        ''')

        # Insertar el CSR en la base de datos
        cursor.execute('INSERT INTO csrs (csr_data) VALUES (?)', (csr_bytes,))
        conn.commit()

        # Cerrar la conexión a la base de datos
        conn.close()

        return privada_pem
    
    



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
                decrypted_message = self.decrypt_message(bytes(mensaje[0]), bytes(mensaje[1]), self.key, b"additional_authenticated_data")
                self.area_mensajes.insert(tk.END, f"{mensaje[2]}: {decrypted_message.decode('utf-8')}\n")
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
    
class Creacion_torneo(tk.Toplevel):
    def __init__(self, master, id_usuario):
        self.master = tk.Tk() 
        self.master.title(f"Creación de torneos")
        self.master.geometry("400x400")
        self.id_usuario = id_usuario
        self.datos_torneos()
        self.boton_crear_torneos = tk.Button(self.master, text="Crear", command=self.crear) 
        self.boton_crear_torneos.pack()

    def datos_torneos(self):
        self.label_nombre_torneo = tk.Label(self.master, text="Nombre del torneo:")
        self.label_nombre_torneo.pack()

        self.entrada_nombre_torneo = tk.Entry(self.master)
        self.entrada_nombre_torneo.pack()

        self.label_fecha = tk.Label(self.master, text="Fecha:")
        self.label_fecha.pack()

        self.entrada_fecha = tk.Entry(self.master)
        self.entrada_fecha.pack()

        self.label_hora = tk.Label(self.master, text="Hora:")
        self.label_hora.pack()

        # Selector de horas
        horas = [str(i).zfill(2) for i in range(24)]  # Rellenar con cero a la izquierda
        self.combobox_horas = ttk.Combobox(self.master, values=horas, state="readonly")
        self.combobox_horas.pack()

        # Selector de minutos
        minutos = ["00","15", "30", "45"]  # Rellenar con cero a la izquierda
        self.combobox_minutos = ttk.Combobox(self.master, values=minutos, state="readonly")
        self.combobox_minutos.pack()

        self.label_nivel = tk.Label(self.master, text="Nivel:")
        self.label_nivel.pack()

        # Opciones para el menú desplegable de experiencia
        opciones_experiencia = ["Cero Patatero", "Poca", "Media", "Alta", "Modo Dios"]

        self.combobox_nivel = ttk.Combobox(self.master, values=opciones_experiencia, state="readonly")
        self.combobox_nivel.pack()

        self.label_lugar = tk.Label(self.master, text="Lugar:")
        self.label_lugar.pack()

        self.entrada_lugar = tk.Entry(self.master)
        self.entrada_lugar.pack()

        self.label_precio = tk.Label(self.master, text="Precio (en euros):")
        self.label_precio.pack()

        self.entrada_precio = tk.Entry(self.master)
        self.entrada_precio.pack()

    def crear(self):
        try: 
            nombre_torneo = self.entrada_nombre_torneo.get()
            if self.torneo_existente(nombre_torneo):
                messagebox.showerror("Error", "El nombre del torneo ya está registrado. Por favor, elige otro.")
                return
            fecha = self.entrada_fecha.get()
            # Obtener horas y minutos seleccionados
            hora = self.combobox_horas.get()
            minutos = self.combobox_minutos.get()

            # Unir horas y minutos en el formato deseado
            hora_completa = f"{hora}:{minutos}"
            nivel = self.combobox_nivel.get()
            lugar = self.entrada_lugar.get()
            precio = self.entrada_precio.get()

            self.guardar_en_la_base(nombre_torneo, fecha, hora_completa, nivel, lugar, precio)
            messagebox.showinfo("Registro Completado", "Registro completado con éxito.") # Mostrar un mensaje de éxito
            self.master.destroy()

        except Exception as e: #para que me salte las excepciones si pasa algo 
            messagebox.showerror("Error", f"Error al registrar: {str(e)}")

    def guardar_en_la_base(self, nombre_torneo, fecha, hora, nivel, lugar, precio):
        try:
            # Conectar a la base de datos (creará la base de datos si no existe)
            conexion = sqlite3.connect("registro.db")

            cursor = conexion.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Torneos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre_torneo TEXT,
                    fecha TEXT,
                    hora TEXT,
                    nivel TEXT,
                    lugar TEXT,
                    precio REAL
                )
            ''')
            

            # Insertar los datos en la tabla
            cursor.execute('''
                INSERT INTO Torneos (nombre_torneo, fecha, hora, nivel, lugar, precio)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (nombre_torneo, fecha, hora, nivel, lugar, precio))
            # Guardar los cambios y cerrar la conexión
            conexion.commit()
            conexion.close()

        except Exception as e:
            print(f"Error en guardar_en_la_base: {str(e)}")
            raise e  # Vuelve a lanzar la excepción para ver el seguimiento completo


    
    def torneo_existente(self, nombre_torneo):
        # Verificar si el nombre de usuario ya está en la base de datos
        conexion = sqlite3.connect("registro.db")
        cursor = conexion.cursor()
        cursor.execute("SELECT * FROM Torneos WHERE nombre_torneo = ?", (nombre_torneo,))
        resultado = cursor.fetchone()
        conexion.close()
        return resultado is not None

class Apuntarse_torneos(tk.Toplevel):
    def __init__(self, master, id_usuario):
        super().__init__(master)
        self.title(f"Creación de torneos")
        self.geometry("400x400")
        self.id_usuario = id_usuario

class Ver_torneos(tk.Toplevel):
    def __init__(self, master, id_usuario):
        super().__init__(master)
        self.title(f"Creación de torneos")
        self.geometry("400x400")
        self.id_usuario = id_usuario


if __name__ == "__main__":
    main = Main()
