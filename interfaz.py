import tkinter as tk
from tkinter import messagebox

class InterfazPrincipal:
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

        self.boton = tk.Button(master, text="Enviar", command=self.mostrar_mensaje)
        self.boton.pack()

        self.enlace_label = tk.Label(master, text="Ir a la Segunda Interfaz", fg="blue", cursor="hand2")
        self.enlace_label.pack()
        self.enlace_label.bind("<Button-1>", lambda e: self.mostrar_segunda_interfaz())

    def mostrar_mensaje(self):
        usuario = self.entrada_usuario.get()
        contraseña = self.entrada_contraseña.get()
        mensaje = f"Usuario: {usuario}, Contraseña: {contraseña}"
        tk.messagebox.showinfo("Mensaje", mensaje)

    def mostrar_segunda_interfaz(self):
        self.segunda_interfaz = SegundaInterfaz(self.master)

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

        self.entrada_experiencia = tk.Entry(self.master)
        self.entrada_experiencia.pack()

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
        # Aquí puedes agregar la lógica para procesar la información del registro
        nombre_usuario = self.entrada_nombre_usuario.get()
        contraseña = self.entrada_contraseña.get()
        experiencia = self.entrada_experiencia.get()
        correo = self.entrada_correo.get()
        nombre_apellidos = self.entrada_nombre_apellidos.get()
        ciudad = self.entrada_ciudad.get()

        # Mostrar un mensaje de éxito (puedes adaptar esto según tu lógica de registro)
        mensaje = f"Registro completado:\nUsuario: {nombre_usuario}\nContraseña: {contraseña}\nExperiencia: {experiencia}\nCorreo: {correo}\nNombre y Apellidos: {nombre_apellidos}\nCiudad: {ciudad}"
        tk.messagebox.showinfo("Registro Completado", mensaje)

        # Cerrar la ventana actual y volver a la ventana principal
        self.master.destroy()

    def mostrar(self):
        self.master.wait_window()

if __name__ == "__main__":
    root = tk.Tk()
    app = InterfazPrincipal(root)
    root.mainloop()
