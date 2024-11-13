import tkinter as tk
from tkinter import ttk, Menu
from scapy.all import ARP, Ether, srp, sniff, IP
import socket
import threading
import subprocess
import time
import configparser

# Cargar configuración desde archivo INI
config = configparser.ConfigParser()
config.read('config.ini')

# Obtener intervalo de actualización del archivo INI
update_interval = config.getint('Settings', 'update_interval', fallback=5)

# Función para obtener el nombre del Wi-Fi (SSID)
def obtener_nombre_red():
    try:
        resultado = subprocess.check_output('netsh wlan show interfaces', shell=True)
        resultado = resultado.decode('latin-1')
        for linea in resultado.split('\n'):
            if "SSID" in linea:
                ssid = linea.split(":")[1].strip()
                return f"Red: {ssid}"
        return "No conectado a ninguna red"
    except Exception as e:
        print(f"Error al obtener el nombre de la red: {e}")
        return "Error al obtener red"

# Función para calcular el rango de IP automáticamente
def obtener_ip_range():
    ip_address = socket.gethostbyname(socket.gethostname())
    print(f"Dirección IP: {ip_address}")

    subnet_mask = "255.255.255.0"
    ip_parts = list(map(int, ip_address.split('.')))
    mask_parts = list(map(int, subnet_mask.split('.')))

    network_parts = [str(ip & mask) for ip, mask in zip(ip_parts, mask_parts)]
    network_address = '.'.join(network_parts)

    return f"{network_address}/24"

# Función para escanear dispositivos en la red
def obtener_dispositivos():
    dispositivos = []
    ip_range = obtener_ip_range()

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether / arp

    print(f"Escaneando la red en el rango: {ip_range}")

    try:
        resultado = srp(paquete, timeout=2, verbose=False)[0]
    except Exception as e:
        print(f"Error al realizar el escaneo: {e}")
        return []

    for enviado, recibido in resultado:
        dispositivos.append((recibido.psrc, recibido.hwsrc))

    return dispositivos

# Función para actualizar la lista de dispositivos
def actualizar_dispositivos():
    label_estado.set("Escaneando dispositivos...")
    root.update_idletasks()

    def actualizar_en_hilo():
        dispositivos = obtener_dispositivos()

        # Limpiar la tabla en el hilo principal
        tree.after(0, lambda: [tree.delete(row) for row in tree.get_children()])

        # Agregar los dispositivos a la tabla
        for ip, mac in dispositivos:
            hostname = "No encontrado"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass
            tree.insert("", "end", values=(ip, hostname, mac))

        label_estado.set("Escaneo completado.")
        nombre_red.set(obtener_nombre_red())
        iniciar_contador_hilo()

    threading.Thread(target=actualizar_en_hilo).start()

# Función que se ejecuta en un hilo separado
def actualizar_dispositivos_hilo():
    threading.Thread(target=actualizar_dispositivos).start()

# Función para contar el tiempo de actualización
def contador_actualizacion():
    tiempo_actualizacion = update_interval
    for i in range(tiempo_actualizacion, 0, -1):
        label_tiempo_actualizacion.set(f"Próxima actualización en: {i} segundos")
        time.sleep(1)
    actualizar_dispositivos_hilo()

# Función que inicia el hilo del contador
def iniciar_contador_hilo():
    threading.Thread(target=contador_actualizacion).start()
    label_tiempo_actualizacion.set("Actualizando...")

# Función para monitorear el tráfico de red
def paquete_callback(paquete):
    if paquete.haslayer(IP):
        ip_src = paquete[IP].src
        ip_dst = paquete[IP].dst
        traffic_display.insert(tk.END, f"Paquete: {ip_src} -> {ip_dst}\n")

def iniciar_monitoreo_trafico():
    label_estado.set("Monitoreando tráfico...")
    root.update_idletasks()
    threading.Thread(target=lambda: sniff(prn=paquete_callback, filter="ip", store=0)).start()

# Configuración de la ventana de la interfaz
root = tk.Tk()
root.title("Monitor de Dispositivos Conectados")
root.geometry("600x600")
root.configure(bg="#2E2E2E")

# Menú de configuración
menu_bar = Menu(root)
config_menu = Menu(menu_bar, tearoff=0)
config_menu.add_command(label="Configuración", command=lambda: mostrar_configuracion())
menu_bar.add_cascade(label="Configuración", menu=config_menu)
menu_bar.add_command(label="Ayuda", command=lambda: mostrar_ayuda())
root.config(menu=menu_bar)

# Mostrar el nombre de la red en la parte superior
nombre_red = tk.StringVar()
nombre_red.set(obtener_nombre_red())
label_red = tk.Label(root, textvariable=nombre_red, font=("Helvetica", 16), bg="#2E2E2E", fg="#FFFFFF")
label_red.pack(pady=10)

# Indicador de estado del escaneo
label_estado = tk.StringVar()
label_estado.set("Listo para escanear.")
label_escaneo = tk.Label(root, textvariable=label_estado, font=("Helvetica", 12), bg="#2E2E2E", fg="#FFFFFF")
label_escaneo.pack(pady=5)

# Configurar la tabla
tree = ttk.Treeview(root, columns=("IP", "Host", "MAC"), show="headings", height=10)
tree.heading("IP", text="Dirección IP")
tree.heading("Host", text="Host")
tree.heading("MAC", text="Dirección MAC")
tree.pack(fill="both", expand=True, padx=20, pady=10)

# Estilo para la tabla
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#3C3C3C", foreground="white", fieldbackground="#3C3C3C", rowheight=25)
style.configure("Treeview.Heading", background="#2E2E2E", foreground="white", font=("Helvetica", 14, "bold"))
style.map("Treeview.Heading", background=[('active', '#5A5A5A')])

# Crear un marco para los botones y la entrada de tiempo
frame_botones = tk.Frame(root, bg="#2E2E2E")
frame_botones.pack(pady=10)

# Botón para actualizar la lista de dispositivos
btn_actualizar = tk.Button(frame_botones, text="Actualizar Dispositivos", command=actualizar_dispositivos_hilo, bg="#4A4A4A", fg="#FFFFFF")
btn_actualizar.pack(side=tk.LEFT, padx=5)

# Botón para iniciar el monitoreo de tráfico
btn_monitoreo = tk.Button(frame_botones, text="Monitorear Tráfico", command=iniciar_monitoreo_trafico, bg="#4A4A4A", fg="#FFFFFF")
btn_monitoreo.pack(side=tk.LEFT, padx=5)

# Contador de tiempo de actualización
label_tiempo_actualizacion = tk.StringVar()
label_tiempo_actualizacion.set("Próxima actualización en: ")
label_tiempo_display = tk.Label(root, textvariable=label_tiempo_actualizacion, font=("Helvetica", 12), bg="#2E2E2E", fg="#FFFFFF")
label_tiempo_display.pack(pady=5)

# Entrada para el tiempo de actualización
entry_tiempo = tk.Entry(frame_botones, width=5)
entry_tiempo.insert(0, update_interval)
entry_tiempo.pack(side=tk.LEFT, padx=5)

# Apartado para el tráfico de red
label_trafico = tk.Label(root, text="Tráfico de Red:", font=("Helvetica", 12), bg="#2E2E2E", fg="#FFFFFF")
label_trafico.pack(pady=5)
traffic_display = tk.Text(root, height=10, bg="#3C3C3C", fg="white", wrap=tk.WORD)
traffic_display.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

# Funciones para mostrar ayuda y configuración
def mostrar_configuracion():
    configuracion_frame = tk.Frame(root, bg="#2E2E2E")
    configuracion_frame.place(relx=0.5, rely=0.5, anchor="center")

    instrucciones_label = tk.Label(configuracion_frame, text="Configuración", font=("Helvetica", 16), bg="#2E2E2E", fg="#FFFFFF")
    instrucciones_label.pack(pady=10)

    label_actualizar = tk.Label(configuracion_frame, text="Tiempo de actualización (segundos):", bg="#2E2E2E", fg="#FFFFFF")
    label_actualizar.pack(pady=5)

    entry_actualizar = tk.Entry(configuracion_frame, width=5)
    entry_actualizar.insert(0, update_interval)
    entry_actualizar.pack(pady=5)

    def guardar_configuracion():
        nuevo_intervalo = int(entry_actualizar.get())
        config['Settings'] = {'update_interval': str(nuevo_intervalo)}
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        global update_interval
        update_interval = nuevo_intervalo
        configuracion_frame.destroy()

    btn_guardar = tk.Button(configuracion_frame, text="Guardar", command=guardar_configuracion, bg="#4A4A4A", fg="#FFFFFF")
    btn_guardar.pack(pady=5)

    btn_cerrar = tk.Button(configuracion_frame, text="Cerrar", command=configuracion_frame.destroy, bg="#4A4A4A", fg="#FFFFFF")
    btn_cerrar.pack(pady=5)

def mostrar_ayuda():
    ayuda_frame = tk.Frame(root, bg="#2E2E2E")
    ayuda_frame.place(relx=0.5, rely=0.5, anchor="center")

    instrucciones_label = tk.Label(ayuda_frame, text="Instrucciones del Programa", font=("Helvetica", 16), bg="#2E2E2E", fg="#FFFFFF")
    instrucciones_label.pack(pady=10)

    instrucciones_texto = """Bienvenido al Monitor de Dispositivos Conectados.
    
1. Para actualizar la lista de dispositivos, haz clic en 'Actualizar Dispositivos'.
2. Para monitorear el tráfico de la red, haz clic en 'Monitorear Tráfico'.
3. Configura el tiempo de actualización en segundos en el campo correspondiente o en el menú de Configuración.
4. Observa el nombre de la red actual en la parte superior y el tráfico de red en el recuadro inferior.
"""
    instrucciones = tk.Label(ayuda_frame, text=instrucciones_texto, font=("Helvetica", 12), bg="#2E2E2E", fg="#FFFFFF", wraplength=500, justify="left")
    instrucciones.pack(pady=10)

    btn_cerrar = tk.Button(ayuda_frame, text="Cerrar", command=ayuda_frame.destroy, bg="#4A4A4A", fg="#FFFFFF")
    btn_cerrar.pack(pady=5)

iniciar_contador_hilo()
root.mainloop()
