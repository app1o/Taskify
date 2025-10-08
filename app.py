import psutil
import os
import sys
import tkinter
from tkinter import ttk, messagebox
import customtkinter as tk

# --- Import for Windows-specific startup feature ---
try:
    import winreg
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False

class SmartTaskManager(tk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Smart Task Manager 🧑‍💻")
        self.geometry("700x550")
        tk.set_appearance_mode("system")

        # --- Main container ---
        self.main_frame = tk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        title = tk.CTkLabel(self.main_frame, text="Smart Task Manager", font=tk.CTkFont(size=24, weight="bold"))
        title.pack(pady=(10, 20))

        # --- Create Tabbed Interface ---
        self.tab_view = tk.CTkTabview(self.main_frame)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_cheat = self.tab_view.add("Cheat Detector")
        self.tab_processes = self.tab_view.add("Process Explorer")
        self.tab_startup = self.tab_view.add("Startup Manager")
        
        # --- Initialize variables ---
        self.scan_active = False
        self.blacklisted_pids = []
        self.blacklisted_apps = []

        # --- Populate each tab ---
        self.create_cheat_detector_tab()
        self.create_process_explorer_tab()
        self.create_startup_manager_tab()

    # ===================================================================
    # TAB 1: CHEAT DETECTOR
    # ===================================================================
    def create_cheat_detector_tab(self):
        # --- Log Box ---
        log_bx = tk.CTkTextbox(self.tab_cheat, width=200, height=150, corner_radius=10, activate_scrollbars=True, state="disabled")
        log_bx.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_bx = log_bx

        # --- Buttons ---
        button_frame = tk.CTkFrame(self.tab_cheat)
        button_frame.pack(pady=10)

        start_btn = tk.CTkButton(button_frame, text="Start Scan", command=self.start_scan)
        start_btn.pack(side="left", padx=5)

        stop_btn = tk.CTkButton(button_frame, text="Stop Scan", command=self.stop_scan)
        stop_btn.pack(side="left", padx=5)

        ter_btn = tk.CTkButton(button_frame, text="Terminate Found Apps", command=self.terminate_found_apps)
        ter_btn.pack(side="left", padx=5)

    def log(self, message: str):
        self.log_bx.configure(state="normal")
        self.log_bx.insert("end", message + "\n")
        self.log_bx.yview_moveto(1.0)
        self.log_bx.configure(state="disabled")

    def check_for_cheats(self):
        if not self.scan_active:
            self.log("Scan stopped.")
            return

        detected_apps = []
        self.blacklisted_pids.clear()
        
        self.log_bx.configure(state="normal")
        self.log_bx.delete("1.0", "end")
        self.log_bx.configure(state="disabled")

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] in self.blacklisted_apps:
                    self.blacklisted_pids.append(proc.info['pid'])
                    if proc.info['name'] not in detected_apps:
                        detected_apps.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not detected_apps:
            self.log("Scanning... No cheating apps found.")
        else:
            self.log("WARNING: Detected apps running:")
            self.log("\n".join(detected_apps))
        
        self.after(2000, self.check_for_cheats)

    def start_scan(self):
        if self.scan_active:
            return
        self.scan_active = True

        if getattr(sys, 'frozen', False):
            cheat_path = os.path.join(os.path.dirname(sys.executable), "cheat.csv")
        else:
            cheat_path = os.path.join(os.path.dirname(__file__), "cheat.csv")

        if not os.path.exists(cheat_path):
            self.log("ERROR: cheat.csv not found!")
            self.scan_active = False
            return
        
        with open(cheat_path) as f:
            self.blacklisted_apps = [line.strip() for line in f.read().splitlines() if line.strip()]
        
        self.log("Scan started...")
        self.check_for_cheats()

    def stop_scan(self):
        self.scan_active = False

    def terminate_found_apps(self):
        if not self.blacklisted_pids:
            self.log("No processes to terminate.")
            return
        
        terminated_count = 0
        for pid in self.blacklisted_pids:
            try:
                p = psutil.Process(pid)
                p.kill()
                terminated_count += 1
            except psutil.NoSuchProcess:
                continue
        self.log(f"Terminated {terminated_count} processes.")
        self.blacklisted_pids.clear()

    # ===================================================================
    # TAB 2: PROCESS EXPLORER
    # ===================================================================
    def create_process_explorer_tab(self):
        # --- Treeview for displaying processes ---
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", font=('Calibri', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#22559b')])

        tree_frame = tk.CTkFrame(self.tab_processes)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("pid", "name", "cpu", "memory")
        self.process_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        self.process_tree.heading("pid", text="PID")
        self.process_tree.heading("name", text="Process Name")
        self.process_tree.heading("cpu", text="CPU %")
        self.process_tree.heading("memory", text="Memory %")
        
        self.process_tree.column("pid", width=60)
        self.process_tree.column("name", width=250)
        self.process_tree.column("cpu", width=80)
        self.process_tree.column("memory", width=100)

        self.process_tree.pack(fill="both", expand=True)

        # --- Buttons ---
        proc_button_frame = tk.CTkFrame(self.tab_processes)
        proc_button_frame.pack(pady=10)

        refresh_btn = tk.CTkButton(proc_button_frame, text="Refresh Processes", command=self.refresh_processes)
        refresh_btn.pack(side="left", padx=5)

        kill_btn = tk.CTkButton(proc_button_frame, text="Kill Selected Process", command=self.kill_selected_process)
        kill_btn.pack(side="left", padx=5)
        
        # Populate on creation
        self.refresh_processes()

    def refresh_processes(self):
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                p_info = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent'])
                p_info['memory_percent'] = round(p_info['memory_percent'], 2)

                process_values = (
                    p_info['pid'], 
                    p_info['name'], 
                    p_info['cpu_percent'], 
                    p_info['memory_percent']
                )
                self.process_tree.insert("", "end", values=process_values)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    
    def kill_selected_process(self):
        selected_item = self.process_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a process to kill.")
            return

        # Get the NAME of the selected process
        item_details = self.process_tree.item(selected_item)
        target_name = item_details['values'][1]

        # Ask for confirmation
        if not messagebox.askyesno("Confirm Action", 
                                   f"Are you sure you want to terminate all processes named '{target_name}'?"):
            return

        terminated_count = 0
        # Iterate through all running processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                # If a process name matches the target, terminate it
                if proc.info['name'] == target_name:
                    p_to_kill = psutil.Process(proc.info['pid'])
                    p_to_kill.kill()
                    terminated_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Ignore processes that are already gone or can't be accessed
                continue
        
        messagebox.showinfo("Success", f"Terminated {terminated_count} instance(s) of '{target_name}'.")
        self.refresh_processes()

    # ===================================================================
    # TAB 3: STARTUP MANAGER (WINDOWS ONLY)
    # ===================================================================
    def create_startup_manager_tab(self):
        if not IS_WINDOWS:
            label = tk.CTkLabel(self.tab_startup, text="This feature is available on Windows only.", font=tk.CTkFont(size=14))
            label.pack(pady=50, padx=20)
            return

        # --- Treeview for displaying startup apps ---
        tree_frame = tk.CTkFrame(self.tab_startup)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("name", "command", "location")
        self.startup_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        self.startup_tree.heading("name", text="Application Name")
        self.startup_tree.heading("command", text="Command")
        self.startup_tree.heading("location", text="Registry Location")

        self.startup_tree.pack(fill="both", expand=True)

        # --- Buttons ---
        startup_button_frame = tk.CTkFrame(self.tab_startup)
        startup_button_frame.pack(pady=10)
        
        disable_btn = tk.CTkButton(startup_button_frame, text="Disable Selected App", command=self.disable_selected_startup_app)
        disable_btn.pack(side="left", padx=5)

        self.refresh_startup_apps()

    def refresh_startup_apps(self):
        if not IS_WINDOWS: return

        for item in self.startup_tree.get_children():
            self.startup_tree.delete(item)

        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]

        for hive, subkey in run_keys:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            location = "User" if hive == winreg.HKEY_CURRENT_USER else "Machine"
                            self.startup_tree.insert("", "end", values=(name, value, location))
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                continue
    
    def disable_selected_startup_app(self):
        if not IS_WINDOWS: return
        
        selected_item = self.startup_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a startup application to disable.")
            return

        item_details = self.startup_tree.item(selected_item)
        app_name, _, location = item_details['values']

        hive = winreg.HKEY_CURRENT_USER if location == "User" else winreg.HKEY_LOCAL_MACHINE
        subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
        
        if not messagebox.askyesno("Confirm", f"Are you sure you want to disable '{app_name}' from starting up?"):
            return

        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, app_name)
            messagebox.showinfo("Success", f"'{app_name}' has been disabled from startup.")
            self.refresh_startup_apps()
        except FileNotFoundError:
            messagebox.showerror("Error", "Could not find the application in the registry. It might have been already removed.")
        except PermissionError:
            messagebox.showerror("Permission Error", "Could not modify the registry. Please try running as an administrator.")

if __name__ == "__main__":
    app = SmartTaskManager()
    app.mainloop()
    
