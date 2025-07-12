## Python Script to manage firewall rules
import os
import subprocess
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter import filedialog
import time
from PIL import Image, ImageTk

# File path
file_path = "/etc/encrypted_file.enc"
# Check if the encrypted file exists before opening the app
if not os.path.exists(file_path):
    exit()

## global variables
# firewall status
firewall_status_enable_disable = True  # To store the current status of the firewall True for enabled, False for disabled

current_selection_window=None  # To store the current selection window for firewall rules
# for time based rules
block_traffic_time_from = None  # To store the start time for blocking traffic
block_traffic_time_to = None  # To store the end time for blocking traffic

# for IP based rules
ip_addr_block = []  # List to store blocked IP addresses

# for protocol based rules
allowed_protocol = None  # List to store blocked protocols

# for port based rules
blocked_ports_global = []  # List to store blocked ports

# for state based rules
blocked_states_global = []  # List to store blocked states

# for Inbound Outbound based rules
inOutBond_global = None  # Variable to store Inbound/Outbound rules


## All functions to run commands using subprocess
def TimeFilterRunCommand():
    command=f"sudo bash firewall_time_filter.sh {block_traffic_time_from} {block_traffic_time_to}"
    subprocess.run(command, shell=True, check=True)
    messagebox.showinfo("Run Command", f"Command executed: {command}")

def IPFilterRunCommand():
    command=f"sudo bash firewall_ip_filter.sh {' '.join(ip_addr_block)}"
    subprocess.run(command, shell=True, check=True)
    messagebox.showinfo("Run Command", f"Command executed: {command}")

def ProtocolFilterRunCommand():
    command=f"sudo bash firewall_protocol_filter.sh {allowed_protocol}"
    subprocess.run(command, shell=True, check=True)
    messagebox.showinfo("Run Command", f"Command executed: {command}")

def PortFilterRunCommand():
    command=f"sudo bash firewall_port_filter.sh {' '.join(map(str, blocked_ports_global))}"
    subprocess.run(command, shell=True, check=True)
    messagebox.showinfo("Run Command", f"Command executed: {command}")

def StateFilterRunCommand():
    command=f"sudo bash firewall_state_filter.sh {' '.join(blocked_states_global)}"
    subprocess.run(command, shell=True, check=True)
    messagebox.showinfo("Run Command", f"Command executed: {command}")

def InboundOutboundFilterRunCommand():
    command=f"sudo bash firewall_inbound_outbound_filter.sh {inOutBond_global}"
    subprocess.run(command, shell=True, check=True)
    messagebox.showinfo("Run Command", f"Command executed: {command}")

def resetAllFirewallRules():
    # Reset all rules by running a script or command
    command = "sudo bash firewall_reset.sh"
    subprocess.run(command, shell=True, check=True)
    messagebox.showinfo("Reset Rules", "All firewall rules have been reset.")

# GUI for Firewall Management as per shell commands

root = tk.Tk()

root.title("Cyber Security Tool Selector")
screen_width = 400
screen_height = 400
root.geometry(f"{screen_width}x{screen_height}")

# Create a frame for layout purposes
frame = ttk.Frame(root, padding="10")
frame.pack(fill=tk.BOTH, expand=True)
# Create a ComboBox for selection
combo_label = ttk.Label(frame, text="Select a tool to launch:")
combo_label.pack(fill=tk.X, padx=5, pady=5)

def show_frame_as_per_combobox():
    global current_selection_window
    current_selection_window=0
    selected_option = combo.get()
    # Hide all frames
    for child in frame.winfo_children():
        if isinstance(child, ttk.Frame):
            child.pack_forget()
    # Show the selected frame
    if selected_option == "1. Time Based Rules":
        frame_time.pack(fill=tk.BOTH, expand=True)
        current_selection_window=1
    elif selected_option == "2. IP Based Rules":
        frame_IP.pack(fill=tk.BOTH, expand=True)
        current_selection_window=2
    elif selected_option == "3. Protocol Based Rules":
        frame_protocol.pack(fill=tk.BOTH, expand=True)
        current_selection_window=3
    elif selected_option == "4. Port Based Rules":
        frame_port.pack(fill=tk.BOTH, expand=True)
        current_selection_window=4
    elif selected_option == "5. State Based Rules":
        frame_state.pack(fill=tk.BOTH, expand=True)
        current_selection_window=5
    elif selected_option == "6. Inbound Outbound Rules":
        frame_InOutBond.pack(fill=tk.BOTH, expand=True)
        current_selection_window=6
    # show global frames
    global_frame1.pack(fill=tk.BOTH, expand=True)
    global_frame2.pack(fill=tk.BOTH, expand=True)

combo = ttk.Combobox(frame, values=["1. Time Based Rules", "2. IP Based Rules", "3. Protocol Based Rules", "4. Port Based Rules","5. State Based Rules", "6. Inbound Outbound Rules"])
combo.pack(fill=tk.X, padx=5, pady=5)


combo.bind("<<ComboboxSelected>>", lambda event: show_frame_as_per_combobox())

## 6 frames for 6 types

## frame 1 for time based rules
frame_time= ttk.Frame(frame, padding="10")
frame_time.pack(fill=tk.BOTH, expand=True)

#label named for Input time from to
label_time = ttk.Label(frame_time, text="Input Time From: & To: In HH:MM:SS IST 24 Hr format")
label_time.pack(fill=tk.X, padx=5, pady=5)

#label named for Input time from to
label_time = ttk.Label(frame_time, text="From: ")
label_time.pack(fill=tk.X, padx=5, pady=5)

# Entry for time input
entry_time_from = ttk.Entry(frame_time)
entry_time_from.pack(fill=tk.X, padx=5, pady=5)

#label named for Input time from to
label_time = ttk.Label(frame_time, text="To: ")
label_time.pack(fill=tk.X, padx=5, pady=5)
# Entry for time input
entry_time_to = ttk.Entry(frame_time)
entry_time_to.pack(fill=tk.X, padx=5, pady=5)

def IST_to_UST(ist_time):
    # Convert IST (Indian Standard Time) to UST (Universal Standard Time)
    # IST is UTC+5:30, so we subtract 5 hours and 30 minutes
    time_struct = time.strptime(ist_time, "%H:%M:%S")
    ist_seconds = time.mktime(time_struct)
    ust_seconds = ist_seconds - (5 * 3600 + 30 * 60)
    ust_time = time.strftime("%H:%M:%S", time.localtime(ust_seconds))
    return ust_time

def checkTimeInput():
    global block_traffic_time_from, block_traffic_time_to
    # check format of entry_time_from & entry_time_to
    from_time = entry_time_from.get()
    to_time = entry_time_to.get()
    try:
        time.strptime(from_time, "%H:%M:%S")
        time.strptime(to_time, "%H:%M:%S")
    except ValueError:
        messagebox.showerror("Invalid Time Format", "Please enter time in HH:MM:SS 24 Hr format.")
        return
    # If format is correct, run the command
    # Convert these times to UST time format
    from_time_ust = IST_to_UST(from_time)
    to_time_ust = IST_to_UST(to_time)
    block_traffic_time_from = from_time_ust
    block_traffic_time_to = to_time_ust
    messagebox.showinfo("Time Filter",f"Setting time based rules from {from_time_ust} to {to_time_ust} in UST")
    return

# Button to set time based rules
button_time = ttk.Button(frame_time, text="Set Time Based Rules", command=checkTimeInput)
button_time.pack(fill=tk.X, padx=5, pady=5)

def showTimeInput():
    global block_traffic_time_from, block_traffic_time_to
    if block_traffic_time_from and block_traffic_time_to:
        messagebox.showinfo("Blocked Time Filter in UST ", f"Blocked Time From: {block_traffic_time_from} To: {block_traffic_time_to} in UST")
    else:
        messagebox.showinfo("Blocked Time Filter", "No time based rules set yet.")

# Button to set time based rules
button_time = ttk.Button(frame_time, text="Show Blocked Time Filter", command=showTimeInput)
button_time.pack(fill=tk.X, padx=5, pady=5)



## frame 2 for IP based rules
frame_IP= ttk.Frame(frame, padding="10")
frame_IP.pack(fill=tk.BOTH, expand=True)

def checkIPInput(ip_addr_check):
    # check format of ip_addr_check
    try:
        parts = ip_addr_check.split('.')
        if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            raise ValueError("Invalid IP address format")
    except ValueError as e:
        messagebox.showerror("Invalid IP Format", str(e))
        return False
    return True

def addIPtoList():
    global ip_addr_block
    blocked_IP=entry_ip_block.get()
    ## check validity of allowed_IP & blocked_IP 
    if not checkIPInput(blocked_IP):
        return
    ip_addr_block.append(blocked_IP)

def deleteAllIps():
    global ip_addr_block
    ip_addr_block.clear()
    messagebox.showinfo("IP Rules", "All IP based rules have been reset.")

def showAllIpsBlocked():
    messagebox.showinfo("Blocked IPs", f"Blocked IPs: {', '.join(ip_addr_block)}")

#label named for block IP addresses
label_time = ttk.Label(frame_IP, text="IP Address To Be Blocked: ")
label_time.pack(fill=tk.X, padx=5, pady=5)
# Entry for time input
entry_ip_block = ttk.Entry(frame_IP)
entry_ip_block.pack(fill=tk.X, padx=5, pady=5)

# Button to set ip based rules
button_add_ip = ttk.Button(frame_IP, text="Add IPs", command=addIPtoList)
button_add_ip.pack(fill=tk.X, padx=5, pady=5)

# Button to set ip based rules
button_reset_ip = ttk.Button(frame_IP, text="Delete All IPs Reset IP Based Rules", command=deleteAllIps)
button_reset_ip.pack(fill=tk.X, padx=5, pady=5)

# Button to  ip based rules
button_blocked_ip_show = ttk.Button(frame_IP, text="Show Blocked IPs", command=showAllIpsBlocked)
button_blocked_ip_show.pack(fill=tk.X, padx=5, pady=5)





## frame 3 for protocol based rules
frame_protocol= ttk.Frame(frame, padding="10")
frame_protocol.pack(fill=tk.BOTH, expand=True)

# label named for Input protocol allowed only
label_protocol = ttk.Label(frame_protocol, text="Allowed Protocol Filter: ")
label_protocol.pack(fill=tk.X, padx=5, pady=5)

# combobox for protocol selection
protocols = ["TCP", "UDP", "ICMP", "HTTP"]
combo_protocol = ttk.Combobox(frame_protocol, values=protocols)
combo_protocol.pack(fill=tk.X, padx=5, pady=5)

def checkProtocolInput():
    global allowed_protocol
    selected_protocol = combo_protocol.get()
    if selected_protocol not in protocols:
        messagebox.showerror("Invalid Protocol", "Please select a valid protocol (TCP, UDP, ICMP, HTTP).")
        return
    messagebox.showinfo("Protocol Filter", f"Setting rules for {selected_protocol} protocol only allowed.")
    allowed_protocol = selected_protocol
    return

# Button to set protocol based rules
button_protocol = ttk.Button(frame_protocol, text="Set Protocol Based Rules", command=checkProtocolInput)
button_protocol.pack(fill=tk.X, padx=5, pady=5)

def deleteProtocolInput():
    global allowed_protocol
    allowed_protocol = None
    messagebox.showinfo("Protocol Rules", "All protocol based rules have been reset.")

# Button to set protocol based rules
button_protocol_reset = ttk.Button(frame_protocol, text="Delete/Reset Protocol Based Rules", command=deleteProtocolInput)
button_protocol_reset.pack(fill=tk.X, padx=5, pady=5)



## frame 4 for port based rules
frame_port= ttk.Frame(frame, padding="10")
frame_port.pack(fill=tk.BOTH, expand=True)

# label named for Input port number
label_port = ttk.Label(frame_port, text="Input Port Number Blocked: ")
label_port.pack(fill=tk.X, padx=5, pady=5)
# Entry for port input
entry_port = ttk.Entry(frame_port)
entry_port.pack(fill=tk.X, padx=5, pady=5)
def checkPortInput():
    global blocked_ports_global
    port_number = entry_port.get()
    try:
        port_number = int(port_number)
        if not (1 <= port_number <= 65535):
            raise ValueError("Port number must be between 1 and 65535.")
    except ValueError as e:
        messagebox.showerror("Invalid Port Number", str(e))
        return
    blocked_ports_global.append(port_number)
    messagebox.showinfo("Port Filter", f"Setting rules for port {port_number}.")
    return

def deleteAllPorts():
    global blocked_ports_global
    blocked_ports_global.clear()
    messagebox.showinfo("Port Rules", "All port based rules have been reset.")

# Button to set port based rules
button_port = ttk.Button(frame_port, text="Set Port Based Rules", command=checkPortInput)
button_port.pack(fill=tk.X, padx=5, pady=5)
# Button to set port based rules    
button_port_reset = ttk.Button(frame_port, text="Delete/Reset Port Based Rules", command=deleteAllPorts)
button_port_reset.pack(fill=tk.X, padx=5, pady=5)

# button to show all ports blocked
def showBlockedPorts():
    if not blocked_ports_global:
        messagebox.showinfo("Blocked Ports", "No ports have been blocked.")
    else:
        messagebox.showinfo("Blocked Ports", f"Blocked Ports: {', '.join(map(str, blocked_ports_global))}")

button_show_blocked_ports = ttk.Button(frame_port, text="Show Blocked Ports", command=showBlockedPorts)
button_show_blocked_ports.pack(fill=tk.X, padx=5, pady=5)



## frame 5 for state based rules
frame_state= ttk.Frame(frame, padding="10")
frame_state.pack(fill=tk.BOTH, expand=True)

# label named for Input state
label_state = ttk.Label(frame_state, text="Input State (e.g., NEW, ESTABLISHED): ")
label_state.pack(fill=tk.X, padx=5, pady=5)
# Entry for state input
entry_state = ttk.Entry(frame_state)
entry_state.pack(fill=tk.X, padx=5, pady=5)
def checkStateInput():
    global blocked_states_global
    state = entry_state.get().strip().upper()
    valid_states = ["NEW", "ESTABLISHED", "RELATED", "INVALID"]
    if state not in valid_states:
        messagebox.showerror("Invalid State", f"Please enter a valid state: {', '.join(valid_states)}.")
        return
    blocked_states_global.append(state)
    messagebox.showinfo("State Filter", f"Setting rules for state: {state}.")
    return
# Button to set state based rules
button_state = ttk.Button(frame_state, text="Set State Based Rules", command=checkStateInput)
button_state.pack(fill=tk.X, padx=5, pady=5)
def deleteStateInput():
    global blocked_states_global
    blocked_states_global.clear()
    messagebox.showinfo("State Rules", "All state based rules have been reset.")

# Button to set state based rules
button_state_reset = ttk.Button(frame_state, text="Delete/Reset State Based Rules", command=deleteStateInput)
button_state_reset.pack(fill=tk.X, padx=5, pady=5)
# button to show all states blocked
def showBlockedStates():
    if not blocked_states_global:
        messagebox.showinfo("Blocked States", "No states have been blocked.")
    else:
        messagebox.showinfo("Blocked States", f"Blocked States: {', '.join(blocked_states_global)}")


button_show_blocked_states = ttk.Button(frame_state, text="Show Blocked States", command=showBlockedStates)
button_show_blocked_states.pack(fill=tk.X, padx=5, pady=5)



## frame 6 for Inbound Outbound based rules
frame_InOutBond= ttk.Frame(frame, padding="10")
frame_InOutBond.pack(fill=tk.BOTH, expand=True)
# label named for Input Inbound Outbound
label_InOutBond = ttk.Label(frame_InOutBond, text="Input Inbound/Outbound (e.g., IN, OUT): ")
label_InOutBond.pack(fill=tk.X, padx=5, pady=5)

# Entry for Inbound/Outbound input
entry_InOutBond = ttk.Entry(frame_InOutBond)
entry_InOutBond.pack(fill=tk.X, padx=5, pady=5)
def checkInOutBondInput():
    global inOutBond_global
    in_out = entry_InOutBond.get().strip().upper()
    valid_in_out = ["IN", "OUT"]
    if in_out not in valid_in_out:
        messagebox.showerror("Invalid Inbound/Outbound", f"Please enter a valid option: {', '.join(valid_in_out)}.")
        return
    inOutBond_global = in_out
    messagebox.showinfo("Inbound/Outbound Filter", f"Setting rules for: {in_out}.")
    return
# Button to set Inbound/Outbound based rules
button_InOutBond = ttk.Button(frame_InOutBond, text="Set Inbound/Outbound Based Rules", command=checkInOutBondInput)
button_InOutBond.pack(fill=tk.X, padx=5, pady=5)

def deleteInoutBondInput():
    global inOutBond_global
    inOutBond_global = None
    messagebox.showinfo("Inbound/Outbound Rules", "All Inbound/Outbound based rules have been reset.")

# Button to set Inbound/Outbound based rules
button_InOutBond_reset = ttk.Button(frame_InOutBond, text="Delete/Reset Inbound/Outbound Based Rules", command=deleteInoutBondInput)
button_InOutBond_reset.pack(fill=tk.X, padx=5, pady=5)

# show current state of inbound or outbound rule set button
button_showinOutBond = ttk.Button(frame_InOutBond, text="Show Current Inbound/Outbound Rule", command=lambda: messagebox.showinfo("Inbound/Outbound Rule", f"Current Inbound/Outbound Rule: {inOutBond_global if inOutBond_global else 'None'}"))
button_showinOutBond.pack(fill=tk.X, padx=5, pady=5)

# global buttons & all show in frame

global_frame1 = ttk.Frame(frame, padding="10")
global_frame1.pack(fill=tk.BOTH, expand=True)

# Button to reset all firewall rules
button_reset_all = ttk.Button(global_frame1, text="Reset All Firewall Rules", command=resetAllFirewallRules)
button_reset_all.pack(fill=tk.X,side=tk.LEFT, padx=5, pady=5)

def RunSelectedRules():
    if current_selection_window==1:
        TimeFilterRunCommand()
    elif current_selection_window==2:
        IPFilterRunCommand()
    elif current_selection_window==3:
        ProtocolFilterRunCommand()
    elif current_selection_window==4:
        PortFilterRunCommand()
    elif current_selection_window==5:
        StateFilterRunCommand()
    elif current_selection_window==6:
        InboundOutboundFilterRunCommand()
    else:
        messagebox.showerror("Error", "No valid selection made.")

# Button to reset all firewall rules
button_reset_all = ttk.Button(global_frame1, text="Run Rules", command=RunSelectedRules)
button_reset_all.pack(fill=tk.X,side=tk.RIGHT, padx=5, pady=5)

global_frame2 = ttk.Frame(frame, padding="10")
global_frame2.pack(fill=tk.BOTH, expand=True)
# text box to show all blocked time, steate, port, protocol, inbound outbound, IPs etc
text_box = tk.Text(global_frame2, height=10, width=50)
text_box.pack(fill=tk.BOTH, padx=5, pady=5)
# Function to show the current firewall rules in the text box

 
show_frame_as_per_combobox()
root.mainloop()