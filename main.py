import pandas as pd
import requests
from requests.structures import CaseInsensitiveDict
import tkinter as tk
from tkinter import ttk, messagebox

API_KEY = "a67e8979758f4feea51637156bbdaf25"
CSV_PATH = r"C:\Users\aarni\OneDrive\Desktop\Python\KyberhyökkäysAnalyysi\Kyberhyökkäys_data.csv"

try:
    df = pd.read_csv(CSV_PATH)
except FileNotFoundError:
    print("CSV file not found.")
    exit()

#def place_name(lat: float, lon: float) -> str:
#    url = (f"https://api.geoapify.com/v1/geocode/reverse?lat={lat}&lon={lon}&type=city&lang=en&limit=1&format=json&apiKey={API_KEY}")
#    headers = CaseInsensitiveDict()
#    headers["Accept"] = "application/json"
#    resp = requests.get(url, headers=headers)
#    if resp.status_code == 200:
#        data = resp.json()
#        if data.get("results"):
#            city = data["results"][0].get("city")
#            return city if city else "unknown"
#    return "unknown"

def estimate_attack_likelihood(user_input):
    score = 0
    reasons = []
    if user_input["failed_logins"] > 3:
        score += 25; reasons.append("Multiple failed login attempts")
    if user_input["unusual_time_access"] == 1:
        score += 20; reasons.append("Access during unusual hours")
    if user_input["ip_reputation_score"] < 0.3:
        score += 20; reasons.append("Low IP reputation score")
    if user_input["encryption_used"] in ["None", "DES"]:
        score += 15; reasons.append("Weak or no encryption used")
    if user_input["protocol_type"].upper() == "UDP":
        score += 10; reasons.append("Unreliable UDP protocol used")
    if user_input["network_packet_size"] > df["network_packet_size"].mean() * 1.5:
        score += 10; reasons.append("Unusually large network packet size")
    if user_input["session_duration"] > df["session_duration"].mean() * 2:
        score += 10; reasons.append("Long session duration")
    score = min(score, 100)
    return score, reasons

root = tk.Tk()
root.title("Kyberhyökkäys Todennäköisyys")
root.geometry("700x650")
root.resizable(False, False)

tk.Label(root, text="Cybersecurity Attack Likelihood Analyzer", font=("Segoe UI", 16, "bold")).pack(pady=10)
frame = tk.Frame(root); frame.pack(pady=10)

protocol_options = ["TCP", "UDP", "HTTP", "HTTPS"]
encryption_options = ["AES", "RSA", "DES", "None"]
browser_options = ["Chrome", "Firefox", "Edge", "Safari", "Opera"]
yes_no_options = [0, 1]

fields = {
    "network_packet_size": ("Network Packet Size (1–1500 bytes)", "entry"),
    "protocol_type": ("Protocol Type", protocol_options),
    "login_attempts": ("Login Attempts (1–10)", "entry"),
    "session_duration": ("Session Duration (1–5000 sec)", "entry"),
    "encryption_used": ("Encryption Used", encryption_options),
    "ip_reputation_score": ("IP Reputation Score (0–1)", "entry"),
    "failed_logins": ("Failed Logins (0–10)", "entry"),
    "browser_type": ("Browser Type", browser_options),
    "unusual_time_access": ("Unusual Time Access (0 = No, 1 = Yes)", yes_no_options),
}

entries = {}

for i, (key, (label, input_type)) in enumerate(fields.items()):
    tk.Label(frame, text=label, anchor="w").grid(row=i, column=0, padx=10, pady=5, sticky="w")
    if isinstance(input_type, list):
        var = tk.StringVar()
        combo = ttk.Combobox(frame, textvariable=var, values=input_type, state="readonly", width=30)
        combo.grid(row=i, column=1, padx=10, pady=5)
        combo.current(0)
        entries[key] = var
    else:
        var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=var, width=30)
        entry.insert(0, input_type)
        entry.grid(row=i, column=1, padx=10, pady=5)
        entries[key] = var

output_box = tk.Text(root, height=10, width=80, wrap="word", state="disabled")
output_box.pack(pady=10)

def on_check():
    try:
        user_input = {
            "network_packet_size": float(entries["network_packet_size"].get()),
            "protocol_type": entries["protocol_type"].get(),
            "login_attempts": int(entries["login_attempts"].get()),
            "session_duration": float(entries["session_duration"].get()),
            "encryption_used": entries["encryption_used"].get(),
            "ip_reputation_score": float(entries["ip_reputation_score"].get()),
            "failed_logins": int(entries["failed_logins"].get()),
            "browser_type": entries["browser_type"].get(),
            "unusual_time_access": int(entries["unusual_time_access"].get()),
        }

        likelihood, reasons = estimate_attack_likelihood(user_input)
        result = f"Estimated Attack Likelihood: {likelihood}%\n"
        result += "\nRisk Indicators:\n - " + "\n - ".join(reasons) if reasons else "\nNo significant risks detected."

        output_box.config(state="normal")
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, result)
        output_box.config(state="disabled")

    except Exception as e:
        messagebox.showerror("Error", f"Invalid input or missing data:\n{e}")

tk.Button(root, text="Analyze Session", command=on_check, font=("Segoe UI", 12, "bold"),
          bg="#2563eb", fg="white", width=20).pack(pady=10)

root.mainloop()
