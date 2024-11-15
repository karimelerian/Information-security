import re
import tkinter as tk
import math
users_roles = {
    "karim": "Doctor",
    "maya": "Nurse",
    "nadeen": "Admin",
    "janna": "Receptionist"
}
roles_permissions = {
    "Doctor": ["View Patient Data", "Edit Patient Records", "Prescribe Medications"],
    "Nurse": ["View Patient Data", "Administer Medications"],
    "Admin": ["Manage Hospital Staff", "View Reports"],
    "Receptionist": ["Manage Appointments", "View Patient Data"]
}

def check_rbac(role, permission):
    if role in roles_permissions:
        return permission in roles_permissions[role]
    return False

    
def PasswordStrength(password):
    Score = 0
    reasons = []
    entr=0
    entropy=0
    
    if len(password) >= 12:
        Score += 1
        entr += 1
    else:reasons.append("Password should have more than 12 characters")
    if any(char.isupper() for char in password):
        entr += 1
        Score += 26
    else:reasons.append("Password should include uppercase letters")
    if any(char.islower() for char in password):
        entr += 1
        Score += 26
    else:reasons.append("Password should include lowercase letters")
    if any(char.isdigit() for char in password):
        entr += 1
        Score += 10
    else:reasons.append("Password should include a number")
    if any(char in '!@#$%^&*()_+' for char in password):
        entr += 1
        Score += 12
    else:reasons.append("Password should include special characters")
    if re.search(r"(.)\1\1", password):
        reasons.append("Password contains repeating characters (e.g., 'aaaaaa', '111111')")
        entr -= 1
    else:entr += 1
        
    common_patterns = ["123456", "password", "123", "abc123", "meowmeow"]
    if any(pattern in password for pattern in common_patterns):
        reasons.append("Password contains common patterns (e.g., '123456', 'password')")
        entr -= 1
    else:entr += 1
        
    if Score >0 :
        entropy=math.log2(Score ** len(password))
    else:  reasons_text = "\n".join(reasons)
        

    return entropy, reasons, entr
    


def update_ui():
    
    username = username_entry.get()
    password = entry.get() 
    user_role = None
    requested_permission = permission_entry.get()
    if username not in users_roles:
        login_status_label.config(text="Invalid username. Please try again.")
        return 
    entropy, reasons, entr = PasswordStrength(password)  
    
    if reasons:
        reasons_text = "\n".join(reasons)  
    else:
        reasons_text = "strong password"
    reasons_label.config(text=reasons_text)
    strength_label.config(text=f"Password entropy: {entropy:.2f} bits")

    if entropy >= 70.0 and entr== 7 : 
        user_role = users_roles[username]
        login_status_label.config(text=f"Login successful! Your role: {user_role}")
        permissions = roles_permissions[user_role]  
        permissions_text = f"Role: {user_role}\nPermissions:\n" + "\n".join(permissions)
        permissions_label.config(text=permissions_text)
        strong_label.config(text="Password strength: Strong")
    elif entropy >= 50.0 and entr== 7 :
        user_role = users_roles[username]
        login_status_label.config(text=f"Login successful! Your role: {user_role}")
        permissions = roles_permissions[user_role]  
        permissions_text = f"Role: {user_role}\nPermissions:\n" + "\n".join(permissions)
        permissions_label.config(text=permissions_text)
        strong_label.config(text="Password strength: Medium")
    elif entropy >= 30.0 and (entr<= 7 and entr>= 5):
        strong_label.config(text="Password strength: Fair")
        
    elif entropy < 30.0 :
        strong_label.config(text="Password strength: Weak")
        
        

    if user_role is not None:
        if requested_permission:
            if check_rbac(user_role, requested_permission):
                login_status_label.config(text=f"Access granted! You have permission for: {requested_permission}")
            else:
                login_status_label.config(text=f"Access denied! You do not have permission for: {requested_permission}")
        else:
            login_status_label.config(text="Please enter a permission request.")

root = tk.Tk()
root.title("Password Strength Checker with RBAC")
root.geometry("400x600") 
username_label = tk.Label(root, text="Enter your username:")
username_label.pack(pady=10)
username_entry = tk.Entry(root)
username_entry.pack(pady=10)
prompt_label = tk.Label(root, text="Enter your password:")
prompt_label.pack(pady=10)


tk
entry = tk.Entry(root, show='*')

entry.pack(pady=10)  
entry.bind('<KeyRelease>', lambda event: update_ui())
strength_label = tk.Label(root, text="")
strength_label.pack(pady=10)
strong_label= tk.Label(root, text="")
strong_label.pack(pady=10)
reasons_label = tk.Label(root, text="", justify="left", wraplength=280)
reasons_label.pack(pady=10)

login_status_label = tk.Label(root, text="")
login_status_label.pack(pady=10)

requested_perm_label= tk.Label(root, text="request permission")
requested_perm_label.pack(pady=10)
permission_entry = tk.Entry(root)
permission_entry.pack(pady=10)
permission_entry.bind('<Return>', lambda event: update_ui())


permissions_label = tk.Label(root, text="", justify="left", wraplength=280)
permissions_label.pack(pady=10)

root.mainloop()
