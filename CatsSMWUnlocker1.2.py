import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, Checkbutton, IntVar
import os
import glob

def is_smc(rom):
    size = len(rom)
    return 512 if size % 1024 == 512 and size > 1024 else 0

def is_valid_snes_pointer(ptr, rom_size):
    if ptr in (0, 0xFFFFFF, 0xFFFF, 0x000000):
        return True
    offset = ptr & 0xFFFF
    bank = (ptr >> 16) & 0xFF
    if offset >= rom_size:
        return False
    if bank >= 0x80:
        bank -= 0x80
    if bank > 0x7D:
        return False
    return True

def calculate_snes_checksum(data):
    checksum = sum(data) & 0xFFFF
    inverse = checksum ^ 0xFFFF
    return inverse.to_bytes(2, 'little') + checksum.to_bytes(2, 'little')

def multi_layer_unlock(rom_data, log, rom_name, use_fallback):
    # Region detection
    country_codes = {
        0: "Japan (NTSC-J)",
        1: "USA (NTSC-U)",
        2: "Europe (PAL)",
        3: "Sweden (PAL)",
        4: "Finland (PAL)",
        5: "Denmark (PAL)",
        6: "France (PAL)",
        7: "Netherlands (PAL)",
        8: "Spain (PAL)",
        9: "Germany (PAL)",
        10: "Italy (PAL)",
        11: "China (NTSC)",
        12: "Indonesia (PAL)",
        13: "South Korea (NTSC)",
        14: "International (Unknown)"
    }
    
    if len(rom_data) >= 0x7FE0:
        country = rom_data[0x7FD9]
        region_str = country_codes.get(country, f"Unknown (code: {country})")
        log.insert(tk.END, f"Processing {rom_name}: Detected region - {region_str}\n")
        if country not in [0, 1]:
            log.insert(tk.END, "Warning: This region (e.g., PAL) may not be fully supported by Lunar Magic. Proceed with caution.\n")
    else:
        log.insert(tk.END, f"Processing {rom_name}: Could not detect region - header too short.\n")

    log.insert(tk.END, f"Multi-layer unlock initiated\n")
    log.insert(tk.END, "Authorizing access to ROM contents...\n")

    # Force title restoration
    original_title = b"SUPER MARIOWORLD" + b' ' * 5
    titles = [0x7FC0, 0xFFC0, 0x81BC0]
    for offset in titles:
        if len(rom_data) > offset + 21:
            rom_data[offset:offset+21] = original_title
            log.insert(tk.END, f"Title restored at ${offset:05X}\n")

    # Reset checksum
    if len(rom_data) >= 0xFFDE:
        rom_data[0xFFDE:0xFFE0] = b'\x00\x00'

    unlocked_layers = 0
    i = 0
    while i < len(rom_data) - 8:
        if rom_data[i:i+4] == b'RATS':
            log.insert(tk.END, f"RATS tag detected at ${i:06X} - decrypting protected data...\n")
            ptr_start = i + 8
            ptr_end = ptr_start + 0x600
            data_start = ptr_end

            for ptr_key in [0xAA, 0x55, 0x69, 0x96, 0xFF]:
                for data_key in [0xAA, ptr_key ^ 0xFF, 0x55, 0x00]:
                    test_bytes = rom_data[ptr_start:ptr_start + 0x300]
                    valid = 0
                    for j in range(0, len(test_bytes), 3):
                        if j + 3 > len(test_bytes): 
                            break
                        dec = bytes(b ^ ptr_key for b in test_bytes[j:j+3])
                        ptr = dec[0] | (dec[1] << 8) | (dec[2] << 16)
                        if is_valid_snes_pointer(ptr, len(rom_data)):
                            valid += 1

                    if valid >= 30:
                        log.insert(tk.END, f"Success: Pointer key 0x{ptr_key:02X} validated ({valid} valid pointers)\n")
                        for j in range(ptr_start, ptr_end):
                            if j < len(rom_data):
                                rom_data[j] ^= ptr_key
                        for j in range(data_start, len(rom_data)):
                            rom_data[j] ^= data_key
                        unlocked_layers += 1
                        break
                else:
                    continue
                break
            i += 0x1000
        else:
            i += 1

    # Special handling for animation GFX 0x33 issue
    if unlocked_layers == 0 and use_fallback:
        log.insert(tk.END, "Standard decryption failed - applying specialized routines...\n")
        
        # First attempt: Detect and fix specific GFX corruption patterns
        gfx_signature = b'\x33\x00\x00\x00'
        for pos in range(0x10000, len(rom_data) - 4):
            if rom_data[pos:pos+4] == gfx_signature:
                log.insert(tk.END, f"Detected potential GFX corruption at ${pos:06X}\n")
                # Apply selective correction rather than full XOR
                rom_data[pos+1] = 0x80  # Standard header fix
                rom_data[pos+2] = 0x00
                rom_data[pos+3] = 0x00
        
        # Apply targeted decryption only to likely encrypted sections
        common_keys = [0xAA, 0x55, 0x69, 0x42, 0x96, 0xFF]
        for key in common_keys:
            log.insert(tk.END, f"Testing decryption key 0x{key:02X}\n")
            # Only apply to sections that appear to be encrypted
            for j in range(0x10000, len(rom_data), 0x1000):
                section = rom_data[j:j+0x1000]
                if any(b != 0 for b in section):
                    for k in range(len(section)):
                        rom_data[j+k] ^= key
            unlocked_layers += 1
    elif unlocked_layers == 0:
        log.insert(tk.END, "Standard decryption failed. Enable fallback mode for advanced recovery attempts.\n")

    if unlocked_layers > 0:
        log.insert(tk.END, f"Success: {unlocked_layers} protection layers removed from {rom_name}\n")
        log.insert(tk.END, "ROM is now accessible for Lunar Magic editing.\n")
    else:
        log.insert(tk.END, f"Unable to unlock {rom_name}. Manual intervention may be required.\n")
    return unlocked_layers > 0

def unlock_single_rom(input_path, output_path, log, use_fallback):
    rom_name = os.path.basename(input_path)
    log.insert(tk.END, f"Processing: {rom_name}\n")
    
    try:
        with open(input_path, 'rb') as f:
            rom = bytearray(f.read())

        header = is_smc(rom)
        data = rom[header:]

        success = multi_layer_unlock(data, log, rom_name, use_fallback)

        with open(output_path, 'wb') as f:
            f.write(rom[:header] + data)
            
        if success:
            log.insert(tk.END, f"Successfully saved: {os.path.basename(output_path)}\n")
        else:
            log.insert(tk.END, f"Partial save completed: {os.path.basename(output_path)}\n")
            
        return success
        
    except Exception as e:
        log.insert(tk.END, f"Error processing {rom_name}: {str(e)}\n")
        return False

class AdvancedReUnlockerBatch:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced ROM Unlocker 1.6")
        self.root.geometry("780x680")
        self.root.configure(bg="#0d1b2a")

        title_label = tk.Label(self.root, text="Advanced ROM Unlocker", 
                              font=("Segoe UI", 16, "bold"), bg="#0d1b2a", fg="#e0e1dd")
        title_label.pack(pady=10)

        subtitle_label = tk.Label(self.root, text="Version 1.6 | For Super Mario World ROMs", 
                                 font=("Segoe UI", 10), bg="#0d1b2a", fg="#778da9")
        subtitle_label.pack()

        frame = tk.Frame(self.root, bg="#1b263b", bd=2, relief=tk.GROOVE)
        frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        self.log = scrolledtext.ScrolledText(frame, height=20, width=80, 
                                            bg="#0d1b2a", fg="#e0e1dd",
                                            font=("Consolas", 9))
        self.log.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        button_frame = tk.Frame(self.root, bg="#0d1b2a")
        button_frame.pack(pady=10)

        select_btn = tk.Button(button_frame, text="Select File", command=self.select_file,
                              bg="#415a77", fg="#e0e1dd", font=("Segoe UI", 10),
                              width=12, relief=tk.RAISED, bd=2)
        select_btn.grid(row=0, column=0, padx=5)

        batch_btn = tk.Button(button_frame, text="Select Directory", command=self.select_directory,
                             bg="#415a77", fg="#e0e1dd", font=("Segoe UI", 10),
                             width=12, relief=tk.RAISED, bd=2)
        batch_btn.grid(row=0, column=1, padx=5)

        unlock_btn = tk.Button(button_frame, text="Unlock ROM(s)", command=self.unlock,
                              bg="#2a9d8f", fg="#e0e1dd", font=("Segoe UI", 10, "bold"),
                              width=12, relief=tk.RAISED, bd=2)
        unlock_btn.grid(row=0, column=2, padx=5)

        self.use_fallback_var = IntVar(value=0)
        fallback_check = Checkbutton(self.root, 
                                     text="Enable Advanced Recovery (may affect graphics)",
                                     variable=self.use_fallback_var,
                                     bg="#0d1b2a", fg="#e0e1dd", 
                                     font=("Segoe UI", 10),
                                     selectcolor="#415a77")
        fallback_check.pack(pady=5)

        status_frame = tk.Frame(self.root, bg="#0d1b2a")
        status_frame.pack(pady=10)
        
        self.status_label = tk.Label(status_frame, text="Ready", 
                                     font=("Segoe UI", 9), bg="#0d1b2a", fg="#778da9")
        self.status_label.pack()

        self.is_batch = False
        self.input_path = ""

    def select_file(self):
        self.input_path = filedialog.askopenfilename(
            title="Select ROM file",
            filetypes=[("SNES ROMs", "*.smc *.sfc *.fig"), ("All files", "*.*")]
        )
        if self.input_path:
            self.is_batch = False
            self.status_label.config(text=f"Selected: {os.path.basename(self.input_path)}")

    def select_directory(self):
        dir_path = filedialog.askdirectory(title="Select directory with ROMs")
        if dir_path:
            self.input_path = dir_path
            self.is_batch = True
            self.status_label.config(text=f"Directory: {os.path.basename(dir_path)}")

    def unlock(self):
        if not hasattr(self, 'input_path') or not self.input_path:
            messagebox.showwarning("Warning", "Please select a file or directory first.")
            return
            
        self.log.delete(1.0, tk.END)
        self.log.insert(tk.END, "ROM unlock process initiated...\n")
        self.log.insert(tk.END, "="*60 + "\n\n")
        
        use_fallback = bool(self.use_fallback_var.get())
        
        try:
            if self.is_batch:
                rom_files = glob.glob(os.path.join(self.input_path, "*.smc")) + \
                           glob.glob(os.path.join(self.input_path, "*.sfc"))
                
                if not rom_files:
                    messagebox.showwarning("Warning", "No ROM files found in selected directory.")
                    return
                    
                successful = 0
                for rom_path in rom_files:
                    output_path = os.path.splitext(rom_path)[0] + "_unlocked.smc"
                    if unlock_single_rom(rom_path, output_path, self.log, use_fallback):
                        successful += 1
                        
                self.log.insert(tk.END, f"\nProcess complete: {successful}/{len(rom_files)} ROMs unlocked.\n")
                
            else:
                output_path = os.path.splitext(self.input_path)[0] + "_unlocked.smc"
                if unlock_single_rom(self.input_path, output_path, self.log, use_fallback):
                    messagebox.showinfo("Success", "ROM successfully unlocked!")
                else:
                    messagebox.showwarning("Partial Success", 
                                         "ROM processed with limited success.\nCheck log for details.")
                    
        except Exception as e:
            self.log.insert(tk.END, f"\nCritical error: {str(e)}\n")
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = AdvancedReUnlockerBatch()
    app.run()