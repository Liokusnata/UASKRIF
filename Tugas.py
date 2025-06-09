import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import math
import random
import string

# === RC4 Core ===
def ksa(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S, n):
    i = j = 0
    keystream = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    return keystream

def rc4(key, n):
    S = ksa(key)
    return prga(S, n)

def encrypt_rc4(plaintext, keystream):
    plaintext_bytes = plaintext.encode('utf-8')
    return [plaintext_bytes[i] ^ keystream[i] for i in range(len(plaintext_bytes))]

def decrypt_rc4(cipher_bytes, keystream):
    return bytes([cipher_bytes[i] ^ keystream[i] for i in range(len(cipher_bytes))]).decode('utf-8', errors='replace')

def bytes_to_hex(cipher_bytes):
    return ''.join(f'{b:02x}' for b in cipher_bytes)

def hex_to_bytes(hex_string):
    try:
        return bytes.fromhex(hex_string)
    except ValueError:
        return None

# === GUI App ===
class RC4App:
    def __init__(self, root):
        self.root = root
        self.root.title("RC4 Encryption & Decryption")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        
        # Set theme colors
        self.bg_color = "#f0f0f0"
        self.primary_color = "#4a6fa5"
        self.success_color = "#d4edda"
        self.error_color = "#f8d7da"
        self.warning_color = "#fff3cd"
        
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background=self.primary_color)
        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabel", background=self.bg_color, padding=3)
        style.configure("TLabelframe", background=self.bg_color)
        style.configure("TLabelframe.Label", background=self.bg_color)
        
        # Mode: 0 = Enkripsi, 1 = Dekripsi
        self.mode_var = tk.IntVar(value=0)

        # Frame Utama
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Top: Toggle Mode
        mode_frame = ttk.Frame(main_frame)
        mode_frame.pack(fill="x", pady=(0, 10))

        ttk.Radiobutton(mode_frame, text="Enkripsi", variable=self.mode_var, value=0, 
                        command=self.switch_mode).pack(side="left", padx=(0, 15))
        ttk.Radiobutton(mode_frame, text="Dekripsi", variable=self.mode_var, value=1, 
                        command=self.switch_mode).pack(side="left")

        # Content Frame (untuk form dinamis)
        self.content_frame = ttk.Frame(main_frame)
        self.content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Di bawahnya: Visualisasi Keystream
        vis_frame = ttk.LabelFrame(main_frame, text="Visualisasi Keystream", padding=5)
        vis_frame.pack(fill="x", pady=(10, 0))

        # Create tooltips for visualization buttons
        self.tooltips = {}
        vis_buttons = [
            ("Bar", self.show_bar, "Tampilkan diagram batang nilai keystream"),
            ("Line", self.show_line, "Tampilkan grafik perubahan nilai keystream"),
            ("Heatmap", self.show_heatmap, "Tampilkan peta panas distribusi keystream"),
            ("Histogram", self.show_histogram, "Tampilkan distribusi frekuensi nilai keystream"),
            ("Scatter", self.show_scatter, "Tampilkan sebaran nilai keystream"),
            ("Statistik", self.show_stats, "Tampilkan analisis statistik keystream")
        ]

        for i, (label, cmd, tip) in enumerate(vis_buttons):
            btn = ttk.Button(vis_frame, text=label, command=cmd)
            btn.grid(row=0, column=i, padx=5, pady=5)
            self.tooltips[btn] = tip
            btn.bind("<Enter>", self.show_tooltip)
            btn.bind("<Leave>", self.hide_tooltip)

        # Tooltip label
        self.tooltip_label = ttk.Label(vis_frame, text="", 
                                      background="#ffffe0", 
                                      relief="solid", 
                                      borderwidth=1,
                                      wraplength=280)
        self.tooltip_label.place_forget()

        # Inisialisasi form pertama kali sebagai Enkripsi
        self.build_encrypt_form()

    def show_tooltip(self, event):
        widget = event.widget
        tip = self.tooltips.get(widget, "")
        if tip:
            x = widget.winfo_x()
            y = widget.winfo_y() + widget.winfo_height() + 5
            self.tooltip_label.config(text=tip)
            self.tooltip_label.place(x=x, y=y, width=300)

    def hide_tooltip(self, event):
        self.tooltip_label.place_forget()

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def switch_mode(self):
        self.clear_content()
        if self.mode_var.get() == 0:
            self.build_encrypt_form()
        else:
            self.build_decrypt_form()

    def build_encrypt_form(self):
        frame = ttk.Frame(self.content_frame, padding=10)
        frame.pack(fill="both", expand=True)
        
        # Konfigurasi grid
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(2, weight=0)
        
        # Row 0: Key
        ttk.Label(frame, text="Key:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.enc_key_entry = ttk.Entry(frame)
        self.enc_key_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        
        # Generate Key button
        ttk.Button(frame, text="Generate Key", command=self.generate_key).grid(row=0, column=2, padx=5, pady=5)

        # Row 1: Plaintext (multiline dengan scrollbar)
        ttk.Label(frame, text="Plaintext:").grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        
        # Frame untuk text dan scrollbar
        text_frame = ttk.Frame(frame)
        text_frame.grid(row=1, column=1, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        # Text widget dengan scrollbar
        self.enc_plain_text = tk.Text(text_frame, height=4, wrap="word")
        self.enc_plain_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.enc_plain_text.yview)
        self.enc_plain_text.configure(yscrollcommand=self.enc_plain_scroll.set)
        
        self.enc_plain_text.pack(side="left", fill="both", expand=True)
        self.enc_plain_scroll.pack(side="right", fill="y")

        # Row 2: Tombol Enkripsi
        ttk.Button(frame, text="Enkripsi", command=self.encrypt).grid(row=2, column=0, columnspan=3, pady=10)

        # Row 3: Output Ciphertext
        ttk.Label(frame, text="Ciphertext (hex):").grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        self.enc_output = tk.Text(frame, height=4, wrap="word")
        self.enc_output.grid(row=3, column=1, columnspan=2, sticky="ew", padx=5, pady=5)

        # Row 4: Output Keystream
        ttk.Label(frame, text="Keystream:").grid(row=4, column=0, sticky="nw", padx=5, pady=5)
        self.enc_keystream_output = tk.Text(frame, height=4, wrap="word")
        self.enc_keystream_output.grid(row=4, column=1, columnspan=2, sticky="ew", padx=5, pady=5)

    def build_decrypt_form(self):
        frame = ttk.Frame(self.content_frame, padding=10)
        frame.pack(fill="both", expand=True)
        
        # Konfigurasi grid
        frame.columnconfigure(1, weight=1)
        
        # Row 0: Key
        ttk.Label(frame, text="Key:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.dec_key_entry = ttk.Entry(frame)
        self.dec_key_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        # Row 1: Ciphertext (multiline dengan scrollbar)
        ttk.Label(frame, text="Ciphertext (hex):").grid(row=1, column=0, sticky="nw", padx=5, pady=5)
        
        # Frame untuk text dan scrollbar
        text_frame = ttk.Frame(frame)
        text_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        # Text widget dengan scrollbar
        self.dec_cipher_text = tk.Text(text_frame, height=4, wrap="word")
        self.dec_cipher_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.dec_cipher_text.yview)
        self.dec_cipher_text.configure(yscrollcommand=self.dec_cipher_scroll.set)
        
        self.dec_cipher_text.pack(side="left", fill="both", expand=True)
        self.dec_cipher_scroll.pack(side="right", fill="y")

        # Row 2: Tombol Dekripsi
        ttk.Button(frame, text="Dekripsi", command=self.decrypt).grid(row=2, column=0, columnspan=2, pady=10)

        # Row 3: Output Plaintext
        ttk.Label(frame, text="Hasil Dekripsi:").grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        self.dec_output = tk.Text(frame, height=4, wrap="word")
        self.dec_output.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

        # Row 4: Output Keystream
        ttk.Label(frame, text="Keystream:").grid(row=4, column=0, sticky="nw", padx=5, pady=5)
        self.dec_keystream_output = tk.Text(frame, height=4, wrap="word")
        self.dec_keystream_output.grid(row=4, column=1, sticky="ew", padx=5, pady=5)
        
    def generate_key(self):
        """Generate a random key dan masukkan ke entry key enkripsi saja"""
        if self.mode_var.get() == 0:  # Encryption mode
            characters = string.ascii_letters + string.digits + string.punctuation
            key_length = random.randint(12, 24)
            key = ''.join(random.SystemRandom().choice(characters) for _ in range(key_length))
            
            self.enc_key_entry.delete(0, tk.END)
            self.enc_key_entry.insert(0, key)

    def encrypt(self):
        try:
            key_str = self.enc_key_entry.get()
            plaintext = self.enc_plain_text.get("1.0", tk.END).strip()  # Ambil dari Text widget

            if not key_str.strip() or not plaintext:
                messagebox.showerror("Error", "Key dan plaintext harus diisi.")
                return

            # Konversi key ke bytes
            key_bytes = [ord(c) for c in key_str]
            self.keystream = rc4(key_bytes, len(plaintext))
            cipher_bytes = encrypt_rc4(plaintext, self.keystream)
            hex_cipher = bytes_to_hex(cipher_bytes)

            self.enc_output.delete("1.0", tk.END)
            self.enc_output.insert(tk.END, hex_cipher)
            self.enc_output.config(bg=self.success_color)

            self.enc_keystream_output.delete("1.0", tk.END)
            self.enc_keystream_output.insert(tk.END, str(self.keystream))
            
        except Exception as e:
            self.enc_output.config(bg=self.error_color)
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        try:
            key_str = self.dec_key_entry.get()
            hex_cipher = self.dec_cipher_text.get("1.0", tk.END).strip()  # Ambil dari Text widget

            if not key_str.strip() or not hex_cipher:
                messagebox.showerror("Error", "Key dan ciphertext harus diisi.")
                return

            cipher_bytes = hex_to_bytes(hex_cipher)
            if cipher_bytes is None:
                messagebox.showerror("Error", "Format ciphertext tidak valid. Harus hex.")
                return

            key_bytes = [ord(c) for c in key_str]
            self.keystream = rc4(key_bytes, len(cipher_bytes))
            plaintext = decrypt_rc4(cipher_bytes, self.keystream)

            self.dec_output.delete("1.0", tk.END)
            self.dec_output.insert(tk.END, plaintext)
            self.dec_output.config(bg=self.success_color)

            self.dec_keystream_output.delete("1.0", tk.END)
            self.dec_keystream_output.insert(tk.END, str(self.keystream))
            
        except Exception as e:
            self.dec_output.config(bg=self.error_color)
            messagebox.showerror("Error", str(e))

    def plot_figure(self, fig):
        window = tk.Toplevel(self.root)
        window.title("Visualisasi Keystream")
        window.geometry("800x400")
        canvas = FigureCanvasTkAgg(fig, master=window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add export button
        export_btn = ttk.Button(window, text="Simpan Gambar", 
                               command=lambda: self.save_plot(fig))
        export_btn.pack(pady=5)

    def save_plot(self, fig):
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", ".png"), ("JPEG files", ".jpg"), ("All files", ".")]
        )
        if filename:
            fig.savefig(filename)

    def show_bar(self):
        if not hasattr(self, 'keystream'):
            messagebox.showinfo("Info", "Silakan enkripsi atau dekripsi terlebih dahulu.")
            return
        
        # Downsample if too large
        if len(self.keystream) > 1000:
            keystream_sample = random.sample(self.keystream, 1000)
        else:
            keystream_sample = self.keystream
            
        fig = plt.Figure(figsize=(8, 3))
        ax = fig.add_subplot(111)
        ax.bar(range(len(keystream_sample)), keystream_sample, color=self.primary_color)
        ax.set_title("Bar Chart Keystream")
        ax.set_xlabel("Index Byte")
        ax.set_ylabel("Nilai Keystream (0–255)")
        self.plot_figure(fig)

    def show_line(self):
        if not hasattr(self, 'keystream'):
            messagebox.showinfo("Info", "Silakan enkripsi atau dekripsi terlebih dahulu.")
            return
            
        # Downsample if too large
        if len(self.keystream) > 1000:
            keystream_sample = random.sample(self.keystream, 1000)
        else:
            keystream_sample = self.keystream
            
        fig = plt.Figure(figsize=(8, 3))
        ax = fig.add_subplot(111)
        ax.plot(keystream_sample, color=self.primary_color)
        ax.set_title("Line Chart Keystream")
        ax.set_xlabel("Index Byte")
        ax.set_ylabel("Nilai Keystream (0–255)")
        self.plot_figure(fig)

    def show_heatmap(self):
        if not hasattr(self, 'keystream'):
            messagebox.showinfo("Info", "Silakan enkripsi atau dekripsi terlebih dahulu.")
            return
        size = int(math.sqrt(len(self.keystream)))
        if size * size > len(self.keystream):
            size -= 1
        matrix = [self.keystream[i * size:(i + 1) * size] for i in range(size)]

        fig = plt.Figure(figsize=(6, 5))
        ax = fig.add_subplot(111)
        sns.heatmap(matrix, ax=ax, cmap="viridis", cbar=True)
        ax.set_title("Heatmap Distribusi Keystream")
        self.plot_figure(fig)


        fig = plt.Figure(figsize=(8, 1.5))
        ax = fig.add_subplot(111)
        sns.heatmap([self.keystream], ax=ax, cbar=True, cmap="viridis")
        ax.set_title("Heatmap Keystream")
        ax.set_yticks([])
        ax.set_xlabel("Index Byte")
        self.plot_figure(fig)

    def show_histogram(self):
        if not hasattr(self, 'keystream'):
            messagebox.showinfo("Info", "Silakan enkripsi atau dekripsi terlebih dahulu.")
            return
            
        fig = plt.Figure(figsize=(8, 3))
        ax = fig.add_subplot(111)
        ax.hist(self.keystream, bins=256, range=(0, 256), edgecolor='black', color=self.primary_color)
        ax.set_title("Histogram Keystream")
        ax.set_xlabel("Nilai Keystream")
        ax.set_ylabel("Frekuensi")
        self.plot_figure(fig)

    def show_scatter(self):
        if not hasattr(self, 'keystream'):
            messagebox.showinfo("Info", "Silakan enkripsi atau dekripsi terlebih dahulu.")
            return

        fig = plt.Figure(figsize=(8, 3))
        ax = fig.add_subplot(111)
        ax.scatter(range(len(self.keystream)), self.keystream, s=10, color=self.primary_color)
        ax.set_title("Scatter Plot Keystream")
        ax.set_xlabel("Index Byte")
        ax.set_ylabel("Nilai Keystream (0–255)")
        self.plot_figure(fig)
            
        # Downsample if too large
        if len(self.keystream) > 1000:
            keystream_sample = random.sample(self.keystream, 1000)
            indices = random.sample(range(len(self.keystream)), 1000)
        else:
            keystream_sample = self.keystream
            indices = range(len(self.keystream))
            
        fig = plt.Figure(figsize=(8, 3))
        ax = fig.add_subplot(111)
        ax.scatter(indices, keystream_sample, s=10, color=self.primary_color)
        ax.set_title("Scatter Plot Keystream")
        ax.set_xlabel("Index Byte")
        ax.set_ylabel("Nilai Keystream (0–255)")
        self.plot_figure(fig)
        
    def show_stats(self):
        if not hasattr(self, 'keystream'):
            messagebox.showinfo("Info", "Silakan enkripsi atau dekripsi terlebih dahulu.")
            return
        import statistics

        ks = self.keystream
        stats_text = (
            f"Jumlah Byte Keystream: {len(ks)}\n"
            f"Nilai Minimum       : {min(ks)}\n"
            f"Nilai Maksimum      : {max(ks)}\n"
            f"Rata-rata           : {statistics.mean(ks):.2f}\n"
            f"Median              : {statistics.median(ks)}\n"
            f"Standar Deviasi     : {statistics.stdev(ks):.2f}"
        )

        messagebox.showinfo("Statistik Keystream", stats_text)

        # Create stats window
        stats_win = tk.Toplevel(self.root)
        stats_win.title("Statistik Keystream")
        stats_win.geometry("400x300")
        
        # Create main frame
        frame = ttk.Frame(stats_win, padding=10)
        frame.pack(fill="both", expand=True)
        
        # Calculate statistics
        length = len(self.keystream)
        unique = len(set(self.keystream))
        min_val = min(self.keystream)
        max_val = max(self.keystream)
        avg = sum(self.keystream) / length
        
        # Calculate standard deviation
        variance = sum((x - avg) ** 2 for x in self.keystream) / length
        std_dev = math.sqrt(variance)
        
        # Create stats display with Treeview
        ttk.Label(frame, text="Statistik Keystream", 
                 font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Create Treeview for tabular display
        columns = ("metric", "value")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=6)
        
        # Configure columns
        tree.heading("metric", text="Metrik")
        tree.heading("value", text="Nilai")
        tree.column("metric", width=150, anchor="w")
        tree.column("value", width=150, anchor="w")
        
        # Add data
        stats = [
            ("Panjang Keystream", f"{length}"),
            ("Nilai Minimum", f"{min_val}"),
            ("Nilai Maksimum", f"{max_val}"),
            ("Rata-rata", f"{avg:.4f}"),
            ("Standar Deviasi", f"{std_dev:.4f}"),
            ("Nilai Unik", f"{unique} ({unique/256*100:.1f}%)")
        ]
        
        for stat in stats:
            tree.insert("", "end", values=stat)
        
        tree.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 10))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=2, sticky="ns")
        
        # Configure grid weights
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)
        
        # Add export button
        ttk.Button(frame, text="Export ke CSV", command=self.export_stats).grid(row=2, column=0, columnspan=2, pady=(5, 0))
        
    def export_stats(self):
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", ".csv"), ("All files", ".*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Statistik,Nilai\n")
                    f.write(f"Panjang Keystream,{len(self.keystream)}\n")
                    f.write(f"Nilai Minimum,{min(self.keystream)}\n")
                    f.write(f"Nilai Maksimum,{max(self.keystream)}\n")
                    
                    avg = sum(self.keystream) / len(self.keystream)
                    f.write(f"Rata-rata,{avg:.4f}\n")
                    
                    variance = sum((x - avg) ** 2 for x in self.keystream) / len(self.keystream)
                    std_dev = math.sqrt(variance)
                    f.write(f"Standar Deviasi,{std_dev:.4f}\n")
                    
                    unique = len(set(self.keystream))
                    f.write(f"Nilai Unik,{unique}\n")
                    f.write(f"Persentase Unik,{unique/256*100:.2f}%\n")
                
            except Exception as e:
                messagebox.showerror("Error", f"Gagal menyimpan file: {str(e)}")


# === Jalankan Aplikasi ===
if __name__ == "__main__":
    root = tk.Tk()
    app = RC4App(root)
    root.mainloop()