import os
import time
import numpy as np
import base64
import matplotlib.pyplot as plt
from flask import Flask, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename
import pandas as pd
from Crypto.Util.Padding import pad, unpad

''' Pemanggilan Algoritma'''
from algoritma.aesm.maes import MAES
from algoritma.chacha.cha import CHACHA
from algoritma.aesstd.oaes import AES


app = Flask(__name__)

BLOCK_SIZE=16
FILE_ENCDEC = "static/file"
GRAPH = "static/grafik"

os.makedirs(FILE_ENCDEC, exist_ok=True)
os.makedirs(GRAPH, exist_ok=True)

app.config["FILE_ENCDEC"] = FILE_ENCDEC
app.config["GRAPH"] = GRAPH

import matplotlib
matplotlib.use('Agg')  # Hindari backend GUI
import matplotlib.pyplot as plt
# import numpy as np

def create_comparison_graph(results, graph_filename):
    algorithms = [r["algoritma"] for r in results]
    entropy_before = [r["entropy_before"] for r in results]
    entropy_after = [r["entropy_after"] for r in results]
    execution_time = [r["execution_time"] for r in results]
    speed = [r["speed"] for r in results]

    # Membuat figure dengan tiga subplot vertikal
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 15))

    # Grafik Entropi (Line Chart)
    x = np.arange(len(algorithms))
    ax1.plot(x, entropy_before, marker='o', linestyle='-', linewidth=2, markersize=8, label='Sebelum', color='skyblue')
    ax1.plot(x, entropy_after, marker='s', linestyle='--', linewidth=2, markersize=8, label='Sesudah', color='lightcoral')
    ax1.set_ylabel('Entropi', fontsize=12)
    ax1.set_title('Perbandingan Entropi', fontsize=14)
    ax1.set_xticks(x)
    ax1.set_xticklabels(algorithms, rotation=45, fontsize=10)
    ax1.legend(fontsize=10)
    ax1.grid(True, linestyle='--', alpha=0.7)

    # Grafik Waktu Eksekusi (Line Chart)
    ax2.plot(x, execution_time, marker='^', linestyle='-', linewidth=2, markersize=8, color='lightgreen')
    ax2.set_ylabel('Waktu Eksekusi (detik)', fontsize=12)
    ax2.set_title('Waktu Eksekusi per Algoritma', fontsize=14)
    ax2.set_xticks(x)
    ax2.set_xticklabels(algorithms, rotation=45, fontsize=10)
    ax2.grid(True, linestyle='--', alpha=0.7)

    # Grafik Kecepatan (Line Chart)
    ax3.plot(x, speed, marker='d', linestyle='-', linewidth=2, markersize=8, color='lightgreen')
    ax3.set_ylabel('Kecepatan (KB/detik)', fontsize=12)
    ax3.set_title('Kecepatan Proses per Algoritma', fontsize=14)
    ax3.set_xticks(x)
    ax3.set_xticklabels(algorithms, rotation=45, fontsize=10)
    ax3.grid(True, linestyle='--', alpha=0.7)

    # Mengatur layout agar tidak saling tumpang tindih
    plt.tight_layout()

    # Simpan grafik
    plt.savefig(graph_filename, bbox_inches='tight')
    plt.close()

def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = byte_counts / len(data)
    probabilities = probabilities[probabilities > 0]
    return -np.sum(probabilities * np.log2(probabilities))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/test')
def test():
    return render_template('all.html')

@app.route('/chart')
def chrt():
    return render_template('chart.html')

@app.route('/proses', methods=['POST'])
def uploadfile():
    if "file" not in request.files:
        return "Tidak ada file yang diunggah", 400

    file = request.files["file"]
    mode = request.form["mode"].lower()
    key = request.form["key"]
    algoritma = request.form["algoritma"]

    if file.filename == "":
        return "Nama file kosong!", 400
    if not key:
        return "Kunci tidak boleh kosong!", 400

    # Baca file langsung dari request tanpa menyimpannya terlebih dahulu
    filename = secure_filename(file.filename)
    file_data = file.read()

    file_size_kb = len(file_data) / 1024  # Konversi ukuran file ke KB
    entropy_before = calculate_entropy(file_data)
    start_time = time.time()
    
    if algoritma == "Chacha20":
        cha = CHACHA(key)
        if mode == "enkripsi":
            encrypted = cha.encrypt(file_data)
            processed_data = base64.b64encode(encrypted)

        elif mode == "dekripsi":
            try:
                encrypted_data = base64.b64decode(file_data)
            except Exception as e:
                return f"Base64 decode error: {e}", 400

            processed_data = cha.decrypt(encrypted_data)
            
    elif algoritma == "AES_Modified":
        maes = MAES(bytes(key, 'utf-8'))
        processed_data = b""  # Inisialisasi variabel untuk menampung hasil

        if mode == "enkripsi":
            for i in range(0, len(file_data), BLOCK_SIZE):
                chunk = file_data[i:i + BLOCK_SIZE]

                # Tambahkan padding di blok terakhir
                if i + BLOCK_SIZE >= len(file_data):
                    chunk = pad(chunk, BLOCK_SIZE)
                elif len(chunk) < BLOCK_SIZE:
                    chunk = pad(chunk, BLOCK_SIZE)

                processed_data += maes.encrypt(chunk)
            processed_data = base64.b64encode(processed_data)

        elif mode == "dekripsi":
            try:
                # Decode base64 sebelum didekripsi
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                return f"Base64 decode error: {e}", 400

            for i in range(0, len(decoded_data), BLOCK_SIZE):
                chunk = decoded_data[i:i + BLOCK_SIZE]
                if len(chunk) != BLOCK_SIZE:
                    continue  # Lewati blok tidak valid
                processed_data += maes.decrypt(chunk)

            # Unpad hanya jika seluruh hasil berhasil didekripsi
            try:
                processed_data = unpad(processed_data, BLOCK_SIZE)
            except ValueError as e:
                print(f"[WARNING] Unpad gagal: {e}")
                # Biarkan hasil tetap, padding kemungkinan rusak
                pass

        else:
            return "Mode tidak valid! Pilih enkripsi atau dekripsi.", 400
            
    elif algoritma == "aes_standard":
        aes = AES(bytes(key, 'utf-8'))
        processed_data = b""  # Inisialisasi variabel untuk menampung hasil

        if mode == "enkripsi":
            for i in range(0, len(file_data), BLOCK_SIZE):
                chunk = file_data[i:i + BLOCK_SIZE]

                # Tambahkan padding di blok terakhir
                if i + BLOCK_SIZE >= len(file_data):
                    chunk = pad(chunk, BLOCK_SIZE)
                elif len(chunk) < BLOCK_SIZE:
                    chunk = pad(chunk, BLOCK_SIZE)

                processed_data += aes.encrypt(chunk)
            processed_data = base64.b64encode(processed_data)

        elif mode == "dekripsi":
            try:
                # Decode base64 sebelum didekripsi
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                return f"Base64 decode error: {e}", 400

            for i in range(0, len(decoded_data), BLOCK_SIZE):
                chunk = decoded_data[i:i + BLOCK_SIZE]
                if len(chunk) != BLOCK_SIZE:
                    continue  # Lewati blok tidak valid
                processed_data += aes.decrypt(chunk)

            # Unpad hanya jika seluruh hasil berhasil didekripsi
            try:
                processed_data = unpad(processed_data, BLOCK_SIZE)
            except ValueError as e:
                print(f"[WARNING] Unpad gagal: {e}")
                # Biarkan hasil tetap, padding kemungkinan rusak
                pass

        else:
            return "Mode tidak valid! Pilih enkripsi atau dekripsi.", 400

            
    elif algoritma == "Mix":
        maes = MAES(bytes(key, 'utf-8'))
        cha = CHACHA(key)
        processed_data = b""

        #Enkripsi MAES (BLOK 16 BYTE)
        if mode == "enkripsi":
            tmp = b""
            for i in range(0, len(file_data), BLOCK_SIZE):
                chunk = file_data[i:i + BLOCK_SIZE]

                # Tambahkan padding di blok terakhir
                if i + BLOCK_SIZE >= len(file_data):
                    chunk = pad(chunk, BLOCK_SIZE)
                elif len(chunk) < BLOCK_SIZE:
                    chunk = pad(chunk, BLOCK_SIZE)

                tmp += maes.encrypt(chunk)

            #enkripsi chcha20 (stream)
            processed_data = cha.encrypt(tmp)
            processed_data = base64.b64encode(processed_data)


        elif mode == "dekripsi":
            try:
                # Decode base64 sebelum dekripsi dengan ChaCha
                encrypted_data = base64.b64decode(file_data)
            except Exception as e:
                return f"Base64 decode error: {e}", 400

            tmp = cha.decrypt(encrypted_data)

            processed_data = b""
            for i in range(0, len(tmp), BLOCK_SIZE):
                chunk = tmp[i:i + BLOCK_SIZE]
                if len(chunk) != BLOCK_SIZE:
                    continue
                processed_data += maes.decrypt(chunk)

            try:
                processed_data = unpad(processed_data, BLOCK_SIZE)
            except ValueError as e:
                print(f"[WARNING] Unpad gagal: {e}")
                pass

        else:
            return "Mode tidak valid! Pilih enkripsi atau dekripsi.", 400


    end_time = time.time()
    execution_time = end_time - start_time
    entropy_after = calculate_entropy(processed_data)
    speed = file_size_kb / execution_time if execution_time > 0 else 0

    # Simpan hanya hasil proses ke server
    if not os.path.exists(app.config["FILE_ENCDEC"]):
        os.makedirs(app.config["FILE_ENCDEC"])
    
    processed_filename = f"{mode}_{filename}" if mode == "enkripsi" else f"{mode}_{filename}"
    processed_filepath = os.path.join(app.config["FILE_ENCDEC"], processed_filename)
    
    with open(processed_filepath, "wb") as f:
        f.write(processed_data)
    
    

    # Buat grafik entropi dan performa
    graph_filename = f"static/grafik/grafik_{processed_filename}.png"
    create_graph(entropy_before, entropy_after, execution_time, speed, graph_filename)

    results = [{
        'processed_filename': processed_filename,
        'entropy_before': entropy_before,
        'entropy_after': entropy_after,
        'execution_time': round(execution_time, 2),
        'speed': round(speed, 2),
    }]

    return render_template(
        'index.html', 
        results=results,
        file_size= file_size_kb,
        select_mode=mode,
        graph_link=graph_filename
    )


# Definisikan route '/all' yang menerima request POST
@app.route('/all', methods=['POST'])
def performa():
    # Periksa apakah ada file dalam request
    if "file" not in request.files:
        return "Tidak ada file yang diunggah", 400

    # Ambil file, mode, kunci, dan algoritma dari form
    file = request.files["file"]
    mode = "enkripsi"  # Mode: enkripsi atau dekripsi
    key = request.form["key"]  # Kunci untuk enkripsi/dekripsi

    # Validasi file dan kunci
    if file.filename == "":
        return "Nama file kosong!", 400
    if not key:
        return "Kunci tidak boleh kosong!", 400
    if len(key) != 16:
        return "Kunci harus tepat 16 karakter!", 400

    # Amankan nama file dan baca isi file
    filename = secure_filename(file.filename)  
    file_data = file.read() 
    file_size_kb = len(file_data) / 1024  # Menghitung ukuran file dalam KB
    entropy_before = calculate_entropy(file_data) 
    
    # Inisialisasi list untuk menyimpan hasil
    results_enc = []
    results_dec = []
    # Tentukan algoritma yang akan dijalankan: semua algoritma atau satu algoritma
    algorithms = ["Chacha20", "AES Standar", "AES Modifikasi", "AESM + Chacha20"]

    # Iterasi untuk setiap algoritma
    for algo in algorithms:
        processed_data = b""  # Inisialisasi data hasil pemrosesan
        start_time = time.perf_counter()  # Catat waktu mulai

        # Proses algoritma berdasarkan pilihan
        try:
            if algo == "Chacha20":
                cha = CHACHA(key)  # Inisialisasi objek Chacha20 dengan kunci
                if mode == "enkripsi":
                    encrypted = cha.encrypt(file_data)
                    processed_data = base64.b64encode(encrypted)

                else:
                    return "Mode tidak valid! Pilih enkripsi atau dekripsi.", 400

            elif algo == "AES Modifikasi":
                maes = MAES(bytes(key, 'utf-8'))  # Inisialisasi objek AES Modified
                # Proses data per blok (BLOCK_SIZE)
                for i in range(0, len(file_data), BLOCK_SIZE):
                    chunk = file_data[i:i + BLOCK_SIZE]  # Ambil potongan data
                    if mode == "enkripsi":
                        if i + BLOCK_SIZE >= len(file_data):
                            chunk = pad(chunk, BLOCK_SIZE)
                        elif len(chunk) < BLOCK_SIZE:
                            chunk = pad(chunk, BLOCK_SIZE)

                        processed_data += maes.encrypt(chunk)
                    else:
                        return "Mode tidak valid! Pilih enkripsi atau dekripsi.", 400
                processed_data = base64.b64encode(processed_data)

            elif algo == "AES Standar":
                aes = AES(bytes(key, 'utf-8'))  # Inisialisasi objek AES standar
                # Proses data per blok (BLOCK_SIZE)
                for i in range(0, len(file_data), BLOCK_SIZE):
                    chunk = file_data[i:i + BLOCK_SIZE]  # Ambil potongan data
                    if mode == "enkripsi":
                        # Tambahkan padding di blok terakhir
                        if i + BLOCK_SIZE >= len(file_data):
                            chunk = pad(chunk, BLOCK_SIZE)
                        elif len(chunk) < BLOCK_SIZE:
                            chunk = pad(chunk, BLOCK_SIZE)

                        processed_data += aes.encrypt(chunk)  # Enkripsi potongan
                processed_data = base64.b64encode(processed_data)

            elif algo == "AESM + Chacha20":
                maes = MAES(bytes(key, 'utf-8'))  # Inisialisasi objek AES Modified
                cha = CHACHA(key)  # Inisialisasi objek Chacha20
                if mode == "enkripsi":
                    tmp = b""
                    for i in range(0, len(file_data), BLOCK_SIZE):
                        chunk = file_data[i:i + BLOCK_SIZE]

                        # Tambahkan padding di blok terakhir
                        if i + BLOCK_SIZE >= len(file_data):
                            chunk = pad(chunk, BLOCK_SIZE)
                        elif len(chunk) < BLOCK_SIZE:
                            chunk = pad(chunk, BLOCK_SIZE)

                        tmp += maes.encrypt(chunk) ## 1. proses enkripsi MAES
                    
                    res = cha.encrypt(tmp) ## 2. proses enkrispi chacha
                    processed_data = base64.b64encode(res)

        except Exception as e:
            return f"Error pada algoritma {algo}: {str(e)}", 500  # Tangani error
        
        end_time = time.perf_counter()  # Catat waktu selesai
        execution_time = end_time - start_time  # Hitung waktu eksekusi
        entropy_after = calculate_entropy(processed_data)  # Hitung entropi setelah pemrosesan
        speed = abs(file_size_kb / execution_time if execution_time > 0 else 0)  # Hitung kecepatan (KB/detik)

        # Simpan file hasil pemrosesan
        if not os.path.exists(app.config["FILE_ENCDEC"]):
            os.makedirs(app.config["FILE_ENCDEC"])  # Buat direktori jika belum ada
        processed_filename = f"{mode}{algo}{filename}"  # Nama file hasil
        processed_filepath = os.path.join(app.config["FILE_ENCDEC"], processed_filename)
        with open(processed_filepath, "wb") as f:
            f.write(processed_data)  # Tulis data ke file

        # Simpan metrik ke dalam results
        results_enc.append({
            "algoritma": algo,
            "entropy_before": entropy_before,
            "entropy_after": entropy_after,
            "execution_time": execution_time,
            "speed": round(speed, 2),
            "processed_filename": processed_filename
        })
        
        # Proses Dekripsi (membaca file hasil enkripsi)
        with open(processed_filepath, "rb") as f:
            file_enc = f.read()
        
        file_size_enc = len(file_enc) / 1024
        entropy_before_dec = calculate_entropy(file_enc) 
        start_time_dec = time.time()
        decrypted_data = b""
        ## Dekripsi
        if algo == "Chacha20":
            cha = CHACHA(key)  # Inisialisasi objek Chacha20 dengan kunci
            try:
                encrypted_data = base64.b64decode(file_enc)
            except Exception as e:
                return f"Base64 decode error: {e}", 400

            processed_data = cha.decrypt(encrypted_data)
            
        elif algo == "AES Modifikasi":
            maes = MAES(bytes(key, 'utf-8'))  # Inisialisasi objek AES Modified
            try:
                # Decode base64 sebelum didekripsi
                decoded_data = base64.b64decode(file_enc)
            except Exception as e:
                return f"Base64 decode error: {e}", 400
            
            # Proses data per blok (BLOCK_SIZE)
            for i in range(0, len(decoded_data), BLOCK_SIZE):
                chunk = decoded_data[i:i + BLOCK_SIZE]
                if len(chunk) != BLOCK_SIZE:
                    # Lewati blok tak valid
                    continue
                decrypted_data += maes.decrypt(chunk)

            # Unpad hanya jika seluruh hasil berhasil didekripsi
            try:
                decrypted_data = unpad(decrypted_data, BLOCK_SIZE)
            except ValueError as e:
                print(f"[WARNING] Unpad gagal: {e}")
                # Biarkan hasil tetap, padding kemungkinan rusak
                pass
            
        elif algo == "AES Standar":
            aes = AES(bytes(key, 'utf-8'))  # Inisialisasi objek AES standar
            try:
                # Decode base64 sebelum didekripsi
                decoded_data = base64.b64decode(file_enc)
            except Exception as e:
                return f"Base64 decode error: {e}", 400
            
            # Proses data per blok (BLOCK_SIZE)
            for i in range(0, len(decoded_data), BLOCK_SIZE):
                chunk = decoded_data[i:i + BLOCK_SIZE]
                if len(chunk) != BLOCK_SIZE:
                    # Lewati blok tak valid
                    continue
                decrypted_data += aes.decrypt(chunk)

            # Unpad hanya jika seluruh hasil berhasil didekripsi
            try:
                decrypted_data = unpad(decrypted_data, BLOCK_SIZE)
            except ValueError as e:
                print(f"[WARNING] Unpad gagal: {e}")
                # Biarkan hasil tetap, padding kemungkinan rusak
                pass
            
        elif algo == "AESM + Chacha20":
            maes = MAES(bytes(key, 'utf-8'))  # Inisialisasi objek AES Modified
            cha = CHACHA(key)  # Inisialisasi objek Chacha20
            try:
                # Decode base64 sebelum dekripsi dengan ChaCha
                encrypted_data = base64.b64decode(file_enc)
            except Exception as e:
                return f"Base64 decode error: {e}", 400

            tmp = cha.decrypt(encrypted_data)

            # Dekripsi dengan MAES per blok
            for i in range(0, len(tmp), BLOCK_SIZE):
                chunk = tmp[i:i + BLOCK_SIZE]
                if len(chunk) != BLOCK_SIZE:
                    continue
                decrypted_data += maes.decrypt(chunk) # dekripsi maes, 
            try:
                decrypted_data = unpad(decrypted_data, BLOCK_SIZE)
            except ValueError as e:
                print(f"[WARNING] Unpad gagal: {e}")
                pass
                
        end_time_dec = time.time()  # Catat waktu selesai
        kecepatan = end_time_dec - start_time_dec  # Hitung waktu eksekusi (hasil)
        entropy_after_dec = calculate_entropy(decrypted_data)  # Hitung entropi setelah pemrosesan
        speed_dec = abs(file_size_enc / kecepatan if kecepatan > 0 else 0 ) # Hitung kecepatan (KB/detik)

        # Simpan file hasil pemrosesan
        if not os.path.exists(app.config["FILE_ENCDEC"]):
            os.makedirs(app.config["FILE_ENCDEC"])  # Buat direktori jika belum ada
        processed_filename = f"dekripsi_{algo}_{filename}"  # Nama file hasil
        processed_filepath = os.path.join(app.config["FILE_ENCDEC"], processed_filename)
        with open(processed_filepath, "wb") as f:
            f.write(decrypted_data)  # Tulis data ke file

        # Hasil dekripsi API
        results_dec.append({
            "algoritma": algo,
            "entropy_before": entropy_before_dec,
            "entropy_after": entropy_after_dec,
            "execution_time": kecepatan, ## hasil lalu di simpan di sini
            "speed": round(speed_dec, 2),
            "processed_filename": processed_filename
        })

    # Render template HTML dengan hasil
    return render_template(
        'all.html',
        results=results_enc,  # Data hasil untuk ditampilkan
        results_dec=results_dec,
        file_size=file_size_kb,
        select_mode=mode,  # Mode yang dipilih (enkripsi/dekripsi)
    )

@app.route('/download/<filename>')
def download_file(filename):
    filepath = os.path.join(app.config["FILE_ENCDEC"], filename)
    
    if not os.path.exists(filepath):
        return "File tidak ditemukan!", 404

    return send_file(filepath, as_attachment=True)

def create_graph(entropy_before, entropy_after, execution_time, speed, graph_filename):
    """Membuat grafik dari hasil enkripsi/dekripsi."""
    labels = ["Entropi Sebelum", "Entropi Sesudah", "Waktu (detik)", "Kecepatan (KB/detik)"]
    values = [entropy_before, entropy_after, execution_time, speed]

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values, color=['blue', 'red', 'green', 'orange'])
    plt.xlabel("Parameter")
    plt.ylabel("Nilai")
    plt.title("Analisis Enkripsi/Dekripsi")
    plt.savefig(graph_filename)
    plt.close()

if __name__ == '__main__':
    app.run(debug=True, port=5001)
